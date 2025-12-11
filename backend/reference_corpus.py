"""
Reference Corpus Management

Manages known-benign and known-malicious samples for continuous testing.
"""
import json
import pickle
import os
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Optional
from enum import Enum

from config import BENIGN_CORPUS, MALICIOUS_CORPUS, ADVERSARIAL_CORPUS, DATA_DIR
from verification_engine import engine, TriangulationResult, RiskLevel


class CorpusType(Enum):
    BENIGN = "benign"
    MALICIOUS = "malicious"
    ADVERSARIAL = "adversarial"


@dataclass
class CorpusSample:
    """A sample in the reference corpus"""
    filename: str
    corpus_type: CorpusType
    expected_label: RiskLevel
    description: str
    file_hash: str
    created_at: str
    last_verified: Optional[str] = None
    last_result: Optional[str] = None
    drift_detected: bool = False


@dataclass
class CorpusCheckResult:
    """Result of a corpus verification run"""
    timestamp: str
    samples_checked: int
    samples_passed: int
    samples_failed: int
    drift_detected: list[dict]
    new_fp: int
    new_fn: int


class ReferenceCorpus:
    """
    Manages the reference corpus for continuous verification.
    """
    
    def __init__(self):
        self.baseline_file = DATA_DIR / "corpus_baseline.json"
        self.history_file = DATA_DIR / "corpus_history.json"
        self.samples: list[CorpusSample] = []
        self._load_baseline()
    
    def _load_baseline(self):
        """Load baseline from disk"""
        if self.baseline_file.exists():
            with open(self.baseline_file, 'r') as f:
                data = json.load(f)
                self.samples = [
                    CorpusSample(
                        **{**s, 'corpus_type': CorpusType(s['corpus_type']), 
                           'expected_label': RiskLevel(s['expected_label'])}
                    )
                    for s in data
                ]
    
    def _save_baseline(self):
        """Save baseline to disk"""
        data = []
        for s in self.samples:
            d = asdict(s)
            d['corpus_type'] = s.corpus_type.value
            d['expected_label'] = s.expected_label.value
            data.append(d)
        
        with open(self.baseline_file, 'w') as f:
            json.dump(data, f, indent=2)
    
    def _append_history(self, result: CorpusCheckResult):
        """Append check result to history"""
        history = []
        if self.history_file.exists():
            with open(self.history_file, 'r') as f:
                history = json.load(f)
        
        history.append(asdict(result))
        
        # Keep last 90 days
        history = history[-90:]
        
        with open(self.history_file, 'w') as f:
            json.dump(history, f, indent=2)
    
    def get_corpus_path(self, corpus_type: CorpusType) -> Path:
        """Get path for corpus type"""
        if corpus_type == CorpusType.BENIGN:
            return BENIGN_CORPUS
        elif corpus_type == CorpusType.MALICIOUS:
            return MALICIOUS_CORPUS
        else:
            return ADVERSARIAL_CORPUS
    
    def register_sample(
        self,
        filepath: Path,
        corpus_type: CorpusType,
        expected_label: RiskLevel,
        description: str
    ) -> CorpusSample:
        """Register a new sample in the corpus"""
        with open(filepath, 'rb') as f:
            data = f.read()
        
        file_hash = engine.compute_hash(data)
        
        sample = CorpusSample(
            filename=filepath.name,
            corpus_type=corpus_type,
            expected_label=expected_label,
            description=description,
            file_hash=file_hash,
            created_at=datetime.utcnow().isoformat()
        )
        
        # Check for duplicates
        for existing in self.samples:
            if existing.file_hash == file_hash:
                return existing
        
        self.samples.append(sample)
        self._save_baseline()
        
        return sample
    
    def scan_and_register_all(self):
        """Scan corpus directories and register new samples"""
        for corpus_type in CorpusType:
            corpus_path = self.get_corpus_path(corpus_type)
            if not corpus_path.exists():
                continue
            
            expected = RiskLevel.SAFE if corpus_type == CorpusType.BENIGN else RiskLevel.CRITICAL
            
            for filepath in corpus_path.glob("*"):
                if filepath.is_file() and filepath.suffix in ('.pkl', '.pickle', '.bin'):
                    # Check if already registered
                    with open(filepath, 'rb') as f:
                        file_hash = engine.compute_hash(f.read())
                    
                    if not any(s.file_hash == file_hash for s in self.samples):
                        self.register_sample(
                            filepath,
                            corpus_type,
                            expected,
                            f"Auto-registered from {corpus_type.value} corpus"
                        )
    
    def run_corpus_check(self) -> CorpusCheckResult:
        """
        Run verification on all corpus samples and detect drift.
        """
        drift_detected = []
        samples_passed = 0
        samples_failed = 0
        new_fp = 0
        new_fn = 0
        
        for sample in self.samples:
            corpus_path = self.get_corpus_path(sample.corpus_type)
            filepath = corpus_path / sample.filename
            
            if not filepath.exists():
                samples_failed += 1
                continue
            
            # Verify sample
            with open(filepath, 'rb') as f:
                data = f.read()
            
            result = engine.verify_pickle(data)
            actual_label = result.consensus or result.aieye_result
            
            # Check for drift
            expected_safe = sample.expected_label in (RiskLevel.SAFE, RiskLevel.LOW)
            actual_safe = actual_label in (RiskLevel.SAFE, RiskLevel.LOW)
            
            if expected_safe != actual_safe:
                sample.drift_detected = True
                drift_detected.append({
                    'filename': sample.filename,
                    'corpus_type': sample.corpus_type.value,
                    'expected': sample.expected_label.value,
                    'actual': actual_label.value,
                    'reasoning': result.reasoning
                })
                
                # Track FP/FN
                if sample.corpus_type == CorpusType.BENIGN and not actual_safe:
                    new_fp += 1
                elif sample.corpus_type in (CorpusType.MALICIOUS, CorpusType.ADVERSARIAL) and actual_safe:
                    new_fn += 1
                
                samples_failed += 1
            else:
                samples_passed += 1
            
            # Update sample
            sample.last_verified = datetime.utcnow().isoformat()
            sample.last_result = actual_label.value
        
        self._save_baseline()
        
        result = CorpusCheckResult(
            timestamp=datetime.utcnow().isoformat(),
            samples_checked=len(self.samples),
            samples_passed=samples_passed,
            samples_failed=samples_failed,
            drift_detected=drift_detected,
            new_fp=new_fp,
            new_fn=new_fn
        )
        
        self._append_history(result)
        
        return result
    
    def get_drift_history(self) -> list[dict]:
        """Get historical drift data"""
        if self.history_file.exists():
            with open(self.history_file, 'r') as f:
                return json.load(f)
        return []
    
    def get_summary(self) -> dict:
        """Get corpus summary statistics"""
        by_type = {t.value: 0 for t in CorpusType}
        by_label = {l.value: 0 for l in RiskLevel}
        drifted = 0
        
        for sample in self.samples:
            by_type[sample.corpus_type.value] += 1
            by_label[sample.expected_label.value] += 1
            if sample.drift_detected:
                drifted += 1
        
        return {
            'total_samples': len(self.samples),
            'by_type': by_type,
            'by_expected_label': by_label,
            'drifted_samples': drifted
        }


# Singleton
corpus = ReferenceCorpus()


def create_benign_samples():
    """
    Create synthetic benign pickle samples for testing.
    """
    samples = []
    
    # Simple dict (training args style)
    training_args = {
        'learning_rate': 5e-5,
        'num_train_epochs': 3,
        'per_device_train_batch_size': 16,
        'warmup_steps': 500,
        'weight_decay': 0.01,
        'logging_dir': './logs',
        'output_dir': './results',
    }
    samples.append(('training_args.bin', training_args, 'Standard training arguments'))
    
    # PEFT-style adapter config
    peft_config = {
        'lora_A': [[0.1, 0.2], [0.3, 0.4]],
        'lora_B': [[0.5, 0.6], [0.7, 0.8]],
        'lora_alpha': 16,
        'lora_dropout': 0.1,
        'r': 8,
        'target_modules': ['q_proj', 'v_proj'],
    }
    samples.append(('peft_adapter.bin', peft_config, 'PEFT LoRA adapter config'))
    
    # Trainer state
    trainer_state = {
        'epoch': 2.5,
        'global_step': 1000,
        'best_metric': 0.95,
        'best_model_checkpoint': './checkpoint-500',
    }
    samples.append(('trainer_state.bin', trainer_state, 'Trainer state checkpoint'))
    
    # Optimizer state
    optimizer_state = {
        'param_groups': [{'lr': 5e-5, 'weight_decay': 0.01}],
        'state': {0: {'step': 1000, 'exp_avg': [0.1, 0.2]}},
    }
    samples.append(('optimizer.bin', optimizer_state, 'Optimizer state'))
    
    # Create files
    BENIGN_CORPUS.mkdir(parents=True, exist_ok=True)
    
    for filename, data, description in samples:
        filepath = BENIGN_CORPUS / filename
        with open(filepath, 'wb') as f:
            pickle.dump(data, f)
        
        corpus.register_sample(
            filepath,
            CorpusType.BENIGN,
            RiskLevel.SAFE,
            description
        )
    
    return len(samples)


def create_malicious_samples():
    """
    Create synthetic malicious pickle samples for testing.
    
    WARNING: These are for testing only. They contain patterns that
    would execute code if unpickled without protection.
    """
    MALICIOUS_CORPUS.mkdir(parents=True, exist_ok=True)
    samples_created = 0
    
    # Create malicious pickle using pickle protocol
    # This creates a pickle that would call os.system
    class MaliciousPickle:
        def __reduce__(self):
            import os
            return (os.system, ('echo pwned',))
    
    # os.system payload
    try:
        filepath = MALICIOUS_CORPUS / "os_system_payload.pkl"
        with open(filepath, 'wb') as f:
            # We'll create a minimal malicious pickle manually
            # GLOBAL os system + REDUCE
            malicious_bytes = (
                b'\x80\x04\x95\x1a\x00\x00\x00\x00\x00\x00\x00'  # Protocol 4 header
                b'\x8c\x02os\x94'  # SHORT_BINUNICODE "os"
                b'\x8c\x06system\x94'  # SHORT_BINUNICODE "system"
                b'\x93'  # STACK_GLOBAL
                b'\x8c\x0becho pwned\x94'  # STRING arg
                b'\x85'  # TUPLE1
                b'R'  # REDUCE
                b'.'  # STOP
            )
            f.write(malicious_bytes)
        
        corpus.register_sample(
            filepath,
            CorpusType.MALICIOUS,
            RiskLevel.CRITICAL,
            "os.system RCE payload"
        )
        samples_created += 1
    except Exception:
        pass
    
    # subprocess payload
    try:
        filepath = MALICIOUS_CORPUS / "subprocess_payload.pkl"
        with open(filepath, 'wb') as f:
            malicious_bytes = (
                b'\x80\x04\x95\x2a\x00\x00\x00\x00\x00\x00\x00'
                b'\x8c\nsubprocess\x94'
                b'\x8c\x05Popen\x94'
                b'\x93'
                b'\x8c\x04echo\x94'
                b'\x85'
                b'R'
                b'.'
            )
            f.write(malicious_bytes)
        
        corpus.register_sample(
            filepath,
            CorpusType.MALICIOUS,
            RiskLevel.CRITICAL,
            "subprocess.Popen RCE payload"
        )
        samples_created += 1
    except Exception:
        pass
    
    # builtins exec payload
    try:
        filepath = MALICIOUS_CORPUS / "exec_payload.pkl"
        with open(filepath, 'wb') as f:
            malicious_bytes = (
                b'\x80\x04\x95\x25\x00\x00\x00\x00\x00\x00\x00'
                b'\x8c\x08builtins\x94'
                b'\x8c\x04exec\x94'
                b'\x93'
                b'\x8c\x0cprint("hi")\x94'
                b'\x85'
                b'R'
                b'.'
            )
            f.write(malicious_bytes)
        
        corpus.register_sample(
            filepath,
            CorpusType.MALICIOUS,
            RiskLevel.CRITICAL,
            "builtins.exec RCE payload"
        )
        samples_created += 1
    except Exception:
        pass
    
    return samples_created


def create_adversarial_samples():
    """
    Create obfuscated/adversarial samples for testing.
    """
    ADVERSARIAL_CORPUS.mkdir(parents=True, exist_ok=True)
    samples_created = 0
    
    # Nested reduce (obfuscated)
    try:
        filepath = ADVERSARIAL_CORPUS / "nested_reduce.pkl"
        with open(filepath, 'wb') as f:
            # Multiple nested REDUCEs trying to hide the payload
            obfuscated = (
                b'\x80\x04\x95\x30\x00\x00\x00\x00\x00\x00\x00'
                b'\x8c\x08builtins\x94'
                b'\x8c\x07getattr\x94'
                b'\x93'
                b'\x8c\x02os\x94'
                b'\x8c\x06system\x94'
                b'\x86'
                b'R'
                b'\x8c\x05echo \x94'
                b'\x85'
                b'R'
                b'.'
            )
            f.write(obfuscated)
        
        corpus.register_sample(
            filepath,
            CorpusType.ADVERSARIAL,
            RiskLevel.CRITICAL,
            "Obfuscated via nested getattr -> os.system"
        )
        samples_created += 1
    except Exception:
        pass
    
    # Import module obfuscation
    try:
        filepath = ADVERSARIAL_CORPUS / "import_obfuscated.pkl"
        with open(filepath, 'wb') as f:
            obfuscated = (
                b'\x80\x04\x95\x35\x00\x00\x00\x00\x00\x00\x00'
                b'\x8c\timportlib\x94'
                b'\x8c\rimport_module\x94'
                b'\x93'
                b'\x8c\x02os\x94'
                b'\x85'
                b'R'
                b'\x8c\x06system\x94'
                b'\x86'
                b'R'
                b'.'
            )
            f.write(obfuscated)
        
        corpus.register_sample(
            filepath,
            CorpusType.ADVERSARIAL,
            RiskLevel.CRITICAL,
            "Obfuscated via importlib.import_module"
        )
        samples_created += 1
    except Exception:
        pass
    
    return samples_created


def initialize_corpus():
    """Initialize the reference corpus with all sample types"""
    benign = create_benign_samples()
    malicious = create_malicious_samples()
    adversarial = create_adversarial_samples()
    
    return {
        'benign': benign,
        'malicious': malicious,
        'adversarial': adversarial,
        'total': benign + malicious + adversarial
    }
