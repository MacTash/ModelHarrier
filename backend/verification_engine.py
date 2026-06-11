"""
AI-Eye Verification Engine

Core verification logic integrating:
- pickletools for opcode-level disassembly
- fickling for RCE detection
- PEFT artifact signature matching
- Sandbox loader with blocked imports
"""
import io
import hashlib
import pickle
import pickletools
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum

# Try to import fickling - may not be installed
try:
    from fickling.fickle import Pickled
    from fickling.analysis import check_safety
    FICKLING_AVAILABLE = True
except ImportError:
    FICKLING_AVAILABLE = False

try:
    import picklescan.scanner as picklescan_scanner
    PICKLESCAN_AVAILABLE = True
except ImportError:
    PICKLESCAN_AVAILABLE = False

try:
    import tensortrap
    TENSORTRAP_AVAILABLE = True
except ImportError:
    TENSORTRAP_AVAILABLE = False

from config import (
    DANGEROUS_OPCODES,
    DANGEROUS_MODULES,
    DANGEROUS_CALLABLES,
    PEFT_SIGNATURES,
    TRAINER_SIGNATURES,
    CRITICAL_THRESHOLD,
    HIGH_THRESHOLD,
    MEDIUM_THRESHOLD,
)


class RiskLevel(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    SAFE = "safe"


@dataclass
class OpcodeInfo:
    """Information about a pickle opcode"""
    name: str
    arg: Optional[str]
    position: int
    risk_score: int = 0


@dataclass
class GlobalReference:
    """A GLOBAL/STACK_GLOBAL reference in pickle"""
    module: str
    name: str
    position: int
    is_dangerous: bool = False
    reason: str = ""


@dataclass
class PickletoolsResult:
    """Results from pickletools analysis"""
    opcodes: list[OpcodeInfo] = field(default_factory=list)
    opcode_counts: dict[str, int] = field(default_factory=dict)
    global_refs: list[GlobalReference] = field(default_factory=list)
    has_reduce: bool = False
    has_global: bool = False
    raw_disassembly: str = ""
    risk_score: int = 0
    risk_level: RiskLevel = RiskLevel.SAFE


@dataclass
class FicklingResult:
    """Results from fickling analysis"""
    is_safe: bool = True
    is_likely_safe: bool = True
    findings: list[str] = field(default_factory=list)
    injected_code: list[str] = field(default_factory=list)
    available: bool = True


@dataclass
class SandboxResult:
    """Results from sandbox load attempt"""
    load_succeeded: bool = False
    blocked_imports: list[str] = field(default_factory=list)
    error: Optional[str] = None
    loaded_type: Optional[str] = None


@dataclass
class PeftMatchResult:
    """Results from PEFT/Trainer signature matching"""
    is_peft_adapter: bool = False
    is_trainer_output: bool = False
    matched_signatures: list[str] = field(default_factory=list)
    confidence: float = 0.0


@dataclass
class PicklescanResult:
    """Results from picklescan CVE database scan"""
    available: bool = True
    issues: list[dict] = field(default_factory=list)
    vulnerable: bool = False
    scan_error: Optional[str] = None


@dataclass
class TensorTrapResult:
    """Results from TensorTrap model file scan"""
    available: bool = True
    is_suspicious: bool = False
    findings: list[str] = field(default_factory=list)
    risk_score: float = 0.0
    model_type: Optional[str] = None
    scan_error: Optional[str] = None


@dataclass
class TriangulationResult:
    """Combined result from all verification tools"""
    file_hash: str
    file_size: int
    
    # Individual tool results
    aieye_result: RiskLevel = RiskLevel.SAFE
    aieye_score: int = 0
    pickletools_result: PickletoolsResult = field(default_factory=PickletoolsResult)
    fickling_result: FicklingResult = field(default_factory=FicklingResult)
    sandbox_result: SandboxResult = field(default_factory=SandboxResult)
    peft_result: PeftMatchResult = field(default_factory=PeftMatchResult)
    
    picklescan_result: PicklescanResult = field(default_factory=PicklescanResult)
    tensortrap_result: TensorTrapResult = field(default_factory=TensorTrapResult)

    # Triangulated conclusion
    consensus: Optional[RiskLevel] = None
    is_false_positive: bool = False
    is_false_negative: bool = False
    confidence: float = 0.0
    reasoning: list[str] = field(default_factory=list)


class VerificationEngine:
    """
    Core verification engine that triangulates results from multiple tools.
    """
    
    def __init__(self):
        self.fickling_available = FICKLING_AVAILABLE
    
    def compute_hash(self, data: bytes) -> str:
        """Compute SHA256 hash of pickle data"""
        return hashlib.sha256(data).hexdigest()
    
    def analyze_with_pickletools(self, data: bytes) -> PickletoolsResult:
        """
        Analyze pickle using pickletools for opcode-level inspection.
        """
        result = PickletoolsResult()
        
        try:
            # Get disassembly
            output = io.StringIO()
            pickletools.dis(io.BytesIO(data), output)
            result.raw_disassembly = output.getvalue()
            
            # Parse opcodes
            for opcode, arg, pos in pickletools.genops(io.BytesIO(data)):
                opcode_name = opcode.name
                
                # Track opcode counts
                result.opcode_counts[opcode_name] = result.opcode_counts.get(opcode_name, 0) + 1
                
                # Calculate risk score for this opcode
                risk = DANGEROUS_OPCODES.get(opcode_name, 0)
                
                result.opcodes.append(OpcodeInfo(
                    name=opcode_name,
                    arg=str(arg) if arg is not None else None,
                    position=pos,
                    risk_score=risk
                ))
                
                result.risk_score += risk
                
                # Track specific dangerous patterns
                if opcode_name == "REDUCE":
                    result.has_reduce = True
                
                if opcode_name in ("GLOBAL", "STACK_GLOBAL"):
                    result.has_global = True
                    
                    # Parse module.callable
                    if arg:
                        parts = str(arg).split(" ", 1) if " " in str(arg) else [str(arg), ""]
                        module = parts[0] if parts else ""
                        name = parts[1] if len(parts) > 1 else ""
                        
                        is_dangerous = False
                        reason = ""
                        
                        # Check if module is dangerous
                        for dangerous_mod in DANGEROUS_MODULES:
                            if dangerous_mod in module.lower():
                                is_dangerous = True
                                reason = f"Dangerous module: {dangerous_mod}"
                                result.risk_score += 25
                                break
                        
                        # Check if callable is dangerous
                        if not is_dangerous:
                            for dangerous_call in DANGEROUS_CALLABLES:
                                if dangerous_call in name.lower():
                                    is_dangerous = True
                                    reason = f"Dangerous callable: {dangerous_call}"
                                    result.risk_score += 20
                                    break
                        
                        result.global_refs.append(GlobalReference(
                            module=module,
                            name=name,
                            position=pos,
                            is_dangerous=is_dangerous,
                            reason=reason
                        ))
            
            # Determine risk level
            if result.risk_score >= CRITICAL_THRESHOLD:
                result.risk_level = RiskLevel.CRITICAL
            elif result.risk_score >= HIGH_THRESHOLD:
                result.risk_level = RiskLevel.HIGH
            elif result.risk_score >= MEDIUM_THRESHOLD:
                result.risk_level = RiskLevel.MEDIUM
            elif result.risk_score > 0:
                result.risk_level = RiskLevel.LOW
            else:
                result.risk_level = RiskLevel.SAFE
                
        except Exception as e:
            result.raw_disassembly = f"Error: {str(e)}"
            result.risk_level = RiskLevel.HIGH  # Assume risky if we can't parse
            
        return result
    
    def analyze_with_fickling(self, data: bytes) -> FicklingResult:
        """
        Analyze pickle using fickling for RCE detection.
        """
        result = FicklingResult()
        
        if not FICKLING_AVAILABLE:
            result.available = False
            result.findings.append("fickling not installed")
            return result
        
        try:
            pickled = Pickled.load(io.BytesIO(data))
            
            # Check safety
            safety_result = check_safety(pickled)
            result.is_safe = safety_result.is_safe
            result.is_likely_safe = safety_result.is_likely_safe if hasattr(safety_result, 'is_likely_safe') else safety_result.is_safe
            
            # Get findings
            if hasattr(safety_result, 'findings'):
                result.findings = [str(f) for f in safety_result.findings]
            
            # Check for injected code
            if hasattr(pickled, 'properties') and hasattr(pickled.properties, 'has_import'):
                if pickled.properties.has_import:
                    result.findings.append("Contains import statements")
                    result.is_safe = False
            
        except Exception as e:
            result.findings.append(f"Analysis error: {str(e)}")
            result.is_safe = False  # Assume unsafe if we can't analyze
            
        return result
    
    def analyze_with_picklescan(self, data: bytes) -> PicklescanResult:
        """
        Scan pickle bytes against picklescan CVE database.
        Detects known malicious pickle patterns like:
        - GHSA-vvpj-8cmc-gx39 (pkgutil.resolve_name bypass, CVSS 10.0)
        - GHSA-5x36-vg95-r43c (subprocess.check_output misuse)
        - General unsafe opcode combinations
        """
        result = PicklescanResult()

        if not PICKLESCAN_AVAILABLE:
            result.available = False
            return result

        try:
            scan_result = picklescan_scanner.scan_pickle(data)
            result.vulnerable = scan_result.vulnerable
            result.issues = [
                {
                    "cve": getattr(issue, "cve", None),
                    "severity": getattr(issue, "severity", "unknown"),
                    "description": getattr(issue, "description", str(issue)),
                    "opcode": getattr(issue, "opcode", None),
                }
                for issue in getattr(scan_result, "issues", [])
            ]
        except Exception as e:
            result.scan_error = str(e)

        return result

    def analyze_with_tensortrap(self, data: bytes) -> TensorTrapResult:
        """
        Scan bytes for PyTorch / TensorFlow / Keras / JAX model indicators.
        TensorTrap checks for suspicious __reduce__ usage, unsafe globals,
        and known model-bug patterns in serialized ML frameworks.
        """
        result = TensorTrapResult()

        if not TENSORTRAP_AVAILABLE:
            result.available = False
            return result

        try:
            tt_result = tensortrap.scan_bytes(data)
            result.is_suspicious = getattr(tt_result, "is_suspicious", False)
            result.risk_score = getattr(tt_result, "risk_score", 0.0)
            result.model_type = getattr(tt_result, "model_type", None)
            result.findings = [
                str(f) for f in getattr(tt_result, "findings", [])
            ]
        except Exception as e:
            result.scan_error = str(e)

        return result

    def analyze_in_sandbox(self, data: bytes) -> SandboxResult:
        """
        Attempt to load pickle in sandbox with blocked imports.
        """
        result = SandboxResult()
        
        class RestrictedUnpickler(pickle.Unpickler):
            """Unpickler that blocks dangerous imports"""
            
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.blocked = []
            
            def find_class(self, module, name):
                # Block dangerous modules
                for dangerous in DANGEROUS_MODULES:
                    if dangerous in module.lower():
                        self.blocked.append(f"{module}.{name}")
                        raise pickle.UnpicklingError(f"Blocked: {module}.{name}")
                
                # Block dangerous callables
                for dangerous in DANGEROUS_CALLABLES:
                    if dangerous in name.lower():
                        self.blocked.append(f"{module}.{name}")
                        raise pickle.UnpicklingError(f"Blocked: {module}.{name}")
                
                # Allow safe imports
                return super().find_class(module, name)
        
        try:
            unpickler = RestrictedUnpickler(io.BytesIO(data))
            obj = unpickler.load()
            result.load_succeeded = True
            result.loaded_type = type(obj).__name__
            result.blocked_imports = unpickler.blocked
        except pickle.UnpicklingError as e:
            result.error = str(e)
            result.blocked_imports = [str(e).replace("Blocked: ", "")]
        except Exception as e:
            result.error = str(e)
            
        return result
    
    def check_peft_signatures(self, data: bytes) -> PeftMatchResult:
        """
        Check if pickle contains PEFT adapter or Trainer output signatures.
        """
        result = PeftMatchResult()
        
        # Convert to string for pattern matching
        data_str = data.decode('latin-1', errors='replace')
        
        # Check PEFT signatures
        peft_matches = 0
        for sig in PEFT_SIGNATURES:
            if sig in data_str:
                result.matched_signatures.append(f"PEFT: {sig}")
                peft_matches += 1
        
        if peft_matches >= 2:
            result.is_peft_adapter = True
            result.confidence = min(1.0, peft_matches / len(PEFT_SIGNATURES))
        
        # Check Trainer signatures
        trainer_matches = 0
        for sig in TRAINER_SIGNATURES:
            if sig in data_str:
                result.matched_signatures.append(f"Trainer: {sig}")
                trainer_matches += 1
        
        if trainer_matches >= 2:
            result.is_trainer_output = True
            result.confidence = max(result.confidence, min(1.0, trainer_matches / len(TRAINER_SIGNATURES)))
        
        return result
    
    def triangulate(self, data: bytes, aieye_score: int = 0) -> TriangulationResult:
        """
        Run all verification tools and triangulate results.
        
        Decision logic:
        - If AIEye=risky, fickling=safe, pickletools=no dangerous ops → False Positive
        - If AIEye=safe, fickling=unsafe → False Negative
        - If all tools agree → High confidence result
        """
        result = TriangulationResult(
            file_hash=self.compute_hash(data),
            file_size=len(data)
        )
        
        # Run all analyses
        result.pickletools_result = self.analyze_with_pickletools(data)
        result.fickling_result = self.analyze_with_fickling(data)
        result.picklescan_result = self.analyze_with_picklescan(data)
        result.tensortrap_result = self.analyze_with_tensortrap(data)
        result.sandbox_result = self.analyze_in_sandbox(data)
        result.peft_result = self.check_peft_signatures(data)
        
        # AIEye score (passed from frontend or calculated)
        result.aieye_score = aieye_score
        if aieye_score >= CRITICAL_THRESHOLD:
            result.aieye_result = RiskLevel.CRITICAL
        elif aieye_score >= HIGH_THRESHOLD:
            result.aieye_result = RiskLevel.HIGH
        elif aieye_score >= MEDIUM_THRESHOLD:
            result.aieye_result = RiskLevel.MEDIUM
        elif aieye_score > 0:
            result.aieye_result = RiskLevel.LOW
        else:
            result.aieye_result = RiskLevel.SAFE
        
        # Triangulation logic
        risky_signals = 0
        safe_signals = 0
        
        # Pickletools signals
        pt = result.pickletools_result
        if pt.has_reduce and any(g.is_dangerous for g in pt.global_refs):
            risky_signals += 2
            result.reasoning.append("pickletools: REDUCE with dangerous GLOBAL detected")
        elif pt.has_global and any(g.is_dangerous for g in pt.global_refs):
            risky_signals += 1
            result.reasoning.append("pickletools: Dangerous GLOBAL reference detected")
        elif not pt.has_reduce and not any(g.is_dangerous for g in pt.global_refs):
            safe_signals += 1
            result.reasoning.append("pickletools: No dangerous opcodes detected")
        
        # Picklescan signals (CVE database scan)
        ps = result.picklescan_result
        if ps.available:
            if ps.vulnerable:
                risky_signals += 3
                cves = [i.get("cve") or "unknown" for i in ps.issues[:3]]
                result.reasoning.append(
                    f"picklescan: Vulnerable to {len(ps.issues)} issue(s) — {', '.join(cves)}"
                )
            else:
                safe_signals += 1
                result.reasoning.append("picklescan: No known CVEs detected")

        # TensorTrap signals (ML framework scan)
        tt = result.tensortrap_result
        if tt.available:
            if tt.is_suspicious:
                risky_signals += 2
                result.reasoning.append(
                    f"tensortrap: Suspicious pattern(s) in {tt.model_type or 'unknown model'} — {', '.join(tt.findings[:3])}"
                )
            else:
                safe_signals += 1
                result.reasoning.append("tensortrap: No suspicious ML patterns detected")

        # Fickling signals
        if result.fickling_result.available:
            if not result.fickling_result.is_safe:
                risky_signals += 2
                result.reasoning.append(f"fickling: Unsafe - {', '.join(result.fickling_result.findings[:3])}")
            elif result.fickling_result.is_likely_safe:
                safe_signals += 1
                result.reasoning.append("fickling: Likely safe")
        
        # Sandbox signals
        if result.sandbox_result.load_succeeded:
            safe_signals += 1
            result.reasoning.append(f"sandbox: Loaded successfully as {result.sandbox_result.loaded_type}")
        elif result.sandbox_result.blocked_imports:
            risky_signals += 2
            result.reasoning.append(f"sandbox: Blocked imports - {', '.join(result.sandbox_result.blocked_imports[:3])}")
        
        # PEFT/Trainer signals (reduce risk for known patterns)
        if result.peft_result.is_peft_adapter or result.peft_result.is_trainer_output:
            safe_signals += 1
            pattern = "PEFT adapter" if result.peft_result.is_peft_adapter else "Trainer output"
            result.reasoning.append(f"signature: Known {pattern} pattern detected")
        
        # Determine consensus
        total_signals = risky_signals + safe_signals
        if total_signals > 0:
            risk_ratio = risky_signals / total_signals
            
            if risk_ratio >= 0.7:
                result.consensus = RiskLevel.CRITICAL if risky_signals >= 4 else RiskLevel.HIGH
            elif risk_ratio >= 0.4:
                result.consensus = RiskLevel.MEDIUM
            elif risk_ratio > 0:
                result.consensus = RiskLevel.LOW
            else:
                result.consensus = RiskLevel.SAFE
            
            result.confidence = abs(0.5 - risk_ratio) * 2  # 0 at 50/50, 1 at unanimous
        else:
            result.consensus = RiskLevel.LOW
            result.confidence = 0.3
        
        # Detect FP/FN
        aieye_risky = result.aieye_result in (RiskLevel.CRITICAL, RiskLevel.HIGH)
        tools_safe = (
            not result.fickling_result.available or result.fickling_result.is_safe
        ) and (
            not pt.has_reduce or not any(g.is_dangerous for g in pt.global_refs)
        )
        tools_risky = (
            result.fickling_result.available and not result.fickling_result.is_safe
        ) or (
            pt.has_reduce and any(g.is_dangerous for g in pt.global_refs)
        )
        
        if aieye_risky and tools_safe:
            result.is_false_positive = True
            result.reasoning.append("⚠️ POTENTIAL FALSE POSITIVE: AIEye flagged but tools show safe")
        
        if not aieye_risky and tools_risky:
            result.is_false_negative = True
            result.reasoning.append("🚨 POTENTIAL FALSE NEGATIVE: AIEye missed but tools show risky")
        
        return result
    
    def verify_pickle(self, data: bytes) -> TriangulationResult:
        """
        Main entry point for pickle verification.
        """
        return self.triangulate(data)


# Singleton instance
engine = VerificationEngine()


def verify_pickle_file(filepath: str) -> TriangulationResult:
    """Verify a pickle file from disk"""
    with open(filepath, 'rb') as f:
        data = f.read()
    return engine.verify_pickle(data)


def verify_pickle_bytes(data: bytes) -> TriangulationResult:
    """Verify pickle bytes directly"""
    return engine.verify_pickle(data)
