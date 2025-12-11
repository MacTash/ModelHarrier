"""
AI-Eye Backend Configuration
"""
import os
from pathlib import Path

# Base paths
BACKEND_DIR = Path(__file__).parent
CORPUS_DIR = BACKEND_DIR / "corpus_samples"
DATA_DIR = BACKEND_DIR / "data"

# Ensure data directory exists
DATA_DIR.mkdir(exist_ok=True)

# Database
TELEMETRY_DB = DATA_DIR / "telemetry.db"

# Corpus paths
BENIGN_CORPUS = CORPUS_DIR / "benign"
MALICIOUS_CORPUS = CORPUS_DIR / "malicious"
ADVERSARIAL_CORPUS = CORPUS_DIR / "adversarial"

# Server config
HOST = os.getenv("AIEYE_HOST", "0.0.0.0")
PORT = int(os.getenv("AIEYE_PORT", "5001"))
DEBUG = os.getenv("AIEYE_DEBUG", "true").lower() == "true"

# Scheduled jobs
CORPUS_CHECK_HOUR = int(os.getenv("CORPUS_CHECK_HOUR", "3"))  # Run at 3 AM
CORPUS_CHECK_MINUTE = int(os.getenv("CORPUS_CHECK_MINUTE", "0"))

# Risk score thresholds
CRITICAL_THRESHOLD = 80
HIGH_THRESHOLD = 60
MEDIUM_THRESHOLD = 40

# Opcode risk weights
DANGEROUS_OPCODES = {
    "GLOBAL": 10,
    "REDUCE": 15,
    "BUILD": 8,
    "INST": 12,
    "OBJ": 12,
    "NEWOBJ": 10,
    "NEWOBJ_EX": 10,
    "STACK_GLOBAL": 10,
}

# Dangerous module patterns
DANGEROUS_MODULES = [
    "os",
    "subprocess",
    "sys",
    "builtins",
    "commands",
    "pty",
    "socket",
    "posix",
    "nt",
    "importlib",
    "__builtin__",
]

# Dangerous callable patterns
DANGEROUS_CALLABLES = [
    "system",
    "popen",
    "spawn",
    "exec",
    "eval",
    "compile",
    "open",
    "run",
    "call",
    "Popen",
    "check_output",
    "check_call",
    "getattr",
    "setattr",
    "delattr",
    "__import__",
    "load_module",
    "import_module",
]

# PEFT adapter signatures
PEFT_SIGNATURES = [
    "lora_A",
    "lora_B",
    "lora_embedding_A",
    "lora_embedding_B",
    "adapter_",
    "prefix_encoder",
    "prompt_encoder",
    "soft_prompt",
]

# Trainer output signatures
TRAINER_SIGNATURES = [
    "training_args",
    "trainer_state",
    "optimizer",
    "scheduler",
    "rng_state",
]
