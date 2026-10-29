"""Configuration constants for ModelHarrier."""

from pathlib import Path
import os

MODEL_HARRIER_DIR = Path(os.environ.get("MODEL_HARRIER_HOME", Path.home() / ".model-harrier")).expanduser()
MODEL_HARRIER_CACHE_DIR = Path(os.environ.get("MODEL_HARRIER_CACHE_DIR", Path.home() / ".cache" / "model-harrier")).expanduser()
LEGACY_DIR = Path.home() / ".ai-eye"
DB_PATH = MODEL_HARRIER_DIR / "model-harrier.db"
if not DB_PATH.exists() and (LEGACY_DIR / "ai-eye.db").exists():
    DB_PATH = LEGACY_DIR / "ai-eye.db"

CRITICAL_THRESHOLD = 80
HIGH_THRESHOLD = 60
MEDIUM_THRESHOLD = 40

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

TRAINER_SIGNATURES = [
    "training_args",
    "trainer_state",
    "optimizer",
    "scheduler",
    "rng_state",
]

HF_API_BASE = "https://huggingface.co/api/models"
