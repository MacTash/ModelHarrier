"""Format scanner registry with content-first dispatch for common wrappers."""

import pickletools
from pathlib import Path

from model_harrier.scan.formats.safetensors import scan_safetensors
from model_harrier.scan.formats.gguf import scan_gguf
from model_harrier.scan.formats.onnx import scan_onnx
from model_harrier.scan.formats.keras import scan_keras
from model_harrier.scan.formats.archive import scan_archive
from model_harrier.scan.formats.tokenizer import scan_tokenizer


SCANNERS = {
    ".safetensors": scan_safetensors,
    ".gguf": scan_gguf,
    ".onnx": scan_onnx,
    ".h5": scan_keras,
    ".keras": scan_keras,
    ".hdf5": scan_keras,
    ".zip": scan_archive,
    ".tar": scan_archive,
    ".tar.gz": scan_archive,
    ".tgz": scan_archive,
    ".gz": scan_archive,
    ".bz2": scan_archive,
    ".xz": scan_archive,
    ".7z": scan_archive,
    ".json": None,
}


def scan_file(filename: str, data: bytes) -> list[dict]:
    ext = detect_format(filename, data)
    original_ext = _get_extension(filename)
    archive_extensions = {".zip", ".tar", ".tar.gz", ".tgz", ".gz", ".bz2", ".xz", ".7z"}
    pickle_extensions = {".pkl", ".pickle", ".dill", ".joblib", ".pt", ".pth", ".ckpt", ".bin"}
    compatible = (ext == "archive" and original_ext in archive_extensions) or (ext == "pickle" and original_ext in pickle_extensions)
    mismatch = ext != original_ext and ext not in ("unknown", "") and not compatible
    scanner = SCANNERS.get(ext)
    if scanner is None:
        if ext == "pickle":
            from model_harrier.scan.pickles import verify_pickle_bytes

            result = verify_pickle_bytes(data)
            verdict = result.consensus.value if result.consensus else result.aieye_result.value
            findings = [{"issue": "pickle_static_analysis", "severity": verdict, "description": reason} for reason in result.reasoning]
            if not findings:
                findings.append({"issue": "pickle_inspected", "severity": "info", "description": f"Pickle opcodes inspected; verdict {verdict}"})
        elif ext == ".json" and "tokenizer" in filename.lower():
            findings = scan_tokenizer(data)
        else:
            findings = []
    elif ext in (".zip", ".tar", ".tar.gz", ".tgz", ".gz", ".bz2", ".xz", ".7z", "archive"):
        findings = scan_archive(data)
    elif ext == "executable":
        findings = [{"issue": "executable_content", "severity": "high", "description": "File content has a native executable signature"}]
    else:
        findings = scanner(data)

    if mismatch:
        findings.insert(0, {"issue": "content_extension_mismatch", "severity": "medium", "description": f"Content looks like {ext}, but filename ends with {original_ext or '[no extension]'}"})
    return findings


def detect_format(filename: str, data: bytes) -> str:
    """Identify formats from signatures before trusting the suffix."""
    if data.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08", b"\x1f\x8b", b"BZh", b"\xfd7zXZ\x00", b"7z\xbc\xaf'\x1c")):
        return "archive"
    if len(data) >= 262 and data[257:262] == b"ustar":
        return "archive"
    if data.startswith(b"GGUF"):
        return ".gguf"
    if data.startswith(b"\x7fELF") or data.startswith(b"MZ"):
        return "executable"

    ext = _get_extension(filename)
    if ext in (".pkl", ".pickle", ".dill", ".joblib", ".pt", ".pth", ".ckpt", ".bin"):
        return "pickle" if _looks_like_pickle(data) or ext in (".pkl", ".pickle", ".dill", ".joblib") else ext
    if _looks_like_pickle(data):
        return "pickle"
    if ext:
        return ext
    return "unknown"


def _looks_like_pickle(data: bytes) -> bool:
    if len(data) < 3 or data[0] != 0x80 or data[1] not in (2, 3, 4, 5):
        return False
    try:
        return any(opcode.name == "STOP" for opcode, _arg, _pos in pickletools.genops(data))
    except Exception:
        return False


def _get_extension(filename: str) -> str:
    lower = filename.lower()
    if lower.endswith(".tar.gz"):
        return ".tar.gz"
    if lower.endswith(".tgz"):
        return ".tgz"
    return Path(lower).suffix
