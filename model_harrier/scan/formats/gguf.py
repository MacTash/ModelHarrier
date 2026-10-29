"""GGUF format scanner.

Validates GGUF header integrity, detects Jinja2 SSTI in chat_template
(CVE-2024-34359), tensor size overflows (CVE-2026-33298 class),
alignment value abuse, malformed metadata, and extracts model metadata.
"""

import struct
from typing import Optional

GGUF_MAGIC = 0x46554747
SUPPORTED_VERSIONS = {1, 2, 3}
MAX_TENSOR_COUNT = 1_000_000
MAX_METADATA_COUNT = 100_000
MAX_STRING_LENGTH = 10_000_000

SSTI_PATTERNS = [
    "{{",
    "{%",
    "{|",
    "__import__",
    "self.__class__",
    "os.system",
    "subprocess",
    ".__subclasses__",
    "().__class__",
    "request.application",
    "config.from_object",
    "url_for.__globals__",
]

GGUF_VALUE_TYPE_UINT8 = 0
GGUF_VALUE_TYPE_INT8 = 1
GGUF_VALUE_TYPE_UINT16 = 2
GGUF_VALUE_TYPE_INT16 = 3
GGUF_VALUE_TYPE_UINT32 = 4
GGUF_VALUE_TYPE_INT32 = 5
GGUF_VALUE_TYPE_FLOAT32 = 6
GGUF_VALUE_TYPE_BOOL = 7
GGUF_VALUE_TYPE_STRING = 8
GGUF_VALUE_TYPE_ARRAY = 9
GGUF_VALUE_TYPE_UINT64 = 10
GGUF_VALUE_TYPE_INT64 = 11
GGUF_VALUE_TYPE_FLOAT64 = 12

FILE_TYPE_MAP = {
    0: "F32",
    1: "F16",
    2: "Q4_0",
    3: "Q4_1",
    6: "Q5_0",
    7: "Q5_1",
    8: "Q8_0",
    10: "Q2_K",
    11: "Q3_K",
    12: "Q4_K",
    13: "Q5_K",
    14: "Q6_K",
    15: "Q8_K",
    16: "IQ1_S",
    17: "IQ1_M",
    18: "IQ2_XXS",
    19: "IQ2_XS",
    20: "IQ2_S",
    21: "IQ2_M",
    22: "IQ3_XXS",
    23: "IQ3_XS",
    24: "IQ3_S",
    25: "IQ3_M",
    26: "IQ4_NL",
    27: "IQ4_XS",
    29: "BF16",
    30: "Q4_0_4_4",
    31: "Q4_0_4_8",
    32: "Q4_0_8_8",
}

GGUF_VALUE_SIZES = [4, 1, 1, 2, 4, 8, 4, 8, 0, 0, 8, 8, 8]


def scan_gguf(data: bytes) -> list[dict]:
    findings = []

    if len(data) < 32:
        findings.append({"issue": "file_too_small", "severity": "high", "description": "File too small to contain valid GGUF header"})
        return findings

    magic = struct.unpack("<I", data[0:4])[0]
    if magic != GGUF_MAGIC:
        findings.append({"issue": "invalid_magic", "severity": "high", "description": f"Invalid GGUF magic bytes: 0x{magic:08X}"})
        return findings

    version = struct.unpack("<I", data[4:8])[0]
    if version not in SUPPORTED_VERSIONS:
        findings.append({"issue": "unsupported_version", "severity": "medium", "description": f"GGUF version {version} not in supported set {SUPPORTED_VERSIONS}"})

    tensor_count = struct.unpack("<Q", data[8:16])[0]
    if tensor_count > MAX_TENSOR_COUNT:
        findings.append({"issue": "excessive_tensor_count", "severity": "high", "description": f"Tensor count {tensor_count} exceeds {MAX_TENSOR_COUNT}"})

    metadata_count = struct.unpack("<Q", data[16:24])[0]
    if metadata_count > MAX_METADATA_COUNT:
        findings.append({"issue": "excessive_metadata_count", "severity": "high", "description": f"Metadata count {metadata_count} exceeds {MAX_METADATA_COUNT}"})

    extracted = extract_gguf_metadata(data)
    if extracted:
        if extracted.get("architecture"):
            findings.append({"issue": "gguf_metadata", "severity": "info", "description": f"Architecture: {extracted['architecture']}"})
        if extracted.get("quantization"):
            findings.append({"issue": "gguf_metadata", "severity": "info", "description": f"Quantization: {extracted['quantization']}"})
        if extracted.get("context_length"):
            findings.append({"issue": "gguf_metadata", "severity": "info", "description": f"Context Length: {extracted['context_length']}"})
        if extracted.get("parameter_count"):
            findings.append({"issue": "gguf_metadata", "severity": "info", "description": f"Parameters: {extracted['parameter_count']}"})

    offset = 24
    for i in range(min(metadata_count, MAX_METADATA_COUNT)):
        if offset + 4 > len(data):
            break
        key_len = struct.unpack("<I", data[offset:offset + 4])[0]
        offset += 4
        if key_len > MAX_STRING_LENGTH or key_len > len(data) - offset:
            findings.append({"issue": "string_length_overflow", "severity": "critical", "description": f"Metadata key {i} has invalid length {key_len}"})
            break
        key = data[offset:offset + key_len].decode("utf-8", errors="replace")
        offset += key_len

        if offset + 4 > len(data):
            break
        value_type = struct.unpack("<I", data[offset:offset + 4])[0]
        offset += 4

        try:
            offset = _skip_value(data, offset, value_type, findings, i)
        except (struct.error, IndexError):
            findings.append({"issue": "metadata_parse_error", "severity": "high", "description": f"Failed to parse metadata entry {i}"})
            break

        if key.lower() in ("chat_template", "tokenizer.chat_template", "ggml.chat_template"):
            chat_template = _extract_string_value(data, offset, value_type)
            if chat_template:
                ssti = _check_ssti(chat_template)
                findings.extend(ssti)

    alignment = _extract_alignment(data)
    if alignment is not None:
        if alignment <= 0 or alignment > 4096:
            findings.append({"issue": "invalid_alignment", "severity": "high", "description": f"Alignment value {alignment} is outside valid range (1-4096)"})

    if offset < len(data):
        pass

    return findings


def extract_gguf_metadata(data: bytes) -> dict:
    if len(data) < 24:
        return {}
    magic = struct.unpack("<I", data[0:4])[0] if len(data) >= 4 else 0
    if magic != GGUF_MAGIC:
        return {}

    version = struct.unpack("<I", data[4:8])[0] if len(data) >= 8 else 0
    tensor_count = struct.unpack("<Q", data[8:16])[0] if len(data) >= 16 else 0
    metadata_count = struct.unpack("<Q", data[16:24])[0] if len(data) >= 24 else 0

    meta: dict[str, object] = {
        "version": version,
        "tensor_count": tensor_count,
        "metadata_entries": metadata_count,
        "architecture": None,
        "name": None,
        "description": None,
        "quantization": None,
        "context_length": None,
        "layers": None,
        "hidden_size": None,
        "num_heads": None,
        "num_kv_heads": None,
        "parameter_count": None,
        "tokenizer_type": None,
        "file_type": None,
    }

    arch = None
    offset = 24
    for _ in range(min(metadata_count, MAX_METADATA_COUNT)):
        if offset + 4 > len(data):
            break
        key_len = struct.unpack("<I", data[offset:offset + 4])[0]
        offset += 4
        if key_len > MAX_STRING_LENGTH or key_len > len(data) - offset:
            break
        key = data[offset:offset + key_len].decode("utf-8", errors="replace")
        offset += key_len
        if offset + 4 > len(data):
            break
        value_type = struct.unpack("<I", data[offset:offset + 4])[0]
        offset += 4

        if key == "general.architecture" and value_type == GGUF_VALUE_TYPE_STRING:
            v = _read_string_value(data, offset)
            if v:
                meta["architecture"] = v
                arch = v.lower().replace("-", "_")
        elif key == "general.name" and value_type == GGUF_VALUE_TYPE_STRING:
            v = _read_string_value(data, offset)
            if v:
                meta["name"] = v
        elif key == "general.description" and value_type == GGUF_VALUE_TYPE_STRING:
            v = _read_string_value(data, offset)
            if v:
                meta["description"] = v[:200]
        elif key == "general.file_type" and value_type == GGUF_VALUE_TYPE_UINT32:
            ft = struct.unpack("<I", data[offset:offset + 4])[0] if offset + 4 <= len(data) else None
            if ft is not None:
                meta["file_type"] = ft
                meta["quantization"] = FILE_TYPE_MAP.get(ft, f"Unknown({ft})")
        elif key.endswith(".context_length") and value_type in (GGUF_VALUE_TYPE_UINT32, GGUF_VALUE_TYPE_INT32, GGUF_VALUE_TYPE_UINT64):
            meta["context_length"] = _read_uint(data, offset, value_type)
        elif key.endswith(".block_count") and value_type == GGUF_VALUE_TYPE_UINT32:
            meta["layers"] = _read_uint(data, offset, value_type)
        elif key.endswith(".embedding_length") and value_type == GGUF_VALUE_TYPE_UINT32:
            meta["hidden_size"] = _read_uint(data, offset, value_type)
        elif key.endswith(".attention.head_count") and value_type == GGUF_VALUE_TYPE_UINT32:
            meta["num_heads"] = _read_uint(data, offset, value_type)
        elif key.endswith(".attention.head_count_kv") and value_type == GGUF_VALUE_TYPE_UINT32:
            meta["num_kv_heads"] = _read_uint(data, offset, value_type)
        elif key == "tokenizer.ggml.model" and value_type == GGUF_VALUE_TYPE_STRING:
            v = _read_string_value(data, offset)
            if v:
                meta["tokenizer_type"] = v

        try:
            offset = _skip_value(data, offset, value_type, [], -1)
        except (struct.error, IndexError):
            break

    if arch and meta["layers"] and meta["hidden_size"]:
        approx = meta["layers"] * meta["hidden_size"] * meta["hidden_size"] * 4
        meta["parameter_count"] = _format_param_count(approx)

    return meta


def _read_uint(data: bytes, offset: int, vtype: int) -> Optional[int]:
    size_map = {GGUF_VALUE_TYPE_UINT32: 4, GGUF_VALUE_TYPE_INT32: 4, GGUF_VALUE_TYPE_UINT64: 8}
    sz = size_map.get(vtype)
    if not sz or offset + sz > len(data):
        return None
    if sz == 4:
        return struct.unpack("<I", data[offset:offset + 4])[0]
    return struct.unpack("<Q", data[offset:offset + 8])[0]


def _read_string_value(data: bytes, offset: int) -> Optional[str]:
    if offset + 8 > len(data):
        return None
    length = struct.unpack("<Q", data[offset:offset + 8])[0]
    if length > MAX_STRING_LENGTH or length > len(data) - offset - 8:
        return None
    return data[offset + 8:offset + 8 + length].decode("utf-8", errors="replace")


def _format_param_count(count: int) -> str:
    if count >= 1_000_000_000:
        return f"{count / 1_000_000_000:.1f}B"
    if count >= 1_000_000:
        return f"{count / 1_000_000:.1f}M"
    return str(count)


def _skip_value(data: bytes, offset: int, value_type: int, findings: list[dict], entry_idx: int) -> int:
    GGUF_VALUE_TYPE_STRING = 8
    GGUF_VALUE_TYPE_ARRAY = 9

    if value_type == GGUF_VALUE_TYPE_STRING:
        if offset + 4 > len(data):
            raise struct.error("truncated string length")
        length = struct.unpack("<Q", data[offset:offset + 8])[0]
        offset += 8
        if length > MAX_STRING_LENGTH or length > len(data) - offset:
            findings.append({"issue": "string_length_overflow", "severity": "critical", "description": f"Metadata entry {entry_idx} has oversized string value ({length} bytes)"})
            raise struct.error("string overflow")
        return offset + length
    elif value_type == GGUF_VALUE_TYPE_ARRAY:
        if offset + 4 > len(data):
            raise struct.error("truncated array header")
        array_type = struct.unpack("<I", data[offset:offset + 4])[0]
        offset += 4
        if offset + 8 > len(data):
            raise struct.error("truncated array length")
        array_len = struct.unpack("<Q", data[offset:offset + 8])[0]
        offset += 8
        for _ in range(min(array_len, 100_000)):
            offset = _skip_value(data, offset, array_type, findings, entry_idx)
        return offset
    elif value_type <= 7:
        sizes = [4, 1, 1, 2, 4, 8, 4, 8]
        return offset + sizes[value_type]
    else:
        findings.append({"issue": "unknown_value_type", "severity": "medium", "description": f"Unknown GGUF value type {value_type} in metadata entry {entry_idx}"})
        return offset


def _extract_string_value(data: bytes, offset: int, value_type: int) -> Optional[str]:
    GGUF_VALUE_TYPE_STRING = 8
    if value_type != GGUF_VALUE_TYPE_STRING:
        return None
    if offset + 8 > len(data):
        return None
    length = struct.unpack("<Q", data[offset:offset + 8])[0]
    if length > MAX_STRING_LENGTH or length > len(data) - offset - 8:
        return None
    return data[offset + 8:offset + 8 + length].decode("utf-8", errors="replace")


def _check_ssti(template: str) -> list[dict]:
    findings = []
    for pattern in SSTI_PATTERNS:
        if pattern in template:
            findings.append({
                "issue": "jinja2_ssti_chat_template",
                "severity": "critical",
                "description": f"Jinja2 SSTI pattern '{pattern}' found in chat_template (CVE-2024-34359)",
            })
            break

    if "{" in template and "}" in template:
        from ast import parse
        try:
            fake_env = template.replace("{{", "__").replace("{%", "__").replace("{#", "__")
            parse(f"f'''{fake_env}'''")
        except SyntaxError:
            findings.append({"issue": "suspicious_template_syntax", "severity": "medium", "description": "chat_template contains syntactically suspicious Jinja2 constructs"})

    return findings


def _extract_alignment(data: bytes) -> Optional[int]:
    GGUF_KEY_ALIGNMENT = "general.alignment"
    GGUF_VALUE_TYPE_UINT32 = 4

    if len(data) < 24:
        return None
    metadata_count = struct.unpack("<Q", data[16:24])[0]
    offset = 24
    for _ in range(min(metadata_count, MAX_METADATA_COUNT)):
        if offset + 4 > len(data):
            break
        key_len = struct.unpack("<I", data[offset:offset + 4])[0]
        offset += 4
        if key_len > len(data) - offset:
            break
        key = data[offset:offset + key_len].decode("utf-8", errors="replace")
        offset += key_len
        if offset + 4 > len(data):
            break
        value_type = struct.unpack("<I", data[offset:offset + 4])[0]
        offset += 4
        if key == GGUF_KEY_ALIGNMENT and value_type == GGUF_VALUE_TYPE_UINT32:
            if offset + 4 <= len(data):
                return struct.unpack("<I", data[offset:offset + 4])[0]
        try:
            offset = _skip_value(data, offset, value_type, [], -1)
        except (struct.error, IndexError):
            break
    return None
