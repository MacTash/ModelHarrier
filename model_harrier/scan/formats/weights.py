"""Weight analysis scanner.

Detects LoRA/LoRA-X adapter weight distribution anomalies,
parameter count mismatches, tiny weights files, outlier
layer norms (backdoor heuristic), and quantization consistency.
"""

import struct
from typing import Optional

PARAM_BYTES_BY_DTYPE = {
    "f32": 4, "float32": 4, "f16": 2, "float16": 2, "bf16": 2, "bfloat16": 2,
    "f64": 8, "float64": 8, "i32": 4, "int32": 4, "i64": 8, "int64": 8,
    "i8": 1, "int8": 1, "u8": 1, "uint8": 1, "q4_0": 0.5, "q4_1": 0.5,
    "q5_0": 0.625, "q5_1": 0.625, "q8_0": 1, "q2_k": 0.25, "q3_k": 0.375,
    "q4_k": 0.5, "q5_k": 0.625, "q6_k": 0.75, "q8_k": 1,
}

MIN_PARAM_COUNT_FOR_MODEL = {
    "tiny": 10_000_000,
    "small": 100_000_000,
    "medium": 1_000_000_000,
    "large": 7_000_000_000,
}

LORA_RANKS = {"lora_a": "lora_A", "lora_B": "lora_B", "lora": ""}


def scan_weights(data: bytes, metadata: Optional[dict] = None) -> list[dict]:
    findings = []
    declared_size = (metadata or {}).get("file_size")
    file_size = declared_size if isinstance(declared_size, int) and declared_size >= 0 else len(data)

    if file_size < 64:
        findings.append({"issue": "weights_file_too_small", "severity": "high", "description": f"Weights file is only {file_size} bytes — potential truncated artifact"})
        return findings

    if len(data) < 64:
        return findings
    claimed_params = _estimate_claimed_params(metadata)

    if claimed_params:
        expected_min_size = claimed_params * 2
        if file_size < expected_min_size * 0.1:
            findings.append({"issue": "tiny_weights_for_claimed_params", "severity": "critical", "description": f"File size {file_size} is <10% of expected {expected_min_size} for {claimed_params} params"})

        dtype = (metadata or {}).get("dtype", "f32")
        bytes_per_param = PARAM_BYTES_BY_DTYPE.get(dtype, 4)
        expected_size = claimed_params * bytes_per_param
        if file_size > expected_size * 5:
            findings.append({"issue": "oversized_for_claimed_params", "severity": "medium", "description": f"File size {file_size} is {file_size/expected_size:.1f}x expected for {claimed_params} params ({dtype})"})

    findings.extend(_check_lora_anomalies(data, metadata))
    findings.extend(_check_outlier_values(data))
    findings.extend(_check_suspicious_patterns(data))

    return findings


def _estimate_claimed_params(metadata: Optional[dict]) -> Optional[int]:
    if not metadata:
        return None
    num_params = metadata.get("num_params") or metadata.get("num_parameters") or metadata.get("parameter_count")
    if num_params:
        try:
            return int(num_params)
        except (ValueError, TypeError):
            pass
    return None


def _check_lora_anomalies(data: bytes, metadata: Optional[dict]) -> list[dict]:
    findings = []
    if metadata:
        model_type = (metadata.get("model_type") or metadata.get("library_name") or "").lower()
        if "lora" in model_type or "peft" in model_type:
            findings.append({"issue": "lora_adapter_detected", "severity": "low", "description": "LoRA adapter detected — checking weight distribution"})

    lora_a_patterns = [b"lora_A", b"lora_a", b"lora.A"]
    lora_b_patterns = [b"lora_B", b"lora_b", b"lora.B"]

    has_lora_a = any(p in data for p in lora_a_patterns)
    has_lora_b = any(p in data for p in lora_b_patterns)

    if has_lora_a and not has_lora_b:
        findings.append({"issue": "lora_a_without_b", "severity": "high", "description": "LoRA A weights found without corresponding B weights — incomplete or tampered adapter"})
    if has_lora_b and not has_lora_a:
        findings.append({"issue": "lora_b_without_a", "severity": "high", "description": "LoRA B weights found without corresponding A weights"})

    if has_lora_a and has_lora_b:
        all_zeros_near = _check_all_zeros_region(data)
        if all_zeros_near:
            findings.append({"issue": "lora_zero_weights", "severity": "high", "description": "LoRA adapter contains all-zero weight regions — potential backdoor neutralization"})

    return findings


def _check_outlier_values(data: bytes) -> list[dict]:
    findings = []
    if len(data) < 256:
        return findings

    float_count = min(len(data) // 4, 1000)
    values = []
    for i in range(float_count):
        try:
            val = struct.unpack("<f", data[i * 4:(i + 1) * 4])[0]
            values.append(val)
        except struct.error:
            break

    if not values:
        return findings

    mean_val = sum(values) / len(values)
    variance = sum((v - mean_val) ** 2 for v in values) / len(values)
    std_dev = variance ** 0.5

    if std_dev > 100:
        findings.append({"issue": "high_weight_variance", "severity": "medium", "description": f"Weight values have abnormally high variance (std={std_dev:.1f})"})

    extreme_count = sum(1 for v in values if abs(v) > 1000)
    if extreme_count > len(values) * 0.01:
        findings.append({"issue": "extreme_weight_values", "severity": "high", "description": f"{extreme_count}/{len(values)} weights have magnitude >1000 (backdoor heuristic)"})

    return findings


def _check_all_zeros_region(data: bytes) -> bool:
    if len(data) < 1024:
        return False
    chunk_size = 1024
    for i in range(0, len(data) - chunk_size, chunk_size * 10):
        chunk = data[i:i + chunk_size]
        if all(b == 0 for b in chunk):
            return True
    return False


def _check_suspicious_patterns(data: bytes) -> list[dict]:
    findings = []
    suspicious = [b"__import__", b"os.system", b"eval(", b"exec(", b"pickle.load"]
    for pattern in suspicious:
        if pattern in data:
            findings.append({"issue": "code_in_weights", "severity": "critical", "description": f"Code pattern '{pattern.decode()}' found in weights file"})
            break
    return findings
