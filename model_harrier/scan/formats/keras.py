"""Keras / HDF5 format scanner.

Detects Lambda layer serialization (CVE-2025-1550), custom function/class
references, and suspicious config entries in model JSON.
"""

import gzip
import json

LAMBDA_LAYER_CLASS = "Lambda"
SUSPICIOUS_CUSTOM_CLASSES = [
    "Custom>", "Functional>", "eval", "exec", "os.system", "subprocess",
]

SUSPICIOUS_CONFIG_KEYS = [
    "__import__", "builtins", "sys.", "shutil", "importlib",
]

LAMBDA_FUNCTION_INDICATORS = [
    "function", "lambda", "custom_function", "custom_op",
]


def scan_keras(data: bytes) -> list[dict]:
    findings = []

    if len(data) < 16:
        findings.append({"issue": "file_too_small", "severity": "high", "description": "File too small to contain valid Keras model"})
        return findings

    is_gzip = data[0:2] == b"\x1f\x8b"

    if is_gzip:
        try:
            data = gzip.decompress(data)
        except Exception:
            findings.append({"issue": "corrupt_gzip", "severity": "medium", "description": "File appears gzip-compressed but failed to decompress"})
            return findings

    try:
        import h5py
        import io
        with h5py.File(io.BytesIO(data), "r") as f:
            findings.extend(_scan_h5py_model(f))
        return findings
    except ImportError:
        findings.append({"issue": "h5py_not_installed", "severity": "low", "description": "h5py not installed — using raw byte heuristics only"})
    except Exception:
        pass

    decoded = data.decode("utf-8", errors="replace")
    text_scan = _scan_raw_text(decoded)
    findings.extend(text_scan)

    raw_scan = _scan_raw_bytes(data)
    findings.extend(raw_scan)

    return findings


def _scan_h5py_model(f) -> list[dict]:
    findings = []

    model_config_raw = f.attrs.get("model_config", None)
    if model_config_raw:
        try:
            if isinstance(model_config_raw, bytes):
                model_config_raw = model_config_raw.decode("utf-8")
            config = json.loads(model_config_raw) if isinstance(model_config_raw, str) else model_config_raw
        except (json.JSONDecodeError, TypeError):
            findings.append({"issue": "model_config_parse_error", "severity": "medium", "description": "Failed to parse model_config JSON from HDF5 attributes"})
            config = None

        if config:
            findings.extend(_check_config(config))

    custom_objects = f.attrs.get("custom_objects", None)
    if custom_objects:
        findings.append({"issue": "custom_objects_present", "severity": "high", "description": "Model has custom_objects — potential custom code execution"})

    training_config = f.attrs.get("training_config", None)
    if training_config:
        try:
            if isinstance(training_config, bytes):
                training_config = training_config.decode("utf-8")
            tc = json.loads(training_config) if isinstance(training_config, str) else training_config
            if isinstance(tc, dict):
                optimizer_config = tc.get("optimizer_config", {})
                if isinstance(optimizer_config, dict):
                    class_name = optimizer_config.get("class_name", "")
                    if class_name in SUSPICIOUS_CUSTOM_CLASSES:
                        findings.append({"issue": "suspicious_optimizer_class", "severity": "high", "description": f"Optimizer uses suspicious class: {class_name}"})
        except (json.JSONDecodeError, TypeError):
            pass

    for key in f.attrs:
        for indicator in LAMBDA_FUNCTION_INDICATORS:
            if indicator in key.lower():
                findings.append({"issue": "lambda_layer_serialized", "severity": "critical", "description": f"Lambda layer detected in attribute '{key}' (CVE-2025-1550)"})

    return findings


def _check_config(config: dict) -> list[dict]:
    findings = []

    class_name = config.get("class_name", "")
    if LAMBDA_LAYER_CLASS in class_name:
        findings.append({"issue": "lambda_layer_detected", "severity": "critical", "description": f"Lambda layer detected: {class_name} (CVE-2025-1550)"})

    config_dict = config.get("config", {})
    if isinstance(config_dict, dict):
        for key, value in config_dict.items():
            if isinstance(value, str):
                for indicator in LAMBDA_FUNCTION_INDICATORS:
                    if indicator in value.lower():
                        findings.append({"issue": "custom_function_reference", "severity": "critical", "description": f"Custom function reference in config key '{key}': {value[:100]}"})
                for pattern in SUSPICIOUS_CONFIG_KEYS:
                    if pattern in value.lower():
                        findings.append({"issue": "suspicious_config_value", "severity": "critical", "description": f"Suspicious pattern '{pattern}' in config key '{key}'"})

    layers = config_dict.get("layers", [])
    if isinstance(layers, list):
        for i, layer in enumerate(layers):
            if isinstance(layer, dict):
                lc = layer.get("class_name", "")
                if LAMBDA_LAYER_CLASS in lc:
                    findings.append({"issue": "lambda_layer_in_layers", "severity": "critical", "description": f"Lambda layer at index {i} (CVE-2025-1550)"})
                lc_config = layer.get("config", {})
                if isinstance(lc_config, dict):
                    for val in lc_config.values():
                        if isinstance(val, str) and any(indicator in val.lower() for indicator in LAMBDA_FUNCTION_INDICATORS):
                            findings.append({"issue": "embedded_function_in_layer", "severity": "critical", "description": f"Embedded function reference in layer {i}"})

    return findings


def _scan_raw_text(decoded: str) -> list[dict]:
    findings = []
    if LAMBDA_LAYER_CLASS in decoded:
        findings.append({"issue": "lambda_layer_raw_detected", "severity": "critical", "description": "Lambda layer class name found in raw file content (CVE-2025-1550)"})
    for indicator in LAMBDA_FUNCTION_INDICATORS:
        if indicator in decoded.lower():
            findings.append({"issue": "custom_function_raw", "severity": "high", "description": f"Custom function indicator '{indicator}' found in raw content"})
    for pattern in SUSPICIOUS_CONFIG_KEYS:
        if pattern in decoded.lower():
            findings.append({"issue": "suspicious_pattern_raw", "severity": "critical", "description": f"Suspicious pattern '{pattern}' found in raw file content"})
    return findings


def _scan_raw_bytes(data: bytes) -> list[dict]:
    findings = []
    for pattern in SUSPICIOUS_CONFIG_KEYS:
        if pattern.encode() in data:
            findings.append({"issue": "suspicious_bytes", "severity": "critical", "description": f"Suspicious byte pattern '{pattern}' found in file"})
    if any(p.encode() in data for p in LAMBDA_FUNCTION_INDICATORS):
        findings.append({"issue": "custom_function_bytes", "severity": "high", "description": "Custom function indicators found in raw bytes"})
    return findings
