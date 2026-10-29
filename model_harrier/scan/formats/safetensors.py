"""Bounded structural validation for SafeTensors files."""

from __future__ import annotations

import json
import struct
from typing import Any

MAX_HEADER_SIZE = 100 * 1024 * 1024
DTYPE_BYTES = {
    "BOOL": 1, "U8": 1, "I8": 1, "F8_E4M3": 1, "F8_E4M3FN": 1,
    "F8_E4M3FNUZ": 1, "F8_E5M2": 1, "F8_E5M2FNUZ": 1,
    "U16": 2, "I16": 2, "F16": 2, "BF16": 2,
    "U32": 4, "I32": 4, "F32": 4,
    "U64": 8, "I64": 8, "F64": 8,
}


def _finding(issue: str, severity: str, description: str) -> dict[str, str]:
    return {"issue": issue, "severity": severity, "description": description}


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate key: {key}")
        result[key] = value
    return result


def scan_safetensors(data: bytes) -> list[dict]:
    """Inspect header and offsets without mapping or allocating tensor data."""
    if len(data) < 8:
        return [_finding("file_too_small", "high", "File is too small to contain a SafeTensors header")]

    header_size = struct.unpack_from("<Q", data)[0]
    if not 2 <= header_size <= MAX_HEADER_SIZE:
        return [_finding("invalid_header_size", "high", f"Header size {header_size} is outside the allowed range")]
    if header_size > len(data) - 8:
        return [_finding("header_size_mismatch", "critical", f"Header declares {header_size} bytes but only {len(data) - 8} remain")]

    raw_header = data[8:8 + header_size]
    try:
        header = json.loads(raw_header, object_pairs_hook=_unique_object)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        return [_finding("malformed_header", "critical", f"SafeTensors header is invalid: {exc}")]
    if not isinstance(header, dict):
        return [_finding("header_type_invalid", "high", "Header must be a JSON object")]

    body_size = len(data) - 8 - header_size
    tensor_entries: list[tuple[str, int, int]] = []
    findings: list[dict[str, str]] = []
    metadata = header.get("__metadata__", {})
    if not isinstance(metadata, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in metadata.items()):
        findings.append(_finding("invalid_metadata", "high", "__metadata__ must be a string-to-string object"))
    elif _suspicious_metadata(metadata):
        findings.append(_finding("suspicious_metadata", "medium", "Metadata contains code-like content; inspect the value and source"))

    for name, entry in header.items():
        if name == "__metadata__":
            continue
        if not isinstance(entry, dict):
            findings.append(_finding("invalid_tensor_entry", "critical", f"Tensor entry {name!r} is not an object"))
            continue
        dtype = entry.get("dtype")
        shape = entry.get("shape")
        offsets = entry.get("data_offsets")
        if not isinstance(dtype, str) or dtype not in DTYPE_BYTES:
            findings.append(_finding("invalid_dtype", "critical", f"Tensor {name!r} has unsupported dtype {dtype!r}"))
            continue
        if not isinstance(shape, list) or any(type(dim) is not int or dim < 0 for dim in shape):
            findings.append(_finding("invalid_shape", "critical", f"Tensor {name!r} has an invalid shape"))
            continue
        if not isinstance(offsets, list) or len(offsets) != 2 or any(type(pos) is not int for pos in offsets):
            findings.append(_finding("invalid_offsets", "critical", f"Tensor {name!r} must have two integer data offsets"))
            continue
        start, end = offsets
        if start < 0 or end < start or end > body_size:
            findings.append(_finding("offset_out_of_bounds", "critical", f"Tensor {name!r} offsets [{start}, {end}) exceed the {body_size}-byte data section"))
            continue
        element_count = 1
        for dimension in shape:
            element_count *= dimension
        expected_size = element_count * DTYPE_BYTES[dtype]
        if end - start != expected_size:
            findings.append(_finding("tensor_size_mismatch", "critical", f"Tensor {name!r} shape and dtype require {expected_size} bytes, offsets declare {end - start}"))
        tensor_entries.append((name, start, end))

    ordered = sorted(tensor_entries, key=lambda entry: (entry[1], entry[2]))
    cursor = 0
    for name, start, end in ordered:
        if start < cursor:
            findings.append(_finding("overlapping_tensors", "critical", f"Tensor {name!r} overlaps a preceding tensor"))
        elif start > cursor:
            findings.append(_finding("tensor_data_gap", "high", f"Unreferenced gap of {start - cursor} bytes before tensor {name!r}"))
        cursor = max(cursor, end)
    if cursor < body_size:
        findings.append(_finding("trailing_tensor_data", "high", f"{body_size - cursor} bytes at the end of the tensor section are unreferenced"))
    elif not tensor_entries and body_size:
        findings.append(_finding("unclaimed_tensor_data", "high", f"File has {body_size} data bytes but no tensor entries"))

    findings.insert(0, _finding("safetensors_summary", "info", f"Validated {len(tensor_entries)} tensor entries; data section is {body_size} bytes"))
    return findings


def _suspicious_metadata(metadata: dict[str, str]) -> bool:
    markers = ("__import__(", "subprocess", "os.system(", "eval(", "exec(", "pickle.loads(")
    return any(any(marker in value.lower() for marker in markers) for value in metadata.values())
