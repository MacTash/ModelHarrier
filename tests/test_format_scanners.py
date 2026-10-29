from __future__ import annotations

import io
import json
import pickle
import struct
import zipfile

from model_harrier.scan.formats import detect_format, scan_file
from model_harrier.scan.formats.archive import scan_archive
from model_harrier.scan.formats.safetensors import scan_safetensors
from model_harrier.scan.formats.tokenizer import scan_tokenizer
from model_harrier.scan.formats.weights import scan_weights


def _safetensors(header: dict, body: bytes = b"") -> bytes:
    encoded = json.dumps(header, separators=(",", ":")).encode()
    padding = (-len(encoded)) % 8
    encoded += b" " * padding
    return struct.pack("<Q", len(encoded)) + encoded + body


def _zip(entries: list[tuple[str, bytes, int | None]]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        for name, payload, mode in entries:
            info = zipfile.ZipInfo(name)
            if mode is not None:
                info.external_attr = mode << 16
            archive.writestr(info, payload)
    return output.getvalue()


def test_safetensors_accepts_valid_tensor_ranges() -> None:
    payload = _safetensors({"weight": {"dtype": "F32", "shape": [2], "data_offsets": [0, 8]}}, b"12345678")
    assert not [item for item in scan_safetensors(payload) if item["severity"] in ("high", "critical")]


def test_safetensors_rejects_shape_offset_mismatch() -> None:
    payload = _safetensors({"weight": {"dtype": "F32", "shape": [2], "data_offsets": [0, 4]}}, b"1234")
    issues = {item["issue"] for item in scan_safetensors(payload)}
    assert "tensor_size_mismatch" in issues


def test_safetensors_rejects_offsets_outside_data_section() -> None:
    payload = _safetensors({"weight": {"dtype": "U8", "shape": [10], "data_offsets": [0, 10]}}, b"x")
    issues = {item["issue"] for item in scan_safetensors(payload)}
    assert "offset_out_of_bounds" in issues


def test_safetensors_rejects_duplicate_json_keys() -> None:
    header = b'{"x":{"dtype":"U8","shape":[1],"data_offsets":[0,1]},"x":{"dtype":"U8","shape":[1],"data_offsets":[0,1]}}'
    header += b" " * ((-len(header)) % 8)
    payload = struct.pack("<Q", len(header)) + header + b"x"
    assert scan_safetensors(payload)[0]["issue"] == "malformed_header"


def test_archive_detects_windows_and_posix_traversal_paths() -> None:
    payload = _zip([("../outside.pkl", b"x", None), ("C:\\outside.py", b"x", None)])
    issues = {item["issue"] for item in scan_archive(payload)}
    assert "zip_slip_path_traversal" in issues
    assert "zip_slip_absolute_path" in issues


def test_archive_detects_symlink_members() -> None:
    payload = _zip([("link", b"../../outside", 0o120777)])
    assert "archive_symlink" in {item["issue"] for item in scan_archive(payload)}


def test_content_detection_finds_pickle_with_benign_suffix() -> None:
    payload = pickle.dumps(__import__("os").system, protocol=4)
    assert detect_format("weights.data", payload) == "pickle"
    issues = scan_file("weights.data", payload)
    assert any(item["issue"] == "content_extension_mismatch" for item in issues)


def test_content_first_router_scans_archive_members() -> None:
    payload = _zip([("../outside.py", b"benign", None)])

    issues = scan_file("renamed.model", payload)

    assert "zip_slip_path_traversal" in {item["issue"] for item in issues}


def test_large_weight_skipped_for_budget_is_not_reported_as_tiny() -> None:
    issues = scan_weights(b"", {"file_size": 100_000_000})
    assert "weights_file_too_small" not in {item["issue"] for item in issues}


def test_relative_path_token_fragment_is_not_a_tokenizer_vulnerability() -> None:
    tokenizer = {"model": {"type": "BPE", "vocab": {"../": 1}}, "added_tokens": []}
    issues = scan_tokenizer(json.dumps(tokenizer).encode())
    assert "suspicious_string_in_tokenizer" not in {item["issue"] for item in issues}


def test_code_words_in_tokenizer_vocabulary_are_not_execution_findings() -> None:
    tokenizer = {
        "model": {"type": "BPE", "vocab": {"subprocess": 1, "os.system": 2, "exec(": 3}},
        "added_tokens": [{"id": 4, "content": "__import__"}],
    }
    issues = scan_tokenizer(json.dumps(tokenizer).encode())
    assert not [item for item in issues if item["severity"] in ("high", "critical")]
