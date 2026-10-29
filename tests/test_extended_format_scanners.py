from __future__ import annotations

import gzip
import io
import json
import struct
import sys
import zipfile
from types import ModuleType, SimpleNamespace

from model_harrier.scan.formats import scan_file
from model_harrier.scan.formats.gguf import extract_gguf_metadata, scan_gguf
from model_harrier.scan.formats.keras import _scan_h5py_model, scan_keras
from model_harrier.scan.formats.onnx import scan_onnx


def _gguf(entries: list[tuple[str, int, bytes]]) -> bytes:
    data = bytearray(struct.pack("<4sIQQ", b"GGUF", 3, 0, len(entries)))
    for key, value_type, value in entries:
        encoded_key = key.encode("utf-8")
        data.extend(struct.pack("<Q", len(encoded_key)))
        data.extend(encoded_key)
        data.extend(struct.pack("<I", value_type))
        data.extend(value)
    return bytes(data + b"\x00" * max(0, 32 - len(data)))


def _gguf_string(value: str) -> bytes:
    encoded = value.encode("utf-8")
    return struct.pack("<Q", len(encoded)) + encoded


def _keras_zip(config: dict) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("config.json", json.dumps(config))
        archive.writestr("metadata.json", json.dumps({"keras_version": "3.0.0"}))
        archive.writestr("model.weights.h5", b"weights")
    return output.getvalue()


def test_gguf_reads_standard_uint64_keys_and_metadata_strings() -> None:
    sample = _gguf([("general.architecture", 8, _gguf_string("llama"))])

    metadata = extract_gguf_metadata(sample)
    findings = scan_gguf(sample)

    assert metadata["architecture"] == "llama"
    assert not [item for item in findings if item["severity"] in ("high", "critical")]


def test_gguf_extracts_standard_uint64_architecture_fields() -> None:
    sample = _gguf([
        ("general.architecture", 8, _gguf_string("llama")),
        ("llama.block_count", 10, struct.pack("<Q", 32)),
        ("llama.embedding_length", 10, struct.pack("<Q", 4096)),
        ("llama.context_length", 10, struct.pack("<Q", 8192)),
    ])

    metadata = extract_gguf_metadata(sample)

    assert metadata["layers"] == 32
    assert metadata["hidden_size"] == 4096
    assert metadata["context_length"] == 8192


def test_gguf_detects_template_injection_in_metadata_value() -> None:
    sample = _gguf([("tokenizer.chat_template", 8, _gguf_string("{{ self.__class__ }}"))])

    findings = scan_gguf(sample)

    assert "jinja2_ssti_chat_template" in {item["issue"] for item in findings}


def test_gguf_reports_truncated_scalar_metadata() -> None:
    key = b"general.file_type"
    sample = struct.pack("<4sIQQ", b"GGUF", 3, 0, 1)
    sample += struct.pack("<Q", len(key)) + key + struct.pack("<I", 4)

    findings = scan_gguf(sample)

    assert "truncated_metadata_value" in {item["issue"] for item in findings}


def test_gguf_rejects_nonstandard_oversized_metadata_key() -> None:
    sample = struct.pack("<4sIQQQ", b"GGUF", 3, 0, 1, 65_536) + b"x" * 8

    findings = scan_gguf(sample)

    assert "string_length_overflow" in {item["issue"] for item in findings}


def test_onnx_accepts_benign_parsed_graph_without_findings(monkeypatch) -> None:
    model = SimpleNamespace(
        graph=SimpleNamespace(node=[], initializer=[]),
        opset_import=[],
    )
    onnx = ModuleType("onnx")
    onnx.load_model_from_string = lambda _data: model
    monkeypatch.setitem(sys.modules, "onnx", onnx)

    findings = scan_onnx(b"\x08\x08" + b"\x00" * 14)

    assert findings == []


def test_onnx_flags_custom_operator_in_parsed_graph(monkeypatch) -> None:
    node = SimpleNamespace(domain="com.microsoft.custom", attribute=[])
    model = SimpleNamespace(
        graph=SimpleNamespace(node=[node], initializer=[]),
        opset_import=[],
    )
    onnx = ModuleType("onnx")
    onnx.load_model_from_string = lambda _data: model
    monkeypatch.setitem(sys.modules, "onnx", onnx)

    findings = scan_onnx(b"\x08\x08" + b"\x00" * 14)

    assert "custom_operator_domain" in {item["issue"] for item in findings}


def test_onnx_reports_parse_failure_for_malformed_model(monkeypatch) -> None:
    onnx = ModuleType("onnx")

    def fail_parse(_data: bytes):
        raise ValueError("invalid protobuf")

    onnx.load_model_from_string = fail_parse
    monkeypatch.setitem(sys.modules, "onnx", onnx)

    findings = scan_onnx(b"\x08\x08" + b"\x00" * 14)

    assert "onnx_parse_error" in {item["issue"] for item in findings}


def test_keras_zip_container_accepts_benign_config() -> None:
    sample = _keras_zip({"class_name": "Functional", "config": {"layers": [{"class_name": "Dense", "config": {"units": 8}}]}})

    findings = scan_file("model.keras", sample)

    assert not [item for item in findings if item["severity"] in ("high", "critical")]


def test_keras_zip_container_finds_serialized_lambda_layer() -> None:
    sample = _keras_zip({"class_name": "Functional", "config": {"layers": [{"class_name": "Lambda", "config": {}}]}})

    findings = scan_file("model.keras", sample)

    assert "lambda_layer_in_layers" in {item["issue"] for item in findings}


def test_keras_checks_hdf5_signature_at_user_block_offset() -> None:
    sample = b"\x00" * 512 + b"\x89HDF\r\n\x1a\n" + b"\x00" * 16

    findings = scan_keras(sample)

    assert "invalid_hdf5_signature" not in {item["issue"] for item in findings}


def test_keras_accepts_benign_hdf5_attributes() -> None:
    findings = _scan_h5py_model(SimpleNamespace(attrs={}))

    assert findings == []


def test_keras_hdf5_config_flags_lambda_layer() -> None:
    attrs = {"model_config": json.dumps({"class_name": "Lambda", "config": {}})}

    findings = _scan_h5py_model(SimpleNamespace(attrs=attrs))

    assert "lambda_layer_detected" in {item["issue"] for item in findings}


def test_keras_bounds_gzip_decompression(monkeypatch) -> None:
    monkeypatch.setattr("model_harrier.scan.formats.keras.MAX_KERAS_DECOMPRESSED_SIZE", 64)
    sample = gzip.compress(b"\x89HDF\r\n\x1a\n" + b"x" * 1024)

    findings = scan_keras(sample)

    assert "keras_decompression_limit" in {item["issue"] for item in findings}
