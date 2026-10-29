from __future__ import annotations

from model_harrier.scan.coverage import aggregate_gguf_info, aggregate_safetensors, compute_security_confidence


def test_aggregate_safetensors_counts_unique_shards_and_structural_metadata():
    findings = [
        {"filename": "weights-1.safetensors", "category": "model", "description": "SafeTensors model weight file"},
        {"filename": "weights-2.safetensors", "category": "model", "description": "SafeTensors model weight file"},
        {"filename": "weights-1.safetensors", "category": "deep_scan", "description": "Tensors: 2"},
        {"filename": "weights-1.safetensors", "category": "deep_scan", "description": "Metadata keys: format, architecture"},
    ]

    result = aggregate_safetensors(findings)

    assert result["shard_count"] == 2
    assert result["tensor_count"] == 2
    assert result["metadata_fields"] == ["architecture", "format"]


def test_aggregate_gguf_extracts_metadata_without_touching_other_categories():
    findings = [
        {"filename": "model.gguf", "category": "deep_scan", "issue": "gguf_metadata", "description": "Architecture: llama"},
        {"filename": "model.gguf", "category": "deep_scan", "issue": "gguf_metadata", "description": "Quantization: Q4_K_M"},
        {"filename": "model.gguf", "category": "deep_scan", "issue": "gguf_metadata", "description": "Context Length: 8192"},
        {"filename": "README.md", "category": "metadata", "issue": "gguf_metadata", "description": "Architecture: ignored"},
    ]

    result = aggregate_gguf_info(findings)

    assert result["files"] == 3
    assert result["architecture"] == {"llama"}
    assert result["quantization"] == {"Q4_K_M"}
    assert result["context_length"] == 8192


def test_compute_security_confidence_reports_scanned_bytes_and_skips():
    model_info = {
        "cardData": {"license": "apache-2.0"},
        "siblings": [
            {"rfilename": "config.json", "size": 100},
            {"rfilename": "weights.safetensors", "size": 900},
            {"rfilename": "large.gguf", "size": 10 * 1024 * 1024},
        ],
    }
    findings = [
        {"filename": "config.json", "category": "config", "description": "Configuration"},
        {"filename": "weights.safetensors", "category": "deep_scan", "description": "Header valid"},
        {"filename": "large.gguf", "category": "deep_scan", "issue": "scan_size_limit", "description": "Deep scan skipped"},
    ]

    result = compute_security_confidence(model_info, findings)

    assert result["metadata_coverage"] == {"inspected": 3, "total": 3, "pct": 100}
    assert result["deep_scan_rate"] == {"scanned": 1, "skipped": 1, "failed": 0, "total": 2, "pct": 50}
    assert result["byte_coverage"] == {"inspected": 900, "total": 10_486_760, "pct": 0}
    assert result["unscanned"][0]["file"] == "large.gguf"


def test_compute_security_confidence_marks_weight_without_attempt():
    result = compute_security_confidence(
        {"siblings": [{"rfilename": "model.onnx", "size": 64}]},
        [],
    )

    assert result["unscanned"] == [{"file": "model.onnx", "reason": "No deep scan attempted", "category": "not_scanned"}]
