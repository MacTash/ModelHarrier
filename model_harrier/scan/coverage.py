"""Scan coverage and artifact metadata aggregation."""

import re
from pathlib import Path


def aggregate_safetensors(file_findings: list[dict], model_info: dict | None = None) -> dict:
    """Summarize SafeTensors shards and structural metadata from scan findings."""
    safetensors_filenames = {
        finding["filename"]
        for finding in file_findings
        if finding.get("filename", "").endswith(".safetensors")
    }
    total_tensors = 0
    metadata_fields: set[str] = set()
    for finding in file_findings:
        if finding.get("category") != "deep_scan":
            continue
        description = finding.get("description", "")
        if description.startswith("Tensors:"):
            match = re.search(r"Tensors:\s*(\d+)", description)
            if match:
                total_tensors += int(match.group(1))
        if description.startswith("Metadata keys:"):
            metadata_fields.update(
                key.strip()
                for key in description.split(":", 1)[1].split(",")
                if key.strip()
            )
    return {
        "shard_count": len(safetensors_filenames),
        "tensor_count": total_tensors or "Not computed (deep scan skipped)",
        "metadata_fields": sorted(metadata_fields),
        "anomalies": [],
        "suspicious_metadata": [],
    }


def aggregate_gguf_info(file_findings: list[dict]) -> dict:
    """Aggregate GGUF metadata from deep-scan findings."""
    meta = {
        "files": 0,
        "architecture": set(),
        "quantization": set(),
        "context_length": None,
        "layers": None,
        "hidden_size": None,
        "num_heads": None,
        "parameter_count": None,
        "tensor_count": 0,
    }
    for finding in file_findings:
        if finding.get("category") != "deep_scan":
            continue
        description = finding.get("description", "")
        if description.startswith("Architecture:"):
            meta["architecture"].add(description.split(":", 1)[1].strip())
        elif description.startswith("Quantization:"):
            meta["quantization"].add(description.split(":", 1)[1].strip())
        elif description.startswith("Context Length:"):
            try:
                meta["context_length"] = int(description.split(":", 1)[1].strip())
            except (ValueError, IndexError):
                pass
        elif description.startswith("Parameters:"):
            meta["parameter_count"] = description.split(":", 1)[1].strip()
        if finding.get("filename", "").endswith(".gguf") and finding.get("issue") == "gguf_metadata":
            meta["files"] += 1
    return meta


def compute_security_confidence(model_info: dict, file_findings: list[dict]) -> dict:
    """Summarize metadata, byte, and deep-scan coverage for a repository scan."""
    siblings = model_info.get("siblings", [])
    total_files = len(siblings)
    total_bytes = 0
    files_with_size = 0
    for sibling in siblings:
        size = sibling.get("size")
        if size and size > 0:
            total_bytes += size
            files_with_size += 1

    deep_by_file: dict[str, list[dict]] = {}
    for finding in file_findings:
        if finding.get("category") == "deep_scan":
            deep_by_file.setdefault(finding["filename"], []).append(finding)

    weight_exts = {".safetensors", ".gguf", ".bin", ".pt", ".pth", ".h5", ".hdf5", ".onnx"}
    deep_scanned_ok = 0
    deep_scanned_skipped = 0
    deep_scanned_bytes = 0
    deep_failed = 0
    for filename, entries in deep_by_file.items():
        skipped = any(entry.get("issue") in ("scan_size_limit", "scan_size_unknown") for entry in entries)
        failed = any(entry.get("issue") == "download_failed" for entry in entries)
        if skipped:
            deep_scanned_skipped += 1
        elif failed:
            deep_failed += 1
        else:
            deep_scanned_ok += 1
            sibling = next((item for item in siblings if item.get("rfilename") == filename), None)
            size = sibling.get("size", 0) if sibling else 0
            if size and size > 0:
                deep_scanned_bytes += size

    total_candidates = len(deep_by_file)
    card_data = model_info.get("cardData")
    has_card = card_data is not None and bool(card_data)
    has_config_info = any("config.json" in str(finding.get("filename", "")) for finding in file_findings)
    metadata_pct = round((files_with_size / max(total_files, 1)) * 100) if total_files > 0 else 0
    deep_pct = round((deep_scanned_ok / max(total_candidates, 1)) * 100) if total_candidates > 0 else 100
    byte_pct = round((deep_scanned_bytes / max(total_bytes, 1)) * 100) if total_bytes > 0 else 0
    model_info_score = 100 if has_card and has_config_info else 50 if has_card or has_config_info else 0
    overall = round(metadata_pct * 0.25 + deep_pct * 0.30 + byte_pct * 0.20 + model_info_score * 0.25)
    overall = max(0, min(100, overall))

    unscanned = []
    for filename, entries in deep_by_file.items():
        if any(entry.get("issue") in ("scan_size_limit", "scan_size_unknown") for entry in entries):
            sibling = next((item for item in siblings if item.get("rfilename") == filename), None)
            size = sibling.get("size") if sibling else None
            reason = f"File size {size / 1024 / 1024:.0f} MB exceeds deep-scan threshold" if size else "File size unknown"
            unscanned.append({"file": filename, "reason": reason, "category": "deep_skipped"})
        if any(entry.get("issue") == "download_failed" for entry in entries):
            unscanned.append({"file": filename, "reason": "Download failed", "category": "download_failed"})

    weight_files_no_scan = []
    for sibling in siblings:
        filename = sibling.get("rfilename", "")
        if Path(filename).suffix.lower() in weight_exts and filename not in deep_by_file:
            weight_files_no_scan.append(filename)
    unscanned.extend(
        {"file": filename, "reason": "No deep scan attempted", "category": "not_scanned"}
        for filename in weight_files_no_scan
    )

    return {
        "confidence_pct": overall,
        "confidence_level": "HIGH" if overall >= 80 else "MEDIUM" if overall >= 50 else "LOW",
        "metadata_coverage": {"inspected": files_with_size, "total": total_files, "pct": metadata_pct},
        "deep_scan_rate": {"scanned": deep_scanned_ok, "skipped": deep_scanned_skipped, "failed": deep_failed, "total": total_candidates, "pct": deep_pct},
        "byte_coverage": {"inspected": deep_scanned_bytes, "total": total_bytes, "pct": byte_pct},
        "model_info_completeness": model_info_score,
        "unscanned": unscanned,
    }
