"""JSON report generator for scan results."""

import json
from datetime import datetime
from typing import Optional


def generate_json_report(
    model_id: str,
    model_info: dict,
    file_findings: list[dict],
    static_analysis: dict,
    alerts: list[dict],
    scan_timestamp: str = None,
    coverage: Optional[dict] = None,
) -> str:
    timestamp = scan_timestamp or datetime.utcnow().isoformat()

    file_counts = {"risky": 0, "code": 0, "safe": 0, "unknown": 0, "total": 0}
    for f in file_findings:
        cat = f.get("category", "unknown")
        file_counts[cat] = file_counts.get(cat, 0) + 1
        file_counts["total"] += 1

    risk_score = _calculate_risk_score(file_findings, static_analysis)
    severity = _score_to_severity(risk_score)

    report = {
        "model_harrier_version": "0.2.0.dev0",
        "scan_timestamp": timestamp,
        "model": {
            "id": model_id,
            "pipeline_tag": model_info.get("pipeline_tag"),
            "library_name": model_info.get("library_name"),
            "downloads": model_info.get("downloads", 0),
            "likes": model_info.get("likes", 0),
            "private": model_info.get("private", False),
            "license": model_info.get("cardData", {}).get("license"),
            "publisher": model_info.get("author"),
            "revision": model_info.get("sha"),
            "last_modified": model_info.get("last_modified"),
        },
        "scan_summary": {
            "risk_score": risk_score,
            "severity": severity,
            "files_scanned": file_counts["total"],
            "risky_files": file_counts["risky"],
            "code_files": file_counts["code"],
            "safe_files": file_counts["safe"],
            "alerts_count": len(alerts),
            "static_risk_score": static_analysis.get("static_risk_score", 0) if static_analysis else 0,
            "static_risk_level": static_analysis.get("static_risk_level", "unknown") if static_analysis else "unknown",
        },
        "file_findings": file_findings,
        "static_analysis": static_analysis,
        "alerts": alerts,
        "scan_coverage": coverage or {},
    }

    return json.dumps(report, indent=2, default=str)


RISKY_EXTENSIONS = {".pickle", ".pkl", ".joblib", ".dill", ".exe", ".dll", ".so", ".dylib"}
CODE_EXTENSIONS = {".py", ".sh", ".js", ".ts", ".cpp", ".c", ".h", ".rs", ".go"}
SCANNABLE_EXTENSIONS = {".safetensors", ".gguf", ".onnx", ".h5", ".keras", ".hdf5", ".zip", ".tar", ".tar.gz", ".tgz", ".gz", ".bz2", ".xz", ".7z", ".pt", ".pth", ".ckpt", ".bin"}


def categorize_file(filename: str) -> tuple[str, str, float]:
    ext = Path(filename).suffix.lower()
    if ext in RISKY_EXTENSIONS:
        return "risky", f"Unsafe format: {ext}", 10.0
    if ext in (".pt", ".pth", ".ckpt", ".bin"):
        return "model", f"Legacy checkpoint format {ext}; may contain pickle data", 4.0
    if ext in CODE_EXTENSIONS:
        return "code", f"Source code: {ext}", 5.0
    if ext in SCANNABLE_EXTENSIONS:
        return "model", f"Model format: {ext}", 2.0
    if "tokenizer" in filename.lower() and ext == ".json":
        return "model", "Tokenizer config", 2.0
    return "unknown", f"Unknown format: {ext}", 3.0


from pathlib import Path


def _calculate_risk_score(file_findings: list[dict], static_analysis: dict) -> float:
    file_risk = 0.0
    for f in file_findings:
        score = f.get("risk_score", 0)
        if score >= 8:
            file_risk += score
        elif score >= 5:
            file_risk += score * 0.7
        else:
            file_risk += score * 0.3

    file_risk = min(file_risk, 60)

    static_risk = static_analysis.get("static_risk_score", 0) if static_analysis else 0
    total = (file_risk * 0.6 + static_risk * 0.4) / 10.0
    return round(min(10.0, max(0.0, total)), 1)


def _score_to_severity(score: float) -> str:
    if score >= 8.0:
        return "critical"
    if score >= 5.0:
        return "high"
    if score >= 3.0:
        return "medium"
    return "low"
