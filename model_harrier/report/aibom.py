"""AIBOM / CycloneDX ML-BOM generator.

Implements CISA G7 clusters for AI Bill of Materials.
"""

import json
from datetime import datetime


def generate_aibom(
    model_id: str,
    model_info: dict,
    findings: list[dict],
    alerts: list[dict],
    risk_score: float,
    severity: str,
) -> str:
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "timestamp": datetime.utcnow().isoformat(),
            "tools": [{"name": "model-harrier", "version": "0.2.0.dev0"}],
            "properties": [
                {"name": "cluster:1:metadata", "value": json.dumps({
                    "author": "model-harrier",
                    "timestamp": datetime.utcnow().isoformat(),
                })},
            ],
        },
        "components": [],
    }

    component = {
        "type": "application",
        "name": model_id,
        "version": model_info.get("pipeline_tag", "unknown"),
        "description": f"AI Model: {model_id}",
        "properties": [
            {"name": "cluster:2:system_level_properties", "value": json.dumps({
                "type": "ai-model",
                "library": model_info.get("library_name", "unknown"),
                "pipeline_tag": model_info.get("pipeline_tag", ""),
            })},
            {"name": "cluster:3:models", "value": json.dumps({
                "id": model_id,
                "architecture": model_info.get("library_name", "unknown"),
                "downloads": model_info.get("downloads", 0),
            })},
            {"name": "cluster:4:datasets", "value": json.dumps({
                "sources": [],
                "license": model_info.get("cardData", {}).get("license") if model_info.get("cardData") else None,
            })},
            {"name": "cluster:5:infrastructure", "value": json.dumps({
                "framework": model_info.get("library_name", "unknown"),
            })},
            {"name": "cluster:6:security", "value": json.dumps({
                "risk_score": risk_score,
                "severity": severity,
                "alerts_count": len(alerts),
                "findings_count": len(findings),
            })},
        ],
        "externalReferences": [
            {"type": "other", "url": f"https://huggingface.co/{model_id}"},
        ],
    }

    if findings:
        component["properties"].append({
            "name": "cluster:6:security:findings",
            "value": json.dumps([{
                "issue": f.get("issue", f.get("type", "unknown")),
                "severity": f.get("severity", "medium"),
                "description": f.get("description", ""),
                "filename": f.get("filename", ""),
            } for f in findings[:50]], default=str),
        })

    bom["components"].append(component)

    return json.dumps(bom, indent=2)
