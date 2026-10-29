"""SARIF 2.1 report generator for CI/CD integration."""

import json
from datetime import datetime


def generate_sarif_report(
    model_id: str,
    findings: list[dict],
    alerts: list[dict],
    risk_score: float,
    severity: str,
) -> str:
    tool_name = "model-harrier"
    tool_version = "0.2.0.dev0"

    results = []
    for finding in findings:
        sarif_level = _severity_to_sarif(finding.get("severity", "medium"))
        result = {
            "ruleId": finding.get("issue", "generic_finding"),
            "level": sarif_level,
            "message": {"text": finding.get("description", "")},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": finding.get("filename", model_id),
                    },
                },
            }],
            "properties": {
                "category": finding.get("category", "unknown"),
                "risk_score": finding.get("risk_score", 0),
            },
        }
        results.append(result)

    for alert in alerts:
        sarif_level = _severity_to_sarif(alert.get("severity", "medium"))
        result = {
            "ruleId": alert.get("type", "alert"),
            "level": sarif_level,
            "message": {"text": alert.get("description", "")},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": model_id,
                    },
                },
            }],
            "properties": {
                "category": "alert",
            },
        }
        results.append(result)

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": tool_name,
                    "version": tool_version,
                    "informationUri": "https://github.com/model-harrier/model-harrier",
                    "rules": _build_rules(findings, alerts),
                },
            },
            "results": results,
            "properties": {
                "model_id": model_id,
                "risk_score": risk_score,
                "severity": severity,
                "scan_timestamp": datetime.utcnow().isoformat(),
            },
        }],
    }

    return json.dumps(sarif, indent=2)


def _severity_to_sarif(severity: str) -> str:
    mapping = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "safe": "none",
    }
    return mapping.get(severity, "warning")


def _build_rules(findings: list[dict], alerts: list[dict]) -> list[dict]:
    seen_rules = set()
    rules = []
    for finding in findings + alerts:
        rule_id = finding.get("issue") or finding.get("type", "generic_finding")
        if rule_id in seen_rules:
            continue
        seen_rules.add(rule_id)
        sarif_level = _severity_to_sarif(finding.get("severity", "medium"))
        rules.append({
            "id": rule_id,
            "name": rule_id.replace("_", " ").title(),
            "shortDescription": {"text": finding.get("description", "")[:100]},
            "defaultConfiguration": {"level": sarif_level},
            "properties": {"category": finding.get("category", "unknown")},
        })
    return rules
