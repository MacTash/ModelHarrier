"""Garak integration for LLM red team probing.

Runs garak scans against HuggingFace models and maps results
to ModelHarrier severity levels. Garak is optional — graceful
fallback if not installed.
"""

import json
import subprocess
import sys
from pathlib import Path
from typing import Optional
from model_harrier.utils.config import MODEL_HARRIER_CACHE_DIR

GARAK_RESULTS_DIR = MODEL_HARRIER_CACHE_DIR / "garak"
GARAK_SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "PASS": "safe",
}


def garak_available() -> bool:
    import importlib.util
    return importlib.util.find_spec("garak") is not None


def scan_with_garak(
    model_id: str,
    probes: Optional[list[str]] = None,
    timeout: int = 600,
) -> dict:
    result = {
        "available": False,
        "model_id": model_id,
        "findings": [],
        "error": None,
        "probes_run": 0,
        "probes_failed": 0,
        "probes_passed": 0,
        "summary": {},
    }

    if not garak_available():
        result["error"] = "garak not installed"
        result["available"] = False
        return result

    result["available"] = True
    GARAK_RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    output_file = GARAK_RESULTS_DIR / f"{model_id.replace('/', '_')}.jsonl"

    cmd = [
        sys.executable, "-m", "garak",
        "--model_type", "huggingface",
        "--model_name", model_id,
        "--output_filename", str(output_file),
    ]

    if probes:
        cmd.extend(["--probes", ",".join(probes)])

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if proc.returncode != 0:
            result["error"] = f"garak exited with code {proc.returncode}: {proc.stderr[:500]}"
    except subprocess.TimeoutExpired:
        result["error"] = f"garak timed out after {timeout}s"
        return result
    except FileNotFoundError:
        result["error"] = "garak module not found despite being importable"
        return result
    except Exception as e:
        result["error"] = str(e)
        return result

    if output_file.exists():
        findings = _parse_garak_output(output_file)
        result["findings"] = findings
        result["probes_run"] = len(findings)
        result["probes_failed"] = sum(1 for f in findings if f["verdict"] == "FAIL")
        result["probes_passed"] = sum(1 for f in findings if f["verdict"] == "PASS")
        result["summary"] = _summarize_findings(findings)

    return result


def _parse_garak_output(output_file: Path) -> list[dict]:
    findings = []
    if not output_file.exists():
        return findings

    try:
        with open(output_file) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue

                finding = {
                    "probe": entry.get("probe", "unknown"),
                    "plugin": entry.get("plugin", ""),
                    "status": entry.get("status", "UNKNOWN"),
                    "verdict": "FAIL" if entry.get("status") in ("FAIL", "ERROR") else "PASS",
                    "severity": GARAK_SEVERITY_MAP.get(entry.get("severity", "MEDIUM"), "medium"),
                    "output": entry.get("output", ""),
                    "trigger": entry.get("trigger", ""),
                    "detector": entry.get("detector", ""),
                }
                findings.append(finding)
    except OSError:
        pass

    return findings


def _summarize_findings(findings: list[dict]) -> dict:
    categories = {}
    severities = {"critical": 0, "high": 0, "medium": 0, "low": 0, "safe": 0}
    for f in findings:
        cat = f.get("probe", "unknown").split(".")[0] if "." in f.get("probe", "") else "unknown"
        if cat not in categories:
            categories[cat] = {"total": 0, "failed": 0, "passed": 0}
        categories[cat]["total"] += 1
        if f["verdict"] == "FAIL":
            categories[cat]["failed"] += 1
        else:
            categories[cat]["passed"] += 1
        sev = f.get("severity", "medium")
        if sev in severities:
            severities[sev] += 1

    return {"by_category": categories, "by_severity": severities}


def list_garak_probes() -> list[str]:
    if not garak_available():
        return []
    try:
        result = subprocess.run(
            [sys.executable, "-m", "garak", "--list_probes"],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0:
            lines = result.stdout.strip().split("\n")
            return [l.strip() for l in lines if l.strip() and not l.startswith("garak")]
    except Exception:
        pass
    return []
