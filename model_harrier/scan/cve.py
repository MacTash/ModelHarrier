"""CVE cross-reference module.

Fetches CVE data from NVD API and OSV, maps to model dependencies,
and caches results locally.
"""

import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional
from model_harrier.utils.config import MODEL_HARRIER_CACHE_DIR

CVE_CACHE_DIR = MODEL_HARRIER_CACHE_DIR / "cve"
CVE_CACHE_TTL = timedelta(hours=24)
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OSV_API_BASE = "https://api.osv.dev/v1"


def get_cve_cache_path(cache_key: str) -> Path:
    CVE_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    return CVE_CACHE_DIR / f"{cache_key}.json"


def is_cache_valid(cache_path: Path) -> bool:
    if not cache_path.exists():
        return False
    mtime = datetime.fromtimestamp(cache_path.stat().st_mtime)
    return datetime.now() - mtime < CVE_CACHE_TTL


def query_nvd(keyword: str, limit: int = 20) -> list[dict]:
    cache_key = f"nvd_{keyword.replace(' ', '_')}"
    cache_path = get_cve_cache_path(cache_key)
    if is_cache_valid(cache_path):
        with open(cache_path) as f:
            return json.load(f)

    try:
        import requests
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": limit,
        }
        resp = requests.get(NVD_API_BASE, params=params, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        vulnerabilities = data.get("vulnerabilities", [])
        results = []
        for vuln in vulnerabilities:
            cve = vuln.get("cve", {})
            metrics = cve.get("metrics", {})
            cvss_score = None
            for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                metrics_list = metrics.get(metric_key, [])
                if metrics_list:
                    cvss_score = metrics_list[0].get("cvssData", {}).get("baseScore")
                    break
            results.append({
                "id": cve.get("id", ""),
                "description": cve.get("descriptions", [{}])[0].get("value", "")[:200] if cve.get("descriptions") else "",
                "cvss_score": cvss_score,
                "severity": _cvss_to_severity(cvss_score),
                "published": cve.get("published", ""),
                "source": "nvd",
            })
        with open(cache_path, "w") as f:
            json.dump(results, f)
        return results
    except Exception:
        return []


def query_osv(package_name: str, ecosystem: str = "PyPI") -> list[dict]:
    cache_key = f"osv_{ecosystem}_{package_name}"
    cache_path = get_cve_cache_path(cache_key)
    if is_cache_valid(cache_path):
        with open(cache_path) as f:
            return json.load(f)

    try:
        import requests
        resp = requests.post(
            f"{OSV_API_BASE}/v1/query",
            json={"package": {"name": package_name, "ecosystem": ecosystem}},
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        vulns = data.get("vulns", [])
        results = []
        for vuln in vulns:
            results.append({
                "id": vuln.get("id", ""),
                "description": vuln.get("summary", "")[:200] if vuln.get("summary") else vuln.get("details", "")[:200],
                "cvss_score": vuln.get("severity", [{}])[0].get("score") if vuln.get("severity") else None,
                "severity": vuln.get("severity", [{}])[0].get("severity", "UNKNOWN") if vuln.get("severity") else "UNKNOWN",
                "published": vuln.get("published", ""),
                "source": "osv",
                "ecosystem": ecosystem,
                "package": package_name,
            })
        with open(cache_path, "w") as f:
            json.dump(results, f)
        return results
    except Exception:
        return []


def check_model_dependencies(library_name: str, transformers_version: Optional[str] = None) -> list[dict]:
    results = []

    dep_map = {
        "transformers": ["transformers", "tokenizers"],
        "diffusers": ["diffusers"],
        "gguf": ["llama-cpp-python"],
        "safetensors": ["safetensors"],
    }

    deps = dep_map.get(library_name, [library_name])
    for dep in deps:
        osv_results = query_osv(dep, "PyPI")
        results.extend(osv_results)

    return results


def update_cve_cache() -> dict:
    deps_to_check = [
        "transformers", "tokenizers", "safetensors",
        "torch", "torchvision", "accelerate",
        "llama-cpp-python", "diffusers", "onnx",
    ]
    stats = {"checked": 0, "found": 0, "errors": 0}
    for dep in deps_to_check:
        try:
            results = query_osv(dep, "PyPI")
            stats["checked"] += 1
            stats["found"] += len(results)
        except Exception:
            stats["errors"] += 1
    return stats


def _cvss_to_severity(score: Optional[float]) -> str:
    if score is None:
        return "unknown"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"
