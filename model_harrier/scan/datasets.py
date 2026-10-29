"""Deep dataset scanner — fetches and analyzes training datasets from HuggingFace."""

import json
import re
from pathlib import Path
from typing import Optional

import requests
from huggingface_hub import HfApi
from model_harrier.utils.config import MODEL_HARRIER_CACHE_DIR

HF_TOKEN = None
try:
    import os
    HF_TOKEN = os.environ.get("HF_TOKEN") or os.environ.get("HUGGINGFACE_TOKEN")
except Exception:
    pass

CACHE_DIR = MODEL_HARRIER_CACHE_DIR / "datasets"

api = HfApi()

SENSITIVE_DATASET_CONTENT_KEYWORDS = [
    "nsfw", "explicit", "adult", "porn", "sexual", "erotica",
    "gore", "violence", "hate", "harassment", "self-harm",
    "jailbreak", "injection", "malware", "exploit", "ransomware",
    "personal information", "private data", "doxx",
    "illegal", "weapon", "bomb", "chemical", "bio",
]

SUSPICIOUS_DATASET_TAGS = {
    "nsfw", "explicit", "not-safe-for-work", "adult-content",
    "jailbreak", "red-team", "hacking", "malware",
    "do-not-train-on",
}

TRUSTED_DATASET_ORGS = {
    "openai", "google", "meta", "microsoft", "anthropic",
    "huggingface", "bigcode", "bigscience", "princeton-nlp",
    "tiiuae", "codeparrot", "databricks", "cohere",
}


def fetch_dataset_info(dataset_id: str) -> Optional[dict]:
    cache_file = CACHE_DIR / f"{dataset_id.replace('/', '_')}.json"
    if cache_file.exists():
        try:
            with open(cache_file) as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            pass

    try:
        info = api.dataset_info(
            repo_id=dataset_id,
            token=HF_TOKEN,
        )
        result = {
            "id": dataset_id,
            "author": info.author if hasattr(info, "author") else None,
            "private": info.private if hasattr(info, "private") else False,
            "downloads": info.downloads if hasattr(info, "downloads") else 0,
            "likes": info.likes if hasattr(info, "likes") else 0,
            "tags": list(info.tags) if hasattr(info, "tags") and info.tags else [],
            "card_data": info.card_data if hasattr(info, "card_data") else None,
            "siblings_count": len(info.siblings) if hasattr(info, "siblings") and info.siblings else 0,
        }
        if hasattr(info, "card_data") and info.card_data:
            card = info.card_data
            result["license"] = getattr(card, "license", None)
            result["size_categories"] = getattr(card, "size_categories", None)
            result["task_categories"] = getattr(card, "task_categories", None)
            result["languages"] = getattr(card, "languages", None)

        cache_file.parent.mkdir(parents=True, exist_ok=True)
        with open(cache_file, "w") as f:
            json.dump(result, f, default=str)
        return result
    except Exception as e:
        return {"id": dataset_id, "error": str(e)}


def scan_training_datasets(dataset_ids: list[str]) -> dict:
    datasets_info = []
    alerts = []

    for ds_id in dataset_ids:
        info = fetch_dataset_info(ds_id)
        if not info:
            continue

        datasets_info.append(info)
        dataset_alerts = _analyze_dataset(info)
        alerts.extend(dataset_alerts)

    return {
        "datasets_scanned": len(datasets_info),
        "datasets_failed": sum(1 for d in datasets_info if "error" in d),
        "datasets": datasets_info,
        "alerts": alerts,
    }


def _analyze_dataset(info: dict) -> list[dict]:
    alerts = []
    ds_id = info.get("id", "unknown")

    if info.get("private"):
        alerts.append({"type": "dataset_private", "severity": "medium", "description": f"Dataset '{ds_id}' is private — cannot verify provenance"})

    downloads = info.get("downloads", 0)
    if downloads < 100:
        alerts.append({"type": "dataset_low_downloads", "severity": "low", "description": f"Dataset '{ds_id}' has only {downloads} downloads — may be untested or malicious"})

    org = ds_id.split("/")[0] if "/" in ds_id else None
    if org and org.lower() in TRUSTED_DATASET_ORGS:
        alerts.append({"type": "dataset_verified_org", "severity": "low", "description": f"Dataset '{ds_id}' from verified organization '{org}'"})

    tags = [t.lower() for t in info.get("tags", []) if isinstance(t, str)]
    context_tags = [t for t in tags if t in SUSPICIOUS_DATASET_TAGS]
    if context_tags:
        alerts.append({
            "type": "dataset_context_tags",
            "severity": "low",
            "description": f"Dataset '{ds_id}' has content or usage context tags: {', '.join(context_tags)}",
        })

    card_data = info.get("card_data")
    if card_data:
        try:
            card_text = json.dumps(card_data, default=str).lower()
        except Exception:
            card_text = str(card_data).lower()
        for kw in SENSITIVE_DATASET_CONTENT_KEYWORDS:
            term = r"\s+".join(re.escape(part) for part in kw.split())
            if re.search(rf"(?<!\w){term}(?!\w)", card_text):
                alerts.append({
                    "type": "dataset_content_scope",
                    "severity": "low",
                    "description": f"Dataset '{ds_id}' card mentions the content-scope term '{kw}'",
                })
                break

    license_val = info.get("license")
    if not license_val:
        license_val = next((tag.split(":", 1)[1] for tag in tags if tag.startswith("license:")), None)
    if not license_val:
        alerts.append({"type": "dataset_no_license", "severity": "medium", "description": f"Dataset '{ds_id}' has no license — unclear usage rights"})
    elif isinstance(license_val, str) and license_val.lower() in ("unknown", "other", "license:unknown", "license:other"):
        alerts.append({"type": "dataset_unknown_license", "severity": "medium", "description": f"Dataset '{ds_id}' has unknown license"})
    elif isinstance(license_val, list):
        for lv in license_val:
            if isinstance(lv, str) and lv.lower() in ("unknown", "other", "license:unknown", "license:other"):
                alerts.append({"type": "dataset_unknown_license", "severity": "medium", "description": f"Dataset '{ds_id}' has unknown license"})
                break

    size_cat = info.get("size_categories")
    if size_cat and isinstance(size_cat, list):
        for sc in size_cat:
            if "1M" in sc or "10M" in sc or "100M" in sc or "1B" in sc:
                alerts.append({"type": "dataset_large_size", "severity": "low", "description": f"Dataset '{ds_id}' is large ({sc}) — may contain diverse content"})

    if info.get("siblings_count", 0) > 1000:
        alerts.append({"type": "dataset_many_files", "severity": "low", "description": f"Dataset '{ds_id}' has {info['siblings_count']} files — large surface area"})

    return alerts


def extract_dataset_ids_from_model(model_info: dict, readme_content: Optional[str] = None) -> list[str]:
    ids = set()

    card_data = model_info.get("cardData") or {}
    if isinstance(card_data, dict):
        datasets = card_data.get("datasets")
        if datasets and isinstance(datasets, list):
            for d in datasets:
                if isinstance(d, str) and d.strip():
                    ids.add(d.strip())
                elif isinstance(d, dict):
                    ds_id = d.get("id") or d.get("name")
                    if ds_id and isinstance(ds_id, str) and ds_id.strip():
                        ids.add(ds_id.strip())

    if readme_content:
        for match in re.finditer(r"huggingface\.co/datasets/([\w\-/]+)", readme_content):
            ids.add(match.group(1))
        for match in re.finditer(r"datasets\s*:\s*\[([^\]]+)\]", readme_content, re.IGNORECASE):
            content = match.group(1)
            parts = [p.strip().strip("'\"") for p in content.split(",")]
            for part in parts:
                if "/" in part:
                    ids.add(part)

    return list(ids)
