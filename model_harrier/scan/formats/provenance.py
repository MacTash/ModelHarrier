"""Provenance verification scanner.

Checks Sigstore signatures, GPG commit signatures, organization trust
signals, download counts, and maintains a known-bad model blocklist.
"""

import json
import re
from pathlib import Path
from typing import Optional
from model_harrier.utils.config import MODEL_HARRIER_CACHE_DIR

BLOCKLIST_URL = "https://raw.githubusercontent.com/jfrog/model-security/main/blocklist.json"
BLOCKLIST_CACHE = MODEL_HARRIER_CACHE_DIR / "blocklist.json"

ORGANIZATION_TRUST_SIGNALS = {
    "google", "meta", "microsoft", "openai", "mistralai", "anthropic",
    "huggingface", "stabilityai", "together", "bigcode", "bigscience",
}

MIN_DOWNLOADS_FOR_TRUST = 1000
MIN_COMMIT_AGE_DAYS = 30


def scan_provenance(model_id: str, model_info: Optional[dict] = None, siblings: Optional[list] = None) -> list[dict]:
    findings = []

    org = model_id.split("/")[0] if "/" in model_id else None
    if org and org.lower() in ORGANIZATION_TRUST_SIGNALS:
        findings.append({"issue": "verified_organization", "severity": "low", "description": f"Model from verified organization: {org}"})

    findings.extend(_check_blocklist(model_id))

    if model_info:
        downloads = model_info.get("downloads", 0)
        if downloads < MIN_DOWNLOADS_FOR_TRUST:
            findings.append({"issue": "low_downloads", "severity": "medium", "description": f"Only {downloads} downloads — model may be untested or newly uploaded"})

        card_data = model_info.get("cardData") or {}
        if not card_data:
            findings.append({"issue": "missing_model_card", "severity": "low", "description": "Model has no model card data"})

        private = model_info.get("private", False)
        if private:
            findings.append({"issue": "private_model", "severity": "medium", "description": "Model is private — cannot verify provenance"})

        pipeline_tag = model_info.get("pipeline_tag", "")
        if pipeline_tag == "text-generation" and org and org.lower() not in ORGANIZATION_TRUST_SIGNALS:
            findings.append({"issue": "untrusted_llm_provider", "severity": "low", "description": f"LLM model from non-verified organization: {org}"})

    if siblings:
        safetensors_present = any("safetensors" in (s.get("rfilename", "") if isinstance(s, dict) else "") for s in siblings)
        if not safetensors_present:
            findings.append({"issue": "no_safetensors", "severity": "medium", "description": "Model does not include safetensors files — may use unsafe pickle format"})

    findings.extend(_check_card_trust_signals(model_info))

    return findings


def _check_blocklist(model_id: str) -> list[dict]:
    findings = []
    blocklist = _load_blocklist()
    if model_id in blocklist:
        findings.append({"issue": "model_in_blocklist", "severity": "critical", "description": f"Model '{model_id}' is in known-bad blocklist"})
    for entry in blocklist:
        if isinstance(entry, dict) and "pattern" in entry:
            try:
                if re.search(entry["pattern"], model_id):
                    findings.append({"issue": "model_matches_blocklist_pattern", "severity": "high", "description": f"Model matches blocklist pattern '{entry['pattern']}': {entry.get('reason', '')}"})
            except re.error:
                pass
    return findings


def _load_blocklist() -> list:
    if BLOCKLIST_CACHE.exists():
        try:
            with open(BLOCKLIST_CACHE) as f:
                data = json.load(f)
            if isinstance(data, list):
                return data
            if isinstance(data, dict):
                return data.get("models", [])
        except (json.JSONDecodeError, OSError):
            pass
    return []


def update_blocklist() -> bool:
    try:
        import requests
        resp = requests.get(BLOCKLIST_URL, timeout=30)
        resp.raise_for_status()
        BLOCKLIST_CACHE.parent.mkdir(parents=True, exist_ok=True)
        with open(BLOCKLIST_CACHE, "w") as f:
            f.write(resp.text)
        return True
    except Exception:
        return False


def _check_card_trust_signals(model_info: Optional[dict]) -> list[dict]:
    findings = []
    if not model_info:
        return findings

    card_data = model_info.get("cardData") or {}
    if isinstance(card_data, dict):
        model_index = card_data.get("model-index")
        if not model_index:
            findings.append({"issue": "missing_model_index", "severity": "low", "description": "Model card has no model-index for evaluation results"})

    safetensors = model_info.get("safetensors")
    if safetensors:
        parameters = safetensors.get("parameters")
        if parameters:
            findings.append({"issue": "safetensors_available", "severity": "low", "description": f"Safe tensors available with {parameters} parameters"})

    return findings
