"""Evidence-backed Hugging Face revision and repository scan metadata.

Revision hashes identify the exact repository snapshot scanned, but do not
authenticate its publisher. Hugging Face model metadata may include automated
repository scan status; that status is reported as supplied and is not treated
as a safety verdict. Publisher popularity and verification badges are context,
not evidence of artifact safety.
"""

import json
import re
from typing import Optional

from model_harrier.utils.config import MODEL_HARRIER_CACHE_DIR

BLOCKLIST_URL = "https://raw.githubusercontent.com/jfrog/model-security/main/blocklist.json"
BLOCKLIST_CACHE = MODEL_HARRIER_CACHE_DIR / "blocklist.json"
_REVISION_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$", re.IGNORECASE)


def get_provenance_evidence(model_info: Optional[dict]) -> dict:
    """Return observable revision and Hub scan metadata without a risk verdict."""
    info = model_info or {}
    revision = info.get("sha") or info.get("revision")
    revision = revision if isinstance(revision, str) and _REVISION_RE.fullmatch(revision) else None

    status = info.get("security_repo_status") or info.get("securityStatus") or {}
    if not isinstance(status, dict):
        status = {}
    scans_done = status.get("scansDone", status.get("scans_done"))
    if scans_done is True:
        scan_state = "complete"
    elif scans_done is False:
        scan_state = "pending"
    else:
        scan_state = "not_reported"
    issues = status.get("filesWithIssues", status.get("files_with_issues", []))
    if not isinstance(issues, list):
        issues = []

    return {
        "revision_sha": revision,
        "revision_pinned": revision is not None,
        "revision_note": (
            "SHA identifies the scanned repository snapshot; it does not authenticate the publisher."
            if revision else "No valid immutable revision SHA was reported by the Hub metadata."
        ),
        "signature_status": "not_reported",
        "signature_note": "The Hugging Face model metadata response does not report commit signature verification.",
        "hub_security_scan": {
            "status": scan_state,
            "files_with_issues": issues,
            "note": "Hub scan metadata is reported as supplied; completion or an empty issue list is not a safety verdict.",
        },
    }


def scan_provenance(model_id: str, model_info: Optional[dict] = None, siblings: Optional[list] = None) -> list[dict]:
    """Check the known-bad blocklist; metadata context is reported separately."""
    return _check_blocklist(model_id)


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
