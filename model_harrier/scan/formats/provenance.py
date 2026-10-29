"""Evidence-backed Hugging Face revision and repository scan metadata.

Revision hashes identify the exact repository snapshot scanned, but do not
authenticate its publisher. Hugging Face model metadata may include automated
repository scan status; that status is reported as supplied and is not treated
as a safety verdict. Publisher popularity and verification badges are context,
not evidence of artifact safety.
"""

import json
import os
import re
from datetime import datetime, timezone
from html.parser import HTMLParser
from typing import Optional
from urllib.parse import quote

import requests

from model_harrier.utils.config import MODEL_HARRIER_CACHE_DIR

BLOCKLIST_URL = "https://raw.githubusercontent.com/jfrog/model-security/main/blocklist.json"
BLOCKLIST_CACHE = MODEL_HARRIER_CACHE_DIR / "blocklist.json"
_REVISION_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$", re.IGNORECASE)
_HF_ENDPOINT = "https://huggingface.co"


class _CommitHistoryParser(HTMLParser):
    """Read the structured commit list embedded in the Hub history page."""

    def __init__(self) -> None:
        super().__init__()
        self.commits: Optional[list] = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        if tag.lower() != "div":
            return
        attributes = dict(attrs)
        if attributes.get("data-target") != "CommitHistoryList":
            return
        props = attributes.get("data-props")
        if not props:
            return
        try:
            decoded = json.loads(props)
        except (json.JSONDecodeError, TypeError):
            return
        commits = decoded.get("commits") if isinstance(decoded, dict) else None
        if isinstance(commits, list):
            self.commits = commits


def parse_commit_signature_status(page_html: str, revision: str) -> str:
    """Extract the Hub's published signature status for one exact commit SHA."""
    if not isinstance(revision, str) or not _REVISION_RE.fullmatch(revision):
        return "not_reported"
    parser = _CommitHistoryParser()
    try:
        parser.feed(page_html)
    except Exception:
        return "not_reported"
    if parser.commits is None:
        return "not_reported"
    for item in parser.commits:
        if not isinstance(item, dict):
            continue
        commit = item.get("commit")
        commit_id = commit.get("id") if isinstance(commit, dict) else None
        if not isinstance(commit_id, str) or commit_id.lower() != revision.lower():
            continue
        status = item.get("verified")
        if status == "verified":
            return "verified"
        if status == "unverified":
            return "unverified"
        if status is None:
            # The Hub omits this property for unsigned commits. The exact commit
            # record must be present before treating an omitted value as unsigned.
            return "unsigned"
        return "not_reported"
    return "not_reported"


def fetch_commit_signature_status(
    model_id: str,
    revision: str,
    token: Optional[str] = None,
    endpoint: Optional[str] = None,
    timeout: float = 15,
) -> dict:
    """Fetch the Hub's signature badge for an immutable model revision.

    The commit-history HTML includes structured Hub verification state while the
    public commits API omits it. Unknown markup or request failures stay
    ``not_reported``; this evidence never contributes to risk scoring.
    """
    result = {
        "status": "not_reported",
        "source": "huggingface_commit_history",
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "note": "Hub signature status could not be read from the commit-history response.",
    }
    if not isinstance(revision, str) or not _REVISION_RE.fullmatch(revision):
        result["note"] = "No valid immutable revision SHA was available for signature lookup."
        return result

    base = (endpoint or os.environ.get("HF_ENDPOINT") or _HF_ENDPOINT).rstrip("/")
    repo_path = quote(model_id.strip("/"), safe="/")
    url = f"{base}/{repo_path}/commits/{quote(revision, safe='')}"
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    try:
        response = requests.get(url, headers=headers, timeout=timeout)
        if response.status_code != 200:
            result["note"] = f"Hub commit-history request returned HTTP {response.status_code}."
            return result
        status = parse_commit_signature_status(response.text, revision)
    except requests.RequestException as exc:
        result["note"] = f"Hub commit-history request failed ({type(exc).__name__})."
        return result

    result["status"] = status
    if status == "verified":
        result["note"] = "The Hub marks this commit signature as verified."
    elif status == "unverified":
        result["note"] = "The Hub reports a signature but could not verify it."
    elif status == "unsigned":
        result["note"] = "The Hub commit record has no signing status."
    else:
        result["note"] = "The Hub response did not expose a recognized signature status for this commit."
    return result


def get_provenance_evidence(model_info: Optional[dict], signature_evidence: Optional[dict] = None) -> dict:
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

    signature = signature_evidence if isinstance(signature_evidence, dict) else {}
    signature_status = signature.get("status", "not_reported")
    if signature_status not in ("verified", "unverified", "unsigned", "not_reported"):
        signature_status = "not_reported"
    return {
        "revision_sha": revision,
        "revision_pinned": revision is not None,
        "revision_note": (
            "SHA identifies the scanned repository snapshot; it does not authenticate the publisher."
            if revision else "No valid immutable revision SHA was reported by the Hub metadata."
        ),
        "signature_status": signature_status,
        "signature_source": signature.get("source"),
        "signature_checked_at": signature.get("checked_at"),
        "signature_note": signature.get("note", "Signature verification was not checked."),
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
