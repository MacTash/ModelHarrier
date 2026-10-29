import json
from html import escape
from types import SimpleNamespace

from model_harrier import cli
from model_harrier.scan.formats import provenance


def test_provenance_reports_revision_hub_scan_and_signature_limit():
    evidence = provenance.get_provenance_evidence({
        "sha": "a" * 40,
        "security_repo_status": {"scansDone": True, "filesWithIssues": []},
    })

    assert evidence["revision_sha"] == "a" * 40
    assert evidence["revision_pinned"] is True
    assert evidence["hub_security_scan"]["status"] == "complete"
    assert evidence["hub_security_scan"]["files_with_issues"] == []
    assert evidence["signature_status"] == "not_reported"
    assert "does not authenticate" in evidence["revision_note"]


def test_provenance_accepts_api_field_variants_and_reports_issues():
    evidence = provenance.get_provenance_evidence({
        "revision": "b" * 64,
        "securityStatus": {"scans_done": False, "files_with_issues": ["weights.bin"]},
    })

    assert evidence["revision_pinned"] is True
    assert evidence["hub_security_scan"]["status"] == "pending"
    assert evidence["hub_security_scan"]["files_with_issues"] == ["weights.bin"]


def test_invalid_or_missing_revision_is_not_pinned():
    assert provenance.get_provenance_evidence({"sha": "latest"})["revision_pinned"] is False
    assert provenance.get_provenance_evidence({})["revision_sha"] is None


def _history_page(sha: str, status: str | None) -> str:
    commit = {"commit": {"id": sha}}
    if status is not None:
        commit["verified"] = status
    return '<div data-target="CommitHistoryList" data-props="{}"></div>'.format(
        escape(json.dumps({"commits": [commit]}), quote=True)
    )


def test_hub_history_parser_reads_verified_unverified_and_unsigned_statuses():
    sha = "c" * 40
    assert provenance.parse_commit_signature_status(_history_page(sha, "verified"), sha) == "verified"
    assert provenance.parse_commit_signature_status(_history_page(sha, "unverified"), sha) == "unverified"
    assert provenance.parse_commit_signature_status(_history_page(sha, None), sha) == "unsigned"


def test_hub_history_parser_fails_closed_on_unknown_or_missing_commit():
    sha = "d" * 40
    assert provenance.parse_commit_signature_status("<html></html>", sha) == "not_reported"
    assert provenance.parse_commit_signature_status(_history_page("e" * 40, "verified"), sha) == "not_reported"
    assert provenance.parse_commit_signature_status(_history_page(sha, "future-state"), sha) == "not_reported"


def test_fetch_commit_signature_status_uses_exact_revision_and_hub_result(monkeypatch):
    sha = "f" * 40
    response = SimpleNamespace(status_code=200, text=_history_page(sha, "verified"))
    requests_seen = []
    monkeypatch.setattr(provenance.requests, "get", lambda url, **kwargs: requests_seen.append((url, kwargs)) or response)

    result = provenance.fetch_commit_signature_status("org/model", sha, token="hf_example")

    assert result["status"] == "verified"
    assert result["source"] == "huggingface_commit_history"
    assert requests_seen[0][0].endswith(f"/org/model/commits/{sha}")
    assert requests_seen[0][1]["headers"] == {"Authorization": "Bearer hf_example"}


def test_provenance_report_includes_signature_status_without_scoring_it():
    result = provenance.get_provenance_evidence(
        {"sha": "a" * 40}, {"status": "verified", "source": "huggingface_commit_history", "note": "Hub verified"}
    )

    assert result["signature_status"] == "verified"
    assert result["signature_source"] == "huggingface_commit_history"
    assert result["signature_note"] == "Hub verified"


def test_popularity_and_publisher_slug_do_not_create_findings(tmp_path, monkeypatch):
    cache = tmp_path / "blocklist.json"
    cache.write_text(json.dumps([]))
    monkeypatch.setattr(provenance, "BLOCKLIST_CACHE", cache)

    assert provenance.scan_provenance(
        "openai/new-model", {"downloads": 0, "tags": []}, siblings=[]
    ) == []


def test_publisher_analysis_keeps_badges_as_context_only():
    unverified = cli._publisher_analysis("org/model", {}, [], None, "org")
    verified = cli._publisher_analysis("org/model", {}, ["verified"], None, "org")

    assert unverified["risk_contribution"] == 0
    assert verified["risk_contribution"] == 0
    assert "context only" in unverified["explanation"]
