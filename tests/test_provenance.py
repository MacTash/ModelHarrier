import json

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
