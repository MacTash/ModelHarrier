from __future__ import annotations

from model_harrier.scan.datasets import _analyze_dataset
from model_harrier.scan.static import analyze_datasets


def test_unknown_license_tag_is_a_compliance_notice_not_a_security_alert() -> None:
    alerts = _analyze_dataset({
        "id": "research/example",
        "downloads": 1_000,
        "tags": ["license:unknown"],
    })

    assert {item["type"] for item in alerts} == {"dataset_unknown_license"}
    assert alerts[0]["severity"] == "medium"


def test_dataset_content_substring_does_not_flag_biology_as_bio() -> None:
    alerts = _analyze_dataset({
        "id": "research/biology-texts",
        "downloads": 1_000,
        "card_data": {"description": "A collection of biology references."},
    })

    assert not [item for item in alerts if item["type"] == "dataset_content_scope"]


def test_sensitive_dataset_content_is_a_low_severity_scope_notice() -> None:
    alerts = _analyze_dataset({
        "id": "research/content-examples",
        "downloads": 1_000,
        "card_data": {"description": "Includes explicit examples for moderation research."},
    })

    notice = next(item for item in alerts if item["type"] == "dataset_content_scope")
    assert notice["severity"] == "low"


def test_context_tags_are_not_classified_as_malicious_artifacts() -> None:
    alerts = _analyze_dataset({
        "id": "research/malware-detection",
        "downloads": 1_000,
        "tags": ["malware", "red-team"],
    })

    notice = next(item for item in alerts if item["type"] == "dataset_context_tags")
    assert notice["severity"] == "low"
    assert all(item["severity"] != "high" for item in alerts)


def test_known_high_risk_dataset_source_keeps_its_high_signal() -> None:
    flags = analyze_datasets(["research/darkweb-corpus"])

    assert flags
    assert flags[0]["risk"] == "critical"
