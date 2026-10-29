"""Regression checks over the small, hand-labeled calibration corpus."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from model_harrier.scan.datasets import _analyze_dataset
from model_harrier.scan.formats.tokenizer import scan_tokenizer
from model_harrier.scan.static import analyze_datasets


CORPUS_PATH = Path(__file__).parent / "fixtures" / "severity_calibration.json"
CORPUS = json.loads(CORPUS_PATH.read_text())


@pytest.mark.parametrize("case", CORPUS, ids=lambda case: case["name"])
def test_labeled_severity_calibration_case(case: dict) -> None:
    assert case["label_confidence"] in {"high", "medium", "low"}
    scanner = case["scanner"]
    if scanner == "dataset_metadata":
        findings = _analyze_dataset(case["input"])
        observed = [{"type": item["type"], "severity": item["severity"]} for item in findings]
        assert sorted(observed, key=lambda x: (x["type"], x["severity"])) == sorted(
            case["expected"], key=lambda x: (x["type"], x["severity"])
        )
    elif scanner == "dataset_source":
        findings = analyze_datasets([case["input"]["source"]])
        assert [{"risk": item["risk"]} for item in findings] == case["expected"]
    elif scanner == "tokenizer":
        findings = scan_tokenizer(json.dumps(case["input"]).encode())
        assert findings == case["expected"]
    elif scanner == "tokenizer_raw":
        findings = scan_tokenizer(case["input"].encode())
        assert [{"issue": item["issue"], "severity": item["severity"]} for item in findings] == case["expected"]
    else:
        pytest.fail(f"Unknown calibration scanner: {scanner}")
