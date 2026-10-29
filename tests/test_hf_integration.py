"""Opt-in, rate-limit-aware tests against a public Hugging Face repository."""

from __future__ import annotations

import os
import re
import time
from collections.abc import Callable

import pytest

from model_harrier.scan import hf


def _retry_rate_limited(call: Callable[[], dict], sleep: Callable[[float], None] = time.sleep) -> dict:
    """Retry HTTP 429 responses with Retry-After or bounded exponential delay."""
    for attempt in range(4):
        try:
            return call()
        except Exception as exc:
            response = getattr(exc, "response", None)
            if getattr(response, "status_code", None) != 429 or attempt == 3:
                raise
            headers = getattr(response, "headers", {}) or {}
            try:
                delay = float(headers.get("Retry-After", min(2 ** attempt, 30)))
            except (TypeError, ValueError):
                delay = min(2 ** attempt, 30)
            sleep(max(0, min(delay, 60)))
    raise AssertionError("unreachable")


class _RateLimitError(Exception):
    def __init__(self, retry_after: str = "0") -> None:
        self.response = type("Response", (), {"status_code": 429, "headers": {"Retry-After": retry_after}})()


def test_rate_limit_retry_honors_retry_after():
    sleeps: list[float] = []
    calls = 0

    def call() -> dict:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise _RateLimitError("3")
        return {"ok": True}

    assert _retry_rate_limited(call, sleeps.append) == {"ok": True}
    assert calls == 2
    assert sleeps == [3.0]


@pytest.mark.hf_integration
def test_huggingface_public_model_metadata(tmp_path, monkeypatch):
    if os.environ.get("MODEL_HARRIER_RUN_HF_INTEGRATION") != "1":
        pytest.skip("Set MODEL_HARRIER_RUN_HF_INTEGRATION=1 to enable live Hub requests")

    repo_id = os.environ.get("MODEL_HARRIER_HF_TEST_REPO", "hf-internal-testing/tiny-random-bert")
    monkeypatch.setattr(hf, "CACHE_DIR", tmp_path)
    monkeypatch.setattr(hf, "HF_TOKEN", os.environ.get("HF_TOKEN") or os.environ.get("HUGGINGFACE_TOKEN"))
    info = _retry_rate_limited(lambda: hf.get_model_info(repo_id, use_cache=False))

    assert re.fullmatch(r"[0-9a-f]{40,64}", info.get("sha", ""), re.IGNORECASE)
    assert info.get("siblings")
