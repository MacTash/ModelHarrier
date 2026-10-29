from __future__ import annotations

from model_harrier.scan.pickles import VerificationEngine


def test_pickle_analysis_never_executes_reducer(monkeypatch) -> None:
    import os

    payload = b"\x80\x04cos\nsystem\nX\x0a\x00\x00\x00do-not-run\x85R."

    def forbidden(*_args, **_kwargs):
        raise AssertionError("pickle analysis attempted execution")

    monkeypatch.setattr(os, "system", forbidden)
    result = VerificationEngine().analyze_in_sandbox(payload)

    assert result.load_succeeded is False
    assert result.blocked_imports == ["os.system"]
