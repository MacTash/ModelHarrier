from __future__ import annotations

import contextlib
import io
import json
import pickle

from model_harrier import cli
from model_harrier.db import store


def test_local_scan_walks_files_and_reports_ast_findings(monkeypatch, tmp_path) -> None:
    (tmp_path / "config.json").write_text('{"trust_remote_code": true}')
    (tmp_path / "nested").mkdir()
    (tmp_path / "nested" / "model.py").write_text("import os as ops\nops.system('whoami')\n")
    (tmp_path / "weights.pkl").write_bytes(pickle.dumps(__import__("os").system, protocol=4))
    monkeypatch.setattr(store, "record_scan", lambda *args, **kwargs: 1)
    output = io.StringIO()

    with contextlib.redirect_stdout(output):
        cli._scan_local(tmp_path, None, True, False)

    report = json.loads(output.getvalue())
    by_name = {item["file"]: item for item in report["results"]}
    assert report["scan_summary"]["files_scanned"] == 3
    assert any(item["issue"] == "custom_model_code" for item in by_name["config.json"]["findings"])
    assert any(item["issue"] == "dangerous_api_call" for item in by_name["nested/model.py"]["findings"])
    assert by_name["weights.pkl"]["format"] == "pickle"
