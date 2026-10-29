from __future__ import annotations

from model_harrier import cli


def test_python_source_uses_ast_and_resolves_import_aliases(monkeypatch, tmp_path) -> None:
    path = tmp_path / "modeling_nested.py"
    path.write_text("# eval('comment only')\nimport os as operating\noperating.system('echo unsafe')\n")
    monkeypatch.setattr(cli.hf, "download_file", lambda _model, _name: path)

    findings = cli._scan_python_code([{"rfilename": "nested/modeling.py"}], "owner/model")

    code_findings = [item for item in findings if item["api"] != "file_found"]
    assert len(code_findings) == 1
    assert code_findings[0]["api"] == "os.system"
    assert code_findings[0]["severity"] == "critical"
    assert code_findings[0]["line"] == 3
