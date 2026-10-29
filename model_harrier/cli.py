"""ModelHarrier CLI — Model Security Scanner.

Usage:
    model-harrier scan <model-id>              Deep scan a HuggingFace model
    model-harrier scan --path <directory>       Scan local directory
    model-harrier scan --list-models            Search available models
    model-harrier list                          Show scan history
    model-harrier show <model-id>               Show last scan result
    model-harrier verify --path <file>          Quick pickle file check
    model-harrier version                       Show version info
"""

import ast
import hashlib
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

from model_harrier import __version__
from model_harrier.db import store
from model_harrier.data import probes as probe_lib
from model_harrier.data.vulnerable_models import check_vulnerable_model
from model_harrier.report.json import generate_json_report, categorize_file
from model_harrier.scan import hf
from model_harrier.scan.pickles import verify_pickle_file, verify_pickle_bytes
from model_harrier.scan.static import perform_static_analysis
from model_harrier.utils.config import MODEL_HARRIER_DIR

app = typer.Typer(
    name="model-harrier",
    help="Static model supply-chain security scanner and terminal workspace",
    add_completion=True,
    pretty_exceptions_show_locals=False,
)
console = Console()

SEVERITY_COLORS = {"critical": "red", "high": "orange3", "medium": "yellow", "low": "blue", "safe": "green"}
SEVERITY_SCORES = {"critical": 10.0, "high": 7.0, "medium": 4.0, "low": 1.0, "safe": 0.0}


def _severity_to_score(severity: str) -> float:
    return SEVERITY_SCORES.get(severity, 3.0)


def _version_callback(value: bool):
    if value:
        console.print(f"model-harrier v{__version__}")
        raise typer.Exit()


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: bool = typer.Option(False, "--version", "-V", help="Show version and exit", callback=_version_callback, is_eager=True),
):
    """Launch the interactive terminal workspace when no command is given."""
    if ctx.invoked_subcommand is None:
        from model_harrier.tui import ModelHarrierApp

        ModelHarrierApp().run()


@app.command()
def scan(
    model_id: str = typer.Argument(None, help="HuggingFace model ID (e.g., 'gpt2', 'meta-llama/Llama-2-7b')"),
    path: Optional[Path] = typer.Option(None, "--path", "-p", help="Scan local directory instead of HF model"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file for JSON report"),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output JSON to stdout"),
    fail_on: Optional[str] = typer.Option(None, "--fail-on", help="Exit non-zero for findings at or above this severity"),
    offline: bool = typer.Option(False, "--offline", help="Use local cache only, no network"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
    list_models: bool = typer.Option(False, "--list-models", help="Search available models"),
    sarif_output: Optional[Path] = typer.Option(None, "--sarif", help="Output SARIF report to file"),
    aibom_output: Optional[Path] = typer.Option(None, "--aibom", help="Output AIBOM (CycloneDX) to file"),
):
    """Deep-scan a HuggingFace model for security vulnerabilities."""
    store.init_db()

    if list_models:
        _list_models()
        return

    if path:
        _scan_local(path, output, json_output, verbose)
        return

    if not model_id:
        console.print("[red]Error:[/] Either provide a <model-id> or use --path")
        raise typer.Exit(code=2)

    _scan_hf_model(model_id, output, json_output, fail_on, offline, verbose, sarif_output, aibom_output)


FILE_TYPE_NAMES = {
    ".py": "Python Module",
    ".json": "JSON Data",
    ".md": "Documentation",
    ".jinja": "Prompt Template",
    ".txt": "Text File",
    ".yaml": "YAML Config",
    ".yml": "YAML Config",
    ".safetensors": "SafeTensors Weights",
    ".gguf": "GGUF Model",
    ".onnx": "ONNX Model",
    ".h5": "Keras/HDF5 Weights",
    ".hdf5": "Keras/HDF5 Weights",
    ".keras": "Keras Model",
    ".pt": "PyTorch Weights",
    ".pth": "PyTorch Weights",
    ".bin": "Binary Weights",
    ".pkl": "Pickle Object",
    ".pickle": "Pickle Object",
    ".zip": "Zip Archive",
    ".tar": "Tar Archive",
    ".gz": "Gzip Archive",
    ".tar.gz": "Compressed Archive",
    ".tgz": "Compressed Archive",
    ".bz2": "Bzip2 Archive",
    ".xz": "XZ Archive",
    ".7z": "7-Zip Archive",
    ".sh": "Shell Script",
    ".js": "JavaScript",
    ".ts": "TypeScript",
    ".cpp": "C++ Source",
    ".c": "C Source",
    ".h": "C Header",
    ".rs": "Rust Source",
    ".go": "Go Source",
    ".gitattributes": "Git Config",
}

DANGEROUS_API_PATTERNS = [
    ("eval", "eval( — dynamic code execution", "critical"),
    ("exec", "exec( — dynamic code execution", "critical"),
    ("compile", "compile( — bytecode compilation", "high"),
    ("pickle.loads", "pickle.loads( — deserialization risk", "high"),
    ("pickle.load", "pickle.load( — deserialization risk", "high"),
    ("marshal.loads", "marshal.loads( — binary deserialization", "critical"),
    ("marshal.load", "marshal.load( — binary deserialization", "critical"),
    ("subprocess.run", "subprocess.run( — shell execution", "critical"),
    ("subprocess.Popen", "subprocess.Popen( — shell execution", "critical"),
    ("subprocess.call", "subprocess.call( — shell execution", "high"),
    ("os.system", "os.system( — shell execution", "critical"),
    ("os.popen", "os.popen( — shell execution", "critical"),
    ("ctypes.CDLL", "ctypes.CDLL( — native code loading", "critical"),
    ("ctypes.windll", "ctypes.windll — native DLL access", "critical"),
    ("socket.connect", "socket.connect( — network connection", "medium"),
    ("socket.send", "socket.send( — data exfiltration", "medium"),
    ("requests.get", "requests.get( — HTTP request from model", "medium"),
    ("requests.post", "requests.post( — HTTP request from model", "medium"),
    ("urllib.request", "urllib.request — HTTP request from model", "medium"),
    ("webbrowser.open", "webbrowser.open( — browser launch", "high"),
    ("os.environ", "os.environ — environment variable access", "low"),
    ("shutil.rmtree", "shutil.rmtree( — filesystem deletion", "high"),
    ("os.remove", "os.remove( — file deletion", "high"),
    ("os.unlink", "os.unlink( — file deletion", "high"),
    ("tempfile.mkdtemp", "tempfile.mkdtemp( — temp file creation", "low"),
]

LICENSE_ANALYSIS = {
    "apache-2.0": {"commercial": "Allowed", "redistribution": "Allowed", "closed_source": "Allowed", "notice": "Required"},
    "mit": {"commercial": "Allowed", "redistribution": "Allowed", "closed_source": "Allowed", "notice": "Required"},
    "bsd": {"commercial": "Allowed", "redistribution": "Allowed", "closed_source": "Allowed", "notice": "Required"},
    "bsd-3-clause": {"commercial": "Allowed", "redistribution": "Allowed", "closed_source": "Allowed", "notice": "Required"},
    "bsd-2-clause": {"commercial": "Allowed", "redistribution": "Allowed", "closed_source": "Allowed", "notice": "Required"},
    "mit-0": {"commercial": "Allowed", "redistribution": "Allowed", "closed_source": "Allowed", "notice": "Not Required"},
    "unlicense": {"commercial": "Allowed", "redistribution": "Allowed", "closed_source": "Allowed", "notice": "Not Required"},
    "cc0-1.0": {"commercial": "Allowed", "redistribution": "Allowed", "closed_source": "Allowed", "notice": "Not Required"},
    "gpl-2.0": {"commercial": "Conditional", "redistribution": "Allowed", "closed_source": "Restricted", "notice": "Required"},
    "gpl-3.0": {"commercial": "Conditional", "redistribution": "Allowed", "closed_source": "Restricted", "notice": "Required"},
    "lgpl-2.1": {"commercial": "Allowed", "redistribution": "Allowed", "closed_source": "Conditional", "notice": "Required"},
    "lgpl-3.0": {"commercial": "Allowed", "redistribution": "Allowed", "closed_source": "Conditional", "notice": "Required"},
    "agpl-3.0": {"commercial": "Conditional", "redistribution": "Allowed", "closed_source": "Restricted", "notice": "Required"},
    "mpl-2.0": {"commercial": "Allowed", "redistribution": "Allowed", "closed_source": "Conditional", "notice": "Required"},
    "cc-by-4.0": {"commercial": "Allowed", "redistribution": "Allowed", "closed_source": "Allowed", "notice": "Required"},
    "cc-by-nc-4.0": {"commercial": "Restricted", "redistribution": "Allowed", "closed_source": "Allowed", "notice": "Required"},
    "cc-by-nc-sa-3.0": {"commercial": "Restricted", "redistribution": "Allowed", "closed_source": "Allowed", "notice": "Required, ShareAlike"},
    "cc-by-sa-4.0": {"commercial": "Allowed", "redistribution": "Allowed", "closed_source": "Allowed", "notice": "Required, ShareAlike"},
    "cc-by-nc-sa-4.0": {"commercial": "Restricted", "redistribution": "Allowed", "closed_source": "Allowed", "notice": "Required, ShareAlike"},
    "llama2": {"commercial": "Allowed", "redistribution": "Allowed", "closed_source": "Allowed", "notice": "Required"},
    "llama3": {"commercial": "Allowed", "redistribution": "Allowed", "closed_source": "Allowed", "notice": "Required"},
    "llama3.1": {"commercial": "Allowed", "redistribution": "Allowed", "closed_source": "Allowed", "notice": "Required"},
    "llama3.2": {"commercial": "Allowed", "redistribution": "Allowed", "closed_source": "Allowed", "notice": "Required"},
    "llama3.3": {"commercial": "Allowed", "redistribution": "Allowed", "closed_source": "Allowed", "notice": "Required"},
    "gemma": {"commercial": "Allowed", "redistribution": "Allowed", "closed_source": "Allowed", "notice": "Required"},
    "gemma-terms": {"commercial": "Allowed", "redistribution": "Allowed", "closed_source": "Allowed", "notice": "Required"},
    "deepseek": {"commercial": "Allowed", "redistribution": "Allowed", "closed_source": "Allowed", "notice": "Required"},
    "openrail": {"commercial": "Allowed", "redistribution": "Allowed", "closed_source": "Allowed", "notice": "Required"},
    "bigscience-openrail-m": {"commercial": "Allowed", "redistribution": "Allowed", "closed_source": "Allowed", "notice": "Required"},
    "bigcode-openrail-m": {"commercial": "Allowed", "redistribution": "Allowed", "closed_source": "Allowed", "notice": "Required"},
    "starcoder2": {"commercial": "Allowed", "redistribution": "Allowed", "closed_source": "Allowed", "notice": "Required"},
    "ai2": {"commercial": "Allowed", "redistribution": "Allowed", "closed_source": "Allowed", "notice": "Required"},
    "odbl": {"commercial": "Allowed", "redistribution": "Allowed", "closed_source": "Conditional", "notice": "Required, ShareAlike"},
    "proprietary": {"commercial": "Restricted", "redistribution": "Restricted", "closed_source": "Allowed", "notice": "Required"},
    "other": {"commercial": "Unknown", "redistribution": "Unknown", "closed_source": "Unknown", "notice": "Unknown"},
}


def _scan_python_code(siblings: list[dict], model_id: str) -> list[dict]:
    findings = []
    py_files = [s for s in siblings if s.get("rfilename", "").endswith(".py")]
    if not py_files:
        findings.append({"file": "N/A", "line": 0, "api": "no_python_files", "severity": "safe", "description": "No Python source files in repository"})
        return findings

    for sibling in py_files:
        filename = sibling["rfilename"]
        try:
            local_path = hf.download_file(model_id, filename)
            content = local_path.read_text(encoding="utf-8", errors="replace")
            size_kb = len(content) / 1024
            findings.append({"file": filename, "line": 0, "api": "file_found", "severity": "info", "description": f"Examined ({size_kb:.1f} KB)"})
            try:
                tree = ast.parse(content, filename=filename)
            except SyntaxError as exc:
                findings.append({"file": filename, "line": exc.lineno or 0, "api": "syntax_error", "severity": "low", "description": f"Could not parse Python source: {exc.msg}"})
                continue

            aliases: dict[str, str] = {}
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    aliases.update({item.asname or item.name.split(".")[0]: item.name for item in node.names})
                elif isinstance(node, ast.ImportFrom):
                    module = node.module or ""
                    aliases.update({item.asname or item.name: f"{module}.{item.name}" for item in node.names})

            def call_path(node: ast.AST) -> str:
                if isinstance(node, ast.Name):
                    return aliases.get(node.id, node.id)
                if isinstance(node, ast.Attribute):
                    prefix = call_path(node.value)
                    return f"{prefix}.{node.attr}" if prefix else node.attr
                return ""

            patterns = {entry[0]: entry[1:] for entry in DANGEROUS_API_PATTERNS}
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                api_pattern = call_path(node.func)
                matched = next((key for key in patterns if api_pattern == key or api_pattern.endswith(f".{key}")), None)
                if matched:
                    description, severity = patterns[matched]
                    findings.append({"file": filename, "line": node.lineno, "col": node.col_offset + 1, "api": matched, "severity": severity, "description": f"{description} at line {node.lineno}"})
        except Exception as e:
            findings.append({"file": filename, "line": 0, "api": "download_failed", "severity": "info", "description": f"Could not download: {e}"})
    return findings


def _scan_python_content(filename: str, content: str) -> list[dict]:
    """Find risky calls in source without matching comments or string literals."""
    try:
        tree = ast.parse(content, filename=filename)
    except SyntaxError as exc:
        return [{"issue": "python_syntax_error", "severity": "low", "description": f"Could not parse Python source at line {exc.lineno}: {exc.msg}"}]

    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            aliases.update({item.asname or item.name.split(".")[0]: item.name for item in node.names})
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            aliases.update({item.asname or item.name: f"{module}.{item.name}" for item in node.names})

    def call_path(node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            prefix = call_path(node.value)
            return f"{prefix}.{node.attr}" if prefix else node.attr
        return ""

    patterns = {entry[0]: entry[1:] for entry in DANGEROUS_API_PATTERNS}
    findings = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        called = call_path(node.func)
        matched = next((key for key in patterns if called == key or called.endswith(f".{key}")), None)
        if matched:
            description, severity = patterns[matched]
            findings.append({
                "issue": "dangerous_api_call",
                "severity": severity,
                "description": f"{description} at {filename}:{node.lineno}",
                "line": node.lineno,
            })
    return findings


def _detect_trust_remote_code(siblings: list[dict], model_info: dict, model_id: str) -> dict:
    result = {"requires": False, "files_loaded": [], "risk_explanation": "Model does not require remote code execution"}
    card_data = model_info.get("cardData") or {}
    if card_data.get("trust_remote_code") is True:
        result["requires"] = True
        result["risk_explanation"] = "Model card explicitly requires trust_remote_code=True"
    config_files = [s for s in siblings if s.get("rfilename", "").endswith("config.json")]
    if config_files:
        try:
            local_path = hf.download_file(model_id, "config.json")
            config = json.loads(local_path.read_text())
            if config.get("trust_remote_code") is True:
                result["requires"] = True
                result["risk_explanation"] = "config.json sets trust_remote_code=True — arbitrary code execution risk"
        except Exception:
            pass
    if result["requires"]:
        for s in siblings:
            fn = s["rfilename"]
            if fn.endswith(".py") and fn.startswith(("modeling", "configuration", "generation", "custom", "modeling_")):
                result["files_loaded"].append(fn)
    return result


def _disassemble_pickle(siblings: list[dict], model_id: str) -> list[dict]:
    findings = []
    pickle_ext = {".pkl", ".pickle", ".dill", ".joblib", ".pt", ".pth", ".ckpt", ".bin"}
    pickle_files = [s for s in siblings if Path(s.get("rfilename", "")).suffix.lower() in pickle_ext]
    if not pickle_files:
        findings.append({"file": "N/A", "opcode": "none_detected", "severity": "safe", "description": "No pickle files detected"})
        return findings

    for sibling in pickle_files:
        filename = sibling["rfilename"]
        file_size = sibling.get("size") or 0
        if file_size > 5 * 1024 * 1024:
            findings.append({"file": filename, "opcode": "scan_size_limit", "severity": "info", "description": f"Pickle opcode scan skipped — {file_size / 1024 / 1024:.1f} MB exceeds the 5 MB inspection cap"})
            continue
        try:
            local_path = hf.download_file(model_id, filename)
            data = local_path.read_bytes()
            findings.append({"file": filename, "opcode": "file_found", "severity": "info", "description": f"Pickle file, {len(data)} bytes"})
            import pickletools
            dangerous_globals = []
            for opcode, arg, pos in pickletools.genops(data):
                opname = opcode.name if hasattr(opcode, 'name') else str(opcode)
                if opname == 'GLOBAL' and arg:
                    arg_str = str(arg)
                    for dangerous_mod in ["os.", "subprocess", "builtins", "ctypes", "shutil", "socket"]:
                        if dangerous_mod in arg_str:
                            dangerous_globals.append((arg_str, pos))
                elif opname == 'REDUCE':
                    findings.append({"file": filename, "opcode": "REDUCE", "severity": "medium", "description": "REDUCE opcode — potential function call", "position": pos})
                elif opname in ('STACK_GLOBAL', 'INST', 'OBJ'):
                    findings.append({"file": filename, "opcode": opname, "severity": "medium", "description": f"{opname} opcode — dynamic reference", "position": pos})
            for arg_str, pos in dangerous_globals:
                findings.append({"file": filename, "opcode": "GLOBAL", "severity": "critical", "description": f"GLOBAL reference: {arg_str}", "position": pos})
            if not dangerous_globals:
                findings.append({"file": filename, "opcode": "safe", "severity": "safe", "description": "No dangerous pickle opcodes detected"})
        except Exception as e:
            findings.append({"file": filename, "opcode": "error", "severity": "info", "description": f"Could not analyze: {e}"})
    return findings


def _parse_dependencies(siblings: list[dict], model_id: str) -> dict:
    result = {"deps": [], "typosquat_risk": [], "git_deps": [], "known_cves": []}
    dep_files = [s for s in siblings if s.get("rfilename", "") in ("requirements.txt", "setup.py", "pyproject.toml")]
    for sibling in dep_files:
        filename = sibling["rfilename"]
        try:
            local_path = hf.download_file(model_id, filename)
            text = local_path.read_text(encoding="utf-8", errors="replace")
            if filename == "requirements.txt":
                for line in text.split("\n"):
                    line = line.strip()
                    if line and not line.startswith("#"):
                        pkg = re.split(r'[=<>!~]', line)[0].strip()
                        if pkg:
                            result["deps"].append(pkg)
            elif filename == "setup.py":
                for match in re.finditer(r'["\']([a-zA-Z0-9_.-]+)["\'][\s,]*', text):
                    pkg = match.group(1)
                    if pkg and pkg not in ("setuptools", "pip", "wheel"):
                        result["deps"].append(pkg)
            elif filename == "pyproject.toml":
                for match in re.finditer(r'(?:requires|dependencies)\s*=\s*\[([^\]]+)\]', text, re.DOTALL):
                    content = match.group(1)
                    for dep_match in re.finditer(r'["\']([a-zA-Z0-9_.-]+)', content):
                        result["deps"].append(dep_match.group(1))
        except Exception:
            pass

    result["deps"] = list(set(result["deps"]))
    typosquat_map = {"tensorflow": "tensorflow", "torch": "pytorch", "transfomers": "transformers", "torchvision": "torchvision"}
    for dep in result["deps"]:
        if dep.lower() in typosquat_map:
            result["typosquat_risk"].append({"dep": dep, "suspected": typosquat_map[dep.lower()]})
        if dep.startswith("git+"):
            result["git_deps"].append(dep)
    return result


def _aggregate_safetensors(file_findings: list[dict], model_info: dict) -> dict:
    safetensors_filenames = set(f["filename"] for f in file_findings if f["filename"].endswith(".safetensors"))
    total_tensors = 0
    metadata_fields: set[str] = set()
    shard_count = len(safetensors_filenames)
    anomalies = []
    suspicious_meta = []
    for f in file_findings:
        if f.get("category") != "deep_scan":
            continue
        desc = f.get("description", "")
        if desc.startswith("Tensors:"):
            import re
            m = re.search(r'Tensors:\s*(\d+)', desc)
            if m:
                total_tensors += int(m.group(1))
        if desc.startswith("Metadata keys:"):
            keys_str = desc.split(":", 1)[1].strip()
            for k in keys_str.split(","):
                k = k.strip()
                if k:
                    metadata_fields.add(k)
    return {
        "shard_count": shard_count,
        "tensor_count": total_tensors or "Not computed (deep scan skipped)",
        "metadata_fields": sorted(metadata_fields),
        "anomalies": anomalies,
        "suspicious_metadata": suspicious_meta,
    }


def _aggregate_gguf_info(file_findings: list[dict]) -> dict:
    """Aggregate GGUF metadata from deep_scan findings."""
    meta = {
        "files": 0,
        "architecture": set(),
        "quantization": set(),
        "context_length": None,
        "layers": None,
        "hidden_size": None,
        "num_heads": None,
        "parameter_count": None,
        "tensor_count": 0,
    }
    descriptors = {}
    for f in file_findings:
        if f.get("category") != "deep_scan":
            continue
        desc = f.get("description", "")
        if desc.startswith("Architecture:"):
            meta["architecture"].add(desc.split(":", 1)[1].strip())
        elif desc.startswith("Quantization:"):
            meta["quantization"].add(desc.split(":", 1)[1].strip())
        elif desc.startswith("Context Length:"):
            try:
                meta["context_length"] = int(desc.split(":", 1)[1].strip())
            except (ValueError, IndexError):
                pass
        elif desc.startswith("Parameters:"):
            meta["parameter_count"] = desc.split(":", 1)[1].strip()
        elif desc.startswith("Deep scan skipped"):
            fn = f["filename"]
            if fn.endswith(".gguf"):
                descriptors.setdefault(fn, {})["skipped"] = True
    for f in file_findings:
        if f.get("category") == "deep_scan" and f["filename"].endswith(".gguf") and f.get("issue") == "gguf_metadata":
            meta["files"] += 1
    return meta


def _compute_security_confidence(model_info: dict, file_findings: list[dict]) -> dict:
    siblings = model_info.get("siblings", [])
    total_files = len(siblings)
    total_bytes = 0
    files_with_size = 0
    for s in siblings:
        sz = s.get("size")
        if sz and sz > 0:
            total_bytes += sz
            files_with_size += 1

    deep_by_file: dict[str, list[dict]] = {}
    for f in file_findings:
        if f.get("category") == "deep_scan":
            deep_by_file.setdefault(f["filename"], []).append(f)

    weight_exts = {".safetensors", ".gguf", ".bin", ".pt", ".pth", ".h5", ".hdf5", ".onnx"}
    deep_scanned_ok = 0
    deep_scanned_skipped = 0
    deep_scanned_bytes = 0
    deep_failed = 0
    for fn, entries in deep_by_file.items():
        skipped = any(e.get("issue") in ("scan_size_limit", "scan_size_unknown") for e in entries)
        failed = any(e.get("issue") == "download_failed" for e in entries)
        if skipped:
            deep_scanned_skipped += 1
        elif failed:
            deep_failed += 1
        else:
            deep_scanned_ok += 1
            for sib in siblings:
                if sib.get("rfilename") == fn:
                    sz = sib.get("size", 0)
                    if sz and sz > 0:
                        deep_scanned_bytes += sz

    total_candidates = len(deep_by_file)
    card_data = model_info.get("cardData")
    has_card = card_data is not None and bool(card_data)
    has_config_info = any("config.json" in str(f.get("filename", "")) for f in file_findings)

    metadata_pct = round((files_with_size / max(total_files, 1)) * 100) if total_files > 0 else 0
    deep_pct = round((deep_scanned_ok / max(total_candidates, 1)) * 100) if total_candidates > 0 else 100
    byte_pct = round((deep_scanned_bytes / max(total_bytes, 1)) * 100) if total_bytes > 0 else 0
    model_info_score = 100 if has_card and has_config_info else 50 if has_card or has_config_info else 0

    overall = round(metadata_pct * 0.25 + deep_pct * 0.30 + byte_pct * 0.20 + model_info_score * 0.25)
    overall = max(0, min(100, overall))

    unscanned = []
    for fn in deep_by_file:
        entries = deep_by_file[fn]
        if any(e.get("issue") in ("scan_size_limit", "scan_size_unknown") for e in entries):
            sib = next((s for s in siblings if s.get("rfilename") == fn), None)
            sz = sib.get("size") if sib else None
            reason = f"File size {sz / 1024 / 1024:.0f} MB exceeds deep-scan threshold" if sz else "File size unknown"
            unscanned.append({"file": fn, "reason": reason, "category": "deep_skipped"})
    for fn in deep_by_file:
        entries = deep_by_file[fn]
        if any(e.get("issue") == "download_failed" for e in entries):
            unscanned.append({"file": fn, "reason": "Download failed", "category": "download_failed"})

    weight_files_no_scan = []
    for s in siblings:
        fn = s.get("rfilename", "")
        ext = Path(fn).suffix.lower()
        if ext in weight_exts and fn not in deep_by_file:
            weight_files_no_scan.append(fn)
    for fn in weight_files_no_scan:
        unscanned.append({"file": fn, "reason": "No deep scan attempted", "category": "not_scanned"})

    for s in siblings:
        fn = s.get("rfilename", "")
        if fn not in deep_by_file and fn not in weight_files_no_scan:
            pass

    return {
        "confidence_pct": overall,
        "confidence_level": "HIGH" if overall >= 80 else "MEDIUM" if overall >= 50 else "LOW",
        "metadata_coverage": {"inspected": files_with_size, "total": total_files, "pct": metadata_pct},
        "deep_scan_rate": {"scanned": deep_scanned_ok, "skipped": deep_scanned_skipped, "failed": deep_failed, "total": total_candidates, "pct": deep_pct},
        "byte_coverage": {"inspected": deep_scanned_bytes, "total": total_bytes, "pct": byte_pct},
        "model_info_completeness": model_info_score,
        "unscanned": unscanned,
    }


def _analyze_license(license_id: str) -> dict:
    if not license_id:
        return LICENSE_ANALYSIS.get("other", {})
    license_lower = license_id.strip().lower()
    if license_lower in LICENSE_ANALYSIS:
        return LICENSE_ANALYSIS[license_lower]
    for key in sorted(LICENSE_ANALYSIS.keys(), key=len, reverse=True):
        if key in license_lower:
            return LICENSE_ANALYSIS[key]
    return LICENSE_ANALYSIS["other"]


def _build_lineage(base_model: Optional[str], training_data: list[str]) -> list[str]:
    chain = []
    if base_model:
        chain.append(base_model)
    for t in training_data:
        chain.append(t)
    return chain


def _readable_timestamp(ts) -> str:
    if not ts:
        return "Unknown"
    if hasattr(ts, "strftime"):
        return ts.strftime("%Y-%m-%d")
    ts_str = str(ts)
    if "T" in ts_str:
        return ts_str[:10]
    return ts_str[:10] if len(ts_str) >= 10 else ts_str


BEHAVIORAL_KEYWORDS = {
    "obliterated": "Model name suggests intentional safety removal",
    "abliterated": "Model name suggests intentional safety removal",
    "uncensored": "Claims to bypass content filters",
    "unrestricted": "Claims to have no restrictions",
    "jailbreak": "Bypass or jailbreak reference",
    "nsfw": "Not safe for work content",
    "unfiltered": "Claims to have no content filtering",
    "no_filter": "Claims to have no content filtering",
    "harmful": "Potentially harmful content",
    "dangerous": "Potentially dangerous content",
    "porn": "Adult content indicator",
    "adult": "Adult content indicator",
    "explicit": "Explicit content indicator",
}


def _assess_behavioral_risk(model_id: str, readme: Optional[str], card_data: Optional[dict], tags: list[str]) -> dict:
    findings = []
    model_name_lower = model_id.lower()
    for kw, reason in BEHAVIORAL_KEYWORDS.items():
        if kw in model_name_lower:
            findings.append({"source": "model_name", "keyword": kw, "reason": reason, "severity": "high"})

    if readme:
        readme_lower = readme.lower()
        for kw, reason in BEHAVIORAL_KEYWORDS.items():
            if kw in readme_lower:
                findings.append({"source": "readme", "keyword": kw, "reason": reason, "severity": "medium"})

    if tags:
        for tag in tags:
            tag_lower = tag.lower()
            for kw, reason in BEHAVIORAL_KEYWORDS.items():
                if kw in tag_lower:
                    findings.append({"source": "tags", "keyword": kw, "reason": reason, "severity": "medium"})
                    break

    description = (card_data or {}).get("description", "") if card_data else ""
    if description:
        desc_lower = description.lower()
        for kw, reason in BEHAVIORAL_KEYWORDS.items():
            if kw in desc_lower:
                findings.append({"source": "card_description", "keyword": kw, "reason": reason, "severity": "medium"})

    if findings:
        top_severity = "high" if any(f["severity"] == "high" for f in findings) else "medium"
        return {"findings": findings, "severity": top_severity, "alert_generated": True}
    return {"findings": [], "severity": "safe", "alert_generated": False}


def _compute_risk_categories(static_analysis: dict, file_findings: list, alerts: list, trust_remote: dict, behavioral: dict, license_info: dict) -> dict:
    exec_score = 0.0
    supply_score = 0.0
    behavior_score = 0.0
    compliance_score = 0.0

    has_pickle = any(f.get("category") == "risky" for f in file_findings)
    if trust_remote.get("requires"):
        exec_score += 8.0
    if has_pickle:
        exec_score += 6.0
    critical_apis = sum(1 for a in alerts if a.get("severity") in ("critical", "high") and ("api_" in a.get("type", "") or "pickle_" in a.get("type", "")))
    exec_score += min(4.0, critical_apis * 2.0)

    if static_analysis.get("base_model_risk"):
        rm = static_analysis["base_model_risk"].get("risk", "")
        supply_score += {"critical": 6.0, "high": 5.0, "medium": 3.0, "low": 1.0}.get(rm, 0)
    supply_score += min(4.0, len(static_analysis.get("risky_dataset_flags", [])) * 2.0)
    if static_analysis.get("unsafe_keywords"):
        supply_score += min(3.0, len(static_analysis["unsafe_keywords"]) * 0.5)

    if behavioral["alert_generated"]:
        sev = behavioral["severity"]
        behavior_score += {"high": 8.0, "medium": 5.0}.get(sev, 0)
    for finding in static_analysis.get("findings", []):
        if any(kw in finding.lower() for kw in ("concerning", "unsafe patterns", "nsfw", "explicit", "adult", "jailbreak", "bypass")):
            behavior_score += 2.0

    lic_statuses = [v for k, v in license_info.items() if k in ("commercial", "redistribution", "closed_source")]
    for s in lic_statuses:
        if s == "Restricted":
            compliance_score += 3.0
        elif s == "Conditional":
            compliance_score += 1.0
        elif s == "Unknown":
            compliance_score += 2.0
    if static_analysis.get("config_flags"):
        compliance_score += min(2.0, len(static_analysis["config_flags"]) * 0.5)

    def label(s):
        if s >= 7.0:
            return "HIGH", "red"
        if s >= 4.0:
            return "MEDIUM", "yellow"
        if s >= 1.0:
            return "LOW", "blue"
        return "NONE", "green"

    return {
        "execution": {"score": round(exec_score, 1), "severity": label(exec_score)[0], "color": label(exec_score)[1]},
        "supply_chain": {"score": round(supply_score, 1), "severity": label(supply_score)[0], "color": label(supply_score)[1]},
        "behavioral": {"score": round(behavior_score, 1), "severity": label(behavior_score)[0], "color": label(behavior_score)[1]},
        "compliance": {"score": round(compliance_score, 1), "severity": label(compliance_score)[0], "color": label(compliance_score)[1]},
    }


def _extract_model_card_intelligence(readme: Optional[str], card_data: Optional[dict], tags: list[str]) -> dict:
    arch = None
    param_count = None
    layers = None
    purpose = None
    claims: list[str] = []

    if readme:
        for line in readme.split("\n"):
            ll = line.strip().lower()
            if "architecture:" in ll or "model architecture:" in ll:
                arch = line.split(":", 1)[1].strip()[:100] if ":" in line else None
            if "parameters:" in ll and arch is None:
                val = line.split(":", 1)[1].strip()[:50] if ":" in line else ""
                if val and any(c.isdigit() for c in val):
                    param_count = val
            if "layers:" in ll:
                val = line.split(":", 1)[1].strip()[:50] if ":" in line else ""
                if val and val.isdigit():
                    layers = val
            if "intended use" in ll or "purpose:" in ll or "use case:" in ll:
                purpose = line.split(":", 1)[1].strip()[:150] if ":" in line else purpose

    claim_keywords = {
        "alignment research": "Alignment research",
        "red-team": "Red-team evaluation",
        "red team": "Red-team evaluation",
        "safety evaluation": "Safety evaluation",
        "refusal removal": "Refusal removal",
        "safety guardrails removed": "Safety guardrails removed",
        "abliteration": "Abliteration research",
        "mechanistic interpretability": "Mechanistic interpretability",
        "research only": "Research only",
        "not for production": "Not for production",
        "evaluation purposes": "Evaluation purposes",
    }
    if readme:
        readme_lower = readme.lower()
        for keyword, claim in claim_keywords.items():
            if keyword in readme_lower and claim not in claims:
                claims.append(claim)

    if tags:
        tag_text = " ".join(t.lower() for t in tags)
        for keyword, claim in claim_keywords.items():
            if keyword in tag_text and claim not in claims:
                claims.append(claim)

    if card_data:
        card_text = str(card_data).lower()
        for keyword, claim in claim_keywords.items():
            if keyword in card_text and claim not in claims:
                claims.append(claim)

    return {
        "architecture": arch,
        "param_count": param_count,
        "layers": layers,
        "purpose": purpose,
        "claims": claims,
    }


def _classify_artifact_type(readme: Optional[str], tags: list[str]) -> dict:
    research_indicators = ["research", "red-team", "red team", "safety evaluation", "alignment research", "abliteration", "evaluation", "research artifact", "not for production"]
    score = 0
    evidence = []
    model_lower = (readme or "").lower()
    for ind in research_indicators:
        if ind in model_lower:
            score += 1
            evidence.append(f"README mentions '{ind}'")
    tag_text = " ".join(t.lower() for t in tags)
    for ind in research_indicators:
        if ind in tag_text:
            if f"tags mention '{ind}'" not in evidence:
                score += 1
                evidence.append(f"Tags mention '{ind}'")
    if score >= 3:
        artifact_type = "Research Artifact"
        confidence = "High"
    elif score >= 1:
        artifact_type = "Research Artifact"
        confidence = "Medium"
    else:
        artifact_type = "Model Release"
        confidence = "High"
    return {"type": artifact_type, "confidence": confidence, "evidence": evidence[:5]}


def _publisher_analysis(model_id: str, model_info: dict, tags: list[str], readme: Optional[str], publisher: str) -> dict:
    signals = []
    if model_info.get("author"):
        signals.append(("✓", "Author field present"))
    if model_info.get("downloads", 0) > 1000:
        signals.append(("i", f"Repository download count: {model_info.get('downloads', 0):,} (popularity context only)"))
    if tags:
        if any("verified" in t.lower() for t in tags):
            signals.append(("✓", "Hugging Face verified organization"))
        else:
            signals.append(("✗", "Not verified by Hugging Face"))
    has_readme = bool(readme)
    if has_readme:
        signals.append(("✓", "Public model documentation (README)"))
    siblings = model_info.get("siblings", [])
    model_count = len({s.get("rfilename", "").split("/")[0] for s in siblings if "/" in s.get("rfilename", "")})
    if model_count > 0:
        signals.append(("✓", f"Organized repository structure"))
    verified = any("verified" in str(t).lower() for t in (tags or []))
    return {
        "signals": signals,
        "verified": verified,
        "risk_contribution": 0,
        "explanation": "Publisher identity, verification badges, and popularity are context only; they do not establish model safety.",
    }


def _scan_hf_model(model_id: str, output: Optional[Path], json_output: bool, fail_on: Optional[str], offline: bool, verbose: bool, sarif_output: Optional[Path] = None, aibom_output: Optional[Path] = None):
    if json_output:
        try:
            model_info = hf.get_model_info(model_id, use_cache=offline, offline=offline)
        except Exception as e:
            print(json.dumps({"error": str(e), "model_id": model_id}))
            raise typer.Exit(code=2)
    else:
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
            progress.add_task(description=f"Scanning [bold]{model_id}[/]...", total=None)
            try:
                model_info = hf.get_model_info(model_id, use_cache=offline, offline=offline)
            except Exception as e:
                console.print(f"[red]Error:[/] Failed to fetch model info: {e}")
                raise typer.Exit(code=2)

    siblings = model_info.get("siblings", [])
    raw_card = model_info.get("cardData") or {}
    if isinstance(raw_card, str):
        try:
            model_info["cardData"] = json.loads(raw_card)
        except (json.JSONDecodeError, ValueError):
            model_info["cardData"] = {}
    else:
        model_info["cardData"] = raw_card or {}
    file_findings = []
    scannable_files = []
    for sibling in siblings:
        filename = sibling.get("rfilename", "")
        if not filename:
            continue
        category, desc, score = categorize_file(filename)
        file_findings.append({"filename": filename, "category": category, "description": desc, "risk_score": score})
        if category == "model" and not offline:
            scannable_files.append(filename)

    if verbose:
        console.print(f"\n[bold]Files found:[/] {len(file_findings)}")
        for f in file_findings:
            color = SEVERITY_COLORS.get("critical" if f["risk_score"] >= 8 else "high" if f["risk_score"] >= 5 else "safe")
            console.print(f"  [{color}]•[/] {f['filename']} — {f['description']}")

    from model_harrier.scan.formats import scan_file
    from model_harrier.scan.formats.provenance import get_provenance_evidence, scan_provenance as scan_provenance_check

    if scannable_files:
        from model_harrier.scan import hf as hf_client
        from model_harrier.scan.formats.weights import scan_weights
        siblings_by_name = {s.get("rfilename", ""): s for s in siblings}
        for filename in scannable_files[:20]:
            try:
                sibling_info = siblings_by_name.get(filename, {})
                file_size = sibling_info.get("size", 0) if isinstance(sibling_info, dict) else 0
            except Exception:
                file_size = 0

            weight_extensions = {".gguf", ".safetensors", ".bin", ".pt", ".pth", ".h5", ".hdf5", ".onnx"}
            ext = Path(filename).suffix.lower()
            is_weight_file = ext in weight_extensions

            deep_findings = []
            max_dl = 5 * 1024 * 1024  # 5 MB cap for any downloaded file
            if is_weight_file and file_size and file_size > max_dl:
                deep_findings = scan_weights(b"", {"file_size": file_size, "library_name": model_info.get("library_name", "")})
                deep_findings.append({"issue": "scan_size_limit", "severity": "low", "description": f"Deep scan skipped — {file_size / 1024 / 1024:.0f} MB file exceeds 5 MB limit"})
            elif is_weight_file and not file_size:
                deep_findings.append({"issue": "scan_size_unknown", "severity": "low", "description": f"Deep scan skipped — file size unknown"})
            elif not is_weight_file and file_size and file_size > max_dl:
                deep_findings.append({"issue": "scan_size_limit", "severity": "low", "description": f"Deep scan skipped — {file_size / 1024 / 1024:.0f} MB file exceeds 5 MB limit"})
            elif not is_weight_file and not file_size:
                deep_findings.append({"issue": "scan_size_unknown", "severity": "low", "description": f"Deep scan skipped — file size unknown"})
            else:
                try:
                    local_path = hf_client.download_file(model_id, filename)
                    with open(local_path, "rb") as f:
                        data = f.read()
                    deep_findings = scan_file(filename, data)
                except Exception as e:
                    err_msg = str(e)[:80] if str(e) else "unknown error"
                    deep_findings = [{"issue": "download_failed", "severity": "low", "description": f"Could not download {filename} for deep scan — {err_msg}"}]

            for df in deep_findings:
                file_findings.append({
                    "filename": filename,
                    "category": "deep_scan",
                    "description": df["description"],
                    "risk_score": _severity_to_score(df.get("severity", "medium")),
                    "issue": df.get("issue", ""),
                    "severity": df.get("severity", "medium"),
                })

    provenance_findings = scan_provenance_check(model_id, model_info, siblings)
    for pf in provenance_findings:
        file_findings.append({
            "filename": "provenance",
            "category": "provenance",
            "description": pf["description"],
            "risk_score": _severity_to_score(pf.get("severity", "medium")),
            "issue": pf.get("issue", ""),
            "severity": pf.get("severity", "medium"),
        })

    tags = model_info.get("tags", [])
    card_data = model_info.get("cardData") or {}

    readme_content = None
    if not offline:
        try:
            readme_content = hf.get_model_card(model_id)
        except Exception:
            pass

    static_analysis = perform_static_analysis(
        model_id=model_id,
        card_data=card_data,
        tags=tags,
        spaces_url=None,
        readme_content=readme_content,
    )

    alerts = []
    vuln = check_vulnerable_model(model_id)
    if vuln:
        alerts.append({"type": "vulnerable_model", "severity": vuln["risk"], "description": f"{vuln['name']}: {vuln['reason']}"})

    risky_files = [f for f in file_findings if f["category"] == "risky"]
    if risky_files:
        alerts.append({"type": "unsafe_files", "severity": "high", "description": f"Found {len(risky_files)} unsafe file(s): {', '.join(f['filename'] for f in risky_files[:5])}"})

    deep_alerts = [f for f in file_findings if f.get("severity") in ("critical", "high")]
    for da in deep_alerts:
        alerts.append({"type": da.get("issue", "deep_scan_finding"), "severity": da["severity"], "description": da["description"]})

    if not offline:
        from model_harrier.scan.datasets import scan_training_datasets, extract_dataset_ids_from_model
        dataset_ids = extract_dataset_ids_from_model(model_info, readme_content)
        if dataset_ids:
            dataset_result = scan_training_datasets(dataset_ids)
            static_analysis["dataset_scan"] = {
                "datasets_scanned": dataset_result["datasets_scanned"],
                "datasets_failed": dataset_result["datasets_failed"],
                "datasets": dataset_result["datasets"],
            }
            for ds_alert in dataset_result["alerts"]:
                alerts.append({
                    "type": ds_alert["type"],
                    "severity": ds_alert["severity"],
                    "description": ds_alert["description"],
                })

    # --- Python Code Analysis ---
    python_scan = {"files_examined": [], "findings": []}
    if not offline:
        python_scan["findings"] = _scan_python_code(siblings, model_id)
        for s in siblings:
            if s.get("rfilename", "").endswith(".py"):
                python_scan["files_examined"].append(s["rfilename"])
        for pf in python_scan["findings"]:
            if pf.get("severity") in ("critical", "high", "medium"):
                file_findings.append({
                    "filename": pf["file"],
                    "category": "code",
                    "description": pf["description"],
                    "risk_score": _severity_to_score(pf["severity"]),
                    "issue": f"api_{pf['api']}",
                    "severity": pf["severity"],
                })

    # --- Dependency Analysis ---
    dependency_analysis = {"deps": [], "typosquat_risk": [], "git_deps": [], "known_cves": []}
    if not offline:
        dependency_analysis = _parse_dependencies(siblings, model_id)

    # --- Pickle Disassembly ---
    pickle_analysis = []
    if not offline:
        pickle_analysis = _disassemble_pickle(siblings, model_id)
        for pk in pickle_analysis:
            if pk.get("severity") in ("critical", "high", "medium"):
                file_findings.append({
                    "filename": pk["file"],
                    "category": "risky",
                    "description": pk["description"],
                    "risk_score": _severity_to_score(pk["severity"]),
                    "issue": f"pickle_{pk['opcode']}",
                    "severity": pk["severity"],
                })

    # --- Trust Remote Code Detection ---
    trust_remote = _detect_trust_remote_code(siblings, model_info, model_id)

    # --- License Analysis ---
    raw_license = (card_data or {}).get("license", "") if card_data else ""
    license_info = _analyze_license(raw_license)

    # --- Behavioral Risk Assessment ---
    behavioral_risk = _assess_behavioral_risk(model_id, readme_content, card_data, tags)

    # --- Risk Categories ---
    publisher_verified = bool(tags and any("verified" in tag.lower() for tag in tags))
    risk_categories = _compute_risk_categories(static_analysis, file_findings, alerts, trust_remote, behavioral_risk, license_info)

    # --- Model Card Intelligence ---
    card_intel = _extract_model_card_intelligence(readme_content, card_data, tags)
    artifact_type = _classify_artifact_type(readme_content, tags)
    publisher_name = model_id.split("/")[0] if "/" in model_id else model_id
    pub_analysis = _publisher_analysis(model_id, model_info, tags, readme_content, publisher_name)

    # --- Aggregate Analysis ---
    safetensors_info = _aggregate_safetensors(file_findings, model_info)
    gguf_info = _aggregate_gguf_info(file_findings)
    confidence_info = _compute_security_confidence(model_info, file_findings)
    deep_results = [item for item in file_findings if item.get("category") == "deep_scan"]
    scan_coverage = {
        "revision": model_info.get("sha"),
        "provenance": get_provenance_evidence(model_info),
        "files_listed": len(siblings),
        "deep_scan_findings": len(deep_results),
        "omitted_or_limited": [
            {"file": item.get("filename"), "reason": item.get("issue"), "detail": item.get("description")}
            for item in deep_results
            if item.get("issue") in ("scan_size_limit", "scan_size_unknown", "download_failed")
        ],
        "security_confidence": confidence_info,
    }
    lineage = _build_lineage(static_analysis.get("base_model"), static_analysis.get("training_data_sources", []))

    report_json = generate_json_report(
        model_id=model_id,
        model_info=model_info,
        file_findings=file_findings,
        static_analysis=static_analysis,
        alerts=alerts,
        coverage=scan_coverage,
    )

    report = json.loads(report_json)
    summary = report["scan_summary"]

    if not json_output:
        score_color = SEVERITY_COLORS.get(summary["severity"], "white")
        c = console

        def title(text):
            c.print(f"\n[bold]{text}[/]")

        def section(text):
            c.print(f"\n[bold]─ {text} ─[/]")

        def kv(k, v, clr=None):
            if clr:
                c.print(f"  [{clr}]{k}:[/] {v}")
            else:
                c.print(f"  {k}: {v}")

        def bullet(text, clr=None):
            if clr:
                c.print(f"  [{clr}]•[/] {text}")
            else:
                c.print(f"  • {text}")

        def sub(text, clr=None):
            if clr:
                c.print(f"    [{clr}]→[/] {text}")
            else:
                c.print(f"    → {text}")

        # ── Header ──
        c.print(f"\n[bold]═══ MODEL SECURITY ASSESSMENT ═══[/]")
        c.print(f"[{score_color}]Risk Score:[/] {summary['risk_score']}/10 ({summary['severity'].upper()})")
        c.print(f"Model: {model_id}")

        # ── Repository Overview ──
        section("Repository Overview")
        card_data = model_info.get("cardData") or {}
        publisher = model_id.split("/")[0] if "/" in model_id else "?"
        verified_org = "No"
        if hasattr(model_info.get("_safer_metadata"), "get"):
            pass
        kv("Publisher", publisher)
        ver = "No"
        for tag in model_info.get("tags", []):
            if "verified" in tag.lower():
                ver = "Yes"
        kv("Verified Organization", ver)
        kv("Downloads", f"{model_info.get('downloads', 0):,}")
        kv("Likes", f"{model_info.get('likes', 0):,}")
        lic_raw = card_data.get("license", "Not Specified") if card_data else "Not Specified"
        kv("License", lic_raw)
        created = _readable_timestamp(model_info.get("created_at"))
        updated = _readable_timestamp(model_info.get("last_modified") or model_info.get("updated_at"))
        kv("Created", created)
        kv("Last Updated", updated)
        lib_name = model_info.get("library_name") or "?"
        kv("Library", lib_name)
        pipeline = model_info.get("pipeline_tag") or "?"
        kv("Pipeline", pipeline)
        if model_info.get("private"):
            c.print("  [red]PRIVATE REPOSITORY[/]")

        # ── Revision and Provenance Evidence ──
        provenance = scan_coverage["provenance"]
        section("Revision & Provenance Evidence")
        kv("Scanned Revision", provenance["revision_sha"] or "Not reported")
        kv("Revision Pin", "Pinned to immutable snapshot" if provenance["revision_pinned"] else "No valid revision pin reported")
        kv("Commit Signature", provenance["signature_status"])
        kv("Signature Note", provenance["signature_note"])
        hub_scan = provenance["hub_security_scan"]
        kv("Hub Repository Scan", hub_scan["status"])
        kv("Hub Reported Files With Issues", len(hub_scan["files_with_issues"]))
        kv("Evidence Note", hub_scan["note"])

        # ── Publisher Analysis ──
        section("Publisher Analysis")
        kv("Publisher", publisher)
        kv("HF Verification Status", "✗ Not verified by Hugging Face" if not publisher_verified else "✓ Verified")
        if pub_analysis["signals"]:
            c.print("  [dim]Observed Signals:[/]")
            for icon, signal in pub_analysis["signals"]:
                c.print(f"    {icon} {signal}")
        c.print("  [dim]Risk Contribution:[/] 0 (identity context only)")
        c.print(f"  [dim]Context:[/] {pub_analysis['explanation']}")
        if artifact_type["type"] == "Research Artifact":
            c.print(f"  [dim]Artifact Classification:[/] {artifact_type['type']} (confidence: {artifact_type['confidence']})")
            for ev in artifact_type["evidence"]:
                c.print(f"    [dim]→[/] {ev}")

        # ── Executive Summary ──
        section("Executive Summary")
        c.print(f"  Overall Risk: [{score_color}]{summary['severity'].upper()}[/] ({summary['risk_score']}/10)")

        findings_bullets = []
        # Pickle-capable artifacts remain deserialization risks even when
        # opcode analysis found no dangerous reducer or hit the size cap.
        pickle_suffixes = {".pkl", ".pickle", ".dill", ".joblib", ".pt", ".pth", ".ckpt", ".bin"}
        has_pickle = any(p.get("opcode") == "file_found" for p in pickle_analysis) or any(
            Path(f.get("filename", "")).suffix.lower() in pickle_suffixes for f in file_findings
        )
        has_exec = any(f.get("issue", "").startswith("pickle_") for f in file_findings)
        uses_safetensors = any(f["filename"].endswith(".safetensors") for f in file_findings)
        publisher_unverified = ver == "No"
        has_lineage = bool(static_analysis.get("base_model"))
        has_additional_data = bool(static_analysis.get("training_data_sources"))

        findings_bullets.append(("[red]✗[/]" if has_pickle else "[green]✓[/]") + " " + ("Pickle-capable artifacts detected — avoid unsafe deserialization" if has_pickle else "No pickle-capable artifacts detected"))
        findings_bullets.append(("[red]✗[/]" if has_exec else "[green]✓[/]") + " " + ("Executable payloads detected" if has_exec else "No executable payloads detected"))
        findings_bullets.append(("[green]✓[/]" if uses_safetensors else "[yellow]⚠[/]") + " " + ("SafeTensors file present; see scan coverage for validation status" if uses_safetensors else "No SafeTensors files found — consider safetensors conversion"))
        findings_bullets.append("[dim]i[/] Publisher verification badge is identity context and does not affect the risk score")
        if has_lineage:
            lineage_type = "distillation" if "distill" in str(static_analysis.get("base_model", "")).lower() else "base model"
            findings_bullets.append(f"[yellow]⚠[/] Model lineage includes {lineage_type}")

        for fb in findings_bullets:
            bullet(fb)

        analyst_assessment = "No immediate indicators of malicious activity were found."
        if has_pickle or has_exec:
            analyst_assessment = "Repository contains potentially risky artifacts. Further manual review recommended."
        if trust_remote["requires"]:
            analyst_assessment = "Model requires trust_remote_code=True — code review strongly recommended before loading."
        if summary["severity"] in ("high", "critical"):
            analyst_assessment = "Multiple security indicators detected. Do not load this model without thorough review."
        c.print(f"\n  [dim]Analyst Assessment:[/] {analyst_assessment}")

        # ── Risk Categories ──
        section("Risk Categories")
        for cat_key, cat_label in [("execution", "Execution Risk"), ("supply_chain", "Supply Chain Risk"), ("behavioral", "Behavioral Risk"), ("compliance", "Compliance Risk")]:
            rc = risk_categories[cat_key]
            c.print(f"  [{rc['color']}]{cat_label}:[/] {rc['severity']} ({rc['score']})")

        if behavioral_risk["alert_generated"]:
            c.print(f"\n  [red]⚠ Behavioral Risk Warning:[/]")
            c.print(f"  This model appears designed to reduce safety alignment and refusal behavior.")
            c.print(f"  Outputs may contain unsafe instructions or harmful content.")
            c.print(f"  [dim]Evidence:[/]")
            for bf in behavioral_risk["findings"]:
                sev_c = SEVERITY_COLORS.get(bf["severity"], "yellow")
                c.print(f"    [{sev_c}]→[/] {bf['source']}: {bf['reason']}")
            if card_intel["claims"]:
                for claim in card_intel["claims"]:
                    if any(k in claim.lower() for k in ("refusal", "guardrails", "red-team", "jailbreak", "evaluation", "safety")):
                        c.print(f"    [dim]→[/] Model card: {claim}")

        # ── File Inventory ──
        section("File Inventory")
        siblings_by_name = {s.get("rfilename", ""): s for s in siblings}
        all_filenames = sorted(set(f["filename"] for f in file_findings if f.get("category") != "provenance"))
        for fn in all_filenames:
            ext = Path(fn).suffix.lower() if "." in fn else fn
            type_name = FILE_TYPE_NAMES.get(ext, FILE_TYPE_NAMES.get(fn, f"Unknown ({ext})"))
            sibling_info = siblings_by_name.get(fn, {})
            size = sibling_info.get("size") if isinstance(sibling_info, dict) else None
            if size and size > 1024:
                size_str = f"{size / 1024:.1f} KB"
            elif size:
                size_str = f"{size} B"
            else:
                size_str = "Size unknown"
            c.print(f"  [bold]{fn}[/]")
            type_line = f"  [dim]Type:[/] {type_name}"
            size_line = f"  [dim]Size:[/] {size_str}"
            c.print(type_line)
            c.print(size_line)
            # Show findings for this file (deep_scan + code + risky, excluding redundant "Unknown format" for known types)
            findings_for_file = [f for f in file_findings if f["filename"] == fn and f.get("category") not in ("model", "provenance")]
            for ff in findings_for_file:
                desc = ff.get('description', '')[:100]
                if "Unknown format" in desc and ext in FILE_TYPE_NAMES:
                    continue
                sev = ff.get("severity", "")
                sev_c = SEVERITY_COLORS.get(sev, "dim")
                if sev:
                    sub(f"[{sev_c}]{desc}[/]")
                else:
                    sub(desc)

        # ── Code Execution Risk ──
        section("Code Execution Risk")
        if python_scan.get("files_examined"):
            c.print(f"  Files Examined ({len(python_scan['files_examined'])}): {', '.join(python_scan['files_examined'][:10])}")
            critical_apis = [p for p in python_scan["findings"] if p.get("severity") == "critical"]
            high_apis = [p for p in python_scan["findings"] if p.get("severity") == "high"]
            medium_apis = [p for p in python_scan["findings"] if p.get("severity") == "medium"]
            if critical_apis:
                c.print(f"  [red]Critical APIs Found:[/] {len(critical_apis)}")
                for p in critical_apis:
                    c.print(f"    [red]✗[/] {p['file']}:{p.get('line', 0)} — {p['description']}")
            else:
                c.print("  [green]Critical APIs Found:[/] None")
            if high_apis:
                c.print(f"  [yellow]Suspicious APIs:[/] {len(high_apis)}")
                for p in high_apis:
                    c.print(f"    [yellow]→[/] {p['file']}:{p.get('line', 0)} — {p['description']}")
            else:
                c.print("  [green]Suspicious APIs:[/] None")
            remote_apis = [p for p in high_apis + medium_apis if "requests." in p.get("api", "") or "urllib." in p.get("api", "") or "socket." in p.get("api", "")]
            if remote_apis:
                c.print(f"  [yellow]Remote Execution Indicators:[/] {len(remote_apis)} found")
            else:
                c.print("  [green]Remote Execution Indicators:[/] None")
        else:
            c.print("  [green]No Python source files in repository[/]")

        # ── Remote Code Requirement ──
        section("Remote Code Requirement")
        if trust_remote["requires"]:
            c.print(f"  [red]Requires trust_remote_code: YES[/]")
            c.print(f"  [red]Risk:[/] {trust_remote['risk_explanation']}")
            if trust_remote["files_loaded"]:
                c.print("  Files Loaded:")
                for f in trust_remote["files_loaded"]:
                    c.print(f"    • {f}")
        else:
            c.print("  [green]Requires trust_remote_code: NO[/]")
            c.print(f"  [dim]✓[/] {trust_remote['risk_explanation']}")

        # ── Pickle Analysis ──
        section("Pickle Stream Analysis")
        if pickle_analysis:
            pickle_files_analyzed = [p for p in pickle_analysis if p.get("opcode") == "file_found"]
            if pickle_files_analyzed:
                c.print(f"  Files Analyzed: {len(pickle_files_analyzed)}")
                for p in pickle_files_analyzed:
                    c.print(f"    • {p['file']}: {p.get('description', '')}")
                dangerous = [p for p in pickle_analysis if p.get("severity") == "critical"]
                if dangerous:
                    c.print(f"  [red]Dangerous References:[/] {len(dangerous)}")
                    for d in dangerous:
                        c.print(f"    [red]✗[/] {d['file']} — {d.get('description', '')}")
                else:
                    c.print("  [green]Dangerous Opcodes:[/] None")
            else:
                c.print("  [green]No pickle files detected[/]")
        else:
            c.print("  [green]No pickle files detected[/]")

        # ── SafeTensors Analysis ──
        section("SafeTensors Analysis")
        c.print(f"  Shards: {safetensors_info['shard_count']}")
        c.print(f"  Tensor Count: {safetensors_info['tensor_count'] or 'Not computed (deep scan skipped)'}")
        if safetensors_info["metadata_fields"]:
            c.print(f"  Metadata Fields: {', '.join(safetensors_info['metadata_fields'][:10])}")
        if safetensors_info["anomalies"]:
            for a in safetensors_info["anomalies"]:
                c.print(f"  [red]Anomaly:[/] {a}")
        else:
            c.print("  [green]Anomalies:[/] None")
        if safetensors_info["suspicious_metadata"]:
            for sm in safetensors_info["suspicious_metadata"]:
                c.print(f"  [yellow]Suspicious Metadata:[/] {sm}")
        else:
            c.print("  [green]Suspicious Metadata:[/] None")

        # ── GGUF Analysis ──
        section("GGUF Analysis")
        if gguf_info["files"] > 0:
            gi = gguf_info
            c.print(f"  GGUF Files: {gi['files']}")
            if gi["architecture"]:
                c.print(f"  Architecture: {', '.join(sorted(gi['architecture']))}")
            if gi["quantization"]:
                c.print(f"  Quantization: {', '.join(sorted(gi['quantization']))}")
            if gi["context_length"]:
                c.print(f"  Context Length: {gi['context_length']:,}")
            if gi["layers"]:
                c.print(f"  Layers: {gi['layers']}")
            if gi["hidden_size"]:
                c.print(f"  Hidden Size: {gi['hidden_size']:,}")
            if gi["num_heads"]:
                c.print(f"  Attention Heads: {gi['num_heads']}")
            if gi["parameter_count"]:
                c.print(f"  Parameters: {gi['parameter_count']}")
            if gi["tensor_count"]:
                c.print(f"  Tensors: {gi['tensor_count']:,}")
        else:
            c.print("  No GGUF files analyzed")

        # ── Dependency Analysis ──
        section("Dependency Analysis")
        if dependency_analysis["deps"]:
            for dep in dependency_analysis["deps"]:
                c.print(f"  • {dep}")
            if dependency_analysis["typosquat_risk"]:
                c.print(f"  [yellow]Typosquatting Risk:[/]")
                for t in dependency_analysis["typosquat_risk"]:
                    c.print(f"    → {t['dep']} (possible typo of {t['suspected']})")
            else:
                c.print("  [green]Typosquatting Risk:[/] None")
            if dependency_analysis["git_deps"]:
                c.print(f"  [yellow]Git-Based Dependencies:[/]")
                for g in dependency_analysis["git_deps"]:
                    c.print(f"    → {g}")
            else:
                c.print("  [green]Git-Based Dependencies:[/] None")
            if dependency_analysis["known_cves"]:
                c.print(f"  [red]Known CVEs:[/]")
                for cv in dependency_analysis["known_cves"]:
                    c.print(f"    → {cv}")
            else:
                c.print("  [green]Known CVEs:[/] None")
        else:
            c.print("  No dependency files found (requirements.txt, setup.py, pyproject.toml)")

        # ── Model Lineage ──
        section("Model Lineage")
        if lineage:
            for i, l in enumerate(lineage):
                arrow = " → " if i < len(lineage) - 1 else ""
                c.print(f"  [dim]↳[/] {l}")
            c.print(f"  Lineage fully traceable: {'Yes' if len(lineage) >= 2 else 'Partial'}")
        else:
            c.print("  No lineage information available")

        # ── Training Datasets ──
        ds = static_analysis.get("dataset_scan", {})
        if ds.get("datasets_scanned", 0) > 0:
            section("Training Datasets (Scanned)")
            for ds_info in ds.get("datasets", []):
                ds_id = ds_info.get("id", "?")
                ds_dl = ds_info.get("downloads", 0)
                ds_lic = ds_info.get("license", "unknown")
                ds_priv = " [red](private)[/]" if ds_info.get("private") else ""
                ds_risk = ds_info.get("risk_level", "")
                risk_color = SEVERITY_COLORS.get(ds_risk, "dim")
                c.print(f"  [{risk_color}]•[/] {ds_id} — {ds_dl} downloads, license: {ds_lic}{ds_priv}")
            if ds.get("datasets_failed", 0) > 0:
                c.print(f"  [yellow]Warning:[/] {ds['datasets_failed']} dataset(s) could not be scanned")

        # ── Model Card Intelligence ──
        section("Model Card Intelligence")
        if card_intel["architecture"]:
            kv("Architecture", card_intel["architecture"])
        if card_intel["param_count"]:
            kv("Parameters", card_intel["param_count"])
        if card_intel["layers"]:
            kv("Layers", card_intel["layers"])
        if card_intel["purpose"]:
            kv("Declared Purpose", card_intel["purpose"])
        if card_intel["claims"]:
            c.print("  [dim]Detected Claims:[/]")
            for claim in card_intel["claims"]:
                impact = "HIGH" if any(k in claim.lower() for k in ("refusal", "guardrails", "red-team", "jailbreak")) else "MEDIUM"
                imp_color = "red" if impact == "HIGH" else "yellow"
                c.print(f"    • {claim} [dim](Behavioral Impact: [{imp_color}]{impact}[/])[/]")
            c.print(f"  [dim]Evidence Source:[/] Model documentation")
        else:
            c.print("  No structured claims detected in model documentation")

        # ── License Analysis ──
        section("License Analysis")
        kv("Repository License", lic_raw)
        for k, v in license_info.items():
            color = "green" if v in ("Allowed", "Required") else "yellow" if v == "Conditional" else "red" if v == "Restricted" else "dim"
            label_map = {"commercial": "Commercial Use", "redistribution": "Redistribution", "closed_source": "Closed Source Deployment", "notice": "Attribution / Notice"}
            lbl = label_map.get(k, k.capitalize())
            c.print(f"  [{color}]{lbl}:[/] {v}")

        # ── Risk Calculation ──
        section("Risk Calculation")
        risk_breakdown = []

        pickle_files = [f["filename"] for f in file_findings if f.get("category") == "risky"]
        non_st_weight_files = [f["filename"] for f in file_findings if f.get("category") in ("binary", "hdf5", "keras") and not f["filename"].endswith(".safetensors")]

        if pickle_files:
            risk_breakdown.append(("+10", f"Pickle artifacts: {', '.join(pickle_files[:5])}{'...' if len(pickle_files) > 5 else ''}", "red"))
        if trust_remote["requires"]:
            risk_breakdown.append(("+25", "trust_remote_code=True", "red"))
        if static_analysis.get("base_model_risk"):
            rmap = {"critical": 40, "high": 30, "medium": 20, "low": 10}
            pts = rmap.get(static_analysis["base_model_risk"].get("risk", ""), 0)
            risk_breakdown.append((f"+{pts}", f"Base model risk: {static_analysis['base_model_risk'].get('name', '?')}", "yellow" if pts < 30 else "red"))
        for flag in static_analysis.get("risky_dataset_flags", []):
            risk_breakdown.append(("+5", f"Risky dataset: {flag.get('source', '?')}", "yellow"))
        if not uses_safetensors:
            if non_st_weight_files:
                risk_breakdown.append(("+5", f"No safetensors — unsafe weights: {', '.join(non_st_weight_files[:5])}{'...' if len(non_st_weight_files) > 5 else ''}", "yellow"))
            else:
                risk_breakdown.append(("+5", "No safetensors format used", "yellow"))
        ds_alerts = len([a for a in alerts if a.get("type", "").startswith("dataset")])

        tot_manual = 0
        for pts, desc, clr in risk_breakdown:
            pts_val = int(pts.replace("+", ""))
            tot_manual += pts_val
            c.print(f"  [{clr}]{pts}[/] {desc}")
        if ds_alerts:
            c.print(f"  [dim]Dataset review signals: {ds_alerts} content or license note(s); shown separately from model compromise risk[/]")

        c.print(f"\n  [bold]Static Risk Score:[/] {summary['static_risk_score']}/100")
        c.print(f"  [bold]Final Risk Score:[/] [{score_color}]{summary['risk_score']}/10[/]")

        # ── Security Confidence ──
        section("Security Confidence")
        conf = confidence_info
        conf_color = "green" if conf["confidence_pct"] >= 80 else "yellow" if conf["confidence_pct"] >= 50 else "red"
        c.print(f"  [{conf_color}]Overall: {conf['confidence_pct']}% ({conf['confidence_level']})[/]")
        mc = conf["metadata_coverage"]
        c.print(f"  Metadata Coverage: {mc['inspected']}/{mc['total']} files ({mc['pct']}%)")
        dc = conf["deep_scan_rate"]
        if dc["total"] > 0:
            c.print(f"  Deep Scan: {dc['scanned']} scanned, {dc['skipped']} skipped, {dc['failed']} failed (rate: {dc['pct']}%)")
        bc = conf["byte_coverage"]
        total_gb = bc["total"] / 1024 / 1024 / 1024 if bc["total"] else 0
        inspected_gb = bc["inspected"] / 1024 / 1024 / 1024 if bc["inspected"] else 0
        c.print(f"  Byte Coverage: {inspected_gb:.2f} GB / {total_gb:.2f} GB ({bc['pct']}%)")
        mi_score = conf["model_info_completeness"]
        mi_label = "Complete" if mi_score >= 80 else "Partial" if mi_score >= 40 else "Minimal"
        c.print(f"  Model Info: {mi_label} ({mi_score}%)")
        if conf["unscanned"]:
            c.print("  Unscanned Content:")
            for u in conf["unscanned"][:5]:
                c.print(f"    [dim]→[/] {u['file']} ({u['reason']})")
            if len(conf["unscanned"]) > 5:
                c.print(f"    ... and {len(conf['unscanned']) - 5} more")

        # ── Verdict ──
        section("Verdict")
        c.print(f"  [{score_color}]Risk Level:[/] {summary['severity'].upper()}")
        conf_level = confidence_info["confidence_level"]
        conf_color_v = "green" if conf_level == "HIGH" else "yellow" if conf_level == "MEDIUM" else "red"
        c.print(f"  [{conf_color_v}]Confidence:[/] {conf_level} ({confidence_info['confidence_pct']}%)")
        if conf_level == "LOW":
            c.print(f"  [red]⚠ Assessment confidence is limited — consider manual inspection[/]")
        c.print("  [dim]Recommended Actions:[/]")

        recommendations = []
        if summary["severity"] in ("low", "medium"):
            recommendations.append(("[green]✓[/] Safe for local testing"))
            recommendations.append(("[green]✓[/] Safe for offline inference"))
        if publisher_unverified:
            recommendations.append(("[yellow]⚠[/] Verify publisher identity before production deployment"))
        if trust_remote["requires"]:
            recommendations.append(("[red]✗[/] Review custom code before loading"))
            recommendations.append(("[red]✗[/] Do not use in production without security audit"))
        if summary["severity"] in ("high", "critical"):
            recommendations.append(("[red]✗[/] Do not load this model"))
        recommendations.append(("[yellow]⚠[/] Review model card manually"))
        if uses_safetensors:
            recommendations.append(("[yellow]⚠[/] Confirm SafeTensors validation completed before loading"))

        for rec in recommendations[:6]:
            c.print(f"    {rec}")

        if alerts:
            c.print(f"\n  [bold]Active Alerts ({len(alerts)}):[/]")
            for alert in alerts:
                color = SEVERITY_COLORS.get(alert["severity"], "yellow")
                c.print(f"    [{color}]⚠[/] [{color}]{alert['severity'].upper()}[/] {alert['description']}")

    scan_id = store.record_scan(
        model_id=model_id,
        risk_score=summary["risk_score"],
        severity=summary["severity"],
        file_count=summary["files_scanned"],
        risky_file_count=summary["risky_files"],
        summary=json.dumps(summary),
    )

    for alert in alerts:
        store.add_alert(scan_id=scan_id, alert_type=alert["type"], severity=alert["severity"], description=alert["description"])

    if output:
        with open(output, "w") as f:
            f.write(report_json)
        if not json_output:
            console.print(f"\n[green]Report saved to:[/] {output}")

    if json_output:
        print(report_json)

    if sarif_output:
        from model_harrier.report.sarif import generate_sarif_report
        sarif = generate_sarif_report(model_id, file_findings, alerts, summary["risk_score"], summary["severity"])
        with open(sarif_output, "w") as f:
            f.write(sarif)
        if not json_output:
            console.print(f"[green]SARIF report saved to:[/] {sarif_output}")

    if aibom_output:
        from model_harrier.report.aibom import generate_aibom
        aibom = generate_aibom(model_id, model_info, file_findings, alerts, summary["risk_score"], summary["severity"])
        with open(aibom_output, "w") as f:
            f.write(aibom)
        if not json_output:
            console.print(f"[green]AIBOM saved to:[/] {aibom_output}")

    if fail_on:
        severity_order = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        threshold = severity_order.get(fail_on.lower(), 0)
        actual = severity_order.get(summary["severity"], 0)
        if actual >= threshold:
            raise typer.Exit(code=1)


def _scan_local(path: Path, output: Optional[Path], json_output: bool, verbose: bool):
    if not path.exists():
        msg = f"Path does not exist: {path}"
        if json_output:
            print(json.dumps({"error": msg}))
        else:
            console.print(f"[red]Error:[/] {msg}")
        raise typer.Exit(code=2)

    from model_harrier.scan.formats import detect_format, scan_file

    max_file_size = 5 * 1024 * 1024
    candidates = [path] if path.is_file() else sorted(
        item for item in path.rglob("*") if item.is_file() and not item.is_symlink()
    )
    results = []
    severity_order = {"info": 0, "safe": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

    if not json_output:
        console.print(f"\n[bold]Scanning local artifacts:[/] {path}")

    with Progress(console=console, disable=json_output) as progress:
        task = progress.add_task("Inspecting files…", total=len(candidates))
        for file_path in candidates:
            try:
                file_size = file_path.stat().st_size
                relative_name = str(file_path if path.is_file() else file_path.relative_to(path))
                category, description, _risk = categorize_file(relative_name)
                detected_format = "unknown"
                findings: list[dict] = []
                digest = None

                if file_size > max_file_size:
                    findings.append({"issue": "scan_size_limit", "severity": "low", "description": f"Skipped {file_size:,}-byte file; scan limit is {max_file_size:,} bytes"})
                else:
                    data = file_path.read_bytes()
                    digest = hashlib.sha256(data).hexdigest()
                    detected_format = detect_format(relative_name, data)
                    findings.extend(scan_file(relative_name, data))
                    if Path(relative_name).suffix.lower() == ".py":
                        findings.extend(_scan_python_content(relative_name, data.decode("utf-8", errors="replace")))
                    if relative_name.lower().endswith("config.json"):
                        try:
                            config_data = json.loads(data)
                            if config_data.get("trust_remote_code") is True or config_data.get("auto_map"):
                                findings.append({"issue": "custom_model_code", "severity": "high", "description": "Config enables custom model code; inspect before loading"})
                        except (json.JSONDecodeError, AttributeError):
                            findings.append({"issue": "malformed_config", "severity": "medium", "description": "Could not parse model configuration JSON"})

                severity = max((item.get("severity", "info") for item in findings), key=lambda value: severity_order.get(value, 1), default="safe")
                results.append({
                    "file": relative_name,
                    "format": detected_format,
                    "category": category,
                    "description": description,
                    "size": file_size,
                    "sha256": digest,
                    "severity": severity,
                    "findings": findings,
                })
            except OSError as exc:
                results.append({"file": str(file_path), "severity": "low", "error": str(exc)})
            progress.advance(task)

    risk_scores = {"safe": 0.0, "info": 0.0, "low": 1.0, "medium": 4.0, "high": 7.0, "critical": 10.0}
    risk_score = max((risk_scores.get(item.get("severity", "safe"), 1.0) for item in results), default=0.0)
    severity = "critical" if risk_score >= 8 else "high" if risk_score >= 7 else "medium" if risk_score >= 4 else "low" if risk_score > 0 else "safe"
    report = {
        "model": {"id": str(path), "revision": None},
        "scan_summary": {
            "severity": severity,
            "risk_score": risk_score,
            "files_scanned": len(results),
            "risky_files": sum(item.get("severity") in ("high", "critical") for item in results),
            "alerts_count": sum(bool(item.get("findings")) for item in results),
        },
        "results": results,
        "scan_coverage": {
            "files_discovered": len(candidates),
            "bytes_scanned": sum(item.get("size", 0) for item in results if item.get("sha256")),
            "size_limit_bytes": max_file_size,
        },
    }

    if json_output:
        print(json.dumps(report, indent=2))
    else:
        table = Table(title=f"Local scan — {severity.upper()} risk {risk_score:.1f}/10")
        table.add_column("File", style="bold")
        table.add_column("Format")
        table.add_column("Severity")
        table.add_column("Finding")
        for item in results:
            color = SEVERITY_COLORS.get(item.get("severity", "safe"), "white")
            first = (item.get("findings") or [{}])[0]
            detail = first.get("description", item.get("error", "No issue found"))
            table.add_row(item.get("file", "?"), item.get("format", "unknown"), f"[{color}]{item.get('severity', 'safe').upper()}[/]", detail)
        console.print(table)

    store.record_scan(str(path), risk_score, severity, len(results), report["scan_summary"]["risky_files"], json.dumps(report))
    if output:
        output.write_text(json.dumps(report, indent=2), encoding="utf-8")
        if not json_output:
            console.print(f"\n[green]Report saved to:[/] {output}")

def _list_models():
    search_term = typer.prompt("Search for models", default="llama")
    try:
        results = hf.search_models(search_term, limit=15)
        if not results:
            console.print("[yellow]No models found.[/]")
            return
        table = Table(title=f"Models matching '{search_term}'")
        table.add_column("Model ID")
        table.add_column("Downloads")
        table.add_column("Pipeline")
        for r in results:
            table.add_row(r["id"], f"{r.get('downloads', 0):,}", r.get("pipeline_tag", ""))
        console.print(table)
    except Exception as e:
        console.print(f"[red]Error:[/] {e}")


@app.command()
def list_history(
    limit: int = typer.Option(10, "--limit", "-l", help="Number of records to show"),
    sort: str = typer.Option("date", "--sort", "-s", help="Sort by: date, score, name"),
):
    """Show scan history."""
    store.init_db()
    scans = store.get_scan_history(limit=limit)
    if not scans:
        console.print("[yellow]No scan history found. Run 'model-harrier scan <model-id>' first.[/]")
        return

    table = Table(title=f"Scan History (last {len(scans)})")
    table.add_column("Date", style="dim")
    table.add_column("Model")
    table.add_column("Score")
    table.add_column("Severity")
    table.add_column("Files")

    for s in scans:
        color = SEVERITY_COLORS.get(s.get("severity", "safe"), "white")
        table.add_row(
            s.get("timestamp", "")[:19],
            s.get("model_id", ""),
            f"{s.get('risk_score', 0):.1f}",
            f"[{color}]{s.get('severity', 'unknown').upper()}[/]",
            str(s.get("file_count", 0)),
        )
    console.print(table)


@app.command()
def show(
    model_id: str = typer.Argument(..., help="Model ID to show"),
):
    """Show last scan result for a model."""
    store.init_db()
    scans = store.get_scan_history(limit=100)
    match = next((s for s in scans if s.get("model_id") == model_id), None)
    if not match:
        console.print(f"[yellow]No scan found for model: {model_id}[/]")
        return

    color = SEVERITY_COLORS.get(match.get("severity", "safe"), "white")
    console.print(f"[bold]Model:[/] {match['model_id']}")
    console.print(f"  [bold]Score:[/] [{color}]{match['risk_score']}/10 ({match['severity'].upper()})[/]")
    console.print(f"  [bold]Date:[/] {match['timestamp']}")
    console.print(f"  [bold]Files:[/] {match['file_count']} total, [red]{match['risky_file_count']} risky[/]")

    summary = match.get("summary")
    if summary and summary != "null":
        try:
            data = json.loads(summary) if isinstance(summary, str) else summary
            for k, v in data.items():
                if k not in ("severity", "risk_score", "files_scanned", "risky_files"):
                    console.print(f"  [dim]{k}:[/] {v}")
        except (json.JSONDecodeError, TypeError):
            pass


@app.command()
def verify(
    path: Path = typer.Option(..., "--path", "-p", help="Path to pickle file for quick analysis"),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output JSON"),
):
    """Quick pickle file safety check."""
    if not path.exists():
        if json_output:
            print(json.dumps({"error": f"File not found: {path}"}))
        else:
            console.print(f"[red]Error:[/] File not found: {path}")
        raise typer.Exit(code=2)

    with open(path, "rb") as f:
        data = f.read()

    result = verify_pickle_bytes(data)

    if json_output:
        import dataclasses
        print(json.dumps(dataclasses.asdict(result), indent=2, default=str))
        return

    verdict = result.consensus.value if result.consensus else result.aieye_result.value
    color = SEVERITY_COLORS.get(verdict, "white")

    console.print(f"\n[bold]File:[/] {path}")
    console.print(f"  [bold]Size:[/] {result.file_size:,} bytes")
    console.print(f"  [bold]Hash:[/] {result.file_hash[:16]}...")
    console.print(f"  [bold]Verdict:[/] [{color}]{verdict.upper()}[/]")
    console.print(f"  [bold]Confidence:[/] {result.confidence:.0%}")

    if result.reasoning:
        console.print(f"\n  [bold]Reasoning:[/]")
        for r in result.reasoning:
            console.print(f"    • {r}")

    if result.is_false_positive or result.is_false_negative:
        fp_fn = "FALSE POSITIVE" if result.is_false_positive else "FALSE NEGATIVE"
        console.print(f"\n  [yellow]⚠ {fp_fn} detected[/]")


@app.command()
def probes(
    category: Optional[str] = typer.Argument(None, help="Probe category (jailbreaks, prompt_injection, etc.)"),
    list_categories: bool = typer.Option(False, "--list", "-l", help="List available probe categories"),
):
    """List available red team probes."""
    if list_categories:
        table = Table(title="Probe Categories")
        table.add_column("Category Key")
        table.add_column("Name")
        table.add_column("Probes")
        for key in probe_lib.get_probe_categories():
            info = probe_lib.get_category_info(key)
            if info:
                table.add_row(key, info["name"], str(info["probe_count"]))
        console.print(table)
        return

    if category:
        probes = probe_lib.get_probes_by_category(category)
        cat_info = probe_lib.get_category_info(category)
        if not cat_info:
            console.print(f"[red]Unknown category:[/] {category}. Use --list to see available categories.")
            raise typer.Exit(code=2)

        console.print(f"[bold]{cat_info['name']}[/] — {cat_info['description']}")
        for i, p in enumerate(probes, 1):
            console.print(f"\n  [bold]{i}. {p['name']}[/]")
            console.print(f"     Prompt: [dim]{p['prompt'][:100]}...[/]")
            console.print(f"     Expected Safe: [green]{p['expected_safe']}[/]")
    else:
        for key in probe_lib.get_probe_categories():
            info = probe_lib.get_category_info(key)
            if info:
                console.print(f"\n[bold]{info['name']}[/] ({info['probe_count']} probes)")
                console.print(f"  {info['description']}")
                for p in probe_lib.get_probes_by_category(key)[:2]:
                    console.print(f"  • [dim]{p['name']}[/]")


@app.command()
def probe(
    model_id: str = typer.Argument(..., help="Model ID to probe"),
    category: Optional[str] = typer.Option(None, "--category", "-c", help="Probe category (jailbreaks, prompt_injection, etc.)"),
    use_garak: bool = typer.Option(False, "--garak", help="Use garak for probing"),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output JSON"),
    timeout: int = typer.Option(300, "--timeout", help="Timeout in seconds for garak probes"),
):
    """Run red team probes against a model."""
    from model_harrier.scan.garak import scan_with_garak, garak_available
    store.init_db()

    if use_garak:
        if not garak_available():
            console.print("[red]Error:[/] garak is not installed. Install with: pip install garak")
            raise typer.Exit(code=2)

        if not json_output:
            console.print(f"[bold]Running garak probes on:[/] {model_id}")
        result = scan_with_garak(model_id, timeout=timeout)

        if json_output:
            print(json.dumps(result, indent=2, default=str))
            return

        if result.get("error"):
            console.print(f"[red]Error:[/] {result['error']}")
            raise typer.Exit(code=2)

        console.print(f"\n[bold]Garak Results — {model_id}[/]")
        console.print(f"  Probes run: {result['probes_run']}")
        console.print(f"  Passed: [green]{result['probes_passed']}[/]")
        console.print(f"  Failed: [red]{result['probes_failed']}[/]")

        console.print(f"\n[bold]Findings by severity:[/]")
        for sev in ("critical", "high", "medium", "low"):
            count = result.get("summary", {}).get("by_severity", {}).get(sev, 0)
            if count:
                color = SEVERITY_COLORS.get(sev, "white")
                console.print(f"  [{color}]{sev.upper()}: {count}[/]")

        if result["findings"]:
            console.print(f"\n[bold]Failed probes:[/]")
            for f in result["findings"]:
                if f["verdict"] == "FAIL":
                    console.print(f"  [red]✗[/] {f['probe']}")
                    if f.get("output", ""):
                        console.print(f"    [dim]{f['output'][:200]}[/]")
        return

    if category:
        probes = probe_lib.get_probes_by_category(category)
        cat_info = probe_lib.get_category_info(category)
        if not cat_info:
            console.print(f"[red]Unknown category:[/] {category}. Use --list to see available.")
            raise typer.Exit(code=2)
        console.print(f"[bold]{cat_info['name']}[/] — {cat_info['description']}")
        for i, p in enumerate(probes, 1):
            console.print(f"\n  [bold]{i}. {p['name']}[/]")
            console.print(f"     Prompt: [dim]{p['prompt'][:200]}...[/]")
            console.print(f"     Expected Safe: [green]{p['expected_safe']}[/]")
    else:
        if not json_output:
            console.print("[yellow]Use --category to filter or --garak to run garak probes.[/]")
            console.print("Use 'probes' command to list available probe categories.")


@app.command()
def watch(
    model_id: str = typer.Argument(None, help="Model ID to watch"),
    list_watched: bool = typer.Option(False, "--list", "-l", help="List watched models"),
    remove: Optional[str] = typer.Option(None, "--remove", help="Remove model from watch list"),
    interval: int = typer.Option(24, "--interval", "-i", help="Check interval in hours"),
):
    """Monitor a model for new CVEs and changes."""
    store.init_db()

    if list_watched:
        targets = store.get_watch_targets()
        if not targets:
            console.print("[yellow]No models being watched.[/]")
            return
        table = Table(title="Watched Models")
        table.add_column("Model ID")
        table.add_column("Interval (h)")
        table.add_column("Last Checked")
        for t in targets:
            table.add_row(t["model_id"], str(t["check_interval_hours"]), t.get("last_checked", "never")[:19])
        console.print(table)
        return

    if remove:
        store.remove_watch_target(remove)
        console.print(f"[green]Removed {remove} from watch list.[/]")
        return

    if not model_id:
        console.print("[red]Error:[/] Provide a <model-id> or use --list")
        raise typer.Exit(code=2)

    store.add_watch_target(model_id, interval)
    console.print(f"[green]Now watching {model_id} (check every {interval}h).[/]")


@app.command()
def version():
    """Show version information."""
    console.print(f"model-harrier v{__version__}")
    console.print(f"Config dir: {MODEL_HARRIER_DIR}")
    console.print("Python: ", sys.version)


@app.command(name="cve-update")
def cve_update():
    """Update local CVE cache for common ML dependencies."""
    from model_harrier.scan.cve import update_cve_cache
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
        progress.add_task(description="Updating CVE cache...", total=None)
        stats = update_cve_cache()
    console.print(f"[green]CVE cache updated:[/] {stats['checked']} packages checked, {stats['found']} CVEs found")


@app.command()
def db(
    action: str = typer.Argument("info", help="Action: info, reset"),
):
    """Database management."""
    store.init_db()

    if action == "info":
        scans = store.get_scan_history(limit=1)
        stats = {"total_scans": len(store.get_scan_history(limit=10000)), "latest_scan": scans[0]["timestamp"][:19] if scans else "none"}
        console.print(f"[bold]Database:[/] {store.DB_PATH}")
        console.print(f"  Total scans: {stats['total_scans']}")
        console.print(f"  Latest scan: {stats['latest_scan']}")
    elif action == "reset":
        if typer.confirm("This will delete all scan history. Are you sure?"):
            store.DB_PATH.unlink(missing_ok=True)
            store.init_db()
            console.print("[green]Database reset.[/]")


if __name__ == "__main__":
    app()
