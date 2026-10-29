# ModelHarrier

**A terminal workspace for inspecting machine learning models and their supply chains.**

ModelHarrier scans Hugging Face repositories and local model directories for suspicious artifacts, risky configuration, and supply-chain signals. Its static scanner inspects files without loading model weights or executing code from the model repository. Use the TUI for interactive review or the CLI for scripts and CI.

> **Project status: alpha.** Detection is heuristic and coverage varies by file format and size. Review findings and scan coverage before making a deployment decision.

## Highlights

- **Terminal workspace:** launch scans, review history, browse probes, and manage a watchlist from a keyboard-driven interface.
- **Artifact inspection:** checks pickle-capable files, SafeTensors, GGUF, ONNX, Keras/HDF5, tokenizer files, and archives.
- **Repository review:** inspects model metadata, configuration, bundled Python, dependency declarations, and selected model-card information.
- **Evidence and coverage:** reports the revision scanned, findings, confidence, and files that were skipped or could not be inspected.
- **Automation outputs:** create JSON, SARIF, and CycloneDX AI Bill of Materials reports.
- **Static pickle analysis:** examines pickle opcodes without deserializing the file.

## Install

Requirements: Python 3.12 or newer.

```bash
git clone https://github.com/MacTash/ai-eye.git
cd ai-eye
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

Optional integrations can be installed individually or together:

```bash
python -m pip install -e '.[garak]'
python -m pip install -e '.[all]'
```

For gated Hugging Face repositories, set a token in your environment:

```bash
export HF_TOKEN=your_hugging_face_token
```

## Launch the TUI

```bash
model-harrier
```

The workspace includes an overview, scan form, scan history, probe library, and watchlist. Use `1`–`5` to switch views, `Ctrl+R` to refresh, and `q` to quit. The scan view accepts a Hugging Face model ID or a local directory.

## CLI

Use the CLI for repeatable scans and automation:

```bash
# Scan a Hugging Face repository or local directory
model-harrier scan openai-community/gpt2
model-harrier scan --path ./models/my-model

# Save reports for review or CI
model-harrier scan openai-community/gpt2 --output report.json
model-harrier scan openai-community/gpt2 --sarif report.sarif
model-harrier scan openai-community/gpt2 --aibom model.cdx.json
model-harrier scan openai-community/gpt2 --fail-on high

# Use cached metadata and files only
model-harrier scan openai-community/gpt2 --offline

# Inspect a pickle file, review history, or browse probes
model-harrier verify --path ./checkpoint.pkl
model-harrier list-history --limit 20
model-harrier probes --list

# Add a model to the watchlist or run optional Garak probes
model-harrier watch openai-community/gpt2 --interval 24
model-harrier probe openai-community/gpt2 --garak
```

Run `model-harrier --help` or `model-harrier <command> --help` for all options. The `harrier` and `ai-eye` executable names remain available as aliases.

## How scanning works

For Hugging Face scans, ModelHarrier retrieves repository metadata and the file list, pins the scan to a repository revision, and inspects supported files within configured limits. Local scans inspect files in the selected directory. The scanner does not import or execute code from scanned model repositories, and it does not deserialize pickle files.

Deep file inspection has a **5 MB per-file limit**. Larger files are listed in the report as skipped; they are not treated as clean. The report’s coverage and confidence sections describe what the scanner could and could not inspect.

Static analysis can identify known indicators and structural anomalies, but it cannot prove that weights are benign, detect every backdoor, or predict model behavior. Heuristic findings can be false positives. Optional Garak probing is a separate behavioral check and is not part of the default static scan.

See [Detection scope and limitations](docs/detection.md) for details and references.

## Data and local files

Scan history is stored in `~/.model-harrier/`. If that directory does not yet contain a database, ModelHarrier can reuse the legacy `~/.ai-eye/ai-eye.db` history. Set `MODEL_HARRIER_HOME` and `MODEL_HARRIER_CACHE_DIR` to use different locations.

Hugging Face scans require network access unless `--offline` is used. Selected repository files may be downloaded to the configured cache for static inspection; scanned model code is not run by the static scanner.

## Development

```bash
make install-dev
make test
make lint
make typecheck
```

Tests use pytest. Ruff and mypy are available through the development dependencies; lint findings are still being worked through as the project transitions from its previous implementation.

## Project name

The project was previously called AI Eye. **ModelHarrier** is the current product and package name; `ai-eye` remains as a compatibility command and in the existing GitHub repository URL.
