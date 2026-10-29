# ModelHarrier

ModelHarrier is a terminal workspace and static supply-chain scanner for machine-learning models. It inspects Hugging Face repositories and local artifacts without loading model weights or executing model code. The project was previously called AI Eye; `ai-eye` remains as a temporary command alias.

## Install

Python 3.12 or newer:

```bash
git clone https://github.com/MacTash/ai-eye.git
cd ai-eye
python -m pip install -e .
```

Optional integrations:

```bash
python -m pip install -e '.[fickling,tensortrap,sklearn,garak,pdf]'
```

## Launch the TUI

```bash
model-harrier
```

The TUI has overview, scan, history, probe library, and watchlist views. Use `1`–`5` to switch views, `Ctrl+R` to refresh, and `q` to quit. Scans accept a Hugging Face model ID or local directory. Set `HF_TOKEN` to access gated repositories.

## CLI

The commands are also available for scripts and CI:

```bash
model-harrier scan openai-community/gpt2
model-harrier scan --path ./models/
model-harrier scan google-bert/bert-base-uncased --json --output report.json
model-harrier scan openai-community/gpt2 --sarif report.sarif --aibom model.cdx.json
model-harrier scan openai-community/gpt2 --fail-on high
model-harrier verify --path checkpoint.pkl
model-harrier list-history --limit 20
model-harrier probes --list
model-harrier probe openai-community/gpt2 --garak
model-harrier watch openai-community/gpt2 --interval 24
```

`harrier` and the legacy `ai-eye` commands currently invoke the same CLI. Use `model-harrier --help` for the full command list.

## What it checks

- Pickle opcodes and suspicious global references without unpickling
- SafeTensors, GGUF, ONNX, Keras/HDF5, tokenizer, and archive structure
- Repository files, model configuration, bundled Python, dependencies, and metadata
- Publisher and revision signals, known vulnerable models, and cached blocklist entries
- Optional Fickling, PickleScan, TensorTrap, and Garak analysis

Findings include evidence and severity. An uneventful static scan means no enabled check found a known indicator; it does not prove that weights are benign or rule out behavioral backdoors. See [detection notes](docs/detection.md) for scope and sources.

## Development

```bash
make install-dev
make test
make lint
```

Scan history is stored in `~/.model-harrier/`. Existing history in `~/.ai-eye/ai-eye.db` is reused when the new database has not yet been created.
