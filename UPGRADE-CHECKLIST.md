# ModelHarrier rebuild

## Delivered

- Rebranded the Python package and primary command to `model-harrier`; kept `harrier` and `ai-eye` command aliases during the transition.
- Replaced the website-first product with a Textual terminal workspace for scans, history, local verification, probe reference, Garak, and watch targets.
- Added regression tests for SafeTensors headers and offsets, archive traversal and links, renamed pickle detection, tokenizer false positives, AST source analysis, local scans, and TUI navigation.
- Removed restricted unpickling from the security decision path. Pickle analysis is opcode-based and does not deserialize.
- Added file-size and archive expansion limits, content-first format routing, pinned Hugging Face revisions, and scan-coverage reporting.
- Documented the scanner model and its limits in `docs/detection.md`.

## Follow-up work

- Add rule-level severity and confidence calibration against a labeled corpus of benign and malicious model artifacts.
- Add more format scanners only with malformed and benign regression samples, including structural tests for ONNX, Keras, GGUF, and model containers.
- Add signed revision and provenance verification as evidence-backed checks; keep publisher popularity as context only.
- Expand Hugging Face integration tests into an opt-in CI job with authentication-aware rate limits.
- Consider splitting the legacy CLI scan/report code into smaller service and presentation modules.
