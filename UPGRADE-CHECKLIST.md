# ModelHarrier rebuild

## Delivered

- Rebranded the Python package and primary command to `model-harrier`; kept `harrier` and `ai-eye` command aliases during the transition.
- Replaced the website-first product with a Textual terminal workspace for scans, history, local verification, probe reference, Garak, and watch targets.
- Added regression tests for SafeTensors headers and offsets, archive traversal and links, renamed pickle detection, tokenizer false positives, AST source analysis, local scans, and TUI navigation.
- Removed restricted unpickling from the security decision path. Pickle analysis is opcode-based and does not deserialize.
- Added file-size and archive expansion limits, content-first format routing, pinned Hugging Face revisions, and scan-coverage reporting.
- Documented the scanner model and its limits in `docs/detection.md`.
- Started severity calibration from the 100-model run: tokenizer vocabulary strings no longer trigger code-execution findings, dataset content and usage labels are contextual low-severity notices, and unknown licenses remain compliance notices.
- Added calibration regression cases for benign tokenizer and dataset text, license metadata, sensitive-content disclosures, and a known high-risk dataset source.
- Started structural format coverage for ONNX, HDF5, GGUF, Keras v3 containers, and content-first archive routing. The tests exposed and fixed dropped ZIP scans, incorrect GGUF metadata key/scalar parsing, missed GGUF chat-template inspection, and unbounded gzip decompression in Keras scanning.
- Added evidence-backed provenance reporting for immutable revision SHAs and Hub repository scan status. Removed download-count, publisher-slug, missing-card, private-repository, and verification-badge heuristics from risk findings and risk scores; retained publisher identity as report context. Commit signature status is explicitly `not_reported` because the Hub model metadata response used by this client does not expose signature verification.

## Follow-up work

- Expand the focused calibration cases into a labeled corpus of benign and malicious model artifacts; calibrate confidence as well as severity.
- Expand format coverage with real ONNX/HDF5 parser integration cases and additional model-container fixtures; current ONNX tests exercise scanner behavior without requiring the optional parser dependency.
- Integrate an authoritative commit-signature verification source when available; the current Hub model metadata API does not expose GPG verification status, so signed revision verification remains incomplete.
- Expand Hugging Face integration tests into an opt-in CI job with authentication-aware rate limits.
- Consider splitting the legacy CLI scan/report code into smaller service and presentation modules.
