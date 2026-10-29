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
- Expanded severity regressions into a hand-labeled corpus covering benign text, reputation-only dataset metadata, contextual dataset content/tags, license notices, a configured high-risk source pattern, and tokenizer structure. Removed dataset download-count and verified-organization alerts as reputation-only signals. Corpus label confidence records confidence in the expected category; scanner confidence calibration still needs externally validated samples.
- Added an optional `format-parsers` dependency group for ONNX and HDF5, with real-parser integration tests for benign and suspicious artifacts. ONNX external weight references are now checked on graph initializers, including traversal paths.

## Follow-up work

- Expand the initial synthetic calibration corpus with externally reviewed benign and malicious model artifacts; add scanner confidence calibration against validated labels.
- Expand ONNX/HDF5 integration coverage with more real-world fixtures and run the optional parser extra in CI.
- Integrate an authoritative commit-signature verification source when available; the current Hub model metadata API does not expose GPG verification status, so signed revision verification remains incomplete.
- Expand Hugging Face integration tests into an opt-in CI job with authentication-aware rate limits.
- Consider splitting the legacy CLI scan/report code into smaller service and presentation modules.
