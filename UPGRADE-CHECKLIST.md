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
- Added evidence-backed provenance reporting for immutable revision SHAs, Hub repository scan status, and the Hub's exact-revision commit-signature status. The documented commits API omits signature status, so the scanner reads the structured commit record embedded in the official commit-history page; unknown markup or failed requests stay `not_reported`. This relays the Hub's verification result and does not locally re-verify the signature. Signature status does not affect risk scores.
- Expanded severity regressions into a hand-labeled corpus covering benign text, reputation-only dataset metadata, contextual dataset content/tags, license notices, a configured high-risk source pattern, and tokenizer structure. Removed dataset download-count and verified-organization alerts as reputation-only signals. Corpus label confidence records confidence in the expected category; scanner confidence calibration still needs externally validated samples.
- Added an optional `format-parsers` dependency group for ONNX and HDF5, with real-parser integration tests for benign and suspicious artifacts. ONNX external weight references are now checked on graph initializers, including traversal paths.
- Added a push/PR test workflow that installs ONNX and HDF5 parsers. The manual Hugging Face workflow covers metadata, revision-pinned file download, signed-commit, and unsigned-commit cases; its repo input supports public, private, or gated targets, with an optional `HF_TOKEN` secret and bounded HTTP 429 retries.

## Follow-up work

- Expand the initial synthetic calibration corpus with externally reviewed benign and malicious model artifacts; add scanner confidence calibration against validated labels.
- Expand ONNX/HDF5 integration coverage with more real-world fixtures and run the optional parser extra in CI.
- Replace the Hub commit-history page payload with a documented signature API if Hugging Face adds one; keep the current parser fail-closed and maintain its signed/unsigned live checks because the page payload is not a public API contract.
- Add a controlled private or gated repository fixture and credential-protected CI run when dedicated test credentials are available.
- Consider splitting the legacy CLI scan/report code into smaller service and presentation modules.
