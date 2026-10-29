# Detection approach

ModelHarrier treats a model repository as an untrusted software supply-chain input. The default scan is static: it reads metadata and bounded file contents and never imports bundled model code or deserializes a checkpoint.

## Design rules

1. **Identify content by structure and signatures as well as filename.** Renaming a pickle or archive must not bypass format checks.
2. **Never execute to decide if execution is dangerous.** Parse pickle opcodes, source ASTs, archive metadata, and format headers without calling model loaders.
3. **Bound work and report coverage.** File size, bytes read, archive expansion, recursion, and elapsed time need limits. A skipped, truncated, malformed, or unsupported artifact is reported as incomplete analysis, never silently counted as clean.
4. **Pin the scanned revision.** Record the Hugging Face commit SHA and use it for metadata and downloads so the scan report identifies the exact repository snapshot.
5. **Keep evidence separate from trust signals.** Download counts, publisher identity, license, and verification badges provide context; popularity and badges do not affect risk scores or prove that bytes are safe.

The report records the immutable Hugging Face revision SHA and any repository scan status returned by Hub metadata. A SHA identifies the snapshot but does not authenticate its publisher. Hub scan completion and an empty reported issue list are not a safety verdict. The current Hub model metadata response does not expose commit signature verification, so ModelHarrier reports that status as unavailable rather than inferring it from repository identity or popularity.

## Detection layers

### Serialization and model formats

Pickle-family artifacts are inspected as opcode streams and cross-checked with optional PickleScan and Fickling engines. `GLOBAL`, `STACK_GLOBAL`, `REDUCE`, and related opcodes are evidence to investigate, not standalone proof of exploitation: interpretation should include the referenced module/callable, opcode context, and whether the serializer is an expected format. The artifact is never unpickled during scanning. PyTorch recommends `weights_only=True` for loading untrusted checkpoints and warns against loading untrusted data; this scanner does not replace that runtime restriction.

SafeTensors checks validate the bounded JSON header, tensor entry schema, dtype, shape, relative offsets, overlaps, and whether the declared data range fits the file. SafeTensors avoids pickle-style arbitrary code execution, but its format checks still matter for malformed files and resource exhaustion. GGUF, ONNX, Keras/HDF5, and tokenizer files receive format-specific structural checks. Unsupported formats and optional scanners that are unavailable are shown in coverage details.

Install the `format-parsers` optional dependency group to enable ONNX protobuf and HDF5 attribute parsing. Without it, those scanners fall back to bounded raw-byte checks and report the missing parser.

### Archives

ZIP and TAR members are checked for normalized path traversal, absolute paths, symlinks or hard links, suspicious nested artifacts, oversized entries, excessive compression ratios, and nested archives within bounded depth and expansion budgets. The scanner reads only bounded member contents and does not extract archives to the filesystem.

### Repository source and metadata

Repository scanning examines all paths returned by the Hub, including nested paths; model configuration fields such as `auto_map` and `trust_remote_code`; Python source using AST-aware checks; dependency declarations; tokenizer and template files; and model-card claims. Hugging Face documents that pickle deserialization may execute code and that its own pickle scanner highlights imports, while also warning that scanners are best-effort. The report therefore keeps source findings distinct from repository reputation signals.

Tokenizer vocabulary and added-token strings are data, not executable code; words such as `subprocess` inside a vocabulary do not create code-execution findings. Dataset license, topic tags, and content descriptions are reported as compliance or scope context, not as evidence that a model artifact is malicious. Explicit high-risk dataset-source patterns remain separate findings.

`tests/fixtures/severity_calibration.json` is a small, synthetic regression corpus for benign text, dataset context and license signals, reputation-only metadata, and malformed tokenizer input. Its labels capture expected scanner behavior, not ground-truth maliciousness; the corpus does not yet support statistical confidence calibration.

### Runtime behavior

Static analysis cannot establish that a model is behaviorally safe or rule out backdoors encoded in weights. The optional Garak integration runs probes only when the configured integration can access the target model. Its results describe the tested probes and outputs, not complete behavioral coverage. Never load untrusted custom model code just to test it; use an isolated environment with restricted network and credentials.

## References

- [Hugging Face: Pickle scanning and its limits](https://huggingface.co/docs/hub/security-pickle)
- [Hugging Face: Hub security features](https://huggingface.co/docs/hub/security)
- [Hugging Face: GPG commit signature verification](https://huggingface.co/docs/hub/main/security-gpg)
- [Hugging Face Hub API: model metadata and security status](https://huggingface.co/docs/huggingface_hub/main/package_reference/hf_api)
- [PyTorch: Serialization semantics and `weights_only`](https://docs.pytorch.org/docs/stable/notes/serialization.html)
- [PyTorch: `torch.load` security guidance](https://docs.pytorch.org/docs/stable/generated/torch.load.html)
- [Hugging Face: SafeTensors format](https://huggingface.co/docs/safetensors/main/en/index)
- [GGML: GGUF file format specification](https://github.com/ggml-org/ggml/blob/master/docs/gguf.md)
- [ONNX Python API: loading serialized models](https://onnx.ai/onnx/api/serialization.html)
- [Promptfoo ModelAudit: static scanner and supported formats](https://github.com/promptfoo/modelaudit)
- [ModelAudit security model: scanner coverage and limitations](https://github.com/promptfoo/modelaudit/blob/main/docs/user/security-model.md)
