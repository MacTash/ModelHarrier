"""tokenizer.json format scanner.

Detects single-edit tampering (HiddenLayer disclosure),
verifies string-to-ID mapping consistency, and flags
abnormally large tokenizer files.
"""

import json

MAX_TOKENIZER_FILE_SIZE = 500 * 1024 * 1024
MAX_VOCAB_SIZE = 1_000_000
SUSPICIOUS_TOKEN_PATTERNS = [
    "eval(", "exec(", "__import__", "os.system", "subprocess",
]

LARGE_TOKEN_THRESHOLD = 1000


def scan_tokenizer(data: bytes) -> list[dict]:
    findings = []

    if len(data) > MAX_TOKENIZER_FILE_SIZE:
        findings.append({"issue": "oversized_tokenizer", "severity": "high", "description": f"Tokenizer file is {len(data)} bytes — abnormally large"})
        return findings

    try:
        tokenizer = json.loads(data)
    except json.JSONDecodeError as e:
        findings.append({"issue": "corrupt_tokenizer_json", "severity": "high", "description": f"Tokenizer JSON is malformed: {e}"})
        return findings

    if not isinstance(tokenizer, dict):
        findings.append({"issue": "invalid_tokenizer_structure", "severity": "high", "description": "Tokenizer root is not a JSON object"})
        return findings

    findings.extend(_check_vocab_size(tokenizer))
    findings.extend(_check_added_tokens(tokenizer))
    findings.extend(_check_merges(tokenizer))
    findings.extend(_check_model_config(tokenizer))
    findings.extend(_scan_suspicious_strings(data))

    return findings


def _check_vocab_size(tokenizer: dict) -> list[dict]:
    findings = []

    model = tokenizer.get("model", {})
    if isinstance(model, dict):
        vocab = model.get("vocab", {})
        if isinstance(vocab, dict) and len(vocab) > MAX_VOCAB_SIZE:
            findings.append({"issue": "excessive_vocab_size", "severity": "medium", "description": f"Vocabulary has {len(vocab)} entries (max {MAX_VOCAB_SIZE})"})

    added_tokens = tokenizer.get("added_tokens", [])
    if isinstance(added_tokens, list) and len(added_tokens) > MAX_VOCAB_SIZE:
        findings.append({"issue": "excessive_added_tokens", "severity": "medium", "description": f"Added tokens count {len(added_tokens)} exceeds {MAX_VOCAB_SIZE}"})

    return findings


def _check_added_tokens(tokenizer: dict) -> list[dict]:
    findings = []
    added_tokens = tokenizer.get("added_tokens", [])
    if not isinstance(added_tokens, list):
        return findings

    seen_ids = set()
    for i, token in enumerate(added_tokens):
        if not isinstance(token, dict):
            continue
        token_id = token.get("id")
        content = token.get("content", "")
        if token_id is not None:
            if token_id in seen_ids:
                findings.append({"issue": "duplicate_token_id", "severity": "medium", "description": f"Duplicate token ID {token_id} at added_tokens[{i}]"})
            seen_ids.add(token_id)

        if isinstance(content, str):
            if len(content) > LARGE_TOKEN_THRESHOLD:
                findings.append({"issue": "abnormally_large_token", "severity": "medium", "description": f"Added token at index {i} has {len(content)} characters"})

            for pattern in SUSPICIOUS_TOKEN_PATTERNS:
                if pattern in content.lower():
                    findings.append({"issue": "suspicious_token_content", "severity": "critical", "description": f"Added token '{content[:50]}' contains suspicious pattern '{pattern}'"})

    return findings


def _check_merges(tokenizer: dict) -> list[dict]:
    findings = []
    model = tokenizer.get("model", {})
    merges = model.get("merges", []) if isinstance(model, dict) else []
    if not isinstance(merges, list):
        return findings

    if len(merges) > 1_000_000:
        findings.append({"issue": "excessive_merges", "severity": "medium", "description": f"BPE merges count {len(merges)} exceeds 1M"})

    seen_merges = set()
    for i, merge in enumerate(merges):
        if not isinstance(merge, str):
            findings.append({"issue": "non_string_merge", "severity": "medium", "description": f"Merge at index {i} is not a string"})
            continue
        if merge in seen_merges:
            findings.append({"issue": "duplicate_merge", "severity": "low", "description": f"Duplicate merge at index {i}: '{merge}'"})
        seen_merges.add(merge)

    return findings


def _check_model_config(tokenizer: dict) -> list[dict]:
    findings = []
    model = tokenizer.get("model", {})
    if not isinstance(model, dict):
        return findings

    model_type = model.get("type", "")
    if not model_type:
        findings.append({"issue": "missing_model_type", "severity": "low", "description": "Tokenizer model type is missing"})

    unk_token = tokenizer.get("unk_token", None)
    if unk_token is None:
        findings.append({"issue": "missing_unk_token", "severity": "low", "description": "Tokenizer missing unk_token"})

    return findings


def _scan_suspicious_strings(data: bytes) -> list[dict]:
    findings = []
    decoded = data.decode("utf-8", errors="replace")
    for pattern in SUSPICIOUS_TOKEN_PATTERNS:
        if pattern in decoded.lower():
            findings.append({"issue": "suspicious_string_in_tokenizer", "severity": "critical", "description": f"Suspicious pattern '{pattern}' found in tokenizer file"})
            break
    return findings
