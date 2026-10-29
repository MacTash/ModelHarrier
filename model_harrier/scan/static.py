"""Static analysis of model metadata, README, config, and training data."""

import json
import re
from pathlib import Path
from typing import Optional

from model_harrier.data.vulnerable_models import (
    check_vulnerable_model,
    find_unsafe_keywords,
    find_safety_indicators,
    UNSAFE_DATASET_PATTERNS,
)


def extract_base_model(card_data: Optional[dict], tags: list[str]) -> Optional[str]:
    if isinstance(card_data, str):
        try:
            card_data = json.loads(card_data)
        except (json.JSONDecodeError, ValueError):
            card_data = None
    if card_data:
        bm = card_data.get("base_model")
        if isinstance(bm, str):
            return bm
        if isinstance(bm, list):
            return bm[0] if bm else None
    base_model_tag = next((t for t in tags if t.startswith("base_model:")), None)
    if base_model_tag:
        return base_model_tag.replace("base_model:", "")
    model_type_tags = ["llama", "mistral", "gpt2", "bert", "falcon", "mpt", "qwen", "phi"]
    for tag in tags:
        lower_tag = tag.lower()
        for mtype in model_type_tags:
            if mtype in lower_tag:
                return tag
    return None


def extract_training_data(card_data: Optional[dict], readme_content: Optional[str] = None) -> list[str]:
    sources: set[str] = set()
    if isinstance(card_data, str):
        try:
            card_data = json.loads(card_data)
        except (json.JSONDecodeError, ValueError):
            card_data = None
    if card_data and card_data.get("datasets") and isinstance(card_data["datasets"], list):
        for d in card_data["datasets"]:
            sources.add(str(d))
    if readme_content:
        patterns = [
            re.compile(r"(?:trained|fine-?tuned|using)\s+(?:on\s+)?(?:the\s+)?([A-Za-z0-9_-]+(?:\s+dataset)?)", re.IGNORECASE),
            re.compile(r"datasets?:\s*\[?([^\]\n]+)", re.IGNORECASE),
            re.compile(r"huggingface\.co/datasets/([A-Za-z0-9_/-]+)", re.IGNORECASE),
        ]
        for pattern in patterns:
            for match in pattern.finditer(readme_content):
                if match.lastindex and match.group(1):
                    sources.add(match.group(1).strip())
    return list(sources)


def analyze_config(config: Optional[dict]) -> tuple[list[str], Optional[str]]:
    flags: list[str] = []
    architecture: Optional[str] = None
    if not config:
        return ["No config.json found"], None

    architecture = config.get("model_type") or (config.get("architectures", [None])[0] if config.get("architectures") else None)

    if config.get("vocab_size", 0) > 100000:
        flags.append(f"Large vocabulary size ({config['vocab_size']}) - may have custom tokens")
    if config.get("num_hidden_layers", 0) > 80:
        flags.append(f"Very deep model ({config['num_hidden_layers']} layers) - expensive to audit")
    if config.get("auto_map"):
        flags.append("Custom model code (auto_map) - requires code review")
    if config.get("trust_remote_code") is True:
        flags.append("CRITICAL: Requires trust_remote_code=True - arbitrary code execution risk")

    return flags, architecture


def analyze_readme(readme_content: str) -> dict:
    unsafe_patterns = find_unsafe_keywords(readme_content)
    safety_mentions = find_safety_indicators(readme_content)
    concerning_phrases: list[str] = []

    concern_patterns = [
        re.compile(r"no\s+safety\s+filter", re.IGNORECASE),
        re.compile(r"removed?\s+(?:safety|refusal)", re.IGNORECASE),
        re.compile(r"bypass(?:es|ing)?\s+(?:safety|content)", re.IGNORECASE),
        re.compile(r"not\s+(?:safe|aligned)", re.IGNORECASE),
        re.compile(r"use\s+at\s+your\s+own\s+risk", re.IGNORECASE),
        re.compile(r"for\s+research\s+(?:only|purposes)", re.IGNORECASE),
        re.compile(r"not\s+for\s+production", re.IGNORECASE),
        re.compile(r"adult\s+content", re.IGNORECASE),
        re.compile(r"nsfw", re.IGNORECASE),
        re.compile(r"explicit", re.IGNORECASE),
    ]
    for pattern in concern_patterns:
        match = pattern.search(readme_content)
        if match:
            concerning_phrases.append(match.group(0))

    return {"unsafe_patterns": unsafe_patterns, "safety_mentions": safety_mentions, "concerning_phrases": concerning_phrases}


def analyze_datasets(datasets: list[str]) -> list[dict]:
    flags: list[dict] = []
    for dataset in datasets:
        for entry in UNSAFE_DATASET_PATTERNS:
            if entry["pattern"].search(dataset):
                flags.append({"source": dataset, "risk": entry["risk"], "reason": entry["reason"]})
                break
    return flags


def calculate_static_risk_score(analysis: dict) -> tuple[int, str]:
    score = 0
    base_model_risk = analysis.get("base_model_risk")
    if base_model_risk:
        risk_map = {"critical": 40, "high": 30, "medium": 20, "low": 10}
        score += risk_map.get(base_model_risk.get("risk", ""), 0)

    score += min(30, len(analysis.get("unsafe_keywords", [])) * 10)

    for flag in analysis.get("risky_dataset_flags", []):
        risk_map = {"critical": 15, "high": 10, "medium": 5}
        score += risk_map.get(flag.get("risk", ""), 0)

    config_flags = analysis.get("config_flags", [])
    critical_config = [f for f in config_flags if "CRITICAL" in f or "trust_remote_code" in f]
    score += len(critical_config) * 25
    score += (len(config_flags) - len(critical_config)) * 5

    score -= min(20, len(analysis.get("safety_indicators", [])) * 5)
    score = max(0, min(100, score))

    if score >= 70:
        level = "critical"
    elif score >= 50:
        level = "high"
    elif score >= 25:
        level = "medium"
    else:
        level = "low"

    return score, level


def perform_static_analysis(
    model_id: str,
    card_data: Optional[dict] = None,
    tags: Optional[list[str]] = None,
    config: Optional[dict] = None,
    readme_content: Optional[str] = None,
    spaces_url: Optional[str] = None,
) -> dict:
    tags = tags or []
    findings: list[str] = []

    base_model = extract_base_model(card_data, tags)
    base_model_risk = check_vulnerable_model(base_model) if base_model else check_vulnerable_model(model_id)

    if base_model_risk:
        findings.append(f"Base model risk: {base_model_risk['name']} - {base_model_risk['reason']}")

    training_data_sources = extract_training_data(card_data, readme_content)
    risky_dataset_flags = analyze_datasets(training_data_sources)
    for flag in risky_dataset_flags:
        findings.append(f"Risky dataset: {flag['source']} - {flag['reason']}")

    config_flags, architecture_type = analyze_config(config)
    for flag in config_flags:
        findings.append(flag)

    readme_analysis = analyze_readme(readme_content) if readme_content else {"unsafe_patterns": [], "safety_mentions": [], "concerning_phrases": []}
    all_unsafe = list(set(find_unsafe_keywords(model_id) + readme_analysis["unsafe_patterns"] + readme_analysis["concerning_phrases"]))

    if all_unsafe:
        findings.append(f"Unsafe patterns detected: {', '.join(all_unsafe)}")

    partial = {
        "base_model_risk": base_model_risk,
        "unsafe_keywords": all_unsafe,
        "safety_indicators": readme_analysis["safety_mentions"],
        "risky_dataset_flags": risky_dataset_flags,
        "config_flags": config_flags,
    }
    static_risk_score, static_risk_level = calculate_static_risk_score(partial)

    return {
        "base_model": base_model,
        "base_model_risk": base_model_risk,
        "unsafe_keywords": all_unsafe,
        "safety_indicators": readme_analysis["safety_mentions"],
        "training_data_sources": training_data_sources,
        "risky_dataset_flags": risky_dataset_flags,
        "config_flags": config_flags,
        "architecture_type": architecture_type,
        "spaces_url": spaces_url,
        "has_spaces": bool(spaces_url),
        "static_risk_score": static_risk_score,
        "static_risk_level": static_risk_level,
        "findings": findings,
    }
