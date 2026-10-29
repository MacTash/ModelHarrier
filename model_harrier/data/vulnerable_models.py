"""Known vulnerable and risky base models database."""

import re
from typing import Optional

VULNERABLE_MODELS: list[dict] = [
    {"pattern": re.compile(r"dolphin", re.IGNORECASE), "name": "Dolphin (Cognitive Computations)", "risk": "high", "reason": "Explicitly trained to remove refusals and safety guardrails"},
    {"pattern": re.compile(r"wizard.?(uncensored|unfiltered)", re.IGNORECASE), "name": "WizardLM Uncensored", "risk": "high", "reason": "Fine-tuned to bypass safety training"},
    {"pattern": re.compile(r"nous.?hermes.?(uncensored)?", re.IGNORECASE), "name": "Nous Hermes", "risk": "medium", "reason": "Known for reduced content restrictions"},
    {"pattern": re.compile(r"openhermes", re.IGNORECASE), "name": "OpenHermes", "risk": "medium", "reason": "Synthetic data training may include unsafe content"},
    {"pattern": re.compile(r"airoboros", re.IGNORECASE), "name": "Airoboros", "risk": "medium", "reason": "Trained with jailbreak style prompts"},
    {"pattern": re.compile(r"goliath", re.IGNORECASE), "name": "Goliath Merged Models", "risk": "medium", "reason": "Model merges may inherit vulnerabilities from multiple sources"},
    {"pattern": re.compile(r"gpt4all", re.IGNORECASE), "name": "GPT4All", "risk": "low", "reason": "Early open model with limited safety training"},
    {"pattern": re.compile(r"llama.?2.?(7b|13b|70b).?chat", re.IGNORECASE), "name": "Llama 2 Chat", "risk": "low", "reason": "Published jailbreak techniques exist (DAN, Developer Mode)"},
    {"pattern": re.compile(r"uncensored", re.IGNORECASE), "name": "Uncensored Model", "risk": "critical", "reason": "Model explicitly marketed as uncensored"},
    {"pattern": re.compile(r"unfiltered", re.IGNORECASE), "name": "Unfiltered Model", "risk": "critical", "reason": "Model explicitly marketed as unfiltered"},
    {"pattern": re.compile(r"no.?refusal", re.IGNORECASE), "name": "No-Refusal Model", "risk": "critical", "reason": "Trained to never refuse requests"},
    {"pattern": re.compile(r"abliterated", re.IGNORECASE), "name": "Abliterated Model", "risk": "critical", "reason": "Safety features surgically removed via activation editing"},
]

RISKY_BASE_MODELS: list[dict] = [
    {"pattern": re.compile(r"mistral.?(7b|instruct)", re.IGNORECASE), "name": "Mistral", "risk": "low", "reason": "Limited safety training compared to competitors"},
    {"pattern": re.compile(r"mixtral", re.IGNORECASE), "name": "Mixtral MoE", "risk": "low", "reason": "MoE architecture may have inconsistent safety across experts"},
    {"pattern": re.compile(r"qwen", re.IGNORECASE), "name": "Qwen (Alibaba)", "risk": "low", "reason": "Different safety alignment methodology"},
    {"pattern": re.compile(r"yi.?(6b|34b)", re.IGNORECASE), "name": "Yi (01.AI)", "risk": "low", "reason": "Limited public safety evaluation"},
    {"pattern": re.compile(r"deepseek", re.IGNORECASE), "name": "DeepSeek", "risk": "low", "reason": "Code-focused training may bypass content filters"},
]

UNSAFE_DATASET_PATTERNS: list[dict] = [
    {"pattern": re.compile(r"4chan", re.IGNORECASE), "risk": "high", "reason": "Known toxic content source"},
    {"pattern": re.compile(r"reddit.?uncensored", re.IGNORECASE), "risk": "high", "reason": "Unmoderated content"},
    {"pattern": re.compile(r"gab", re.IGNORECASE), "risk": "high", "reason": "Known for extremist content"},
    {"pattern": re.compile(r"voat", re.IGNORECASE), "risk": "high", "reason": "Known for extremist content"},
    {"pattern": re.compile(r"parler", re.IGNORECASE), "risk": "medium", "reason": "Limited moderation"},
    {"pattern": re.compile(r"darkweb", re.IGNORECASE), "risk": "critical", "reason": "Potentially illegal content"},
    {"pattern": re.compile(r"piracy", re.IGNORECASE), "risk": "medium", "reason": "Copyright concerns"},
]

UNSAFE_MODEL_KEYWORDS = [
    "uncensored", "unfiltered", "unrestricted", "no refusal", "no ethics",
    "no limits", "jailbreak", "jailbroken", "abliterated", "do anything",
    "bypass", "no guardrails", "no safety", "harmful", "toxic",
    "nsfw", "adult only", "18+", "explicit",
]

SAFETY_INDICATORS = [
    "rlhf", "constitutional ai", "safety trained", "aligned",
    "moderated", "filtered", "safe", "responsible", "ethical",
    "harmless", "helpful", "honest",
]


def check_vulnerable_model(model_id: str) -> Optional[dict]:
    combined = VULNERABLE_MODELS + RISKY_BASE_MODELS
    for model in combined:
        if model["pattern"].search(model_id):
            return model
    return None


def find_unsafe_keywords(text: str) -> list[str]:
    lower_text = text.lower()
    return [kw for kw in UNSAFE_MODEL_KEYWORDS if kw in lower_text]


def find_safety_indicators(text: str) -> list[str]:
    lower_text = text.lower()
    return [ind for ind in SAFETY_INDICATORS if ind in lower_text]
