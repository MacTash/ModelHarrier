"""HuggingFace API client for model metadata and file scanning."""

import json
import os
import hashlib
from pathlib import Path
from typing import Optional
from urllib.parse import quote

import requests
from huggingface_hub import HfApi

from model_harrier.utils.config import HF_API_BASE, MODEL_HARRIER_CACHE_DIR

HF_TOKEN = os.environ.get("HF_TOKEN") or os.environ.get("HUGGINGFACE_TOKEN")
CACHE_DIR = MODEL_HARRIER_CACHE_DIR / "hf"

api = HfApi()


def _cache_path(model_id: str) -> Path:
    key = hashlib.sha256(model_id.encode("utf-8")).hexdigest()[:20]
    return CACHE_DIR / f"{key}.json"


def get_model_info(model_id: str, use_cache: bool = True, offline: bool = False) -> dict:
    cache_file = _cache_path(model_id)
    if use_cache and cache_file.exists():
        with open(cache_file) as f:
            return json.load(f)
    if offline:
        raise FileNotFoundError(f"No cached Hugging Face metadata for {model_id}. Scan once online before using --offline.")

    model_info = api.model_info(
        repo_id=model_id,
        securityStatus=True,
        files_metadata=True,
        token=HF_TOKEN,
    )
    result = model_info.__dict__
    card_data = getattr(model_info, "card_data", None) or getattr(model_info, "cardData", None)
    if card_data:
        if hasattr(card_data, "to_dict"):
            card_data = card_data.to_dict()
        elif isinstance(card_data, str):
            try:
                import yaml

                card_data = yaml.safe_load(card_data) or {}
            except Exception:
                card_data = {}
        result["cardData"] = card_data if isinstance(card_data, dict) else {}
    if hasattr(model_info, "siblings") and model_info.siblings:
        result["siblings"] = [
            {
                "rfilename": s.rfilename,
                "size": getattr(s, "size", None),
            }
            for s in model_info.siblings
        ]
    if hasattr(model_info, "securityStatus"):
        result["securityStatus"] = model_info.securityStatus

    cache_file.parent.mkdir(parents=True, exist_ok=True)
    with open(cache_file, "w") as f:
        json.dump(result, f, default=str)

    return result


def get_file_tree(model_id: str, expand: bool = True) -> list[dict]:
    url = f"https://huggingface.co/api/models/{quote(model_id, safe='')}/tree/main"
    if expand:
        url += "?expand=True"
    headers = {}
    if HF_TOKEN:
        headers["Authorization"] = f"Bearer {HF_TOKEN}"

    resp = requests.get(url, headers=headers, timeout=30)
    resp.raise_for_status()
    return resp.json()


def get_security_status(model_id: str) -> Optional[dict]:
    try:
        info = get_model_info(model_id)
        return info.get("securityStatus")
    except Exception:
        return None


def get_model_card(model_id: str) -> Optional[str]:
    try:
        siblings = get_model_info(model_id, use_cache=True).get("siblings", [])
        readme = next((item.get("rfilename") for item in siblings if item.get("rfilename", "").lower() == "readme.md"), None)
        if not readme:
            return None
        return download_file(model_id, readme).read_text(encoding="utf-8", errors="replace")
    except Exception:
        return None


def get_model_config(model_id: str) -> Optional[dict]:
    try:
        return api.model_info(repo_id=model_id, files_metadata=False, token=HF_TOKEN).cardData
    except Exception:
        return None


def download_file(model_id: str, filename: str, dest: Optional[Path] = None) -> Path:
    if dest is None:
        repo_dir = hashlib.sha256(model_id.encode("utf-8")).hexdigest()[:20]
        dest = CACHE_DIR / repo_dir / filename
    dest.parent.mkdir(parents=True, exist_ok=True)

    revision = "main"
    metadata_path = _cache_path(model_id)
    if metadata_path.exists():
        try:
            with open(metadata_path) as f:
                revision = json.load(f).get("sha") or "main"
        except (OSError, json.JSONDecodeError):
            pass

    api.hf_hub_download(
        repo_id=model_id,
        filename=filename,
        revision=revision,
        local_dir=dest.parent,
        token=HF_TOKEN,
    )
    return dest


def search_models(query: str, limit: int = 10) -> list[dict]:
    results = api.list_models(search=query, limit=limit, token=HF_TOKEN)
    return [{"id": m.modelId, "downloads": getattr(m, "downloads", 0), "pipeline_tag": getattr(m, "pipeline_tag", None)} for m in results]
