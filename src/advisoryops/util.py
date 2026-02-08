from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_text(text: str) -> str:
    h = hashlib.sha256()
    h.update(text.encode("utf-8", errors="ignore"))
    return h.hexdigest()


_whitespace_re = re.compile(r"\s+")


def normalize_text(text: str) -> str:
    # Best-effort normalization: preserve meaning, reduce noise.
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = _whitespace_re.sub(" ", text).strip()
    return text


def advisory_id_from_hash(content_hash: str, prefix_len: int = 12) -> str:
    return f"adv_{content_hash[:prefix_len]}"


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def write_json(path: Path, obj: Any) -> None:
    ensure_dir(path.parent)
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False) + "\n", encoding="utf8")


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf8"))
