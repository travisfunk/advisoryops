"""Shared low-level utilities used across the AdvisoryOps package.

All functions here are pure or have only filesystem side-effects.  Nothing in
this module makes network requests or calls any external API.

Functions
---------
utc_now_iso()
    Return the current UTC time as an ISO-8601 string.  Used for ``fetched_at``,
    ``started_at``, ``finished_at`` timestamps throughout the pipeline.

sha256_text(text)
    SHA-256 hex digest of a UTF-8 string.  Used as the content hash that drives
    content-addressed storage in ingest.py (same text → same advisory_id).

normalize_text(text)
    Collapse CRLF to LF, then collapse runs of whitespace to single spaces.
    Applied to advisory text before hashing so minor formatting differences
    between fetches don't produce different advisory_ids.

advisory_id_from_hash(content_hash, prefix_len=12)
    Construct an advisory ID of the form ``adv_<hex12>`` from a SHA-256 hash.
    12 hex characters = 48 bits → collision probability negligible for millions
    of advisories.

ensure_dir(path)
    ``mkdir(parents=True, exist_ok=True)`` wrapper to reduce boilerplate.

write_json(path, obj) / read_json(path)
    Thin wrappers for deterministic JSON file I/O (UTF-8, 2-space indent,
    ensure_ascii=False so Unicode advisory content is stored as-is).
"""
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
