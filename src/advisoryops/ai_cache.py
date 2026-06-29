"""Content-hash-based cache for AI API responses.

Design
------
* Cache key  : SHA-256 of the canonicalised (sorted-key) JSON of ``key_data``.
* Storage    : ``<cache_root>/<key[:2]>/<key>.json``  (sharded to avoid large dirs).
  The two-character shard prefix keeps directory listing fast even with thousands
  of cache entries (filesystems slow down with > ~10 000 files in one directory).
* Entry JSON : { cache_key, cached_at, model, tokens_used, result }
* Bypass     : per-call ``no_cache=True``, or env var ``AI_CACHE_DISABLED=1``.

Typical usage (wraps any zero-argument callable that hits an LLM API)::

    from advisoryops.ai_cache import cached_call

    entry = cached_call(
        key_data={"model": "gpt-4o-mini", "prompt": prompt_text},
        call_fn=lambda: {"result": call_openai(...), "model": "gpt-4o-mini", "tokens_used": 42},
        model="gpt-4o-mini",
    )
    result = entry["result"]   # always the actual payload
    was_cached = entry.get("from_cache", False)

``call_fn`` is expected to return a dict with at least a ``"result"`` key plus
optional ``"model"`` and ``"tokens_used"`` keys.  If ``call_fn`` returns
something that is not a dict, it is wrapped as ``{"result": <value>}``.
"""
from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Optional


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_DEFAULT_CACHE_ROOT = Path("outputs/ai_cache")


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _cache_key(key_data: Dict[str, Any]) -> str:
    """SHA-256 of the canonicalised (sort_keys=True) JSON of *key_data*."""
    canonical = json.dumps(key_data, sort_keys=True, ensure_ascii=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _cache_path(key: str, cache_root: Path) -> Path:
    """Shard path: ``<root>/<key[:2]>/<key>.json``."""
    return cache_root / key[:2] / f"{key}.json"


# ---------------------------------------------------------------------------
# AICache class
# ---------------------------------------------------------------------------

class AICache:
    """Thin on-disk JSON cache keyed by SHA-256 of request data.

    Args:
        cache_root: Directory for cache files (will be created on first write).
        enabled:    False disables both reads and writes for this instance.
                    Also disabled when env var ``AI_CACHE_DISABLED`` is non-empty.
    """

    def __init__(
        self,
        cache_root: str | Path = _DEFAULT_CACHE_ROOT,
        enabled: bool = True,
    ) -> None:
        self.cache_root = Path(cache_root)
        # Env var AI_CACHE_DISABLED=1 overrides the enabled flag
        env_disabled = bool(os.getenv("AI_CACHE_DISABLED", "").strip())
        self.enabled = enabled and not env_disabled

    # ------------------------------------------------------------------
    # public API
    # ------------------------------------------------------------------

    def get(self, key_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Return the cached entry dict, or ``None`` on miss / disabled."""
        if not self.enabled:
            return None
        path = _cache_path(_cache_key(key_data), self.cache_root)
        if not path.exists():
            return None
        try:
            entry = json.loads(path.read_text(encoding="utf-8"))
            entry["from_cache"] = True
            return entry
        except Exception:
            # Corrupted file — treat as miss
            return None

    def put(
        self,
        key_data: Dict[str, Any],
        result: Any,
        *,
        model: str = "",
        tokens_used: int = 0,
    ) -> Dict[str, Any]:
        """Write *result* to cache and return the full entry dict.

        Writing is skipped when the cache is disabled, but the entry dict
        is still returned so callers always get a consistent structure.
        """
        key = _cache_key(key_data)
        entry: Dict[str, Any] = {
            "cache_key": key,
            "cached_at": _utc_now_iso(),
            "model": model,
            "tokens_used": tokens_used,
            "result": result,
            "from_cache": False,
        }
        if self.enabled:
            path = _cache_path(key, self.cache_root)
            path.parent.mkdir(parents=True, exist_ok=True)
            # Write without from_cache so the stored file is clean
            stored = {k: v for k, v in entry.items() if k != "from_cache"}
            path.write_text(
                json.dumps(stored, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        return entry

    def invalidate(self, key_data: Dict[str, Any]) -> bool:
        """Delete a cache entry.  Returns True if the file existed."""
        path = _cache_path(_cache_key(key_data), self.cache_root)
        if path.exists():
            path.unlink()
            return True
        return False


# ---------------------------------------------------------------------------
# Convenience function
# ---------------------------------------------------------------------------

def cached_call(
    key_data: Dict[str, Any],
    call_fn: Callable[[], Any],
    *,
    model: str = "",
    cache_root: str | Path = _DEFAULT_CACHE_ROOT,
    no_cache: bool = False,
) -> Dict[str, Any]:
    """Call *call_fn* using the on-disk cache.

    Returns an entry dict with keys::

        cache_key   – SHA-256 of *key_data*
        cached_at   – ISO-8601 UTC timestamp of when the entry was written
        model       – model name (from call_fn result or *model* arg)
        tokens_used – int token count (from call_fn result, default 0)
        result      – the actual payload returned by call_fn
        from_cache  – True if this response came from disk, False if live

    When *from_cache* is True, *call_fn* is **not** called.

    Args:
        key_data:   Dict that uniquely identifies the call (will be hashed).
        call_fn:    Zero-argument callable returning a dict with at least
                    ``"result"`` key.  May also include ``"model"`` and
                    ``"tokens_used"``.
        model:      Fallback model name if *call_fn* doesn't supply one.
        cache_root: Directory for cache files.
        no_cache:   Bypass cache entirely (always calls API, never writes).
    """
    cache = AICache(cache_root=cache_root, enabled=not no_cache)

    # --- cache hit ---
    hit = cache.get(key_data)
    if hit is not None:
        return hit

    # --- cache miss: call the API ---
    raw = call_fn()
    if not isinstance(raw, dict):
        raw = {"result": raw}

    result = raw.get("result", raw)
    actual_model = raw.get("model") or model
    tokens = int(raw.get("tokens_used") or 0)

    return cache.put(key_data, result, model=actual_model, tokens_used=tokens)
