"""Tests for advisoryops/ai_cache.py.

Key contract under test
-----------------------
* Cache hit  → call_fn is NOT called (zero API calls).
* Cache miss → call_fn IS called exactly once; result is written to disk.
* no_cache=True → call_fn always called, even when a cache entry exists.
* AI_CACHE_DISABLED env var → same as no_cache for every call.
* put/get roundtrip → stored entry survives a fresh AICache instance.
* Metadata (model, tokens_used, cached_at, cache_key) is preserved.
* from_cache flag is True on hit, False on fresh call.
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from advisoryops.ai_cache import AICache, _cache_key, cached_call


# ── helpers ────────────────────────────────────────────────────────────────

def _mock_call(result: dict | None = None, model: str = "gpt-4o-mini", tokens: int = 10):
    """Return a MagicMock that behaves like a live API call_fn."""
    payload = {"result": result or {"answer": 42}, "model": model, "tokens_used": tokens}
    return MagicMock(return_value=payload)


# ══════════════════════════════════════════════════════════════════════════
# Cache key contract
# ══════════════════════════════════════════════════════════════════════════

def test_cache_key_deterministic() -> None:
    """Same key_data always produces the same SHA-256."""
    d = {"model": "gpt-4o-mini", "prompt": "hello world"}
    assert _cache_key(d) == _cache_key(d)


def test_cache_key_order_independent() -> None:
    """Dict key order doesn't change the hash."""
    d1 = {"model": "gpt-4o-mini", "prompt": "hello"}
    d2 = {"prompt": "hello", "model": "gpt-4o-mini"}
    assert _cache_key(d1) == _cache_key(d2)


def test_cache_key_differs_for_different_inputs() -> None:
    """Different inputs produce different keys."""
    assert _cache_key({"q": "hello"}) != _cache_key({"q": "world"})
    assert _cache_key({"model": "a"}) != _cache_key({"model": "b"})


def test_cache_key_is_64_char_hex() -> None:
    """SHA-256 output is 64 lowercase hex characters."""
    key = _cache_key({"x": 1})
    assert len(key) == 64
    assert all(c in "0123456789abcdef" for c in key)


# ══════════════════════════════════════════════════════════════════════════
# AICache class: get / put / invalidate
# ══════════════════════════════════════════════════════════════════════════

def test_get_returns_none_on_miss(tmp_path: Path) -> None:
    cache = AICache(cache_root=tmp_path)
    assert cache.get({"q": "nonexistent"}) is None


def test_put_then_get_roundtrip(tmp_path: Path) -> None:
    cache = AICache(cache_root=tmp_path)
    key_data = {"q": "roundtrip", "model": "gpt-4o-mini"}
    cache.put(key_data, {"answer": "yes"}, model="gpt-4o-mini", tokens_used=42)

    hit = cache.get(key_data)
    assert hit is not None
    assert hit["result"] == {"answer": "yes"}
    assert hit["model"] == "gpt-4o-mini"
    assert hit["tokens_used"] == 42
    assert hit["from_cache"] is True


def test_put_creates_sharded_file(tmp_path: Path) -> None:
    """Entry is stored at <root>/<key[:2]>/<key>.json."""
    cache = AICache(cache_root=tmp_path)
    key_data = {"q": "persist"}
    cache.put(key_data, {"y": 2}, model="m", tokens_used=3)

    files = list(tmp_path.rglob("*.json"))
    assert len(files) == 1

    entry = json.loads(files[0].read_text(encoding="utf-8"))
    assert entry["result"] == {"y": 2}
    assert entry["model"] == "m"
    assert entry["tokens_used"] == 3
    assert "cached_at" in entry
    assert "cache_key" in entry
    # Shard dir name is first 2 chars of the key
    assert files[0].parent.name == entry["cache_key"][:2]


def test_get_survives_fresh_instance(tmp_path: Path) -> None:
    """Cache persists to disk so a new AICache object can read it."""
    key_data = {"q": "survival"}
    AICache(cache_root=tmp_path).put(key_data, {"z": 99}, model="m", tokens_used=0)

    hit = AICache(cache_root=tmp_path).get(key_data)
    assert hit is not None
    assert hit["result"]["z"] == 99


def test_disabled_cache_skips_reads_and_writes(tmp_path: Path) -> None:
    """enabled=False: get always returns None, put skips disk write."""
    cache = AICache(cache_root=tmp_path, enabled=False)
    key_data = {"q": "disabled"}
    entry = cache.put(key_data, {"v": 1}, model="m", tokens_used=0)

    # Still returns an entry dict (callers always get consistent structure)
    assert entry["result"] == {"v": 1}
    # But nothing was written
    assert not any(tmp_path.rglob("*.json"))
    # And get returns None
    assert cache.get(key_data) is None


def test_invalidate_removes_entry(tmp_path: Path) -> None:
    """invalidate() deletes the cached file and returns True."""
    cache = AICache(cache_root=tmp_path)
    key_data = {"q": "delete_me"}
    cache.put(key_data, {"x": 1})

    assert cache.invalidate(key_data) is True
    assert cache.get(key_data) is None


def test_invalidate_returns_false_for_nonexistent(tmp_path: Path) -> None:
    cache = AICache(cache_root=tmp_path)
    assert cache.invalidate({"q": "never_written"}) is False


def test_corrupted_entry_treated_as_miss(tmp_path: Path) -> None:
    """A cache file with invalid JSON returns None rather than raising."""
    cache = AICache(cache_root=tmp_path)
    key_data = {"q": "corrupt"}
    cache.put(key_data, {"ok": True})

    # Corrupt the file
    files = list(tmp_path.rglob("*.json"))
    files[0].write_text("NOT VALID JSON", encoding="utf-8")

    assert cache.get(key_data) is None


# ══════════════════════════════════════════════════════════════════════════
# cached_call: the main public convenience function
# ══════════════════════════════════════════════════════════════════════════

def test_cache_miss_calls_api_once(tmp_path: Path) -> None:
    """On first call, API function is invoked exactly once."""
    call_fn = _mock_call({"x": 1})
    result = cached_call({"q": "miss"}, call_fn, cache_root=tmp_path)

    call_fn.assert_called_once()
    assert result["result"] == {"x": 1}
    assert result["from_cache"] is False


def test_cache_hit_skips_api_call(tmp_path: Path) -> None:
    """On second call with same key_data, call_fn is NOT invoked."""
    call_fn = _mock_call({"x": 2})
    key_data = {"q": "hit_test"}

    # Warm the cache
    cached_call(key_data, call_fn, cache_root=tmp_path)
    # Second call — must hit cache
    result = cached_call(key_data, call_fn, cache_root=tmp_path)

    assert call_fn.call_count == 1, "API should be called exactly once; second call was a cache hit"
    assert result["result"] == {"x": 2}
    assert result["from_cache"] is True


def test_no_cache_always_calls_api(tmp_path: Path) -> None:
    """no_cache=True bypasses cache — API called on every invocation."""
    call_fn = _mock_call({"x": 3})
    key_data = {"q": "no_cache_test"}

    cached_call(key_data, call_fn, cache_root=tmp_path)
    cached_call(key_data, call_fn, cache_root=tmp_path, no_cache=True)
    cached_call(key_data, call_fn, cache_root=tmp_path, no_cache=True)

    assert call_fn.call_count == 3


def test_no_cache_does_not_write_to_disk(tmp_path: Path) -> None:
    """no_cache=True must not write anything to the cache directory."""
    call_fn = _mock_call({"x": 4})
    cached_call({"q": "no_write"}, call_fn, cache_root=tmp_path, no_cache=True)
    assert not any(tmp_path.rglob("*.json"))


def test_metadata_preserved_in_result(tmp_path: Path) -> None:
    """cached_call result always includes model, tokens_used, cached_at, cache_key."""
    call_fn = _mock_call({"x": 5}, model="gpt-4o-mini", tokens=77)
    result = cached_call({"q": "meta"}, call_fn, cache_root=tmp_path)

    assert result["model"] == "gpt-4o-mini"
    assert result["tokens_used"] == 77
    assert "cached_at" in result
    assert "cache_key" in result


def test_model_fallback_from_kwarg(tmp_path: Path) -> None:
    """If call_fn doesn't set 'model', the model kwarg is used."""
    call_fn = MagicMock(return_value={"result": {"r": 1}})  # no 'model' key
    result = cached_call({"q": "model_fb"}, call_fn, model="my-model", cache_root=tmp_path)
    assert result["model"] == "my-model"


def test_non_dict_return_wrapped(tmp_path: Path) -> None:
    """If call_fn returns a non-dict, it's wrapped as {'result': <value>}."""
    call_fn = MagicMock(return_value="just a string")
    result = cached_call({"q": "wrap"}, call_fn, cache_root=tmp_path)
    assert result["result"] == "just a string"


def test_different_key_data_produces_separate_entries(tmp_path: Path) -> None:
    """Different key_data values create independent cache entries."""
    fn_a = _mock_call({"for": "a"})
    fn_b = _mock_call({"for": "b"})

    cached_call({"q": "a"}, fn_a, cache_root=tmp_path)
    cached_call({"q": "b"}, fn_b, cache_root=tmp_path)

    result_a = cached_call({"q": "a"}, fn_a, cache_root=tmp_path)
    result_b = cached_call({"q": "b"}, fn_b, cache_root=tmp_path)

    # Both should be cache hits (each fn called exactly once total)
    assert fn_a.call_count == 1
    assert fn_b.call_count == 1
    assert result_a["result"] == {"for": "a"}
    assert result_b["result"] == {"for": "b"}


# ══════════════════════════════════════════════════════════════════════════
# Environment variable: AI_CACHE_DISABLED
# ══════════════════════════════════════════════════════════════════════════

def test_env_var_disables_cache_globally(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """AI_CACHE_DISABLED=1 prevents reads and writes regardless of no_cache flag."""
    monkeypatch.setenv("AI_CACHE_DISABLED", "1")
    call_fn = _mock_call({"z": 9})
    key_data = {"q": "env_disable"}

    cached_call(key_data, call_fn, cache_root=tmp_path)
    cached_call(key_data, call_fn, cache_root=tmp_path)

    # Both calls went to the API — env var suppressed cache
    assert call_fn.call_count == 2
    # Nothing written to disk
    assert not any(tmp_path.rglob("*.json"))


def test_env_var_empty_string_does_not_disable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """AI_CACHE_DISABLED='' (empty) should not disable the cache."""
    monkeypatch.setenv("AI_CACHE_DISABLED", "")
    call_fn = _mock_call({"ok": True})
    key_data = {"q": "env_empty"}

    cached_call(key_data, call_fn, cache_root=tmp_path)
    result = cached_call(key_data, call_fn, cache_root=tmp_path)

    assert call_fn.call_count == 1  # second call was a hit
    assert result["from_cache"] is True
