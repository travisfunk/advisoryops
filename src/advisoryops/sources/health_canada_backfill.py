"""Health Canada medical device recalls — incremental polling backfill.

The Health Canada recalls API only exposes the most recent 15 records per
category via:
  https://healthycanadians.gc.ca/recall-alert-rappel-avis/api/recent/en

There is no paginated historical endpoint. The older recalls-rappels.canada.ca
portal has ~6,030 health records but no public API (HTML only).

Strategy: **incremental polling**. Each run fetches all categories from the
recent API, filters for health (cat=3), fetches detail pages, and caches them.
Over time the cache accumulates history. This yields ~15 new records per run
when new recalls are published.

Individual recall details accessible at:
  https://healthycanadians.gc.ca/recall-alert-rappel-avis/api/{recallId}/en

Usage:
    from advisoryops.sources.health_canada_backfill import run_backfill, incremental_update

    stats = run_backfill()           # Fetch current recent + cache
    stats = incremental_update()     # Same, plus publish to discover
"""
from __future__ import annotations

import json
import logging
import re
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

_RECENT_API = "https://healthycanadians.gc.ca/recall-alert-rappel-avis/api/recent/en"
_DETAIL_API = "https://healthycanadians.gc.ca/recall-alert-rappel-avis/api/{recall_id}/en"
_SEARCH_API = "https://healthycanadians.gc.ca/recall-alert-rappel-avis/api/search/en"

_DEFAULT_CACHE_DIR = Path("outputs/health_canada_cache")
_PROGRESS_FILE = "_backfill_progress.json"
_USER_AGENT = "AdvisoryOps/1.0 (security advisory aggregator; Health Canada backfill)"
_TIMEOUT = 30


class _RateLimiter:
    def __init__(self, max_requests: int, window_seconds: float):
        self._max = max_requests
        self._window = window_seconds
        self._timestamps: List[float] = []

    def wait(self) -> None:
        now = time.monotonic()
        self._timestamps = [t for t in self._timestamps if now - t < self._window]
        if len(self._timestamps) >= self._max:
            sleep_time = self._window - (now - self._timestamps[0]) + 0.1
            if sleep_time > 0:
                time.sleep(sleep_time)
        self._timestamps.append(time.monotonic())


def _http_get(
    url: str,
    *,
    timeout: int = _TIMEOUT,
    _fetch_fn: Optional[Callable[[str], bytes]] = None,
) -> bytes:
    if _fetch_fn is not None:
        return _fetch_fn(url)
    headers = {"User-Agent": _USER_AGENT}
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def _load_progress(cache_dir: Path) -> Dict[str, Any]:
    progress_path = cache_dir / _PROGRESS_FILE
    if progress_path.exists():
        try:
            return json.loads(progress_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            pass
    return {
        "recall_ids_fetched": [],
        "records_total": 0,
        "completed": False,
        "last_updated": None,
    }


def _save_progress(cache_dir: Path, progress: Dict[str, Any]) -> None:
    progress["last_updated"] = datetime.now(timezone.utc).isoformat()
    progress_path = cache_dir / _PROGRESS_FILE
    progress_path.write_text(
        json.dumps(progress, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def _save_recall_cache(
    recall_id: str,
    data: Dict[str, Any],
    cache_dir: Path,
) -> None:
    safe_id = re.sub(r"[^a-zA-Z0-9_\-]", "_", str(recall_id))
    cache_file = cache_dir / f"hc_{safe_id}.json"
    if cache_file.exists():
        return
    cache_file.write_text(
        json.dumps(data, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def _load_recall_cache(
    recall_id: str,
    cache_dir: Path,
) -> Optional[Dict[str, Any]]:
    safe_id = re.sub(r"[^a-zA-Z0-9_\-]", "_", str(recall_id))
    cache_file = cache_dir / f"hc_{safe_id}.json"
    if cache_file.exists():
        try:
            return json.loads(cache_file.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None
    return None


# ---------------------------------------------------------------------------
# API response parsing
# ---------------------------------------------------------------------------

def parse_recent_api(response: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Parse the /api/recent/en response, filtering for health/medical (cat=3).

    The response has structure: {"results": {"ALL": [...], "HEALTH": [...], ...}}
    or {"results": {"ALL": [...]}} depending on the endpoint.
    Each entry has: recallId, title, date_published (unix ts), category, url.
    """
    recalls: List[Dict[str, Any]] = []

    # Collect entries from ALL categories to maximize coverage per API call.
    # The recent API returns {"results": {"ALL": [...], "HEALTH": [...], ...}}
    # We merge all lists and deduplicate by recallId.
    results = response.get("results") or response
    entries: List[Dict[str, Any]] = []
    if isinstance(results, dict):
        for key, val in results.items():
            if isinstance(val, list):
                entries.extend(val)
    elif isinstance(results, list):
        entries = results

    seen_ids: set = set()
    for entry in entries:
        if not isinstance(entry, dict):
            continue

        recall_id = str(entry.get("recallId", "") or "").strip()
        if not recall_id or recall_id in seen_ids:
            continue
        seen_ids.add(recall_id)

        # Filter for health/medical category (3)
        categories = entry.get("category") or []
        if isinstance(categories, list):
            cat_ids = [str(c) for c in categories]
        else:
            cat_ids = [str(categories)]

        # If category info is available, filter for health (3)
        # If not available, include anyway (erring on inclusive)
        if cat_ids and "3" not in cat_ids:
            continue

        title = str(entry.get("title", "") or "").strip()
        date_pub = entry.get("date_published", "")
        if isinstance(date_pub, (int, float)):
            # Unix timestamp in milliseconds
            try:
                date_pub = datetime.fromtimestamp(
                    date_pub / 1000, tz=timezone.utc
                ).isoformat()
            except (ValueError, OSError):
                date_pub = str(date_pub)
        else:
            date_pub = str(date_pub or "")

        url = str(entry.get("url", "") or "").strip()

        recalls.append({
            "recall_id": recall_id,
            "title": title,
            "date_published": date_pub,
            "url": url,
            "categories": cat_ids,
        })

    return recalls


def parse_recall_detail(detail: Dict[str, Any]) -> Dict[str, Any]:
    """Parse an individual recall detail API response."""
    result: Dict[str, Any] = {}

    result["recall_id"] = str(detail.get("recallId", "") or "").strip()
    result["title"] = str(detail.get("title", "") or "").strip()

    date_pub = detail.get("date_published", "")
    if isinstance(date_pub, (int, float)):
        try:
            date_pub = datetime.fromtimestamp(
                date_pub / 1000, tz=timezone.utc
            ).isoformat()
        except (ValueError, OSError):
            date_pub = str(date_pub)
    result["date_published"] = str(date_pub or "")

    # Extract panels/sections
    panels = detail.get("panels") or {}
    if isinstance(panels, dict):
        for key, value in panels.items():
            if isinstance(value, str):
                result[key] = value
    elif isinstance(panels, list):
        for panel in panels:
            if isinstance(panel, dict):
                name = panel.get("title", panel.get("panelName", ""))
                text = panel.get("text", panel.get("content", ""))
                if name and text:
                    result[str(name).lower().replace(" ", "_")] = text

    result["url"] = str(detail.get("url", "") or "").strip()
    return result


# ---------------------------------------------------------------------------
# Backfill
# ---------------------------------------------------------------------------

def run_backfill(
    *,
    cache_dir: Optional[Path] = None,
    max_results: Optional[int] = None,
    _fetch_fn: Optional[Callable[[str], bytes]] = None,
) -> Dict[str, Any]:
    """Run Health Canada medical device recalls backfill.

    Fetches the recent API to discover recall IDs, then fetches
    individual detail pages for each.
    """
    if cache_dir is None:
        cache_dir = _DEFAULT_CACHE_DIR
    cache_dir.mkdir(parents=True, exist_ok=True)

    # No "completed" check — this is incremental polling, each run
    # checks for new recent recalls and caches any not yet seen.
    progress = _load_progress(cache_dir)

    rate_limiter = _RateLimiter(max_requests=3, window_seconds=1.0)

    stats: Dict[str, Any] = {
        "status": "running",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "recalls_discovered": 0,
        "details_fetched": 0,
        "details_cached": 0,
        "details_failed": 0,
        "errors": [],
    }

    # Fetch the recent API
    try:
        recent_bytes = _http_get(_RECENT_API, _fetch_fn=_fetch_fn)
        recent_json = json.loads(recent_bytes.decode("utf-8"))
    except Exception as exc:
        logger.error("Failed to fetch Health Canada recent API: %s", exc)
        stats["errors"].append({"stage": "recent_fetch", "error": str(exc)})
        stats["status"] = "error"
        return stats

    recalls = parse_recent_api(recent_json)
    stats["recalls_discovered"] = len(recalls)

    if max_results is not None:
        recalls = recalls[:max_results]

    fetched_ids = set(progress.get("recall_ids_fetched") or [])

    # Fetch detail for each recall
    for recall in recalls:
        recall_id = recall["recall_id"]

        if _load_recall_cache(recall_id, cache_dir) is not None:
            stats["details_cached"] += 1
            continue

        rate_limiter.wait()

        detail_url = _DETAIL_API.format(recall_id=recall_id)
        try:
            detail_bytes = _http_get(detail_url, _fetch_fn=_fetch_fn)
            detail_json = json.loads(detail_bytes.decode("utf-8"))
            parsed = parse_recall_detail(detail_json)
            merged = {**recall, **parsed}
            _save_recall_cache(recall_id, merged, cache_dir)
            stats["details_fetched"] += 1
            fetched_ids.add(recall_id)
        except Exception as exc:
            logger.warning("Failed to fetch detail for %s: %s", recall_id, exc)
            stats["details_failed"] += 1
            # Cache the basic info from the list
            _save_recall_cache(recall_id, recall, cache_dir)

    progress["recall_ids_fetched"] = sorted(fetched_ids)
    progress["records_total"] = stats["recalls_discovered"]
    progress["completed"] = True
    _save_progress(cache_dir, progress)

    stats["finished_at"] = datetime.now(timezone.utc).isoformat()
    stats["status"] = "completed"
    return stats


def generate_signals_from_cache(
    *,
    cache_dir: Optional[Path] = None,
    source_id: str = "health-canada-recalls-historical",
    limit: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """Generate normalized signals from cached Health Canada recalls."""
    if cache_dir is None:
        cache_dir = _DEFAULT_CACHE_DIR
    if not cache_dir.exists():
        return []

    fetched_at = datetime.now(timezone.utc).isoformat()
    signals: List[Dict[str, Any]] = []

    for cache_file in sorted(cache_dir.glob("hc_*.json")):
        if limit is not None and len(signals) >= limit:
            break

        try:
            data = json.loads(cache_file.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue

        recall_id = str(data.get("recall_id", "") or "").strip()
        title = str(data.get("title", "") or "").strip()
        published = str(data.get("date_published", "") or "").strip()
        url = str(data.get("url", "") or "").strip()
        if url and not url.startswith("http"):
            url = f"https://healthycanadians.gc.ca{url}"

        guid = recall_id or cache_file.stem

        # Build summary from available fields
        summary_parts = [title]
        for key in ("issue", "what_you_should_do", "affected_products"):
            val = str(data.get(key, "") or "").strip()
            if val and val not in title:
                summary_parts.append(val)
                break
        summary = " | ".join(summary_parts) if summary_parts else title

        signals.append({
            "source": source_id,
            "guid": guid,
            "title": title or guid,
            "link": url,
            "published_date": published,
            "summary": summary or title,
            "fetched_at": fetched_at,
        })

    return signals


def incremental_update(
    *,
    cache_dir: Optional[Path] = None,
    out_root: str = "outputs/discover",
    source_id: str = "health-canada-recalls-historical",
    signal_limit: Optional[int] = None,
    _fetch_fn: Optional[Callable[[str], bytes]] = None,
) -> Dict[str, Any]:
    """Incremental: re-fetch recent API, cache new recalls, publish all."""
    from .discover_sync import publish_to_discover

    if cache_dir is None:
        cache_dir = _DEFAULT_CACHE_DIR
    cache_dir.mkdir(parents=True, exist_ok=True)

    rate_limiter = _RateLimiter(max_requests=3, window_seconds=1.0)

    stats: Dict[str, Any] = {
        "status": "running",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "new_recalls": 0,
        "errors": [],
    }

    try:
        recent_bytes = _http_get(_RECENT_API, _fetch_fn=_fetch_fn)
        recent_json = json.loads(recent_bytes.decode("utf-8"))
        recalls = parse_recent_api(recent_json)

        for recall in recalls:
            recall_id = recall["recall_id"]
            if _load_recall_cache(recall_id, cache_dir) is not None:
                continue

            rate_limiter.wait()
            detail_url = _DETAIL_API.format(recall_id=recall_id)
            try:
                detail_bytes = _http_get(detail_url, _fetch_fn=_fetch_fn)
                detail_json = json.loads(detail_bytes.decode("utf-8"))
                parsed = parse_recall_detail(detail_json)
                merged = {**recall, **parsed}
                _save_recall_cache(recall_id, merged, cache_dir)
                stats["new_recalls"] += 1
            except Exception as exc:
                logger.warning("Detail fetch failed for %s: %s", recall_id, exc)
                _save_recall_cache(recall_id, recall, cache_dir)
                stats["new_recalls"] += 1

    except Exception as exc:
        logger.warning("Failed to fetch Health Canada API: %s", exc)
        stats["errors"].append({"stage": "fetch", "error": str(exc)})

    # Publish all cached signals
    signals = generate_signals_from_cache(
        cache_dir=cache_dir, source_id=source_id, limit=signal_limit,
    )
    publish_stats = publish_to_discover(
        signals, source_id=source_id, out_root=out_root,
    )

    stats["status"] = "completed"
    stats["finished_at"] = datetime.now(timezone.utc).isoformat()
    stats["total_signals_published"] = publish_stats["total_signals"]
    stats["new_signals_published"] = publish_stats["new_signals"]
    return stats
