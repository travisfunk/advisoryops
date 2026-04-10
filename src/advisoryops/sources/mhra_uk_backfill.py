"""MHRA UK medical device alerts historical backfill.

Pulls the full MHRA (Medicines and Healthcare products Regulatory Agency)
medical safety alert catalog via the GOV.UK search API:
  https://www.gov.uk/api/search.json?filter_document_type=medical_safety_alert

1,381 alerts with full pagination (start/count parameters).

Key features:
  - JSON REST API with pagination (count=100, start=0,100,200...)
  - Each result has title, description, link, public_timestamp
  - No API key required
  - All records are medical device safety alerts by definition

Usage:
    from advisoryops.sources.mhra_uk_backfill import run_backfill, incremental_update

    stats = run_backfill(max_results=200)  # Test sample
    stats = run_backfill()                  # Full 1,381 alerts
    stats = incremental_update()            # Recent + publish
"""
from __future__ import annotations

import http.client
import json
import logging
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

_API_BASE = "https://www.gov.uk/api/search.json"
_DEFAULT_PARAMS = {
    "filter_document_type": "medical_safety_alert",
    "count": "100",
}
_GOV_UK_BASE = "https://www.gov.uk"

_DEFAULT_CACHE_DIR = Path("outputs/mhra_uk_cache")
_PROGRESS_FILE = "_backfill_progress.json"
_USER_AGENT = "AdvisoryOps/1.0 (security advisory aggregator; MHRA UK backfill)"
_TIMEOUT = 30
_PAGE_SIZE = 100


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


def _load_progress(cache_dir: Path) -> Dict[str, Any]:
    progress_path = cache_dir / _PROGRESS_FILE
    if progress_path.exists():
        try:
            return json.loads(progress_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            pass
    return {
        "last_start": 0,
        "total_results": None,
        "records_fetched": 0,
        "pages_fetched": 0,
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


def _alert_cache_id(record: Dict[str, Any]) -> Optional[str]:
    """Generate a stable cache ID from an MHRA alert record."""
    link = str(record.get("link", "") or "").strip()
    if link:
        # /drug-device-alerts/some-alert-name → some-alert-name
        slug = link.rsplit("/", 1)[-1]
        if slug:
            return re.sub(r"[^a-zA-Z0-9_\-]", "_", slug)
    title = str(record.get("title", "") or "").strip()
    if title:
        return re.sub(r"[^a-zA-Z0-9_\-]", "_", title[:80])
    return None


def _save_alert_cache(
    record: Dict[str, Any],
    cache_dir: Path,
) -> Optional[str]:
    cache_id = _alert_cache_id(record)
    if not cache_id:
        return None
    cache_file = cache_dir / f"mhra_{cache_id}.json"
    if cache_file.exists():
        return cache_id
    cache_file.write_text(
        json.dumps(record, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return cache_id


def _fetch_page(
    start: int,
    count: int,
    *,
    rate_limiter: _RateLimiter,
    _fetch_fn: Optional[Callable[[str], bytes]] = None,
) -> Tuple[Dict[str, Any], int]:
    """Fetch a page from the GOV.UK search API."""
    params = dict(_DEFAULT_PARAMS)
    params["start"] = str(start)
    params["count"] = str(count)

    url = f"{_API_BASE}?{urllib.parse.urlencode(params)}"

    if _fetch_fn is not None:
        raw = _fetch_fn(url)
        return json.loads(raw), 200

    rate_limiter.wait()

    headers = {"User-Agent": _USER_AGENT}
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data, 200
    except urllib.error.HTTPError as exc:
        if exc.code in (429, 500, 502, 503):
            return {}, exc.code
        raise RuntimeError(
            f"GOV.UK API error {exc.code} at start={start}: {exc}"
        ) from exc
    except (
        http.client.IncompleteRead,
        http.client.RemoteDisconnected,
        ConnectionResetError,
        ConnectionError,
        TimeoutError,
        urllib.error.URLError,
    ) as exc:
        logger.debug("Transient error at start=%d: %s", start, exc)
        return {}, 503
    except json.JSONDecodeError as exc:
        logger.debug("JSON decode error at start=%d: %s", start, exc)
        return {}, 503


def run_backfill(
    *,
    cache_dir: Optional[Path] = None,
    max_results: Optional[int] = None,
    page_size: int = _PAGE_SIZE,
    _fetch_fn: Optional[Callable[[str], bytes]] = None,
) -> Dict[str, Any]:
    """Run MHRA UK medical device alerts backfill."""
    if cache_dir is None:
        cache_dir = _DEFAULT_CACHE_DIR
    cache_dir.mkdir(parents=True, exist_ok=True)

    rate_limiter = _RateLimiter(max_requests=4, window_seconds=1.0)
    progress = _load_progress(cache_dir)

    if progress.get("completed"):
        return {
            "status": "already_completed",
            "records_fetched": progress.get("records_fetched", 0),
        }

    start = progress.get("last_start", 0)
    total_results = progress.get("total_results")

    stats: Dict[str, Any] = {
        "status": "running",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "pages_fetched": progress.get("pages_fetched", 0),
        "records_fetched": progress.get("records_fetched", 0),
        "records_new": 0,
        "records_skipped": 0,
        "total_results": total_results,
        "errors": [],
    }

    while True:
        if max_results is not None and stats["records_fetched"] >= max_results:
            break
        if total_results is not None and start >= total_results:
            progress["completed"] = True
            break

        try:
            data, status_code = _fetch_page(
                start, page_size,
                rate_limiter=rate_limiter,
                _fetch_fn=_fetch_fn,
            )
        except RuntimeError as exc:
            stats["errors"].append({"start": start, "error": str(exc)})
            break

        if status_code == 429:
            time.sleep(30)
            continue

        if total_results is None:
            total_results = data.get("total", 0)
            stats["total_results"] = total_results
            progress["total_results"] = total_results

        results = data.get("results") or []
        if not results:
            progress["completed"] = True
            break

        page_new = 0
        page_skipped = 0
        for record in results:
            if not isinstance(record, dict):
                continue
            cache_id = _alert_cache_id(record)
            if not cache_id:
                continue
            cache_file = cache_dir / f"mhra_{cache_id}.json"
            if cache_file.exists():
                page_skipped += 1
            else:
                _save_alert_cache(record, cache_dir)
                page_new += 1

        stats["records_new"] += page_new
        stats["records_skipped"] += page_skipped
        stats["records_fetched"] += len(results)
        stats["pages_fetched"] += 1

        start += page_size
        progress["last_start"] = start
        progress["records_fetched"] = stats["records_fetched"]
        progress["pages_fetched"] = stats["pages_fetched"]
        _save_progress(cache_dir, progress)

    _save_progress(cache_dir, progress)
    stats["finished_at"] = datetime.now(timezone.utc).isoformat()
    stats["status"] = "completed" if progress.get("completed") else "paused"
    return stats


def generate_signals_from_cache(
    *,
    cache_dir: Optional[Path] = None,
    source_id: str = "mhra-uk-alerts",
    limit: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """Generate normalized signals from cached MHRA alerts."""
    if cache_dir is None:
        cache_dir = _DEFAULT_CACHE_DIR
    if not cache_dir.exists():
        return []

    fetched_at = datetime.now(timezone.utc).isoformat()
    signals: List[Dict[str, Any]] = []

    for cache_file in sorted(cache_dir.glob("mhra_*.json")):
        if limit is not None and len(signals) >= limit:
            break

        try:
            data = json.loads(cache_file.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue

        title = str(data.get("title", "") or "").strip()
        description = str(data.get("description", "") or "").strip()
        link = str(data.get("link", "") or "").strip()
        if link and not link.startswith("http"):
            link = f"{_GOV_UK_BASE}{link}"
        published = str(data.get("public_timestamp", "") or "").strip()

        guid = _alert_cache_id(data) or cache_file.stem

        signals.append({
            "source": source_id,
            "guid": guid,
            "title": title or guid,
            "link": link,
            "published_date": published,
            "summary": description or title,
            "fetched_at": fetched_at,
        })

    return signals


def incremental_update(
    *,
    cache_dir: Optional[Path] = None,
    out_root: str = "outputs/discover",
    source_id: str = "mhra-uk-alerts",
    max_results: int = 200,
    signal_limit: Optional[int] = None,
    _fetch_fn: Optional[Callable[[str], bytes]] = None,
) -> Dict[str, Any]:
    """Incremental: fetch most recent alerts and publish all cached signals."""
    from .discover_sync import publish_to_discover

    if cache_dir is None:
        cache_dir = _DEFAULT_CACHE_DIR
    cache_dir.mkdir(parents=True, exist_ok=True)

    rate_limiter = _RateLimiter(max_requests=4, window_seconds=1.0)

    stats: Dict[str, Any] = {
        "status": "running",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "new_alerts": 0,
        "errors": [],
    }

    # Fetch first few pages (most recent alerts sorted by relevance)
    start = 0
    fetched = 0
    while fetched < max_results:
        try:
            data, status_code = _fetch_page(
                start, _PAGE_SIZE,
                rate_limiter=rate_limiter,
                _fetch_fn=_fetch_fn,
            )
        except Exception as exc:
            stats["errors"].append({"start": start, "error": str(exc)})
            break

        if status_code == 429:
            time.sleep(30)
            continue

        results = data.get("results") or []
        if not results:
            break

        for record in results:
            if not isinstance(record, dict):
                continue
            cache_id = _alert_cache_id(record)
            if cache_id:
                cache_file = cache_dir / f"mhra_{cache_id}.json"
                if not cache_file.exists():
                    _save_alert_cache(record, cache_dir)
                    stats["new_alerts"] += 1

        fetched += len(results)
        start += _PAGE_SIZE

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
