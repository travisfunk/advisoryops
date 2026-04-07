"""FDA safety communications / enforcement historical backfill.

Pulls the openFDA device enforcement database (~38,500 records) which contains
the formal regulatory actions behind FDA safety communications. Filters for
cybersecurity-relevant entries.

FDA Safety Communications themselves have no API — they exist only as HTML pages
on FDA.gov (which blocks automated access). The enforcement endpoint provides
the structured data that backs those communications: product details, recall
classification, distribution, and reason for the action.

Endpoint: https://api.fda.gov/device/enforcement.json
  - Paginated via limit (max 100) and skip
  - No API key required (240 req/min/IP limit)
  - 38,500+ records, dating back to ~2004

Usage:
    from advisoryops.sources.fda_safety_comms_backfill import run_backfill, incremental_update

    stats = run_backfill(max_results=1000)  # Test sample
    stats = run_backfill()                   # Full pull
    stats = incremental_update()             # Recent + publish
"""
from __future__ import annotations

import json
import logging
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

_API_BASE = "https://api.fda.gov/device/enforcement.json"
_DEFAULT_CACHE_DIR = Path("outputs/fda_safety_comms_cache")
_PROGRESS_FILE = "_backfill_progress.json"
_USER_AGENT = "AdvisoryOps/1.0 (security advisory aggregator; FDA enforcement backfill)"
_TIMEOUT = 30
_PAGE_SIZE = 100  # openFDA max

# Cybersecurity relevance keywords (same set as openFDA recalls backfill)
_CYBER_KEYWORDS = [
    "cybersecurity", "vulnerability", "exploit", "unauthorized access",
    "data breach", "encryption", "authentication", "password",
    "remote", "network", "software", "firmware", "patch",
    "hack", "malware", "ransomware",
    "cve-", "security update",
]

_CYBER_RE = re.compile(
    "|".join(re.escape(kw) for kw in _CYBER_KEYWORDS),
    re.IGNORECASE,
)


class _RateLimiter:
    """Sliding-window rate limiter."""

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
                logger.debug("Rate limit: sleeping %.1fs", sleep_time)
                time.sleep(sleep_time)
        self._timestamps.append(time.monotonic())


def _get_rate_limiter() -> _RateLimiter:
    return _RateLimiter(max_requests=4, window_seconds=1.0)


def _load_progress(cache_dir: Path) -> Dict[str, Any]:
    progress_path = cache_dir / _PROGRESS_FILE
    if progress_path.exists():
        try:
            return json.loads(progress_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            pass
    return {
        "last_skip": 0,
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


def is_cyber_relevant(record: Dict[str, Any]) -> bool:
    """Check if an enforcement record is cybersecurity-relevant."""
    text = " ".join([
        str(record.get("reason_for_recall", "") or ""),
        str(record.get("product_description", "") or ""),
        str(record.get("code_info", "") or ""),
        str(record.get("product_type", "") or ""),
    ])
    return bool(_CYBER_RE.search(text))


def _record_cache_id(record: Dict[str, Any]) -> Optional[str]:
    """Generate a stable cache ID from an enforcement record."""
    for key in ("recall_number", "event_id"):
        val = str(record.get(key, "") or "").strip()
        if val:
            return re.sub(r"[^a-zA-Z0-9_\-.]", "_", val)
    return None


def _save_record_cache(
    record: Dict[str, Any],
    cache_dir: Path,
) -> Optional[str]:
    """Save an enforcement record to cache. Returns cache ID or None."""
    cache_id = _record_cache_id(record)
    if not cache_id:
        return None
    cache_file = cache_dir / f"enf_{cache_id}.json"
    if cache_file.exists():
        return cache_id
    data = dict(record)
    data["_cyber_relevant"] = is_cyber_relevant(record)
    cache_file.write_text(
        json.dumps(data, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return cache_id


def _fetch_page(
    skip: int,
    limit: int,
    *,
    search: str = "",
    rate_limiter: _RateLimiter,
    _fetch_fn: Optional[Callable[[str], bytes]] = None,
) -> Tuple[Dict[str, Any], int]:
    """Fetch a page from the openFDA device enforcement API."""
    params: Dict[str, str] = {
        "limit": str(limit),
        "skip": str(skip),
    }
    if search:
        params["search"] = search

    api_key = os.environ.get("OPENFDA_API_KEY", "")
    if api_key:
        params["api_key"] = api_key

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
        if exc.code == 429:
            return {}, 429
        if exc.code == 404:
            return {"results": []}, 404
        raise RuntimeError(
            f"openFDA enforcement API error {exc.code} at skip={skip}: {exc}"
        ) from exc
    except (urllib.error.URLError, json.JSONDecodeError) as exc:
        raise RuntimeError(
            f"openFDA enforcement API request failed at skip={skip}: {exc}"
        ) from exc


def run_backfill(
    *,
    cache_dir: Optional[Path] = None,
    max_results: Optional[int] = None,
    page_size: int = _PAGE_SIZE,
    _fetch_fn: Optional[Callable[[str], bytes]] = None,
) -> Dict[str, Any]:
    """Run FDA device enforcement historical backfill.

    Args:
        cache_dir: Cache directory.
        max_results: Maximum records to fetch. None = all.
        page_size: Results per page (max 100).
        _fetch_fn: Injectable fetch function for testing.

    Returns:
        Stats dict.
    """
    if cache_dir is None:
        cache_dir = _DEFAULT_CACHE_DIR
    cache_dir.mkdir(parents=True, exist_ok=True)

    rate_limiter = _get_rate_limiter()
    progress = _load_progress(cache_dir)

    if progress.get("completed"):
        logger.info("FDA enforcement backfill already completed.")
        return {
            "status": "already_completed",
            "records_fetched": progress.get("records_fetched", 0),
        }

    skip = progress.get("last_skip", 0)
    total_results = progress.get("total_results")

    stats: Dict[str, Any] = {
        "status": "running",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "pages_fetched": progress.get("pages_fetched", 0),
        "records_fetched": progress.get("records_fetched", 0),
        "records_new": 0,
        "records_skipped": 0,
        "cyber_relevant": 0,
        "total_results": total_results,
        "errors": [],
    }

    consecutive_429s = 0
    max_429_retries = 5

    logger.info(
        "Starting FDA enforcement backfill from skip=%d (max_results=%s)",
        skip, max_results or "all",
    )

    while True:
        if max_results is not None and stats["records_fetched"] >= max_results:
            break

        if total_results is not None and skip >= total_results:
            progress["completed"] = True
            break

        # openFDA skip cap
        if skip > 25000:
            logger.info("Reached openFDA skip limit (25000). Marking completed.")
            progress["completed"] = True
            break

        try:
            data, status_code = _fetch_page(
                skip, page_size,
                rate_limiter=rate_limiter,
                _fetch_fn=_fetch_fn,
            )
        except RuntimeError as exc:
            logger.error("Page fetch error at skip=%d: %s", skip, exc)
            stats["errors"].append({"skip": skip, "error": str(exc)})
            break

        if status_code == 429:
            consecutive_429s += 1
            if consecutive_429s >= max_429_retries:
                stats["errors"].append({"skip": skip, "error": "429 rate limit"})
                break
            time.sleep(min(30 * consecutive_429s, 120))
            continue

        consecutive_429s = 0

        if total_results is None:
            meta = data.get("meta") or {}
            total_obj = meta.get("results") or {}
            total_results = total_obj.get("total", 0)
            stats["total_results"] = total_results
            progress["total_results"] = total_results
            logger.info("openFDA reports %d total enforcement records.", total_results)

        results = data.get("results") or []
        if not results:
            progress["completed"] = True
            break

        page_new = 0
        page_skipped = 0
        page_cyber = 0
        for record in results:
            if not isinstance(record, dict):
                continue
            cache_id = _record_cache_id(record)
            if not cache_id:
                continue
            cache_file = cache_dir / f"enf_{cache_id}.json"
            if cache_file.exists():
                page_skipped += 1
            else:
                _save_record_cache(record, cache_dir)
                page_new += 1
            if is_cyber_relevant(record):
                page_cyber += 1

        stats["records_new"] += page_new
        stats["records_skipped"] += page_skipped
        stats["cyber_relevant"] += page_cyber
        stats["records_fetched"] += len(results)
        stats["pages_fetched"] += 1

        skip += page_size
        progress["last_skip"] = skip
        progress["records_fetched"] = stats["records_fetched"]
        progress["pages_fetched"] = stats["pages_fetched"]
        _save_progress(cache_dir, progress)

        logger.info(
            "Page %d: %d records (%d new, %d cached, %d cyber). Progress: %d/%s",
            stats["pages_fetched"], len(results),
            page_new, page_skipped, page_cyber,
            stats["records_fetched"], total_results or "?",
        )

    _save_progress(cache_dir, progress)
    stats["finished_at"] = datetime.now(timezone.utc).isoformat()
    stats["status"] = "completed" if progress.get("completed") else "paused"

    logger.info(
        "FDA enforcement backfill %s: %d records (%d new, %d cached, %d cyber).",
        stats["status"], stats["records_fetched"],
        stats["records_new"], stats["records_skipped"], stats["cyber_relevant"],
    )

    return stats


def generate_signals_from_cache(
    *,
    cache_dir: Optional[Path] = None,
    source_id: str = "fda-safety-comms-historical",
    limit: Optional[int] = None,
    cyber_only: bool = True,
) -> List[Dict[str, Any]]:
    """Generate normalized signal dicts from cached enforcement records.

    Args:
        cache_dir: Cache directory.
        source_id: Source ID for signals.
        limit: Max signals to generate.
        cyber_only: If True (default), only emit cyber-relevant signals.

    Returns:
        List of normalized signal dicts.
    """
    if cache_dir is None:
        cache_dir = _DEFAULT_CACHE_DIR
    if not cache_dir.exists():
        return []

    fetched_at = datetime.now(timezone.utc).isoformat()
    signals: List[Dict[str, Any]] = []

    for cache_file in sorted(cache_dir.glob("enf_*.json")):
        if limit is not None and len(signals) >= limit:
            break

        try:
            data = json.loads(cache_file.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue

        if cyber_only and not data.get("_cyber_relevant", False):
            continue

        recall_number = str(data.get("recall_number", "") or "").strip()
        event_id = str(data.get("event_id", "") or "").strip()
        guid = recall_number or event_id or cache_file.stem

        firm = str(data.get("recalling_firm", "") or "").strip()
        product_desc = str(data.get("product_description", "") or "").strip()
        reason = str(data.get("reason_for_recall", "") or "").strip()
        classification = str(data.get("classification", "") or "").strip()

        title = recall_number or event_id or "FDA Enforcement"
        if firm:
            title = f"{title}: {firm}"

        summary_parts = []
        if reason:
            summary_parts.append(reason)
        if product_desc and product_desc not in reason:
            summary_parts.append(product_desc)
        if firm and firm not in " ".join(summary_parts):
            summary_parts.append(firm)
        if classification:
            summary_parts.append(f"Class {classification}")
        summary = " | ".join(summary_parts) if summary_parts else title

        # Date: prefer report_date, fall back to recall_initiation_date
        published = str(
            data.get("report_date", "")
            or data.get("recall_initiation_date", "")
            or data.get("center_classification_date", "")
            or ""
        ).strip()

        # Link to openFDA query
        link = ""
        if recall_number:
            link = f'https://api.fda.gov/device/enforcement.json?search=recall_number:"{recall_number}"'
        elif event_id:
            link = f'https://api.fda.gov/device/enforcement.json?search=event_id:"{event_id}"'

        signals.append({
            "source": source_id,
            "guid": guid,
            "title": title,
            "link": link,
            "published_date": published,
            "summary": summary,
            "fetched_at": fetched_at,
        })

    return signals


def incremental_update(
    *,
    cache_dir: Optional[Path] = None,
    out_root: str = "outputs/discover",
    source_id: str = "fda-safety-comms-historical",
    days_back: int = 30,
    max_results: Optional[int] = None,
    signal_limit: Optional[int] = None,
    _fetch_fn: Optional[Callable[[str], bytes]] = None,
) -> Dict[str, Any]:
    """Incremental update: fetch recent enforcement records and publish.

    Queries openFDA with report_date range for records from the last N days.
    Uses 30 days by default (enforcement records can lag).

    Args:
        cache_dir: Cache directory.
        out_root: Discover output root.
        source_id: Source ID for discover output.
        days_back: Days back to check.
        max_results: Cap on fetched records.
        signal_limit: Cap on published signals.
        _fetch_fn: Injectable fetch function for testing.

    Returns:
        Stats dict.
    """
    from .discover_sync import publish_to_discover

    if cache_dir is None:
        cache_dir = _DEFAULT_CACHE_DIR
    cache_dir.mkdir(parents=True, exist_ok=True)

    rate_limiter = _get_rate_limiter()

    now = datetime.now(timezone.utc)
    start_date = now - __import__("datetime").timedelta(days=days_back)
    date_fmt = "%Y%m%d"

    search = (
        f"report_date:[{start_date.strftime(date_fmt)}+TO+{now.strftime(date_fmt)}]"
    )

    stats: Dict[str, Any] = {
        "status": "running",
        "started_at": now.isoformat(),
        "incremental_range": f"{start_date.strftime(date_fmt)} to {now.strftime(date_fmt)}",
        "new_records_fetched": 0,
        "new_records_cached": 0,
        "errors": [],
    }

    skip = 0
    total_results = None

    while True:
        if max_results is not None and stats["new_records_fetched"] >= max_results:
            break
        if total_results is not None and skip >= total_results:
            break
        if skip > 25000:
            break

        try:
            data, status_code = _fetch_page(
                skip, _PAGE_SIZE,
                search=search,
                rate_limiter=rate_limiter,
                _fetch_fn=_fetch_fn,
            )
        except Exception as exc:
            stats["errors"].append({"skip": skip, "error": str(exc)})
            break

        if status_code == 429:
            time.sleep(30)
            continue

        if total_results is None:
            meta = data.get("meta") or {}
            total_obj = meta.get("results") or {}
            total_results = total_obj.get("total", 0)

        results = data.get("results") or []
        if not results:
            break

        for record in results:
            if not isinstance(record, dict):
                continue
            stats["new_records_fetched"] += 1
            cache_id = _record_cache_id(record)
            if cache_id:
                cache_file = cache_dir / f"enf_{cache_id}.json"
                if not cache_file.exists():
                    _save_record_cache(record, cache_dir)
                    stats["new_records_cached"] += 1

        skip += _PAGE_SIZE

    # Publish all cyber-relevant cached signals
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

    logger.info(
        "FDA enforcement incremental: %d records fetched, %d cached. "
        "Published %d signals (%d new) to %s.",
        stats["new_records_fetched"], stats["new_records_cached"],
        publish_stats["total_signals"], publish_stats["new_signals"],
        publish_stats["out_dir"],
    )

    return stats
