"""openFDA device recalls historical backfill.

Pulls the full openFDA device recall database (~60,000+ records) via paginated
requests to https://api.fda.gov/device/recall.json and caches each recall
locally. Only cybersecurity-relevant recalls generate pipeline signals.

Key features:
  - Paginated: limit=100, skip=0,100,200...
  - Resumable: progress file tracks last skip offset
  - Caches ALL recalls (for re-filtering later)
  - Generates signals only for cybersecurity-relevant recalls
  - Rate limiting: 240 req/min (no key), more with API key
  - Incremental: query by date_received for recent recalls

Usage:
    from advisoryops.sources.openfda_backfill import run_backfill, incremental_update

    stats = run_backfill(max_results=1000)  # Test sample
    stats = run_backfill()                   # Full 60K+ pull
    stats = incremental_update()             # Recent recalls + publish
"""
from __future__ import annotations

import http.client
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

_API_BASE = "https://api.fda.gov/device/recall.json"
_DEFAULT_CACHE_DIR = Path("outputs/openfda_cache")
_PROGRESS_FILE = "_backfill_progress.json"
_USER_AGENT = "AdvisoryOps/1.0 (security advisory aggregator; openFDA backfill)"
_TIMEOUT = 30
_PAGE_SIZE = 100  # openFDA max per request

# Cybersecurity relevance keywords (matched case-insensitive against
# reason_for_recall, product_description, root_cause_description).
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
    """4 req/s by default (240/min), conservative to stay under limits."""
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
        "recalls_fetched": 0,
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


def is_cyber_relevant(recall: Dict[str, Any]) -> bool:
    """Check if a recall record is cybersecurity-relevant."""
    text = " ".join([
        str(recall.get("reason_for_recall", "") or ""),
        str(recall.get("product_description", "") or ""),
        str(recall.get("root_cause_description", "") or ""),
        str(recall.get("code_info", "") or ""),
    ])
    return bool(_CYBER_RE.search(text))


def _recall_cache_id(recall: Dict[str, Any]) -> Optional[str]:
    """Generate a stable cache filename from a recall record."""
    # Prefer res_event_number, then recall_number, then event_id
    for key in ("res_event_number", "recall_number", "event_id"):
        val = str(recall.get(key, "") or "").strip()
        if val:
            # Sanitize for filesystem
            return re.sub(r"[^a-zA-Z0-9_\-.]", "_", val)
    return None


def _save_recall_cache(
    recall: Dict[str, Any],
    cache_dir: Path,
) -> Optional[str]:
    """Save a recall record to cache. Returns cache ID or None."""
    cache_id = _recall_cache_id(recall)
    if not cache_id:
        return None
    cache_file = cache_dir / f"recall_{cache_id}.json"
    if cache_file.exists():
        return cache_id
    # Store raw recall + computed cyber relevance flag
    record = dict(recall)
    record["_cyber_relevant"] = is_cyber_relevant(recall)
    cache_file.write_text(
        json.dumps(record, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return cache_id


def _load_recall_cache(
    cache_id: str,
    cache_dir: Path,
) -> Optional[Dict[str, Any]]:
    cache_file = cache_dir / f"recall_{cache_id}.json"
    if cache_file.exists():
        try:
            return json.loads(cache_file.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None
    return None


def _fetch_page(
    skip: int,
    limit: int,
    *,
    search: str = "",
    rate_limiter: _RateLimiter,
    _fetch_fn: Optional[Callable[[str], bytes]] = None,
) -> Tuple[Dict[str, Any], int]:
    """Fetch a page from the openFDA device recall API.

    Returns (parsed_json, http_status_code).
    """
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
        if exc.code in (429, 500, 502, 503):
            return {}, exc.code
        if exc.code == 404:
            # openFDA returns 404 when skip exceeds total
            return {"results": []}, 404
        raise RuntimeError(
            f"openFDA API error {exc.code} at skip={skip}: {exc}"
        ) from exc
    except (
        http.client.IncompleteRead,
        http.client.RemoteDisconnected,
        ConnectionResetError,
        ConnectionError,
        TimeoutError,
        urllib.error.URLError,
    ) as exc:
        logger.debug("Transient error at skip=%d: %s", skip, exc)
        return {}, 503
    except json.JSONDecodeError as exc:
        logger.debug("JSON decode error at skip=%d: %s", skip, exc)
        return {}, 503


def run_backfill(
    *,
    cache_dir: Optional[Path] = None,
    max_results: Optional[int] = None,
    page_size: int = _PAGE_SIZE,
    _fetch_fn: Optional[Callable[[str], bytes]] = None,
) -> Dict[str, Any]:
    """Run openFDA device recalls historical backfill.

    Args:
        cache_dir: Cache directory. Defaults to outputs/openfda_cache/
        max_results: Maximum recalls to fetch. None = all.
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
        logger.info("openFDA backfill already completed.")
        return {
            "status": "already_completed",
            "recalls_fetched": progress.get("recalls_fetched", 0),
        }

    skip = progress.get("last_skip", 0)
    total_results = progress.get("total_results")

    stats: Dict[str, Any] = {
        "status": "running",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "pages_fetched": progress.get("pages_fetched", 0),
        "recalls_fetched": progress.get("recalls_fetched", 0),
        "recalls_new": 0,
        "recalls_skipped": 0,
        "cyber_relevant": 0,
        "total_results": total_results,
        "errors": [],
    }

    consecutive_429s = 0
    max_429_retries = 5

    logger.info(
        "Starting openFDA backfill from skip=%d (max_results=%s)",
        skip, max_results or "all",
    )

    try:
        while True:
            if max_results is not None and stats["recalls_fetched"] >= max_results:
                logger.info("Reached max_results=%d, stopping.", max_results)
                break

            if total_results is not None and skip >= total_results:
                logger.info("Reached end of openFDA database (%d total).", total_results)
                progress["completed"] = True
                break

            # openFDA caps skip at 25000 — need to use date-based search for beyond
            if skip > 25000 and not progress.get("completed"):
                logger.info(
                    "Reached openFDA skip limit (25000). Mark completed for basic backfill. "
                    "Use date-range queries for deeper history."
                )
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

            if status_code in (429, 500, 502, 503):
                consecutive_429s += 1
                if consecutive_429s >= max_429_retries:
                    logger.error(
                        "Too many retryable errors (%d). Stopping. Progress is saved.",
                        status_code,
                    )
                    stats["errors"].append({"skip": skip, "error": f"{status_code} after {max_429_retries} retries"})
                    break
                backoff = min(30 * consecutive_429s, 120)
                logger.warning(
                    "HTTP %d at skip=%d (attempt %d/%d). Backing off %ds.",
                    status_code, skip, consecutive_429s, max_429_retries, backoff,
                )
                time.sleep(backoff)
                continue

            consecutive_429s = 0

            if total_results is None:
                meta = data.get("meta") or {}
                total_obj = meta.get("results") or {}
                total_results = total_obj.get("total", 0)
                stats["total_results"] = total_results
                progress["total_results"] = total_results
                logger.info("openFDA reports %d total device recalls.", total_results)

            results = data.get("results") or []
            if not results:
                logger.info("Empty page at skip=%d, done.", skip)
                progress["completed"] = True
                break

            page_new = 0
            page_skipped = 0
            page_cyber = 0
            for recall in results:
                if not isinstance(recall, dict):
                    continue
                cache_id = _recall_cache_id(recall)
                if not cache_id:
                    continue
                cache_file = cache_dir / f"recall_{cache_id}.json"
                if cache_file.exists():
                    page_skipped += 1
                else:
                    _save_recall_cache(recall, cache_dir)
                    page_new += 1
                if is_cyber_relevant(recall):
                    page_cyber += 1

            stats["recalls_new"] += page_new
            stats["recalls_skipped"] += page_skipped
            stats["cyber_relevant"] += page_cyber
            stats["recalls_fetched"] += len(results)
            stats["pages_fetched"] += 1

            skip += page_size
            progress["last_skip"] = skip
            progress["recalls_fetched"] = stats["recalls_fetched"]
            progress["pages_fetched"] = stats["pages_fetched"]
            _save_progress(cache_dir, progress)

            logger.info(
                "Page %d: %d recalls (%d new, %d cached, %d cyber). Progress: %d/%s",
                stats["pages_fetched"], len(results),
                page_new, page_skipped, page_cyber,
                stats["recalls_fetched"], total_results or "?",
            )

    except Exception as exc:
        logger.error("Unexpected error in openFDA backfill: %s", exc)
        stats["errors"].append({"error": f"unhandled: {exc}"})
        stats["status"] = "error"

    _save_progress(cache_dir, progress)
    stats["finished_at"] = datetime.now(timezone.utc).isoformat()
    if stats["status"] != "error":
        stats["status"] = "completed" if progress.get("completed") else "paused"

    logger.info(
        "openFDA backfill %s: %d recalls (%d new, %d cached, %d cyber-relevant).",
        stats["status"], stats["recalls_fetched"],
        stats["recalls_new"], stats["recalls_skipped"], stats["cyber_relevant"],
    )

    return stats


def generate_signals_from_cache(
    *,
    cache_dir: Optional[Path] = None,
    source_id: str = "openfda-recalls-historical",
    limit: Optional[int] = None,
    cyber_only: bool = True,
) -> List[Dict[str, Any]]:
    """Generate normalized signal dicts from cached recall files.

    Args:
        cache_dir: Cache directory.
        source_id: Source ID for signals.
        limit: Max signals to generate.
        cyber_only: If True (default), only emit signals for cyber-relevant recalls.

    Returns:
        List of normalized signal dicts.
    """
    if cache_dir is None:
        cache_dir = _DEFAULT_CACHE_DIR
    if not cache_dir.exists():
        return []

    fetched_at = datetime.now(timezone.utc).isoformat()
    signals: List[Dict[str, Any]] = []

    for cache_file in sorted(cache_dir.glob("recall_*.json")):
        if limit is not None and len(signals) >= limit:
            break

        try:
            data = json.loads(cache_file.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue

        if cyber_only and not data.get("_cyber_relevant", False):
            continue

        # Build signal
        recall_number = str(data.get("recall_number", "") or data.get("res_event_number", "") or "").strip()
        event_id = str(data.get("event_id", "") or "").strip()
        guid = recall_number or event_id or cache_file.stem

        firm = str(data.get("recalling_firm", "") or "").strip()
        product_desc = str(data.get("product_description", "") or "").strip()
        reason = str(data.get("reason_for_recall", "") or "").strip()

        title = recall_number or event_id or "FDA Device Recall"
        if firm:
            title = f"{title}: {firm}"

        summary_parts = []
        if reason:
            summary_parts.append(reason)
        if product_desc and product_desc not in reason:
            summary_parts.append(product_desc)
        if firm and firm not in " ".join(summary_parts):
            summary_parts.append(firm)
        summary = " | ".join(summary_parts) if summary_parts else title

        # Date: prefer recall_initiation_date, fall back to event_date_terminated
        published = str(
            data.get("recall_initiation_date", "")
            or data.get("event_date_terminated", "")
            or data.get("center_classification_date", "")
            or ""
        ).strip()

        # Link
        link = ""
        res_event = str(data.get("res_event_number", "") or "").strip()
        if res_event:
            link = f'https://api.fda.gov/device/recall.json?search=res_event_number:"{res_event}"'
        elif recall_number:
            link = f'https://api.fda.gov/device/recall.json?search=recall_number:"{recall_number}"'

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
    source_id: str = "openfda-recalls-historical",
    days_back: int = 7,
    max_results: Optional[int] = None,
    signal_limit: Optional[int] = None,
    _fetch_fn: Optional[Callable[[str], bytes]] = None,
) -> Dict[str, Any]:
    """Incremental update: fetch recent recalls and publish to discover dir.

    1. Queries openFDA with date_received range for last N days.
    2. Caches new recalls.
    3. Publishes all cyber-relevant cached signals to discover output.

    Args:
        cache_dir: Cache directory.
        out_root: Discover output root.
        source_id: Source ID for discover output.
        days_back: Days back to check for new recalls.
        max_results: Cap on fetched recalls.
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
        f"date_received:[{start_date.strftime(date_fmt)}+TO+{now.strftime(date_fmt)}]"
    )

    stats: Dict[str, Any] = {
        "status": "running",
        "started_at": now.isoformat(),
        "incremental_range": f"{start_date.strftime(date_fmt)} to {now.strftime(date_fmt)}",
        "new_recalls_fetched": 0,
        "new_recalls_cached": 0,
        "errors": [],
    }

    skip = 0
    total_results = None

    while True:
        if max_results is not None and stats["new_recalls_fetched"] >= max_results:
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

        if status_code in (429, 500, 502, 503):
            time.sleep(30)
            continue

        if total_results is None:
            meta = data.get("meta") or {}
            total_obj = meta.get("results") or {}
            total_results = total_obj.get("total", 0)

        results = data.get("results") or []
        if not results:
            break

        for recall in results:
            if not isinstance(recall, dict):
                continue
            stats["new_recalls_fetched"] += 1
            cache_id = _recall_cache_id(recall)
            if cache_id:
                cache_file = cache_dir / f"recall_{cache_id}.json"
                if not cache_file.exists():
                    _save_recall_cache(recall, cache_dir)
                    stats["new_recalls_cached"] += 1

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
        "openFDA incremental: %d recalls fetched, %d cached. "
        "Published %d signals (%d new) to %s.",
        stats["new_recalls_fetched"], stats["new_recalls_cached"],
        publish_stats["total_signals"], publish_stats["new_signals"],
        publish_stats["out_dir"],
    )

    return stats
