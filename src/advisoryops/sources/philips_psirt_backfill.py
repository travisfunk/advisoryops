"""Philips Product Security advisory backfill.

Scrapes Philips' product security advisory archive pages to build a
complete catalog of advisories (~200 total, 2017-present).

Philips publishes advisories at predictable yearly archive URLs:
  https://www.philips.com/a-w/security/security-advisories.html          (current)
  https://www.philips.com/a-w/security/security-advisories/archive-{YEAR}.html

Each page contains a list of advisories with: title, date, CVE IDs,
affected products, and severity.  No RSS/JSON/CSAF feeds exist.

Key features:
  - Discovers advisories from yearly archive pages (2017 to current year)
  - Parses advisory entries from HTML (title, date, link, summary)
  - Caches each advisory to outputs/philips_psirt_cache/
  - Resumable via progress file
  - All Philips advisories are healthcare-relevant by definition

Usage:
    from advisoryops.sources.philips_psirt_backfill import run_backfill, incremental_update

    stats = run_backfill()           # Full archive pull
    stats = incremental_update()     # Current year + publish
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
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

_BASE_URL = "https://www.philips.com/a-w/security/security-advisories"
_CURRENT_PAGE = f"{_BASE_URL}.html"
_ARCHIVE_PATTERN = f"{_BASE_URL}/archive-{{year}}.html"
# Philips also uses: /product-security-{YEAR}.html
_ALT_ARCHIVE_PATTERN = f"{_BASE_URL}/product-security-{{year}}.html"

_DEFAULT_CACHE_DIR = Path("outputs/philips_psirt_cache")
_PROGRESS_FILE = "_backfill_progress.json"
_USER_AGENT = "AdvisoryOps/1.0 (security advisory aggregator; Philips PSIRT backfill)"
_TIMEOUT = 30
_FIRST_ARCHIVE_YEAR = 2017


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
        "years_completed": [],
        "advisories_total": 0,
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


# ---------------------------------------------------------------------------
# HTML parsing — extract advisory entries from Philips pages
# ---------------------------------------------------------------------------

# Pattern to find advisory-like entries in Philips HTML
# Philips advisory pages contain titles with dates and CVE references
_DATE_RE = re.compile(r"\b(\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|\w+ \d{1,2},? \d{4}|\d{4}-\d{2}-\d{2})\b")
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")
_LINK_RE = re.compile(r'href=["\']([^"\']*(?:advisory|security|bulletin|psirt)[^"\']*)["\']', re.IGNORECASE)
_TITLE_RE = re.compile(
    r'<(?:h[1-6]|a|div|span|td|li)[^>]*>([^<]*(?:advisory|security|vulnerability|update|bulletin)[^<]*)</(?:h[1-6]|a|div|span|td|li)>',
    re.IGNORECASE,
)


def parse_advisory_page(
    html: str,
    *,
    page_url: str = "",
    year: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """Parse a Philips advisory archive page and extract advisory entries.

    Returns a list of advisory dicts with: advisory_id, title, date,
    cves, link, summary.
    """
    advisories: List[Dict[str, Any]] = []

    # Strategy: find all links that look like advisory detail pages,
    # then extract title, date, CVE from surrounding context.
    # Philips pages use <a> tags with advisory titles as link text.

    # Find all anchor tags with href and text content
    anchor_re = re.compile(
        r'<a\s[^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)</a>',
        re.IGNORECASE | re.DOTALL,
    )

    seen_links: set = set()

    for match in anchor_re.finditer(html):
        href = match.group(1).strip()
        text = re.sub(r"<[^>]+>", "", match.group(2)).strip()

        if not text or len(text) < 10:
            continue

        # Filter for advisory-like links
        href_lower = href.lower()
        text_lower = text.lower()

        is_advisory = (
            "advisory" in href_lower
            or "security" in href_lower
            or "bulletin" in href_lower
            or "psirt" in href_lower
            or "cve" in text_lower
            or "vulnerability" in text_lower
            or "advisory" in text_lower
            or "security" in text_lower
        )

        if not is_advisory:
            continue

        # Normalize the link
        if href.startswith("/"):
            href = f"https://www.philips.com{href}"
        elif not href.startswith("http"):
            continue

        if href in seen_links:
            continue
        seen_links.add(href)

        # Extract CVEs from surrounding context
        context_start = max(0, match.start() - 500)
        context_end = min(len(html), match.end() + 500)
        context = html[context_start:context_end]
        cves = sorted(set(_CVE_RE.findall(context)))

        # Extract date
        dates = _DATE_RE.findall(context)
        date_str = dates[0] if dates else (str(year) if year else "")

        # Build advisory ID from URL or title
        advisory_id = href.rsplit("/", 1)[-1].replace(".html", "").replace(".htm", "")
        if not advisory_id or advisory_id == "security-advisories":
            advisory_id = re.sub(r"[^a-zA-Z0-9_\-]", "_", text[:60])

        advisories.append({
            "advisory_id": f"PHILIPS-{advisory_id}",
            "title": text,
            "link": href,
            "date": date_str,
            "cves": cves,
            "vendor": "Philips",
            "summary": text,
        })

    return advisories


def _save_advisory_cache(
    advisory_id: str,
    data: Dict[str, Any],
    cache_dir: Path,
) -> None:
    safe_id = re.sub(r"[^a-zA-Z0-9_\-]", "_", advisory_id)
    cache_file = cache_dir / f"{safe_id}.json"
    if cache_file.exists():
        return  # Don't overwrite
    cache_file.write_text(
        json.dumps(data, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def _load_advisory_cache(
    advisory_id: str,
    cache_dir: Path,
) -> Optional[Dict[str, Any]]:
    safe_id = re.sub(r"[^a-zA-Z0-9_\-]", "_", advisory_id)
    cache_file = cache_dir / f"{safe_id}.json"
    if cache_file.exists():
        try:
            return json.loads(cache_file.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None
    return None


# ---------------------------------------------------------------------------
# Backfill
# ---------------------------------------------------------------------------

def _get_archive_urls() -> List[Dict[str, Any]]:
    """Generate the list of archive page URLs to scrape."""
    current_year = datetime.now(timezone.utc).year
    urls = [{"url": _CURRENT_PAGE, "year": current_year}]
    for year in range(current_year - 1, _FIRST_ARCHIVE_YEAR - 1, -1):
        urls.append({
            "url": _ARCHIVE_PATTERN.format(year=year),
            "year": year,
        })
        urls.append({
            "url": _ALT_ARCHIVE_PATTERN.format(year=year),
            "year": year,
        })
    return urls


def run_backfill(
    *,
    cache_dir: Optional[Path] = None,
    _fetch_fn: Optional[Callable[[str], bytes]] = None,
) -> Dict[str, Any]:
    """Run Philips PSIRT historical backfill.

    Fetches yearly archive pages and parses advisory entries.
    """
    if cache_dir is None:
        cache_dir = _DEFAULT_CACHE_DIR
    cache_dir.mkdir(parents=True, exist_ok=True)

    progress = _load_progress(cache_dir)
    if progress.get("completed"):
        return {
            "status": "already_completed",
            "advisories_total": progress.get("advisories_total", 0),
        }

    rate_limiter = _RateLimiter(max_requests=2, window_seconds=1.0)

    stats: Dict[str, Any] = {
        "status": "running",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "pages_fetched": 0,
        "pages_failed": 0,
        "advisories_found": 0,
        "advisories_new": 0,
        "errors": [],
    }

    completed_years = set(progress.get("years_completed") or [])

    for page_info in _get_archive_urls():
        page_url = page_info["url"]
        year = page_info["year"]

        if year in completed_years:
            continue

        rate_limiter.wait()

        try:
            html_bytes = _http_get(page_url, _fetch_fn=_fetch_fn)
            html = html_bytes.decode("utf-8", errors="replace")
            stats["pages_fetched"] += 1
        except Exception as exc:
            logger.debug("Failed to fetch %s: %s", page_url, exc)
            stats["pages_failed"] += 1
            stats["errors"].append({"url": page_url, "error": str(exc)})
            continue

        advisories = parse_advisory_page(html, page_url=page_url, year=year)
        stats["advisories_found"] += len(advisories)

        for adv in advisories:
            advisory_id = adv["advisory_id"]
            if _load_advisory_cache(advisory_id, cache_dir) is None:
                _save_advisory_cache(advisory_id, adv, cache_dir)
                stats["advisories_new"] += 1

        completed_years.add(year)

    progress["years_completed"] = sorted(completed_years)
    progress["advisories_total"] = stats["advisories_found"]
    progress["completed"] = True
    _save_progress(cache_dir, progress)

    stats["finished_at"] = datetime.now(timezone.utc).isoformat()
    stats["status"] = "completed"

    logger.info(
        "Philips PSIRT backfill: %d advisories from %d pages (%d new).",
        stats["advisories_found"], stats["pages_fetched"], stats["advisories_new"],
    )

    return stats


def generate_signals_from_cache(
    *,
    cache_dir: Optional[Path] = None,
    source_id: str = "philips-psirt",
    limit: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """Generate normalized signals from cached Philips advisories."""
    if cache_dir is None:
        cache_dir = _DEFAULT_CACHE_DIR
    if not cache_dir.exists():
        return []

    fetched_at = datetime.now(timezone.utc).isoformat()
    signals: List[Dict[str, Any]] = []

    for cache_file in sorted(cache_dir.glob("PHILIPS-*.json")):
        if limit is not None and len(signals) >= limit:
            break

        try:
            data = json.loads(cache_file.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue

        advisory_id = data.get("advisory_id", cache_file.stem)
        title = data.get("title") or advisory_id
        link = data.get("link", "")
        cves = data.get("cves") or []
        date_str = data.get("date", "")

        summary_parts = [data.get("summary", "")]
        if cves:
            summary_parts.append(f"CVEs: {', '.join(cves)}")
        summary = " | ".join(p for p in summary_parts if p)

        signals.append({
            "source": source_id,
            "guid": advisory_id,
            "title": title,
            "link": link,
            "published_date": date_str,
            "summary": summary or title,
            "fetched_at": fetched_at,
        })

    return signals


def incremental_update(
    *,
    cache_dir: Optional[Path] = None,
    out_root: str = "outputs/discover",
    source_id: str = "philips-psirt",
    signal_limit: Optional[int] = None,
    _fetch_fn: Optional[Callable[[str], bytes]] = None,
) -> Dict[str, Any]:
    """Incremental update: fetch current year page and publish all signals.

    Only fetches the current year's page (lightweight) to pick up new advisories,
    then publishes all cached signals to discover output.
    """
    from .discover_sync import publish_to_discover

    if cache_dir is None:
        cache_dir = _DEFAULT_CACHE_DIR
    cache_dir.mkdir(parents=True, exist_ok=True)

    stats: Dict[str, Any] = {
        "status": "running",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "new_advisories": 0,
        "errors": [],
    }

    # Fetch only current year page for incremental
    try:
        html_bytes = _http_get(_CURRENT_PAGE, _fetch_fn=_fetch_fn)
        html = html_bytes.decode("utf-8", errors="replace")

        current_year = datetime.now(timezone.utc).year
        advisories = parse_advisory_page(html, page_url=_CURRENT_PAGE, year=current_year)

        for adv in advisories:
            if _load_advisory_cache(adv["advisory_id"], cache_dir) is None:
                _save_advisory_cache(adv["advisory_id"], adv, cache_dir)
                stats["new_advisories"] += 1
    except Exception as exc:
        logger.warning("Failed to fetch Philips current advisories: %s", exc)
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
