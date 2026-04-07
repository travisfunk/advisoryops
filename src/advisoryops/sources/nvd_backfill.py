"""NVD historical backfill — paginated pull of all CVEs from NVD API 2.0.

Fetches the complete NVD CVE database (240,000+ records) via paginated
requests to https://services.nvd.nist.gov/rest/json/cves/2.0 and caches
each CVE as a raw JSON file in outputs/nvd_cache/.

Key features:
  - Paginated: resultsPerPage=2000, startIndex increments by 2000
  - Resumable: scans cache dir to find already-fetched CVEs, skips pages
    whose CVEs are already cached, and persists a progress file
  - Rate-limited: 50 req/30s with API key, 5 req/30s without
  - 429 backoff: exponential backoff on rate-limit responses
  - Progress tracking: writes outputs/nvd_cache/_backfill_progress.json

Usage:
    from advisoryops.sources.nvd_backfill import run_backfill

    # Test with 5,000 records
    stats = run_backfill(max_results=5000)

    # Full pull (all 240K+ CVEs)
    stats = run_backfill()
"""
from __future__ import annotations

import json
import logging
import os
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

_NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_DEFAULT_CACHE_DIR = Path("outputs/nvd_cache")
_PROGRESS_FILE = "_backfill_progress.json"
_USER_AGENT = "AdvisoryOps/1.0 (security advisory aggregator; historical backfill)"
_TIMEOUT = 30
_PAGE_SIZE = 2000
_429_MAX_RETRIES = 5


class RateLimiter:
    """Sliding-window rate limiter for NVD API calls."""

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


def _get_rate_limiter() -> RateLimiter:
    """Return a rate limiter tuned to whether an API key is available."""
    if os.environ.get("NVD_API_KEY"):
        return RateLimiter(max_requests=45, window_seconds=30)
    return RateLimiter(max_requests=4, window_seconds=30)


def _load_progress(cache_dir: Path) -> Dict[str, Any]:
    """Load backfill progress state from cache directory."""
    progress_path = cache_dir / _PROGRESS_FILE
    if progress_path.exists():
        try:
            return json.loads(progress_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            pass
    return {
        "last_start_index": 0,
        "total_results": None,
        "cves_fetched": 0,
        "pages_fetched": 0,
        "last_updated": None,
        "completed": False,
    }


def _save_progress(cache_dir: Path, progress: Dict[str, Any]) -> None:
    """Persist backfill progress state."""
    progress["last_updated"] = datetime.now(timezone.utc).isoformat()
    progress_path = cache_dir / _PROGRESS_FILE
    progress_path.write_text(
        json.dumps(progress, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def _save_cve_raw(cve_data: Dict[str, Any], cache_dir: Path) -> Optional[str]:
    """Save a single raw CVE record to cache. Returns CVE ID or None."""
    cve_obj = cve_data.get("cve") or {}
    cve_id = cve_obj.get("id", "")
    if not cve_id:
        return None

    cache_file = cache_dir / f"{cve_id}.json"
    if cache_file.exists():
        return cve_id  # Already cached

    # Extract and save the enrichment fields (same format as nvd_enrich cache)
    fields = _extract_fields_for_cache(cve_obj)
    cache_file.write_text(
        json.dumps(fields, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return cve_id


def _extract_fields_for_cache(cve_obj: Dict[str, Any]) -> Dict[str, Any]:
    """Extract NVD fields into the same format used by nvd_enrich cache.

    This ensures backfilled CVEs are immediately usable by the enrichment
    pipeline without re-fetching.
    """
    result: Dict[str, Any] = {}

    # Description — prefer English
    descriptions = cve_obj.get("descriptions") or []
    for desc in descriptions:
        if desc.get("lang", "").startswith("en"):
            result["nvd_description"] = desc.get("value", "")
            break
    if "nvd_description" not in result and descriptions:
        result["nvd_description"] = descriptions[0].get("value", "")

    # CVSS — prefer v3.1 → v3.0 → v2
    metrics = cve_obj.get("metrics") or {}
    cvss_data = None

    for key in ("cvssMetricV31", "cvssMetricV30"):
        metric_list = metrics.get(key) or []
        if metric_list:
            cvss_data = metric_list[0].get("cvssData") or {}
            break

    if cvss_data is None:
        v2_list = metrics.get("cvssMetricV2") or []
        if v2_list:
            cvss_data = v2_list[0].get("cvssData") or {}

    if cvss_data:
        result["cvss_score"] = cvss_data.get("baseScore", 0)
        result["cvss_vector"] = cvss_data.get("vectorString", "")
        severity = cvss_data.get("baseSeverity", "")
        if not severity:
            score = result["cvss_score"]
            if score >= 9.0:
                severity = "CRITICAL"
            elif score >= 7.0:
                severity = "HIGH"
            elif score >= 4.0:
                severity = "MEDIUM"
            else:
                severity = "LOW"
        result["cvss_severity"] = severity.upper()

    # CWE IDs
    cwe_ids: List[str] = []
    weaknesses = cve_obj.get("weaknesses") or []
    for w in weaknesses:
        for desc in w.get("description") or []:
            val = desc.get("value", "")
            if val.startswith("CWE-"):
                cwe_ids.append(val)
    result["cwe_ids"] = sorted(set(cwe_ids))

    # Affected products from CPE configurations
    products: List[str] = []
    seen_products: set = set()
    configurations = cve_obj.get("configurations") or []
    for config in configurations:
        for node in config.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                cpe = match.get("criteria", "")
                if cpe:
                    readable = _parse_cpe_product(cpe)
                    if readable and readable not in seen_products:
                        seen_products.add(readable)
                        products.append(readable)
    result["affected_products"] = products

    # Store published date for signal generation
    published = cve_obj.get("published", "")
    if published:
        result["published_date"] = published

    # Store references for link generation
    refs = cve_obj.get("references") or []
    ref_urls = [r.get("url", "") for r in refs if isinstance(r, dict) and r.get("url")]
    if ref_urls:
        result["references"] = ref_urls

    return result


def _parse_cpe_product(cpe_string: str) -> str:
    """Extract human-readable 'vendor product' from a CPE 2.3 URI."""
    parts = cpe_string.split(":")
    if len(parts) >= 5:
        vendor = parts[3].replace("_", " ").title()
        product = parts[4].replace("_", " ").title()
        if vendor in ("*", "-"):
            return product
        if product in ("*", "-"):
            return vendor
        return f"{vendor} {product}"
    return cpe_string


def _fetch_page(
    start_index: int,
    results_per_page: int,
    *,
    rate_limiter: RateLimiter,
    _fetch_fn: Optional[Callable[[str], bytes]] = None,
) -> Tuple[Dict[str, Any], int]:
    """Fetch a single page from the NVD CVE API.

    Returns (parsed_json, http_status_code).
    Raises RuntimeError on non-retryable errors.
    """
    url = (
        f"{_NVD_API_BASE}"
        f"?resultsPerPage={results_per_page}"
        f"&startIndex={start_index}"
    )

    if _fetch_fn is not None:
        raw = _fetch_fn(url)
        return json.loads(raw), 200

    rate_limiter.wait()

    headers = {"User-Agent": _USER_AGENT}
    api_key = os.environ.get("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key

    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data, 200
    except urllib.error.HTTPError as exc:
        if exc.code == 429:
            return {}, 429
        raise RuntimeError(
            f"NVD API error {exc.code} for startIndex={start_index}: {exc}"
        ) from exc
    except (urllib.error.URLError, json.JSONDecodeError) as exc:
        raise RuntimeError(
            f"NVD API request failed for startIndex={start_index}: {exc}"
        ) from exc


def _find_resume_index(cache_dir: Path, progress: Dict[str, Any]) -> int:
    """Determine where to resume from based on progress file and cache state."""
    last_index = progress.get("last_start_index", 0)
    if progress.get("completed"):
        return -1  # Already done
    return last_index


def run_backfill(
    *,
    cache_dir: Optional[Path] = None,
    max_results: Optional[int] = None,
    page_size: int = _PAGE_SIZE,
    _fetch_fn: Optional[Callable[[str], bytes]] = None,
) -> Dict[str, Any]:
    """Run NVD historical backfill.

    Args:
        cache_dir: Directory to cache CVE JSON files. Defaults to outputs/nvd_cache/
        max_results: Maximum number of CVEs to fetch. None = all available.
        page_size: Number of results per API page (max 2000).
        _fetch_fn: Injectable fetch function for testing. Receives URL, returns bytes.

    Returns:
        Stats dict with counts and timing info.
    """
    if cache_dir is None:
        cache_dir = _DEFAULT_CACHE_DIR
    cache_dir.mkdir(parents=True, exist_ok=True)

    rate_limiter = _get_rate_limiter()
    progress = _load_progress(cache_dir)

    start_index = _find_resume_index(cache_dir, progress)
    if start_index == -1:
        logger.info("NVD backfill already completed. Delete progress file to re-run.")
        return {
            "status": "already_completed",
            "cves_cached": progress.get("cves_fetched", 0),
        }

    stats = {
        "status": "running",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "pages_fetched": progress.get("pages_fetched", 0),
        "cves_fetched": progress.get("cves_fetched", 0),
        "cves_new": 0,
        "cves_skipped": 0,
        "total_results": progress.get("total_results"),
        "errors": [],
    }

    total_results = progress.get("total_results")
    consecutive_429s = 0

    logger.info(
        "Starting NVD backfill from startIndex=%d (max_results=%s)",
        start_index,
        max_results or "all",
    )

    while True:
        # Check termination conditions
        if max_results is not None and stats["cves_fetched"] >= max_results:
            logger.info("Reached max_results=%d, stopping.", max_results)
            break

        if total_results is not None and start_index >= total_results:
            logger.info(
                "Reached end of NVD database (%d total results).", total_results
            )
            progress["completed"] = True
            break

        # Fetch page
        try:
            data, status_code = _fetch_page(
                start_index,
                page_size,
                rate_limiter=rate_limiter,
                _fetch_fn=_fetch_fn,
            )
        except RuntimeError as exc:
            logger.error("Page fetch error at startIndex=%d: %s", start_index, exc)
            stats["errors"].append(
                {"start_index": start_index, "error": str(exc)}
            )
            break

        # Handle 429 rate limiting with backoff
        if status_code == 429:
            consecutive_429s += 1
            if consecutive_429s >= _429_MAX_RETRIES:
                logger.error(
                    "Too many consecutive 429s (%d). Stopping backfill. "
                    "Resume later — progress is saved.",
                    consecutive_429s,
                )
                stats["errors"].append(
                    {"start_index": start_index, "error": "429 rate limit exceeded"}
                )
                break
            backoff = min(30 * consecutive_429s, 120)
            logger.warning(
                "429 rate limited (attempt %d/%d). Backing off %ds.",
                consecutive_429s,
                _429_MAX_RETRIES,
                backoff,
            )
            time.sleep(backoff)
            continue  # Retry same page

        consecutive_429s = 0  # Reset on success

        # Parse response
        if total_results is None:
            total_results = data.get("totalResults", 0)
            stats["total_results"] = total_results
            progress["total_results"] = total_results
            logger.info("NVD reports %d total CVEs.", total_results)

            # Apply max_results cap
            if max_results is not None:
                effective_total = min(total_results, max_results)
                logger.info("Capped to max_results=%d", effective_total)

        vulnerabilities = data.get("vulnerabilities") or []
        if not vulnerabilities:
            logger.warning(
                "Empty page at startIndex=%d, advancing.", start_index
            )
            start_index += page_size
            continue

        # Save each CVE to cache
        page_new = 0
        page_skipped = 0
        for vuln in vulnerabilities:
            if not isinstance(vuln, dict):
                continue
            cve_obj = vuln.get("cve") or {}
            cve_id = cve_obj.get("id", "")
            if not cve_id:
                continue

            cache_file = cache_dir / f"{cve_id}.json"
            if cache_file.exists():
                page_skipped += 1
            else:
                _save_cve_raw(vuln, cache_dir)
                page_new += 1

        stats["cves_new"] += page_new
        stats["cves_skipped"] += page_skipped
        stats["cves_fetched"] += len(vulnerabilities)
        stats["pages_fetched"] += 1

        # Update progress
        start_index += page_size
        progress["last_start_index"] = start_index
        progress["cves_fetched"] = stats["cves_fetched"]
        progress["pages_fetched"] = stats["pages_fetched"]
        _save_progress(cache_dir, progress)

        logger.info(
            "Page %d: %d CVEs (%d new, %d cached). Progress: %d/%s",
            stats["pages_fetched"],
            len(vulnerabilities),
            page_new,
            page_skipped,
            stats["cves_fetched"],
            total_results or "?",
        )

    # Final save
    _save_progress(cache_dir, progress)
    stats["finished_at"] = datetime.now(timezone.utc).isoformat()
    stats["status"] = "completed" if progress.get("completed") else "paused"

    logger.info(
        "NVD backfill %s: %d CVEs fetched (%d new, %d already cached), %d pages.",
        stats["status"],
        stats["cves_fetched"],
        stats["cves_new"],
        stats["cves_skipped"],
        stats["pages_fetched"],
    )

    return stats


def generate_signals_from_cache(
    *,
    cache_dir: Optional[Path] = None,
    source_id: str = "nvd-historical",
    limit: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """Generate normalized signal dicts from cached NVD CVE files.

    Reads all CVE JSON files from the cache directory and converts them
    to the standard signal format used by the pipeline.

    Args:
        cache_dir: Cache directory. Defaults to outputs/nvd_cache/
        source_id: Source ID to tag signals with.
        limit: Maximum number of signals to generate.

    Returns:
        List of normalized signal dicts.
    """
    if cache_dir is None:
        cache_dir = _DEFAULT_CACHE_DIR

    if not cache_dir.exists():
        return []

    fetched_at = datetime.now(timezone.utc).isoformat()
    signals: List[Dict[str, Any]] = []

    for cache_file in sorted(cache_dir.glob("CVE-*.json")):
        if limit is not None and len(signals) >= limit:
            break

        try:
            data = json.loads(cache_file.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue

        cve_id = cache_file.stem  # e.g. "CVE-2024-1234"
        published = data.get("published_date", "")
        description = data.get("nvd_description", "")
        refs = data.get("references") or []
        link = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        if refs:
            link = refs[0]

        signals.append({
            "source": source_id,
            "guid": cve_id,
            "title": cve_id,
            "link": link,
            "published_date": published,
            "summary": description,
            "fetched_at": fetched_at,
        })

    return signals
