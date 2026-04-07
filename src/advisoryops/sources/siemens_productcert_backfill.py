"""Siemens ProductCERT advisory backfill via CSAF JSON feed.

Pulls advisories from the Siemens ProductCERT CSAF TLP:WHITE feed:
  https://cert-portal.siemens.com/productcert/csaf/ssa-feed-tlp-white.json

This feed covers Siemens industrial automation products (SIMATIC, SCALANCE,
SICAM, etc.) — many of which are deployed in healthcare environments.

Note: Siemens Healthineers operates a separate advisory program with only
~4 public advisories. This module covers the much larger parent Siemens
ProductCERT catalog (200+ advisories) which is highly relevant to healthcare
infrastructure security.

Key features:
  - Single JSON feed with advisory metadata (no pagination needed)
  - Per-advisory CSAF v2.0 JSON for detailed vulnerability data
  - Caches each advisory locally
  - All advisories include CVE, CVSS, CWE, and remediation info

Usage:
    from advisoryops.sources.siemens_productcert_backfill import run_backfill, incremental_update

    stats = run_backfill()           # Fetch full feed + per-advisory CSAF
    stats = incremental_update()     # Re-check feed + publish
"""
from __future__ import annotations

import json
import logging
import re
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

_FEED_URL = "https://cert-portal.siemens.com/productcert/csaf/ssa-feed-tlp-white.json"
_CSAF_BASE = "https://cert-portal.siemens.com/productcert/csaf"

_DEFAULT_CACHE_DIR = Path("outputs/siemens_productcert_cache")
_PROGRESS_FILE = "_backfill_progress.json"
_USER_AGENT = "AdvisoryOps/1.0 (security advisory aggregator; Siemens ProductCERT backfill)"
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
        "feed_fetched": False,
        "advisories_in_feed": 0,
        "csaf_fetched": 0,
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
# Feed parsing
# ---------------------------------------------------------------------------

def parse_csaf_feed(feed_json: Dict[str, Any]) -> List[Dict[str, str]]:
    """Parse the CSAF TLP:WHITE feed index to extract advisory metadata.

    The feed is a JSON object with a list of advisory entries, each with:
      - id: SSA advisory ID (e.g., "ssa-123456")
      - title: Advisory title
      - published: Publication date
      - updated: Last update date
      - url: URL to the full CSAF JSON document

    Returns list of dicts with advisory_id, title, published, url.
    """
    entries: List[Dict[str, str]] = []

    # The CSAF feed format: list of objects with advisory metadata
    feed_list = feed_json if isinstance(feed_json, list) else feed_json.get("advisories") or feed_json.get("items") or []

    for entry in feed_list:
        if not isinstance(entry, dict):
            continue

        advisory_id = str(entry.get("id", "") or entry.get("name", "") or "").strip()
        title = str(entry.get("title", "") or entry.get("summary", "") or "").strip()
        published = str(entry.get("published", "") or entry.get("initial_release_date", "") or "").strip()
        url = str(entry.get("url", "") or entry.get("href", "") or "").strip()

        if not advisory_id:
            # Try to extract from URL
            if url:
                advisory_id = url.rsplit("/", 1)[-1].replace(".json", "")

        if advisory_id:
            entries.append({
                "advisory_id": advisory_id.upper(),
                "title": title or advisory_id,
                "published": published,
                "url": url or f"{_CSAF_BASE}/{advisory_id.lower()}.json",
            })

    return entries


def parse_csaf_advisory(csaf: Dict[str, Any]) -> Dict[str, Any]:
    """Extract structured fields from a Siemens CSAF v2.0 advisory."""
    result: Dict[str, Any] = {}

    doc = csaf.get("document") or {}
    tracking = doc.get("tracking") or {}

    result["advisory_id"] = tracking.get("id", "")
    result["title"] = doc.get("title", "")
    result["initial_release_date"] = tracking.get("initial_release_date", "")
    result["current_release_date"] = tracking.get("current_release_date", "")

    # Notes
    notes = doc.get("notes") or []
    for note in notes:
        category = (note.get("category") or "").lower()
        text = note.get("text", "")
        if "summary" in category or "general" in category:
            if "description" not in result:
                result["description"] = text

    # References
    refs = doc.get("references") or []
    result["references"] = [r.get("url", "") for r in refs if isinstance(r, dict) and r.get("url")]

    # Vulnerabilities
    vulns = csaf.get("vulnerabilities") or []
    cves: List[str] = []
    cwes: List[str] = []
    remediations: List[str] = []
    cvss_scores: List[float] = []

    for vuln in vulns:
        cve = vuln.get("cve", "")
        if cve and cve.startswith("CVE-"):
            cves.append(cve)

        cwe = vuln.get("cwe") or {}
        if cwe.get("id", "").startswith("CWE-"):
            cwes.append(cwe["id"])

        for score_entry in vuln.get("scores") or []:
            for key in ("cvss_v3", "cvss_v31"):
                cvss = score_entry.get(key) or {}
                base = cvss.get("baseScore")
                if base is not None:
                    cvss_scores.append(float(base))
                    if "cvss_vector" not in result:
                        result["cvss_vector"] = cvss.get("vectorString", "")
                        result["cvss_severity"] = cvss.get("baseSeverity", "")

        for rem in vuln.get("remediations") or []:
            detail = rem.get("details", "").strip()
            if detail and detail not in remediations:
                remediations.append(detail)

    result["cves"] = sorted(set(cves))
    result["cwes"] = sorted(set(cwes))
    result["remediations"] = remediations
    if cvss_scores:
        result["cvss_score"] = max(cvss_scores)

    # Product tree
    product_tree = csaf.get("product_tree") or {}
    products: List[str] = []
    for branch in product_tree.get("branches") or []:
        name = branch.get("name", "")
        if name:
            products.append(name)
        for sub in branch.get("branches") or []:
            sub_name = sub.get("name", "")
            if sub_name:
                products.append(sub_name)
    result["products"] = products[:20]  # Cap to avoid huge lists

    return result


def _save_advisory_cache(
    advisory_id: str,
    data: Dict[str, Any],
    cache_dir: Path,
) -> None:
    safe_id = re.sub(r"[^a-zA-Z0-9_\-]", "_", advisory_id)
    cache_file = cache_dir / f"{safe_id}.json"
    if cache_file.exists():
        return
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

def run_backfill(
    *,
    cache_dir: Optional[Path] = None,
    _fetch_fn: Optional[Callable[[str], bytes]] = None,
) -> Dict[str, Any]:
    """Run Siemens ProductCERT backfill via CSAF feed."""
    if cache_dir is None:
        cache_dir = _DEFAULT_CACHE_DIR
    cache_dir.mkdir(parents=True, exist_ok=True)

    progress = _load_progress(cache_dir)
    if progress.get("completed"):
        return {
            "status": "already_completed",
            "advisories_total": progress.get("advisories_in_feed", 0),
        }

    rate_limiter = _RateLimiter(max_requests=5, window_seconds=1.0)

    stats: Dict[str, Any] = {
        "status": "running",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "advisories_in_feed": 0,
        "csaf_fetched": 0,
        "csaf_cached": 0,
        "csaf_failed": 0,
        "errors": [],
    }

    # Fetch the feed index
    try:
        feed_bytes = _http_get(_FEED_URL, _fetch_fn=_fetch_fn)
        feed_json = json.loads(feed_bytes.decode("utf-8"))
    except Exception as exc:
        logger.error("Failed to fetch CSAF feed: %s", exc)
        stats["errors"].append({"stage": "feed_fetch", "error": str(exc)})
        stats["status"] = "error"
        return stats

    entries = parse_csaf_feed(feed_json)
    stats["advisories_in_feed"] = len(entries)
    progress["feed_fetched"] = True
    progress["advisories_in_feed"] = len(entries)

    # Fetch each advisory's CSAF JSON
    for entry in entries:
        advisory_id = entry["advisory_id"]

        if _load_advisory_cache(advisory_id, cache_dir) is not None:
            stats["csaf_cached"] += 1
            continue

        rate_limiter.wait()

        try:
            csaf_bytes = _http_get(entry["url"], _fetch_fn=_fetch_fn)
            csaf_json = json.loads(csaf_bytes.decode("utf-8"))
            parsed = parse_csaf_advisory(csaf_json)
            # Merge feed metadata with CSAF data
            merged = {**entry, **parsed}
            merged["vendor"] = "Siemens"
            _save_advisory_cache(advisory_id, merged, cache_dir)
            stats["csaf_fetched"] += 1
        except Exception as exc:
            logger.warning("Failed to fetch CSAF for %s: %s", advisory_id, exc)
            stats["csaf_failed"] += 1
            # Still cache the feed entry without CSAF enrichment
            entry["vendor"] = "Siemens"
            _save_advisory_cache(advisory_id, entry, cache_dir)

    progress["csaf_fetched"] = stats["csaf_fetched"]
    progress["completed"] = True
    _save_progress(cache_dir, progress)

    stats["finished_at"] = datetime.now(timezone.utc).isoformat()
    stats["status"] = "completed"

    logger.info(
        "Siemens ProductCERT backfill: %d in feed, %d CSAF fetched, %d cached, %d failed.",
        stats["advisories_in_feed"], stats["csaf_fetched"],
        stats["csaf_cached"], stats["csaf_failed"],
    )

    return stats


def generate_signals_from_cache(
    *,
    cache_dir: Optional[Path] = None,
    source_id: str = "siemens-productcert-psirt",
    limit: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """Generate normalized signals from cached Siemens advisories."""
    if cache_dir is None:
        cache_dir = _DEFAULT_CACHE_DIR
    if not cache_dir.exists():
        return []

    fetched_at = datetime.now(timezone.utc).isoformat()
    signals: List[Dict[str, Any]] = []

    for cache_file in sorted(cache_dir.glob("SSA-*.json")):
        if limit is not None and len(signals) >= limit:
            break

        try:
            data = json.loads(cache_file.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue

        advisory_id = data.get("advisory_id", cache_file.stem)
        title = data.get("title") or advisory_id
        link = data.get("url") or ""
        if not link and data.get("references"):
            link = data["references"][0]
        cves = data.get("cves") or []
        published = data.get("published") or data.get("initial_release_date", "")

        summary_parts = []
        if data.get("description"):
            summary_parts.append(data["description"])
        elif title:
            summary_parts.append(title)
        if cves:
            summary_parts.append(f"CVEs: {', '.join(cves[:5])}")
        summary = " | ".join(summary_parts) if summary_parts else title

        signals.append({
            "source": source_id,
            "guid": advisory_id,
            "title": title,
            "link": link,
            "published_date": published,
            "summary": summary or title,
            "fetched_at": fetched_at,
        })

    return signals


def incremental_update(
    *,
    cache_dir: Optional[Path] = None,
    out_root: str = "outputs/discover",
    source_id: str = "siemens-productcert-psirt",
    signal_limit: Optional[int] = None,
    _fetch_fn: Optional[Callable[[str], bytes]] = None,
) -> Dict[str, Any]:
    """Incremental update: re-fetch feed, cache new advisories, publish all."""
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

    # Re-fetch feed to check for new entries
    try:
        feed_bytes = _http_get(_FEED_URL, _fetch_fn=_fetch_fn)
        feed_json = json.loads(feed_bytes.decode("utf-8"))
        entries = parse_csaf_feed(feed_json)

        rate_limiter = _RateLimiter(max_requests=5, window_seconds=1.0)

        for entry in entries:
            advisory_id = entry["advisory_id"]
            if _load_advisory_cache(advisory_id, cache_dir) is not None:
                continue

            rate_limiter.wait()

            try:
                csaf_bytes = _http_get(entry["url"], _fetch_fn=_fetch_fn)
                csaf_json = json.loads(csaf_bytes.decode("utf-8"))
                parsed = parse_csaf_advisory(csaf_json)
                merged = {**entry, **parsed}
                merged["vendor"] = "Siemens"
                _save_advisory_cache(advisory_id, merged, cache_dir)
                stats["new_advisories"] += 1
            except Exception as exc:
                logger.warning("CSAF fetch failed for %s: %s", advisory_id, exc)
                entry["vendor"] = "Siemens"
                _save_advisory_cache(advisory_id, entry, cache_dir)
                stats["new_advisories"] += 1

    except Exception as exc:
        logger.warning("Failed to fetch Siemens CSAF feed: %s", exc)
        stats["errors"].append({"stage": "feed_fetch", "error": str(exc)})

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
