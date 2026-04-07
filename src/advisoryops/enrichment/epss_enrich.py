"""EPSS (Exploit Prediction Scoring System) enrichment.

Fetches exploit probability scores from https://api.first.org/data/v1/epss
and applies them to issues. Scores range from 0.0 to 1.0.

Cache: outputs/epss_cache/epss_scores.json (daily refresh)
"""
from __future__ import annotations

import json
import logging
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

_API_BASE = "https://api.first.org/data/v1/epss"
_DEFAULT_CACHE_DIR = Path("outputs/epss_cache")
_CACHE_FILE = "epss_scores.json"
_USER_AGENT = "AdvisoryOps/1.0 (security advisory aggregator; EPSS enrichment)"
_TIMEOUT = 60
_PAGE_SIZE = 100000  # EPSS supports large pages


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


def fetch_all_scores(
    *,
    _fetch_fn: Optional[Callable[[str], bytes]] = None,
) -> Dict[str, Dict[str, Any]]:
    """Fetch all EPSS scores and return as {cve_id: {epss, percentile, date}}."""
    scores: Dict[str, Dict[str, Any]] = {}
    offset = 0

    while True:
        url = f"{_API_BASE}?envelope=true&limit={_PAGE_SIZE}&offset={offset}"
        raw = _http_get(url, _fetch_fn=_fetch_fn)
        data = json.loads(raw.decode("utf-8"))

        records = data.get("data") or []
        if not records:
            break

        for rec in records:
            cve = str(rec.get("cve", "") or "").strip()
            if cve:
                scores[cve] = {
                    "epss": float(rec.get("epss", 0)),
                    "percentile": float(rec.get("percentile", 0)),
                    "date": str(rec.get("date", "") or ""),
                }

        total = data.get("total", 0)
        offset += len(records)
        if offset >= total:
            break

    return scores


def populate_cache(
    *,
    cache_dir: Optional[Path] = None,
    _fetch_fn: Optional[Callable[[str], bytes]] = None,
) -> Dict[str, Any]:
    """Download all EPSS scores and save to cache."""
    if cache_dir is None:
        cache_dir = _DEFAULT_CACHE_DIR
    cache_dir.mkdir(parents=True, exist_ok=True)

    scores = fetch_all_scores(_fetch_fn=_fetch_fn)

    cache_data = {
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "total_scores": len(scores),
        "scores": scores,
    }
    (cache_dir / _CACHE_FILE).write_text(
        json.dumps(cache_data, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    logger.info("EPSS cache populated: %d scores.", len(scores))
    return {"status": "completed", "total_scores": len(scores)}


def load_cache(
    *,
    cache_dir: Optional[Path] = None,
) -> Dict[str, Dict[str, Any]]:
    """Load EPSS scores from cache. Returns {cve_id: {epss, percentile}}."""
    if cache_dir is None:
        cache_dir = _DEFAULT_CACHE_DIR
    cache_file = cache_dir / _CACHE_FILE
    if not cache_file.exists():
        return {}
    try:
        data = json.loads(cache_file.read_text(encoding="utf-8"))
        return data.get("scores") or {}
    except (json.JSONDecodeError, OSError):
        return {}


def enrich_issue(
    issue: Dict[str, Any],
    scores: Dict[str, Dict[str, Any]],
) -> bool:
    """Add EPSS score to an issue. Returns True if enriched."""
    cves = issue.get("cves") or []
    issue_id = issue.get("issue_id", "")

    # Try issue_id first, then iterate CVEs
    candidates = []
    if issue_id and issue_id.startswith("CVE-"):
        candidates.append(issue_id)
    candidates.extend(c for c in cves if c != issue_id)

    for cve in candidates:
        epss = scores.get(cve)
        if epss:
            issue["epss_score"] = epss["epss"]
            issue["epss_percentile"] = epss["percentile"]
            return True

    return False


def enrich_issues(
    issues: List[Dict[str, Any]],
    *,
    cache_dir: Optional[Path] = None,
) -> int:
    """Enrich a list of issues with EPSS scores. Returns count enriched."""
    scores = load_cache(cache_dir=cache_dir)
    if not scores:
        logger.warning("EPSS cache is empty. Run populate_cache() first.")
        return 0

    enriched = 0
    for issue in issues:
        if enrich_issue(issue, scores):
            enriched += 1

    return enriched
