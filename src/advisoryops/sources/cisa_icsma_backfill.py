"""CISA ICSMA historical backfill — full archive of ICS Medical Advisories.

Pulls the complete ICSMA catalog (~182 advisories, 2016–present) using two
complementary data sources:

1. **ICS Advisory Project CSV** — single HTTP GET, 17 columns per advisory,
   covers the full catalog including pre-CSAF advisories.
   URL: https://raw.githubusercontent.com/icsadvprj/ICS-Advisory-Project/main/ICS-CERT_ADV/CISA_ICS_ADV_Master.csv

2. **cisagov/CSAF GitHub repo** — per-advisory CSAF v2.0 JSON with detailed
   CVE, CVSS, CWE, vendor/product, and remediation data.
   Discovery: https://api.github.com/repos/cisagov/CSAF/git/trees/develop?recursive=1
   Files: https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/{YEAR}/{id}.json

Strategy:
  - CSV gives the complete list with basic metadata
  - CSAF JSON enriches each advisory with structured vulnerability details
  - Cache CSAF JSON locally for resumability

Usage:
    from advisoryops.sources.cisa_icsma_backfill import run_backfill

    stats = run_backfill()  # Fetches all ~182 ICSMA advisories
"""
from __future__ import annotations

import csv
import json
import logging
import re
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

_CSV_URL = (
    "https://raw.githubusercontent.com/icsadvprj/ICS-Advisory-Project"
    "/main/ICS-CERT_ADV/CISA_ICS_ADV_Master.csv"
)
_CSAF_TREE_URL = (
    "https://api.github.com/repos/cisagov/CSAF/git/trees/develop?recursive=1"
)
_CSAF_RAW_BASE = (
    "https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white"
)

_DEFAULT_CACHE_DIR = Path("outputs/cisa_icsma_cache")
_PROGRESS_FILE = "_backfill_progress.json"
_USER_AGENT = "AdvisoryOps/1.0 (security advisory aggregator; ICSMA backfill)"
_TIMEOUT = 30

# Match ICSMA advisory IDs: ICSMA-YY-DDD-NN
_ICSMA_ID_RE = re.compile(r"ICSMA-\d{2}-\d{3}-\d{2}")


class _RateLimiter:
    """Simple sliding-window rate limiter."""

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


def _load_progress(cache_dir: Path) -> Dict[str, Any]:
    """Load backfill progress state."""
    progress_path = cache_dir / _PROGRESS_FILE
    if progress_path.exists():
        try:
            return json.loads(progress_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            pass
    return {
        "csv_fetched": False,
        "csaf_files_fetched": 0,
        "csaf_files_total": 0,
        "advisories_total": 0,
        "completed": False,
        "last_updated": None,
    }


def _save_progress(cache_dir: Path, progress: Dict[str, Any]) -> None:
    """Persist backfill progress state."""
    progress["last_updated"] = datetime.now(timezone.utc).isoformat()
    progress_path = cache_dir / _PROGRESS_FILE
    progress_path.write_text(
        json.dumps(progress, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def _http_get(
    url: str,
    *,
    timeout: int = _TIMEOUT,
    _fetch_fn: Optional[Callable[[str], bytes]] = None,
) -> bytes:
    """Fetch URL content as bytes."""
    if _fetch_fn is not None:
        return _fetch_fn(url)
    headers = {"User-Agent": _USER_AGENT}
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


# ---------------------------------------------------------------------------
# Stage 1: Parse the ICS Advisory Project master CSV
# ---------------------------------------------------------------------------

def parse_icsma_csv(csv_text: str) -> List[Dict[str, Any]]:
    """Parse ICS Advisory Project CSV, returning only ICSMA rows.

    Each row becomes a dict with normalized field names.
    """
    advisories: List[Dict[str, Any]] = []
    reader = csv.DictReader(StringIO(csv_text))
    for row in reader:
        if not isinstance(row, dict):
            continue
        advisory_id = (row.get("ICS-CERT_Number") or "").strip()
        if not advisory_id.startswith("ICSMA-"):
            continue

        # Parse CVEs (comma-separated)
        cve_raw = (row.get("CVE_Number") or "").strip()
        cves = [c.strip() for c in cve_raw.split(",") if c.strip().startswith("CVE-")]

        # Parse CWEs (comma-separated)
        cwe_raw = (row.get("CWE_Number") or "").strip()
        cwes = [c.strip() for c in cwe_raw.split(",") if c.strip().startswith("CWE-")]

        # Parse CVSS
        cvss_raw = (row.get("Cumulative_CVSS") or "").strip()
        try:
            cvss_score = float(cvss_raw) if cvss_raw else None
        except ValueError:
            cvss_score = None

        advisories.append({
            "advisory_id": advisory_id,
            "title": (row.get("ICS-CERT_Advisory_Title") or "").strip(),
            "vendor": (row.get("Vendor") or "").strip(),
            "product": (row.get("Product") or "").strip(),
            "products_affected": (row.get("Products_Affected") or "").strip(),
            "original_release_date": (row.get("Original_Release_Date") or "").strip(),
            "last_updated": (row.get("Last_Updated") or "").strip(),
            "cves": cves,
            "cwes": cwes,
            "cvss_score": cvss_score,
            "cvss_severity": (row.get("CVSS_Severity") or "").strip(),
            "sector": (row.get("Critical_Infrastructure_Sector") or "").strip(),
            "distribution": (row.get("Product_Distribution") or "").strip(),
            "headquarters": (row.get("Company_Headquarters") or "").strip(),
        })

    return advisories


# ---------------------------------------------------------------------------
# Stage 2: Discover and fetch CSAF JSON files from GitHub
# ---------------------------------------------------------------------------

def discover_csaf_files(
    tree_json: Dict[str, Any],
) -> List[Dict[str, str]]:
    """Extract ICSMA CSAF file paths from the GitHub tree API response.

    Returns list of dicts with 'path' and 'url' keys.
    """
    files: List[Dict[str, str]] = []
    for item in tree_json.get("tree") or []:
        path = item.get("path", "")
        if "/icsma-" in path.lower() and path.endswith(".json"):
            # Build raw URL from path
            url = f"{_CSAF_RAW_BASE}/{'/'.join(path.split('/')[-2:])}"
            files.append({"path": path, "url": url})
    return files


def parse_csaf_advisory(csaf: Dict[str, Any]) -> Dict[str, Any]:
    """Extract structured fields from a CSAF v2.0 advisory JSON.

    Returns enrichment data that overlays on the CSV-sourced advisory.
    """
    result: Dict[str, Any] = {}

    doc = csaf.get("document") or {}
    tracking = doc.get("tracking") or {}

    result["advisory_id"] = tracking.get("id", "")
    result["title"] = doc.get("title", "")
    result["initial_release_date"] = tracking.get("initial_release_date", "")
    result["current_release_date"] = tracking.get("current_release_date", "")

    # Extract notes (risk evaluation, summary, etc.)
    notes = doc.get("notes") or []
    for note in notes:
        category = (note.get("category") or "").lower()
        text = note.get("text", "")
        if category == "summary" or category == "general":
            if "description" not in result:
                result["description"] = text
        elif "risk" in category:
            result["risk_evaluation"] = text

    # Extract references
    refs = doc.get("references") or []
    result["references"] = [
        r.get("url", "") for r in refs
        if isinstance(r, dict) and r.get("url")
    ]

    # Extract vulnerabilities
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
        cwe_id = cwe.get("id", "")
        if cwe_id.startswith("CWE-"):
            cwes.append(cwe_id)

        # CVSS scores
        for score_entry in vuln.get("scores") or []:
            cvss_v3 = score_entry.get("cvss_v3") or score_entry.get("cvss_v31") or {}
            base = cvss_v3.get("baseScore")
            if base is not None:
                cvss_scores.append(float(base))
                if "cvss_vector" not in result:
                    result["cvss_vector"] = cvss_v3.get("vectorString", "")
                    result["cvss_severity"] = cvss_v3.get("baseSeverity", "")

        # Remediations
        for rem in vuln.get("remediations") or []:
            detail = rem.get("details", "").strip()
            if detail and detail not in remediations:
                remediations.append(detail)

    result["cves"] = sorted(set(cves))
    result["cwes"] = sorted(set(cwes))
    result["remediations"] = remediations
    if cvss_scores:
        result["cvss_score"] = max(cvss_scores)

    # Extract product tree
    product_tree = csaf.get("product_tree") or {}
    vendors: List[str] = []
    products: List[str] = []
    for branch in product_tree.get("branches") or []:
        vendor_name = branch.get("name", "")
        if vendor_name:
            vendors.append(vendor_name)
        for sub in branch.get("branches") or []:
            prod_name = sub.get("name", "")
            if prod_name:
                products.append(prod_name)
    if vendors:
        result["vendor"] = vendors[0]
    if products:
        result["products"] = products

    return result


# ---------------------------------------------------------------------------
# Stage 3: Merge CSV + CSAF data and cache
# ---------------------------------------------------------------------------

def _merge_advisory(
    csv_row: Dict[str, Any],
    csaf_data: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """Merge CSV base data with optional CSAF enrichment."""
    merged = dict(csv_row)

    if csaf_data is None:
        return merged

    # CSAF overrides where it has richer data
    if csaf_data.get("description"):
        merged["description"] = csaf_data["description"]
    if csaf_data.get("risk_evaluation"):
        merged["risk_evaluation"] = csaf_data["risk_evaluation"]
    if csaf_data.get("references"):
        merged["references"] = csaf_data["references"]
    if csaf_data.get("remediations"):
        merged["remediations"] = csaf_data["remediations"]
    if csaf_data.get("cvss_vector"):
        merged["cvss_vector"] = csaf_data["cvss_vector"]
    if csaf_data.get("products"):
        merged["products_list"] = csaf_data["products"]

    # Merge CVEs (union of both sources)
    csv_cves = set(csv_row.get("cves") or [])
    csaf_cves = set(csaf_data.get("cves") or [])
    merged["cves"] = sorted(csv_cves | csaf_cves)

    # Merge CWEs
    csv_cwes = set(csv_row.get("cwes") or [])
    csaf_cwes = set(csaf_data.get("cwes") or [])
    merged["cwes"] = sorted(csv_cwes | csaf_cwes)

    # Use highest CVSS score
    csv_score = csv_row.get("cvss_score")
    csaf_score = csaf_data.get("cvss_score")
    scores = [s for s in [csv_score, csaf_score] if s is not None]
    if scores:
        merged["cvss_score"] = max(scores)

    if csaf_data.get("cvss_severity"):
        merged["cvss_severity"] = csaf_data["cvss_severity"]

    return merged


def _save_advisory_cache(
    advisory_id: str,
    data: Dict[str, Any],
    cache_dir: Path,
) -> None:
    """Save merged advisory data to cache."""
    cache_file = cache_dir / f"{advisory_id}.json"
    cache_file.write_text(
        json.dumps(data, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def _load_advisory_cache(
    advisory_id: str,
    cache_dir: Path,
) -> Optional[Dict[str, Any]]:
    """Load cached advisory data."""
    cache_file = cache_dir / f"{advisory_id}.json"
    if cache_file.exists():
        try:
            return json.loads(cache_file.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None
    return None


# ---------------------------------------------------------------------------
# Main backfill orchestrator
# ---------------------------------------------------------------------------

def run_backfill(
    *,
    cache_dir: Optional[Path] = None,
    _fetch_fn: Optional[Callable[[str], bytes]] = None,
) -> Dict[str, Any]:
    """Run CISA ICSMA historical backfill.

    Args:
        cache_dir: Directory to cache advisory JSON files.
        _fetch_fn: Injectable fetch function for testing.

    Returns:
        Stats dict with counts and timing info.
    """
    if cache_dir is None:
        cache_dir = _DEFAULT_CACHE_DIR
    cache_dir.mkdir(parents=True, exist_ok=True)

    progress = _load_progress(cache_dir)
    if progress.get("completed"):
        logger.info("ICSMA backfill already completed. Delete progress file to re-run.")
        return {
            "status": "already_completed",
            "advisories_total": progress.get("advisories_total", 0),
        }

    rate_limiter = _RateLimiter(max_requests=10, window_seconds=10)
    stats: Dict[str, Any] = {
        "status": "running",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "csv_advisories": 0,
        "csaf_enriched": 0,
        "csaf_skipped_cached": 0,
        "csaf_not_found": 0,
        "advisories_total": 0,
        "errors": [],
    }

    # Stage 1: Fetch and parse the master CSV
    logger.info("Fetching ICS Advisory Project master CSV...")
    try:
        csv_bytes = _http_get(_CSV_URL, _fetch_fn=_fetch_fn)
        csv_text = csv_bytes.decode("utf-8", errors="replace")
    except Exception as exc:
        logger.error("Failed to fetch CSV: %s", exc)
        stats["errors"].append({"stage": "csv_fetch", "error": str(exc)})
        stats["status"] = "error"
        return stats

    csv_advisories = parse_icsma_csv(csv_text)
    stats["csv_advisories"] = len(csv_advisories)
    logger.info("Parsed %d ICSMA advisories from CSV.", len(csv_advisories))

    progress["csv_fetched"] = True
    progress["advisories_total"] = len(csv_advisories)
    _save_progress(cache_dir, progress)

    # Stage 2: Discover CSAF JSON files
    logger.info("Discovering CSAF files from GitHub...")
    csaf_map: Dict[str, str] = {}  # advisory_id → URL
    try:
        tree_bytes = _http_get(_CSAF_TREE_URL, _fetch_fn=_fetch_fn)
        tree_json = json.loads(tree_bytes.decode("utf-8"))
        csaf_files = discover_csaf_files(tree_json)
        for f in csaf_files:
            # Extract advisory ID from filename: icsma-YY-DDD-NN.json → ICSMA-YY-DDD-NN
            fname = f["path"].rsplit("/", 1)[-1].replace(".json", "")
            advisory_id = fname.upper()
            csaf_map[advisory_id] = f["url"]
        logger.info("Found %d CSAF ICSMA files on GitHub.", len(csaf_map))
        progress["csaf_files_total"] = len(csaf_map)
    except Exception as exc:
        logger.warning("Failed to discover CSAF files: %s. Continuing with CSV only.", exc)
        stats["errors"].append({"stage": "csaf_discovery", "error": str(exc)})

    # Stage 3: For each CSV advisory, fetch CSAF enrichment and merge
    for adv in csv_advisories:
        advisory_id = adv["advisory_id"]

        # Check cache first
        cached = _load_advisory_cache(advisory_id, cache_dir)
        if cached is not None:
            stats["csaf_skipped_cached"] += 1
            continue

        # Try to fetch CSAF enrichment
        csaf_data = None
        csaf_url = csaf_map.get(advisory_id)
        if csaf_url:
            try:
                rate_limiter.wait()
                csaf_bytes = _http_get(csaf_url, _fetch_fn=_fetch_fn)
                csaf_json = json.loads(csaf_bytes.decode("utf-8"))
                csaf_data = parse_csaf_advisory(csaf_json)
                stats["csaf_enriched"] += 1
                progress["csaf_files_fetched"] = (
                    progress.get("csaf_files_fetched", 0) + 1
                )
            except Exception as exc:
                logger.warning(
                    "Failed to fetch CSAF for %s: %s", advisory_id, exc
                )
                stats["errors"].append({
                    "advisory_id": advisory_id,
                    "error": str(exc),
                })
        else:
            stats["csaf_not_found"] += 1

        # Merge and cache
        merged = _merge_advisory(adv, csaf_data)
        _save_advisory_cache(advisory_id, merged, cache_dir)

    # Mark complete
    stats["advisories_total"] = len(csv_advisories)
    progress["completed"] = True
    _save_progress(cache_dir, progress)

    stats["finished_at"] = datetime.now(timezone.utc).isoformat()
    stats["status"] = "completed"

    logger.info(
        "ICSMA backfill complete: %d advisories (%d CSAF-enriched, %d cached, %d CSV-only).",
        stats["advisories_total"],
        stats["csaf_enriched"],
        stats["csaf_skipped_cached"],
        stats["csaf_not_found"],
    )

    return stats


def generate_signals_from_cache(
    *,
    cache_dir: Optional[Path] = None,
    source_id: str = "cisa-icsma-historical",
    limit: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """Generate normalized signal dicts from cached ICSMA advisory files.

    Returns signals in the standard pipeline format.
    """
    if cache_dir is None:
        cache_dir = _DEFAULT_CACHE_DIR

    if not cache_dir.exists():
        return []

    fetched_at = datetime.now(timezone.utc).isoformat()
    signals: List[Dict[str, Any]] = []

    for cache_file in sorted(cache_dir.glob("ICSMA-*.json")):
        if limit is not None and len(signals) >= limit:
            break

        try:
            data = json.loads(cache_file.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue

        advisory_id = data.get("advisory_id", cache_file.stem)
        title = data.get("title") or advisory_id
        vendor = data.get("vendor", "")
        product = data.get("product", "")

        # Build summary
        parts = []
        if data.get("description"):
            parts.append(data["description"])
        elif vendor or product:
            parts.append(f"{vendor} {product}".strip())
        cves = data.get("cves") or []
        if cves:
            parts.append(f"CVEs: {', '.join(cves)}")
        summary = " | ".join(parts) if parts else title

        # Build link — CISA advisory URL pattern
        link = f"https://www.cisa.gov/news-events/ics-medical-advisories/{advisory_id.lower()}"

        published = data.get("original_release_date", "")

        signals.append({
            "source": source_id,
            "guid": advisory_id,
            "title": title,
            "link": link,
            "published_date": published,
            "summary": summary,
            "fetched_at": fetched_at,
        })

    return signals
