"""CWE (Common Weakness Enumeration) catalog enrichment.

Downloads the MITRE CWE database and provides human-readable names and
descriptions for CWE IDs that appear in NVD-enriched issues.

The canonical source is https://cwe.mitre.org/data/downloads.html
but XML ZIP parsing is heavy. Instead we maintain a lightweight JSON
lookup built from the CWE list or fetched from a structured API.

For simplicity, this module uses a static approach: parse CWE data from
the MITRE JSON-compatible endpoint or maintain a curated lookup. The
full XML can be added later if needed.

Cache: outputs/cwe_cache/cwe_catalog.json
"""
from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

_DEFAULT_CACHE_DIR = Path("outputs/cwe_cache")
_CACHE_FILE = "cwe_catalog.json"

# CWE data is available from multiple sources. The simplest for JSON:
# NIST NVD references CWEs. MITRE publishes XML.
# For initial integration, we provide a populate function that accepts
# parsed CWE data (from XML or any source) and a built-in subset of
# the most common CWEs relevant to medical device security.

# Top ~100 CWEs commonly found in medical device/healthcare CVEs
_BUILTIN_CWES: Dict[str, Dict[str, str]] = {
    "CWE-20": {"name": "Improper Input Validation", "category": "input"},
    "CWE-22": {"name": "Improper Limitation of a Pathname to a Restricted Directory", "category": "input"},
    "CWE-77": {"name": "Improper Neutralization of Special Elements used in a Command", "category": "injection"},
    "CWE-78": {"name": "Improper Neutralization of Special Elements used in an OS Command", "category": "injection"},
    "CWE-79": {"name": "Improper Neutralization of Input During Web Page Generation", "category": "injection"},
    "CWE-89": {"name": "Improper Neutralization of Special Elements used in an SQL Command", "category": "injection"},
    "CWE-94": {"name": "Improper Control of Generation of Code", "category": "injection"},
    "CWE-119": {"name": "Improper Restriction of Operations within the Bounds of a Memory Buffer", "category": "memory"},
    "CWE-120": {"name": "Buffer Copy without Checking Size of Input", "category": "memory"},
    "CWE-121": {"name": "Stack-based Buffer Overflow", "category": "memory"},
    "CWE-122": {"name": "Heap-based Buffer Overflow", "category": "memory"},
    "CWE-125": {"name": "Out-of-bounds Read", "category": "memory"},
    "CWE-190": {"name": "Integer Overflow or Wraparound", "category": "numeric"},
    "CWE-200": {"name": "Exposure of Sensitive Information to an Unauthorized Actor", "category": "info_leak"},
    "CWE-250": {"name": "Execution with Unnecessary Privileges", "category": "privilege"},
    "CWE-255": {"name": "Credentials Management Errors", "category": "auth"},
    "CWE-259": {"name": "Use of Hard-coded Password", "category": "auth"},
    "CWE-264": {"name": "Permissions, Privileges, and Access Controls", "category": "privilege"},
    "CWE-269": {"name": "Improper Privilege Management", "category": "privilege"},
    "CWE-276": {"name": "Incorrect Default Permissions", "category": "privilege"},
    "CWE-284": {"name": "Improper Access Control", "category": "privilege"},
    "CWE-287": {"name": "Improper Authentication", "category": "auth"},
    "CWE-295": {"name": "Improper Certificate Validation", "category": "crypto"},
    "CWE-306": {"name": "Missing Authentication for Critical Function", "category": "auth"},
    "CWE-307": {"name": "Improper Restriction of Excessive Authentication Attempts", "category": "auth"},
    "CWE-311": {"name": "Missing Encryption of Sensitive Data", "category": "crypto"},
    "CWE-312": {"name": "Cleartext Storage of Sensitive Information", "category": "crypto"},
    "CWE-319": {"name": "Cleartext Transmission of Sensitive Information", "category": "crypto"},
    "CWE-326": {"name": "Inadequate Encryption Strength", "category": "crypto"},
    "CWE-327": {"name": "Use of a Broken or Risky Cryptographic Algorithm", "category": "crypto"},
    "CWE-330": {"name": "Use of Insufficiently Random Values", "category": "crypto"},
    "CWE-352": {"name": "Cross-Site Request Forgery", "category": "web"},
    "CWE-362": {"name": "Concurrent Execution using Shared Resource with Improper Synchronization", "category": "concurrency"},
    "CWE-400": {"name": "Uncontrolled Resource Consumption", "category": "dos"},
    "CWE-416": {"name": "Use After Free", "category": "memory"},
    "CWE-426": {"name": "Untrusted Search Path", "category": "injection"},
    "CWE-434": {"name": "Unrestricted Upload of File with Dangerous Type", "category": "input"},
    "CWE-476": {"name": "NULL Pointer Dereference", "category": "memory"},
    "CWE-502": {"name": "Deserialization of Untrusted Data", "category": "injection"},
    "CWE-522": {"name": "Insufficiently Protected Credentials", "category": "auth"},
    "CWE-532": {"name": "Insertion of Sensitive Information into Log File", "category": "info_leak"},
    "CWE-601": {"name": "URL Redirection to Untrusted Site", "category": "web"},
    "CWE-611": {"name": "Improper Restriction of XML External Entity Reference", "category": "injection"},
    "CWE-639": {"name": "Authorization Bypass Through User-Controlled Key", "category": "auth"},
    "CWE-668": {"name": "Exposure of Resource to Wrong Sphere", "category": "info_leak"},
    "CWE-672": {"name": "Operation on a Resource after Expiration or Release", "category": "memory"},
    "CWE-693": {"name": "Protection Mechanism Failure", "category": "general"},
    "CWE-732": {"name": "Incorrect Permission Assignment for Critical Resource", "category": "privilege"},
    "CWE-755": {"name": "Improper Handling of Exceptional Conditions", "category": "error"},
    "CWE-770": {"name": "Allocation of Resources Without Limits or Throttling", "category": "dos"},
    "CWE-776": {"name": "Improper Restriction of Recursive Entity References in DTDs", "category": "injection"},
    "CWE-787": {"name": "Out-of-bounds Write", "category": "memory"},
    "CWE-798": {"name": "Use of Hard-coded Credentials", "category": "auth"},
    "CWE-862": {"name": "Missing Authorization", "category": "auth"},
    "CWE-863": {"name": "Incorrect Authorization", "category": "auth"},
    "CWE-908": {"name": "Use of Uninitialized Resource", "category": "memory"},
    "CWE-918": {"name": "Server-Side Request Forgery", "category": "web"},
    "CWE-1021": {"name": "Improper Restriction of Rendered UI Layers or Frames", "category": "web"},
    "CWE-1236": {"name": "Improper Neutralization of Formula Elements in a CSV File", "category": "injection"},
}


def populate_cache(
    *,
    cache_dir: Optional[Path] = None,
    extra_cwes: Optional[Dict[str, Dict[str, str]]] = None,
) -> Dict[str, Any]:
    """Populate the CWE catalog cache.

    Uses the built-in catalog plus any extra CWEs provided.
    For full MITRE XML parsing, pass parsed CWEs as extra_cwes.
    """
    if cache_dir is None:
        cache_dir = _DEFAULT_CACHE_DIR
    cache_dir.mkdir(parents=True, exist_ok=True)

    catalog = dict(_BUILTIN_CWES)
    if extra_cwes:
        catalog.update(extra_cwes)

    cache_data = {
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "total_cwes": len(catalog),
        "catalog": catalog,
    }
    (cache_dir / _CACHE_FILE).write_text(
        json.dumps(cache_data, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    logger.info("CWE catalog cached: %d entries.", len(catalog))
    return {"status": "completed", "total_cwes": len(catalog)}


def load_cache(
    *,
    cache_dir: Optional[Path] = None,
) -> Dict[str, Dict[str, str]]:
    """Load CWE catalog from cache. Returns {cwe_id: {name, category}}."""
    if cache_dir is None:
        cache_dir = _DEFAULT_CACHE_DIR
    cache_file = cache_dir / _CACHE_FILE
    if not cache_file.exists():
        # Fall back to built-in catalog
        return dict(_BUILTIN_CWES)
    try:
        data = json.loads(cache_file.read_text(encoding="utf-8"))
        return data.get("catalog") or dict(_BUILTIN_CWES)
    except (json.JSONDecodeError, OSError):
        return dict(_BUILTIN_CWES)


def get_cwe_name(cwe_id: str, catalog: Optional[Dict[str, Dict[str, str]]] = None) -> str:
    """Look up the human-readable name for a CWE ID."""
    if catalog is None:
        catalog = _BUILTIN_CWES
    entry = catalog.get(cwe_id, {})
    return entry.get("name", "")


def enrich_issue(
    issue: Dict[str, Any],
    catalog: Dict[str, Dict[str, str]],
) -> bool:
    """Add CWE names to an issue's cwe_ids. Returns True if enriched."""
    cwe_ids = issue.get("cwe_ids") or []
    if not cwe_ids:
        return False

    cwe_names = []
    for cwe_id in cwe_ids:
        entry = catalog.get(cwe_id, {})
        name = entry.get("name", "")
        if name:
            cwe_names.append(f"{cwe_id}: {name}")

    if cwe_names:
        issue["cwe_names"] = cwe_names
        return True
    return False


def enrich_issues(
    issues: List[Dict[str, Any]],
    *,
    cache_dir: Optional[Path] = None,
) -> int:
    """Enrich issues with CWE names. Returns count enriched."""
    catalog = load_cache(cache_dir=cache_dir)
    enriched = 0
    for issue in issues:
        if enrich_issue(issue, catalog):
            enriched += 1
    return enriched
