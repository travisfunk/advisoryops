"""Cross-reference enrichment orchestrator.

Applies all available enrichment sources to a list of issues:
  - EPSS scores (exploit probability)
  - CWE names (human-readable weakness descriptions)
  - CISA Vulnrichment (ADP CVSS, SSVC decision points)

Called by community_build.py after NVD enrichment.

ATT&CK ICS techniques are available via attack_ics.py for manual
lookups but not auto-applied to issues (requires keyword matching
that's better done in the scoring stage).
"""
from __future__ import annotations

import logging
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


def apply_enrichments(
    issues: List[Dict[str, Any]],
    *,
    epss: bool = True,
    cwe: bool = True,
    vulnrichment: bool = False,
    _vulnrichment_fetch_fn: Optional[Callable] = None,
) -> Dict[str, int]:
    """Apply all available cross-reference enrichments to issues.

    Args:
        issues: List of scored issue dicts (modified in-place).
        epss: Apply EPSS scores.
        cwe: Apply CWE name lookups.
        vulnrichment: Apply CISA Vulnrichment (per-CVE HTTP calls — slow).
        _vulnrichment_fetch_fn: Injectable fetch for testing.

    Returns:
        Dict with counts of how many issues each enrichment source touched.
    """
    counts: Dict[str, int] = {}

    if epss:
        try:
            from .epss_enrich import enrich_issues as epss_enrich
            n = epss_enrich(issues)
            counts["epss"] = n
            logger.info("EPSS enrichment: %d/%d issues.", n, len(issues))
        except Exception as exc:
            logger.warning("EPSS enrichment failed: %s", exc)
            counts["epss"] = 0

    if cwe:
        try:
            from .cwe_catalog import enrich_issues as cwe_enrich
            n = cwe_enrich(issues)
            counts["cwe"] = n
            logger.info("CWE enrichment: %d/%d issues.", n, len(issues))
        except Exception as exc:
            logger.warning("CWE enrichment failed: %s", exc)
            counts["cwe"] = 0

    if vulnrichment:
        try:
            from .vulnrichment import enrich_issue as vr_enrich_one
            n = 0
            for issue in issues:
                try:
                    if vr_enrich_one(issue, _fetch_fn=_vulnrichment_fetch_fn):
                        n += 1
                except Exception:
                    pass
            counts["vulnrichment"] = n
            logger.info("Vulnrichment enrichment: %d/%d issues.", n, len(issues))
        except Exception as exc:
            logger.warning("Vulnrichment enrichment failed: %s", exc)
            counts["vulnrichment"] = 0

    return counts
