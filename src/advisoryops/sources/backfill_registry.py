"""Backfill module registry — auto-discovers and runs incremental updates.

Each backfill module registers itself here. The ``run_all_incremental()``
function is called by ``community_build.py`` before the discover/correlate
stages to ensure backfill sources have fresh data in the discover output
directories.

To add a new backfill module (e.g., Phase 1C openFDA):
    1. Implement ``incremental_update(**kwargs) -> Dict`` in your module
    2. Add an entry to ``BACKFILL_MODULES`` below

Each entry is a tuple of:
    (source_id, callable, description)

The callable must accept these keyword arguments:
    out_root: str       — discover output root
    _fetch_fn: Optional — injectable fetch function (for testing)
"""
from __future__ import annotations

import logging
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

logger = logging.getLogger(__name__)

# Type alias for a backfill incremental_update function
BackfillFn = Callable[..., Dict[str, Any]]

# Registry: (source_id, import_path, description)
# Using import paths (lazy) so we don't import all modules at registration time.
_REGISTRY: List[Tuple[str, str, str]] = [
    (
        "nvd-historical",
        "advisoryops.sources.nvd_backfill:incremental_update",
        "NVD CVE database (recent modifications)",
    ),
    (
        "cisa-icsma-historical",
        "advisoryops.sources.cisa_icsma_backfill:incremental_update",
        "CISA ICS Medical Advisories",
    ),
    (
        "openfda-recalls-historical",
        "advisoryops.sources.openfda_backfill:incremental_update",
        "openFDA device recalls",
    ),
]


def _resolve_fn(import_path: str) -> BackfillFn:
    """Resolve 'module.path:function_name' to a callable."""
    module_path, fn_name = import_path.rsplit(":", 1)
    import importlib
    mod = importlib.import_module(module_path)
    return getattr(mod, fn_name)


def get_registered_modules() -> List[Tuple[str, str, str]]:
    """Return the list of registered backfill modules.

    Each entry is (source_id, import_path, description).
    """
    return list(_REGISTRY)


def run_all_incremental(
    *,
    out_root: str = "outputs/discover",
    skip_sources: Optional[Sequence[str]] = None,
    _fetch_fns: Optional[Dict[str, Callable]] = None,
) -> Dict[str, Any]:
    """Run incremental_update() for all registered backfill modules.

    Errors in individual modules are caught and logged — a single module
    failure does not abort the pipeline.

    Args:
        out_root: Discover output root directory.
        skip_sources: Source IDs to skip (e.g., for testing).
        _fetch_fns: Dict of source_id → mock fetch function (for testing).

    Returns:
        Summary dict with per-module results.
    """
    skip = set(skip_sources or [])
    results: Dict[str, Any] = {
        "modules_run": 0,
        "modules_skipped": 0,
        "modules_failed": 0,
        "details": {},
    }

    for source_id, import_path, description in _REGISTRY:
        if source_id in skip:
            logger.info("Skipping backfill: %s (skip list)", source_id)
            results["modules_skipped"] += 1
            results["details"][source_id] = {"status": "skipped"}
            continue

        logger.info("Running backfill incremental update: %s (%s)", source_id, description)
        try:
            fn = _resolve_fn(import_path)
            kwargs: Dict[str, Any] = {"out_root": out_root}
            if _fetch_fns and source_id in _fetch_fns:
                kwargs["_fetch_fn"] = _fetch_fns[source_id]
            stats = fn(**kwargs)
            results["modules_run"] += 1
            results["details"][source_id] = stats
            logger.info(
                "Backfill %s completed: %s",
                source_id,
                stats.get("status", "unknown"),
            )
        except Exception as exc:
            results["modules_failed"] += 1
            results["details"][source_id] = {
                "status": "error",
                "error": str(exc),
            }
            logger.warning(
                "Backfill %s failed (continuing with pipeline): %s",
                source_id,
                exc,
            )

    return results
