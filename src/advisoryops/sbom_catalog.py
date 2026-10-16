"""Small, complete advisory identity projection for private browser SBOM checks.

No inventory ever enters this publisher. Version strings are retained as evidence,
not interpreted: the existing feed does not bind version ranges to components.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Sequence


def write_sbom_catalog(
    rows: Sequence[dict[str, Any]],
    path: Path,
    *,
    generated_at: str,
) -> dict[str, Any]:
    """Publish every tracked issue, including those without product evidence."""
    from .source_vendors import load_vendor_sources, populate_source_vendors

    rows = populate_source_vendors(rows, load_vendor_sources())
    fields = (
        "issue_id",
        "title",
        "priority",
        "cves",
        "vendor",
        "kev_vendor",
        "kev_product",
        "affected_products",
        "affected_versions",
        "canonical_link",
    )
    catalog = {
        "version": 1,
        "generated_at": generated_at,
        "total_records": len(rows),
        "records_with_products": sum(
            bool(r.get("affected_products") or r.get("kev_product")) for r in rows
        ),
        "matching_policy": "product_identity_candidates_only",
        "issues": [
            {key: row[key] for key in fields if key in row}
            for row in sorted(rows, key=lambda row: row.get("issue_id", ""))
        ],
    }
    payload = json.dumps(catalog, ensure_ascii=False, indent=2) + "\n"
    if len(payload.encode("utf-8")) > 25 * 1024 * 1024:
        raise RuntimeError("SBOM catalog exceeds 25 MiB; shard it before publishing")
    path.write_text(payload, encoding="utf-8", newline="\n")
    return catalog
