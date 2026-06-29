"""Regression guard: pharmaceutical sources stay disabled.

Problem 9 (2026-04-12): MHRA UK alerts and FDA MedWatch produce pharmaceutical
recalls that collide with the FDA Class I/II/III device classification scale
and leak into the medical_device bucket. AdvisoryOps is a medical device
security platform; pharmaceutical content is out of scope (handled by
pharmacy / EMR workflows, not InfoSec / Clinical Engineering).

These sources must remain disabled in configs/sources.json and absent from
configs/community_public_sources.json validated sets. Re-enabling requires
explicit review and a scoped ingest filter to drop medicines recalls.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SOURCES_JSON = REPO_ROOT / "configs" / "sources.json"
VALIDATED_SETS_JSON = REPO_ROOT / "configs" / "community_public_sources.json"

PHARMACEUTICAL_SOURCE_IDS = frozenset({
    "fda-medwatch",
    "mhra-uk-alerts",
})


def _load_sources():
    with SOURCES_JSON.open(encoding="utf-8") as f:
        data = json.load(f)
    out = {}
    for bucket in data.values():
        if not isinstance(bucket, list):
            continue
        for entry in bucket:
            if isinstance(entry, dict) and "source_id" in entry:
                out[entry["source_id"]] = entry
    return out


def test_pharmaceutical_sources_disabled():
    sources = _load_sources()
    for src_id in PHARMACEUTICAL_SOURCE_IDS:
        assert src_id in sources, (
            f"{src_id} missing from sources.json - if intentionally removed, "
            "delete it from PHARMACEUTICAL_SOURCE_IDS too"
        )
        entry = sources[src_id]
        assert entry.get("enabled") is False, (
            f"{src_id} must stay disabled (pharmaceutical content out of scope). Got enabled="
            f"{entry.get('enabled')!r}"
        )
        assert "excluded_reason" in entry, (
            f"{src_id} is disabled but missing excluded_reason field; the "
            "rationale must be preserved inline for future maintainers"
        )


def test_pharmaceutical_sources_not_in_validated_sets():
    with VALIDATED_SETS_JSON.open(encoding="utf-8") as f:
        data = json.load(f)
    for vset in data.get("validated_sets", []):
        set_ids = set(vset.get("source_ids") or [])
        leaked = set_ids & PHARMACEUTICAL_SOURCE_IDS
        assert not leaked, (
            f"Validated set {vset.get('set_id')!r} contains pharmaceutical "
            f"sources {leaked} - remove them or add a narrower upstream filter"
        )


def test_pharmaceutical_sources_declared_excluded():
    with VALIDATED_SETS_JSON.open(encoding="utf-8") as f:
        data = json.load(f)
    excluded = {e.get("source_id") for e in data.get("excluded_sources") or []}
    missing = PHARMACEUTICAL_SOURCE_IDS - excluded
    assert not missing, (
        f"Pharmaceutical sources missing from excluded_sources list: {missing}. "
        "Add them with a rationale so the exclusion is self-documenting."
    )
