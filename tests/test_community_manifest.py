from pathlib import Path

from advisoryops.community_manifest import load_community_manifest


def test_load_community_manifest_default() -> None:
    manifest = load_community_manifest()
    gold = manifest.get_set("gold_pass1")

    assert manifest.schema_version == 1
    # 9 after 2026-04-12 Problem 9 pharmaceutical exclusion (fda-medwatch removed).
    assert len(gold.source_ids) == 9
    assert "cisa-icsma" in gold.source_ids
    assert "openfda-device-recalls" in gold.source_ids
    assert "fda-medwatch" not in gold.source_ids
    assert manifest.candidate_sources == ["vuldb-cti-api"]
