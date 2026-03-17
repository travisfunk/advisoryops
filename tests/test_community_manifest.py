from pathlib import Path

from advisoryops.community_manifest import load_community_manifest


def test_load_community_manifest_default() -> None:
    manifest = load_community_manifest()
    gold = manifest.get_set("gold_pass1")

    assert manifest.schema_version == 1
    assert len(gold.source_ids) == 10
    assert "cisa-icsma" in gold.source_ids
    assert "openfda-device-recalls" in gold.source_ids
    assert manifest.candidate_sources == ["armis-labs", "health-canada-recalls"]
