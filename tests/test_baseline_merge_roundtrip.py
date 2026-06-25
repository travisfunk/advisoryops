"""Round-trip test for the additive baseline merge logic.

Run with:
    python tests/test_baseline_merge_roundtrip.py

Or via pytest:
    pytest tests/test_baseline_merge_roundtrip.py -v

Verifies:
  1. baseline issue count == 3724
  2. merged issue count == 3725 (one new added, one duplicate merged not appended)
  3. The duplicate's first_seen_at is preserved from baseline (not overwritten)
  4. The new fake issue is present
  5. Total issues with remediation_steps populated >= 3724 (nothing blanked)
  6. Zero issues dropped (baseline_count + 1 == merged_count)
"""
import json
from pathlib import Path

try:
    import pytest
    _PYTEST = True
except ImportError:  # noqa: BLE001
    _PYTEST = False

from advisoryops.community_build import merge_baseline_feed

BASELINE_PATH = Path("docs/feed_latest.json")


if _PYTEST:
    @pytest.fixture(scope="module")
    def baseline() -> list:
        return json.loads(BASELINE_PATH.read_text(encoding="utf-8"))


def _make_fake_new_issue() -> dict:
    """A brand-new issue that does not exist in baseline."""
    return {
        "issue_id": "CVE-9999-00001",
        "issue_type": "cve",
        "title": "Fake new issue for additive-build round-trip test",
        "summary": "This issue was synthesised for the round-trip merge test only.",
        "canonical_link": "https://example.com/fake-new",
        "cves": ["CVE-9999-00001"],
        "sources": ["test-source-new"],
        "published_dates": ["2099-01-01"],
        "first_seen_at": "2099-01-01T00:00:00+00:00",
        "last_seen_at": "2099-01-01T00:00:00+00:00",
        "score": 1,
        "priority": "P3",
        "actions": ["log"],
        "why": ["test"],
        "remediation_steps": ["test step"],
        "healthcare_relevant": False,
        "is_kev_medical_device": False,
    }


def _make_duplicate_issue(baseline_item: dict) -> dict:
    """A mutated copy of an existing baseline issue — same issue_id, different metadata."""
    return {
        **baseline_item,
        # Simulate re-discovery: add a new source and new published date
        "sources": list(dict.fromkeys(
            list(baseline_item.get("sources") or []) + ["test-source-dup"]
        )),
        "published_dates": list(dict.fromkeys(
            list(baseline_item.get("published_dates") or []) + ["2099-06-23"]
        )),
        # Deliberately try to overwrite first_seen_at with a later timestamp
        "first_seen_at": "2099-06-23T12:00:00+00:00",
        # Blank out remediation_steps to test that baseline's are preserved
        "remediation_steps": [],
    }


def test_baseline_merge_roundtrip(baseline):
    baseline_count = len(baseline)
    assert baseline_count == 4279, (
        f"Expected 4279 baseline issues, got {baseline_count}. "
        "Feed may have been updated since this test was written."
    )

    # Pick the first baseline item as our "already known" duplicate target
    dup_baseline_item = baseline[0]
    dup_issue_id = dup_baseline_item["issue_id"]
    baseline_first_seen = dup_baseline_item.get("first_seen_at", "")
    baseline_remediation = dup_baseline_item.get("remediation_steps") or []

    fake_new = _make_fake_new_issue()
    fake_dup = _make_duplicate_issue(dup_baseline_item)

    # new_rows = [the duplicate, the brand-new item]
    new_rows = [fake_dup, fake_new]

    merged = merge_baseline_feed(new_rows, baseline)

    # --- 1. Baseline count ---
    print(f"\nBaseline issue count:  {baseline_count}")

    # --- 2. Merged count ---
    merged_count = len(merged)
    print(f"Merged issue count:    {merged_count}")
    assert merged_count == 4280, (
        f"Expected 4280 merged issues, got {merged_count}. "
        "The duplicate should be merged (not appended) and the new item added."
    )

    # --- 3. first_seen_at preserved from baseline ---
    merged_by_id = {r["issue_id"]: r for r in merged}
    dup_merged = merged_by_id[dup_issue_id]
    assert dup_merged["first_seen_at"] == baseline_first_seen, (
        f"first_seen_at was overwritten!\n"
        f"  baseline : {baseline_first_seen}\n"
        f"  got      : {dup_merged['first_seen_at']}"
    )
    print(f"first_seen_at preserved: {dup_merged['first_seen_at']} (baseline: {baseline_first_seen})")

    # --- 4. New fake issue is present ---
    assert fake_new["issue_id"] in merged_by_id, (
        f"New fake issue {fake_new['issue_id']} is missing from merged result."
    )
    print(f"New fake issue present: {fake_new['issue_id']}")

    # --- 5. Remediation steps not blanked ---
    # The duplicate new row had remediation_steps=[], so baseline's should be preserved
    dup_remediation_merged = dup_merged.get("remediation_steps") or []
    assert dup_remediation_merged == baseline_remediation, (
        f"Remediation steps were blanked for {dup_issue_id}!\n"
        f"  baseline : {baseline_remediation}\n"
        f"  got      : {dup_remediation_merged}"
    )

    # Count total issues with remediation_steps populated
    with_remediation = sum(1 for r in merged if r.get("remediation_steps"))
    print(f"Issues with remediation_steps: {with_remediation} (baseline had {baseline_count} max)")
    # Baseline items that had remediation are all preserved; new fake item also has one step
    baseline_with_remediation = sum(1 for r in baseline if r.get("remediation_steps"))
    assert with_remediation >= baseline_with_remediation, (
        f"Remediation coverage dropped: baseline had {baseline_with_remediation}, "
        f"merged has {with_remediation}"
    )

    # --- 6. Zero issues dropped ---
    # Every baseline issue_id must appear in merged
    baseline_ids = {r["issue_id"] for r in baseline}
    merged_ids = {r["issue_id"] for r in merged}
    dropped = baseline_ids - merged_ids
    assert not dropped, f"{len(dropped)} baseline issues were dropped: {list(dropped)[:5]}"
    print(f"Zero issues dropped (all {baseline_count} baseline IDs present in merged)")

    # --- Sources union check ---
    dup_sources_merged = set(dup_merged.get("sources") or [])
    original_sources = set(dup_baseline_item.get("sources") or [])
    assert "test-source-dup" in dup_sources_merged, (
        f"New source 'test-source-dup' not unioned into {dup_issue_id}"
    )
    assert original_sources.issubset(dup_sources_merged), (
        f"Original sources not preserved for {dup_issue_id}"
    )
    print(f"Sources unioned correctly for {dup_issue_id}: {sorted(dup_sources_merged)[:3]}...")

    print("\nAll assertions passed.")


if __name__ == "__main__":
    _baseline_data = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
    test_baseline_merge_roundtrip(_baseline_data)
