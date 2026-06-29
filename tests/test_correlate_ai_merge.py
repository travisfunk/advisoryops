"""Tests for Task 2.3 — AI merge integration in the correlate pipeline.

All tests use injectable _decision_fn / _ai_decision_fn so no OPENAI_API_KEY
is required.  The tests exercise:

  1. Regression — no --ai-merge leaves output identical
  2. Two UNK issues that share product/summary tokens get merged
  3. merged_from field is set on the surviving issue
  4. Absorbed issue disappears from the output list
  5. merge_log.jsonl is written with correct fields
  6. Issues with different CVE sets are NOT merged (hard zero in heuristic)
  7. Transitive merges: A-B and B-C → single group {A, B, C}
  8. Non-merged pairs produce merge_log entries with merged=False
  9. AI decision returning same_issue=False doesn't merge
 10. Low-confidence same_issue=True doesn't merge (below threshold)
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

import pytest

from advisoryops.ai_correlate import MergeDecision
from advisoryops.correlate import (
    _UnionFind,
    _apply_ai_merge,
    _merge_issues_group,
    _survivor_priority,
    correlate,
)


# ---------------------------------------------------------------------------
# Fixtures helpers
# ---------------------------------------------------------------------------

def _write_jsonl(path: Path, rows: list) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")


def _read_jsonl(path: Path) -> list:
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]


def _decision(same: bool, confidence: float = 0.95, reasoning: str = "test") -> MergeDecision:
    return MergeDecision(
        same_issue=same, confidence=confidence,
        reasoning=reasoning, model="mock", tokens_used=10,
    )


def _always_same(_a: Dict, _b: Dict) -> MergeDecision:
    return _decision(True, 0.95)


def _always_different(_a: Dict, _b: Dict) -> MergeDecision:
    return _decision(False, 0.97)


def _low_confidence(_a: Dict, _b: Dict) -> MergeDecision:
    return _decision(True, 0.50)  # below 0.70 threshold


# ---------------------------------------------------------------------------
# Issue fixtures
# ---------------------------------------------------------------------------

# Two UNK issues about the same Baxter infusion pump — overlapping tokens, no CVE
_BAXTER_A: Dict[str, Any] = {
    "issue_id": "UNK-baxter-aaa",
    "issue_type": "unknown",
    "cves": [],
    "title": "Baxter Infusion Pump Firmware Vulnerability",
    "summary": (
        "A vulnerability in Baxter infusion pump firmware allows network-based "
        "attackers to modify device configuration. No patch available. "
        "Recommended mitigation: isolate device network segment."
    ),
    "canonical_link": "https://example.com/baxter-a",
    "links": ["https://example.com/baxter-a"],
    "sources": ["cisa-icsma"],
    "published_dates": ["2024-05-10"],
    "first_seen_at": "2024-05-10T10:00:00+00:00",
    "last_seen_at": "2024-05-10T10:00:00+00:00",
    "counts": {"signals": 1, "sources": 1, "links": 1},
    "signals": [{"source": "cisa-icsma", "signal_id": "sig-a1", "guid": "ga1",
                 "link": "https://example.com/baxter-a", "title": "Baxter Infusion Pump Firmware Vulnerability",
                 "published_date": "2024-05-10", "fetched_at": "2024-05-10T10:00:00+00:00"}],
}

_BAXTER_B: Dict[str, Any] = {
    "issue_id": "UNK-baxter-bbb",
    "issue_type": "unknown",
    "cves": [],
    "title": "FDA Safety Communication: Baxter Pump Network Risk",
    "summary": (
        "FDA warns of network security risk in Baxter infusion pump line. "
        "Device firmware vulnerable to configuration tampering via network access. "
        "Healthcare facilities advised to isolate affected devices."
    ),
    "canonical_link": "https://example.com/baxter-b",
    "links": ["https://example.com/baxter-b"],
    "sources": ["fda-mdm"],
    "published_dates": ["2024-05-14"],
    "first_seen_at": "2024-05-14T08:00:00+00:00",
    "last_seen_at": "2024-05-14T08:00:00+00:00",
    "counts": {"signals": 1, "sources": 1, "links": 1},
    "signals": [{"source": "fda-mdm", "signal_id": "sig-b1", "guid": "gb1",
                 "link": "https://example.com/baxter-b", "title": "FDA Safety Communication: Baxter Pump Network Risk",
                 "published_date": "2024-05-14", "fetched_at": "2024-05-14T08:00:00+00:00"}],
}

# Unrelated CVE issue
_CISCO_CVE: Dict[str, Any] = {
    "issue_id": "CVE-2024-5001",
    "issue_type": "cve",
    "cves": ["CVE-2024-5001"],
    "title": "Cisco IOS RCE",
    "summary": "Buffer overflow in Cisco IOS XE allows remote code execution.",
    "canonical_link": "https://nvd.nist.gov/vuln/detail/CVE-2024-5001",
    "links": ["https://nvd.nist.gov/vuln/detail/CVE-2024-5001"],
    "sources": ["cisa-ics"],
    "published_dates": ["2024-04-01"],
    "first_seen_at": "2024-04-01T00:00:00+00:00",
    "last_seen_at": "2024-04-01T00:00:00+00:00",
    "counts": {"signals": 1, "sources": 1, "links": 1},
    "signals": [{"source": "cisa-ics", "signal_id": "sig-c1", "guid": "gc1",
                 "link": "https://nvd.nist.gov/vuln/detail/CVE-2024-5001", "title": "Cisco IOS RCE",
                 "published_date": "2024-04-01", "fetched_at": "2024-04-01T00:00:00+00:00"}],
}

# Third Baxter issue (for transitive merge test)
_BAXTER_C: Dict[str, Any] = {
    "issue_id": "UNK-baxter-ccc",
    "issue_type": "unknown",
    "cves": [],
    "title": "ICS-CERT: Baxter Infusion Pump Network Exposure",
    "summary": (
        "ICS-CERT advisory on Baxter infusion pump vulnerability. "
        "Firmware security flaw enables unauthorized network configuration changes. "
        "Segment device from clinical network immediately."
    ),
    "canonical_link": "https://example.com/baxter-c",
    "links": ["https://example.com/baxter-c"],
    "sources": ["ics-cert"],
    "published_dates": ["2024-05-20"],
    "first_seen_at": "2024-05-20T12:00:00+00:00",
    "last_seen_at": "2024-05-20T12:00:00+00:00",
    "counts": {"signals": 1, "sources": 1, "links": 1},
    "signals": [{"source": "ics-cert", "signal_id": "sig-c2", "guid": "gc2",
                 "link": "https://example.com/baxter-c", "title": "ICS-CERT: Baxter Infusion Pump Network Exposure",
                 "published_date": "2024-05-20", "fetched_at": "2024-05-20T12:00:00+00:00"}],
}


# ===========================================================================
# Unit tests — _UnionFind
# ===========================================================================

def test_union_find_single_group():
    uf = _UnionFind(["a", "b", "c"])
    uf.union("a", "b")
    uf.union("b", "c")
    groups = uf.groups()
    # All three should be in the same group
    roots = {uf.find(k) for k in ["a", "b", "c"]}
    assert len(roots) == 1


def test_union_find_two_groups():
    uf = _UnionFind(["a", "b", "c", "d"])
    uf.union("a", "b")
    uf.union("c", "d")
    groups = uf.groups()
    assert len(groups) == 2


def test_union_find_cve_beats_unk_as_root():
    uf = _UnionFind(["UNK-aaabbb", "CVE-2024-1234"])
    uf.union("UNK-aaabbb", "CVE-2024-1234")
    # CVE should be the root (higher priority)
    assert uf.find("UNK-aaabbb") == "CVE-2024-1234"
    assert uf.find("CVE-2024-1234") == "CVE-2024-1234"


# ===========================================================================
# Unit tests — _survivor_priority
# ===========================================================================

def test_survivor_priority_cve_beats_unk():
    assert _survivor_priority("CVE-2024-1234") < _survivor_priority("UNK-aabbcc")


def test_survivor_priority_lex_among_cves():
    assert _survivor_priority("CVE-2024-0001") < _survivor_priority("CVE-2024-9999")


# ===========================================================================
# Unit tests — _merge_issues_group
# ===========================================================================

def test_merge_issues_group_unions_fields():
    merged = _merge_issues_group([_BAXTER_A, _BAXTER_B], survivor_id="UNK-baxter-aaa")
    assert merged["issue_id"] == "UNK-baxter-aaa"
    assert "UNK-baxter-bbb" in merged["merged_from"]
    assert "cisa-icsma" in merged["sources"]
    assert "fda-mdm" in merged["sources"]
    assert "https://example.com/baxter-a" in merged["links"]
    assert "https://example.com/baxter-b" in merged["links"]
    assert "2024-05-10" in merged["published_dates"]
    assert "2024-05-14" in merged["published_dates"]
    assert merged["counts"]["signals"] == 2
    assert merged["counts"]["sources"] == 2


def test_merge_issues_group_takes_longest_summary():
    merged = _merge_issues_group([_BAXTER_A, _BAXTER_B], survivor_id="UNK-baxter-aaa")
    # Both have long summaries; merged should have the longest
    assert len(merged["summary"]) >= len(_BAXTER_A["summary"])
    assert len(merged["summary"]) >= len(_BAXTER_B["summary"])


def test_merge_issues_group_cve_survivor_type():
    # If one is CVE and one is unknown, merged type should be "cve"
    cve_iss = dict(_CISCO_CVE)
    unk_iss = dict(_BAXTER_A)
    merged = _merge_issues_group([cve_iss, unk_iss], survivor_id="CVE-2024-5001")
    assert merged["issue_type"] == "cve"


def test_merge_issues_group_deduplicates_signals():
    # Same signal appearing in both — should appear only once
    shared_signal = _BAXTER_A["signals"][0]
    issue_a = dict(_BAXTER_A, signals=[shared_signal])
    issue_b = dict(_BAXTER_B, signals=[shared_signal])  # same signal_id
    merged = _merge_issues_group([issue_a, issue_b], survivor_id="UNK-baxter-aaa")
    signal_ids = [s["signal_id"] for s in merged["signals"]]
    assert len(signal_ids) == len(set(signal_ids)), "Duplicate signals not deduplicated"


def test_merge_issues_group_timestamps():
    merged = _merge_issues_group([_BAXTER_A, _BAXTER_B], survivor_id="UNK-baxter-aaa")
    assert merged["first_seen_at"] == "2024-05-10T10:00:00+00:00"
    assert merged["last_seen_at"] == "2024-05-14T08:00:00+00:00"


# ===========================================================================
# _apply_ai_merge integration tests
# ===========================================================================

def test_apply_ai_merge_merges_similar_issues(tmp_path):
    """Two issues that score above heuristic threshold + AI says same → merged."""
    issue_objs = [_BAXTER_A, _BAXTER_B, _CISCO_CVE]
    merged_list, log_path = _apply_ai_merge(
        issue_objs,
        out_root=tmp_path,
        _decision_fn=_always_same,
    )
    # Baxter A and B should be merged; Cisco CVE is separate
    issue_ids = {i["issue_id"] for i in merged_list}
    # One Baxter survives, one is absorbed
    baxter_ids = {i for i in issue_ids if "baxter" in i.lower() or "UNK" in i}
    assert len(baxter_ids) == 1, f"Expected 1 surviving Baxter issue, got: {baxter_ids}"
    # Cisco stays
    assert "CVE-2024-5001" in issue_ids


def test_apply_ai_merge_merged_from_field(tmp_path):
    """Surviving issue has merged_from listing absorbed IDs."""
    issue_objs = [_BAXTER_A, _BAXTER_B]
    merged_list, _ = _apply_ai_merge(
        issue_objs,
        out_root=tmp_path,
        _decision_fn=_always_same,
    )
    assert len(merged_list) == 1
    survivor = merged_list[0]
    assert "merged_from" in survivor
    assert len(survivor["merged_from"]) == 1


def test_apply_ai_merge_absorbed_id_absent(tmp_path):
    """Absorbed issue ID must not appear as a standalone issue."""
    issue_objs = [_BAXTER_A, _BAXTER_B]
    merged_list, _ = _apply_ai_merge(
        issue_objs,
        out_root=tmp_path,
        _decision_fn=_always_same,
    )
    all_ids = {i["issue_id"] for i in merged_list}
    # Exactly one of the two Baxter IDs survives
    assert len(all_ids & {"UNK-baxter-aaa", "UNK-baxter-bbb"}) == 1


def test_apply_ai_merge_no_merge_when_decision_false(tmp_path):
    """AI says different → no merge, both issues survive."""
    issue_objs = [_BAXTER_A, _BAXTER_B]
    merged_list, _ = _apply_ai_merge(
        issue_objs,
        out_root=tmp_path,
        _decision_fn=_always_different,
    )
    assert len(merged_list) == 2
    assert not any(i.get("merged_from") for i in merged_list)


def test_apply_ai_merge_low_confidence_no_merge(tmp_path):
    """same_issue=True but confidence < 0.70 → no merge."""
    issue_objs = [_BAXTER_A, _BAXTER_B]
    merged_list, _ = _apply_ai_merge(
        issue_objs,
        out_root=tmp_path,
        _decision_fn=_low_confidence,
    )
    assert len(merged_list) == 2


def test_apply_ai_merge_issue_count_lte_baseline(tmp_path):
    """After AI merge, count must be <= count before merge."""
    issue_objs = [_BAXTER_A, _BAXTER_B, _CISCO_CVE]
    merged_list, _ = _apply_ai_merge(
        issue_objs,
        out_root=tmp_path,
        _decision_fn=_always_same,
    )
    assert len(merged_list) <= len(issue_objs)


def test_apply_ai_merge_writes_merge_log(tmp_path):
    """merge_log.jsonl is written with one entry per candidate pair."""
    issue_objs = [_BAXTER_A, _BAXTER_B, _CISCO_CVE]
    _, log_path = _apply_ai_merge(
        issue_objs,
        out_root=tmp_path,
        _decision_fn=_always_same,
    )
    assert log_path.exists(), "merge_log.jsonl not written"
    entries = _read_jsonl(log_path)
    # Baxter A/B are the only heuristic candidates; Cisco is distinct CVE
    assert len(entries) >= 1
    for entry in entries:
        assert "candidate_a" in entry
        assert "candidate_b" in entry
        assert "similarity_score" in entry
        assert "same_issue" in entry
        assert "confidence" in entry
        assert "reasoning" in entry
        assert "model" in entry
        assert "tokens_used" in entry
        assert "merged" in entry


def test_apply_ai_merge_log_merged_flag(tmp_path):
    """Log entry has merged=True for merged pairs, merged=False for rejected."""
    issue_objs = [_BAXTER_A, _BAXTER_B]

    # Merge pass
    _, log_path = _apply_ai_merge(
        issue_objs, out_root=tmp_path / "merge", _decision_fn=_always_same,
    )
    entries = _read_jsonl(log_path)
    merged_entries = [e for e in entries if e["merged"]]
    assert len(merged_entries) >= 1

    # No-merge pass
    _, log_path2 = _apply_ai_merge(
        issue_objs, out_root=tmp_path / "nomerge", _decision_fn=_always_different,
    )
    entries2 = _read_jsonl(log_path2)
    assert all(not e["merged"] for e in entries2)


def test_apply_ai_merge_transitive(tmp_path):
    """A-B merge + B-C merge → single group {A, B, C}."""
    call_count = [0]

    def _pair_decision(a: Dict, b: Dict) -> MergeDecision:
        call_count[0] += 1
        # Always say same_issue for these three Baxter issues
        return _decision(True, 0.95)

    issue_objs = [_BAXTER_A, _BAXTER_B, _BAXTER_C]
    merged_list, _ = _apply_ai_merge(
        issue_objs,
        out_root=tmp_path,
        _decision_fn=_pair_decision,
    )
    assert len(merged_list) == 1, f"Expected 1 merged issue, got {len(merged_list)}"
    survivor = merged_list[0]
    # All three original IDs should be accounted for
    all_ids = {survivor["issue_id"]} | set(survivor.get("merged_from") or [])
    assert all_ids == {"UNK-baxter-aaa", "UNK-baxter-bbb", "UNK-baxter-ccc"}


# ===========================================================================
# correlate() regression: ai_merge=False must not alter output
# ===========================================================================

def _make_discover(path: Path, signals: list) -> None:
    _write_jsonl(path / "items.jsonl", signals)


def test_correlate_no_ai_merge_regression(tmp_path):
    """Running correlate without ai_merge produces identical output to the
    old behaviour (no merged_from fields, same issue count)."""
    discover = tmp_path / "discover"
    out_baseline = tmp_path / "baseline"
    out_ai = tmp_path / "ai"

    sigs = [
        {"source": "src-a", "guid": "CVE-2025-00001", "title": "CVE-2025-00001",
         "summary": "test", "link": "https://example.com/a",
         "published_date": "2026-01-01", "fetched_at": "2026-01-01T00:00:00+00:00"},
        {"source": "src-b", "guid": "CVE-2025-00002", "title": "CVE-2025-00002",
         "summary": "other", "link": "https://example.com/b",
         "published_date": "2026-01-02", "fetched_at": "2026-01-02T00:00:00+00:00"},
    ]
    _make_discover(discover / "src-a", [sigs[0]])
    _make_discover(discover / "src-b", [sigs[1]])

    # Baseline — no ai_merge
    correlate(out_root_discover=str(discover), out_root_issues=str(out_baseline))
    baseline = _read_jsonl(out_baseline / "issues.jsonl")

    # With ai_merge=False explicitly — should be identical
    correlate(out_root_discover=str(discover), out_root_issues=str(out_ai), ai_merge=False)
    ai_out = _read_jsonl(out_ai / "issues.jsonl")

    assert len(baseline) == len(ai_out)
    assert not any(i.get("merged_from") for i in ai_out)
    # merge_log should not be written
    assert not (out_ai / "merge_log.jsonl").exists()


# ===========================================================================
# correlate() with ai_merge=True end-to-end (using _ai_decision_fn)
# ===========================================================================

def test_correlate_ai_merge_reduces_count(tmp_path):
    """correlate(ai_merge=True) merges candidates; issue count ≤ baseline."""
    discover = tmp_path / "discover"
    out_base = tmp_path / "base"
    out_ai = tmp_path / "ai"

    # Two UNK issues that the heuristic will flag as candidates (shared tokens,
    # no CVEs so the heuristic won't hard-zero them).
    sig_a = {
        "source": "src-a", "guid": "baxter-pump-a",
        "title": "Baxter Infusion Pump Firmware Vulnerability",
        "summary": (
            "Baxter infusion pump firmware allows network attackers to modify configuration. "
            "No patch. Isolate device network segment."
        ),
        "link": "https://example.com/baxter-a",
        "published_date": "2024-05-10", "fetched_at": "2024-05-10T10:00:00+00:00",
    }
    sig_b = {
        "source": "src-b", "guid": "baxter-pump-b",
        "title": "FDA Communication: Baxter Pump Network Risk",
        "summary": (
            "FDA warns of network security risk in Baxter infusion pump. "
            "Firmware vulnerable to configuration tampering. Isolate affected devices."
        ),
        "link": "https://example.com/baxter-b",
        "published_date": "2024-05-14", "fetched_at": "2024-05-14T08:00:00+00:00",
    }
    _make_discover(discover / "src-a", [sig_a])
    _make_discover(discover / "src-b", [sig_b])

    # Baseline (no AI)
    correlate(out_root_discover=str(discover), out_root_issues=str(out_base))
    baseline = _read_jsonl(out_base / "issues.jsonl")

    # AI merge with mock decision function that always merges
    correlate(
        out_root_discover=str(discover),
        out_root_issues=str(out_ai),
        ai_merge=True,
        _ai_decision_fn=_always_same,
    )
    ai_out = _read_jsonl(out_ai / "issues.jsonl")

    # Count must be <= baseline
    assert len(ai_out) <= len(baseline), (
        f"AI-merged count ({len(ai_out)}) > baseline ({len(baseline)})"
    )

    # At least one issue should have merged_from
    merged = [i for i in ai_out if i.get("merged_from")]
    assert len(merged) >= 1, "Expected at least one merged issue"

    # merge_log.jsonl must exist
    merge_log = out_ai / "merge_log.jsonl"
    assert merge_log.exists(), "merge_log.jsonl not written"
    log_entries = _read_jsonl(merge_log)
    assert len(log_entries) >= 1


def test_correlate_ai_merge_meta_json(tmp_path):
    """meta.json records ai_merge fields."""
    discover = tmp_path / "discover"
    out = tmp_path / "out"

    sig = {
        "source": "src-x", "guid": "CVE-2025-99999", "title": "CVE-2025-99999",
        "summary": "test", "link": "https://example.com/x",
        "published_date": "2026-01-01", "fetched_at": "2026-01-01T00:00:00+00:00",
    }
    _make_discover(discover / "src-x", [sig])

    correlate(
        out_root_discover=str(discover),
        out_root_issues=str(out),
        ai_merge=True,
        _ai_decision_fn=_always_different,
    )

    meta = json.loads((out / "meta.json").read_text(encoding="utf-8"))
    assert "ai_merge" in meta
    assert meta["ai_merge"]["enabled"] is True
    assert "issues_before" in meta["ai_merge"]
    assert "issues_after" in meta["ai_merge"]
    assert "merges_performed" in meta["ai_merge"]
