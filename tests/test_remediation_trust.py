"""Tests for remediation trust and attribution features.

Covers:
  - Playbook pattern basis field (PART 1)
  - Recommendation rationale (PART 2)
  - generated_by attribution (PART 3)
  - feedback.py round-trip (PART 4)
  - Recommendation disclaimer (PART 5)
  - Dashboard feedback button (PART 6)
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from advisoryops.playbook import load_playbook, Playbook, MitigationPattern
from advisoryops.recommend import (
    PatternRecommendation,
    RemediationPacket,
    RECOMMENDATION_DISCLAIMER,
    _parse_ai_response,
    recommend_mitigations,
)
from advisoryops.packet_export import export_json, export_markdown, export_csv_tasks
from advisoryops.feedback import record_feedback, load_feedback, FEEDBACK_TYPES
from advisoryops.community_build import _feed_entry, _DASHBOARD_HTML


# ── fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def playbook() -> Playbook:
    return load_playbook()


def _rce_issue() -> dict:
    return {
        "issue_id": "CVE-2024-1234",
        "title": "Remote Code Execution in Philips IntelliSpace Cardiovascular",
        "summary": (
            "A critical vulnerability allows unauthenticated remote code execution. "
            "No patch available. Vendor recommends network segmentation."
        ),
        "sources": ["cisa-icsma"],
        "score": 95,
        "priority": "P0",
        "cves": ["CVE-2024-1234"],
        "links": ["https://www.cisa.gov/ics/advisories/icsma-24-001"],
    }


def _make_call_fn(selected_patterns, reasoning="Test reasoning."):
    result = {"selected_patterns": selected_patterns, "reasoning": reasoning}
    return MagicMock(return_value={"result": result, "model": "gpt-4o-mini", "tokens_used": 55})


def _make_packet(playbook_inst=None):
    pb = playbook_inst or load_playbook()
    seg = pb.get("SEGMENTATION_VLAN_ISOLATION")
    patterns = [
        PatternRecommendation(
            pattern_id="SEGMENTATION_VLAN_ISOLATION",
            why_selected="Device is network-accessible with no patch available.",
            parameters={"current_vlan_subnet": "10.0.1.0/24"},
            priority_order=1,
            rationale="Selected because: advisory states unauthenticated RCE with no patch; device is network-reachable per CISA ICS-Medical source; segmentation reduces lateral movement risk.",
            basis=seg.basis if seg else "",
        ),
    ]
    tasks_by_role: dict = {}
    for rec in patterns:
        p = pb.get(rec.pattern_id)
        if p:
            for step in p.steps:
                tasks_by_role.setdefault(step.role, []).append(
                    f"[{p.name}] {step.action}: {step.details}"
                )
    return RemediationPacket(
        issue_id="CVE-2024-1234",
        recommended_patterns=patterns,
        tasks_by_role=tasks_by_role,
        reasoning="Primary control: network isolation due to unpatched RCE.",
        citations=["https://www.cisa.gov/ics/advisories/icsma-24-001"],
        model="gpt-4o-mini",
        tokens_used=280,
        from_cache=False,
    )


# ══════════════════════════════════════════════════════════════════════════════
# PART 1: Every playbook pattern has a non-empty basis field
# ══════════════════════════════════════════════════════════════════════════════

class TestPlaybookBasis:
    def test_every_pattern_has_basis(self, playbook: Playbook):
        for p in playbook.patterns:
            assert p.basis, f"Pattern {p.id} is missing a basis field"

    def test_basis_is_string(self, playbook: Playbook):
        for p in playbook.patterns:
            assert isinstance(p.basis, str)

    def test_basis_references_real_standards(self, playbook: Playbook):
        """At least some patterns cite recognized standards."""
        all_bases = " ".join(p.basis for p in playbook.patterns)
        assert "NIST" in all_bases or "IEC" in all_bases or "FDA" in all_bases

    def test_segmentation_cites_iec_62443(self, playbook: Playbook):
        seg = playbook.get("SEGMENTATION_VLAN_ISOLATION")
        assert seg is not None
        assert "IEC 62443" in seg.basis

    def test_patching_cites_fda(self, playbook: Playbook):
        pat = playbook.get("PATCHING_APPLY_VENDOR_OR_CUSTOMER")
        assert pat is not None
        assert "FDA" in pat.basis


# ══════════════════════════════════════════════════════════════════════════════
# PART 2: Rationale is populated on recommendation output
# ══════════════════════════════════════════════════════════════════════════════

class TestRationale:
    def test_rationale_field_on_recommendation(self):
        rec = PatternRecommendation(
            pattern_id="SEGMENTATION_VLAN_ISOLATION",
            why_selected="test",
            parameters={},
            priority_order=1,
            rationale="Selected because: RCE with no patch, network-reachable device.",
        )
        assert "Selected because" in rec.rationale

    def test_parse_extracts_rationale(self, playbook: Playbook):
        raw = {
            "selected_patterns": [{
                "pattern_id": "SEGMENTATION_VLAN_ISOLATION",
                "why_selected": "ok",
                "rationale": "Selected because: no patch, network-reachable, CISA source confirms critical severity.",
                "parameters": {},
                "priority_order": 1,
            }],
            "reasoning": "test",
        }
        recs, _, _, _ = _parse_ai_response(raw, playbook, _rce_issue())
        assert len(recs) == 1
        assert "no patch" in recs[0].rationale

    def test_rationale_defaults_to_empty(self, playbook: Playbook):
        raw = {
            "selected_patterns": [{
                "pattern_id": "SEGMENTATION_VLAN_ISOLATION",
                "why_selected": "ok",
                "parameters": {},
                "priority_order": 1,
            }],
            "reasoning": "",
        }
        recs, _, _, _ = _parse_ai_response(raw, playbook, _rce_issue())
        assert recs[0].rationale == ""

    def test_basis_populated_from_playbook(self, playbook: Playbook):
        raw = {
            "selected_patterns": [{
                "pattern_id": "SEGMENTATION_VLAN_ISOLATION",
                "why_selected": "ok",
                "parameters": {},
                "priority_order": 1,
            }],
            "reasoning": "",
        }
        recs, _, _, _ = _parse_ai_response(raw, playbook, _rce_issue())
        assert "IEC 62443" in recs[0].basis

    def test_recommend_mitigations_has_rationale(self, playbook: Playbook, tmp_path: Path):
        call_fn = _make_call_fn([{
            "pattern_id": "SEGMENTATION_VLAN_ISOLATION",
            "why_selected": "ok",
            "rationale": "Selected because: critical RCE, no patch available.",
            "parameters": {},
            "priority_order": 1,
        }])
        packet = recommend_mitigations(_rce_issue(), playbook, cache_root=tmp_path, _call_fn=call_fn)
        assert "critical RCE" in packet.recommended_patterns[0].rationale


# ══════════════════════════════════════════════════════════════════════════════
# PART 3: generated_by field present on AI outputs
# ══════════════════════════════════════════════════════════════════════════════

class TestGeneratedBy:
    def test_remediation_packet_default_generated_by(self):
        packet = RemediationPacket(
            issue_id="test",
            recommended_patterns=[],
            tasks_by_role={},
            reasoning="",
            citations=[],
        )
        assert packet.generated_by == "ai"

    def test_feed_entry_includes_generated_by(self):
        issue = {"issue_id": "CVE-2024-0001", "generated_by": "hybrid"}
        entry = _feed_entry(issue)
        assert entry["generated_by"] == "hybrid"

    def test_feed_entry_defaults_to_deterministic(self):
        issue = {"issue_id": "CVE-2024-0001"}
        entry = _feed_entry(issue)
        assert entry["generated_by"] == "deterministic"

    def test_json_export_includes_generated_by(self, tmp_path: Path):
        packet = _make_packet()
        out = tmp_path / "p.json"
        export_json(packet, out)
        doc = json.loads(out.read_text())
        assert doc["generated_by"] == "ai"


# ══════════════════════════════════════════════════════════════════════════════
# PART 4: feedback.py record and load round-trip
# ══════════════════════════════════════════════════════════════════════════════

class TestFeedback:
    def test_record_and_load(self, tmp_path: Path):
        fb_path = tmp_path / "feedback.jsonl"
        record_feedback("CVE-2024-1234", "SEGMENTATION_VLAN_ISOLATION", "incorrect",
                        comment="Doesn't apply to our firmware", path=fb_path)
        entries = load_feedback(path=fb_path)
        assert len(entries) == 1
        assert entries[0]["issue_id"] == "CVE-2024-1234"
        assert entries[0]["feedback_type"] == "incorrect"
        assert "firmware" in entries[0]["comment"]

    def test_filter_by_issue_id(self, tmp_path: Path):
        fb_path = tmp_path / "feedback.jsonl"
        record_feedback("CVE-2024-1111", "PAT_A", "helpful", path=fb_path)
        record_feedback("CVE-2024-2222", "PAT_B", "incorrect", path=fb_path)
        entries = load_feedback(issue_id="CVE-2024-1111", path=fb_path)
        assert len(entries) == 1
        assert entries[0]["issue_id"] == "CVE-2024-1111"

    def test_invalid_feedback_type(self, tmp_path: Path):
        fb_path = tmp_path / "feedback.jsonl"
        with pytest.raises(ValueError, match="Invalid feedback_type"):
            record_feedback("CVE-2024-1234", "PAT_A", "invalid_type", path=fb_path)

    def test_all_feedback_types_accepted(self, tmp_path: Path):
        fb_path = tmp_path / "feedback.jsonl"
        for ft in FEEDBACK_TYPES:
            record_feedback("CVE-2024-0001", "PAT_A", ft, path=fb_path)
        entries = load_feedback(path=fb_path)
        assert len(entries) == len(FEEDBACK_TYPES)

    def test_load_missing_file(self, tmp_path: Path):
        entries = load_feedback(path=tmp_path / "nonexistent.jsonl")
        assert entries == []

    def test_entry_has_timestamp(self, tmp_path: Path):
        fb_path = tmp_path / "feedback.jsonl"
        entry = record_feedback("CVE-2024-1234", "PAT_A", "helpful", path=fb_path)
        assert "timestamp" in entry
        assert "2026" in entry["timestamp"] or "20" in entry["timestamp"]

    def test_append_mode(self, tmp_path: Path):
        fb_path = tmp_path / "feedback.jsonl"
        record_feedback("CVE-2024-1111", "PAT_A", "helpful", path=fb_path)
        record_feedback("CVE-2024-2222", "PAT_B", "incorrect", path=fb_path)
        entries = load_feedback(path=fb_path)
        assert len(entries) == 2


# ══════════════════════════════════════════════════════════════════════════════
# PART 5: Disclaimer present in packet export output
# ══════════════════════════════════════════════════════════════════════════════

class TestDisclaimer:
    def test_disclaimer_constant(self):
        assert "Verify against vendor documentation" in RECOMMENDATION_DISCLAIMER

    def test_packet_has_disclaimer(self):
        packet = _make_packet()
        assert "Verify against vendor documentation" in packet.disclaimer

    def test_json_export_has_disclaimer(self, tmp_path: Path):
        out = tmp_path / "p.json"
        export_json(_make_packet(), out)
        doc = json.loads(out.read_text())
        assert "disclaimer" in doc
        assert "Verify against vendor documentation" in doc["disclaimer"]

    def test_markdown_export_has_disclaimer(self, tmp_path: Path):
        pb = load_playbook()
        out = tmp_path / "p.md"
        export_markdown(_make_packet(pb), pb, out)
        content = out.read_text()
        assert "Disclaimer" in content
        assert "Verify against vendor documentation" in content

    def test_json_export_has_rationale_and_basis(self, tmp_path: Path):
        out = tmp_path / "p.json"
        export_json(_make_packet(), out)
        doc = json.loads(out.read_text())
        pat = doc["recommended_patterns"][0]
        assert "rationale" in pat
        assert "basis" in pat
        assert "IEC 62443" in pat["basis"]


# ══════════════════════════════════════════════════════════════════════════════
# PART 6: Dashboard HTML contains feedback button class/element
# ══════════════════════════════════════════════════════════════════════════════

class TestDashboardFeedback:
    def test_feedback_btn_class_in_css(self):
        assert "feedback-btn" in _DASHBOARD_HTML

    def test_feedback_dropdown_class_in_css(self):
        assert "feedback-dropdown" in _DASHBOARD_HTML

    def test_feedback_menu_class_in_css(self):
        assert "feedback-menu" in _DASHBOARD_HTML

    def test_submit_feedback_in_js(self):
        assert "submitFeedback" in _DASHBOARD_HTML

    def test_disclaimer_bar_in_css(self):
        assert "disclaimer-bar" in _DASHBOARD_HTML

    def test_disclaimer_text_in_html(self):
        assert "Verify against vendor documentation" in _DASHBOARD_HTML

    def test_flag_this_recommendation_button(self):
        assert "Flag this recommendation" in _DASHBOARD_HTML

    def test_feedback_types_in_menu(self):
        for ft in ["incorrect", "too_aggressive", "too_conservative", "missing_context", "helpful"]:
            assert ft in _DASHBOARD_HTML
