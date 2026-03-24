"""Tests for Parts 2-4: non_applicability, side_effects, friction, action checklist."""
from dataclasses import field
from advisoryops.recommend import PatternRecommendation, RemediationPacket
from advisoryops.packet_export import export_action_checklist, export_json
from pathlib import Path
import json


def _make_rec(**overrides):
    defaults = dict(
        pattern_id="SEGMENTATION_VLAN_ISOLATION",
        why_selected="Network-accessible, no patch available",
        parameters={"device_ip": "10.0.1.50"},
        priority_order=1,
        rationale="Selected because device is network-exposed with no vendor patch",
        basis="NIST SP 800-82 Rev 3",
        side_effects=["May disrupt telemetry if wireless is used"],
        friction_level="medium",
        friction_reason="Requires network team coordination",
    )
    defaults.update(overrides)
    return PatternRecommendation(**defaults)


def _make_packet(**overrides):
    defaults = dict(
        issue_id="CVE-2025-TEST",
        recommended_patterns=[_make_rec()],
        tasks_by_role={"netops": ["Isolate device"]},
        reasoning="Device is network-exposed with active exploitation",
        citations=["https://nvd.nist.gov/vuln/detail/CVE-2025-TEST"],
        model="gpt-4o-mini",
        tokens_used=200,
        non_applicability=["Only relevant if device is internet-exposed",
                          "Does not apply to vendor-managed configurations"],
        evidence_gaps=["Exact firmware version unknown"],
        handling_warnings=["Do not reboot without vendor guidance"],
    )
    defaults.update(overrides)
    return RemediationPacket(**defaults)


class TestPatternRecommendationFields:
    def test_side_effects_default_empty(self):
        rec = PatternRecommendation(
            pattern_id="TEST", why_selected="test",
            parameters={}, priority_order=1)
        assert rec.side_effects == []
        assert rec.friction_level == ""
        assert rec.friction_reason == ""

    def test_side_effects_populated(self):
        rec = _make_rec()
        assert rec.side_effects == ["May disrupt telemetry if wireless is used"]
        assert rec.friction_level == "medium"
        assert rec.friction_reason == "Requires network team coordination"


class TestRemediationPacketFields:
    def test_non_applicability_default_empty(self):
        pkt = RemediationPacket(
            issue_id="X", recommended_patterns=[], tasks_by_role={},
            reasoning="", citations=[])
        assert pkt.non_applicability == []

    def test_non_applicability_populated(self):
        pkt = _make_packet()
        assert len(pkt.non_applicability) == 2
        assert "internet-exposed" in pkt.non_applicability[0]


class TestExportJsonNewFields:
    def test_json_includes_new_fields(self, tmp_path):
        pkt = _make_packet()
        out = export_json(pkt, tmp_path / "test_packet.json")
        data = json.loads(out.read_text(encoding="utf-8"))

        assert data["non_applicability"] == pkt.non_applicability
        assert data["handling_warnings"] == pkt.handling_warnings
        assert data["evidence_gaps"] == pkt.evidence_gaps

        rec = data["recommended_patterns"][0]
        assert rec["side_effects"] == ["May disrupt telemetry if wireless is used"]
        assert rec["friction_level"] == "medium"
        assert rec["friction_reason"] == "Requires network team coordination"


class TestActionChecklist:
    def test_basic_checklist(self):
        pkt = _make_packet()
        result = export_action_checklist(pkt)

        assert "ACTION CHECKLIST: CVE-2025-TEST" in result
        assert "IMMEDIATE SAFE ACTIONS:" in result or "ACTIONS REQUIRING BIOMED" in result
        assert "KEY ASSUMPTIONS" in result
        assert "internet-exposed" in result
        assert "KNOWN UNKNOWNS:" in result
        assert "firmware version unknown" in result
        assert "HANDLING WARNINGS:" in result
        assert "Do not reboot" in result
        assert "DISCLAIMER:" in result

    def test_checklist_empty_packet(self):
        pkt = RemediationPacket(
            issue_id="EMPTY", recommended_patterns=[], tasks_by_role={},
            reasoning="", citations=[])
        result = export_action_checklist(pkt)
        assert "ACTION CHECKLIST: EMPTY" in result
        assert "DISCLAIMER:" in result

    def test_high_friction_partitioned(self):
        rec_high = _make_rec(friction_level="high", priority_order=1)
        rec_low = _make_rec(
            pattern_id="MONITOR_LOG_REVIEW", friction_level="low",
            priority_order=2, why_selected="Low effort monitoring")
        pkt = _make_packet(recommended_patterns=[rec_high, rec_low])
        result = export_action_checklist(pkt)
        # High friction goes to biomed/vendor, low goes to immediate
        assert "IMMEDIATE SAFE ACTIONS:" in result
