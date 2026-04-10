"""Feature 1 — FDA risk class extraction, lookup, and scoring tests.

Covers:
  - extract_risk_class_from_recall (top-level, nested, invalid, missing, list, int)
  - lookup_risk_class (product_code, device_name, no match)
  - _score_fda_risk_class scoring bonus (Class III +30, Class II +10, Class I +0, null +0)
  - Integration with score_issue_v2
"""
from __future__ import annotations

import json

import pytest

from advisoryops.enrichment.fda_classification import (
    extract_risk_class_from_recall,
    lookup_risk_class,
)
from advisoryops.score import score_issue_v2, _score_fda_risk_class


# ═══════════════════════════════════════════════════════════════════════════
# TestExtractRiskClassFromRecall
# ═══════════════════════════════════════════════════════════════════════════

class TestExtractRiskClassFromRecall:
    def test_extracts_top_level_device_class(self):
        recall = {"device_class": "3"}
        assert extract_risk_class_from_recall(recall) == "3"

    def test_extracts_nested_openfda_device_class(self):
        recall = {"openfda": {"device_class": "2"}}
        assert extract_risk_class_from_recall(recall) == "2"

    def test_rejects_invalid_N_value(self):
        recall = {"device_class": "N"}
        assert extract_risk_class_from_recall(recall) is None

    def test_rejects_invalid_U_value(self):
        recall = {"device_class": "U"}
        assert extract_risk_class_from_recall(recall) is None

    def test_handles_missing_field(self):
        recall = {"openfda": {}, "product_description": "Some device"}
        assert extract_risk_class_from_recall(recall) is None

    def test_handles_list_value(self):
        recall = {"openfda": {"device_class": ["3"]}}
        assert extract_risk_class_from_recall(recall) == "3"

    def test_coerces_integer_to_string(self):
        recall = {"device_class": 3}
        assert extract_risk_class_from_recall(recall) == "3"

    def test_top_level_takes_precedence_over_nested(self):
        recall = {"device_class": "1", "openfda": {"device_class": "3"}}
        assert extract_risk_class_from_recall(recall) == "1"

    def test_empty_list_returns_none(self):
        recall = {"openfda": {"device_class": []}}
        assert extract_risk_class_from_recall(recall) is None

    def test_completely_empty_recall(self):
        assert extract_risk_class_from_recall({}) is None

    def test_rejects_arbitrary_string(self):
        recall = {"device_class": "unknown"}
        assert extract_risk_class_from_recall(recall) is None


# ═══════════════════════════════════════════════════════════════════════════
# TestClassificationLookup
# ═══════════════════════════════════════════════════════════════════════════

class TestClassificationLookup:
    @pytest.fixture
    def sample_db(self):
        return {
            "_fetched_at": "2026-01-01T00:00:00+00:00",
            "LJT": {
                "device_class": "2",
                "device_name": "Port & Catheter, Implanted, Subcutaneous, Intravascular",
                "product_code": "LJT",
            },
            "DXY": {
                "device_class": "3",
                "device_name": "Pacemaker, Implantable",
                "product_code": "DXY",
            },
            "FRN": {
                "device_class": "1",
                "device_name": "Bandage, Adhesive",
                "product_code": "FRN",
            },
        }

    def test_product_code_exact_match(self, sample_db):
        assert lookup_risk_class(product_code="DXY", classifications=sample_db) == "3"

    def test_device_name_substring_match(self, sample_db):
        assert lookup_risk_class(
            device_name="Pacemaker, Implantable",
            classifications=sample_db,
        ) == "3"

    def test_returns_none_when_no_match(self, sample_db):
        assert lookup_risk_class(
            product_code="ZZZZZ",
            device_name="Quantum Flux Capacitor",
            classifications=sample_db,
        ) is None

    def test_product_code_takes_precedence_over_name(self, sample_db):
        # product_code LJT → class 2, even though name matches pacemaker (class 3)
        assert lookup_risk_class(
            product_code="LJT",
            device_name="Pacemaker, Implantable",
            classifications=sample_db,
        ) == "2"

    def test_returns_none_with_no_classifications(self):
        assert lookup_risk_class(product_code="ABC", classifications=None) is None

    def test_short_device_name_skipped(self, sample_db):
        # Very short names (<4 chars) should not match to avoid false positives
        assert lookup_risk_class(device_name="CT", classifications=sample_db) is None


# ═══════════════════════════════════════════════════════════════════════════
# TestScoreRiskClassBonus
# ═══════════════════════════════════════════════════════════════════════════

class TestScoreRiskClassBonus:
    def test_class_3_adds_30(self):
        issue = {"fda_risk_class": "3"}
        pts, why = _score_fda_risk_class(issue)
        assert pts == 30
        assert len(why) == 1
        assert "+30" in why[0]
        assert "Class III" in why[0]

    def test_class_2_adds_10(self):
        issue = {"fda_risk_class": "2"}
        pts, why = _score_fda_risk_class(issue)
        assert pts == 10
        assert "+10" in why[0]

    def test_class_1_adds_nothing(self):
        issue = {"fda_risk_class": "1"}
        pts, why = _score_fda_risk_class(issue)
        assert pts == 0
        assert why == []

    def test_null_adds_nothing(self):
        issue = {}
        pts, why = _score_fda_risk_class(issue)
        assert pts == 0
        assert why == []


# ═══════════════════════════════════════════════════════════════════════════
# Integration: score_issue_v2 includes FDA risk class bonus
# ═══════════════════════════════════════════════════════════════════════════

class TestScoreV2FdaIntegration:
    def test_class3_issue_gets_bonus_in_v2(self):
        issue = {
            "issue_id": "CVE-2024-TEST",
            "issue_type": "cve",
            "title": "Test issue",
            "summary": "Some vulnerability",
            "sources": [],
            "fda_risk_class": "3",
        }
        result = score_issue_v2(issue)
        assert any("fda-risk-class" in w for w in result.why)
        # Base CVE score (10) + FDA Class III (30) = at least 40
        assert result.score >= 40

    def test_no_fda_field_means_no_bonus(self):
        base_issue = {
            "issue_id": "CVE-2024-TEST",
            "issue_type": "cve",
            "title": "Test issue",
            "summary": "Some vulnerability",
            "sources": [],
        }
        result = score_issue_v2(base_issue)
        assert not any("fda-risk-class" in w for w in result.why)

    def test_class2_vs_class3_score_difference(self):
        base = {
            "issue_id": "CVE-2024-TEST",
            "issue_type": "cve",
            "title": "Test issue",
            "summary": "Some vulnerability",
            "sources": [],
        }
        issue_c2 = {**base, "fda_risk_class": "2"}
        issue_c3 = {**base, "fda_risk_class": "3"}
        score_c2 = score_issue_v2(issue_c2).score
        score_c3 = score_issue_v2(issue_c3).score
        assert score_c3 - score_c2 == 20  # 30 - 10 = 20 point difference


# ═══════════════════════════════════════════════════════════════════════════
# Bug 1 regression: inline score/why/priority update after enrichment
# ═══════════════════════════════════════════════════════════════════════════

class TestInlineScoreUpdate:
    """Simulate the pipeline pattern: issue is scored first (no fda_risk_class),
    then fda_risk_class is set and score/why/priority updated inline."""

    def test_inline_update_adds_why_and_score(self):
        from advisoryops.score import _priority_from_score, _actions_for_priority

        # Simulate a scored issue that had no fda_risk_class at scoring time
        issue = {
            "issue_id": "CVE-2024-TEST",
            "score": 52,
            "priority": "P3",
            "why": ["base: issue_type=cve (+10)", "keyword: RCE (+30)", "priority: P3 (score=52)"],
            "actions": ["log"],
        }

        # Set fda_risk_class and apply inline update (same as community_build does)
        issue["fda_risk_class"] = "3"
        pts, why_strs = _score_fda_risk_class(issue)
        assert pts == 30

        issue["score"] += pts
        issue["why"] = [w for w in issue["why"] if not w.startswith("priority:")]
        issue["why"].extend(why_strs)
        new_priority = _priority_from_score(issue["score"])
        issue["why"].append(f"priority: {new_priority} (score={issue['score']})")
        issue["priority"] = new_priority
        issue["actions"] = _actions_for_priority(new_priority)

        assert issue["score"] == 82
        assert issue["priority"] == "P2"  # 82 >= 60
        assert any("fda-risk-class" in w for w in issue["why"])
        assert issue["why"][-1] == "priority: P2 (score=82)"

    def test_class3_promotes_p3_to_p2(self):
        """Class III (+30) should promote a P3 issue near the threshold to P2."""
        from advisoryops.score import _priority_from_score

        # score=52 is P3 (< 60). Adding +30 = 82, which is P2.
        assert _priority_from_score(52) == "P3"
        assert _priority_from_score(52 + 30) == "P2"


# ═══════════════════════════════════════════════════════════════════════════
# Bug 2 regression: enriched signal titles from openFDA recalls
# ═══════════════════════════════════════════════════════════════════════════

class TestOpenFdaSignalEnrichment:
    """Verify that generate_signals_from_cache produces rich titles/summaries."""

    def test_signal_title_includes_device_name(self, tmp_path):
        """A recall with openfda.device_name should produce a title with that name."""
        import json

        recall = {
            "res_event_number": "30666",
            "recalling_firm": "Philips Medical Systems",
            "product_description": "HeartStart MRx Monitor/Defibrillator",
            "reason_for_recall": "Battery may fail during defibrillation.",
            "openfda": {
                "device_name": "Defibrillator, External, Automatic",
                "device_class": "3",
            },
            "_cyber_relevant": True,
        }
        cache_dir = tmp_path / "openfda_cache"
        cache_dir.mkdir()
        (cache_dir / "recall_30666.json").write_text(json.dumps(recall))

        from advisoryops.sources.openfda_backfill import generate_signals_from_cache

        signals = generate_signals_from_cache(cache_dir=cache_dir, cyber_only=True)
        assert len(signals) == 1
        sig = signals[0]

        # Title should contain the device name, not just "30666: Philips Medical Systems"
        assert "Defibrillator" in sig["title"]
        assert "Philips Medical Systems" in sig["title"]

        # Summary should contain device name, product desc, and reason
        assert "Defibrillator" in sig["summary"]
        assert "HeartStart" in sig["summary"]
        assert "Battery may fail" in sig["summary"]

    def test_signal_fallback_when_no_device_name(self, tmp_path):
        """A recall without openfda.device_name should use product_description."""
        import json

        recall = {
            "res_event_number": "25002",
            "recalling_firm": "Jostra-Bentley Corporation",
            "product_description": "Spiral Gold Hollow Fiber Oxygenator",
            "reason_for_recall": "Separation between lid and housing unit.",
            "openfda": {},
            "_cyber_relevant": True,
        }
        cache_dir = tmp_path / "openfda_cache"
        cache_dir.mkdir()
        (cache_dir / "recall_25002.json").write_text(json.dumps(recall))

        from advisoryops.sources.openfda_backfill import generate_signals_from_cache

        signals = generate_signals_from_cache(cache_dir=cache_dir, cyber_only=True)
        assert len(signals) == 1
        sig = signals[0]

        # Title should fall back to product_description
        assert "Oxygenator" in sig["title"]
        assert "Jostra-Bentley" in sig["title"]
