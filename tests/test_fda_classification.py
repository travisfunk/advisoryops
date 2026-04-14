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
    extract_product_from_summary,
    extract_risk_class_from_enforcement,
    extract_risk_class_from_recall,
    extract_vendor_from_title,
    extract_vendor_products_for_issue,
    extract_vendor_products_from_enforcement,
    lookup_class_by_recall_number,
    lookup_risk_class,
    lookup_vendor_products_by_recall_number,
)
from advisoryops.score import score_issue_v2, _score_fda_risk_class


class TestExtractRiskClassFromEnforcement:
    def test_class_iii(self):
        assert extract_risk_class_from_enforcement({"classification": "Class III"}) == "3"

    def test_class_ii(self):
        assert extract_risk_class_from_enforcement({"classification": "Class II"}) == "2"

    def test_class_i(self):
        assert extract_risk_class_from_enforcement({"classification": "Class I"}) == "1"

    def test_case_insensitive(self):
        assert extract_risk_class_from_enforcement({"classification": "class iii"}) == "3"

    def test_whitespace_tolerated(self):
        assert extract_risk_class_from_enforcement({"classification": "  Class II  "}) == "2"

    def test_missing_field(self):
        assert extract_risk_class_from_enforcement({}) is None

    def test_null_value(self):
        assert extract_risk_class_from_enforcement({"classification": None}) is None

    def test_unknown_value(self):
        assert extract_risk_class_from_enforcement({"classification": "Class IV"}) is None


class TestLookupClassByRecallNumber:
    def test_happy_path(self, tmp_path):
        (tmp_path / "enf_Z-0001-2014.json").write_text(
            json.dumps({"classification": "Class II", "recall_number": "Z-0001-2014"}),
            encoding="utf-8",
        )
        assert lookup_class_by_recall_number("Z-0001-2014", cache_dir=tmp_path) == "2"

    def test_missing_file_returns_none(self, tmp_path):
        assert lookup_class_by_recall_number("Z-9999-9999", cache_dir=tmp_path) is None

    def test_empty_recall_number_returns_none(self, tmp_path):
        assert lookup_class_by_recall_number("", cache_dir=tmp_path) is None

    def test_corrupt_json_returns_none(self, tmp_path):
        (tmp_path / "enf_Z-0002-2014.json").write_text("not json", encoding="utf-8")
        assert lookup_class_by_recall_number("Z-0002-2014", cache_dir=tmp_path) is None


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

    def test_class2_vs_class3_hit_their_respective_floors(self):
        """With the clinical-severity floor, low-base-score Class III items
        land at the P0 threshold (150) and Class II items at P1 (100).
        The additive +30/+10 contribution is dominated by the floor when
        the cyber-signal base score is low.
        """
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
        assert score_c2 == 100  # Class II floor
        assert score_c3 == 150  # Class III floor


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


# ═══════════════════════════════════════════════════════════════════════════
# Problem 3 residual — vendor + affected_products extraction (2026-04-13)
# ═══════════════════════════════════════════════════════════════════════════

class TestExtractVendorProductsFromEnforcement:
    def test_happy_path_both_fields(self):
        record = {
            "recalling_firm": "GE Healthcare Finland Oy",
            "product_description": (
                "GE Healthcare CARESCAPE Monitor B850    Product Usage:    "
                "Intended uses of CARESCAPE B850..."
            ),
        }
        vendor, products = extract_vendor_products_from_enforcement(record)
        assert vendor == "GE Healthcare Finland Oy"
        assert products == ["GE Healthcare CARESCAPE Monitor B850"]

    def test_product_description_with_sentence_split(self):
        record = {
            "recalling_firm": "St Jude Medical Inc.",
            "product_description": (
                "PM1226 ACCENT ST MRI SR RF and PM2222 ACCENT ST. These low "
                "voltage (LV) devices are implantable pacemaker pulse generators..."
            ),
        }
        vendor, products = extract_vendor_products_from_enforcement(record)
        assert vendor == "St Jude Medical Inc."
        # First sentence should be the product list
        assert "PM1226" in products[0]
        assert "PM2222" in products[0]

    def test_empty_record(self):
        vendor, products = extract_vendor_products_from_enforcement({})
        assert vendor is None
        assert products == []

    def test_firm_only(self):
        vendor, products = extract_vendor_products_from_enforcement({
            "recalling_firm": "Acme Medical",
        })
        assert vendor == "Acme Medical"
        assert products == []

    def test_non_dict_returns_empty(self):
        vendor, products = extract_vendor_products_from_enforcement(None)  # type: ignore[arg-type]
        assert vendor is None
        assert products == []


class TestLookupVendorProductsByRecallNumber:
    def test_happy_path(self, tmp_path):
        (tmp_path / "enf_Z-0001-2014.json").write_text(
            json.dumps({
                "recalling_firm": "Maquet Cardiovascular, LLC",
                "product_description": "Ultima OPCAB System, Sterile, Rx Only.",
            }),
            encoding="utf-8",
        )
        vendor, products = lookup_vendor_products_by_recall_number(
            "Z-0001-2014", cache_dir=tmp_path,
        )
        assert vendor == "Maquet Cardiovascular, LLC"
        assert products == ["Ultima OPCAB System, Sterile, Rx Only."]

    def test_missing_file_returns_empty(self, tmp_path):
        vendor, products = lookup_vendor_products_by_recall_number(
            "Z-9999-9999", cache_dir=tmp_path,
        )
        assert vendor is None
        assert products == []

    def test_empty_recall_number(self, tmp_path):
        vendor, products = lookup_vendor_products_by_recall_number(
            "", cache_dir=tmp_path,
        )
        assert vendor is None
        assert products == []

    def test_corrupt_json(self, tmp_path):
        (tmp_path / "enf_Z-0002-2014.json").write_text("not json", encoding="utf-8")
        vendor, products = lookup_vendor_products_by_recall_number(
            "Z-0002-2014", cache_dir=tmp_path,
        )
        assert vendor is None
        assert products == []


class TestExtractVendorFromTitle:
    def test_happy_path(self):
        title = "Automated External Defibrillators (Non-Wearable) recall (Philips Medical Systems)"
        assert extract_vendor_from_title(title) == "Philips Medical Systems"

    def test_vendor_with_punctuation(self):
        assert extract_vendor_from_title(
            "Pump, Infusion recall (Deltec, Inc)"
        ) == "Deltec, Inc"

    def test_no_parentheses(self):
        assert extract_vendor_from_title("CVE-2024-1234") is None

    def test_empty_title(self):
        assert extract_vendor_from_title("") is None

    def test_z_recall_format_returns_none(self):
        # Titles like "Z-0096-2019: GE Healthcare Finland Oy" use a different
        # format; extractor should return None (caller falls back to cache).
        assert extract_vendor_from_title("Z-0096-2019: GE Healthcare Finland Oy") is None


class TestExtractProductFromSummary:
    def test_pipe_delimited_tail(self):
        summary = (
            "The device may disarm... | Philips Medical HeartStart MRx "
            "Monitor/Defibrillator Model: M3535A, M3536A | Philips Medical "
            "Systems | Device: Automated External Defibrillators."
        )
        products = extract_product_from_summary(summary)
        assert products
        assert "HeartStart" in products[0] or "M3535A" in products[0]

    def test_narrative_only_extracts_model_codes(self):
        summary = (
            "Philips Heartstart MRx Monitor/Defibrillator models M3535A "
            "and M3536A may experience a critical delay in energy delivery "
            "when switching from manual to AED mode if using software "
            "versions below A.02.00."
        )
        products = extract_product_from_summary(summary)
        assert "M3535A" in products
        assert "M3536A" in products

    def test_empty_summary(self):
        assert extract_product_from_summary("") == []

    def test_ignores_common_acronyms(self):
        # CVE, AED, MRI, ICD, etc. should not be treated as model codes
        summary = "CVE-2024-1234 affects AED devices using MRI and ICD."
        products = extract_product_from_summary(summary)
        # CVE-2024-1234 contains digits+letters but is filtered by the CVE
        # check; acronyms alone would not qualify anyway (no digit).
        assert "CVE" not in products
        assert "AED" not in products
        assert "MRI" not in products


class TestExtractVendorProductsForIssue:
    def test_z_recall_uses_enforcement_cache(self, tmp_path):
        (tmp_path / "enf_Z-0001-2014.json").write_text(
            json.dumps({
                "recalling_firm": "Maquet Cardiovascular, LLC",
                "product_description": "Ultima OPCAB System.",
            }),
            encoding="utf-8",
        )
        issue = {
            "title": "Z-0001-2014: Maquet Cardiovascular",
            "summary": "",
        }
        vendor, products = extract_vendor_products_for_issue(issue, cache_dir=tmp_path)
        assert vendor == "Maquet Cardiovascular, LLC"
        assert products == ["Ultima OPCAB System."]

    def test_falls_back_to_title_when_no_recall_number(self, tmp_path):
        issue = {
            "title": "Automated External Defibrillators (Non-Wearable) recall (Philips Medical Systems)",
            "summary": "Philips Heartstart MRx models M3535A and M3536A...",
        }
        vendor, products = extract_vendor_products_for_issue(issue, cache_dir=tmp_path)
        assert vendor == "Philips Medical Systems"
        assert "M3535A" in products
        assert "M3536A" in products

    def test_merges_when_enforcement_partial(self, tmp_path):
        # Enforcement record has vendor but empty product_description;
        # extractor should fall back to summary for product
        (tmp_path / "enf_Z-0050-2019.json").write_text(
            json.dumps({
                "recalling_firm": "St Jude Medical Inc.",
                "product_description": "",
            }),
            encoding="utf-8",
        )
        issue = {
            "title": "Z-0050-2019: St Jude Medical",
            "summary": (
                "Firmware update for models PM1272 and PM2272. | "
                "Assurity MRI Model Numbers: PM1272, PM2272 | "
                "St Jude Medical | Device: Pacemaker."
            ),
        }
        vendor, products = extract_vendor_products_for_issue(issue, cache_dir=tmp_path)
        assert vendor == "St Jude Medical Inc."
        # Path B should have filled the product gap
        assert products
        assert "PM1272" in products[0] or "Assurity" in products[0]

    def test_neither_path_returns_empties(self, tmp_path):
        issue = {"title": "unrelated", "summary": ""}
        vendor, products = extract_vendor_products_for_issue(issue, cache_dir=tmp_path)
        assert vendor is None
        assert products == []
