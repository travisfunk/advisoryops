"""Tests for the FDA clinical-severity floor applied at the end of v2 scoring.

Rules under test (score.py::_apply_fda_clinical_floor):
  A. Class III ``fda_risk_class="3"`` → score = max(score, 150)
  B. Class II  ``fda_risk_class="2"`` → score = max(score, 100)
  C. Class I   ``fda_risk_class="1"`` → score += 10
  No FDA class → score unchanged.
"""
from __future__ import annotations

from advisoryops.score import _apply_fda_clinical_floor, score_issue_v2


# --- unit tests on the helper ----------------------------------------------

class TestApplyFdaClinicalFloor:
    def test_class_iii_low_score_floors_to_150(self):
        why: list[str] = []
        out = _apply_fda_clinical_floor({"fda_risk_class": "3"}, 50, why)
        assert out == 150
        assert any("Class III" in w and "P0" in w for w in why)

    def test_class_iii_high_score_unchanged(self):
        why: list[str] = []
        out = _apply_fda_clinical_floor({"fda_risk_class": "3"}, 200, why)
        assert out == 200
        assert why == []

    def test_class_iii_exactly_150_unchanged(self):
        why: list[str] = []
        out = _apply_fda_clinical_floor({"fda_risk_class": "3"}, 150, why)
        assert out == 150
        assert why == []

    def test_class_ii_low_score_floors_to_100(self):
        why: list[str] = []
        out = _apply_fda_clinical_floor({"fda_risk_class": "2"}, 30, why)
        assert out == 100
        assert any("Class II" in w and "P1" in w for w in why)

    def test_class_ii_high_score_unchanged(self):
        why: list[str] = []
        out = _apply_fda_clinical_floor({"fda_risk_class": "2"}, 120, why)
        assert out == 120
        assert why == []

    def test_class_i_adds_ten(self):
        why: list[str] = []
        out = _apply_fda_clinical_floor({"fda_risk_class": "1"}, 40, why)
        assert out == 50
        assert any("Class I" in w and "+10" in w for w in why)

    def test_class_i_high_score_still_adds_ten(self):
        """Class I boost has no ceiling — it's a small additive signal."""
        why: list[str] = []
        out = _apply_fda_clinical_floor({"fda_risk_class": "1"}, 180, why)
        assert out == 190

    def test_no_fda_class_unchanged(self):
        why: list[str] = []
        out = _apply_fda_clinical_floor({}, 55, why)
        assert out == 55
        assert why == []

    def test_null_fda_class_unchanged(self):
        why: list[str] = []
        out = _apply_fda_clinical_floor({"fda_risk_class": None}, 55, why)
        assert out == 55
        assert why == []


# --- integration tests through score_issue_v2 ------------------------------

def _bare_issue(**extra):
    """Minimal issue that produces a low v2 base score with no source bonuses."""
    base = {
        "issue_id": "UNK-test",
        "issue_type": "recall",
        "title": "Some recall notice",
        "summary": "",
        "sources": [],
        "links": [],
    }
    base.update(extra)
    return base


class TestFdaFloorIntegration:
    def test_class_iii_promotes_to_p0(self):
        issue = _bare_issue(fda_risk_class="3")
        result = score_issue_v2(issue)
        assert result.score >= 150
        assert result.priority == "P0"
        assert any("Class III auto-floored" in w for w in result.why)

    def test_class_ii_promotes_to_p1(self):
        issue = _bare_issue(fda_risk_class="2")
        result = score_issue_v2(issue)
        assert result.score >= 100
        assert result.priority in ("P0", "P1")
        assert any("Class II auto-floored" in w for w in result.why)

    def test_class_i_does_not_floor(self):
        """Class I contributes +10 but must not auto-floor into P1/P0."""
        issue = _bare_issue(fda_risk_class="1")
        result = score_issue_v2(issue)
        assert result.score < 100
        assert result.priority in ("P2", "P3")
        assert any("Class I" in w and "+10" in w for w in result.why)

    def test_no_fda_class_behaves_like_v2_baseline(self):
        issue = _bare_issue()
        result = score_issue_v2(issue)
        assert not any("Class III auto-floored" in w for w in result.why)
        assert not any("Class II auto-floored" in w for w in result.why)
