"""Feature 2 — KEV cross-reference for medical devices.

Tests:
  - is_kev_medical_device flag logic
  - _score_kev_medical_device scoring bonus
  - Stacking with existing bonuses
"""
from __future__ import annotations

from advisoryops.score import _score_kev_medical_device


class TestKevMedicalDeviceFlag:
    """Test that the flag sets correctly based on both conditions."""

    def test_flag_true_when_both_conditions_met(self):
        issue = {
            "healthcare_relevant": True,
            "kev_due_date": "2024-06-01",
            "is_kev_medical_device": True,
        }
        pts, why = _score_kev_medical_device(issue)
        assert pts == 40
        assert len(why) == 1
        assert "actively exploited medical device" in why[0]

    def test_flag_false_when_not_healthcare(self):
        """Only healthcare_relevant=True qualifies."""
        issue = {
            "healthcare_relevant": False,
            "kev_due_date": "2024-06-01",
            "is_kev_medical_device": False,
        }
        pts, why = _score_kev_medical_device(issue)
        assert pts == 0
        assert why == []

    def test_flag_false_when_no_kev(self):
        """Healthcare-relevant but no KEV indicators."""
        issue = {
            "healthcare_relevant": True,
            "is_kev_medical_device": False,
        }
        pts, why = _score_kev_medical_device(issue)
        assert pts == 0

    def test_flag_false_when_missing(self):
        """No flag at all."""
        issue = {}
        pts, why = _score_kev_medical_device(issue)
        assert pts == 0


class TestKevMedicalDeviceScoring:
    def test_bonus_adds_40(self):
        issue = {"is_kev_medical_device": True}
        pts, why = _score_kev_medical_device(issue)
        assert pts == 40
        assert "+40" in why[0]

    def test_no_bonus_when_false(self):
        issue = {"is_kev_medical_device": False}
        pts, why = _score_kev_medical_device(issue)
        assert pts == 0
        assert why == []

    def test_why_field_captures_reasoning(self):
        issue = {"is_kev_medical_device": True}
        pts, why = _score_kev_medical_device(issue)
        assert "kev-medical-device" in why[0]
        assert "actively exploited" in why[0]

    def test_stacking_with_fda_class_3(self):
        """KEV medical device bonus stacks with FDA Class III bonus."""
        from advisoryops.score import _score_fda_risk_class

        issue = {
            "is_kev_medical_device": True,
            "fda_risk_class": "3",
        }
        kev_pts, _ = _score_kev_medical_device(issue)
        fda_pts, _ = _score_fda_risk_class(issue)
        assert kev_pts + fda_pts == 70  # 40 + 30
