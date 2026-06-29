"""Tests for advisoryops.ai_score — AI healthcare relevance classifier.

All tests use the _call_fn injection point so no API key is required.
"""
from __future__ import annotations

import pytest

from advisoryops.ai_score import (
    HealthcareClassification,
    classify_healthcare_relevance,
)


# ---------------------------------------------------------------------------
# Mock call_fn helpers
# ---------------------------------------------------------------------------

def _mock_call(category, confidence=0.9, reasoning="test", device_types=None):
    """Return a zero-argument callable that produces a canned classification."""
    def _fn():
        return {
            "result": {
                "category": category,
                "confidence": confidence,
                "reasoning": reasoning,
                "device_types": device_types or [],
            },
            "model": "gpt-4o-mini",
            "tokens_used": 50,
        }
    return _fn


# ---------------------------------------------------------------------------
# Happy path tests
# ---------------------------------------------------------------------------

def test_medical_device_classification():
    issue = {
        "issue_id": "CVE-2024-9999",
        "title": "Buffer overflow in infusion pump firmware",
        "summary": "A critical vulnerability allows unauthenticated remote access.",
    }
    result = classify_healthcare_relevance(
        issue,
        _call_fn=_mock_call("medical_device", device_types=["infusion pump"]),
    )
    assert isinstance(result, HealthcareClassification)
    assert result.category == "medical_device"
    assert result.confidence == pytest.approx(0.9)
    assert result.device_types == ["infusion pump"]
    assert result.model == "gpt-4o-mini"
    assert result.tokens_used == 50


def test_healthcare_it_classification():
    issue = {
        "issue_id": "UNK-abc",
        "title": "SQL injection in EHR platform",
        "summary": "An attacker can exfiltrate patient records.",
    }
    result = classify_healthcare_relevance(
        issue,
        _call_fn=_mock_call("healthcare_it", confidence=0.85),
    )
    assert result.category == "healthcare_it"
    assert result.confidence == pytest.approx(0.85)
    assert result.device_types == []


def test_healthcare_adjacent_classification():
    issue = {
        "issue_id": "UNK-xyz",
        "title": "Vulnerability in hospital HVAC control system",
        "summary": "Building management software affected.",
    }
    result = classify_healthcare_relevance(
        issue,
        _call_fn=_mock_call("healthcare_adjacent", confidence=0.75),
    )
    assert result.category == "healthcare_adjacent"


def test_not_healthcare_classification():
    issue = {
        "issue_id": "CVE-2024-1111",
        "title": "Remote code execution in web browser",
        "summary": "Chrome V8 engine vulnerability allows code execution.",
    }
    result = classify_healthcare_relevance(
        issue,
        _call_fn=_mock_call("not_healthcare", confidence=0.95),
    )
    assert result.category == "not_healthcare"


# ---------------------------------------------------------------------------
# Dataclass field tests
# ---------------------------------------------------------------------------

def test_classification_has_all_fields():
    issue = {"issue_id": "T-001", "title": "Test", "summary": "Test summary"}
    result = classify_healthcare_relevance(
        issue,
        _call_fn=_mock_call("medical_device", device_types=["ventilator"]),
    )
    assert hasattr(result, "category")
    assert hasattr(result, "confidence")
    assert hasattr(result, "reasoning")
    assert hasattr(result, "device_types")
    assert hasattr(result, "model")
    assert hasattr(result, "tokens_used")
    assert hasattr(result, "from_cache")


def test_from_cache_false_with_call_fn():
    issue = {"issue_id": "T-002", "title": "Test", "summary": "Desc"}
    result = classify_healthcare_relevance(
        issue,
        _call_fn=_mock_call("not_healthcare"),
    )
    assert result.from_cache is False


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

def test_invalid_category_coerced_to_not_healthcare():
    """API returning an unrecognised category should be coerced to not_healthcare."""
    issue = {"issue_id": "T-003", "title": "Test", "summary": "Desc"}

    def _bad_category():
        return {
            "result": {
                "category": "totally_invalid",
                "confidence": 0.8,
                "reasoning": "oops",
                "device_types": [],
            },
            "model": "gpt-4o-mini",
            "tokens_used": 20,
        }

    result = classify_healthcare_relevance(issue, _call_fn=_bad_category)
    assert result.category == "not_healthcare"


def test_confidence_clamped_to_0_1():
    issue = {"issue_id": "T-004", "title": "Test", "summary": "Desc"}

    def _over_confidence():
        return {
            "result": {
                "category": "medical_device",
                "confidence": 2.5,
                "reasoning": "very sure",
                "device_types": [],
            },
            "model": "gpt-4o-mini",
            "tokens_used": 10,
        }

    result = classify_healthcare_relevance(issue, _call_fn=_over_confidence)
    assert result.confidence == pytest.approx(1.0)


def test_negative_confidence_clamped():
    issue = {"issue_id": "T-005", "title": "Test", "summary": "Desc"}

    def _negative_confidence():
        return {
            "result": {
                "category": "not_healthcare",
                "confidence": -0.5,
                "reasoning": "uncertain",
                "device_types": [],
            },
            "model": "gpt-4o-mini",
            "tokens_used": 10,
        }

    result = classify_healthcare_relevance(issue, _call_fn=_negative_confidence)
    assert result.confidence == pytest.approx(0.0)


def test_empty_device_types_list():
    issue = {"issue_id": "T-006", "title": "Test", "summary": "Desc"}
    result = classify_healthcare_relevance(
        issue,
        _call_fn=_mock_call("healthcare_it"),
    )
    assert isinstance(result.device_types, list)
    assert result.device_types == []


def test_multiple_device_types_preserved():
    issue = {"issue_id": "T-007", "title": "Test", "summary": "Desc"}
    result = classify_healthcare_relevance(
        issue,
        _call_fn=_mock_call("medical_device", device_types=["infusion pump", "patient monitor"]),
    )
    assert "infusion pump" in result.device_types
    assert "patient monitor" in result.device_types


def test_missing_issue_fields_handled():
    """classify_healthcare_relevance should not crash on a sparse issue dict."""
    result = classify_healthcare_relevance(
        {},
        _call_fn=_mock_call("not_healthcare"),
    )
    assert result.category == "not_healthcare"


# ---------------------------------------------------------------------------
# Integration with score_issues (ai_score flag)
# ---------------------------------------------------------------------------

def test_score_issues_ai_score_adds_category(tmp_path):
    """When ai_score=True, scored rows get a healthcare_category field."""
    import json
    from advisoryops.score import score_issues

    issues_path = tmp_path / "issues.jsonl"
    issues_path.write_text(
        json.dumps({
            "issue_id": "CVE-2024-AI-TEST",
            "issue_type": "cve",
            "title": "Vulnerability in generic network switch",
            "summary": "A buffer overflow allows remote code execution.",
            "sources": ["generic-source"],
            "links": [],
        }, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    out_root = tmp_path / "scored"

    def _mock_classify_fn():
        return {
            "result": {
                "category": "healthcare_adjacent",
                "confidence": 0.8,
                "reasoning": "Network infrastructure used in hospitals.",
                "device_types": [],
            },
            "model": "gpt-4o-mini",
            "tokens_used": 30,
        }

    score_issues(
        in_issues=str(issues_path),
        out_root_scored=str(out_root),
        min_priority="P3",
        top=0,
        scoring_version="v2",
        ai_score=True,
        _ai_classify_fn=_mock_classify_fn,
    )

    scored = [
        json.loads(l)
        for l in (out_root / "issues_scored.jsonl").read_text(encoding="utf-8").splitlines()
        if l.strip()
    ]
    assert len(scored) == 1
    assert "healthcare_category" in scored[0]
    assert scored[0]["healthcare_category"] == "healthcare_adjacent"


def test_score_issues_ai_score_boosts_score_for_medical_device(tmp_path):
    """AI medical_device classification with confidence >= 0.7 adds +20 pts."""
    import json
    from advisoryops.score import score_issues

    issues_path = tmp_path / "issues.jsonl"
    # Low-signal issue that would otherwise score low
    issue = {
        "issue_id": "UNK-DEVICE-001",
        "issue_type": "unknown",
        "title": "Firmware update available",
        "summary": "Vendor releases firmware update for hardware device.",
        "sources": ["vendor-advisory"],
        "links": [],
    }
    issues_path.write_text(json.dumps(issue) + "\n", encoding="utf-8")

    def _medical_device_fn():
        return {
            "result": {
                "category": "medical_device",
                "confidence": 0.9,
                "reasoning": "Firmware device in clinical use.",
                "device_types": ["implantable device"],
            },
            "model": "gpt-4o-mini",
            "tokens_used": 40,
        }

    out_root = tmp_path / "scored"
    score_issues(
        in_issues=str(issues_path),
        out_root_scored=str(out_root),
        min_priority="P3",
        top=0,
        scoring_version="v2",
        ai_score=True,
        _ai_classify_fn=_medical_device_fn,
    )

    scored = [
        json.loads(l)
        for l in (out_root / "issues_scored.jsonl").read_text(encoding="utf-8").splitlines()
        if l.strip()
    ]
    assert len(scored) == 1
    row = scored[0]
    # Should have received the +20 medical_device boost on top of base score
    assert any("ai-classify: medical_device" in w for w in row["why"])
    assert row["healthcare_category"] == "medical_device"


def test_score_issues_ai_score_skips_issues_with_hc_signals(tmp_path):
    """Issues that already have device/clinical signals are not sent to AI."""
    import json
    from advisoryops.score import score_issues

    issues_path = tmp_path / "issues.jsonl"
    # This issue will trigger the infusion pump device signal
    issue = {
        "issue_id": "CVE-2024-PUMP",
        "issue_type": "cve",
        "title": "Vulnerability in infusion pump controller",
        "summary": "Remote code execution in infusion pump firmware.",
        "sources": ["cisa-icsma"],
        "links": [],
    }
    issues_path.write_text(json.dumps(issue) + "\n", encoding="utf-8")

    classify_call_count = {"n": 0}

    def _counting_fn():
        classify_call_count["n"] += 1
        return {
            "result": {
                "category": "medical_device",
                "confidence": 0.9,
                "reasoning": "already classified",
                "device_types": [],
            },
            "model": "gpt-4o-mini",
            "tokens_used": 10,
        }

    out_root = tmp_path / "scored"
    score_issues(
        in_issues=str(issues_path),
        out_root_scored=str(out_root),
        min_priority="P3",
        top=0,
        scoring_version="v2",
        ai_score=True,
        _ai_classify_fn=_counting_fn,
    )

    # AI classifier must NOT have been called (issue already has device signal)
    assert classify_call_count["n"] == 0
