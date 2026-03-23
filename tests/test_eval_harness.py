"""Tests for advisoryops/eval_harness.py (Phase 5, Task 5.2).

Contract under test
-------------------
* _infer_healthcare_category maps score signals to the right category.
* evaluate_fixture returns correct FixtureResult for pass and fail cases.
* evaluate() over all 12 golden fixtures produces:
    - total_fixtures == 12
    - correlation accuracy == 1.0
    - cve_coverage accuracy == 1.0
    - scoring accuracy == 1.0
    - healthcare accuracy >= 0.9  (11/12 — fixture-07 is an ambiguous case)
* summary.json and summary.md are written with all required fields.
* Per-fixture JSON files are written for each fixture.
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from advisoryops.eval_harness import (
    DimensionResult,
    FixtureResult,
    _infer_healthcare_category,
    evaluate,
    evaluate_fixture,
)
from advisoryops.score import score_issue_v2

GOLDEN_DIR = Path("tests/fixtures/golden")
MANIFEST = GOLDEN_DIR / "manifest.json"


# ══════════════════════════════════════════════════════════════════════════════
# _infer_healthcare_category
# ══════════════════════════════════════════════════════════════════════════════

def _score_result_with_why(why_entries):
    """Build a minimal score result mock with a given why list."""
    r = MagicMock()
    r.why = why_entries
    return r


def test_infer_patient_monitor_is_medical_device() -> None:
    r = _score_result_with_why(["device: patient monitor (+20)"])
    assert _infer_healthcare_category(r) == "medical_device"


def test_infer_pacs_is_medical_device() -> None:
    r = _score_result_with_why(["device: medical imaging/PACS (+15)"])
    assert _infer_healthcare_category(r) == "medical_device"


def test_infer_infusion_pump_is_medical_device() -> None:
    r = _score_result_with_why(["device: infusion/drug pump (+25)"])
    assert _infer_healthcare_category(r) == "medical_device"


def test_infer_ehr_is_healthcare_it() -> None:
    r = _score_result_with_why(["device: EHR/EMR (+10)"])
    assert _infer_healthcare_category(r) == "healthcare_it"


def test_infer_phi_signal_is_medical_device() -> None:
    r = _score_result_with_why(["clinical: PHI/patient data (+15)"])
    assert _infer_healthcare_category(r) == "medical_device"


def test_infer_patient_safety_is_medical_device() -> None:
    r = _score_result_with_why(["clinical: patient safety (+25)"])
    assert _infer_healthcare_category(r) == "medical_device"


def test_infer_cisa_icsma_is_medical_device() -> None:
    r = _score_result_with_why(["source-authority: CISA ICS-Medical (+20)", "device: healthcare context (+10)"])
    assert _infer_healthcare_category(r) == "medical_device"


def test_infer_healthcare_context_only_is_healthcare_it() -> None:
    r = _score_result_with_why(["device: healthcare context (+10)"])
    assert _infer_healthcare_category(r) == "healthcare_it"


def test_infer_no_signals_is_not_healthcare() -> None:
    r = _score_result_with_why(["base: issue_type=cve (+10)", "source: KEV source (+80)"])
    assert _infer_healthcare_category(r) == "not_healthcare"


# ══════════════════════════════════════════════════════════════════════════════
# evaluate_fixture: individual fixture cases
# ══════════════════════════════════════════════════════════════════════════════

def test_evaluate_fixture_returns_fixture_result() -> None:
    result = evaluate_fixture(GOLDEN_DIR / "fixture-03-kev-single-cve")
    assert isinstance(result, FixtureResult)


def test_fixture_03_passes_all_dimensions() -> None:
    result = evaluate_fixture(GOLDEN_DIR / "fixture-03-kev-single-cve")
    assert result.passed is True
    assert result.error is None
    for dim_name, dim in result.dimensions.items():
        assert dim.passed, f"Dimension '{dim_name}' failed: {dim.details}"


def test_fixture_03_issue_count_correct() -> None:
    result = evaluate_fixture(GOLDEN_DIR / "fixture-03-kev-single-cve")
    assert result.actual_issue_count == 1


def test_fixture_09_two_issues() -> None:
    """fixture-09 has 2 distinct KEV CVEs → 2 issues."""
    result = evaluate_fixture(GOLDEN_DIR / "fixture-09-two-distinct-kev-cves")
    assert result.actual_issue_count == 2


def test_fixture_05_five_cves() -> None:
    """fixture-05 has 5 CVEs in one advisory → 5 issues."""
    result = evaluate_fixture(GOLDEN_DIR / "fixture-05-icsma-pacs-server-multi-cve")
    assert result.actual_issue_count == 5


def test_fixture_11_no_cves() -> None:
    """fixture-11 has no CVEs (UNK- issue type)."""
    result = evaluate_fixture(GOLDEN_DIR / "fixture-11-unknown-nonhealthcare")
    assert result.actual_cves == []


def test_fixture_11_not_healthcare() -> None:
    result = evaluate_fixture(GOLDEN_DIR / "fixture-11-unknown-nonhealthcare")
    assert "not_healthcare" in result.actual_healthcare_categories


def test_fixture_missing_files_returns_error(tmp_path: Path) -> None:
    """evaluate_fixture on an empty dir returns error result, not exception."""
    result = evaluate_fixture(tmp_path)
    assert result.passed is False
    assert result.error is not None


def test_fixture_correlation_dimension_structure() -> None:
    result = evaluate_fixture(GOLDEN_DIR / "fixture-03-kev-single-cve")
    corr = result.dimensions["correlation"]
    assert isinstance(corr, DimensionResult)
    assert corr.expected == 1
    assert corr.actual == 1


def test_fixture_scoring_dimension_structure() -> None:
    result = evaluate_fixture(GOLDEN_DIR / "fixture-03-kev-single-cve")
    scoring = result.dimensions["scoring"]
    assert isinstance(scoring, DimensionResult)
    assert scoring.passed is True


# ══════════════════════════════════════════════════════════════════════════════
# evaluate(): full run against all 12 golden fixtures
# ══════════════════════════════════════════════════════════════════════════════

@pytest.fixture(scope="module")
def eval_result(tmp_path_factory):
    """Run evaluate() once against all golden fixtures; reuse across tests."""
    out = tmp_path_factory.mktemp("eval_out")
    summary_json, summary_md, fixtures_out = evaluate(
        fixtures_dir=str(GOLDEN_DIR),
        out_dir=str(out),
    )
    summary = json.loads(summary_json.read_text())
    return summary, summary_json, summary_md, fixtures_out


def test_evaluate_total_fixtures(eval_result) -> None:
    summary, *_ = eval_result
    assert summary["total_fixtures"] == 12


def test_evaluate_correlation_accuracy_perfect(eval_result) -> None:
    summary, *_ = eval_result
    assert summary["accuracy_by_dimension"]["correlation"] == 1.0


def test_evaluate_cve_coverage_accuracy_perfect(eval_result) -> None:
    summary, *_ = eval_result
    assert summary["accuracy_by_dimension"]["cve_coverage"] == 1.0


def test_evaluate_scoring_accuracy_perfect(eval_result) -> None:
    summary, *_ = eval_result
    assert summary["accuracy_by_dimension"]["scoring"] == 1.0


def test_evaluate_healthcare_accuracy_at_least_90_percent(eval_result) -> None:
    summary, *_ = eval_result
    assert summary["accuracy_by_dimension"]["healthcare"] >= 0.9


def test_evaluate_summary_json_has_required_fields(eval_result) -> None:
    summary, *_ = eval_result
    for field in ("total_fixtures", "pass_count", "fail_count", "pass_rate",
                  "accuracy_by_dimension", "fixtures", "generated_at"):
        assert field in summary, f"Missing field: {field}"


def test_evaluate_summary_json_written(eval_result) -> None:
    _, summary_json, *_ = eval_result
    assert summary_json.exists()
    doc = json.loads(summary_json.read_text())
    assert doc["total_fixtures"] == 12


def test_evaluate_summary_md_written(eval_result) -> None:
    _, _, summary_md, _ = eval_result
    assert summary_md.exists()
    content = summary_md.read_text()
    assert "# AdvisoryOps Evaluation Report" in content
    assert "Accuracy by Dimension" in content
    assert "Fixture Results" in content


def test_evaluate_per_fixture_files_written(eval_result) -> None:
    _, _, _, fixtures_out = eval_result
    fixture_files = list(fixtures_out.glob("*.json"))
    assert len(fixture_files) == 12


def test_evaluate_per_fixture_files_valid_json(eval_result) -> None:
    _, _, _, fixtures_out = eval_result
    for f in fixtures_out.glob("*.json"):
        doc = json.loads(f.read_text())
        assert "fixture_id" in doc
        assert "passed" in doc


def test_evaluate_pass_count_gte_11(eval_result) -> None:
    """At least 11/12 fixtures should pass (fixture-07 healthcare is ambiguous)."""
    summary, *_ = eval_result
    assert summary["pass_count"] >= 11


def test_evaluate_fixture_summary_has_dimensions(eval_result) -> None:
    summary, *_ = eval_result
    for fs in summary["fixtures"]:
        if not fs.get("error"):
            dims = fs.get("dimensions", {})
            assert "correlation" in dims
            assert "cve_coverage" in dims
            assert "scoring" in dims
            assert "healthcare" in dims
