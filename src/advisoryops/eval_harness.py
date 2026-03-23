"""Evaluation harness for golden test fixtures (Phase 5, Task 5.2).

Runs the full deterministic pipeline (correlate → score_issue_v2) against
every fixture in the golden set and measures accuracy across four dimensions:

  - correlation  : correct number of issues produced; all expected CVEs found
  - cve_coverage : all expected CVE IDs appear in the correlated output
  - scoring      : every issue's priority falls within expected_priority_range
  - healthcare   : inferred healthcare category matches expected

Golden fixtures (``tests/fixtures/golden/``)
-------------------------------------------
Each fixture is a subdirectory with two files:
  input.json    — list of raw signal dicts (the same shape as items.jsonl)
  expected.json — expected values:
    {
      "description": "<human description of what this fixture tests>",
      "expected_issue_count": <int>,
      "expected_cves": ["CVE-YYYY-NNNN", ...],
      "expected_priority_range": ["P0", "P1"],   // all scored issues must be in this set
      "expected_healthcare_category": "medical_device"
    }

The manifest (``tests/fixtures/golden/manifest.json``) lists fixture IDs::
    { "fixtures": [{"id": "fixture-001"}, ...] }

Outputs (per run):
  outputs/eval/fixtures/<id>.json   per-fixture JSON reports
  outputs/eval/summary.json         aggregate counts + accuracy_by_dimension
  outputs/eval/summary.md           human-readable report with ASCII progress bars

Healthcare category inference
-----------------------------
The harness infers healthcare category from the v2 score ``why`` list using
the same prefixes that score.py appends (``"device: ..."``, ``"clinical: ..."``,
``"CISA ICS-Medical"``).  This is deterministic — no AI calls during eval.

Usage::

    from advisoryops.eval_harness import evaluate
    evaluate(fixtures_dir="tests/fixtures/golden", out_dir="outputs/eval")

    # Or via CLI:
    advisoryops evaluate --fixtures tests/fixtures/golden --out outputs/eval
"""
from __future__ import annotations

import contextlib
import io
import json
import tempfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .correlate import correlate
from .score import score_issue_v2


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Healthcare category inference
# ---------------------------------------------------------------------------

def _infer_healthcare_category(score_result) -> str:
    """Infer healthcare category from v2 score signals.

    Categories (same vocabulary as golden fixture expected.json):
      medical_device   — specific medical device keywords or CISA ICS-Medical source
      healthcare_it    — EHR/EMR or generic healthcare context only
      not_healthcare   — no healthcare signals

    Note: this is a deterministic heuristic; ambiguous cases (e.g. CISA
    ICS-Medical advisories for software-only products) may be misclassified.
    """
    why = score_result.why

    # Specific device signals → unambiguously medical device
    _SPECIFIC_DEVICE_PREFIXES = (
        "device: infusion/drug pump",
        "device: ventilator/life-support",
        "device: cardiac implant/defibrillator",
        "device: patient monitor",
        "device: medical imaging/PACS",
    )
    for w in why:
        if any(w.startswith(p) for p in _SPECIFIC_DEVICE_PREFIXES):
            return "medical_device"

    # EHR/EMR → healthcare IT
    if any(w.startswith("device: EHR/EMR") for w in why):
        return "healthcare_it"

    # Strong clinical signals (patient-facing) → medical device
    _STRONG_CLINICAL_PREFIXES = (
        "clinical: life-sustaining",
        "clinical: patient safety",
        "clinical: ICU",
        "clinical: PHI",
    )
    for w in why:
        if any(w.startswith(p) for p in _STRONG_CLINICAL_PREFIXES):
            return "medical_device"

    # CISA ICS-Medical source authority → typically a medical device advisory
    if any("CISA ICS-Medical" in w for w in why):
        return "medical_device"

    # Generic healthcare context only → healthcare IT (software/systems)
    if any(w.startswith("device: healthcare context") for w in why):
        return "healthcare_it"

    return "not_healthcare"


# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------

@dataclass
class DimensionResult:
    passed: bool
    expected: Any
    actual: Any
    details: str = ""


@dataclass
class FixtureResult:
    fixture_id: str
    description: str
    passed: bool
    dimensions: Dict[str, DimensionResult] = field(default_factory=dict)
    actual_issue_count: int = 0
    actual_cves: List[str] = field(default_factory=list)
    actual_priorities: List[str] = field(default_factory=list)
    actual_healthcare_categories: List[str] = field(default_factory=list)
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Per-fixture runner
# ---------------------------------------------------------------------------

def _run_correlate_on_signals(signals: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Write signals to a temp discover dir, run correlate, return issues."""
    with tempfile.TemporaryDirectory() as tmp:
        src_dir = Path(tmp) / "eval_src"
        src_dir.mkdir()
        (src_dir / "items.jsonl").write_text(
            "\n".join(json.dumps(s, ensure_ascii=False) for s in signals),
            encoding="utf-8",
        )
        issues_dir = Path(tmp) / "issues"
        issues_dir.mkdir()

        # Suppress correlate's stdout chatter
        with contextlib.redirect_stdout(io.StringIO()):
            correlate(
                out_root_discover=tmp,
                out_root_issues=str(issues_dir),
            )

        issues_path = issues_dir / "issues.jsonl"
        if not issues_path.exists():
            return []
        return [
            json.loads(line)
            for line in issues_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]


def evaluate_fixture(fixture_dir: Path) -> FixtureResult:
    """Run the pipeline against one golden fixture and return a FixtureResult."""
    fid = fixture_dir.name

    input_path = fixture_dir / "input.json"
    expected_path = fixture_dir / "expected.json"
    if not input_path.exists() or not expected_path.exists():
        return FixtureResult(
            fixture_id=fid,
            description="",
            passed=False,
            error=f"Missing input.json or expected.json in {fixture_dir}",
        )

    signals: List[Dict[str, Any]] = json.loads(input_path.read_text(encoding="utf-8"))
    expected: Dict[str, Any] = json.loads(expected_path.read_text(encoding="utf-8"))

    exp_count: int = expected.get("expected_issue_count", 0)
    exp_cves: List[str] = [c.upper() for c in (expected.get("expected_cves") or [])]
    exp_priority_range: List[str] = expected.get("expected_priority_range") or []
    exp_healthcare: str = expected.get("expected_healthcare_category", "")
    description: str = expected.get("description", "")

    try:
        issues = _run_correlate_on_signals(signals)
    except Exception as exc:
        return FixtureResult(
            fixture_id=fid,
            description=description,
            passed=False,
            error=f"Correlate failed: {exc}",
        )

    # Score every issue
    scored = [(iss, score_issue_v2(iss)) for iss in issues]

    # Collect actuals
    actual_count = len(issues)
    actual_cves = sorted({
        cve.upper()
        for iss in issues
        for cve in (iss.get("cves") or [])
    })
    actual_priorities = sorted({res.priority for _, res in scored})
    actual_hc_categories = sorted({_infer_healthcare_category(res) for _, res in scored})
    # Use the most "medical" category when multiple issues are present
    hc_priority = {"medical_device": 3, "healthcare_it": 2, "not_healthcare": 1}
    actual_hc = max(actual_hc_categories, key=lambda c: hc_priority.get(c, 0)) if actual_hc_categories else "not_healthcare"

    # ── dimension 1: correlation (issue count) ────────────────────────────────
    count_pass = actual_count == exp_count
    corr_dim = DimensionResult(
        passed=count_pass,
        expected=exp_count,
        actual=actual_count,
        details=(
            "issue count matches"
            if count_pass
            else f"got {actual_count}, expected {exp_count}"
        ),
    )

    # ── dimension 2: CVE coverage ─────────────────────────────────────────────
    if exp_cves:
        missing = sorted(set(exp_cves) - set(actual_cves))
        cve_pass = len(missing) == 0
        cve_details = "all expected CVEs found" if cve_pass else f"missing CVEs: {missing}"
    else:
        # No CVEs expected — check none were found unexpectedly
        cve_pass = len(actual_cves) == 0
        cve_details = (
            "no CVEs expected and none found"
            if cve_pass
            else f"unexpected CVEs found: {actual_cves}"
        )
    cve_dim = DimensionResult(
        passed=cve_pass,
        expected=exp_cves,
        actual=actual_cves,
        details=cve_details,
    )

    # ── dimension 3: scoring calibration ──────────────────────────────────────
    if exp_priority_range and scored:
        out_of_range = [
            res.priority
            for _, res in scored
            if res.priority not in exp_priority_range
        ]
        priority_pass = len(out_of_range) == 0
        priority_details = (
            "all priorities in expected range"
            if priority_pass
            else f"out-of-range priorities: {out_of_range} (expected {exp_priority_range})"
        )
    else:
        priority_pass = True
        priority_details = "no scoring expectation defined"
    priority_dim = DimensionResult(
        passed=priority_pass,
        expected=exp_priority_range,
        actual=actual_priorities,
        details=priority_details,
    )

    # ── dimension 4: healthcare classification ────────────────────────────────
    hc_pass = actual_hc == exp_healthcare
    hc_dim = DimensionResult(
        passed=hc_pass,
        expected=exp_healthcare,
        actual=actual_hc,
        details=(
            "healthcare category matches"
            if hc_pass
            else f"got '{actual_hc}', expected '{exp_healthcare}'"
        ),
    )

    all_passed = all([count_pass, cve_pass, priority_pass, hc_pass])

    return FixtureResult(
        fixture_id=fid,
        description=description,
        passed=all_passed,
        dimensions={
            "correlation": corr_dim,
            "cve_coverage": cve_dim,
            "scoring": priority_dim,
            "healthcare": hc_dim,
        },
        actual_issue_count=actual_count,
        actual_cves=actual_cves,
        actual_priorities=actual_priorities,
        actual_healthcare_categories=actual_hc_categories,
    )


# ---------------------------------------------------------------------------
# Summary builders
# ---------------------------------------------------------------------------

def _build_summary_json(results: List[FixtureResult], started_at: str) -> Dict[str, Any]:
    total = len(results)
    passed = sum(1 for r in results if r.passed)
    failed = total - passed

    dim_names = ["correlation", "cve_coverage", "scoring", "healthcare"]
    accuracy_by_dimension: Dict[str, float] = {}
    for dim in dim_names:
        dim_pass = sum(
            1
            for r in results
            if r.error is None and r.dimensions.get(dim, DimensionResult(False, None, None)).passed
        )
        accuracy_by_dimension[dim] = dim_pass / total if total else 0.0

    fixture_summaries = []
    for r in results:
        fs: Dict[str, Any] = {
            "fixture_id": r.fixture_id,
            "passed": r.passed,
            "actual_issue_count": r.actual_issue_count,
            "actual_priorities": r.actual_priorities,
            "actual_healthcare": r.actual_healthcare_categories,
        }
        if r.error:
            fs["error"] = r.error
        else:
            fs["dimensions"] = {
                k: {"passed": v.passed, "expected": v.expected, "actual": v.actual, "details": v.details}
                for k, v in r.dimensions.items()
            }
        fixture_summaries.append(fs)

    return {
        "generated_at": _utc_now_iso(),
        "started_at": started_at,
        "total_fixtures": total,
        "pass_count": passed,
        "fail_count": failed,
        "pass_rate": round(passed / total, 4) if total else 0.0,
        "accuracy_by_dimension": {k: round(v, 4) for k, v in accuracy_by_dimension.items()},
        "fixtures": fixture_summaries,
    }


def _build_summary_markdown(summary: Dict[str, Any]) -> str:
    lines = []
    add = lines.append

    add("# AdvisoryOps Evaluation Report")
    add("")
    add(f"**Generated:** {summary['generated_at']}  ")
    add(f"**Fixtures:** {summary['total_fixtures']}  ")
    add(f"**Passed:** {summary['pass_count']}  ")
    add(f"**Failed:** {summary['fail_count']}  ")
    add(f"**Pass rate:** {summary['pass_rate']:.1%}  ")
    add("")

    add("## Accuracy by Dimension")
    add("")
    for dim, acc in summary["accuracy_by_dimension"].items():
        bar_len = int(acc * 20)
        bar = "#" * bar_len + "-" * (20 - bar_len)
        add(f"- **{dim}**: {acc:.1%}  [{bar}]")
    add("")

    add("## Fixture Results")
    add("")
    add("| Fixture | Pass | Issues | Priorities | HC Category | Dimensions |")
    add("|---------|------|--------|------------|-------------|------------|")

    for fs in summary["fixtures"]:
        status = "PASS" if fs["passed"] else "FAIL"
        issues = fs["actual_issue_count"]
        priorities = ", ".join(fs.get("actual_priorities") or [])
        hc = ", ".join(fs.get("actual_healthcare") or [])
        if fs.get("error"):
            dim_status = f"ERROR: {fs['error'][:50]}"
        else:
            dims = fs.get("dimensions", {})
            dim_status = " ".join(
                f"{k[:4]}={'OK' if v['passed'] else 'FAIL'}"
                for k, v in dims.items()
            )
        fid_short = fs["fixture_id"].replace("fixture-", "")
        add(f"| {fid_short} | {status} | {issues} | {priorities} | {hc} | {dim_status} |")

    add("")

    # Failures detail
    failures = [fs for fs in summary["fixtures"] if not fs["passed"]]
    if failures:
        add("## Failures Detail")
        add("")
        for fs in failures:
            add(f"### {fs['fixture_id']}")
            add("")
            if fs.get("error"):
                add(f"**Error:** {fs['error']}")
            else:
                for dim, v in fs.get("dimensions", {}).items():
                    if not v["passed"]:
                        add(f"- **{dim}**: {v['details']}")
                        add(f"  - expected: `{v['expected']}`")
                        add(f"  - actual:   `{v['actual']}`")
            add("")
    else:
        add("## All fixtures passed!")
        add("")

    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def evaluate(
    fixtures_dir: str = "tests/fixtures/golden",
    out_dir: str = "outputs/eval",
) -> Tuple[Path, Path, Path]:
    """Run all golden fixtures through the pipeline and write evaluation reports.

    Args:
        fixtures_dir: Directory containing manifest.json and fixture subdirs.
        out_dir:      Output directory for reports.

    Returns:
        Tuple of (summary_json_path, summary_md_path, fixtures_out_dir).
    """
    started_at = _utc_now_iso()
    fixtures_root = Path(fixtures_dir)
    out_root = Path(out_dir)
    fixtures_out = out_root / "fixtures"
    fixtures_out.mkdir(parents=True, exist_ok=True)

    manifest_path = fixtures_root / "manifest.json"
    if not manifest_path.exists():
        raise FileNotFoundError(f"Manifest not found: {manifest_path}")

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    fixture_entries = manifest.get("fixtures") or []

    results: List[FixtureResult] = []
    for entry in fixture_entries:
        fid = entry["id"]
        fixture_dir = fixtures_root / fid
        print(f"  Evaluating {fid} ...", end=" ", flush=True)
        result = evaluate_fixture(fixture_dir)
        status = "PASS" if result.passed else "FAIL"
        print(status)
        results.append(result)

        # Write per-fixture JSON report
        fixture_report = {
            "fixture_id": result.fixture_id,
            "description": result.description,
            "passed": result.passed,
            "actual_issue_count": result.actual_issue_count,
            "actual_cves": result.actual_cves,
            "actual_priorities": result.actual_priorities,
            "actual_healthcare_categories": result.actual_healthcare_categories,
            "error": result.error,
            "dimensions": (
                {
                    k: {
                        "passed": v.passed,
                        "expected": v.expected,
                        "actual": v.actual,
                        "details": v.details,
                    }
                    for k, v in result.dimensions.items()
                }
                if not result.error
                else {}
            ),
        }
        out_file = fixtures_out / f"{fid}.json"
        out_file.write_text(
            json.dumps(fixture_report, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

    # Build and write summary
    summary = _build_summary_json(results, started_at)
    summary_json = out_root / "summary.json"
    summary_json.write_text(
        json.dumps(summary, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    summary_md_text = _build_summary_markdown(summary)
    summary_md = out_root / "summary.md"
    summary_md.write_text(summary_md_text, encoding="utf-8")

    passed = summary["pass_count"]
    total = summary["total_fixtures"]
    print(f"\nEvaluation complete: {passed}/{total} fixtures passed")
    for dim, acc in summary["accuracy_by_dimension"].items():
        print(f"  {dim}: {acc:.1%}")

    return summary_json, summary_md, fixtures_out
