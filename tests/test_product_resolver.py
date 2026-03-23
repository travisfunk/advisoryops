"""Tests for advisoryops.product_resolver.resolve_product."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from advisoryops.product_resolver import resolve_product, _tokenise, _match_quality


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_issues(path: Path, issues: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as f:
        for issue in issues:
            f.write(json.dumps(issue, ensure_ascii=False) + "\n")


FIXTURE_ISSUES = [
    {
        "issue_id": "ICSMA-2026-001",
        "title": "Baxter Sigma Spectrum infusion pump remote code execution",
        "summary": "A buffer overflow in the Sigma Spectrum wireless module allows RCE without authentication.",
        "score": 90,
        "priority": "P0",
        "sources": ["cisa-icsma"],
        "canonical_link": "https://example.test/ICSMA-2026-001",
        "published_dates": ["2026-03-01"],
    },
    {
        "issue_id": "ICSMA-2026-002",
        "title": "Philips MX800 patient monitor denial of service",
        "summary": "A crafted DICOM packet causes the MX800 bedside monitor to reboot.",
        "score": 70,
        "priority": "P1",
        "sources": ["cisa-icsma", "philips-psirt"],
        "canonical_link": "https://example.test/ICSMA-2026-002",
        "published_dates": ["2026-03-05"],
    },
    {
        "issue_id": "ICSMA-2026-003",
        "title": "Contec CMS8000 patient monitor hard-coded credentials",
        "summary": "The CMS8000 contains hard-coded backdoor credentials exposing patient data.",
        "score": 85,
        "priority": "P0",
        "sources": ["cisa-icsma", "fda-mds2"],
        "canonical_link": "https://example.test/ICSMA-2026-003",
        "published_dates": ["2026-03-10"],
    },
    {
        "issue_id": "ICSMA-2026-004",
        "title": "Honeywell Dolphin scanner firmware update required",
        "summary": "Multiple CVEs affect the Dolphin barcode scanner; firmware v5.2 resolves all issues.",
        "score": 40,
        "priority": "P2",
        "sources": ["ics-cert"],
        "canonical_link": "https://example.test/ICSMA-2026-004",
        "published_dates": ["2026-03-12"],
    },
    {
        "issue_id": "ICSMA-2026-005",
        "title": "GE HealthCare Vivid ultrasound SQL injection",
        "summary": "SQL injection in the Vivid series web interface allows database exfiltration.",
        "score": 60,
        "priority": "P1",
        "sources": ["ge-psirt"],
        "canonical_link": "https://example.test/ICSMA-2026-005",
        "published_dates": ["2026-03-14"],
    },
    {
        "issue_id": "ICSMA-2026-006",
        "title": "Low severity informational bulletin",
        "summary": "No known exploits. Informational advisory only.",
        "score": 5,
        "priority": "P3",
        "sources": ["vendor-bulletin"],
        "canonical_link": "https://example.test/ICSMA-2026-006",
        "published_dates": ["2026-03-15"],
    },
]


# ---------------------------------------------------------------------------
# Unit tests for internal helpers
# ---------------------------------------------------------------------------

def test_tokenise_basic() -> None:
    assert _tokenise("Sigma Spectrum") == ["sigma", "spectrum"]


def test_tokenise_strips_short() -> None:
    # single-char tokens dropped (MIN_TOKEN_LEN=2)
    tokens = _tokenise("A big device")
    assert "a" not in tokens
    assert "big" in tokens
    assert "device" in tokens


def test_tokenise_handles_punctuation() -> None:
    assert _tokenise("CVE-2026-1234") == ["cve", "2026", "1234"]


def test_match_quality_phrase() -> None:
    assert _match_quality(["sigma", "spectrum"], "Baxter Sigma Spectrum pump") == 3


def test_match_quality_all_tokens() -> None:
    # tokens present but not adjacent → quality 2
    q = _match_quality(["sigma", "pump"], "The sigma wireless pump device")
    assert q == 2


def test_match_quality_partial() -> None:
    q = _match_quality(["sigma", "spectrum"], "sigma infusion pump")
    assert q == 1


def test_match_quality_no_match() -> None:
    assert _match_quality(["sigma", "spectrum"], "unrelated infusion device") == 0


# ---------------------------------------------------------------------------
# resolve_product tests
# ---------------------------------------------------------------------------

def test_resolve_product_title_match(tmp_path: Path) -> None:
    issues_file = tmp_path / "issues.jsonl"
    _write_issues(issues_file, FIXTURE_ISSUES)

    results = resolve_product("Sigma Spectrum", issues_path=str(issues_file))

    assert len(results) >= 1
    ids = [r["issue_id"] for r in results]
    assert "ICSMA-2026-001" in ids, "Sigma Spectrum title match not found"


def test_resolve_product_summary_match(tmp_path: Path) -> None:
    issues_file = tmp_path / "issues.jsonl"
    _write_issues(issues_file, FIXTURE_ISSUES)

    # "CMS8000" appears in both title and summary of issue 003
    results = resolve_product("CMS8000", issues_path=str(issues_file))
    ids = [r["issue_id"] for r in results]
    assert "ICSMA-2026-003" in ids


def test_resolve_product_match_field_title(tmp_path: Path) -> None:
    issues_file = tmp_path / "issues.jsonl"
    _write_issues(issues_file, FIXTURE_ISSUES)

    results = resolve_product("MX800", issues_path=str(issues_file))
    assert results, "Expected at least one result for MX800"
    mx800 = next((r for r in results if r["issue_id"] == "ICSMA-2026-002"), None)
    assert mx800 is not None
    assert mx800["match_field"] == "title"


def test_resolve_product_match_field_summary_only(tmp_path: Path) -> None:
    """A query that matches only in summary should report match_field='summary'."""
    issues_file = tmp_path / "issues.jsonl"
    # custom issue where query word is only in summary
    _write_issues(issues_file, [
        {
            "issue_id": "TEST-001",
            "title": "Unrelated device advisory",
            "summary": "The widgetpro firmware has a heap overflow.",
            "score": 50,
            "priority": "P1",
            "sources": ["test-src"],
            "published_dates": ["2026-01-01"],
        }
    ])

    results = resolve_product("widgetpro", issues_path=str(issues_file))
    assert results
    assert results[0]["match_field"] == "summary"


def test_resolve_product_sorted_by_score_desc(tmp_path: Path) -> None:
    issues_file = tmp_path / "issues.jsonl"
    _write_issues(issues_file, FIXTURE_ISSUES)

    # "monitor" appears in both MX800 (score=70) and CMS8000 (score=85)
    results = resolve_product("monitor", issues_path=str(issues_file))
    assert len(results) >= 2
    scores = [r["score"] for r in results]
    assert scores == sorted(scores, reverse=True), "Results not sorted by score desc"


def test_resolve_product_top_limit(tmp_path: Path) -> None:
    issues_file = tmp_path / "issues.jsonl"
    # 10 identical issues that all match "pump"
    issues = [
        {
            "issue_id": f"PUMP-{i:03d}",
            "title": f"Pump vulnerability {i}",
            "summary": "Generic pump advisory.",
            "score": i * 10,
            "priority": "P1",
            "sources": ["test"],
            "published_dates": ["2026-01-01"],
        }
        for i in range(10)
    ]
    _write_issues(issues_file, issues)

    results = resolve_product("pump", issues_path=str(issues_file), top=3)
    assert len(results) == 3


def test_resolve_product_no_match(tmp_path: Path) -> None:
    issues_file = tmp_path / "issues.jsonl"
    _write_issues(issues_file, FIXTURE_ISSUES)

    results = resolve_product("zzznomatchxyz", issues_path=str(issues_file))
    assert results == []


def test_resolve_product_case_insensitive(tmp_path: Path) -> None:
    issues_file = tmp_path / "issues.jsonl"
    _write_issues(issues_file, FIXTURE_ISSUES)

    upper = resolve_product("SIGMA SPECTRUM", issues_path=str(issues_file))
    lower = resolve_product("sigma spectrum", issues_path=str(issues_file))
    mixed = resolve_product("Sigma Spectrum", issues_path=str(issues_file))

    assert [r["issue_id"] for r in upper] == [r["issue_id"] for r in lower]
    assert [r["issue_id"] for r in upper] == [r["issue_id"] for r in mixed]


def test_resolve_product_result_keys(tmp_path: Path) -> None:
    issues_file = tmp_path / "issues.jsonl"
    _write_issues(issues_file, FIXTURE_ISSUES)

    results = resolve_product("Dolphin scanner", issues_path=str(issues_file))
    assert results
    r = results[0]
    assert set(r.keys()) == {"issue_id", "title", "score", "priority", "sources", "match_field"}
    assert isinstance(r["sources"], list)
    assert isinstance(r["score"], int)


def test_resolve_product_file_not_found() -> None:
    with pytest.raises(FileNotFoundError):
        resolve_product("Sigma Spectrum", issues_path="/nonexistent/path/issues.jsonl")


def test_resolve_product_empty_query(tmp_path: Path) -> None:
    issues_file = tmp_path / "issues.jsonl"
    _write_issues(issues_file, FIXTURE_ISSUES)

    # Empty query produces no tokens → empty result
    results = resolve_product("", issues_path=str(issues_file))
    assert results == []


def test_resolve_product_issue_id_match(tmp_path: Path) -> None:
    """Searching by raw issue_id fragment should match via issue_id field."""
    issues_file = tmp_path / "issues.jsonl"
    _write_issues(issues_file, FIXTURE_ISSUES)

    results = resolve_product("ICSMA-2026-005", issues_path=str(issues_file))
    ids = [r["issue_id"] for r in results]
    assert "ICSMA-2026-005" in ids


# ---------------------------------------------------------------------------
# CLI integration test
# ---------------------------------------------------------------------------

def test_cli_lookup_command(tmp_path: Path, monkeypatch, capsys) -> None:
    """The 'lookup' CLI command prints results and exits 0."""
    from advisoryops.cli import build_parser

    issues_file = tmp_path / "issues.jsonl"
    _write_issues(issues_file, FIXTURE_ISSUES)

    monkeypatch.chdir(tmp_path)
    parser = build_parser()
    args = parser.parse_args([
        "lookup",
        "--product", "Sigma Spectrum",
        "--issues-path", str(issues_file),
        "--top", "5",
    ])
    rc = args.fn(args)
    assert rc == 0
    captured = capsys.readouterr()
    assert "ICSMA-2026-001" in captured.out


def test_cli_lookup_no_match(tmp_path: Path, monkeypatch, capsys) -> None:
    issues_file = tmp_path / "issues.jsonl"
    _write_issues(issues_file, FIXTURE_ISSUES)

    monkeypatch.chdir(tmp_path)
    from advisoryops.cli import build_parser
    parser = build_parser()
    args = parser.parse_args([
        "lookup",
        "--product", "zzzunknownproduct",
        "--issues-path", str(issues_file),
    ])
    rc = args.fn(args)
    assert rc == 0
    captured = capsys.readouterr()
    assert "No matches" in captured.out


def test_cli_lookup_json_flag(tmp_path: Path, monkeypatch, capsys) -> None:
    issues_file = tmp_path / "issues.jsonl"
    _write_issues(issues_file, FIXTURE_ISSUES)

    monkeypatch.chdir(tmp_path)
    from advisoryops.cli import build_parser
    parser = build_parser()
    args = parser.parse_args([
        "lookup",
        "--product", "Dolphin scanner",
        "--issues-path", str(issues_file),
        "--json",
    ])
    args.fn(args)
    captured = capsys.readouterr()
    out = captured.out
    # The JSON block starts on a line that begins with "[" (not indented)
    lines = out.splitlines(keepends=True)
    json_start_line = next(
        (i for i, ln in enumerate(lines) if ln.startswith("[")), None
    )
    assert json_start_line is not None, f"No top-level JSON array in output:\n{out}"
    parsed = json.loads("".join(lines[json_start_line:]))
    assert isinstance(parsed, list)
    assert len(parsed) >= 1
    assert "issue_id" in parsed[0]
