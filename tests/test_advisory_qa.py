"""Tests for advisoryops.advisory_qa.answer_question."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from advisoryops.advisory_qa import (
    answer_question,
    _tokenise,
    _relevance_score,
    _find_relevant_issues,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

FIXTURE_ISSUES = [
    {
        "issue_id": "ICSMA-2026-101",
        "title": "Baxter Sigma Spectrum infusion pump remote code execution",
        "summary": (
            "A buffer overflow in the Sigma Spectrum wireless module allows unauthenticated "
            "remote code execution on the infusion pump. No patch available. CISA rates Critical."
        ),
        "score": 95,
        "priority": "P0",
        "sources": ["cisa-icsma"],
        "published_dates": ["2026-03-01"],
    },
    {
        "issue_id": "ICSMA-2026-102",
        "title": "Philips MX800 patient monitor denial of service",
        "summary": (
            "A crafted DICOM packet causes the MX800 bedside monitor to reboot unexpectedly, "
            "interrupting patient monitoring."
        ),
        "score": 70,
        "priority": "P1",
        "sources": ["cisa-icsma", "philips-psirt"],
        "published_dates": ["2026-03-05"],
    },
    {
        "issue_id": "ICSMA-2026-103",
        "title": "Contec CMS8000 patient monitor hard-coded credentials",
        "summary": (
            "The CMS8000 contains hard-coded backdoor credentials exposing patient data "
            "remotely. Vendor has released firmware 2.0.1 as a fix."
        ),
        "score": 85,
        "priority": "P0",
        "sources": ["cisa-icsma", "fda-mds2"],
        "published_dates": ["2026-03-10"],
    },
    {
        "issue_id": "ICSMA-2026-104",
        "title": "Honeywell Dolphin scanner firmware update",
        "summary": (
            "Multiple CVEs affect the Dolphin barcode scanner; firmware v5.2 resolves all issues."
        ),
        "score": 40,
        "priority": "P2",
        "sources": ["ics-cert"],
        "published_dates": ["2026-03-12"],
    },
    {
        "issue_id": "ICSMA-2026-105",
        "title": "GE HealthCare Vivid ultrasound SQL injection",
        "summary": (
            "SQL injection in the Vivid series web interface allows unauthenticated "
            "database exfiltration. Patch is available."
        ),
        "score": 60,
        "priority": "P1",
        "sources": ["ge-psirt"],
        "published_dates": ["2026-03-14"],
    },
]


def _write_issues(path: Path, issues: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as f:
        for issue in issues:
            f.write(json.dumps(issue, ensure_ascii=False) + "\n")


def _mock_call_fn(answer: str = "Based on the context, two infusion pumps have critical vulnerabilities.",
                  supporting: list[dict] | None = None,
                  gaps: list[str] | None = None):
    """Factory that returns a zero-argument callable mimicking an AI response."""
    if supporting is None:
        supporting = [{"issue_id": "ICSMA-2026-101", "why_relevant": "Critical RCE on infusion pump."}]
    if gaps is None:
        gaps = []

    result = {
        "answer": answer,
        "supporting_issues": supporting,
        "evidence_gaps": gaps,
    }

    def _fn() -> dict:
        return {"result": result, "model": "gpt-4o-mini", "tokens_used": 120}

    return _fn


# ---------------------------------------------------------------------------
# Unit tests for internal helpers
# ---------------------------------------------------------------------------

def test_tokenise_question() -> None:
    tokens = _tokenise("Which infusion pumps have critical vulnerabilities?")
    assert "infusion" in tokens
    assert "pumps" in tokens
    assert "critical" in tokens
    assert "vulnerabilities" in tokens


def test_relevance_score_title_weight() -> None:
    issue = {"title": "infusion pump vulnerability", "summary": "low severity"}
    # "infusion" and "pump" both in title → score = 2+2 = 4
    score = _relevance_score(["infusion", "pump"], issue)
    assert score == 4


def test_relevance_score_summary_weight() -> None:
    issue = {"title": "unrelated device advisory", "summary": "infusion pump affected"}
    # "infusion" and "pump" both in summary → score = 1+1 = 2
    score = _relevance_score(["infusion", "pump"], issue)
    assert score == 2


def test_relevance_score_mixed() -> None:
    issue = {"title": "infusion pump advisory", "summary": "critical remote code execution"}
    # "infusion" in title (+2), "critical" in summary (+1) → 3
    score = _relevance_score(["infusion", "critical"], issue)
    assert score == 3


def test_relevance_score_no_match() -> None:
    issue = {"title": "network switch firmware", "summary": "VLAN misconfiguration"}
    assert _relevance_score(["infusion", "pump"], issue) == 0


def test_find_relevant_issues_top_k() -> None:
    tokens = _tokenise("infusion pump")
    results = _find_relevant_issues(tokens, FIXTURE_ISSUES, top_k=2)
    assert len(results) <= 2
    # Sigma Spectrum issue should be top result (infusion in title + summary)
    assert results[0]["issue_id"] == "ICSMA-2026-101"


def test_find_relevant_issues_empty_tokens_falls_back_to_score() -> None:
    results = _find_relevant_issues([], FIXTURE_ISSUES, top_k=3)
    assert len(results) == 3
    scores = [r["score"] for r in results]
    assert scores == sorted(scores, reverse=True)


# ---------------------------------------------------------------------------
# answer_question tests
# ---------------------------------------------------------------------------

def test_answer_question_returns_required_keys(tmp_path: Path) -> None:
    issues_file = tmp_path / "issues.jsonl"
    _write_issues(issues_file, FIXTURE_ISSUES)

    result = answer_question(
        "Which infusion pumps have critical vulnerabilities?",
        issues_path=str(issues_file),
        top_k=3,
        cache_root=str(tmp_path / "cache"),
        _call_fn=_mock_call_fn(),
    )

    required_keys = {"question", "answer", "supporting_issues", "evidence_gaps",
                     "model", "tokens_used", "from_cache"}
    assert required_keys == set(result.keys())


def test_answer_question_answer_is_nonempty_string(tmp_path: Path) -> None:
    issues_file = tmp_path / "issues.jsonl"
    _write_issues(issues_file, FIXTURE_ISSUES)

    result = answer_question(
        "What are the critical vulnerabilities?",
        issues_path=str(issues_file),
        top_k=3,
        cache_root=str(tmp_path / "cache"),
        _call_fn=_mock_call_fn(answer="The Sigma Spectrum pump has a critical RCE (ICSMA-2026-101)."),
    )

    assert isinstance(result["answer"], str)
    assert len(result["answer"]) > 0


def test_answer_question_supporting_issues_shape(tmp_path: Path) -> None:
    issues_file = tmp_path / "issues.jsonl"
    _write_issues(issues_file, FIXTURE_ISSUES)

    result = answer_question(
        "Infusion pump vulnerabilities",
        issues_path=str(issues_file),
        top_k=3,
        cache_root=str(tmp_path / "cache"),
        _call_fn=_mock_call_fn(
            supporting=[{"issue_id": "ICSMA-2026-101", "why_relevant": "RCE on infusion pump."}]
        ),
    )

    assert isinstance(result["supporting_issues"], list)
    for si in result["supporting_issues"]:
        assert "issue_id" in si
        assert "title" in si
        assert "score" in si
        assert "priority" in si
        assert "why_relevant" in si


def test_answer_question_supporting_issues_enriched_with_local_data(tmp_path: Path) -> None:
    """title/score/priority in supporting_issues come from local corpus, not AI."""
    issues_file = tmp_path / "issues.jsonl"
    _write_issues(issues_file, FIXTURE_ISSUES)

    result = answer_question(
        "infusion pump",
        issues_path=str(issues_file),
        top_k=5,
        cache_root=str(tmp_path / "cache"),
        _call_fn=_mock_call_fn(
            supporting=[{"issue_id": "ICSMA-2026-101", "why_relevant": "Critical pump issue."}]
        ),
    )

    si = result["supporting_issues"][0]
    assert si["issue_id"] == "ICSMA-2026-101"
    assert si["title"] == "Baxter Sigma Spectrum infusion pump remote code execution"
    assert si["score"] == 95
    assert si["priority"] == "P0"


def test_answer_question_top_k_limits_context(tmp_path: Path) -> None:
    """The call_fn should only see top_k issues in the prompt (verify via call count tracking)."""
    issues_file = tmp_path / "issues.jsonl"
    _write_issues(issues_file, FIXTURE_ISSUES)

    calls: list[dict] = []

    def _tracking_call_fn():
        # Capture that we were called; return minimal valid response
        calls.append({"called": True})
        return {
            "result": {"answer": "Limited context answer.", "supporting_issues": [], "evidence_gaps": []},
            "model": "gpt-4o-mini",
            "tokens_used": 50,
        }

    answer_question(
        "patient monitor",
        issues_path=str(issues_file),
        top_k=2,  # only 2 issues in context
        cache_root=str(tmp_path / "cache"),
        _call_fn=_tracking_call_fn,
    )
    assert len(calls) == 1  # called exactly once


def test_answer_question_empty_corpus_graceful(tmp_path: Path) -> None:
    """Empty issues file returns a graceful no-data response without crashing."""
    issues_file = tmp_path / "issues.jsonl"
    issues_file.write_text("", encoding="utf-8")

    # _call_fn should NOT be called for empty corpus
    called = []

    def _should_not_be_called():
        called.append(True)
        return {"result": {}, "model": "gpt-4o-mini", "tokens_used": 0}

    result = answer_question(
        "What are the critical vulnerabilities?",
        issues_path=str(issues_file),
        top_k=5,
        cache_root=str(tmp_path / "cache"),
        _call_fn=_should_not_be_called,
    )

    assert not called, "_call_fn must not be invoked for empty corpus"
    assert result["answer"] != ""
    assert result["supporting_issues"] == []
    assert len(result["evidence_gaps"]) >= 1


def test_answer_question_file_not_found() -> None:
    with pytest.raises(FileNotFoundError):
        answer_question(
            "Any question",
            issues_path="/nonexistent/path/issues.jsonl",
            _call_fn=_mock_call_fn(),
        )


def test_answer_question_call_fn_injection(tmp_path: Path) -> None:
    """_call_fn override is used instead of live API."""
    issues_file = tmp_path / "issues.jsonl"
    _write_issues(issues_file, FIXTURE_ISSUES)

    expected_answer = "Mock answer from injected call function."
    result = answer_question(
        "What monitors are affected?",
        issues_path=str(issues_file),
        top_k=3,
        cache_root=str(tmp_path / "cache"),
        _call_fn=_mock_call_fn(answer=expected_answer),
    )

    assert result["answer"] == expected_answer
    assert result["from_cache"] is False
    assert result["model"] == "gpt-4o-mini"
    assert result["tokens_used"] == 120


def test_answer_question_caching(tmp_path: Path) -> None:
    """Second call with same question returns from_cache=True."""
    issues_file = tmp_path / "issues.jsonl"
    _write_issues(issues_file, FIXTURE_ISSUES)
    cache_dir = tmp_path / "cache"

    call_count = [0]

    def _counting_call_fn():
        call_count[0] += 1
        return {
            "result": {
                "answer": "Cached answer about infusion pumps.",
                "supporting_issues": [],
                "evidence_gaps": [],
            },
            "model": "gpt-4o-mini",
            "tokens_used": 80,
        }

    # First call — live
    r1 = answer_question(
        "infusion pump vulnerabilities",
        issues_path=str(issues_file),
        top_k=3,
        cache_root=str(cache_dir),
        _call_fn=_counting_call_fn,
    )
    assert r1["from_cache"] is False
    assert call_count[0] == 1

    # Second call — should hit cache
    r2 = answer_question(
        "infusion pump vulnerabilities",
        issues_path=str(issues_file),
        top_k=3,
        cache_root=str(cache_dir),
        _call_fn=_counting_call_fn,
    )
    assert r2["from_cache"] is True
    assert call_count[0] == 1  # call_fn not invoked again


def test_answer_question_evidence_gaps_populated(tmp_path: Path) -> None:
    issues_file = tmp_path / "issues.jsonl"
    _write_issues(issues_file, FIXTURE_ISSUES)

    gaps = ["Patch availability for CMS8000 unclear.", "Exploit status not confirmed."]
    result = answer_question(
        "Is there a patch for the Contec monitor?",
        issues_path=str(issues_file),
        top_k=3,
        cache_root=str(tmp_path / "cache"),
        _call_fn=_mock_call_fn(gaps=gaps),
    )

    assert result["evidence_gaps"] == gaps


def test_answer_question_different_top_k_different_cache(tmp_path: Path) -> None:
    """top_k is part of the cache key — different top_k = different cache entry."""
    issues_file = tmp_path / "issues.jsonl"
    _write_issues(issues_file, FIXTURE_ISSUES)
    cache_dir = tmp_path / "cache"
    call_count = [0]

    def _fn():
        call_count[0] += 1
        return {
            "result": {"answer": "answer", "supporting_issues": [], "evidence_gaps": []},
            "model": "gpt-4o-mini",
            "tokens_used": 10,
        }

    answer_question("monitor vulnerabilities", issues_path=str(issues_file),
                    top_k=3, cache_root=str(cache_dir), _call_fn=_fn)
    answer_question("monitor vulnerabilities", issues_path=str(issues_file),
                    top_k=5, cache_root=str(cache_dir), _call_fn=_fn)

    assert call_count[0] == 2  # both are cache misses (different top_k)


# ---------------------------------------------------------------------------
# CLI tests
# ---------------------------------------------------------------------------

def test_cli_ask_human_readable_output(tmp_path: Path, monkeypatch, capsys) -> None:
    issues_file = tmp_path / "issues.jsonl"
    _write_issues(issues_file, FIXTURE_ISSUES)

    from advisoryops.cli import build_parser
    from advisoryops import advisory_qa

    # Patch answer_question to avoid needing the real AI cache path logic
    def _mock_answer(question, issues_path, top_k, model, cache_root=None, _call_fn=None):
        return {
            "question": question,
            "answer": "The Sigma Spectrum pump (ICSMA-2026-101) has a critical RCE vulnerability.",
            "supporting_issues": [
                {"issue_id": "ICSMA-2026-101", "title": "Baxter Sigma Spectrum infusion pump RCE",
                 "score": 95, "priority": "P0", "why_relevant": "Critical RCE."},
            ],
            "evidence_gaps": [],
            "model": "gpt-4o-mini",
            "tokens_used": 100,
            "from_cache": False,
        }

    monkeypatch.setattr(advisory_qa, "answer_question", _mock_answer)
    # Also patch the import in cli
    import advisoryops.cli as cli_mod
    monkeypatch.setattr(cli_mod, "answer_question", _mock_answer)

    monkeypatch.chdir(tmp_path)
    parser = build_parser()
    args = parser.parse_args([
        "ask",
        "--question", "Which infusion pumps have critical vulnerabilities?",
        "--issues-path", str(issues_file),
        "--top-k", "3",
    ])
    rc = args.fn(args)
    assert rc == 0

    captured = capsys.readouterr()
    out = captured.out
    assert "Question:" in out
    assert "Answer:" in out
    assert "Supporting issues:" in out
    assert "ICSMA-2026-101" in out
    assert "Evidence gaps:" in out


def test_cli_ask_json_flag(tmp_path: Path, monkeypatch, capsys) -> None:
    issues_file = tmp_path / "issues.jsonl"
    _write_issues(issues_file, FIXTURE_ISSUES)

    from advisoryops import advisory_qa
    import advisoryops.cli as cli_mod

    mock_response = {
        "question": "test question",
        "answer": "Test answer.",
        "supporting_issues": [],
        "evidence_gaps": ["no data"],
        "model": "gpt-4o-mini",
        "tokens_used": 50,
        "from_cache": False,
    }

    def _mock_answer(question, issues_path, top_k, model, cache_root=None, _call_fn=None):
        return mock_response

    monkeypatch.setattr(advisory_qa, "answer_question", _mock_answer)
    monkeypatch.setattr(cli_mod, "answer_question", _mock_answer)

    monkeypatch.chdir(tmp_path)
    from advisoryops.cli import build_parser
    parser = build_parser()
    args = parser.parse_args([
        "ask",
        "--question", "test question",
        "--issues-path", str(issues_file),
        "--json",
    ])
    rc = args.fn(args)
    assert rc == 0

    captured = capsys.readouterr()
    parsed = json.loads(captured.out)
    assert parsed["question"] == "test question"
    assert "answer" in parsed
    assert "supporting_issues" in parsed
    assert "evidence_gaps" in parsed


def test_cli_ask_no_match_corpus(tmp_path: Path, monkeypatch, capsys) -> None:
    """ask command on empty corpus exits 0 with graceful message."""
    issues_file = tmp_path / "issues.jsonl"
    issues_file.write_text("", encoding="utf-8")

    monkeypatch.chdir(tmp_path)
    from advisoryops.cli import build_parser
    parser = build_parser()
    args = parser.parse_args([
        "ask",
        "--question", "Any question",
        "--issues-path", str(issues_file),
    ])
    rc = args.fn(args)
    assert rc == 0
    out = capsys.readouterr().out
    assert "Answer:" in out


# ---------------------------------------------------------------------------
# Sample output demonstration (not a strict assertion test)
# ---------------------------------------------------------------------------

def test_sample_answer_output(tmp_path: Path, capsys) -> None:
    """Print a representative answer_question() output using a mock call."""
    issues_file = tmp_path / "issues.jsonl"
    _write_issues(issues_file, FIXTURE_ISSUES)

    result = answer_question(
        "Which infusion pumps have critical vulnerabilities?",
        issues_path=str(issues_file),
        top_k=3,
        cache_root=str(tmp_path / "cache"),
        _call_fn=_mock_call_fn(
            answer=(
                "The Baxter Sigma Spectrum infusion pump (ICSMA-2026-101) has a critical "
                "remote code execution vulnerability rated P0 by CISA. A buffer overflow in the "
                "wireless module allows unauthenticated access. No patch is currently available."
            ),
            supporting=[
                {"issue_id": "ICSMA-2026-101", "why_relevant": "Critical RCE on infusion pump, no patch."},
            ],
            gaps=[],
        ),
    )

    print("\n--- Sample answer_question() output ---")
    print(json.dumps(result, indent=2, ensure_ascii=False))
    print("---")

    assert result["question"] == "Which infusion pumps have critical vulnerabilities?"
    assert "ICSMA-2026-101" in result["answer"]
    assert result["supporting_issues"][0]["score"] == 95
    assert result["from_cache"] is False
