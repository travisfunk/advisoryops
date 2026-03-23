"""Phase 3, Task 3.1 — verify that all _KEYWORDS patterns actually fire.

Before the fix, every pattern used \\\\b (literal backslash-b) instead of
\\b (regex word boundary), so no keyword ever matched.  These tests prove
each pattern is now live.
"""
from __future__ import annotations

import pytest

from advisoryops.score import score_issue, _KEYWORDS


# ── helpers ────────────────────────────────────────────────────────────────

def _issue(summary: str, *, sources=None, links=None, issue_type: str = "cve") -> dict:
    return {
        "issue_id": "CVE-2024-TEST",
        "issue_type": issue_type,
        "title": "",
        "summary": summary,
        "sources": sources or ["cisa-icsma"],
        "links": links or [],
    }


def _has_keyword_label(why: list[str], fragment: str) -> bool:
    return any(fragment.lower() in w.lower() for w in why)


# ── sanity: patterns compile and actually use \\b ─────────────────────────

def test_all_keyword_patterns_compile() -> None:
    """All 11 _KEYWORDS entries should be well-formed compiled patterns."""
    assert len(_KEYWORDS) == 11
    for rx, pts, label in _KEYWORDS:
        assert hasattr(rx, "search"), f"Not a compiled pattern: {label}"
        assert pts > 0, f"Non-positive points for: {label}"


def test_keyword_patterns_use_word_boundary() -> None:
    """Spot-check that the patterns match correctly with word boundary semantics."""
    # 'dos' should NOT match inside 'doses' or 'dosage' — word boundary matters
    rx_dos = next(rx for rx, _, lbl in _KEYWORDS if "DoS" in lbl)
    assert rx_dos.search("denial of service attack"), "Should match full phrase"
    assert not rx_dos.search("dosage"), "'dosage' must not match \\bdos\\b"
    assert not rx_dos.search("doses"), "'doses' must not match \\bdos\\b"


# ── per-keyword firing tests ───────────────────────────────────────────────

def test_keyword_actively_exploited() -> None:
    r = score_issue(_issue("This vulnerability is actively exploited in the wild."))
    assert _has_keyword_label(r.why, "actively exploited"), r.why
    assert r.score >= 10 + 40  # base + actively exploited


def test_keyword_known_exploited() -> None:
    r = score_issue(_issue("Known exploited vulnerability affects multiple products."))
    assert _has_keyword_label(r.why, "KEV/known exploited"), r.why
    assert r.score >= 10 + 80


def test_keyword_rce_full_phrase() -> None:
    r = score_issue(_issue("Allows unauthenticated remote code execution on affected systems."))
    assert _has_keyword_label(r.why, "RCE"), r.why
    assert r.score >= 10 + 30


def test_keyword_rce_abbreviation() -> None:
    r = score_issue(_issue("Critical RCE in firmware component."))
    assert _has_keyword_label(r.why, "RCE"), r.why
    assert r.score >= 10 + 30


def test_keyword_auth_bypass_full() -> None:
    r = score_issue(_issue("Allows authentication bypass without valid credentials."))
    assert _has_keyword_label(r.why, "auth bypass"), r.why
    assert r.score >= 10 + 25


def test_keyword_auth_bypass_short() -> None:
    r = score_issue(_issue("Exploiting this auth bypass gives full admin access."))
    assert _has_keyword_label(r.why, "auth bypass"), r.why


def test_keyword_privilege_escalation() -> None:
    r = score_issue(_issue("Local user can achieve privilege escalation to root."))
    assert _has_keyword_label(r.why, "privilege escalation"), r.why
    assert r.score >= 10 + 20


def test_keyword_code_execution() -> None:
    r = score_issue(_issue("Crafted packet leads to arbitrary code execution."))
    assert _has_keyword_label(r.why, "code execution"), r.why
    assert r.score >= 10 + 25


def test_keyword_data_exfiltration() -> None:
    r = score_issue(_issue("Enables silent data exfiltration of patient records."))
    assert _has_keyword_label(r.why, "data exfiltration"), r.why
    assert r.score >= 10 + 15


def test_keyword_information_disclosure() -> None:
    r = score_issue(_issue("Results in information disclosure of internal file paths."))
    assert _has_keyword_label(r.why, "information disclosure"), r.why
    assert r.score >= 10 + 15


def test_keyword_sql_injection() -> None:
    r = score_issue(_issue("Login form is vulnerable to SQL injection attacks."))
    assert _has_keyword_label(r.why, "SQLi"), r.why
    assert r.score >= 10 + 15


def test_keyword_sqli_abbreviation() -> None:
    r = score_issue(_issue("Classic SQLi found in search parameter."))
    assert _has_keyword_label(r.why, "SQLi"), r.why


def test_keyword_denial_of_service() -> None:
    r = score_issue(_issue("Sending malformed packets causes denial of service."))
    assert _has_keyword_label(r.why, "DoS"), r.why
    assert r.score >= 10 + 5


def test_keyword_poc_full() -> None:
    r = score_issue(_issue("A proof of concept exploit has been published."))
    assert _has_keyword_label(r.why, "PoC"), r.why
    assert r.score >= 10 + 10


def test_keyword_poc_abbreviation() -> None:
    r = score_issue(_issue("Public PoC code available on GitHub."))
    assert _has_keyword_label(r.why, "PoC"), r.why


# ── stacking: multiple keywords add up ────────────────────────────────────

def test_multiple_keywords_stack() -> None:
    """RCE + actively exploited + NVD link should stack above P1 threshold.

    'remote code execution' triggers both the RCE pattern (+30) and the
    'code execution' pattern (+25) because the phrase contains the substring.
    base(10) + actively_exploited(40) + rce(30) + code_execution(25) + nvd(5) = 110 -> P0.
    """
    r = score_issue(_issue(
        "An actively exploited vulnerability allows remote code execution.",
        links=["https://nvd.nist.gov/vuln/detail/CVE-2024-TEST"],
    ))
    assert r.score >= 100, f"Expected >=100, got {r.score}. why={r.why}"
    assert r.priority == "P0", f"Expected P0, got {r.priority}"
    assert _has_keyword_label(r.why, "actively exploited")
    assert _has_keyword_label(r.why, "RCE")


def test_kev_source_plus_rce_reaches_p0() -> None:
    """KEV source (+80) + RCE keyword (+30) + CVE base (+10) = 120 -> P0."""
    r = score_issue(_issue(
        "Remote code execution in widely deployed component.",
        sources=["cisa-kev-json"],
    ))
    # base(10) + kev_source(80) + rce(30) = 120 -> P0
    assert r.score >= 120, f"Expected >=120, got {r.score}. why={r.why}"
    assert r.priority == "P0", f"Expected P0, got {r.priority}"


# ── build plan verification case ──────────────────────────────────────────

def test_build_plan_verification_case() -> None:
    """Exact scenario from the build plan Task 3.1 verification command."""
    issue = {
        "issue_id": "CVE-2024-TEST",
        "issue_type": "cve",
        "title": "Remote Code Execution in Medical Device",
        "summary": "An actively exploited vulnerability allows remote code execution",
        "sources": ["cisa-icsma"],
        "links": ["https://nvd.nist.gov/vuln/detail/CVE-2024-TEST"],
    }
    result = score_issue(issue)
    assert result.score > 20, f"Score too low ({result.score}), keywords not matching"
    assert any(
        "RCE" in w or "rce" in w.lower() or "remote code" in w.lower() or "code execution" in w.lower()
        for w in result.why
    ), f"RCE keyword not detected in: {result.why}"
