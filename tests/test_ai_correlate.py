"""Tests for advisoryops.ai_correlate — Tasks 2.1 and 2.2."""
from __future__ import annotations

import pytest

from advisoryops.ai_correlate import (
    MergeDecision,
    _cve_overlap,
    _date_proximity_score,
    _jaccard,
    _summary_jaccard,
    _tokenize,
    _vendor_product_tokens,
    ai_merge_decision,
    find_merge_candidates,
)


# ---------------------------------------------------------------------------
# Unit tests — helper functions
# ---------------------------------------------------------------------------

def test_jaccard_identical():
    s = {"alpha", "beta", "gamma"}
    assert _jaccard(s, s) == 1.0


def test_jaccard_disjoint():
    assert _jaccard({"a", "b"}, {"c", "d"}) == 0.0


def test_jaccard_partial():
    score = _jaccard({"a", "b", "c"}, {"b", "c", "d"})
    # intersection=2, union=4 → 0.5
    assert abs(score - 0.5) < 1e-9


def test_jaccard_both_empty():
    assert _jaccard(set(), set()) == 0.0


def test_tokenize_drops_stopwords_and_short():
    tokens = _tokenize("A buffer overflow in the device firmware")
    assert "a" not in tokens
    assert "in" not in tokens
    assert "the" not in tokens
    assert "buffer" in tokens
    assert "overflow" in tokens
    assert "device" in tokens
    assert "firmware" in tokens


def test_tokenize_lowercases():
    tokens = _tokenize("Philips IntelliSpace PACS")
    assert "philips" in tokens
    assert "intellispace" in tokens
    assert "pacs" in tokens


# ---------------------------------------------------------------------------
# Unit tests — CVE overlap
# ---------------------------------------------------------------------------

def test_cve_overlap_full():
    a = {"cves": ["CVE-2024-1234", "CVE-2024-5678"]}
    b = {"cves": ["CVE-2024-1234", "CVE-2024-5678"]}
    assert _cve_overlap(a, b) == 1.0


def test_cve_overlap_none_when_both_have_cves():
    a = {"cves": ["CVE-2024-0001"]}
    b = {"cves": ["CVE-2024-9999"]}
    assert _cve_overlap(a, b) == 0.0


def test_cve_overlap_both_empty():
    assert _cve_overlap({}, {}) == 0.0


def test_cve_overlap_partial():
    a = {"cves": ["CVE-2024-1111", "CVE-2024-2222"]}
    b = {"cves": ["CVE-2024-2222", "CVE-2024-3333"]}
    # intersection=1, union=3 → 1/3
    assert abs(_cve_overlap(a, b) - 1 / 3) < 1e-9


# ---------------------------------------------------------------------------
# Unit tests — date proximity
# ---------------------------------------------------------------------------

def test_date_proximity_same_date():
    a = {"published_dates": ["2024-06-01"]}
    b = {"published_dates": ["2024-06-01"]}
    assert _date_proximity_score(a, b) == 1.0


def test_date_proximity_within_window():
    a = {"published_dates": ["2024-06-01"]}
    b = {"published_dates": ["2024-07-01"]}  # 30 days apart, within 90-day window
    assert _date_proximity_score(a, b) == 1.0


def test_date_proximity_outside_double_window():
    a = {"published_dates": ["2024-01-01"]}
    b = {"published_dates": ["2025-01-01"]}  # 365 days, well beyond 2× window
    assert _date_proximity_score(a, b) == 0.0


def test_date_proximity_missing_date():
    # When one or both dates are unknown, returns 0.5 (neutral)
    a = {"published_dates": ["2024-06-01"]}
    b = {}
    assert _date_proximity_score(a, b) == 0.5


# ---------------------------------------------------------------------------
# Test Case 1 — High-confidence merge candidate (same product, overlapping CVE)
# ---------------------------------------------------------------------------

CISA_ICSMA_PHILIPS = {
    "issue_id": "CVE-2024-1234",
    "issue_type": "cve",
    "cves": ["CVE-2024-1234"],
    "title": "Philips IntelliSpace Cardiovascular Remote Code Execution",
    "summary": (
        "A critical vulnerability in Philips IntelliSpace Cardiovascular (ISCV) "
        "allows unauthenticated remote code execution. No patch available. "
        "Vendor recommends network segmentation as interim mitigation."
    ),
    "sources": ["cisa-icsma"],
    "published_dates": ["2024-03-12"],
}

VENDOR_PSIRT_PHILIPS = {
    "issue_id": "UNK-aabbcc001122",
    "issue_type": "unknown",
    "cves": ["CVE-2024-1234"],
    "title": "CISA Advisory: Philips ISCV Vulnerability",
    "summary": (
        "Remote access vulnerability in Philips IntelliSpace platform. "
        "Critical severity, no patch. Segmentation recommended."
    ),
    "sources": ["philips-psirt"],
    "published_dates": ["2024-03-15"],
}


def test_find_merge_candidates_high_confidence_pair():
    """Two issues sharing a CVE and product tokens should be a candidate."""
    candidates = find_merge_candidates([CISA_ICSMA_PHILIPS, VENDOR_PSIRT_PHILIPS])
    assert len(candidates) >= 1
    id_a, id_b, score = candidates[0]
    assert {id_a, id_b} == {"CVE-2024-1234", "UNK-aabbcc001122"}
    assert score >= 0.40, f"Expected high score, got {score}"


# ---------------------------------------------------------------------------
# Test Case 2 — Issues with different CVEs should NOT be candidates
# ---------------------------------------------------------------------------

ISSUE_CISCO_CVE = {
    "issue_id": "CVE-2024-5001",
    "issue_type": "cve",
    "cves": ["CVE-2024-5001"],
    "title": "Cisco IOS Remote Code Execution",
    "summary": "Buffer overflow in Cisco IOS XE allows remote code execution.",
    "sources": ["cisa-ics"],
    "published_dates": ["2024-04-01"],
}

ISSUE_PALO_CVE = {
    "issue_id": "CVE-2024-9999",
    "issue_type": "cve",
    "cves": ["CVE-2024-9999"],
    "title": "Palo Alto PAN-OS Authentication Bypass",
    "summary": "Authentication bypass in Palo Alto PAN-OS allows privilege escalation.",
    "sources": ["cisa-ics"],
    "published_dates": ["2024-04-02"],
}


def test_find_merge_candidates_different_cves_not_candidate():
    """Issues with non-overlapping CVE sets should never be merge candidates."""
    candidates = find_merge_candidates([ISSUE_CISCO_CVE, ISSUE_PALO_CVE])
    # The composite scorer hard-penalises non-overlapping CVE sets
    assert candidates == []


# ---------------------------------------------------------------------------
# Test Case 3 — Unknown issues: same product family, no CVEs, close in time
# ---------------------------------------------------------------------------

UNKNOWN_A = {
    "issue_id": "UNK-aaa111",
    "issue_type": "unknown",
    "cves": [],
    "title": "Baxter Infusion Pump Firmware Vulnerability",
    "summary": (
        "A vulnerability in Baxter infusion pump firmware allows network-based "
        "attackers to modify device configuration. No patch available. "
        "Recommended mitigation: isolate device network segment."
    ),
    "sources": ["cisa-icsma"],
    "published_dates": ["2024-05-10"],
}

UNKNOWN_B = {
    "issue_id": "UNK-bbb222",
    "issue_type": "unknown",
    "cves": [],
    "title": "FDA Safety Communication: Baxter Pump Network Risk",
    "summary": (
        "FDA warns of network security risk in Baxter infusion pump line. "
        "Device firmware vulnerable to configuration tampering via network access. "
        "Healthcare facilities advised to isolate affected devices."
    ),
    "sources": ["fda-mdm"],
    "published_dates": ["2024-05-14"],
}

UNRELATED = {
    "issue_id": "UNK-ccc333",
    "issue_type": "unknown",
    "cves": [],
    "title": "Apache Log4j Logging Framework Vulnerability",
    "summary": (
        "Critical zero-day in Apache Log4j allows remote code execution via JNDI "
        "injection. Affects all Java applications using Log4j 2.x."
    ),
    "sources": ["nvd"],
    "published_dates": ["2024-01-01"],
}


def test_find_merge_candidates_no_cve_product_overlap():
    """Two no-CVE issues with strong product/summary overlap should be candidates."""
    candidates = find_merge_candidates([UNKNOWN_A, UNKNOWN_B, UNRELATED])

    # Extract the pair IDs that appear
    pair_ids = [frozenset([id_a, id_b]) for id_a, id_b, _ in candidates]

    # The two Baxter issues should be a candidate
    assert frozenset(["UNK-aaa111", "UNK-bbb222"]) in pair_ids, (
        f"Expected Baxter pair as candidate, got: {candidates}"
    )


def test_find_merge_candidates_unrelated_not_paired():
    """The unrelated Apache issue should not pair with the Baxter issues."""
    candidates = find_merge_candidates([UNKNOWN_A, UNKNOWN_B, UNRELATED])
    for id_a, id_b, score in candidates:
        pair = {id_a, id_b}
        assert "UNK-ccc333" not in pair or score < 0.25, (
            f"Unrelated issue unexpectedly paired: {id_a} <-> {id_b} (score={score})"
        )


# ---------------------------------------------------------------------------
# Test Case 4 — Single issue: no pairs possible
# ---------------------------------------------------------------------------

def test_find_merge_candidates_single_issue():
    assert find_merge_candidates([CISA_ICSMA_PHILIPS]) == []


# ---------------------------------------------------------------------------
# Test Case 5 — Empty input
# ---------------------------------------------------------------------------

def test_find_merge_candidates_empty():
    assert find_merge_candidates([]) == []


# ---------------------------------------------------------------------------
# Test Case 6 — max_pair_fraction cap
# ---------------------------------------------------------------------------

def _make_issue(n: int) -> dict:
    return {
        "issue_id": f"UNK-{n:04d}",
        "issue_type": "unknown",
        "cves": [],
        "title": f"Vendor{n} Device{n} Vulnerability {n}",
        "summary": f"A vulnerability in Vendor{n} Device{n} firmware version {n}.",
        "sources": ["test"],
        "published_dates": ["2024-06-01"],
    }


def test_find_merge_candidates_respects_pair_cap():
    """With 50 issues, at most 5% of N*(N-1)/2 pairs should be returned."""
    issues = [_make_issue(i) for i in range(50)]
    candidates = find_merge_candidates(issues, threshold=0.0)
    max_pairs = int(50 * 49 / 2 * 0.05)
    assert len(candidates) <= max(1, max_pairs), (
        f"Too many candidates: {len(candidates)} > {max_pairs}"
    )


# ---------------------------------------------------------------------------
# Test Case 7 — Return format: sorted descending, no self-pairs, no dupes
# ---------------------------------------------------------------------------

def test_find_merge_candidates_output_format():
    """Candidates should be sorted desc by score, no self-pairs, no duplicate pairs."""
    issues = [CISA_ICSMA_PHILIPS, VENDOR_PSIRT_PHILIPS, UNKNOWN_A, UNKNOWN_B, UNRELATED]
    candidates = find_merge_candidates(issues)

    for id_a, id_b, score in candidates:
        assert id_a != id_b, "Self-pair found"
        assert id_a < id_b, "Pair IDs not in lexicographic order"
        assert 0.0 <= score <= 1.0, f"Score out of range: {score}"

    scores = [s for _, _, s in candidates]
    assert scores == sorted(scores, reverse=True), "Candidates not sorted by score descending"

    pairs = [frozenset([a, b]) for a, b, _ in candidates]
    assert len(pairs) == len(set(pairs)), "Duplicate pairs found"


# ===========================================================================
# Task 2.2 — ai_merge_decision tests (mocked API, no OPENAI_API_KEY required)
# ===========================================================================

# ---------------------------------------------------------------------------
# Minimal mock client helpers
# ---------------------------------------------------------------------------

class _MockUsage:
    def __init__(self, total: int):
        self.total_tokens = total


class _MockResponse:
    def __init__(self, json_text: str, tokens: int = 42):
        self.output_text = json_text
        self.id = "mock-response-id"
        self.usage = _MockUsage(tokens)


class _MockResponsesNamespace:
    """Mimics client.responses with a configurable create() callable."""

    def __init__(self, create_fn):
        self._create_fn = create_fn

    def create(self, **kwargs):
        return self._create_fn(**kwargs)


class _MockClient:
    def __init__(self, json_text: str, tokens: int = 42):
        self.responses = _MockResponsesNamespace(
            lambda **kw: _MockResponse(json_text, tokens)
        )


class _ErrorClient:
    """Always raises on create()."""

    class responses:
        @staticmethod
        def create(**kwargs):
            raise RuntimeError("Simulated API failure")


# ---------------------------------------------------------------------------
# merge_decision test fixtures
# ---------------------------------------------------------------------------

_ISSUE_PHILIPS_CISA = {
    "issue_id": "CVE-2024-1234",
    "cves": ["CVE-2024-1234"],
    "title": "Philips IntelliSpace Cardiovascular Remote Code Execution",
    "summary": (
        "Critical vulnerability in Philips IntelliSpace Cardiovascular (ISCV) allows "
        "unauthenticated remote code execution. Vendor recommends network segmentation."
    ),
    "sources": ["cisa-icsma"],
    "published_dates": ["2024-03-12"],
}

_ISSUE_PHILIPS_PSIRT = {
    "issue_id": "UNK-aabbcc001122",
    "cves": ["CVE-2024-1234"],
    "title": "CISA Advisory for Philips ISCV",
    "summary": (
        "Remote access vulnerability in Philips IntelliSpace platform. "
        "Critical severity. Segmentation recommended as interim mitigation."
    ),
    "sources": ["philips-psirt"],
    "published_dates": ["2024-03-15"],
}

_ISSUE_UNRELATED = {
    "issue_id": "CVE-2024-9999",
    "cves": ["CVE-2024-9999"],
    "title": "Apache Log4j Remote Code Execution",
    "summary": "Critical zero-day in Apache Log4j. Affects Java applications.",
    "sources": ["nvd"],
    "published_dates": ["2021-12-10"],
}


# ---------------------------------------------------------------------------
# Test: same_issue = True
# ---------------------------------------------------------------------------

def test_merge_decision_same_issue_mock():
    """Mock returning same_issue=True is parsed correctly."""
    mock_json = '{"same_issue": true, "confidence": 0.92, "reasoning": "Both reference CVE-2024-1234 and Philips ISCV."}'
    client = _MockClient(mock_json, tokens=120)

    decision = ai_merge_decision(
        _ISSUE_PHILIPS_CISA,
        _ISSUE_PHILIPS_PSIRT,
        _client=client,
        no_cache=True,
    )

    assert isinstance(decision, MergeDecision)
    assert decision.same_issue is True
    assert abs(decision.confidence - 0.92) < 1e-6
    assert "CVE-2024-1234" in decision.reasoning or len(decision.reasoning) > 5
    assert decision.model == "gpt-4o-mini"
    assert decision.tokens_used == 120


# ---------------------------------------------------------------------------
# Test: same_issue = False
# ---------------------------------------------------------------------------

def test_merge_decision_different_issue_mock():
    """Mock returning same_issue=False is parsed correctly."""
    mock_json = (
        '{"same_issue": false, "confidence": 0.97, '
        '"reasoning": "Different CVEs and vendors — these are unrelated issues."}'
    )
    client = _MockClient(mock_json, tokens=85)

    decision = ai_merge_decision(
        _ISSUE_PHILIPS_CISA,
        _ISSUE_UNRELATED,
        _client=client,
        no_cache=True,
    )

    assert isinstance(decision, MergeDecision)
    assert decision.same_issue is False
    assert decision.confidence >= 0.9
    assert len(decision.reasoning) > 5
    assert decision.tokens_used == 85


# ---------------------------------------------------------------------------
# Test: API error → uncertain result (no exception raised)
# ---------------------------------------------------------------------------

def test_merge_decision_api_error_returns_uncertain():
    """On API failure the function returns an uncertain decision, not an exception."""
    decision = ai_merge_decision(
        _ISSUE_PHILIPS_CISA,
        _ISSUE_PHILIPS_PSIRT,
        _client=_ErrorClient(),
        no_cache=True,
    )

    assert isinstance(decision, MergeDecision)
    assert decision.same_issue is False
    assert decision.confidence == 0.0
    assert len(decision.reasoning) > 0  # some error message
    assert decision.tokens_used == 0


# ---------------------------------------------------------------------------
# Test: confidence is clamped to [0, 1]
# ---------------------------------------------------------------------------

def test_merge_decision_confidence_clamped():
    """Out-of-range confidence values from the model are clamped to [0, 1]."""
    mock_json = '{"same_issue": true, "confidence": 1.5, "reasoning": "High confidence."}'
    client = _MockClient(mock_json)
    decision = ai_merge_decision(_ISSUE_PHILIPS_CISA, _ISSUE_PHILIPS_PSIRT, _client=client, no_cache=True)
    assert decision.confidence <= 1.0

    mock_json2 = '{"same_issue": false, "confidence": -0.3, "reasoning": "Low confidence."}'
    client2 = _MockClient(mock_json2)
    decision2 = ai_merge_decision(_ISSUE_PHILIPS_CISA, _ISSUE_UNRELATED, _client=client2, no_cache=True)
    assert decision2.confidence >= 0.0


# ---------------------------------------------------------------------------
# Test: bad JSON from model → uncertain result (no exception)
# ---------------------------------------------------------------------------

def test_merge_decision_bad_json_returns_uncertain():
    """Malformed model output is handled gracefully."""
    client = _MockClient("NOT VALID JSON {{{")
    decision = ai_merge_decision(_ISSUE_PHILIPS_CISA, _ISSUE_PHILIPS_PSIRT, _client=client, no_cache=True)
    assert isinstance(decision, MergeDecision)
    assert decision.same_issue is False
    assert decision.confidence == 0.0


# ---------------------------------------------------------------------------
# Test: MergeDecision dataclass has all required fields
# ---------------------------------------------------------------------------

def test_merge_decision_dataclass_fields():
    """MergeDecision exposes all fields required by the build plan."""
    d = MergeDecision(
        same_issue=True,
        confidence=0.8,
        reasoning="Test reasoning.",
        model="gpt-4o-mini",
        tokens_used=99,
    )
    assert hasattr(d, "same_issue")
    assert hasattr(d, "confidence")
    assert hasattr(d, "reasoning")
    assert hasattr(d, "model")
    assert hasattr(d, "tokens_used")
    assert d.same_issue is True
    assert d.tokens_used == 99


# ---------------------------------------------------------------------------
# Test: cache hit skips the API call
# ---------------------------------------------------------------------------

def test_merge_decision_cache_hit(tmp_path):
    """A cached result is returned without calling the API."""
    call_count = {"n": 0}

    class _CountingClient:
        class responses:
            @staticmethod
            def create(**kwargs):
                call_count["n"] += 1
                return _MockResponse(
                    '{"same_issue": true, "confidence": 0.88, "reasoning": "Cached."}',
                    tokens=50,
                )

    cache_root = tmp_path / "ai_cache"

    # First call — should hit the API
    d1 = ai_merge_decision(
        _ISSUE_PHILIPS_CISA,
        _ISSUE_PHILIPS_PSIRT,
        _client=_CountingClient(),
        cache_root=str(cache_root),
    )
    assert call_count["n"] == 1
    assert d1.same_issue is True

    # Second call with same inputs — should return from cache (no new API call)
    d2 = ai_merge_decision(
        _ISSUE_PHILIPS_CISA,
        _ISSUE_PHILIPS_PSIRT,
        _client=_CountingClient(),
        cache_root=str(cache_root),
    )
    assert call_count["n"] == 1, "Cache hit should not call the API again"
    assert d2.same_issue is True
    assert abs(d2.confidence - d1.confidence) < 1e-6


# ---------------------------------------------------------------------------
# Test: (A, B) and (B, A) share the same cache entry
# ---------------------------------------------------------------------------

def test_merge_decision_cache_symmetric(tmp_path):
    """Swapping issue_a and issue_b reuses the same cache entry."""
    call_count = {"n": 0}

    class _CountingClient:
        class responses:
            @staticmethod
            def create(**kwargs):
                call_count["n"] += 1
                return _MockResponse(
                    '{"same_issue": false, "confidence": 0.75, "reasoning": "Symmetric test."}',
                    tokens=30,
                )

    cache_root = tmp_path / "ai_cache_sym"

    ai_merge_decision(
        _ISSUE_PHILIPS_CISA,
        _ISSUE_UNRELATED,
        _client=_CountingClient(),
        cache_root=str(cache_root),
    )
    assert call_count["n"] == 1

    ai_merge_decision(
        _ISSUE_UNRELATED,
        _ISSUE_PHILIPS_CISA,  # reversed order
        _client=_CountingClient(),
        cache_root=str(cache_root),
    )
    assert call_count["n"] == 1, "(B, A) should reuse the (A, B) cache entry"
