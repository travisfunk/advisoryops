"""Tests for source_mitigations.py — source-cited mitigation extraction."""
from __future__ import annotations

import pytest

from advisoryops.source_mitigations import extract_source_mitigations


def _make_issue(**overrides):
    """Create a minimal scored issue dict for testing."""
    base = {
        "issue_id": "CVE-2024-1234",
        "title": "Test Vulnerability in Medical Device",
        "summary": (
            "A critical vulnerability in Acme Infusion Pump firmware allows "
            "remote code execution. CISA recommends minimizing network exposure "
            "for all control system devices, ensuring they are not accessible "
            "from the Internet. Apply firmware update v2.3.1 from Acme. "
            "Monitor device logs for unusual activity."
        ),
        "sources": ["cisa-icsma", "tenable-newest"],
        "cves": ["CVE-2024-1234"],
        "signals": [
            {"source": "cisa-icsma", "link": "https://cisa.gov/icsma-1234", "guid": "ICSMA-2024-1234"},
            {"source": "tenable-newest", "link": "https://tenable.com/vuln/1234", "guid": "T-1234"},
        ],
        "priority": "P0",
        "score": 300,
    }
    base.update(overrides)
    return base


def _fake_call_fn_with_mitigations():
    """Return a callable that simulates AI extraction results."""
    def _call():
        return {
            "result": {
                "mitigations": [
                    {
                        "action": "Minimize network exposure for all control system devices",
                        "mitigation_type": "network",
                        "verbatim_snippet": "minimize network exposure",
                    },
                    {
                        "action": "Apply firmware update v2.3.1",
                        "mitigation_type": "patch",
                        "verbatim_snippet": "Apply firmware update v2.3.1",
                    },
                    {
                        "action": "Monitor device logs for unusual activity",
                        "mitigation_type": "monitor",
                        "verbatim_snippet": "Monitor device logs",
                    },
                ]
            },
            "model": "gpt-4o-mini",
            "tokens_used": 150,
        }
    return _call


def _fake_call_fn_empty():
    """Return a callable that simulates no mitigations found."""
    def _call():
        return {"result": {"mitigations": []}, "model": "gpt-4o-mini", "tokens_used": 50}
    return _call


class TestExtractSourceMitigations:

    def test_returns_list(self):
        issue = _make_issue()
        result = extract_source_mitigations(issue, _call_fn=_fake_call_fn_with_mitigations())
        assert isinstance(result, list)

    def test_expected_structure(self):
        issue = _make_issue()
        result = extract_source_mitigations(issue, _call_fn=_fake_call_fn_with_mitigations())
        assert len(result) == 3
        for m in result:
            assert "source" in m
            assert "source_tier" in m
            assert "action" in m
            assert "citation" in m
            assert "url" in m
            assert "mitigation_type" in m

    def test_mitigation_types_valid(self):
        issue = _make_issue()
        result = extract_source_mitigations(issue, _call_fn=_fake_call_fn_with_mitigations())
        valid_types = {"network", "patch", "monitor", "credential", "process", "other"}
        for m in result:
            assert m["mitigation_type"] in valid_types

    def test_source_attributed(self):
        issue = _make_issue()
        result = extract_source_mitigations(issue, _call_fn=_fake_call_fn_with_mitigations())
        assert all(m["source"] == "cisa-icsma" for m in result)

    def test_source_tier_populated(self):
        issue = _make_issue()
        result = extract_source_mitigations(issue, _call_fn=_fake_call_fn_with_mitigations())
        for m in result:
            assert isinstance(m["source_tier"], int)
            assert 1 <= m["source_tier"] <= 5

    def test_citation_populated(self):
        issue = _make_issue()
        result = extract_source_mitigations(issue, _call_fn=_fake_call_fn_with_mitigations())
        assert result[0]["citation"] == "ICSMA-2024-1234"

    def test_url_populated(self):
        issue = _make_issue()
        result = extract_source_mitigations(issue, _call_fn=_fake_call_fn_with_mitigations())
        assert result[0]["url"] == "https://cisa.gov/icsma-1234"

    def test_call_fn_injection_works(self):
        """Verify _call_fn is actually used (not the real API)."""
        called = []
        def _tracking_call():
            called.append(True)
            return {"result": {"mitigations": []}, "model": "test", "tokens_used": 0}

        issue = _make_issue()
        extract_source_mitigations(issue, _call_fn=_tracking_call)
        assert len(called) == 1

    def test_empty_summary_returns_empty(self):
        issue = _make_issue(summary="")
        result = extract_source_mitigations(issue, _call_fn=_fake_call_fn_empty())
        assert result == []

    def test_no_sources_returns_empty(self):
        issue = _make_issue(sources=[])
        result = extract_source_mitigations(issue, _call_fn=_fake_call_fn_empty())
        assert result == []

    def test_empty_mitigations_result(self):
        issue = _make_issue()
        result = extract_source_mitigations(issue, _call_fn=_fake_call_fn_empty())
        assert result == []

    def test_action_text_preserved(self):
        issue = _make_issue()
        result = extract_source_mitigations(issue, _call_fn=_fake_call_fn_with_mitigations())
        actions = [m["action"] for m in result]
        assert "Minimize network exposure for all control system devices" in actions
        assert "Apply firmware update v2.3.1" in actions
        assert "Monitor device logs for unusual activity" in actions

    def test_invalid_type_normalized_to_other(self):
        def _call():
            return {
                "result": {
                    "mitigations": [
                        {"action": "Do something", "mitigation_type": "INVALID_TYPE"},
                    ]
                },
                "model": "test",
                "tokens_used": 0,
            }
        issue = _make_issue()
        result = extract_source_mitigations(issue, _call_fn=_call)
        assert result[0]["mitigation_type"] == "other"
