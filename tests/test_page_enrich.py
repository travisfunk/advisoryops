"""Tests for page_enrich.py — advisory page content fetching and caching."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from advisoryops.page_enrich import (
    _collect_urls,
    _strip_html,
    _get_cached,
    _put_cache,
    _url_hash,
    enrich_issue_from_links,
)


def _make_issue(**overrides):
    base = {
        "issue_id": "CVE-2024-TEST",
        "title": "Test Issue",
        "summary": "Test summary",
        "canonical_link": "https://cisa.gov/advisory/test-1",
        "sources": ["cisa-icsma"],
        "signals": [
            {"source": "cisa-icsma", "link": "https://cisa.gov/advisory/test-1"},
            {"source": "tenable-newest", "link": "https://tenable.com/vuln/test-1"},
        ],
        "links": ["https://nvd.nist.gov/vuln/detail/CVE-2024-TEST"],
    }
    base.update(overrides)
    return base


class TestStripHTML:

    def test_removes_tags(self):
        result = _strip_html("<p>Hello <b>world</b></p>")
        assert "Hello" in result
        assert "world" in result
        assert "<" not in result

    def test_decodes_entities(self):
        result = _strip_html("&amp; &lt; &gt;")
        assert "& < >" in result

    def test_preserves_plain_text(self):
        result = _strip_html("No HTML here")
        assert result == "No HTML here"

    def test_collapses_whitespace(self):
        result = _strip_html("<p>A</p>    <p>B</p>")
        assert "A" in result
        assert "B" in result


class TestCollectURLs:

    def test_collects_canonical_link(self):
        issue = _make_issue()
        urls = _collect_urls(issue)
        assert "https://cisa.gov/advisory/test-1" in urls

    def test_collects_signal_links(self):
        issue = _make_issue()
        urls = _collect_urls(issue)
        assert "https://tenable.com/vuln/test-1" in urls

    def test_collects_links_list(self):
        issue = _make_issue()
        urls = _collect_urls(issue)
        assert "https://nvd.nist.gov/vuln/detail/CVE-2024-TEST" in urls

    def test_deduplicates(self):
        issue = _make_issue(
            canonical_link="https://cisa.gov/advisory/test-1",
            links=["https://cisa.gov/advisory/test-1"],
        )
        urls = _collect_urls(issue)
        cisa_urls = [u for u in urls if "cisa.gov" in u]
        assert len(cisa_urls) == 1

    def test_empty_issue(self):
        issue = _make_issue(canonical_link="", links=[], signals=[])
        urls = _collect_urls(issue)
        assert urls == []

    def test_handles_dict_links(self):
        issue = _make_issue(links=[{"url": "https://example.org/advisory"}])
        urls = _collect_urls(issue)
        assert "https://example.org/advisory" in urls


class TestPageCache:

    def test_put_and_get(self, tmp_path):
        url = "https://example.com/test"
        text = "This is cached content"
        _put_cache(url, text, tmp_path)
        result = _get_cached(url, tmp_path)
        assert result == text

    def test_cache_miss(self, tmp_path):
        result = _get_cached("https://nonexistent.example.com", tmp_path)
        assert result is None

    def test_cache_file_created(self, tmp_path):
        url = "https://example.com/test"
        _put_cache(url, "content", tmp_path)
        expected_path = tmp_path / f"{_url_hash(url)}.txt"
        assert expected_path.exists()


class TestEnrichIssueFromLinks:

    def test_returns_string(self):
        issue = _make_issue(canonical_link="", links=[], signals=[])
        result = enrich_issue_from_links(issue)
        assert isinstance(result, str)

    def test_empty_issue_returns_empty(self):
        issue = _make_issue(canonical_link="", links=[], signals=[])
        result = enrich_issue_from_links(issue)
        assert result == ""

    def test_uses_cache(self, tmp_path):
        url = "https://cached-test.example.com/advisory"
        cached_text = "Mitigations: apply patch v2.0"
        _put_cache(url, cached_text, tmp_path)

        issue = _make_issue(
            canonical_link=url,
            links=[],
            signals=[],
        )
        result = enrich_issue_from_links(issue, cache_dir=tmp_path)
        assert "apply patch v2.0" in result


class TestEnrichedTextFlowsToMitigation:

    def test_enriched_text_used_over_summary(self):
        """If enriched_text is set on an issue, mitigation extraction should use it."""
        from advisoryops.source_mitigations import extract_source_mitigations

        def _call():
            return {
                "result": {
                    "mitigations": [
                        {"action": "Apply firmware update v3.0", "mitigation_type": "patch"},
                    ]
                },
                "model": "test",
                "tokens_used": 0,
            }

        issue = _make_issue(
            summary="Brief CVE mention",
            enriched_text="Full page: MITIGATIONS section recommends applying firmware update v3.0",
        )
        result = extract_source_mitigations(issue, _call_fn=_call)
        assert len(result) == 1
        assert "Apply firmware update v3.0" in result[0]["action"]
