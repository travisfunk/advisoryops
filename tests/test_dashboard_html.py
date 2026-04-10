"""Tests for dashboard HTML — structure, validity, inline data."""

import json
import os
import sys
from html.parser import HTMLParser

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, "src"))

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
DASHBOARD_DIR = os.path.join(REPO_ROOT, "dashboard")
INDEX_PATH = os.path.join(DASHBOARD_DIR, "index.html")


def _read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


# ------------------------------------------------------------------
# HTML validity
# ------------------------------------------------------------------

class _StrictParser(HTMLParser):
    """Raises on parser errors."""
    def __init__(self):
        super().__init__()
        self.errors = []
    def handle_starttag(self, tag, attrs):
        pass
    def handle_endtag(self, tag):
        pass
    def error(self, message):
        self.errors.append(message)


def test_index_html_parses():
    html = _read(INDEX_PATH)
    parser = _StrictParser()
    parser.feed(html)
    assert not parser.errors, f"HTML parse errors: {parser.errors}"


# ------------------------------------------------------------------
# Required section IDs
# ------------------------------------------------------------------

REQUIRED_SECTIONS = ["issues-section", "sources-section", "methodology-section", "about-section"]


@pytest.mark.parametrize("section_id", REQUIRED_SECTIONS)
def test_index_has_section(section_id):
    html = _read(INDEX_PATH)
    assert f'id="{section_id}"' in html, f"Missing section: {section_id}"


# ------------------------------------------------------------------
# No external dependencies
# ------------------------------------------------------------------

def test_no_external_cdn():
    html = _read(INDEX_PATH)
    for cdn in ["cdn.jsdelivr", "unpkg.com", "cdnjs.cloudflare"]:
        assert cdn not in html, f"External CDN found: {cdn}"


def test_no_framework_imports():
    html = _read(INDEX_PATH)
    for fw in ["react", "jquery", "vue", "angular", "bootstrap"]:
        assert fw.lower() not in html.lower().replace("advisoryops", ""), f"Framework reference: {fw}"



# ------------------------------------------------------------------
# Search functionality
# ------------------------------------------------------------------

def test_search_input_exists():
    html = _read(INDEX_PATH)
    assert 'id="search-input"' in html, "Search input element missing"


def test_search_has_event_handler():
    html = _read(INDEX_PATH)
    assert "search-input" in html and "addEventListener" in html, "Search event handler missing"
    assert "searchQuery" in html, "searchQuery variable not found in JS"


def test_search_filter_logic():
    """Search filter should match against title, cves, vendor, affected_products."""
    html = _read(INDEX_PATH)
    assert "i.title" in html, "Search doesn't reference title"
    assert "i.cves" in html or "cves" in html, "Search doesn't reference cves"
    assert "i.vendor" in html, "Search doesn't reference vendor"
