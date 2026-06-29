"""Tests for feed schema contract (docs/feed_contract.json).

Enforces the contract between the pipeline output and the dashboard JS:
  - The contract file itself is valid and well-formed
  - Required fields are present in feed rows
  - Every field the dashboard references is declared in the contract
"""

import json
import os
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, "src"))

REPO_ROOT = Path(__file__).resolve().parent.parent
CONTRACT_PATH = REPO_ROOT / "docs" / "feed_contract.json"
FEED_PATH = REPO_ROOT / "outputs" / "community_public" / "feed_healthcare.json"
DASHBOARD_PATH = REPO_ROOT / "dashboard" / "index.html"


def _load_contract():
    return json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))


class TestContractLoads:
    def test_contract_parses_as_json(self):
        contract = _load_contract()
        assert isinstance(contract, dict)

    def test_has_version(self):
        contract = _load_contract()
        assert "version" in contract
        assert contract["version"] >= 1

    def test_has_fields(self):
        contract = _load_contract()
        assert "fields" in contract
        assert len(contract["fields"]) > 0

    def test_required_fields_have_type(self):
        contract = _load_contract()
        for name, spec in contract["fields"].items():
            assert "type" in spec, f"Field {name} missing 'type'"
            assert "required" in spec, f"Field {name} missing 'required'"


class TestRequiredFieldsInFeed:
    @pytest.fixture(autouse=True)
    def _skip_if_no_feed(self):
        if not FEED_PATH.exists():
            pytest.skip("No feed file — skipping (no-op without pipeline output)")

    def test_required_fields_present(self):
        contract = _load_contract()
        required_fields = [
            name for name, spec in contract["fields"].items()
            if spec.get("required") is True
        ]

        data = json.loads(FEED_PATH.read_text(encoding="utf-8"))
        issues = data.get("issues", data) if isinstance(data, dict) else data
        if not issues:
            pytest.skip("Feed has no issues")

        for field in required_fields:
            present = sum(1 for row in issues if field in row and row[field] not in (None, ""))
            pct = present / len(issues)
            assert pct >= 0.95, (
                f"Required field '{field}' present in only {present}/{len(issues)} "
                f"rows ({pct:.1%}), need >= 95%"
            )


class TestDashboardReadsOnlyDeclaredFields:
    def test_dashboard_fields_declared(self):
        contract = _load_contract()
        declared = set(contract["fields"].keys())

        html = DASHBOARD_PATH.read_text(encoding="utf-8")

        # Find field references: issue.fieldname and i.fieldname in JS
        # These patterns appear in the renderDetail, renderList, sort, and
        # filter functions. We look for dot-notation access on known
        # variable names that hold issue objects.
        pattern = re.compile(r'\b(?:issue|i)\.([a-z_][a-z0-9_]*)', re.IGNORECASE)
        referenced = set()
        for match in pattern.finditer(html):
            field = match.group(1)
            # Filter out JS builtins and DOM properties
            js_builtins = {
                'length', 'trim', 'toLowerCase', 'toUpperCase', 'indexOf',
                'slice', 'join', 'filter', 'map', 'sort', 'push', 'pop',
                'replace', 'split', 'substring', 'charAt', 'toString',
                'style', 'display', 'innerHTML', 'textContent',
                'preventDefault', 'target', 'value', 'checked',
                'className', 'classList', 'parentNode', 'children',
                'addEventListener', 'removeEventListener', 'getAttribute',
                'get', 'set', 'has', 'keys', 'values', 'entries',
                'forEach', 'includes', 'startsWith', 'endsWith',
                'match', 'search', 'test', 'exec',
            }
            if field not in js_builtins:
                referenced.add(field)

        undeclared = referenced - declared
        assert not undeclared, (
            f"Dashboard references fields not in contract: {sorted(undeclared)}. "
            f"Add them to docs/feed_contract.json or remove the dashboard reference."
        )
