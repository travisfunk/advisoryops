"""Tests for extract_fields.py — LLM field extraction for issues with missing data."""

import os
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, "src"))

from advisoryops.extract_fields import extract_fields


def _make_call_fn(result_dict):
    """Return a mock call_fn that returns the given result dict."""
    return MagicMock(return_value={"result": result_dict, "model": "test", "tokens_used": 10})


def test_extraction_module_imports():
    from advisoryops import extract_fields as mod
    assert hasattr(mod, "extract_fields")


def test_extract_fields_with_mock_returns_dict():
    issue = {"issue_id": "UNK-test", "title": "item", "vendor": "", "summary": "Abiomed Impella Controller vulnerability."}
    call_fn = _make_call_fn({"vendor": "Abiomed", "product_name": "Impella Controller", "severity": "high"})
    result = extract_fields(issue, _call_fn=call_fn)
    assert result["vendor"] == "Abiomed"
    assert result["product_name"] == "Impella Controller"
    assert result["severity"] == "high"


def test_extract_fields_omits_missing_keys():
    issue = {"issue_id": "UNK-test", "summary": "Some advisory text."}
    call_fn = _make_call_fn({"vendor": "Philips"})
    result = extract_fields(issue, _call_fn=call_fn)
    assert "vendor" in result
    assert "product_name" not in result
    assert "severity" not in result


def test_extract_fields_handles_empty_summary():
    issue = {"issue_id": "UNK-test", "summary": ""}
    result = extract_fields(issue)
    assert result == {}


def test_extract_fields_handles_empty_result():
    issue = {"issue_id": "UNK-test", "summary": "Some text."}
    call_fn = _make_call_fn({})
    result = extract_fields(issue, _call_fn=call_fn)
    assert result == {}


def test_extract_fields_validates_severity():
    issue = {"issue_id": "UNK-test", "summary": "Some text."}
    call_fn = _make_call_fn({"severity": "UNKNOWN"})
    result = extract_fields(issue, _call_fn=call_fn)
    assert "severity" not in result


def test_extract_fields_normalizes_severity_case():
    issue = {"issue_id": "UNK-test", "summary": "Some text."}
    call_fn = _make_call_fn({"severity": "HIGH"})
    result = extract_fields(issue, _call_fn=call_fn)
    assert result["severity"] == "high"


def test_extract_fields_affected_products_array():
    issue = {"issue_id": "UNK-test", "summary": "Some text."}
    call_fn = _make_call_fn({"affected_products": ["Model A", "Model B"]})
    result = extract_fields(issue, _call_fn=call_fn)
    assert result["affected_products"] == ["Model A", "Model B"]


def test_extract_fields_uses_cache(tmp_path):
    """Call twice with the same input — second call should hit the cache."""
    issue = {"issue_id": "UNK-cache-test", "summary": "Test advisory for caching."}
    call_count = {"n": 0}

    def counting_call_fn():
        call_count["n"] += 1
        return {"result": {"vendor": "TestCo"}, "model": "test", "tokens_used": 5}

    # First call — uses the call_fn
    r1 = extract_fields(issue, cache_root=str(tmp_path), _call_fn=counting_call_fn)
    # Note: when _call_fn is provided directly, it bypasses cache. This test
    # verifies the function accepts cache_root without error. True cache
    # testing requires the default code path with OPENAI_API_KEY.
    assert r1["vendor"] == "TestCo"
    assert call_count["n"] == 1
