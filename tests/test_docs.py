"""Tests for documentation files."""
from pathlib import Path

DOCS_ROOT = Path(__file__).resolve().parent.parent / "docs"


def test_schema_md_exists():
    assert (DOCS_ROOT / "schema.md").exists()


def test_schema_md_nonempty():
    text = (DOCS_ROOT / "schema.md").read_text(encoding="utf-8")
    assert len(text) > 100


def test_schema_md_has_field_table():
    text = (DOCS_ROOT / "schema.md").read_text(encoding="utf-8")
    assert "issue_id" in text
    assert "priority" in text
    # `evidence_completeness` was removed 2026-04-13 per audit finding C-012 —
    # it was documented but never actually emitted by _feed_entry. Assert on
    # `generated_by` instead, which is both in the schema and in _feed_entry.
    assert "generated_by" in text


def test_data_rights_md_exists():
    assert (DOCS_ROOT / "data_rights.md").exists()


def test_data_rights_md_nonempty():
    text = (DOCS_ROOT / "data_rights.md").read_text(encoding="utf-8")
    assert len(text) > 100


def test_data_rights_mentions_public_domain():
    text = (DOCS_ROOT / "data_rights.md").read_text(encoding="utf-8")
    assert "public domain" in text.lower() or "public safety" in text.lower()


def test_playbook_governance_md_exists():
    assert (DOCS_ROOT / "playbook_governance.md").exists()


def test_playbook_governance_md_nonempty():
    text = (DOCS_ROOT / "playbook_governance.md").read_text(encoding="utf-8")
    assert len(text) > 100


def test_playbook_governance_mentions_approval():
    text = (DOCS_ROOT / "playbook_governance.md").read_text(encoding="utf-8")
    assert "approved" in text.lower() or "approval" in text.lower()


def test_playbook_governance_mentions_deprecation():
    text = (DOCS_ROOT / "playbook_governance.md").read_text(encoding="utf-8")
    assert "deprecat" in text.lower()
