"""Tests for advisoryops/packet_export.py (Phase 4, Task 4.3).

Contract under test
-------------------
* export_json  — valid JSON, schema_version=1, all required fields present.
* export_markdown — readable content with all section headings and role labels.
* export_csv_tasks — correct columns, one row per playbook step, safe task_ids.
* Patterns not in the playbook are gracefully skipped (no KeyError).
* Empty recommended_patterns produces valid minimal output in all formats.
* _safe_stem sanitizes special characters in issue IDs.
"""
from __future__ import annotations

import csv
import io
import json
from pathlib import Path

import pytest

from advisoryops.packet_export import (
    _safe_stem,
    _task_rows,
    export_csv_tasks,
    export_json,
    export_markdown,
)
from advisoryops.playbook import load_playbook, Playbook
from advisoryops.recommend import PatternRecommendation, RemediationPacket


# ── fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def playbook() -> Playbook:
    return load_playbook()


def _make_packet(
    issue_id: str = "CVE-2024-1234",
    patterns: list | None = None,
) -> RemediationPacket:
    """Build a RemediationPacket with realistic content for testing."""
    if patterns is None:
        patterns = [
            PatternRecommendation(
                pattern_id="SEGMENTATION_VLAN_ISOLATION",
                why_selected="Device is network-accessible with no patch available.",
                parameters={"current_vlan_subnet": "10.0.1.0/24", "maintenance_window": "TBD"},
                priority_order=1,
            ),
            PatternRecommendation(
                pattern_id="ACCESS_CONTROL_ACL_ALLOWLIST",
                why_selected="ACL reduces exposure while patch is pending.",
                parameters={"allowed_hosts": "PACS server"},
                priority_order=2,
            ),
        ]
    # Build tasks_by_role from real playbook (load fresh; can't use fixture in non-test code)
    pb = load_playbook()
    tasks_by_role: dict = {}
    for rec in patterns:
        p = pb.get(rec.pattern_id)
        if not p:
            continue
        for step in p.steps:
            tasks_by_role.setdefault(step.role, []).append(
                f"[{p.name}] {step.action}: {step.details}"
            )

    return RemediationPacket(
        issue_id=issue_id,
        recommended_patterns=patterns,
        tasks_by_role=tasks_by_role,
        reasoning="Primary controls: network isolation and access restriction.",
        citations=["https://www.cisa.gov/ics/advisories/icsma-24-001"],
        model="gpt-4o-mini",
        tokens_used=280,
        from_cache=False,
    )


def _make_empty_packet() -> RemediationPacket:
    return RemediationPacket(
        issue_id="UNK-abc123",
        recommended_patterns=[],
        tasks_by_role={},
        reasoning="",
        citations=[],
        model="gpt-4o-mini",
        tokens_used=0,
        from_cache=True,
    )


# ══════════════════════════════════════════════════════════════════════════════
# _safe_stem
# ══════════════════════════════════════════════════════════════════════════════

def test_safe_stem_cve_id() -> None:
    assert _safe_stem("CVE-2024-1234") == "CVE-2024-1234"


def test_safe_stem_replaces_slash() -> None:
    assert "/" not in _safe_stem("foo/bar")


def test_safe_stem_replaces_spaces() -> None:
    assert " " not in _safe_stem("foo bar baz")


def test_safe_stem_preserves_alphanumeric_dash_underscore() -> None:
    stem = _safe_stem("ABC_def-123")
    assert stem == "ABC_def-123"


# ══════════════════════════════════════════════════════════════════════════════
# _task_rows
# ══════════════════════════════════════════════════════════════════════════════

def test_task_rows_returns_one_row_per_step(playbook: Playbook) -> None:
    packet = _make_packet()
    rows = _task_rows(packet, playbook)
    # SEGMENTATION has 4 steps, ACCESS_CONTROL_ACL_ALLOWLIST has 3
    assert len(rows) == 7


def test_task_rows_skips_unknown_pattern(playbook: Playbook) -> None:
    packet = _make_packet(patterns=[
        PatternRecommendation("HALLUCINATED", "...", {}, 1),
        PatternRecommendation("SEGMENTATION_VLAN_ISOLATION", "ok", {}, 2),
    ])
    rows = _task_rows(packet, playbook)
    pids = {r[1] for r in rows}
    assert "HALLUCINATED" not in pids
    assert "SEGMENTATION_VLAN_ISOLATION" in pids


def test_task_rows_tuple_structure(playbook: Playbook) -> None:
    packet = _make_packet(patterns=[
        PatternRecommendation("SEGMENTATION_VLAN_ISOLATION", "ok", {}, 1),
    ])
    rows = _task_rows(packet, playbook)
    assert len(rows) > 0
    priority_order, pattern_id, pattern_name, role, action, details, verif = rows[0]
    assert priority_order == 1
    assert pattern_id == "SEGMENTATION_VLAN_ISOLATION"
    assert isinstance(action, str) and len(action) > 0
    assert isinstance(verif, str)


# ══════════════════════════════════════════════════════════════════════════════
# export_json
# ══════════════════════════════════════════════════════════════════════════════

def test_export_json_creates_file(playbook: Playbook, tmp_path: Path) -> None:
    out = tmp_path / "CVE-2024-1234_packet.json"
    export_json(_make_packet(), out)
    assert out.exists()


def test_export_json_valid_json(playbook: Playbook, tmp_path: Path) -> None:
    out = tmp_path / "packet.json"
    export_json(_make_packet(), out)
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert isinstance(doc, dict)


def test_export_json_schema_version(tmp_path: Path) -> None:
    out = tmp_path / "p.json"
    export_json(_make_packet(), out)
    doc = json.loads(out.read_text())
    assert doc["schema_version"] == 1


def test_export_json_required_fields(tmp_path: Path) -> None:
    out = tmp_path / "p.json"
    export_json(_make_packet(), out)
    doc = json.loads(out.read_text())
    for field in ("generated_at", "issue_id", "model", "tokens_used", "from_cache",
                  "reasoning", "citations", "recommended_patterns", "tasks_by_role"):
        assert field in doc, f"Missing field: {field}"


def test_export_json_issue_id(tmp_path: Path) -> None:
    out = tmp_path / "p.json"
    export_json(_make_packet("CVE-2024-9999"), out)
    doc = json.loads(out.read_text())
    assert doc["issue_id"] == "CVE-2024-9999"


def test_export_json_recommended_patterns_structure(tmp_path: Path) -> None:
    out = tmp_path / "p.json"
    export_json(_make_packet(), out)
    doc = json.loads(out.read_text())
    assert len(doc["recommended_patterns"]) == 2
    p = doc["recommended_patterns"][0]
    for key in ("priority_order", "pattern_id", "why_selected", "parameters"):
        assert key in p


def test_export_json_metadata(tmp_path: Path) -> None:
    out = tmp_path / "p.json"
    packet = _make_packet()
    export_json(packet, out)
    doc = json.loads(out.read_text())
    assert doc["model"] == "gpt-4o-mini"
    assert doc["tokens_used"] == 280
    assert doc["from_cache"] is False


def test_export_json_citations(tmp_path: Path) -> None:
    out = tmp_path / "p.json"
    export_json(_make_packet(), out)
    doc = json.loads(out.read_text())
    assert "https://www.cisa.gov/ics/advisories/icsma-24-001" in doc["citations"]


def test_export_json_empty_patterns(tmp_path: Path) -> None:
    out = tmp_path / "p.json"
    export_json(_make_empty_packet(), out)
    doc = json.loads(out.read_text())
    assert doc["recommended_patterns"] == []


def test_export_json_content_length(tmp_path: Path) -> None:
    out = tmp_path / "p.json"
    export_json(_make_packet(), out)
    assert len(out.read_text()) > 100


# ══════════════════════════════════════════════════════════════════════════════
# export_markdown
# ══════════════════════════════════════════════════════════════════════════════

def test_export_markdown_creates_file(playbook: Playbook, tmp_path: Path) -> None:
    out = tmp_path / "packet.md"
    export_markdown(_make_packet(), playbook, out)
    assert out.exists()


def test_export_markdown_content_length(playbook: Playbook, tmp_path: Path) -> None:
    out = tmp_path / "packet.md"
    export_markdown(_make_packet(), playbook, out)
    assert len(out.read_text()) > 100


def test_export_markdown_has_header(playbook: Playbook, tmp_path: Path) -> None:
    out = tmp_path / "packet.md"
    export_markdown(_make_packet(), playbook, out)
    content = out.read_text()
    assert "# Remediation Packet: CVE-2024-1234" in content


def test_export_markdown_has_reasoning_section(playbook: Playbook, tmp_path: Path) -> None:
    out = tmp_path / "packet.md"
    export_markdown(_make_packet(), playbook, out)
    content = out.read_text()
    assert "## AI Reasoning" in content
    assert "network isolation" in content


def test_export_markdown_has_recommended_patterns_section(playbook: Playbook, tmp_path: Path) -> None:
    out = tmp_path / "packet.md"
    export_markdown(_make_packet(), playbook, out)
    content = out.read_text()
    assert "## Recommended Patterns" in content
    assert "SEGMENTATION_VLAN_ISOLATION" in content
    assert "ACCESS_CONTROL_ACL_ALLOWLIST" in content


def test_export_markdown_has_tasks_by_role_section(playbook: Playbook, tmp_path: Path) -> None:
    out = tmp_path / "packet.md"
    export_markdown(_make_packet(), playbook, out)
    content = out.read_text()
    assert "## Tasks by Role" in content
    assert "Network Operations" in content
    assert "Information Security" in content


def test_export_markdown_has_verification_section(playbook: Playbook, tmp_path: Path) -> None:
    out = tmp_path / "packet.md"
    export_markdown(_make_packet(), playbook, out)
    content = out.read_text()
    assert "## Verification" in content
    assert "- [ ]" in content  # checklist items


def test_export_markdown_has_references_section(playbook: Playbook, tmp_path: Path) -> None:
    out = tmp_path / "packet.md"
    export_markdown(_make_packet(), playbook, out)
    content = out.read_text()
    assert "## References" in content
    assert "cisa.gov" in content


def test_export_markdown_why_selected_present(playbook: Playbook, tmp_path: Path) -> None:
    out = tmp_path / "packet.md"
    export_markdown(_make_packet(), playbook, out)
    content = out.read_text()
    assert "no patch available" in content.lower()


def test_export_markdown_parameters_rendered(playbook: Playbook, tmp_path: Path) -> None:
    out = tmp_path / "packet.md"
    export_markdown(_make_packet(), playbook, out)
    content = out.read_text()
    assert "current_vlan_subnet" in content
    assert "10.0.1.0/24" in content


def test_export_markdown_empty_patterns_no_error(playbook: Playbook, tmp_path: Path) -> None:
    out = tmp_path / "packet.md"
    export_markdown(_make_empty_packet(), playbook, out)
    content = out.read_text()
    assert "UNK-abc123" in content


def test_export_markdown_htm_ce_role_displayed(playbook: Playbook, tmp_path: Path) -> None:
    out = tmp_path / "packet.md"
    export_markdown(_make_packet(), playbook, out)
    content = out.read_text()
    assert "HTM / Clinical Engineering" in content


# ══════════════════════════════════════════════════════════════════════════════
# export_csv_tasks
# ══════════════════════════════════════════════════════════════════════════════

def _read_csv(path: Path) -> list[dict]:
    with path.open(encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def test_export_csv_creates_file(playbook: Playbook, tmp_path: Path) -> None:
    out = tmp_path / "packet.csv"
    export_csv_tasks(_make_packet(), playbook, out)
    assert out.exists()


def test_export_csv_content_length(playbook: Playbook, tmp_path: Path) -> None:
    out = tmp_path / "packet.csv"
    export_csv_tasks(_make_packet(), playbook, out)
    assert len(out.read_text()) > 100


def test_export_csv_columns(playbook: Playbook, tmp_path: Path) -> None:
    out = tmp_path / "packet.csv"
    export_csv_tasks(_make_packet(), playbook, out)
    rows = _read_csv(out)
    assert len(rows) > 0
    expected = {"task_id", "role", "action", "details", "verification", "priority", "pattern_id"}
    assert set(rows[0].keys()) == expected


def test_export_csv_row_count(playbook: Playbook, tmp_path: Path) -> None:
    # SEGMENTATION has 4 steps, ACL_ALLOWLIST has 3 → 7 rows total
    out = tmp_path / "packet.csv"
    export_csv_tasks(_make_packet(), playbook, out)
    rows = _read_csv(out)
    assert len(rows) == 7


def test_export_csv_task_id_format(playbook: Playbook, tmp_path: Path) -> None:
    out = tmp_path / "packet.csv"
    export_csv_tasks(_make_packet(), playbook, out)
    rows = _read_csv(out)
    assert rows[0]["task_id"] == "CVE-2024-1234-001"
    assert rows[6]["task_id"] == "CVE-2024-1234-007"


def test_export_csv_valid_roles(playbook: Playbook, tmp_path: Path) -> None:
    out = tmp_path / "packet.csv"
    export_csv_tasks(_make_packet(), playbook, out)
    rows = _read_csv(out)
    valid_roles = {"infosec", "netops", "htm_ce", "it_ops", "vendor", "clinical_ops"}
    for row in rows:
        assert row["role"] in valid_roles, f"Invalid role: {row['role']}"


def test_export_csv_pattern_id_column(playbook: Playbook, tmp_path: Path) -> None:
    out = tmp_path / "packet.csv"
    export_csv_tasks(_make_packet(), playbook, out)
    rows = _read_csv(out)
    pattern_ids = {r["pattern_id"] for r in rows}
    assert "SEGMENTATION_VLAN_ISOLATION" in pattern_ids
    assert "ACCESS_CONTROL_ACL_ALLOWLIST" in pattern_ids


def test_export_csv_verification_not_empty(playbook: Playbook, tmp_path: Path) -> None:
    out = tmp_path / "packet.csv"
    export_csv_tasks(_make_packet(), playbook, out)
    rows = _read_csv(out)
    for row in rows:
        assert row["verification"].strip(), "verification should not be empty"


def test_export_csv_priority_column(playbook: Playbook, tmp_path: Path) -> None:
    out = tmp_path / "packet.csv"
    export_csv_tasks(_make_packet(), playbook, out)
    rows = _read_csv(out)
    # Priority 1 rows come first (SEGMENTATION = priority_order 1)
    assert rows[0]["priority"] == "1"


def test_export_csv_empty_patterns(playbook: Playbook, tmp_path: Path) -> None:
    out = tmp_path / "packet.csv"
    export_csv_tasks(_make_empty_packet(), playbook, out)
    rows = _read_csv(out)
    assert rows == []  # header only, no data rows


def test_export_csv_skips_unknown_patterns(playbook: Playbook, tmp_path: Path) -> None:
    packet = _make_packet(patterns=[
        PatternRecommendation("INVENTED_PATTERN", "bogus", {}, 1),
        PatternRecommendation("SEGMENTATION_VLAN_ISOLATION", "real", {}, 2),
    ])
    out = tmp_path / "packet.csv"
    export_csv_tasks(packet, playbook, out)
    rows = _read_csv(out)
    pids = {r["pattern_id"] for r in rows}
    assert "INVENTED_PATTERN" not in pids
    assert "SEGMENTATION_VLAN_ISOLATION" in pids
