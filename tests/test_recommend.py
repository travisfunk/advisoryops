"""Tests for advisoryops/recommend.py (Phase 4, Task 4.2).

Contract under test
-------------------
* System prompt embeds ALL approved pattern IDs — AI cannot hallucinate others.
* Hallucinated pattern IDs in AI responses are silently filtered.
* tasks_by_role is built from actual playbook steps for each selected pattern.
* Cache hit avoids the second API call (call_fn.call_count == 1).
* no_cache=True forces API call every time.
* RemediationPacket fields: issue_id, recommended_patterns, tasks_by_role,
  reasoning, citations, model, tokens_used, from_cache.
* PatternRecommendation.priority_order sorts the list ascending (1 = first).
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from advisoryops.playbook import load_playbook, Playbook
from advisoryops.recommend import (
    PatternRecommendation,
    RemediationPacket,
    _build_system_prompt,
    _build_user_prompt,
    _parse_ai_response,
    recommend_mitigations,
)


# ── fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def playbook() -> Playbook:
    return load_playbook()


def _rce_issue() -> dict:
    return {
        "issue_id": "CVE-2024-1234",
        "title": "Remote Code Execution in Philips IntelliSpace Cardiovascular",
        "summary": (
            "A critical vulnerability allows unauthenticated remote code execution. "
            "No patch available. Vendor recommends network segmentation."
        ),
        "sources": ["cisa-icsma"],
        "score": 95,
        "priority": "P0",
        "cves": ["CVE-2024-1234"],
        "links": ["https://www.cisa.gov/ics/advisories/icsma-24-001"],
    }


def _make_call_fn(
    selected_patterns: list,
    reasoning: str = "Test reasoning.",
    model: str = "gpt-4o-mini",
    tokens: int = 55,
) -> MagicMock:
    """Return a zero-argument MagicMock that produces a valid cached_call payload."""
    result = {"selected_patterns": selected_patterns, "reasoning": reasoning}
    return MagicMock(return_value={"result": result, "model": model, "tokens_used": tokens})


def _seg_pattern_item(priority: int = 1) -> dict:
    return {
        "pattern_id": "SEGMENTATION_VLAN_ISOLATION",
        "why_selected": "Device is network-accessible with no patch available.",
        "parameters": {"current_vlan_subnet": "10.0.1.0/24", "maintenance_window": "TBD"},
        "priority_order": priority,
    }


def _acl_pattern_item(priority: int = 2) -> dict:
    return {
        "pattern_id": "ACCESS_CONTROL_ACL_ALLOWLIST",
        "why_selected": "ACL allowlist reduces exposure while patch is pending.",
        "parameters": {"allowed_hosts": "PACS server"},
        "priority_order": priority,
    }


# ══════════════════════════════════════════════════════════════════════════════
# Prompt builder tests
# ══════════════════════════════════════════════════════════════════════════════

def test_system_prompt_contains_all_pattern_ids(playbook: Playbook) -> None:
    """Every approved pattern ID appears in the system prompt."""
    prompt = _build_system_prompt(playbook)
    for p in playbook.patterns:
        assert p.id in prompt, f"Pattern ID '{p.id}' missing from system prompt"


def test_system_prompt_contains_pattern_conditions(playbook: Playbook) -> None:
    """When-to-use conditions appear in the system prompt."""
    prompt = _build_system_prompt(playbook)
    first = playbook.patterns[0]
    for cond in first.when_to_use.conditions:
        assert cond[:40] in prompt, f"Condition snippet missing: {cond[:40]!r}"


def test_system_prompt_contains_inputs_required(playbook: Playbook) -> None:
    """inputs_required field values appear in the system prompt."""
    prompt = _build_system_prompt(playbook)
    first = playbook.patterns[0]
    for inp in first.inputs_required:
        assert inp in prompt, f"Input '{inp}' missing from system prompt"


def test_user_prompt_includes_issue_fields() -> None:
    issue = _rce_issue()
    prompt = _build_user_prompt(issue)
    assert "CVE-2024-1234" in prompt
    assert "Remote Code Execution" in prompt
    assert "P0" in prompt
    assert "cisa-icsma" in prompt
    assert "95" in prompt


def test_user_prompt_includes_links() -> None:
    issue = _rce_issue()
    prompt = _build_user_prompt(issue)
    assert "cisa.gov" in prompt


def test_user_prompt_handles_empty_issue() -> None:
    """No KeyError on a minimal issue dict."""
    prompt = _build_user_prompt({})
    assert "issue_id" in prompt


# ══════════════════════════════════════════════════════════════════════════════
# _parse_ai_response
# ══════════════════════════════════════════════════════════════════════════════

def test_parse_valid_response_returns_single_recommendation(playbook: Playbook) -> None:
    raw = {
        "selected_patterns": [_seg_pattern_item()],
        "reasoning": "Segmentation is the primary control here.",
    }
    recs, tasks, reasoning, _ = _parse_ai_response(raw, playbook, _rce_issue())
    assert len(recs) == 1
    assert recs[0].pattern_id == "SEGMENTATION_VLAN_ISOLATION"
    assert recs[0].priority_order == 1
    assert "Segmentation is the primary" in reasoning


def test_parse_filters_hallucinated_pattern_ids(playbook: Playbook) -> None:
    """AI cannot hallucinate pattern IDs — they are silently dropped."""
    raw = {
        "selected_patterns": [
            {"pattern_id": "INVENTED_PATTERN_XYZ", "why_selected": "...", "parameters": {}, "priority_order": 1},
            _seg_pattern_item(priority=2),
        ],
        "reasoning": "test",
    }
    recs, _, _, _ = _parse_ai_response(raw, playbook, _rce_issue())
    ids = [r.pattern_id for r in recs]
    assert "INVENTED_PATTERN_XYZ" not in ids
    assert "SEGMENTATION_VLAN_ISOLATION" in ids
    assert len(recs) == 1


def test_parse_builds_tasks_by_role(playbook: Playbook) -> None:
    """tasks_by_role is built from playbook steps of each selected pattern."""
    raw = {"selected_patterns": [_seg_pattern_item()], "reasoning": ""}
    _, tasks, _, _ = _parse_ai_response(raw, playbook, _rce_issue())
    # SEGMENTATION_VLAN_ISOLATION has steps for netops, infosec, htm_ce
    assert "netops" in tasks
    assert "infosec" in tasks
    assert "htm_ce" in tasks
    assert len(tasks["netops"]) == 2  # two netops steps in that pattern


def test_parse_task_text_includes_pattern_name(playbook: Playbook) -> None:
    raw = {"selected_patterns": [_seg_pattern_item()], "reasoning": ""}
    _, tasks, _, _ = _parse_ai_response(raw, playbook, _rce_issue())
    all_tasks = [t for ts in tasks.values() for t in ts]
    assert any("VLAN" in t or "Zone Isolation" in t for t in all_tasks)


def test_parse_empty_response_returns_empty(playbook: Playbook) -> None:
    recs, tasks, reasoning, _ = _parse_ai_response({}, playbook, _rce_issue())
    assert recs == []
    assert tasks == {}
    assert reasoning == ""


def test_parse_non_dict_response_treated_as_empty(playbook: Playbook) -> None:
    recs, tasks, _, _ = _parse_ai_response("oops", playbook, _rce_issue())
    assert recs == []
    assert tasks == {}


def test_parse_sorts_by_priority_order(playbook: Playbook) -> None:
    """Recommendations are sorted ascending by priority_order (1 = first)."""
    raw = {
        "selected_patterns": [
            _acl_pattern_item(priority=2),
            _seg_pattern_item(priority=1),
        ],
        "reasoning": "",
    }
    recs, _, _, _ = _parse_ai_response(raw, playbook, _rce_issue())
    assert len(recs) == 2
    assert recs[0].pattern_id == "SEGMENTATION_VLAN_ISOLATION"
    assert recs[1].pattern_id == "ACCESS_CONTROL_ACL_ALLOWLIST"


def test_parse_parameters_coerced_to_str(playbook: Playbook) -> None:
    raw = {
        "selected_patterns": [
            {
                "pattern_id": "SEGMENTATION_VLAN_ISOLATION",
                "why_selected": "ok",
                "parameters": {"current_vlan_subnet": 42, "maintenance_window": None},
                "priority_order": 1,
            }
        ],
        "reasoning": "",
    }
    recs, _, _, _ = _parse_ai_response(raw, playbook, _rce_issue())
    assert isinstance(recs[0].parameters["current_vlan_subnet"], str)


# ══════════════════════════════════════════════════════════════════════════════
# recommend_mitigations: mock API call
# ══════════════════════════════════════════════════════════════════════════════

def test_recommend_returns_remediation_packet(playbook: Playbook, tmp_path: Path) -> None:
    call_fn = _make_call_fn([_seg_pattern_item()])
    packet = recommend_mitigations(_rce_issue(), playbook, cache_root=tmp_path, _call_fn=call_fn)
    assert isinstance(packet, RemediationPacket)
    assert packet.issue_id == "CVE-2024-1234"


def test_recommend_packet_has_at_least_one_pattern(playbook: Playbook, tmp_path: Path) -> None:
    call_fn = _make_call_fn([_seg_pattern_item()])
    packet = recommend_mitigations(_rce_issue(), playbook, cache_root=tmp_path, _call_fn=call_fn)
    assert len(packet.recommended_patterns) >= 1
    assert packet.recommended_patterns[0].pattern_id == "SEGMENTATION_VLAN_ISOLATION"


def test_recommend_packet_has_tasks_by_role(playbook: Playbook, tmp_path: Path) -> None:
    call_fn = _make_call_fn([_seg_pattern_item()])
    packet = recommend_mitigations(_rce_issue(), playbook, cache_root=tmp_path, _call_fn=call_fn)
    assert len(packet.tasks_by_role) >= 2
    all_tasks = [t for ts in packet.tasks_by_role.values() for t in ts]
    assert any("VLAN" in t or "Zone" in t for t in all_tasks)


def test_recommend_packet_includes_citations(playbook: Playbook, tmp_path: Path) -> None:
    call_fn = _make_call_fn([_seg_pattern_item()])
    packet = recommend_mitigations(_rce_issue(), playbook, cache_root=tmp_path, _call_fn=call_fn)
    assert "https://www.cisa.gov/ics/advisories/icsma-24-001" in packet.citations


def test_recommend_call_fn_called_exactly_once(playbook: Playbook, tmp_path: Path) -> None:
    """On first call (cache miss), the API function is invoked exactly once."""
    call_fn = _make_call_fn([_seg_pattern_item()])
    recommend_mitigations(_rce_issue(), playbook, cache_root=tmp_path, _call_fn=call_fn)
    call_fn.assert_called_once()


def test_recommend_cache_hit_skips_api_call(playbook: Playbook, tmp_path: Path) -> None:
    """Second call with same issue hits cache — call_fn NOT invoked again."""
    call_fn = _make_call_fn([_seg_pattern_item()])
    issue = _rce_issue()

    recommend_mitigations(issue, playbook, cache_root=tmp_path, _call_fn=call_fn)
    recommend_mitigations(issue, playbook, cache_root=tmp_path, _call_fn=call_fn)

    assert call_fn.call_count == 1, "Cache hit should skip second API call"


def test_recommend_second_call_from_cache_flag(playbook: Playbook, tmp_path: Path) -> None:
    """Packet from cache hit has from_cache=True."""
    call_fn = _make_call_fn([_seg_pattern_item()])
    issue = _rce_issue()

    p1 = recommend_mitigations(issue, playbook, cache_root=tmp_path, _call_fn=call_fn)
    p2 = recommend_mitigations(issue, playbook, cache_root=tmp_path, _call_fn=call_fn)

    assert p1.from_cache is False
    assert p2.from_cache is True


def test_recommend_no_cache_always_calls_api(playbook: Playbook, tmp_path: Path) -> None:
    """no_cache=True bypasses cache — API called on every invocation."""
    call_fn = _make_call_fn([_seg_pattern_item()])
    issue = _rce_issue()

    recommend_mitigations(issue, playbook, cache_root=tmp_path, _call_fn=call_fn, no_cache=True)
    recommend_mitigations(issue, playbook, cache_root=tmp_path, _call_fn=call_fn, no_cache=True)

    assert call_fn.call_count == 2


def test_recommend_metadata_captured(playbook: Playbook, tmp_path: Path) -> None:
    """RemediationPacket captures model name and token count."""
    call_fn = _make_call_fn([_seg_pattern_item()], model="gpt-4o-mini", tokens=77)
    packet = recommend_mitigations(_rce_issue(), playbook, cache_root=tmp_path, _call_fn=call_fn)
    assert packet.model == "gpt-4o-mini"
    assert packet.tokens_used == 77


def test_recommend_hallucinated_patterns_filtered(playbook: Playbook, tmp_path: Path) -> None:
    """AI-hallucinated pattern IDs are dropped; real ones are kept."""
    call_fn = _make_call_fn([
        {"pattern_id": "HALLUCINATED_PATTERN_XYZ", "why_selected": "bogus", "parameters": {}, "priority_order": 1},
        _seg_pattern_item(priority=2),
    ])
    packet = recommend_mitigations(_rce_issue(), playbook, cache_root=tmp_path, _call_fn=call_fn)
    ids = [r.pattern_id for r in packet.recommended_patterns]
    assert "HALLUCINATED_PATTERN_XYZ" not in ids
    assert "SEGMENTATION_VLAN_ISOLATION" in ids


def test_recommend_multiple_patterns_ordered(playbook: Playbook, tmp_path: Path) -> None:
    """Multiple patterns are returned sorted by priority_order (1 first)."""
    call_fn = _make_call_fn([_acl_pattern_item(priority=2), _seg_pattern_item(priority=1)])
    packet = recommend_mitigations(_rce_issue(), playbook, cache_root=tmp_path, _call_fn=call_fn)
    assert len(packet.recommended_patterns) == 2
    assert packet.recommended_patterns[0].pattern_id == "SEGMENTATION_VLAN_ISOLATION"
    assert packet.recommended_patterns[1].pattern_id == "ACCESS_CONTROL_ACL_ALLOWLIST"


def test_recommend_tasks_span_multiple_roles(playbook: Playbook, tmp_path: Path) -> None:
    """When two patterns are selected, tasks_by_role includes roles from both."""
    call_fn = _make_call_fn([_seg_pattern_item(priority=1), _acl_pattern_item(priority=2)])
    packet = recommend_mitigations(_rce_issue(), playbook, cache_root=tmp_path, _call_fn=call_fn)
    # Both patterns share netops, infosec, htm_ce roles — all should appear
    assert "netops" in packet.tasks_by_role
    assert "infosec" in packet.tasks_by_role
    assert "htm_ce" in packet.tasks_by_role


def test_recommend_empty_links_gives_empty_citations(playbook: Playbook, tmp_path: Path) -> None:
    call_fn = _make_call_fn([_seg_pattern_item()])
    issue = {**_rce_issue(), "links": []}
    packet = recommend_mitigations(issue, playbook, cache_root=tmp_path, _call_fn=call_fn)
    assert packet.citations == []


def test_recommend_all_patterns_are_valid_ids(playbook: Playbook, tmp_path: Path) -> None:
    """Every pattern_id in the packet exists in the playbook."""
    call_fn = _make_call_fn([_seg_pattern_item(), _acl_pattern_item(priority=2)])
    packet = recommend_mitigations(_rce_issue(), playbook, cache_root=tmp_path, _call_fn=call_fn)
    valid_ids = {p.id for p in playbook.patterns}
    for rec in packet.recommended_patterns:
        assert rec.pattern_id in valid_ids
