"""Pattern selection engine (Phase 4, Task 4.2).

Given a scored issue and a loaded Playbook, uses an LLM to select the most
appropriate mitigation patterns and parameterize them for the specific issue.

Design
------
* The AI sees the *full* pattern catalog (ids, names, conditions, inputs) so it
  can ONLY select from approved patterns.
* Hallucinated pattern IDs are silently filtered before the packet is returned.
  This is the key safety property: the AI cannot invent new patterns, only choose
  from the curated and clinically-reviewed set.
* Results are cached via ai_cache so repeat calls for the same issue are free.

Prompt architecture:
  * System/instruction prompt — embeds the full pattern catalog as structured text
    so the model sees all valid options at once.  Includes explicit rules:
    select 1-4 patterns, use only approved IDs, fill parameters from issue context.
  * User/input prompt — presents the scored issue fields (id, title, priority, score,
    CVEs, sources, links, summary).
  * Response format — json_object mode so the model always returns parseable JSON.

Output (RemediationPacket):
  recommended_patterns — list of PatternRecommendation (pattern_id, why_selected,
                         parameters dict, priority_order integer)
  tasks_by_role        — dict mapping role → list of task strings, built from the
                         playbook steps of all selected patterns
  reasoning            — 2-3 sentence AI summary of the recommendations
  citations            — deduped list of issue links (for source references)
  model / tokens_used / from_cache — cost and provenance metadata
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from .ai_cache import cached_call
from .playbook import Playbook

_DEFAULT_MODEL = "gpt-4o-mini"
_DEFAULT_CACHE_ROOT = "outputs/ai_cache"


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class PatternRecommendation:
    """One AI-selected pattern with parameterisation hints."""
    pattern_id: str
    why_selected: str
    parameters: Dict[str, str]
    priority_order: int  # 1 = highest priority


@dataclass
class RemediationPacket:
    """Full recommendation output for a single scored issue."""
    issue_id: str
    recommended_patterns: List[PatternRecommendation]
    tasks_by_role: Dict[str, List[str]]
    reasoning: str
    citations: List[str]
    model: str = ""
    tokens_used: int = 0
    from_cache: bool = False
    # Provenance fields (default empty so existing callers are unaffected)
    evidence_sources: List[str] = field(default_factory=list)
    extracted_facts: Dict[str, Any] = field(default_factory=dict)
    inferred_facts: Dict[str, Any] = field(default_factory=dict)
    confidence_by_field: Dict[str, float] = field(default_factory=dict)
    insufficient_evidence: bool = False
    evidence_gaps: List[str] = field(default_factory=list)
    handling_warnings: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Prompt builders
# ---------------------------------------------------------------------------

def _pattern_catalog_text(playbook: Playbook) -> str:
    """Serialize all patterns as a compact text block suitable for the prompt."""
    lines: List[str] = []
    for p in playbook.patterns:
        lines.append(f"Pattern ID: {p.id}")
        lines.append(f"  Name: {p.name}")
        lines.append(f"  Category: {p.category}")
        lines.append(f"  Severity fit: {', '.join(p.severity_fit)}")
        if p.when_to_use.conditions:
            lines.append("  Apply when:")
            for cond in p.when_to_use.conditions:
                lines.append(f"    - {cond}")
        if p.when_to_use.constraints:
            lines.append("  Constraints:")
            for c in p.when_to_use.constraints:
                lines.append(f"    - {c}")
        if p.inputs_required:
            lines.append(f"  Inputs required: {', '.join(p.inputs_required)}")
        lines.append("")
    return "\n".join(lines)


def _build_system_prompt(playbook: Playbook) -> str:
    """Build the system/instruction prompt embedding the full pattern catalog."""
    catalog = _pattern_catalog_text(playbook)
    valid_ids = ", ".join(p.id for p in playbook.patterns)
    return (
        "You are a healthcare cybersecurity mitigation advisor.\n"
        "Given a scored security issue, select the most appropriate mitigation "
        "patterns from the approved catalog below.\n\n"
        "RULES:\n"
        f"1. You MUST ONLY select pattern_ids from this approved list: {valid_ids}\n"
        "2. Do NOT invent new patterns or modify existing ones.\n"
        "3. Select 1-4 patterns most relevant to the issue. "
        "Do not include patterns whose conditions clearly do not apply.\n"
        "4. PARAMETER EXTRACTION (critical): Fill the 'parameters' dict by extracting "
        "values directly from the advisory text. Do NOT use 'unknown' — instead extract "
        "partial information where possible (e.g. vendor name, device type, CVE ID, "
        "patch status). Only omit a parameter if it is truly absent from all available text.\n"
        "5. ATTACK-VECTOR ANALYSIS (required before selecting patterns): Before selecting "
        "patterns, first determine: (a) Is this network-accessible? (b) Does the vendor "
        "provide a patch or only workarounds? (c) Is the device life-critical or "
        "patient-care adjacent? Use these answers to choose the most appropriate patterns. "
        "For example: network-accessible + no patch = segmentation patterns first; "
        "vendor patch available = patching pattern; life-critical device = operational "
        "caution and clinical notice patterns.\n"
        "6. Return ONLY valid JSON — no markdown fences, no commentary.\n\n"
        "OUTPUT FORMAT (return exactly this JSON structure, nothing else):\n"
        '{\n'
        '  "selected_patterns": [\n'
        '    {\n'
        '      "pattern_id": "<approved pattern id>",\n'
        '      "why_selected": "<1-2 sentence justification including attack vector analysis>",\n'
        '      "parameters": {<key: extracted value from advisory text>},\n'
        '      "priority_order": <integer, 1 = highest priority>\n'
        '    }\n'
        '  ],\n'
        '  "reasoning": "<2-3 sentence overall summary including attack vector and why these patterns were chosen>",\n'
        '  "evidence_sources": ["<source_id from the issue>", ...],\n'
        '  "confidence_by_field": {\n'
        '    "pattern_selection": <float 0.0-1.0>,\n'
        '    "parameter_extraction": <float 0.0-1.0>\n'
        '  },\n'
        '  "extracted_facts": {"<key>": "<fact from advisory text>"},\n'
        '  "inferred_facts": {"<key>": "<fact reasoned from context>"},\n'
        '  "evidence_gaps": ["<missing info that would improve recommendations>", ...],\n'
        '  "insufficient_evidence": <true | false>,\n'
        '  "handling_warnings": ["<medical device operational caution if applicable>", ...]\n'
        "}\n\n"
        "APPROVED PATTERNS CATALOG:\n"
        + catalog
    )


def _build_user_prompt(issue: Dict[str, Any]) -> str:
    """Build the user/input prompt from a scored issue dict."""
    issue_id = issue.get("issue_id", "unknown")
    title = issue.get("title", "")
    summary = issue.get("summary", "")
    priority = issue.get("priority", "")
    score = issue.get("score", "")
    cves = issue.get("cves") or []
    sources = issue.get("sources") or []
    links = issue.get("links") or []

    lines = [
        "Select mitigation patterns for the following security issue:",
        "",
        f"issue_id:  {issue_id}",
        f"title:     {title}",
        f"priority:  {priority}",
        f"score:     {score}",
        f"cves:      {', '.join(cves) if cves else 'none'}",
        f"sources:   {', '.join(str(s) for s in sources) if sources else 'none'}",
        f"links:     {', '.join(str(l) for l in links[:5]) if links else 'none'}",
        "",
        "summary:",
        summary or "(no summary provided)",
        "",
        "Return the JSON response.",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Response parsing
# ---------------------------------------------------------------------------

def _parse_ai_response(
    raw_json: Any,
    playbook: Playbook,
    issue: Dict[str, Any],
) -> Tuple[List[PatternRecommendation], Dict[str, List[str]], str, Dict[str, Any]]:
    """Parse AI JSON into (recommended_patterns, tasks_by_role, reasoning, provenance).

    Hallucinated pattern IDs (not in the playbook) are silently dropped.
    Returns a 4-tuple; the last element is a dict of provenance fields.
    """
    if not isinstance(raw_json, dict):
        raw_json = {}

    reasoning = str(raw_json.get("reasoning") or "")
    selected_raw = raw_json.get("selected_patterns") or []
    if not isinstance(selected_raw, list):
        selected_raw = []

    valid_ids = {p.id for p in playbook.patterns}
    recommendations: List[PatternRecommendation] = []
    tasks_by_role: Dict[str, List[str]] = {}

    for item in selected_raw:
        if not isinstance(item, dict):
            continue
        pid = str(item.get("pattern_id") or "").strip()
        if pid not in valid_ids:
            continue  # silently drop hallucinated IDs

        params = item.get("parameters") or {}
        if not isinstance(params, dict):
            params = {}

        rec = PatternRecommendation(
            pattern_id=pid,
            why_selected=str(item.get("why_selected") or ""),
            parameters={str(k): str(v) for k, v in params.items()},
            priority_order=int(item.get("priority_order") or 1),
        )
        recommendations.append(rec)

        # Build role-split task list from playbook steps
        pattern = playbook.get(pid)
        if pattern:
            for step in pattern.steps:
                role_tasks = tasks_by_role.setdefault(step.role, [])
                task_text = f"[{pattern.name}] {step.action}: {step.details}"
                role_tasks.append(task_text)

    recommendations.sort(key=lambda r: r.priority_order)

    # Extract provenance fields
    provenance = {
        "evidence_sources": [str(s) for s in (raw_json.get("evidence_sources") or []) if s],
        "confidence_by_field": {str(k): float(v) for k, v in (raw_json.get("confidence_by_field") or {}).items()},
        "extracted_facts": dict(raw_json.get("extracted_facts") or {}),
        "inferred_facts": dict(raw_json.get("inferred_facts") or {}),
        "evidence_gaps": [str(g) for g in (raw_json.get("evidence_gaps") or []) if g],
        "insufficient_evidence": bool(raw_json.get("insufficient_evidence", False)),
        "handling_warnings": [str(w) for w in (raw_json.get("handling_warnings") or []) if w],
    }

    return recommendations, tasks_by_role, reasoning, provenance


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def recommend_mitigations(
    issue: Dict[str, Any],
    playbook: Playbook,
    *,
    model: str = _DEFAULT_MODEL,
    no_cache: bool = False,
    cache_root: str = _DEFAULT_CACHE_ROOT,
    _call_fn: Optional[Callable[[], Any]] = None,
) -> RemediationPacket:
    """Select and parameterize mitigation patterns for a scored issue.

    The AI sees the full approved pattern catalog embedded in the prompt so it
    can ONLY select from those patterns.  Hallucinated IDs are filtered before
    the packet is returned.

    Results are cached by content hash of the issue fields + playbook version,
    so repeat calls for the same issue cost zero API credits.

    Args:
        issue:      Scored issue dict (keys: issue_id, title, summary, score,
                    priority, cves, sources, links).
        playbook:   Loaded Playbook instance from ``playbook.load_playbook()``.
        model:      OpenAI model to use (default: gpt-4o-mini).
        no_cache:   Bypass the response cache (always calls the API).
        cache_root: Directory for AI response cache files.
        _call_fn:   Override the API call function for testing. When provided,
                    called with no arguments; must return a dict with keys
                    ``result`` (parsed AI JSON), ``model``, and ``tokens_used``.

    Returns:
        RemediationPacket with recommended patterns, role-split tasks, citations,
        and cost metadata.

    Raises:
        RuntimeError: if OPENAI_API_KEY is not set and no ``_call_fn`` override
                      is provided.
    """
    issue_id = str(issue.get("issue_id") or "unknown")

    system_prompt = _build_system_prompt(playbook)
    user_prompt = _build_user_prompt(issue)

    # Cache key: content-hash of the issue fields that affect the recommendation
    key_data: Dict[str, Any] = {
        "fn": "recommend_mitigations_v2",
        "issue_id": issue_id,
        "title": str(issue.get("title") or ""),
        "summary": str(issue.get("summary") or ""),
        "score": int(issue.get("score") or 0),
        "playbook_version": playbook.version,
    }

    def _default_call_fn() -> Dict[str, Any]:
        if not os.getenv("OPENAI_API_KEY"):
            raise RuntimeError(
                "OPENAI_API_KEY is not set. Set the env var or pass _call_fn for testing."
            )
        from openai import OpenAI  # type: ignore

        client = OpenAI()
        resp = client.responses.create(
            model=model,
            instructions=system_prompt,
            input=user_prompt,
            text={"format": {"type": "json_object"}},
        )
        json_text = (getattr(resp, "output_text", None) or "").strip()
        if not json_text:
            raise RuntimeError("OpenAI response had empty output_text (expected JSON).")
        parsed = json.loads(json_text)
        usage = getattr(resp, "usage", None)
        tokens = int(getattr(usage, "total_tokens", 0) or 0) if usage else 0
        return {"result": parsed, "model": model, "tokens_used": tokens}

    actual_call_fn = _call_fn if _call_fn is not None else _default_call_fn

    entry = cached_call(
        key_data,
        actual_call_fn,
        model=model,
        cache_root=cache_root,
        no_cache=no_cache,
    )

    raw_result = entry.get("result") or {}
    recommendations, tasks_by_role, reasoning, provenance = _parse_ai_response(
        raw_result, playbook, issue
    )

    # Citations: issue links (deduped, up to 10)
    citations: List[str] = []
    for link in (issue.get("links") or []):
        s = str(link).strip()
        if s and s not in citations:
            citations.append(s)

    return RemediationPacket(
        issue_id=issue_id,
        recommended_patterns=recommendations,
        tasks_by_role=tasks_by_role,
        reasoning=reasoning,
        citations=citations,
        model=str(entry.get("model") or model),
        tokens_used=int(entry.get("tokens_used") or 0),
        from_cache=bool(entry.get("from_cache")),
        evidence_sources=provenance["evidence_sources"],
        extracted_facts=provenance["extracted_facts"],
        inferred_facts=provenance["inferred_facts"],
        confidence_by_field=provenance["confidence_by_field"],
        insufficient_evidence=provenance["insufficient_evidence"],
        evidence_gaps=provenance["evidence_gaps"],
        handling_warnings=provenance["handling_warnings"],
    )
