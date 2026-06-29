"""AI-powered plain-language advisory summarizer (Session D).

Rewrites raw RSS/feed summaries into 2-3 sentence descriptions written
for hospital security analysts — not developers.  Extracts unknowns,
handling warnings, and evidence completeness alongside the summary.

Pipeline position:
    Called by ``community_build.py`` after scoring, before feed-entry
    generation.  Results are merged back into the issue dict.

Usage::

    from advisoryops.summarize import summarize_advisory

    result = summarize_advisory(issue)
    # result = {
    #   "summary": "A critical vulnerability in ...",
    #   "unknowns": ["affected versions unclear"],
    #   "handling_warnings": ["do not reboot without vendor guidance"],
    #   "evidence_completeness": 0.75,
    # }

Supports ``_call_fn`` injection for zero-cost unit testing (same pattern
as ai_score.py and recommend.py).
"""
from __future__ import annotations

import json
import os
from typing import Any, Callable, Dict, List, Optional

from .ai_cache import cached_call
from .sanitize import sanitize_for_prompt

DEFAULT_MODEL = "gpt-4o-mini"
_DEFAULT_CACHE_ROOT = "outputs/ai_cache"

_SYSTEM_PROMPT = """\
You are a hospital cybersecurity communication specialist. Your job is to \
rewrite raw security advisory data into clear, actionable 2-3 sentence \
summaries that a hospital security analyst can understand immediately.

WRITING RULES:
1. Name the vendor, product/device, and vulnerability type.
2. State the severity (Critical/High/Medium/Low) and whether a patch exists.
3. State what action is recommended in plain language.
4. Use 2-3 sentences. No jargon, no CVE numbers in the summary text.
5. Write as if explaining to someone who protects hospital networks but \
   is not a software developer.

Also extract:
- unknowns: things the advisory leaves unclear (versions, patch timeline, etc.)
- handling_warnings: operational cautions for medical device environments
- evidence_completeness: float 0.0-1.0 indicating how complete the evidence is

Respond ONLY with a JSON object — no markdown, no code fences:
{
  "summary": "<2-3 sentence plain-language summary>",
  "unknowns": ["<what the advisory leaves unclear>", ...],
  "handling_warnings": ["<operational caution for device handling>", ...],
  "evidence_completeness": <float 0.0-1.0>
}\
"""


def _build_user_prompt(issue: Dict[str, Any]) -> str:
    """Build the user prompt from a scored issue dict."""
    issue_id = str(issue.get("issue_id") or "unknown")
    title = sanitize_for_prompt(str(issue.get("title") or ""), field_name="title")
    raw_summary = sanitize_for_prompt(
        str(issue.get("summary") or ""), field_name="summary", max_length=4000,
    )
    priority = str(issue.get("priority") or "")
    score = str(issue.get("score") or "")
    cves = ", ".join(issue.get("cves") or []) or "(none)"
    sources = ", ".join(str(s) for s in (issue.get("sources") or [])) or "(unknown)"
    vendor = str(issue.get("vendor") or "")

    existing_hw = issue.get("handling_warnings") or []
    existing_gaps = issue.get("evidence_gaps") or []

    lines = [
        f"Issue ID: {issue_id}",
        f"Title: {title}",
        f"Priority: {priority} (score {score})",
        f"CVEs: {cves}",
        f"Sources: {sources}",
    ]
    if vendor:
        lines.append(f"Vendor: {vendor}")
    if raw_summary:
        lines.append(f"\nRaw advisory text:\n{raw_summary}")
    if existing_hw:
        lines.append(f"\nExisting handling warnings: {'; '.join(existing_hw)}")
    if existing_gaps:
        lines.append(f"\nKnown evidence gaps: {'; '.join(existing_gaps)}")

    lines.append(
        "\nRewrite this into a plain-language summary for hospital staff. "
        "Respond in JSON."
    )
    return "\n".join(lines)


def summarize_advisory(
    issue: Dict[str, Any],
    *,
    model: str = DEFAULT_MODEL,
    cache_root: str = _DEFAULT_CACHE_ROOT,
    no_cache: bool = False,
    _call_fn: Optional[Callable[[], Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Summarize a scored issue into plain-language output.

    Args:
        issue:      Scored issue dict (needs issue_id, title, summary at minimum).
        model:      OpenAI model to use.
        cache_root: Directory for on-disk AI response cache.
        no_cache:   Bypass cache.
        _call_fn:   Injectable callable for testing.

    Returns:
        Dict with keys: summary, unknowns, handling_warnings, evidence_completeness.
    """
    issue_id = str(issue.get("issue_id") or "unknown")
    title = str(issue.get("title") or "")
    raw_summary = str(issue.get("summary") or "")

    key_data = {
        "fn": "summarize_advisory_v1",
        "model": model,
        "issue_id": issue_id,
        "title": title,
        "summary": raw_summary[:2000],
    }

    if _call_fn is not None:
        entry = _call_fn()
        from_cache = False
    else:
        def _default_call_fn() -> Dict[str, Any]:
            if not os.getenv("OPENAI_API_KEY"):
                raise RuntimeError(
                    "OPENAI_API_KEY is not set. Set the env var or pass _call_fn for testing."
                )
            from openai import OpenAI  # type: ignore

            client = OpenAI()
            user_prompt = _build_user_prompt(issue)
            resp = client.responses.create(
                model=model,
                instructions=_SYSTEM_PROMPT,
                input=user_prompt,
                text={"format": {"type": "json_object"}},
            )
            json_text = (getattr(resp, "output_text", None) or "").strip()
            if not json_text:
                raise RuntimeError("OpenAI response had empty output_text.")
            parsed = json.loads(json_text)
            usage = getattr(resp, "usage", None)
            tokens = int(getattr(usage, "total_tokens", 0) or 0) if usage else 0
            return {"result": parsed, "model": model, "tokens_used": tokens}

        entry = cached_call(
            key_data=key_data,
            call_fn=_default_call_fn,
            cache_root=cache_root,
            no_cache=no_cache,
        )
        from_cache = bool(entry.get("from_cache", False))

    result = entry.get("result") or {}

    summary_text = str(result.get("summary") or "").strip()
    unknowns = [str(u) for u in (result.get("unknowns") or []) if u]
    handling_warnings = [str(w) for w in (result.get("handling_warnings") or []) if w]

    ec = result.get("evidence_completeness", 0.0)
    try:
        evidence_completeness = max(0.0, min(1.0, float(ec)))
    except (ValueError, TypeError):
        evidence_completeness = 0.0

    return {
        "summary": summary_text,
        "unknowns": unknowns,
        "handling_warnings": handling_warnings,
        "evidence_completeness": evidence_completeness,
        "model": str(entry.get("model", model)),
        "tokens_used": int(entry.get("tokens_used", 0)),
        "from_cache": from_cache,
    }
