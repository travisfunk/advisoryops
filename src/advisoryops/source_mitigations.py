"""Source-cited mitigation extraction (Phase 8 — source authority).

Extracts specific mitigation actions explicitly stated in advisory source
text.  These are NOT AI-generated recommendations — they are what CISA,
vendors, and researchers *actually said to do*, attributed to the source
with its authority tier.

Pipeline position:
    Called by ``community_build.py`` after scoring, before feed-entry
    generation.  Results are stored on the issue dict as
    ``issue["source_mitigations"]``.

Design:
    * Uses gpt-4o-mini to parse mitigation steps from source text, but the
      prompt strictly forbids invention: "Extract ONLY mitigations explicitly
      stated in the source text."
    * Each mitigation is attributed to its source with the source's authority
      tier from source_weights.json.
    * Results are cached via ai_cache (same pattern as summarize.py).
    * Supports _call_fn injection for zero-cost unit testing.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from .ai_cache import cached_call
from .sanitize import sanitize_for_prompt

_DEFAULT_MODEL = "gpt-4o-mini"
_DEFAULT_CACHE_ROOT = "outputs/ai_cache"

_MITIGATION_TYPES = {"network", "patch", "monitor", "credential", "process", "other"}

_SYSTEM_PROMPT = """\
You are a cybersecurity advisory analyst. Your job is to extract specific \
mitigation actions that are EXPLICITLY stated in source advisory text.

CRITICAL RULES:
1. Extract ONLY mitigations explicitly stated in the source text. \
Do NOT invent or infer mitigations. If a source does not recommend a \
specific action, do not create one for it.
2. Each mitigation must be a concrete action (e.g., "apply patch v3.2.1", \
"isolate device from network", "rotate credentials").
3. Classify each mitigation into one type: network, patch, monitor, \
credential, process, or other.
4. If the source text is too vague to extract specific mitigations \
(e.g., just a CVE ID with no guidance), return an empty list.
5. Do NOT paraphrase general security advice. Only extract actions the \
source explicitly recommends for this specific vulnerability/issue.

Respond ONLY with a JSON object — no markdown, no code fences:
{
  "mitigations": [
    {
      "action": "<specific mitigation step quoted/paraphrased from source>",
      "mitigation_type": "<network|patch|monitor|credential|process|other>",
      "verbatim_snippet": "<short quote from source text that supports this>"
    }
  ]
}\
"""


def _load_source_tiers() -> Dict[str, int]:
    """Load source_weights.json and build a source_id -> tier_number map."""
    weights_path = Path("configs/source_weights.json")
    if not weights_path.exists():
        return {}
    data = json.loads(weights_path.read_text(encoding="utf-8"))
    tiers = data.get("tiers", {})
    mapping: Dict[str, int] = {}
    for tier_key, tier_data in tiers.items():
        # tier_key is like "tier_1", "tier_2", etc.
        try:
            tier_num = int(tier_key.split("_")[1])
        except (IndexError, ValueError):
            continue
        for sid in tier_data.get("sources", []):
            mapping[sid] = tier_num
    return mapping


def _build_user_prompt(issue: Dict[str, Any], source_id: str) -> str:
    """Build the user prompt for a single source's contribution to an issue."""
    issue_id = str(issue.get("issue_id") or "unknown")
    title = sanitize_for_prompt(str(issue.get("title") or ""), field_name="title")

    # Prefer enriched page text (richer), fall back to RSS summary
    enriched = str(issue.get("enriched_text") or "").strip()
    summary = str(issue.get("summary") or "").strip()
    if enriched and len(enriched) > len(summary):
        advisory_text = sanitize_for_prompt(
            enriched, field_name="enriched_text", max_length=12000,
        )
        text_source = "full advisory page"
    else:
        advisory_text = sanitize_for_prompt(
            summary, field_name="summary", max_length=6000,
        )
        text_source = "RSS summary"

    cves = ", ".join(issue.get("cves") or []) or "(none)"

    lines = [
        f"Issue: {issue_id}",
        f"Title: {title}",
        f"CVEs: {cves}",
        f"Source being analyzed: {source_id}",
        f"Text source: {text_source}",
        "",
        "Advisory text:",
        advisory_text or "(no text available)",
        "",
        "Focus on the MITIGATIONS, RECOMMENDATIONS, or REMEDIATION sections "
        "if present. Extract ONLY the mitigation actions explicitly stated in "
        "this text. If no specific mitigations are stated, return an empty list. "
        "Respond in JSON.",
    ]
    return "\n".join(lines)


def _get_source_url(issue: Dict[str, Any], source_id: str) -> str:
    """Try to find a URL for this source from the issue's links or signals."""
    # Check signals for a link from this source
    for sig in issue.get("signals", []):
        if sig.get("source") == source_id and sig.get("link"):
            return str(sig["link"])
    # Fallback to canonical_link
    return str(issue.get("canonical_link") or "")


def _get_source_citation(issue: Dict[str, Any], source_id: str) -> str:
    """Build a citation string from the issue's signals for this source."""
    for sig in issue.get("signals", []):
        if sig.get("source") == source_id:
            guid = sig.get("guid") or ""
            if guid:
                return guid
    # Fallback to issue_id
    return str(issue.get("issue_id") or "")


def extract_source_mitigations(
    issue: Dict[str, Any],
    *,
    model: str = _DEFAULT_MODEL,
    cache_root: str = _DEFAULT_CACHE_ROOT,
    no_cache: bool = False,
    _call_fn: Optional[Callable[[], Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    """Extract source-cited mitigations from an issue's advisory text.

    Args:
        issue:      Scored issue dict (needs issue_id, title, summary, sources,
                    signals at minimum).
        model:      OpenAI model to use.
        cache_root: Directory for on-disk AI response cache.
        no_cache:   Bypass cache.
        _call_fn:   Injectable callable for testing. When provided, called once
                    (not per-source) and must return a dict with "result" key.

    Returns:
        List of mitigation dicts, each with: source, source_tier, action,
        citation, url, mitigation_type.
    """
    issue_id = str(issue.get("issue_id") or "unknown")
    sources = issue.get("sources") or []
    summary_text = str(issue.get("summary") or "")

    if not sources or not summary_text.strip():
        return []

    tier_map = _load_source_tiers()
    all_mitigations: List[Dict[str, Any]] = []

    # For testing: if _call_fn provided, use it once for all sources
    if _call_fn is not None:
        entry = _call_fn()
        result = entry.get("result") or {}
        raw_mits = result.get("mitigations") or []
        if not isinstance(raw_mits, list):
            raw_mits = []

        # Attribute to first source if available
        src = sources[0] if sources else "unknown"
        for m in raw_mits:
            if not isinstance(m, dict):
                continue
            action = str(m.get("action") or "").strip()
            if not action:
                continue
            mit_type = str(m.get("mitigation_type") or "other").lower()
            if mit_type not in _MITIGATION_TYPES:
                mit_type = "other"
            all_mitigations.append({
                "source": src,
                "source_tier": tier_map.get(src, 5),
                "action": action,
                "citation": _get_source_citation(issue, src),
                "url": _get_source_url(issue, src),
                "mitigation_type": mit_type,
            })
        return all_mitigations

    # Production path: one AI call per issue (all sources combined)
    # Use enriched text in cache key so enriched issues get fresh calls
    enriched = str(issue.get("enriched_text") or "").strip()
    text_for_key = enriched[:3000] if enriched else summary_text[:3000]
    key_data = {
        "fn": "extract_source_mitigations_v2",
        "model": model,
        "issue_id": issue_id,
        "text": text_for_key,
        "sources": sorted(sources),
    }

    def _default_call_fn() -> Dict[str, Any]:
        if not os.getenv("OPENAI_API_KEY"):
            raise RuntimeError(
                "OPENAI_API_KEY is not set. Set the env var or pass _call_fn."
            )
        from openai import OpenAI  # type: ignore

        client = OpenAI()
        user_prompt = _build_user_prompt(issue, ", ".join(sources))
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

    result = entry.get("result") or {}
    raw_mits = result.get("mitigations") or []
    if not isinstance(raw_mits, list):
        raw_mits = []

    # Attribute to the highest-tier source (best authority)
    best_source = sources[0] if sources else "unknown"
    best_tier = tier_map.get(best_source, 5)
    for s in sources:
        t = tier_map.get(s, 5)
        if t < best_tier:
            best_tier = t
            best_source = s

    for m in raw_mits:
        if not isinstance(m, dict):
            continue
        action = str(m.get("action") or "").strip()
        if not action:
            continue
        mit_type = str(m.get("mitigation_type") or "other").lower()
        if mit_type not in _MITIGATION_TYPES:
            mit_type = "other"
        all_mitigations.append({
            "source": best_source,
            "source_tier": best_tier,
            "action": action,
            "citation": _get_source_citation(issue, best_source),
            "url": _get_source_url(issue, best_source),
            "mitigation_type": mit_type,
        })

    return all_mitigations


# ---------------------------------------------------------------------------
# Cross-source CVE correlation (deterministic — no AI)
# ---------------------------------------------------------------------------

def correlate_mitigations_by_cve(
    issues: List[Dict[str, Any]],
) -> int:
    """Fill in source_mitigations for issues that share CVEs with other issues.

    For any issue that has ZERO source_mitigations but shares CVEs with
    issues that DO have mitigations, copy those mitigations with a
    "(via CVE-XXXX)" attribution note.

    Mutates issues in place. Returns the count of issues that gained mitigations.

    Args:
        issues: List of scored issue dicts (already processed by
                extract_source_mitigations).

    Returns:
        Number of issues that received cross-source mitigations.
    """
    # Build CVE -> mitigations index
    cve_mits: Dict[str, List[Dict[str, Any]]] = {}
    for iss in issues:
        mits = iss.get("source_mitigations") or []
        if not mits:
            continue
        for cve in iss.get("cves") or []:
            if cve not in cve_mits:
                cve_mits[cve] = []
            cve_mits[cve].extend(mits)

    if not cve_mits:
        return 0

    count = 0
    for iss in issues:
        if iss.get("source_mitigations"):
            continue  # already has mitigations
        cves = iss.get("cves") or []
        if not cves:
            continue

        cross_mits: List[Dict[str, Any]] = []
        seen_actions: set = set()

        for cve in cves:
            for m in cve_mits.get(cve, []):
                action = m["action"]
                if action in seen_actions:
                    continue
                seen_actions.add(action)
                cross_mits.append({
                    "source": f"{m['source']} (via {cve})",
                    "source_tier": m["source_tier"],
                    "action": action,
                    "citation": m["citation"],
                    "url": m["url"],
                    "mitigation_type": m["mitigation_type"],
                    "cross_source": True,
                })

        if cross_mits:
            iss["source_mitigations"] = cross_mits
            count += 1

    return count
