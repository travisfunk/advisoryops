"""LLM-based field extraction for issues with missing structured data.

FDA-recall-derived issues and other non-CVE records often arrive with
empty vendor, placeholder titles, and no affected_products even though
the AI-rewritten summary contains all of that information. This module
reads the summary and extracts structured fields using the same LLM
infrastructure (model, cache, injectable call_fn) as summarize.py.

Pipeline position:
    Called by ``community_build.py`` AFTER summarization (because it
    reads the rewritten summary), BEFORE feed-entry generation.

Usage::

    from advisoryops.extract_fields import extract_fields

    result = extract_fields(issue)
    # result = {"vendor": "Abiomed", "product_name": "Impella Controller", ...}
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
You are extracting structured fields from a healthcare security advisory summary.

Return a JSON object with any of these fields you can confidently determine:
- vendor: the manufacturer or vendor name
- product_name: the primary product or device name
- affected_products: array of specific product models or versions affected
- severity: one of "critical", "high", "medium", "low" — use the source's own language
- title: a clean human-readable title (only if the current title is missing, empty, or a placeholder like "item")

Only include fields you are confident about. Omit uncertain fields entirely.
Do not invent information not present in the summary.
Return ONLY a JSON object — no markdown, no code fences.\
"""


def _build_user_prompt(issue: Dict[str, Any]) -> str:
    """Build the user prompt from an issue dict."""
    title = str(issue.get("title") or "")
    vendor = str(issue.get("vendor") or "")
    summary = sanitize_for_prompt(
        str(issue.get("summary") or ""), field_name="summary", max_length=4000,
    )

    lines = [
        f"Current title: {title or '(empty)'}",
        f"Current vendor: {vendor or '(empty)'}",
        f"Summary:\n{summary}" if summary else "Summary: (empty)",
        "",
        "Return only the JSON object.",
    ]
    return "\n".join(lines)


def extract_fields(
    issue: Dict[str, Any],
    *,
    model: str = DEFAULT_MODEL,
    cache_root: str = _DEFAULT_CACHE_ROOT,
    no_cache: bool = False,
    _call_fn: Optional[Callable[[], Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Extract structured fields from an issue's summary text using an LLM.

    Returns a dict with any of these fields that could be extracted:
      - vendor: str
      - product_name: str
      - affected_products: List[str]
      - severity: str (one of: critical, high, medium, low)
      - title: str (a clean human-readable title if the current one is placeholder)

    Only fields the model is confident about are returned. Missing fields
    indicate the model could not determine them from the available text.

    Caches by content hash of the input summary.
    """
    summary = str(issue.get("summary") or "")
    if not summary.strip():
        return {}

    title = str(issue.get("title") or "")
    vendor = str(issue.get("vendor") or "")

    key_data = {
        "fn": "extract_fields_v1",
        "model": model,
        "title": title,
        "vendor": vendor,
        "summary": summary[:2000],
    }

    if _call_fn is not None:
        entry = _call_fn()
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
                max_output_tokens=150,
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

    # Only return fields with valid values
    extracted: Dict[str, Any] = {}
    for str_field in ("vendor", "product_name", "severity", "title"):
        val = result.get(str_field)
        if val and isinstance(val, str) and val.strip():
            extracted[str_field] = val.strip()

    if "severity" in extracted:
        extracted["severity"] = extracted["severity"].lower()
        if extracted["severity"] not in ("critical", "high", "medium", "low"):
            del extracted["severity"]

    products = result.get("affected_products")
    if products and isinstance(products, list):
        cleaned = [str(p).strip() for p in products if p and str(p).strip()]
        if cleaned:
            extracted["affected_products"] = cleaned

    return extracted
