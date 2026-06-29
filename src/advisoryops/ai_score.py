"""AI-assisted healthcare relevance classification for AdvisoryOps.

Phase 3, Task 3.3 — For issues where deterministic keyword scoring cannot
determine healthcare/device relevance, this module calls GPT-4o-mini to
classify the issue into one of four categories.

Pipeline position:
    Called by ``score.py`` (``score_issues``) only when ``ai_score=True``
    **and** the issue has no device/clinical/source-authority signal entries
    in its ``why`` list from the deterministic v2 scoring pass.  This selective
    invocation keeps API costs near zero for issues that are clearly medical.

Cost-control design:
    * Issues that already have deterministic signals skip this module entirely.
    * All API responses are cached on disk by ``ai_cache.cached_call`` — same
      issue title + summary never costs credits twice across runs.
    * Score boost is only applied at confidence ≥ 0.70 so low-confidence
      classifications don't inflate scores.
    * The ``_call_fn`` injection point allows all 15 tests to run with zero
      API calls — just pass a lambda that returns a canned response dict.

    medical_device       — affects a regulated medical device (infusion pump,
                           ventilator, implant, imaging system, etc.)
    healthcare_it        — affects healthcare IT infrastructure (EHR, PACS,
                           hospital network, clinical workstation, etc.)
    healthcare_adjacent  — indirectly relevant to healthcare (supply chain,
                           pharma, lab, etc.) but not a direct device/IT issue
    not_healthcare       — no meaningful healthcare relevance

Usage
-----
Call ``classify_healthcare_relevance(issue)`` only for issues where
deterministic classification is uncertain (i.e., ``score_issue_v2`` produced
no device/clinical signal hits).  This keeps API costs low.

The ``_call_fn`` injection point supports zero-cost unit testing::

    result = classify_healthcare_relevance(issue, _call_fn=lambda: {
        "result": {"category": "medical_device", "confidence": 0.9,
                   "reasoning": "...", "device_types": ["infusion pump"]},
        "model": "gpt-4o-mini",
        "tokens_used": 50,
    })
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from .ai_cache import cached_call

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_CLASSIFY_MODEL = "gpt-4o-mini"

_VALID_CATEGORIES = frozenset(
    ["medical_device", "healthcare_it", "healthcare_adjacent", "not_healthcare"]
)

_SYSTEM_PROMPT = """\
You are a healthcare cybersecurity analyst. Your job is to classify whether a \
security issue is relevant to healthcare, and if so, what type.

IMPORTANT — MEDICAL DEVICE RULE: Imaging systems (X-ray, CT, MRI, PET, \
fluoroscopy, dental panoramic, mammography), PACS/DICOM workstations, \
infusion pumps, insulin pumps, IV pumps, patient monitors, bedside monitors, \
ECG/EKG systems, central monitoring systems, ventilators, respirators, \
defibrillators, AEDs, pacemakers, implantable cardiac devices, surgical \
robots, and similar life-critical equipment MUST be classified as \
medical_device — even when these systems run on standard IT hardware \
(Windows, Linux) or use general-purpose software components. The decisive \
factor is the clinical function and deployment context, not the underlying OS.

Respond ONLY with a JSON object — no markdown, no code fences. Use exactly \
this schema:
{
  "category": "<medical_device|healthcare_it|healthcare_adjacent|not_healthcare>",
  "confidence": <float 0.0-1.0>,
  "reasoning": "<one or two sentences>",
  "device_types": ["<device type if applicable>", ...],
  "evidence_sources": ["<source_id that informed this classification>", ...],
  "confidence_by_field": {
    "category": <float 0.0-1.0>,
    "device_types": <float 0.0-1.0>
  },
  "extracted_facts": {"<key>": "<fact directly stated in the advisory>"},
  "inferred_facts": {"<key>": "<fact reasoned from context>"},
  "evidence_gaps": ["<missing information that would improve confidence>", ...],
  "insufficient_evidence": <true | false>,
  "handling_warnings": ["<operational caution for medical device if applicable>", ...]
}

Category definitions:
- medical_device: The vulnerability affects a regulated medical device — \
infusion pumps, ventilators, patient monitors, defibrillators, pacemakers, \
imaging systems (MRI/CT/X-ray/ultrasound/dental panoramic/PACS), surgical \
robots, or similar life-critical devices. Classify here even if the device \
runs on standard Windows/Linux hardware.
- healthcare_it: The vulnerability affects healthcare IT infrastructure — EHR \
or EMR systems, hospital networks, clinical workstations, health information \
exchanges, telehealth platforms, or pharmacy systems. Use this only when the \
affected system is clearly NOT a medical device.
- healthcare_adjacent: The issue indirectly affects healthcare — pharmaceutical \
manufacturing, medical supply chain, lab equipment, building management in \
hospitals, or general-purpose software widely used in clinical settings.
- not_healthcare: No meaningful relevance to healthcare delivery or patient \
safety.

If insufficient information is available to classify confidently, set \
insufficient_evidence=true and list what is missing in evidence_gaps. \
When uncertain between two categories, choose the more specific one if \
confidence >= 0.6, else choose healthcare_adjacent or not_healthcare.\
"""


def _build_user_prompt(issue: Dict[str, Any]) -> str:
    from .sanitize import sanitize_for_prompt

    issue_id = str(issue.get("issue_id") or "unknown")
    title = sanitize_for_prompt(str(issue.get("title") or ""), field_name="title")
    summary = sanitize_for_prompt(str(issue.get("summary") or ""), field_name="summary")
    sources = ", ".join(str(s) for s in (issue.get("sources") or []))
    links = " ".join(str(lnk) for lnk in (issue.get("links") or []))

    parts = [
        f"Issue ID: {issue_id}",
        f"Title: {title}",
    ]
    if summary:
        parts.append(f"Summary: {summary}")
    if sources:
        parts.append(f"Sources: {sources}")
    if links:
        parts.append(f"Links: {links}")
    parts.append(
        "\nClassify this security issue into healthcare relevance categories. "
        "Respond in JSON."
    )
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Public dataclass
# ---------------------------------------------------------------------------

@dataclass
class HealthcareClassification:
    category: str           # one of _VALID_CATEGORIES
    confidence: float       # 0.0–1.0
    reasoning: str          # one or two sentence explanation
    device_types: List[str] # specific device types if medical_device
    model: str
    tokens_used: int
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
# Internal: API call with retry
# ---------------------------------------------------------------------------

def _call_api(issue: Dict[str, Any], *, model: str, client: Any) -> Dict[str, Any]:
    """Call the OpenAI Responses API and return the raw result dict."""
    user_prompt = _build_user_prompt(issue)

    last_exc: Optional[Exception] = None
    for attempt, delay in enumerate([0, 1, 2]):
        if delay:
            time.sleep(delay)
        try:
            response = client.responses.create(
                model=model,
                instructions=_SYSTEM_PROMPT,
                input=user_prompt,
                text={"format": {"type": "json_object"}},
            )
            raw = response.output_text.strip()
            parsed = json.loads(raw)

            category = str(parsed.get("category", "not_healthcare")).strip()
            if category not in _VALID_CATEGORIES:
                category = "not_healthcare"

            confidence = float(parsed.get("confidence", 0.5))
            confidence = max(0.0, min(1.0, confidence))

            reasoning = str(parsed.get("reasoning", "")).strip()
            device_types_raw = parsed.get("device_types") or []
            device_types = [str(d) for d in device_types_raw if d]

            tokens_used = 0
            usage = getattr(response, "usage", None)
            if usage is not None:
                tokens_used = getattr(usage, "total_tokens", 0) or 0

            return {
                "result": {
                    "category": category,
                    "confidence": confidence,
                    "reasoning": reasoning,
                    "device_types": device_types,
                    "evidence_sources": [str(s) for s in (parsed.get("evidence_sources") or []) if s],
                    "confidence_by_field": {str(k): float(v) for k, v in (parsed.get("confidence_by_field") or {}).items()},
                    "extracted_facts": dict(parsed.get("extracted_facts") or {}),
                    "inferred_facts": dict(parsed.get("inferred_facts") or {}),
                    "evidence_gaps": [str(g) for g in (parsed.get("evidence_gaps") or []) if g],
                    "insufficient_evidence": bool(parsed.get("insufficient_evidence", False)),
                    "handling_warnings": [str(w) for w in (parsed.get("handling_warnings") or []) if w],
                },
                "model": model,
                "tokens_used": int(tokens_used),
            }
        except Exception as exc:
            last_exc = exc
            continue

    # All retries exhausted — return an uncertain result
    return {
        "result": {
            "category": "not_healthcare",
            "confidence": 0.0,
            "reasoning": f"Classification failed: {last_exc}",
            "device_types": [],
        },
        "model": model,
        "tokens_used": 0,
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def classify_healthcare_relevance(
    issue: Dict[str, Any],
    *,
    model: str = DEFAULT_CLASSIFY_MODEL,
    cache_root: str | Path = "outputs/ai_cache",
    no_cache: bool = False,
    _call_fn: Optional[Callable[[], Dict[str, Any]]] = None,
    _client: Any = None,
) -> HealthcareClassification:
    """Classify the healthcare relevance of a security issue using AI.

    Args:
        issue:       Scored issue dict (needs at least issue_id, title, summary).
        model:       OpenAI model to use (default: gpt-4o-mini).
        cache_root:  Directory for the on-disk AI response cache.
        no_cache:    Bypass cache and always call the API.
        _call_fn:    Injectable zero-argument callable for testing.  When
                     provided, neither the cache nor the API is used.
        _client:     Injectable OpenAI client for testing.

    Returns:
        HealthcareClassification dataclass.
    """
    issue_id = str(issue.get("issue_id") or "unknown")
    title = str(issue.get("title") or "")
    summary = str(issue.get("summary") or "")

    key_data = {
        "task": "healthcare_classify_v2",
        "model": model,
        "issue_id": issue_id,
        "title": title,
        "summary": summary,
    }

    if _call_fn is not None:
        entry = _call_fn()
        from_cache = False
    else:
        if _client is None:
            from openai import OpenAI
            _client = OpenAI()

        entry = cached_call(
            key_data=key_data,
            call_fn=lambda: _call_api(issue, model=model, client=_client),
            cache_root=cache_root,
            no_cache=no_cache,
        )
        from_cache = bool(entry.get("from_cache", False))

    result = entry.get("result") or {}

    category = str(result.get("category", "not_healthcare")).strip()
    if category not in _VALID_CATEGORIES:
        category = "not_healthcare"

    confidence = float(result.get("confidence", 0.0))
    confidence = max(0.0, min(1.0, confidence))

    reasoning = str(result.get("reasoning", "")).strip()
    device_types_raw = result.get("device_types") or []
    device_types = [str(d) for d in device_types_raw if d]

    return HealthcareClassification(
        category=category,
        confidence=confidence,
        reasoning=reasoning,
        device_types=device_types,
        model=str(entry.get("model", model)),
        tokens_used=int(entry.get("tokens_used", 0)),
        from_cache=from_cache,
        evidence_sources=[str(s) for s in (result.get("evidence_sources") or []) if s],
        extracted_facts=dict(result.get("extracted_facts") or {}),
        inferred_facts=dict(result.get("inferred_facts") or {}),
        confidence_by_field={str(k): float(v) for k, v in (result.get("confidence_by_field") or {}).items()},
        insufficient_evidence=bool(result.get("insufficient_evidence", False)),
        evidence_gaps=[str(g) for g in (result.get("evidence_gaps") or []) if g],
        handling_warnings=[str(w) for w in (result.get("handling_warnings") or []) if w],
    )
