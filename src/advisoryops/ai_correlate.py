"""AI merge candidate detector and merge decision engine for AdvisoryOps.

Task 2.1 — Pre-filter: ``find_merge_candidates`` identifies issue pairs that
MIGHT be the same vulnerability using text-similarity heuristics (no API calls).

Task 2.2 — AI decision: ``ai_merge_decision`` takes two issue records and asks
GPT-4o-mini to decide whether they describe the same underlying vulnerability.
Results are cached on disk via ``ai_cache.cached_call`` so re-runs are free.

Pipeline position:
    correlate.py calls ``find_merge_candidates`` + ``ai_merge_decision`` when
    ``--ai-merge`` is passed.  Both functions are imported lazily (inside
    ``_apply_ai_merge``) so this module is never loaded on standard runs.

Similarity model (composite score, all weights sum to 1.0):
    CVE overlap     0.40 — shared CVE IDs are the strongest dedup signal
    Vendor/product  0.30 — Jaccard of tokenized title + summary (first 300 chars)
    Summary         0.20 — Jaccard of full summary tokens
    Date proximity  0.10 — issues within 90 days score 1.0; beyond 180 days → 0.0

Merge guard rails:
    * If both issues have non-empty CVE sets that don't overlap → hard 0 score
      (different CVEs cannot be the same vulnerability).
    * If neither has CVEs, the CVE weight (0.40) is redistributed to vendor and
      summary so no-CVE pairs can still be merged when text aligns strongly.
    * Candidate pairs are capped at ``max_pair_fraction * total_possible_pairs``
      (default 5%) to prevent quadratic blowup on large issue sets.
    * Only AI decisions with ``confidence >= 0.70`` trigger a merge.
"""
from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# Token helpers
# ---------------------------------------------------------------------------

_NON_ALPHA = re.compile(r"[^a-z0-9]")
_STOPWORDS: Set[str] = {
    "a", "an", "the", "in", "of", "on", "for", "and", "or", "to", "with",
    "is", "are", "was", "were", "be", "been", "by", "at", "from", "has",
    "have", "this", "that", "via", "due", "can", "may", "allows", "allow",
    "could", "which", "when", "affects", "affecting", "affect",
}


def _tokenize(text: str) -> Set[str]:
    """Lowercase, split on non-alphanumerics, drop stopwords and short tokens."""
    tokens: Set[str] = set()
    for tok in _NON_ALPHA.split(text.lower()):
        if len(tok) >= 3 and tok not in _STOPWORDS:
            tokens.add(tok)
    return tokens


def _jaccard(a: Set[str], b: Set[str]) -> float:
    if not a and not b:
        return 0.0
    union = a | b
    intersection = a & b
    return len(intersection) / len(union)


# ---------------------------------------------------------------------------
# Date helpers
# ---------------------------------------------------------------------------

_DATE_RE = re.compile(r"(\d{4}-\d{2}-\d{2})")


def _parse_date(text: str) -> Optional[date]:
    """Extract the first ISO date from a string, return as date or None."""
    m = _DATE_RE.search(text or "")
    if not m:
        return None
    try:
        return datetime.strptime(m.group(1), "%Y-%m-%d").date()
    except ValueError:
        return None


def _earliest_date(issue: Dict[str, Any]) -> Optional[date]:
    """Return the earliest date found across published_dates, first_seen_at."""
    candidates: List[date] = []

    for ds in issue.get("published_dates", []):
        d = _parse_date(str(ds))
        if d:
            candidates.append(d)

    fsa = _parse_date(str(issue.get("first_seen_at") or ""))
    if fsa:
        candidates.append(fsa)

    return min(candidates) if candidates else None


def _date_proximity_score(a: Dict[str, Any], b: Dict[str, Any], *, window_days: int = 90) -> float:
    """Return 1.0 if issues are within window_days of each other, else 0.0.

    If either date is unknown, returns 0.5 (neutral — don't penalise, don't reward).
    """
    da = _earliest_date(a)
    db = _earliest_date(b)
    if da is None or db is None:
        return 0.5
    gap = abs((da - db).days)
    if gap <= window_days:
        return 1.0
    # Decay linearly up to 2× window
    if gap <= window_days * 2:
        return 1.0 - (gap - window_days) / window_days
    return 0.0


# ---------------------------------------------------------------------------
# Vendor / product extraction
# ---------------------------------------------------------------------------

def _vendor_product_tokens(issue: Dict[str, Any]) -> Set[str]:
    """Best-effort extraction of vendor/product tokens from an issue record.

    Sources checked (in priority order):
    - explicit vendor/product fields (if present from AI extract)
    - title
    - summary (first 300 chars to avoid noise)
    """
    parts: List[str] = []
    for field in ("vendor", "vendors", "product", "products", "affected_products"):
        val = issue.get(field)
        if isinstance(val, str):
            parts.append(val)
        elif isinstance(val, list):
            parts.extend(str(v) for v in val)

    parts.append(str(issue.get("title") or ""))
    # Limit summary to first 300 chars — avoid pulling in generic CVE boilerplate
    parts.append(str(issue.get("summary") or "")[:300])

    combined = " ".join(parts)
    return _tokenize(combined)


# ---------------------------------------------------------------------------
# CVE overlap
# ---------------------------------------------------------------------------

def _cve_overlap(a: Dict[str, Any], b: Dict[str, Any]) -> float:
    """Fraction of CVEs shared between two issues.

    Returns 1.0 for full overlap, 0.0 for none.
    If both have no CVEs, return 0.0 (don't treat "both unknown" as a match).
    """
    cves_a: Set[str] = set(a.get("cves") or [])
    cves_b: Set[str] = set(b.get("cves") or [])
    if not cves_a and not cves_b:
        return 0.0
    # Jaccard over CVE sets
    return _jaccard(cves_a, cves_b)


# ---------------------------------------------------------------------------
# Summary similarity
# ---------------------------------------------------------------------------

def _summary_jaccard(a: Dict[str, Any], b: Dict[str, Any]) -> float:
    """Token-level Jaccard similarity of the two issues' summaries."""
    toks_a = _tokenize(str(a.get("summary") or ""))
    toks_b = _tokenize(str(b.get("summary") or ""))
    return _jaccard(toks_a, toks_b)


# ---------------------------------------------------------------------------
# Composite scoring
# ---------------------------------------------------------------------------

# Weights must sum to 1.0
_W_CVE = 0.40       # CVE overlap is the strongest signal
_W_VENDOR = 0.30    # vendor/product token Jaccard
_W_SUMMARY = 0.20   # summary Jaccard
_W_DATE = 0.10      # temporal proximity


def _composite_score(a: Dict[str, Any], b: Dict[str, Any]) -> float:
    """Return a [0, 1] similarity score between two issue records."""
    cve = _cve_overlap(a, b)
    vendor = _jaccard(_vendor_product_tokens(a), _vendor_product_tokens(b))
    summary = _summary_jaccard(a, b)
    date_prox = _date_proximity_score(a, b)

    cves_a: Set[str] = set(a.get("cves") or [])
    cves_b: Set[str] = set(b.get("cves") or [])

    # If both issues have concrete CVE sets that don't overlap, they cannot
    # describe the same vulnerability — hard zero.
    if cves_a and cves_b and cve == 0.0:
        return 0.0

    if not cves_a and not cves_b:
        # Neither issue has CVE information.  Redistribute the CVE weight to
        # vendor/product (60 %) and summary (40 %) so no-CVE pairs can still
        # score well when product and summary tokens align strongly.
        w_vendor = _W_VENDOR + _W_CVE * 0.6   # 0.30 + 0.24 = 0.54
        w_summary = _W_SUMMARY + _W_CVE * 0.4  # 0.20 + 0.16 = 0.36
        score = w_vendor * vendor + w_summary * summary + _W_DATE * date_prox
    else:
        score = (
            _W_CVE * cve
            + _W_VENDOR * vendor
            + _W_SUMMARY * summary
            + _W_DATE * date_prox
        )

    return round(score, 4)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def find_merge_candidates(
    issues: List[Dict[str, Any]],
    *,
    threshold: float = 0.25,
    max_pair_fraction: float = 0.05,
) -> List[Tuple[str, str, float]]:
    """Find issue pairs that might describe the same underlying vulnerability.

    Parameters
    ----------
    issues:
        List of issue dicts as produced by correlate (must have ``issue_id``).
    threshold:
        Minimum composite similarity score to emit a candidate pair.
        Default 0.25 is intentionally permissive — false negatives are worse
        than false positives at this stage (the AI step handles the hard calls).
    max_pair_fraction:
        Safety cap: emit at most this fraction of all possible pairs.
        Guards against quadratic blowup on very large issue sets.
        Default 0.05 (5 %).

    Returns
    -------
    List of (issue_id_a, issue_id_b, score) tuples, sorted descending by score.
    issue_id_a < issue_id_b (lexicographic) to avoid duplicates.
    """
    n = len(issues)
    if n < 2:
        return []

    total_pairs = n * (n - 1) // 2
    # Always allow at least n-1 pairs (minimum edges for a connected spanning tree,
    # required for transitive merge groups). The fraction cap applies to large datasets.
    max_pairs = max(n - 1, int(total_pairs * max_pair_fraction), 1)

    # Build index: issue_id -> dict
    by_id: Dict[str, Dict[str, Any]] = {}
    for iss in issues:
        iid = str(iss.get("issue_id") or "")
        if iid:
            by_id[iid] = iss

    ids = sorted(by_id.keys())
    candidates: List[Tuple[str, str, float]] = []

    for i in range(len(ids)):
        for j in range(i + 1, len(ids)):
            id_a, id_b = ids[i], ids[j]
            score = _composite_score(by_id[id_a], by_id[id_b])
            if score >= threshold:
                candidates.append((id_a, id_b, score))

    # Sort descending by score, then cap
    candidates.sort(key=lambda t: t[2], reverse=True)
    if len(candidates) > max_pairs:
        candidates = candidates[:max_pairs]

    return candidates


# ===========================================================================
# Task 2.2 — AI merge decision engine
# ===========================================================================

DEFAULT_MERGE_MODEL = "gpt-4o-mini"

_MERGE_SYSTEM_PROMPT = """\
You are a cybersecurity analyst deciding whether two advisory records describe
the same underlying vulnerability or security issue.

Carefully consider all of the following signals:
- Do they reference the same CVE identifier(s)?
- Do they affect the same vendor and product (or product family)?
- Do they describe the same class of vulnerability (e.g. RCE, auth bypass)?
- Do they have overlapping or similar remediation/mitigation advice?
- Are they published within a plausible time window of each other?

If you lack sufficient information to make a confident determination, set
insufficient_evidence=true and explain what is missing in evidence_gaps.

Respond with ONLY a valid JSON object — no markdown, no commentary — using
exactly these keys:

{
  "same_issue": <true | false>,
  "confidence": <float 0.0–1.0>,
  "reasoning": "<one or two sentences explaining your decision>",
  "evidence_sources": ["<source_id from issue A>", "<source_id from issue B>", ...],
  "confidence_by_field": {
    "same_issue": <float 0.0–1.0>,
    "vendor_match": <float 0.0–1.0>,
    "cve_match": <float 0.0–1.0>
  },
  "extracted_facts": {
    "<key>": "<fact directly stated in the advisories>"
  },
  "inferred_facts": {
    "<key>": "<fact inferred/reasoned from context>"
  },
  "evidence_gaps": ["<what information is missing or unclear>", ...],
  "insufficient_evidence": <true | false>,
  "handling_warnings": ["<medical device operational caution if applicable>", ...]
}

same_issue must be a JSON boolean (true or false).
confidence must be a number between 0.0 (completely uncertain) and 1.0 (certain).
evidence_sources must list the source_ids (e.g. "cisa-icsma", "nvd") from the
  issue records that informed your decision.
insufficient_evidence must be true when you cannot make a reliable determination.
"""


@dataclass
class MergeDecision:
    """Result of an AI merge decision for a pair of issue records."""

    same_issue: bool
    confidence: float  # 0.0 – 1.0
    reasoning: str
    model: str
    tokens_used: int
    # Provenance fields (default empty so existing callers are unaffected)
    evidence_sources: List[str] = field(default_factory=list)
    extracted_facts: Dict[str, Any] = field(default_factory=dict)
    inferred_facts: Dict[str, Any] = field(default_factory=dict)
    confidence_by_field: Dict[str, float] = field(default_factory=dict)
    insufficient_evidence: bool = False
    evidence_gaps: List[str] = field(default_factory=list)
    handling_warnings: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _issue_fingerprint(issue: Dict[str, Any]) -> Dict[str, Any]:
    """Extract stable, identifying fields for cache-key construction."""
    return {
        "issue_id": str(issue.get("issue_id") or ""),
        "cves": sorted(issue.get("cves") or []),
        "title": str(issue.get("title") or "")[:200],
        "summary": str(issue.get("summary") or "")[:400],
        "sources": sorted(issue.get("sources") or []),
    }


def _build_user_prompt(issue_a: Dict[str, Any], issue_b: Dict[str, Any]) -> str:
    """Build the user-turn prompt for the merge decision call."""

    def _fmt(issue: Dict[str, Any]) -> str:
        lines = [
            f"  issue_id   : {issue.get('issue_id', '')}",
            f"  cves       : {', '.join(issue.get('cves') or []) or '(none)'}",
            f"  title      : {str(issue.get('title') or '')[:150]}",
            f"  summary    : {str(issue.get('summary') or '')[:400]}",
            f"  sources    : {', '.join(issue.get('sources') or [])}",
            f"  dates      : {', '.join(issue.get('published_dates') or [])}",
        ]
        return "\n".join(lines)

    return (
        "ISSUE A:\n"
        + _fmt(issue_a)
        + "\n\nISSUE B:\n"
        + _fmt(issue_b)
        + "\n\nAre these the same underlying vulnerability or security issue? Respond in JSON."
    )


def _parse_merge_response(
    json_text: str,
    *,
    model: str,
    tokens_used: int,
) -> MergeDecision:
    """Parse raw JSON from the API into a MergeDecision. Raises on bad JSON."""
    obj = json.loads(json_text)
    same = bool(obj.get("same_issue", False))
    conf = float(obj.get("confidence", 0.0))
    conf = max(0.0, min(1.0, conf))
    reason = str(obj.get("reasoning") or "").strip() or "No reasoning provided."

    # Provenance fields — default to empty if not present
    evidence_sources = [str(s) for s in (obj.get("evidence_sources") or []) if s]
    conf_by_field = {str(k): float(v) for k, v in (obj.get("confidence_by_field") or {}).items()}
    extracted = dict(obj.get("extracted_facts") or {})
    inferred = dict(obj.get("inferred_facts") or {})
    evidence_gaps = [str(g) for g in (obj.get("evidence_gaps") or []) if g]
    insuff = bool(obj.get("insufficient_evidence", False))
    handling_warnings = [str(w) for w in (obj.get("handling_warnings") or []) if w]

    return MergeDecision(
        same_issue=same,
        confidence=conf,
        reasoning=reason,
        model=model,
        tokens_used=tokens_used,
        evidence_sources=evidence_sources,
        extracted_facts=extracted,
        inferred_facts=inferred,
        confidence_by_field=conf_by_field,
        insufficient_evidence=insuff,
        evidence_gaps=evidence_gaps,
        handling_warnings=handling_warnings,
    )


def _uncertain(*, model: str, reason: str) -> MergeDecision:
    """Return a safe 'uncertain' decision used on unrecoverable errors."""
    return MergeDecision(
        same_issue=False,
        confidence=0.0,
        reasoning=reason,
        model=model,
        tokens_used=0,
    )


def _extract_tokens(usage: Any) -> int:
    """Pull total token count from a Responses API usage object."""
    if usage is None:
        return 0
    try:
        if hasattr(usage, "total_tokens"):
            return int(usage.total_tokens)
        if hasattr(usage, "input_tokens") and hasattr(usage, "output_tokens"):
            return int(usage.input_tokens) + int(usage.output_tokens)
        if isinstance(usage, dict):
            if "total_tokens" in usage:
                return int(usage["total_tokens"])
            return int(usage.get("input_tokens", 0)) + int(usage.get("output_tokens", 0))
    except Exception:
        pass
    return 0


def _call_api(
    client: Any,
    model: str,
    user_prompt: str,
    *,
    max_attempts: int = 3,
    base_delay: float = 1.0,
) -> Dict[str, Any]:
    """Call the OpenAI Responses API with retry/backoff.

    Returns a dict with keys ``result`` (raw JSON text), ``model``,
    ``tokens_used``.  Raises the last exception if all retries fail.
    """
    last_exc: Optional[Exception] = None
    for attempt in range(max_attempts):
        try:
            resp = client.responses.create(
                model=model,
                instructions=_MERGE_SYSTEM_PROMPT,
                input=user_prompt,
                text={"format": {"type": "json_object"}},
            )
            json_text = (getattr(resp, "output_text", None) or "").strip()
            tokens = _extract_tokens(getattr(resp, "usage", None))
            return {"result": json_text, "model": model, "tokens_used": tokens}
        except Exception as exc:
            last_exc = exc
            if attempt < max_attempts - 1:
                time.sleep(base_delay * (2 ** attempt))

    raise last_exc  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def ai_merge_decision(
    issue_a: Dict[str, Any],
    issue_b: Dict[str, Any],
    *,
    model: str = DEFAULT_MERGE_MODEL,
    cache_root: str | Path = "outputs/ai_cache",
    no_cache: bool = False,
    _client: Any = None,
) -> MergeDecision:
    """Ask an LLM whether *issue_a* and *issue_b* describe the same vulnerability.

    Parameters
    ----------
    issue_a, issue_b:
        Issue dicts as produced by ``correlate`` (need at least ``issue_id``,
        ``cves``, ``title``, ``summary``, ``sources``, ``published_dates``).
    model:
        OpenAI model to use (default ``gpt-4o-mini``).
    cache_root:
        Directory for the on-disk response cache.
    no_cache:
        Bypass cache entirely (always calls API, never writes).
    _client:
        Injectable OpenAI client — supply a mock in tests to avoid API calls.
        When ``None`` a real ``openai.OpenAI()`` client is instantiated, which
        requires ``OPENAI_API_KEY`` to be set.

    Returns
    -------
    MergeDecision
        Contains ``same_issue``, ``confidence``, ``reasoning``, ``model``,
        ``tokens_used``.  On unrecoverable API error returns an uncertain
        decision (``same_issue=False``, ``confidence=0.0``) rather than
        raising, so the caller can continue processing remaining pairs.
    """
    # Lazy import so the module loads fine without the SDK installed.
    from advisoryops.ai_cache import cached_call  # type: ignore

    if _client is None:
        try:
            from openai import OpenAI  # type: ignore
            _client = OpenAI()
        except Exception as exc:
            return _uncertain(model=model, reason=f"Could not initialise OpenAI client: {exc}")

    user_prompt = _build_user_prompt(issue_a, issue_b)

    # Cache key: stable fingerprint of both issues + model.
    # Sort fingerprints so (A, B) and (B, A) share a cache entry.
    fp_a = _issue_fingerprint(issue_a)
    fp_b = _issue_fingerprint(issue_b)
    fps = sorted([fp_a, fp_b], key=lambda f: f["issue_id"])
    key_data = {"fn": "ai_merge_decision_v2", "model": model, "a": fps[0], "b": fps[1]}

    try:
        entry = cached_call(
            key_data=key_data,
            call_fn=lambda: _call_api(_client, model, user_prompt),
            model=model,
            cache_root=cache_root,
            no_cache=no_cache,
        )
    except Exception as exc:
        return _uncertain(model=model, reason=f"API error after retries: {exc}")

    json_text: str = entry.get("result") or ""
    actual_model: str = entry.get("model") or model
    tokens: int = int(entry.get("tokens_used") or 0)

    try:
        return _parse_merge_response(json_text, model=actual_model, tokens_used=tokens)
    except Exception as exc:
        return _uncertain(
            model=actual_model,
            reason=f"Could not parse model response: {exc}. Raw: {json_text[:200]}",
        )
