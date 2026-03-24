"""Natural-language Q&A against the advisory corpus (Session G).

How it works
------------
1. Load all issues from a correlated issues JSONL file.
2. Rank issues by keyword relevance to the question using the same
   token-matching approach as ``product_resolver``.
3. Pass the top *top_k* issues as context to an LLM.
4. The LLM answers based *only* on the provided context, cites issue IDs,
   and lists evidence gaps when the context is insufficient.
5. Cache the response by (fn, question-hash, top_k) so repeat calls are free.

The function never invents facts — the system prompt explicitly forbids it.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from .ai_cache import cached_call

_DEFAULT_ISSUES_PATH = "outputs/community_public_expanded/correlate/issues.jsonl"
_DEFAULT_MODEL = "gpt-4o-mini"
_DEFAULT_CACHE_ROOT = "outputs/ai_cache"
_MIN_TOKEN_LEN = 2

# ---------------------------------------------------------------------------
# Token matching (mirrors product_resolver._tokenise / _match_quality)
# ---------------------------------------------------------------------------

def _tokenise(text: str) -> List[str]:
    return [t for t in re.split(r"[^a-z0-9]+", text.lower()) if len(t) >= _MIN_TOKEN_LEN]


def _relevance_score(query_tokens: List[str], issue: Dict[str, Any]) -> int:
    """Return a composite relevance score for *issue* against *query_tokens*.

    Title matches are weighted 2x; summary matches 1x.  The score is the
    total count of query tokens found in either field, so longer questions
    with more matching tokens score higher.
    """
    title_tokens = set(_tokenise(str(issue.get("title") or "")))
    summary_tokens = set(_tokenise(str(issue.get("summary") or "")))
    score = 0
    for t in query_tokens:
        if t in title_tokens:
            score += 2
        elif t in summary_tokens:
            score += 1
    return score


def _find_relevant_issues(
    query_tokens: List[str],
    issues: List[Dict[str, Any]],
    top_k: int,
) -> List[Dict[str, Any]]:
    """Return the *top_k* issues most relevant to *query_tokens*."""
    if not query_tokens:
        # No tokens → return highest-scoring issues by priority score
        return sorted(issues, key=lambda r: int(r.get("score") or 0), reverse=True)[:top_k]

    scored: List[tuple[int, int, Dict[str, Any]]] = []
    for issue in issues:
        rel = _relevance_score(query_tokens, issue)
        if rel > 0:
            issue_score = int(issue.get("score") or 0)
            scored.append((rel, issue_score, issue))

    scored.sort(key=lambda t: (t[0], t[1]), reverse=True)
    return [issue for _, _, issue in scored[:top_k]]


# ---------------------------------------------------------------------------
# Prompt builders
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = (
    "You are a healthcare cybersecurity analyst answering questions about medical "
    "device security advisories. Answer ONLY based on the advisory context provided. "
    "If the context does not contain enough information to answer confidently, say so "
    "clearly and list what information is missing in evidence_gaps. "
    "Be specific: cite issue IDs when referencing advisories. "
    "Be concise: 2-5 sentences for the answer unless more detail is clearly needed. "
    "Never invent facts not present in the provided context.\n\n"
    "Return ONLY valid JSON — no markdown fences, no commentary.\n\n"
    "OUTPUT FORMAT (return exactly this JSON structure, nothing else):\n"
    "{\n"
    '  "answer": "<your answer, 2-5 sentences, citing issue IDs>",\n'
    '  "supporting_issues": [\n'
    '    {"issue_id": "<id>", "why_relevant": "<one sentence explaining relevance>"}\n'
    "  ],\n"
    '  "evidence_gaps": ["<what information was missing or unclear>", ...]\n'
    "}"
)


def _build_user_prompt(question: str, context_issues: List[Dict[str, Any]]) -> str:
    from .sanitize import sanitize_for_prompt

    lines: List[str] = [
        f"Question: {sanitize_for_prompt(question, field_name='question')}",
        "",
        "Advisory context:",
        "",
    ]
    for issue in context_issues:
        summary = sanitize_for_prompt((str(issue.get("summary") or ""))[:400], field_name="summary")
        sources = ", ".join(issue.get("sources") or []) or "(unknown)"
        lines += [
            f"Issue ID: {issue.get('issue_id', '')}",
            f"Title: {issue.get('title', '')}",
            f"Priority: {issue.get('priority', '')}",
            f"Summary: {summary}",
            f"Sources: {sources}",
            "",
        ]
    lines.append("Answer the question based only on the context above. Respond in JSON.")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Response parsing
# ---------------------------------------------------------------------------

def _parse_response(
    raw: Any,
    context_issues: List[Dict[str, Any]],
) -> tuple[str, List[Dict[str, Any]], List[str]]:
    """Parse the AI JSON into (answer, supporting_issues, evidence_gaps).

    ``supporting_issues`` is enriched with title/score/priority from the local
    issue data so callers don't need to re-join.
    """
    if not isinstance(raw, dict):
        raw = {}

    answer = str(raw.get("answer") or "")
    evidence_gaps: List[str] = [str(g) for g in (raw.get("evidence_gaps") or []) if g]

    # Build a lookup from context so we can enrich AI-returned issue refs
    ctx_by_id: Dict[str, Dict[str, Any]] = {
        str(i.get("issue_id") or ""): i for i in context_issues
    }

    supporting_issues: List[Dict[str, Any]] = []
    for item in (raw.get("supporting_issues") or []):
        if not isinstance(item, dict):
            continue
        issue_id = str(item.get("issue_id") or "")
        why = str(item.get("why_relevant") or "")
        ctx = ctx_by_id.get(issue_id, {})
        supporting_issues.append({
            "issue_id": issue_id,
            "title": str(ctx.get("title") or ""),
            "score": int(ctx.get("score") or 0),
            "priority": str(ctx.get("priority") or ""),
            "why_relevant": why,
        })

    return answer, supporting_issues, evidence_gaps


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def answer_question(
    question: str,
    issues_path: str = _DEFAULT_ISSUES_PATH,
    top_k: int = 5,
    model: str = _DEFAULT_MODEL,
    cache_root: str = _DEFAULT_CACHE_ROOT,
    _call_fn: Optional[Callable[[], Any]] = None,
) -> Dict[str, Any]:
    """Answer *question* using the top-*top_k* most relevant issues as context.

    Parameters
    ----------
    question:
        Natural-language question about medical device or healthcare security.
    issues_path:
        Path to the correlated issues JSONL file.
    top_k:
        Number of issues to include as context (default 5).
    model:
        OpenAI model to use (default gpt-4o-mini).
    cache_root:
        Directory for AI response cache files.
    _call_fn:
        Zero-argument callable override for testing.  Must return a dict with
        keys ``result`` (parsed AI JSON), ``model``, and ``tokens_used``.

    Returns
    -------
    dict with keys:
        question, answer, supporting_issues, evidence_gaps,
        model, tokens_used, from_cache.

    Raises
    ------
    FileNotFoundError if *issues_path* does not exist.
    RuntimeError if OPENAI_API_KEY is not set and no *_call_fn* is provided.
    """
    path = Path(issues_path)
    if not path.exists():
        raise FileNotFoundError(f"Issues file not found: {path}")

    # --- Load issues ---
    issues: List[Dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                issues.append(obj)
        except json.JSONDecodeError:
            continue

    # Empty corpus — return a graceful no-context answer without calling AI
    if not issues:
        return {
            "question": question,
            "answer": "No advisory data is available in the corpus to answer this question.",
            "supporting_issues": [],
            "evidence_gaps": ["No issues loaded from the corpus."],
            "model": model,
            "tokens_used": 0,
            "from_cache": False,
        }

    query_tokens = _tokenise(question)
    context_issues = _find_relevant_issues(query_tokens, issues, top_k)

    user_prompt = _build_user_prompt(question, context_issues)

    # Cache key: stable hash of question text + top_k
    question_hash = hashlib.sha256(question.encode("utf-8")).hexdigest()[:16]
    key_data: Dict[str, Any] = {
        "fn": "advisory_qa_v1",
        "question_hash": question_hash,
        "top_k": top_k,
        "model": model,
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
            instructions=_SYSTEM_PROMPT,
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
    )

    raw_result = entry.get("result") or {}
    answer, supporting_issues, evidence_gaps = _parse_response(raw_result, context_issues)

    return {
        "question": question,
        "answer": answer,
        "supporting_issues": supporting_issues,
        "evidence_gaps": evidence_gaps,
        "model": str(entry.get("model") or model),
        "tokens_used": int(entry.get("tokens_used") or 0),
        "from_cache": bool(entry.get("from_cache")),
    }
