"""Product-name lookup against a correlated issues corpus.

Given a product name or nickname (e.g. "Sigma Spectrum", "MX800",
"Contec CMS8000"), tokenise the query and return issues whose title,
summary, or issue_id contain at least one of the query tokens.

Results are ranked by:
  1. Match quality (phrase > all-tokens > partial) — used as a tiebreaker
  2. Issue score (desc) — primary sort so the highest-priority hits surface first

Up to ``top`` (default 20) results are returned.

Each result dict contains:
    issue_id    — stable issue identifier
    title       — issue title
    score       — numeric priority score
    priority    — priority label (P0–P3 or "")
    sources     — list of source_ids that contributed to this issue
    match_field — the highest-priority field that matched the query
                  ("title", "summary", or "issue_id"); if multiple fields
                  match the best-ranked one is reported.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import List

# Fields checked in preference order — used both for matching and for
# choosing which label to report in ``match_field``.
_MATCH_FIELDS = ("title", "summary", "issue_id")

# Tokens shorter than this are treated as stop-words and ignored.
_MIN_TOKEN_LEN = 2


def _tokenise(text: str) -> List[str]:
    """Lower-case the text and split on non-alphanumeric runs."""
    return [t for t in re.split(r"[^a-z0-9]+", text.lower()) if len(t) >= _MIN_TOKEN_LEN]


def _match_quality(tokens: List[str], field_text: str) -> int:
    """Return a match-quality score for one field.

    3 — the full query phrase appears verbatim (substring, case-insensitive)
    2 — every token appears in the field
    1 — at least one token appears in the field
    0 — no match
    """
    lower = field_text.lower()
    # phrase match: rejoin tokens and check as substring
    phrase = " ".join(tokens)
    if phrase and phrase in lower:
        return 3
    field_tokens = set(_tokenise(field_text))
    matched = sum(1 for t in tokens if t in field_tokens)
    if matched == len(tokens):
        return 2
    if matched > 0:
        return 1
    return 0


def resolve_product(
    query: str,
    issues_path: str = "outputs/community_public_expanded/correlate/issues.jsonl",
    top: int = 20,
) -> List[dict]:
    """Return up to *top* issues that match *query* by token-matching.

    Parameters
    ----------
    query:
        Product name or nickname to search for (e.g. "Sigma Spectrum").
    issues_path:
        Path to the correlated issues JSONL file.
    top:
        Maximum number of results to return (default 20).

    Returns
    -------
    List of dicts, each with keys:
        issue_id, title, score, priority, sources, match_field.
    Sorted by issue score descending.

    Raises
    ------
    FileNotFoundError if *issues_path* does not exist.
    """
    path = Path(issues_path)
    if not path.exists():
        raise FileNotFoundError(f"Issues file not found: {path}")

    query_tokens = _tokenise(query)
    if not query_tokens:
        return []

    candidates: list[tuple[int, int, dict]] = []  # (match_quality, issue_score, result)

    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            issue = json.loads(line)
        except json.JSONDecodeError:
            continue

        best_quality = 0
        best_field = ""
        for field in _MATCH_FIELDS:
            fval = str(issue.get(field) or "")
            q = _match_quality(query_tokens, fval)
            if q > best_quality:
                best_quality = q
                best_field = field

        if best_quality == 0:
            continue

        issue_score = int(issue.get("score") or 0)
        result = {
            "issue_id": issue.get("issue_id", ""),
            "title": issue.get("title", ""),
            "score": issue_score,
            "priority": issue.get("priority", ""),
            "sources": issue.get("sources") or [],
            "match_field": best_field,
        }
        candidates.append((best_quality, issue_score, result))

    # Sort: score desc, then match quality desc as secondary tiebreaker
    candidates.sort(key=lambda t: (t[1], t[0]), reverse=True)
    return [r for _, _, r in candidates[:top]]
