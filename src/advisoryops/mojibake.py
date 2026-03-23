"""UTF-8 mojibake detection and repair for advisory text.

Advisory sources — particularly CISA ICS pages — frequently contain text that
was originally encoded in Windows-1252 (cp1252) but was mis-decoded as Latin-1
or re-encoded through multiple layers of HTTP transcoding.  The result is
sequences like "â€™" (which should be "'") or "â€œ" (which should be '"').

This module provides two public functions:

clean_mojibake_text(text)
    Repairs a single string:
    1. Apply a table of known complete mojibake sequences → correct characters.
    2. If artifact markers (specific Unicode chars) remain, attempt a
       cp1252 → UTF-8 byte-level round-trip and accept it only if it reduces
       the artifact count without dropping more than 15% of content.
    3. Strip NBSP (U+00A0) and stray Â (U+00C2) artifacts.

clean_mojibake_value(value)
    Dispatcher for ``str | list | Any``:
    - str   → clean_mojibake_text
    - list  → clean each string element, drop empty results
    - other → return unchanged

Design note: the repair is intentionally conservative.  A generic "replace every
unrecognised byte" approach produces broken output for legitimately multi-lingual
text (e.g. Japanese vendor advisories).  Only complete, known-bad sequences are
replaced; ambiguous bytes are left alone.
"""
from __future__ import annotations

from typing import Any, Optional


# Only replace COMPLETE, known mojibake sequences (avoid generic "??" replacement).
_REPLACEMENTS = {
    "???": "?",
    "???": "?",
    "???": "?",
    "???": "?",
    "??\u009d": "?",
    "??\u009c": "?",
    "???": "?",
    "???": "?",
    "???": "?",
    "???": "?",
    "???": "?",
}


def _score(s: str) -> int:
    # Simple heuristic: common mojibake markers
    return s.count("?") + s.count("?") + s.count("\u009d") + s.count("\u009c")


def _try_repair(s: str) -> str:
    # Attempt latin-1/cp1252 -> utf-8 recovery, but only accept if it clearly improves
    orig = s
    best = s
    best_score = _score(s)

    for enc in ("cp1252", "latin-1"):
        try:
            cand = orig.encode(enc, errors="ignore").decode("utf-8", errors="ignore")
        except Exception:
            continue

        if not cand:
            continue

        cand_score = _score(cand)
        # Guardrail: don't accept if we drop too much content
        if cand_score < best_score and len(cand) >= int(len(orig) * 0.85):
            best = cand
            best_score = cand_score

    return best


def clean_mojibake_text(text: Optional[str]) -> Optional[str]:
    if text is None:
        return None
    if text == "":
        return ""

    s = text

    # Targeted replacements first
    for bad, good in _REPLACEMENTS.items():
        if bad in s:
            s = s.replace(bad, good)

    # If markers remain, try encoding repair
    if ("?" in s) or ("?" in s) or ("\u009d" in s) or ("\u009c" in s):
        s = _try_repair(s)
        for bad, good in _REPLACEMENTS.items():
            if bad in s:
                s = s.replace(bad, good)

    # Strip NBSP and stray ? artifacts
    s = s.replace("\u00a0", " ").replace("\u00c2", "").replace("?", "")
    return s.strip()


def clean_mojibake_value(value: Any) -> Any:
    if value is None or isinstance(value, str):
        return clean_mojibake_text(value)
    if isinstance(value, list):
        out = []
        for item in value:
            if item is None or isinstance(item, str):
                cleaned = clean_mojibake_text(item)
                if cleaned is None or cleaned == "":
                    continue
                out.append(cleaned)
            else:
                out.append(item)
        return out
    return value
