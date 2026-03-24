"""Prompt-injection hardening for AI inputs.

Strips or escapes potentially adversarial content from ingested advisory
text before it is sent to AI prompts.  Every AI prompt builder should pass
source text through ``sanitize_for_prompt`` before embedding it.

Defences:
  1. Role-hijack patterns ("ignore previous instructions", "you are now ...")
  2. Instruction-override patterns ("do not follow", "disregard")
  3. Excessive special characters / encoding tricks
  4. Input length truncation to a safe maximum
  5. Warning logged when sanitization alters the input
"""
from __future__ import annotations

import logging
import re
from typing import Optional

logger = logging.getLogger(__name__)

# Maximum characters allowed in a single prompt input field.
DEFAULT_MAX_LENGTH = 12_000

# Patterns that attempt to hijack the model's role or override instructions.
# Each tuple: (compiled regex, replacement string).
_INJECTION_PATTERNS = [
    # "ignore previous instructions" and variants
    (re.compile(
        r"(?:please\s+)?(?:ignore|disregard|forget|override|bypass)\s+"
        r"(?:all\s+)?(?:previous|prior|above|earlier|system|original)\s+"
        r"(?:instructions?|prompts?|rules?|constraints?|directions?)",
        re.I,
    ), "[REDACTED-INSTRUCTION-OVERRIDE]"),
    # "you are now ..." role hijack
    (re.compile(
        r"you\s+are\s+(?:now|actually|really|henceforth)\s+[a-zA-Z]",
        re.I,
    ), "[REDACTED-ROLE-HIJACK]"),
    # "do not follow" / "stop following"
    (re.compile(
        r"(?:do\s+not|don'?t|stop)\s+follow(?:ing)?\s+"
        r"(?:the\s+)?(?:previous|above|system|original|prior)\s+",
        re.I,
    ), "[REDACTED-INSTRUCTION-OVERRIDE]"),
    # "new instructions:" / "system prompt:" header injection
    (re.compile(
        r"(?:new|updated|revised|real)\s+(?:system\s+)?(?:instructions?|prompt|role)\s*:",
        re.I,
    ), "[REDACTED-PROMPT-HEADER]"),
    # Markdown/XML injection attempting to close and reopen prompt blocks
    (re.compile(
        r"```\s*(?:system|instruction|prompt)",
        re.I,
    ), "[REDACTED-BLOCK]"),
]

# Characters that serve no purpose in advisory text and may be encoding tricks
_SUSPICIOUS_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def sanitize_for_prompt(
    text: str,
    *,
    max_length: int = DEFAULT_MAX_LENGTH,
    field_name: Optional[str] = None,
) -> str:
    """Sanitize arbitrary text before embedding it in an AI prompt.

    Parameters
    ----------
    text : str
        Raw text from an advisory, feed, or user input.
    max_length : int
        Maximum allowed character length (default 12 000).
    field_name : str, optional
        Label used in log warnings to identify which field was sanitized.

    Returns
    -------
    str
        Sanitized text safe for prompt inclusion.
    """
    if not text:
        return ""

    original = text
    label = field_name or "input"

    # 1. Strip control characters
    text = _SUSPICIOUS_CHARS_RE.sub("", text)

    # 2. Detect and redact injection patterns
    for pattern, replacement in _INJECTION_PATTERNS:
        text = pattern.sub(replacement, text)

    # 3. Truncate to safe max length
    if len(text) > max_length:
        text = text[:max_length] + " [TRUNCATED]"

    # 4. Log if anything changed
    if text != original:
        logger.warning(
            "sanitize_for_prompt altered %s (len %d -> %d)",
            label,
            len(original),
            len(text),
        )

    return text
