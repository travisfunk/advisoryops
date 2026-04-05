"""Healthcare relevance filter for AdvisoryOps.

Tags each issue with a ``healthcare_relevant`` boolean so the dashboard
can separate medical-device intelligence from general IT vulnerabilities.
"""

from __future__ import annotations

import re
from typing import Any, Dict

# ---------------------------------------------------------------------------
# Healthcare-specific sources -- any issue from these is relevant
# ---------------------------------------------------------------------------
HEALTHCARE_SOURCES: frozenset[str] = frozenset({
    "cisa-icsma",
    "fda-medwatch",
    "openfda-device-recalls",
    "openfda-device-events",
    "health-canada-recalls",
})

# ---------------------------------------------------------------------------
# Medical device vendors (lowercase for matching)
# ---------------------------------------------------------------------------
MEDICAL_DEVICE_VENDORS: tuple[str, ...] = (
    "ge healthcare",
    "philips",
    "siemens healthineers",
    "bd",
    "baxter",
    "medtronic",
    "stryker",
    "abbott",
    "boston scientific",
    "draeger",
    "hillrom",
    "welch allyn",
    "zoll",
    "mindray",
    "nihon kohden",
    "b. braun",
    "spacelabs",
    "masimo",
    "natus",
    "getinge",
    "olympus medical",
    "fujifilm medical",
    "carestream",
    "hologic",
    "beckman coulter",
    "biomerieux",
    "biomérieux",
    "roche diagnostics",
    "cerner",
    "epic systems",
    "contec health",
    "whill",
)

# ---------------------------------------------------------------------------
# Keyword patterns (case-insensitive)
# ---------------------------------------------------------------------------
_DEVICE_TYPES = [
    r"infusion pump",
    r"ventilator",
    r"patient monitor",
    r"defibrillator",
    r"pacemaker",
    r"imaging",
    r"pacs",
    r"dicom",
    r"\bmri\b",
    r"\bct\b",
    r"x-ray",
    r"ultrasound",
    r"surgical robot",
    r"insulin pump",
    r"blood gas analyzer",
    r"pulse oximeter",
    r"\behr\b",
    r"\bemr\b",
    r"\bhl7\b",
    r"\bfhir\b",
    r"medical device",
    r"clinical",
    r"biomedical",
    r"telehealth",
    r"point of care",
    r"bedside",
    r"wearable medical",
]

_REGULATORY = [
    r"\bfda\b",
    r"iec 62443",
    r"hipaa",
    r"\bphi\b",
    r"\bephi\b",
    r"510\(k\)",
    r"premarket",
    r"postmarket",
    r"medical device regulation",
]

# Single compiled pattern for all keywords.
_KEYWORD_RE: re.Pattern[str] = re.compile(
    "|".join(_DEVICE_TYPES + _REGULATORY), re.IGNORECASE,
)

# Single compiled pattern for vendor names in free text.
_VENDOR_TEXT_RE: re.Pattern[str] = re.compile(
    "|".join(re.escape(v) for v in MEDICAL_DEVICE_VENDORS), re.IGNORECASE,
)

# CISA KEV source IDs
_KEV_SOURCES: frozenset[str] = frozenset({"cisa-kev-csv", "cisa-kev-json"})


def is_healthcare_relevant(issue: Dict[str, Any]) -> bool:
    """Return *True* if the issue is relevant to healthcare / medical devices.

    Any single condition is sufficient:
      a) Source is healthcare-specific.
      b) Title / summary / vendor matches device keywords or vendor names.
      c) ``healthcare_category`` is non-empty.
      d) Source is CISA KEV **and** vendor is a known medical-device maker.
    """
    sources = issue.get("sources") or []

    # (a) Healthcare-specific source
    if any(s in HEALTHCARE_SOURCES for s in sources):
        return True

    # (c) Existing healthcare_category tag
    if issue.get("healthcare_category"):
        return True

    # (b) Keyword / vendor match in text fields
    text = " ".join(str(issue.get(f, "")) for f in ("title", "summary", "vendor"))
    if _KEYWORD_RE.search(text):
        return True
    if _VENDOR_TEXT_RE.search(text):
        return True

    # (d) CISA KEV + medical device vendor
    if any(s in _KEV_SOURCES for s in sources):
        vendor_lower = (issue.get("vendor") or "").lower()
        if any(v in vendor_lower for v in MEDICAL_DEVICE_VENDORS):
            return True

    return False
