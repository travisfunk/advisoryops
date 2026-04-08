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


# ---------------------------------------------------------------------------
# Healthcare category classification
# ---------------------------------------------------------------------------

# Sources that are definitively medical-device-specific
_MEDICAL_DEVICE_SOURCES: frozenset[str] = frozenset({
    "cisa-icsma",
    "fda-medwatch",
    "openfda-device-recalls",
    "openfda-device-events",
    "openfda-recalls-historical",
    "fda-safety-comms-historical",
    "health-canada-recalls",
    "philips-psirt",
    "siemens-productcert",
})

# Device-type keywords → medical_device
_MEDICAL_DEVICE_RE: re.Pattern[str] = re.compile(
    r"infusion pump|ventilator|defibrillator|pacemaker|implantable"
    r"|patient monitor|pulse oximeter|surgical robot|insulin pump"
    r"|blood gas analyzer|x-ray|ultrasound|\bmri\b|\bct\b"
    r"|medical device|biomedical|imaging|pacs|dicom"
    r"|catheter|oxygenator|respirator|wearable medical"
    r"|510\(k\)|premarket|postmarket|medical device regulation"
    r"|\bfda\b|iec 62443",
    re.IGNORECASE,
)

# Healthcare IT keywords → healthcare_it
_HEALTHCARE_IT_RE: re.Pattern[str] = re.compile(
    r"\behr\b|\bemr\b|electronic health record|electronic medical record"
    r"|\bhl7\b|\bfhir\b|telehealth|point of care|clinical informatics"
    r"|health information (system|exchange)|cerner|epic systems",
    re.IGNORECASE,
)

# Healthcare infrastructure keywords → healthcare_infrastructure
_HEALTHCARE_INFRA_RE: re.Pattern[str] = re.compile(
    r"\bhospital\b|\bclinic\b|health care|healthcare"
    r"|hipaa|\bphi\b|\bephi\b|protected health information"
    r"|clinical|bedside|\bicu\b|intensive care",
    re.IGNORECASE,
)


def classify_healthcare_category(issue: Dict[str, Any]) -> str:
    """Classify a healthcare-relevant issue into a specific category.

    Returns one of:
      - "medical_device"
      - "healthcare_it"
      - "healthcare_infrastructure"
      - "healthcare_adjacent"

    Only call this on issues where is_healthcare_relevant() == True.
    """
    sources = issue.get("sources") or []
    text = " ".join(str(issue.get(f, "")) for f in ("title", "summary", "vendor"))

    # 1. Medical device sources are definitive
    if any(s in _MEDICAL_DEVICE_SOURCES for s in sources):
        return "medical_device"

    # 2. Medical device vendor in text
    if _VENDOR_TEXT_RE.search(text):
        return "medical_device"

    # 3. FDA risk class present → medical_device
    if issue.get("fda_risk_class"):
        return "medical_device"

    # 4. Device keywords in text
    if _MEDICAL_DEVICE_RE.search(text):
        return "medical_device"

    # 5. Healthcare IT keywords
    if _HEALTHCARE_IT_RE.search(text):
        return "healthcare_it"

    # 6. Healthcare infrastructure keywords
    if _HEALTHCARE_INFRA_RE.search(text):
        return "healthcare_infrastructure"

    # 7. KEV + medical vendor (condition d from is_healthcare_relevant)
    if any(s in _KEV_SOURCES for s in sources):
        vendor_lower = (issue.get("vendor") or "").lower()
        if any(v in vendor_lower for v in MEDICAL_DEVICE_VENDORS):
            return "medical_device"

    return "healthcare_adjacent"
