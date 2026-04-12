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
# Medical device vendors (lowercase for case-insensitive substring matching)
# Curated allowlist — extend as real vendors are observed in the corpus.
# ---------------------------------------------------------------------------
MEDICAL_DEVICE_VENDORS: tuple[str, ...] = (
    "abbott",
    "abiomed",
    "alivecor",
    "b. braun",
    "baxter",
    "bd",  # Becton Dickinson
    "beckman coulter",
    "biotronik",
    "boston scientific",
    "cochlear",
    "dexcom",
    "drager",
    "draeger",  # German umlaut spelling variant
    "edwards lifesciences",
    "fresenius",
    "ge healthcare",
    "getinge",
    "hillrom",
    "hologic",
    "insulet",
    "intuitive surgical",
    "johnson & johnson medtech",
    "karl storz",
    "livanova",
    "masimo",
    "medcrypt",
    "medtronic",
    "mindray",
    "natus",
    "nihon kohden",
    "olympus medical",
    "penumbra",
    "philips healthcare",
    "resmed",
    "roche diagnostics",
    "siemens healthineers",
    "smith & nephew",
    "smiths medical",
    "spacelabs",
    "steris",
    "stryker",
    "teleflex",
    "terumo",
    "varian",
    "vyaire",
    "welch allyn",
    "zimmer biomet",
    "zoll",
)

# ---------------------------------------------------------------------------
# Medical device product keywords (lowercase for case-insensitive substring
# matching against entries in an issue's ``affected_products`` field).
# Curated seed list — extend as needed.
# ---------------------------------------------------------------------------
MEDICAL_DEVICE_PRODUCT_KEYWORDS: tuple[str, ...] = (
    "infusion pump",
    "insulin pump",
    "pacemaker",
    "defibrillator",
    "icd",
    "crt-d",
    "ventilator",
    "anesthesia",
    "patient monitor",
    "mri",
    "ct scanner",
    "ultrasound",
    "mammography",
    "fluoroscopy",
    "angiography",
    "intellivue",
    "ivenix",
    "impella",
    "dialysis",
    "heartmate",
    "glucose monitor",
    "cgm",
    "continuous glucose",
    "ekg",
    "ecg",
    "electrocardiograph",
    "hearing aid",
    "cochlear implant",
    "surgical robot",
    "da vinci",
    "endoscope",
    "bronchoscope",
    "blood gas analyzer",
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



def _is_medical_device(issue: Dict[str, Any]) -> bool:
    """Strict medical-device determination. True iff at least one rule fires.

    RULE 1 — CISA ICS-Medical authority: ``cisa-icsma`` in sources.
    RULE 2 — Vendor allowlist: ``vendor`` field contains (case-insensitive
             substring) any entry from ``MEDICAL_DEVICE_VENDORS``.
    RULE 3 — FDA risk class populated (non-null ``fda_risk_class``).
    RULE 4 — Affected-product allowlist: any entry in ``affected_products``
             contains (case-insensitive substring) any keyword from
             ``MEDICAL_DEVICE_PRODUCT_KEYWORDS``.
    """
    sources = issue.get("sources") or []
    if "cisa-icsma" in sources:
        return True

    vendor_lower = (issue.get("vendor") or "").lower()
    if vendor_lower and any(v in vendor_lower for v in MEDICAL_DEVICE_VENDORS):
        return True

    if issue.get("fda_risk_class"):
        return True

    affected_products = issue.get("affected_products") or []
    if affected_products:
        products_text = " ".join(str(p) for p in affected_products).lower()
        if any(k in products_text for k in MEDICAL_DEVICE_PRODUCT_KEYWORDS):
            return True

    return False


def classify_healthcare_category(issue: Dict[str, Any]) -> str:
    """Classify a healthcare-relevant issue into a specific category.

    Returns one of:
      - "medical_device"           (strict 4-rule check via _is_medical_device)
      - "healthcare_it"
      - "healthcare_infrastructure"
      - "healthcare_adjacent"

    Only call this on issues where is_healthcare_relevant() == True.
    """
    if _is_medical_device(issue):
        return "medical_device"

    text = " ".join(str(issue.get(f, "")) for f in ("title", "summary", "vendor"))

    if _HEALTHCARE_IT_RE.search(text):
        return "healthcare_it"
    if _HEALTHCARE_INFRA_RE.search(text):
        return "healthcare_infrastructure"
    return "healthcare_adjacent"
