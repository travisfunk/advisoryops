"""Build Phase 5 golden test fixtures from real discovery data."""
import json
import re
from pathlib import Path

icsma_items = [json.loads(l) for l in open("outputs/discover/cisa-icsma/items.jsonl")]
kev_csv_items = [json.loads(l) for l in open("outputs/discover/cisa-kev-csv/items.jsonl")]
kev_json_items = [json.loads(l) for l in open("outputs/discover/cisa-kev-json/items.jsonl")]

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)

kev_csv = {i["guid"]: i for i in kev_csv_items}
kev_json = {i["guid"]: i for i in kev_json_items}
icsma_by_title = {i["title"]: i for i in icsma_items}

root = Path("tests/fixtures/golden")
root.mkdir(parents=True, exist_ok=True)


def write_fixture(fid, inputs, expected):
    d = root / fid
    d.mkdir(exist_ok=True)
    (d / "input.json").write_text(json.dumps(inputs, indent=2), encoding="utf-8")
    (d / "expected.json").write_text(json.dumps(expected, indent=2), encoding="utf-8")
    print("  %s: %d signal(s) -> %d issue(s)" % (fid, len(inputs), expected["expected_issue_count"]))


def extract_cves(item):
    text = " ".join([item.get("guid", ""), item.get("title", ""), item.get("summary", ""), item.get("link", "")])
    return sorted(set(CVE_RE.findall(text)))


# ── 01: ZOLL ePCR IOS ──────────────────────────────────────────────────────
item = icsma_by_title["ZOLL ePCR IOS Mobile Application"]
write_fixture(
    "fixture-01-icsma-zoll-epcr",
    [item],
    {
        "expected_issue_count": 1,
        "expected_cves": ["CVE-2025-12699"],
        "expected_priority_range": ["P3"],
        "expected_healthcare_category": "medical_device",
        "description": (
            "ZOLL ePCR IOS mobile app - PHI disclosure via XSS in medical record fields "
            "(CVSS 5.5 MEDIUM). Product decommissioned, no patch. Single ICSMA signal, no KEV, "
            "no NVD link. Score = 10 (CVE base) -> P3."
        ),
    },
)

# ── 02: WHILL wheelchair Bluetooth ────────────────────────────────────────
item = icsma_by_title["WHILL Model C2 Electric Wheelchairs and Model F Power Chairs"]
write_fixture(
    "fixture-02-icsma-whill-wheelchair",
    [item],
    {
        "expected_issue_count": 1,
        "expected_cves": ["CVE-2025-14346"],
        "expected_priority_range": ["P3"],
        "expected_healthcare_category": "medical_device",
        "description": (
            "WHILL electric wheelchair Bluetooth missing auth (CVSS 9.8 CRITICAL). "
            "Attacker in BT range can override speed and take full control of mobility device. "
            "Single ICSMA signal, no KEV. Score = 10 (CVE base) -> P3. Note: Phase 3 scorer "
            "should elevate this to P0/P1 given patient safety impact."
        ),
    },
)

# ── 03: KEV single – RoundCube RCE ────────────────────────────────────────
item = kev_csv["CVE-2025-49113"]
write_fixture(
    "fixture-03-kev-single-cve",
    [item],
    {
        "expected_issue_count": 1,
        "expected_cves": ["CVE-2025-49113"],
        "expected_priority_range": ["P1"],
        "expected_healthcare_category": "not_healthcare",
        "description": (
            "RoundCube Webmail deserialization RCE (CVE-2025-49113), CISA KEV. "
            "Known exploited in the wild. Score = 10 (CVE) + 80 (KEV source) + 5 (NVD link) = 95 -> P1."
        ),
    },
)

# ── 04: KEV dedup two sources ──────────────────────────────────────────────
csv_item = kev_csv["CVE-2008-0015"]
json_item = kev_json["CVE-2008-0015"]
write_fixture(
    "fixture-04-kev-dedup-two-sources",
    [csv_item, json_item],
    {
        "expected_issue_count": 1,
        "expected_cves": ["CVE-2008-0015"],
        "expected_priority_range": ["P1"],
        "expected_source_count": 2,
        "expected_healthcare_category": "not_healthcare",
        "description": (
            "MS Windows Video ActiveX RCE (CVE-2008-0015). Appears in both cisa-kev-csv and "
            "cisa-kev-json. Correlate must deduplicate into exactly 1 issue with 2 sources. "
            "Score = 95 -> P1."
        ),
    },
)

# ── 05: Santesoft PACS Server – 5 CVEs from one advisory ──────────────────
item = icsma_by_title["Santesoft Sante PACS Server"]
cves = extract_cves(item)
write_fixture(
    "fixture-05-icsma-pacs-server-multi-cve",
    [item],
    {
        "expected_issue_count": len(cves),
        "expected_cves": cves,
        "expected_priority_range": ["P3"],
        "expected_healthcare_category": "medical_device",
        "description": (
            "Santesoft Sante PACS Server advisory (CVSS 9.1 HIGH). Single ICSMA signal "
            "containing %d CVEs: path traversal, double free, cleartext transmission, XSS. "
            "Correlate produces one issue per CVE ID found in summary HTML. No KEV -> all P3." % len(cves)
        ),
    },
)

# ── 06: NIHON KOHDEN patient monitor ──────────────────────────────────────
item = icsma_by_title["NIHON KOHDEN Central Monitor CNS-6201"]
write_fixture(
    "fixture-06-icsma-patient-monitor",
    [item],
    {
        "expected_issue_count": 1,
        "expected_cves": ["CVE-2025-59668"],
        "expected_priority_range": ["P3"],
        "expected_healthcare_category": "medical_device",
        "description": (
            "NIHON KOHDEN Central Monitor CNS-6201 (CVSS 8.7 HIGH). Null pointer dereference, "
            "remotely exploitable, low complexity. Central patient monitoring hardware in clinical use. "
            "No KEV -> P3."
        ),
    },
)

# ── 07: Vertikal Hospital Manager backend ─────────────────────────────────
item = icsma_by_title["Vertikal Systems Hospital Manager Backend Services"]
cves = extract_cves(item)
write_fixture(
    "fixture-07-icsma-hospital-manager",
    [item],
    {
        "expected_issue_count": len(cves),
        "expected_cves": cves,
        "expected_priority_range": ["P3"],
        "expected_healthcare_category": "healthcare_it",
        "description": (
            "Vertikal Systems Hospital Manager backend services (%d CVEs, CVSS 8.7). "
            "Hospital scheduling/operations software. Healthcare IT (not direct medical device). "
            "Remote exploit, low complexity. No KEV -> P3." % len(cves)
        ),
    },
)

# ── 08: KEV + RCE keyword – Excel (validates KEV path vs broken keywords) ──
item = kev_csv["CVE-2007-0671"]
write_fixture(
    "fixture-08-kev-rce-excel",
    [item],
    {
        "expected_issue_count": 1,
        "expected_cves": ["CVE-2007-0671"],
        "expected_priority_range": ["P1"],
        "expected_healthcare_category": "not_healthcare",
        "description": (
            "MS Office Excel RCE (CVE-2007-0671), CISA KEV. Summary contains 'remote code execution' "
            "but keyword patterns are currently broken (double-escaped backslashes in _KEYWORDS). "
            "KEV source bonus (+80) alone produces score = 95 -> P1. Validates that P1 is reached "
            "via KEV independent of keyword matching."
        ),
    },
)

# ── 09: Two distinct KEV CVEs -> 2 separate issues ────────────────────────
item_a = kev_csv["CVE-2025-49113"]  # RoundCube deserialization RCE
item_b = kev_csv["CVE-2025-68461"]  # RoundCube XSS via SVG
write_fixture(
    "fixture-09-two-distinct-kev-cves",
    [item_a, item_b],
    {
        "expected_issue_count": 2,
        "expected_cves": ["CVE-2025-49113", "CVE-2025-68461"],
        "expected_priority_range": ["P1"],
        "expected_healthcare_category": "not_healthcare",
        "description": (
            "Two RoundCube Webmail CVEs from same KEV batch (CVE-2025-49113 RCE + CVE-2025-68461 XSS). "
            "Same vendor/product but different CVE IDs must produce 2 separate issues (not merged). "
            "Both P1 via KEV source."
        ),
    },
)

# ── 10: Varex Imaging dental X-ray ────────────────────────────────────────
item = icsma_by_title["Varex Imaging Panoramic Dental Imaging Software"]
write_fixture(
    "fixture-10-icsma-dental-imaging",
    [item],
    {
        "expected_issue_count": 1,
        "expected_cves": ["CVE-2024-22774"],
        "expected_priority_range": ["P3"],
        "expected_healthcare_category": "medical_device",
        "description": (
            "Varex Imaging panoramic dental X-ray software (CVE-2024-22774, CVSS 8.5 HIGH). "
            "Radiology imaging device. Low attack complexity. No KEV -> P3."
        ),
    },
)

# ── 11: Unknown issue type – non-CVE, non-healthcare ──────────────────────
unknown_item = {
    "fetched_at": "2026-02-21T10:59:38.000000+00:00",
    "guid": "VENDOR-2026-DELL-001",
    "link": "https://example.com/vendor/advisory/2026/001",
    "published_date": "2026-02-18",
    "signal_id": "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
    "source": "vendor-generic",
    "summary": "A vendor security advisory about hard-coded credentials in a storage appliance. No CVE assigned.",
    "title": "Dell Storage Advisory 2026-001",
}
write_fixture(
    "fixture-11-unknown-nonhealthcare",
    [unknown_item],
    {
        "expected_issue_count": 1,
        "expected_cves": [],
        "expected_priority_range": ["P3"],
        "expected_healthcare_category": "not_healthcare",
        "description": (
            "Synthetic vendor advisory with no CVE ID in any field. Correlate assigns "
            "issue_type='unknown' and UNK- prefix ID (SHA-256 of normalized title+date). "
            "Score = 2 (non-CVE base) -> P3. Tests the unknown-type code path and UNK- id generation."
        ),
    },
)

# ── 12: Grassroots DICOM library ──────────────────────────────────────────
item = icsma_by_title["Grassroots DICOM (GDCM)"]
write_fixture(
    "fixture-12-icsma-dicom-library",
    [item],
    {
        "expected_issue_count": 1,
        "expected_cves": ["CVE-2025-11266"],
        "expected_priority_range": ["P3"],
        "expected_healthcare_category": "medical_device",
        "description": (
            "Grassroots DICOM (GDCM) library (CVE-2025-11266, CVSS 6.8). DICOM is the medical "
            "imaging standard used by MRI, CT, X-ray equipment. Low attack complexity. No KEV -> P3."
        ),
    },
)

print("\nDone. 12 fixtures written to tests/fixtures/golden/")
