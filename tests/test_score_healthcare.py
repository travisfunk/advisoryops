"""Phase 3, Task 3.2 — healthcare-specific scoring tests for score_issue_v2().

Covers all four new dimensions:
  1. Source authority weight   (tier-weight scaled from source_weights.json)
  2. Device context signals    (infusion pump, ventilator, PACS, patient monitor…)
  3. Patch feasibility         (no patch, EOL, firmware, vendor-managed)
  4. Clinical impact           (patient safety, life-sustaining, ICU, PHI)
  + Healthcare tier-1 medical source bonus (+50)
"""
from __future__ import annotations

import pytest

from advisoryops.score import score_issue, score_issue_v2


# ── helpers ────────────────────────────────────────────────────────────────

def _issue(
    summary: str = "",
    *,
    title: str = "",
    sources: list[str] | None = None,
    links: list[str] | None = None,
    issue_type: str = "cve",
    issue_id: str = "CVE-2024-TEST",
) -> dict:
    return {
        "issue_id": issue_id,
        "issue_type": issue_type,
        "title": title,
        "summary": summary,
        "sources": sources or ["cisa-icsma"],
        "links": links or [],
    }


def _v2_score(issue: dict) -> int:
    return score_issue_v2(issue).score


def _v2_priority(issue: dict) -> str:
    return score_issue_v2(issue).priority


def _has_label(why: list[str], fragment: str) -> bool:
    return any(fragment.lower() in w.lower() for w in why)


# ══════════════════════════════════════════════════════════════════════════
# Dimension 1: Source authority weight (tier-weight based)
# base_authority_points=30; tier weights: t1=1.0, t2=0.8, t3=0.6, t4=0.3, t5=0.2
# healthcare_tier1_medical_bonus=+50 for cisa-icsma, fda-medwatch, openfda-*, health-canada-recalls
# ══════════════════════════════════════════════════════════════════════════

def test_source_authority_tier1_icsma() -> None:
    """cisa-icsma (tier-1, weight=1.0) → +30 authority + +50 healthcare bonus = +80 over v1."""
    iss = _issue("Generic vulnerability.", sources=["cisa-icsma"])
    v1 = score_issue(iss).score
    v2 = _v2_score(iss)
    # 30 * 1.0 = 30 authority, +50 healthcare = +80
    assert v2 == v1 + 80, f"Expected v1+80={v1+80}, got v2={v2}"
    assert _has_label(score_issue_v2(iss).why, "source-authority")
    assert _has_label(score_issue_v2(iss).why, "healthcare-source")


def test_source_authority_tier1_icsa() -> None:
    """cisa-icsa (tier-1, weight=1.0) → +30 authority only (not in medical bonus set)."""
    iss = _issue("Generic vulnerability.", sources=["cisa-icsa"])
    v1 = score_issue(iss).score
    v2 = _v2_score(iss)
    assert v2 == v1 + 30, f"Expected v1+30={v1+30}, got v2={v2}"
    assert _has_label(score_issue_v2(iss).why, "source-authority")
    assert not _has_label(score_issue_v2(iss).why, "healthcare-source"), \
        "cisa-icsa is tier-1 but not medical-specific"


def test_source_authority_tier2() -> None:
    """Tier-2 source (ncsc-uk, weight=0.85) → +26 authority, no healthcare bonus."""
    iss = _issue("Generic vulnerability.", sources=["ncsc-uk"])
    v1 = score_issue(iss).score
    v2 = _v2_score(iss)
    # round(30 * 0.85) = 26
    assert v2 == v1 + 26, f"Expected v1+26={v1+26}, got v2={v2}"
    assert _has_label(score_issue_v2(iss).why, "tier-2")


def test_source_authority_tier3() -> None:
    """Tier-3 source (mandiant-blog, weight=0.70) → +21 authority."""
    iss = _issue("Generic vulnerability.", sources=["mandiant-blog"])
    v1 = score_issue(iss).score
    v2 = _v2_score(iss)
    # round(30 * 0.70) = 21
    assert v2 == v1 + 21, f"Expected v1+21={v1+21}, got v2={v2}"


def test_source_authority_tier4() -> None:
    """Tier-4 source (dark-reading, weight=0.50) → +15 authority."""
    iss = _issue("Generic vulnerability.", sources=["dark-reading"])
    v1 = score_issue(iss).score
    v2 = _v2_score(iss)
    # round(30 * 0.50) = 15
    assert v2 == v1 + 15, f"Expected v1+15={v1+15}, got v2={v2}"


def test_source_authority_tier5() -> None:
    """Tier-5 source (urlhaus-recent, weight=0.35) → +10 authority."""
    iss = _issue("Generic vulnerability.", sources=["urlhaus-recent"])
    v1 = score_issue(iss).score
    v2 = _v2_score(iss)
    # round(30 * 0.35) = 10  (Python banker's rounding: 10.5 → 10)
    assert v2 == v1 + 10, f"Expected v1+10={v1+10}, got v2={v2}"


def test_source_authority_unknown_source_zero() -> None:
    """Unknown source (not in source_weights.json) gets 0 authority weight."""
    iss = _issue("Generic vulnerability.", sources=["completely-unknown-source"])
    v1 = score_issue(iss).score
    v2 = _v2_score(iss)
    assert not _has_label(score_issue_v2(iss).why, "source-authority"), \
        "Unknown source should produce no source-authority label"


def test_healthcare_source_bonus_fda_medwatch() -> None:
    """fda-medwatch is tier-1 medical → +30 authority + +50 bonus."""
    iss = _issue("Device recall.", sources=["fda-medwatch"])
    v1 = score_issue(iss).score
    v2 = _v2_score(iss)
    assert v2 == v1 + 80, f"Expected v1+80, got v2={v2}"
    assert _has_label(score_issue_v2(iss).why, "healthcare-source")


def test_healthcare_source_bonus_openfda_recalls() -> None:
    """openfda-device-recalls is tier-1 medical → healthcare bonus fires."""
    iss = _issue("FDA cybersecurity recall.", sources=["openfda-device-recalls"])
    result = score_issue_v2(iss)
    assert _has_label(result.why, "healthcare-source"), result.why


def test_healthcare_source_bonus_not_for_tier4() -> None:
    """Tier-4 source (dark-reading) never triggers the healthcare source bonus."""
    iss = _issue("Hospital ransomware attack.", sources=["dark-reading"])
    result = score_issue_v2(iss)
    assert not _has_label(result.why, "healthcare-source"), \
        "Tier-4 source must not get the healthcare medical bonus"


def test_source_authority_highest_tier_wins() -> None:
    """When multiple sources are present, highest tier weight is used (single authority entry)."""
    iss = _issue("Generic vulnerability.", sources=["cisa-icsma", "dark-reading"])
    result = score_issue_v2(iss)
    # cisa-icsma (tier-1, 1.0) wins over dark-reading (tier-4, 0.3)
    authority_labels = [w for w in result.why if "source-authority:" in w]
    assert len(authority_labels) == 1, "Should be exactly one source-authority entry"
    assert "tier-1" in authority_labels[0], f"Expected tier-1, got: {authority_labels[0]}"


def test_kev_source_gets_tier1_authority() -> None:
    """cisa-kev-csv is tier-1 so it gets +30 authority, but no healthcare medical bonus."""
    iss = _issue("Generic vulnerability.", sources=["cisa-kev-csv"])
    v1 = score_issue(iss).score
    v2 = _v2_score(iss)
    # +30 authority, no healthcare bonus (kev is not in medical-specific list)
    assert v2 == v1 + 30, f"Expected v1+30={v1+30}, got v2={v2}"
    assert not _has_label(score_issue_v2(iss).why, "healthcare-source")


# ══════════════════════════════════════════════════════════════════════════
# Dimension 2: Device context signals
# ══════════════════════════════════════════════════════════════════════════

def test_device_infusion_pump() -> None:
    """Infusion pump in summary → +25 device bonus."""
    iss = _issue("Vulnerability in smart infusion pump allows unauthorized dose override.")
    result = score_issue_v2(iss)
    assert _has_label(result.why, "infusion"), result.why
    assert result.score >= score_issue(iss).score + 20  # +20 icsma + 25 pump


def test_device_ventilator() -> None:
    """Ventilator mention → +25 device bonus."""
    iss = _issue("Exploit targets the ventilator control interface over local network.")
    result = score_issue_v2(iss)
    assert _has_label(result.why, "ventilator"), result.why


def test_device_patient_monitor() -> None:
    """Patient monitor mention → +20 device bonus."""
    iss = _issue("Null pointer dereference crashes the central monitor during data refresh.")
    result = score_issue_v2(iss)
    assert _has_label(result.why, "patient monitor"), result.why
    bonus = result.score - score_issue(iss).score
    assert bonus >= 20, f"Expected device bonus >=20, got {bonus}"


def test_device_pacs_imaging() -> None:
    """PACS / DICOM / radiology in title or summary → +15 device bonus."""
    iss = _issue(
        "Path traversal vulnerability in Sante PACS Server allows arbitrary file read.",
        title="Sante PACS Server",
    )
    result = score_issue_v2(iss)
    assert _has_label(result.why, "PACS"), result.why


def test_device_dicom_library() -> None:
    """DICOM library triggers imaging device bonus."""
    iss = _issue("Heap overflow in DICOM parser when processing crafted DICOM files.")
    result = score_issue_v2(iss)
    assert _has_label(result.why, "imaging/PACS"), result.why


def test_device_ehr_emr() -> None:
    """EHR/EMR system mention → +10 device bonus."""
    iss = _issue("SQL injection in EHR login page exposes patient records.")
    result = score_issue_v2(iss)
    assert _has_label(result.why, "EHR"), result.why


def test_device_healthcare_context() -> None:
    """Generic 'hospital' or 'healthcare' → +10 context bonus."""
    iss = _issue("Vulnerability in hospital management backend services.", sources=["cisa-icsma"])
    result = score_issue_v2(iss)
    assert _has_label(result.why, "healthcare context"), result.why


def test_device_non_healthcare_no_bonus() -> None:
    """Non-healthcare summary gets no device context bonus."""
    iss = _issue(
        "Buffer overflow in a router firmware component enables RCE.",
        sources=["some-news-feed"],
    )
    result = score_issue_v2(iss)
    device_labels = [w for w in result.why if "device:" in w]
    # 'firmware' is a patch signal, not a device signal — device labels should be empty
    assert len(device_labels) == 0, f"Unexpected device labels: {device_labels}"


# ══════════════════════════════════════════════════════════════════════════
# Dimension 3: Patch feasibility
# ══════════════════════════════════════════════════════════════════════════

def test_patch_no_patch_available() -> None:
    """'No patch available' → +20 patch bonus."""
    iss = _issue("No patch available for this vulnerability. Vendor recommends network isolation.")
    result = score_issue_v2(iss)
    assert _has_label(result.why, "no patch"), result.why
    bonus = result.score - score_issue(iss).score
    assert bonus >= 20, f"Expected >=20 patch bonus, got {bonus}"


def test_patch_end_of_life() -> None:
    """End of life / decommissioned → +15 patch bonus."""
    iss = _issue("The affected product has reached end of life and will not receive security updates.")
    result = score_issue_v2(iss)
    assert _has_label(result.why, "end of life"), result.why


def test_patch_decommissioned() -> None:
    """'Decommissioned' also triggers the EOL patch signal."""
    iss = _issue("ZOLL ePCR was decommissioned in May 2025. No replacement patch is planned.")
    result = score_issue_v2(iss)
    assert _has_label(result.why, "end of life"), result.why


def test_patch_vendor_managed() -> None:
    """'Vendor-managed' → +10 patch bonus."""
    iss = _issue("Remediation requires vendor-managed firmware deployment to affected devices.")
    result = score_issue_v2(iss)
    assert _has_label(result.why, "vendor-managed"), result.why


def test_patch_firmware() -> None:
    """'Firmware' mention → +10 patch bonus."""
    iss = _issue("The vulnerability exists in the device firmware and requires a firmware update.")
    result = score_issue_v2(iss)
    assert _has_label(result.why, "firmware"), result.why


# ══════════════════════════════════════════════════════════════════════════
# Dimension 4: Clinical impact
# ══════════════════════════════════════════════════════════════════════════

def test_clinical_patient_safety() -> None:
    """'Patient safety' → +25 clinical bonus."""
    iss = _issue("Successful exploitation could impact patient safety by disrupting device operation.")
    result = score_issue_v2(iss)
    assert _has_label(result.why, "patient safety"), result.why
    bonus = result.score - score_issue(iss).score
    assert bonus >= 25, f"Expected >=25 clinical bonus, got {bonus}"


def test_clinical_life_sustaining() -> None:
    """'Life-sustaining' → +30 clinical bonus (highest single clinical signal)."""
    iss = _issue("Attack could disable life-sustaining ventilation in critical care patients.")
    result = score_issue_v2(iss)
    assert _has_label(result.why, "life-sustaining"), result.why
    bonus = result.score - score_issue(iss).score
    assert bonus >= 30, f"Expected >=30, got {bonus}"


def test_clinical_icu() -> None:
    """'ICU' → +20 clinical bonus."""
    iss = _issue("Devices deployed in ICU settings are affected by this denial-of-service vulnerability.")
    result = score_issue_v2(iss)
    assert _has_label(result.why, "ICU"), result.why


def test_clinical_phi() -> None:
    """PHI / patient data mention → +15 clinical bonus."""
    iss = _issue("Exploit allows read access to PHI stored in the application database.")
    result = score_issue_v2(iss)
    assert _has_label(result.why, "PHI"), result.why


def test_clinical_context_generic() -> None:
    """'Clinical' alone → +5 (low-value catch-all)."""
    iss = _issue("Used in clinical environments to manage patient workflows.", sources=["some-source"])
    result = score_issue_v2(iss)
    assert _has_label(result.why, "clinical context"), result.why


# ══════════════════════════════════════════════════════════════════════════
# Combined / regression scenarios
# ══════════════════════════════════════════════════════════════════════════

def test_v2_always_gte_v1() -> None:
    """v2 score must be >= v1 score for any input (v2 only adds points)."""
    cases = [
        _issue("Generic CVE.", sources=["cisa-icsma"]),
        _issue("RCE in router.", sources=["some-feed"]),
        _issue("KEV entry.", sources=["cisa-kev-csv"]),
        _issue("Infusion pump exploit.", sources=["cisa-icsma"]),
        _issue("No patch, EOL device.", sources=["vendor-feed"]),
    ]
    for iss in cases:
        v1 = score_issue(iss).score
        v2 = score_issue_v2(iss).score
        assert v2 >= v1, f"v2 ({v2}) < v1 ({v1}) for issue: {iss}"


def test_score_is_deterministic() -> None:
    """Calling score_issue_v2 twice on the same input always returns identical results."""
    iss = _issue(
        "Patient safety risk: no patch available for infusion pump firmware vulnerability.",
        title="Infusion Pump Firmware RCE",
        sources=["cisa-icsma"],
    )
    r1 = score_issue_v2(iss)
    r2 = score_issue_v2(iss)
    assert r1.score == r2.score
    assert r1.priority == r2.priority
    assert r1.why == r2.why


def test_combined_icsma_device_no_patch_patient_safety() -> None:
    """ICSMA source + patient monitor + no patch + patient safety should reach P0."""
    iss = _issue(
        "No patch available. Patient safety alert: null pointer crash in central monitor "
        "used in intensive care units. Contact vendor for mitigation guidance.",
        title="Central Patient Monitor Vulnerability",
        sources=["cisa-icsma"],
    )
    result = score_issue_v2(iss)
    # base(10) + authority(30) + hc_bonus(50) + patient_monitor(20)
    # + no_patch(20) + vendor_mgd(10) + patient_safety(25) + icu(20) + clinical(5) >= 190
    assert result.score >= 100, f"Expected >=100, got {result.score}. why={result.why}"
    assert result.priority == "P0", f"Expected P0, got {result.priority}"


def test_whill_wheelchair_upgrades_from_p3() -> None:
    """Real WHILL wheelchair advisory: v1=P3, v2 upgrades significantly via ICSMA tier-1 + healthcare bonus."""
    # Simplified version of the real WHILL ICSMA advisory content
    iss = _issue(
        "WHILL Model C2 Electric Wheelchairs do not enforce authentication for Bluetooth. "
        "An attacker in range can pair and issue movement commands. "
        "Critical Infrastructure Sectors: Healthcare and Public Health.",
        title="WHILL Model C2 Electric Wheelchairs",
        sources=["cisa-icsma"],
    )
    v1_result = score_issue(iss)
    v2_result = score_issue_v2(iss)
    assert v1_result.priority == "P3", f"v1 should be P3, got {v1_result.priority}"
    assert v2_result.score > v1_result.score, "v2 must score higher than v1"
    # tier-1 authority(+30) + healthcare_bonus(+50) + healthcare_context(+10) = +90
    # total = 10+90+10 = 110 → P0
    assert v2_result.priority == "P0", \
        f"v2 should be P0, got {v2_result.priority} (score={v2_result.score})"


def test_kev_icsma_combined_reaches_p0() -> None:
    """Issue on KEV + ICSMA source with patient safety note should hit P0."""
    iss = _issue(
        "Known exploited. Patient safety risk in infusion pump firmware. No patch available.",
        sources=["cisa-icsma", "cisa-kev-csv"],
        links=["https://nvd.nist.gov/vuln/detail/CVE-2024-TEST"],
    )
    result = score_issue_v2(iss)
    # v1: 10+80(kev-source)+80(kev-keyword)+5(nvd) = 175; v2 adds more
    assert result.score >= 100
    assert result.priority == "P0"
