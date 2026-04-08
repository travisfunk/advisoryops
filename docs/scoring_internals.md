# Scoring Internals Reference

Technical reference for the AdvisoryOps scoring system. Last updated 2026-04-08.

## Scoring Module

**File**: `src/advisoryops/score.py`

Two scoring versions:
- **v1** (`score_issue()`): keyword-only baseline, fast and deterministic
- **v2** (`score_issue_v2()`): v1 + four healthcare dimensions (default)

## Priority Thresholds

```python
P0: score >= 150   # critical — notify + ingest + track
P1: score >= 100   # significant — ingest + track
P2: score >= 60    # moderate — track only
P3: score < 60     # informational — log only
```

## v1 Scoring: Keyword Baseline

### Base Score
| Condition | Points |
|-----------|--------|
| `issue_type == "cve"` | +10 |
| non-CVE | +2 |

### Keyword Bonuses (additive, matched on issue_id + title + summary)

| Keyword | Points |
|---------|--------|
| KEV / "known exploited" | +80 |
| "actively exploited" | +40 |
| RCE / "remote code execution" | +30 |
| "code execution" / "arbitrary code" | +25 |
| "authentication bypass" / "auth bypass" | +25 |
| "privilege escalation" / "priv esc" | +20 |
| "data exfiltration" / "exfiltration" | +15 |
| "information disclosure" | +15 |
| "SQL injection" / "sqli" | +15 |
| "proof of concept" / "poc" | +10 |
| "denial of service" / "dos" | +5 |

Multiple keywords **stack** (a single issue can match several).

### Source Bonuses
| Condition | Points |
|-----------|--------|
| "kev" or "cisa-kev" in source list | +80 |
| NVD link in links list | +5 |

The KEV source bonus is **separate** from the KEV keyword bonus and can stack with it (80 + 80 = 160).

## v2 Scoring: Healthcare-Aware (default)

v2 runs v1 first, then adds five healthcare dimensions.

### Dimension 1: Source Authority Weight

Uses `configs/source_weights.json`. The highest-tier source for an issue determines the bonus (single entry, no double-counting).

| Tier | Weight | Points | Example Sources |
|------|--------|--------|-----------------|
| Tier 1 | 1.0 | 30 | cisa-icsma, cisa-kev-*, fda-medwatch, openfda-*, health-canada-recalls |
| Tier 2 | 0.85 | 25 | philips-psirt, siemens-productcert, msrc-blog, ncsc-uk, nvd-cve-api |
| Tier 3 | 0.70 | 21 | claroty-team82, armis-labs, google-project-zero, mandiant-blog |
| Tier 4 | 0.50 | 15 | dark-reading, krebs-on-security, healthcare-it-news |
| Tier 5 | 0.35 | 10 | urlhaus-recent, threatfox-iocs, epss-data |

**Healthcare Tier-1 Medical Source Bonus**: If any source is in the `healthcare_tier1_medical_sources` set (cisa-icsma, fda-medwatch, openfda-device-recalls, openfda-device-events, health-canada-recalls, nhs-digital-cyber), an additional **+50** bonus is applied.

### Dimension 2: Device Context Signals

Matched on issue_id + title + summary. **Multiple matches stack.**

| Device Type | Points | Pattern Examples |
|-------------|--------|------------------|
| Infusion/IV/drug pump | +25 | infusion pump, insulin pump, drug pump |
| Ventilator | +25 | ventilator, respiratory, life support |
| Cardiac implant | +25 | defibrillator, pacemaker, cardiac implant |
| Patient monitor | +20 | patient monitor, vital signs, ecg |
| Medical imaging/PACS | +15 | pacs, dicom, mri, ct scan, x-ray |
| EHR/EMR | +10 | ehr, emr, electronic health record |
| Generic healthcare | +10 | hospital, clinic, medical device |

### Dimension 3: Patch Feasibility

**Multiple matches stack.**

| Signal | Points | Keywords |
|--------|--------|----------|
| No patch available | +20 | no patch, unpatched, no available fix |
| End of life | +15 | end of life, eol, decommissioned |
| Vendor-managed | +10 | vendor managed, contact vendor |
| Firmware update | +10 | firmware |

### Dimension 4: Clinical Impact

**Multiple matches stack.**

| Impact | Points | Keywords |
|--------|--------|----------|
| Life-sustaining | +30 | life sustaining, life support |
| Patient safety | +25 | patient safety |
| ICU/critical care | +20 | icu, intensive care, critical care |
| PHI/patient data | +15 | phi, protected health information |
| Clinical context | +5 | clinical |

### Dimension 5: FDA Risk Class

Based on the `fda_risk_class` field extracted from openFDA recall records or the classification database. **Single value, no stacking.**

Calibrated against real 873-issue healthcare corpus distribution (Class II is 72% of FDA recalls).

| Risk Class | Points | Description |
|------------|--------|-------------|
| Class III | +30 | Highest-risk devices (pacemakers, implantable defibrillators). Promotes P3→P2, P2→P1. |
| Class II | +10 | Moderate-risk devices (infusion pumps, most diagnostic equipment). Modest nudge. |
| Class I | +0 | Low-risk devices (bandages, stethoscopes). No bonus. |
| null | +0 | Unknown or not applicable. No bonus. |

## Score Combination Method

**Purely additive.** All dimensions add their points to the running total. No multiplication, weighting, or subtraction. The formula is:

```
score = base
      + sum(keyword_bonuses)
      + kev_source_bonus
      + nvd_link_bonus
      + source_authority_points
      + healthcare_medical_bonus
      + sum(device_signals)
      + sum(patch_signals)
      + sum(clinical_signals)
      + fda_risk_class_bonus
```

## Theoretical Score Range

| Component | Min | Max |
|-----------|-----|-----|
| Base | 2 | 10 |
| Keywords (all stacking) | 0 | 280 |
| KEV source | 0 | 80 |
| NVD link | 0 | 5 |
| Source authority | 0 | 30 |
| Healthcare medical | 0 | 50 |
| Device signals | 0 | 130 |
| Patch signals | 0 | 55 |
| Clinical signals | 0 | 95 |
| FDA risk class | 0 | 30 |
| **Total** | **2** | **765** |

In practice, observed range is 17-163 (most issues score 17-60). P0 threshold is 150.

## The `why` Field

Every scoring decision appends a human-readable string to the `why` list:

```json
{
  "why": [
    "base: issue_type=cve (+10)",
    "keyword: KEV/known exploited (+80)",
    "source: KEV source (+80)",
    "source-authority: tier-1 weight=1.0 (+30)",
    "healthcare-source: tier-1 medical source (+50)",
    "device: infusion/drug pump (+25)",
    "patch: no patch available (+20)",
    "clinical: patient safety (+25)",
    "priority: P0 (score=320)"
  ]
}
```

## Optional AI Classification

When `--ai-score` is set, issues with NO deterministic healthcare signals get an AI classification pass. Boosts:
- medical_device (confidence >= 0.70): +20
- healthcare_it (confidence >= 0.70): +15
- healthcare_adjacent (confidence >= 0.70): +5

---

## Cache Directory Reference

All backfill caches are under `outputs/`:

| Source | Cache Directory | File Pattern | Record Count |
|--------|-----------------|--------------|--------------|
| NVD CVEs | `outputs/nvd_cache/` | `CVE-YYYY-NNNN.json` | ~340,000 |
| CISA ICSMA | `outputs/cisa_icsma_cache/` | `ICSMA-YY-DDD-NN.json` | ~178 |
| openFDA Recalls | `outputs/openfda_cache/` | `recall_NNNNN.json` | ~14,630 |
| FDA Enforcement | `outputs/fda_safety_comms_cache/` | `enf_Z-NNNN-YYYY.json` | ~38,510 |
| MHRA UK | `outputs/mhra_uk_cache/` | `mhra_*.json` | ~1,381 |
| Health Canada | `outputs/health_canada_cache/` | `hc_NNNNN.json` | ~15 (incremental) |
| Philips PSIRT | `outputs/philips_psirt_cache/` | `PHILIPS-*.json` | ~200 |
| Siemens ProductCERT | `outputs/siemens_productcert_cache/` | `SSA-NNNNNN.json` | ~779 |
| EPSS | `outputs/epss_cache/` | `epss_scores.json` | 1 file (325K scores) |
| CWE Catalog | `outputs/cwe_cache/` | `cwe_catalog.json` | 1 file (~60 CWEs) |
| ATT&CK ICS | `outputs/attack_ics_cache/` | `ics_attack.json` | 1 file (~60 techniques) |
| CISA Vulnrichment | `outputs/vulnrichment_cache/` | `CVE-YYYY-NNNN.json` | on-demand |

**Note**: The `analyze_scoring_calibration.py` script looks for `outputs/openfda_recalls_cache/` — this path does NOT exist. The correct path is `outputs/openfda_cache/`.
