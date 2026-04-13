# Pharmaceutical exclusion — Phase 1 diagnosis (Problem 9)

Date: 2026-04-12. Branch: `feature/v1-readiness`.

## TL;DR

- **medical_device bucket pharma count: 2** (threshold to proceed: ≤45). **PROCEED.**
- Both leaked records come from `mhra-uk-alerts`.
- Root cause confirmed: MHRA's "Class 2 Medicines Recall" title is parsed by the upstream FDA-risk-class extractor into `fda_risk_class=2`, which triggers Rule 3 of the 4-rule medical_device classifier.
- Recommended source-level fixes: disable `mhra-uk-alerts` and `fda-medwatch`. Keep Rule 3 unchanged.

## Method

`scripts/diagnose_pharma.py` scanned `docs/feed_latest.json` (3,929 issues) with:

- **Pharma title regex** (title-only, summary was too noisy): `medicines? recall`, `drug recall`, `pharmaceutical recall`, `solution for injection`, `oral tablet`, `oral solution`, `ampoule`, `hydrochloride`, `prolonged-release`, `mg/ml`, `i.u./ml`, `injection bp`, `syrup`, `film-coated tablets?`, `inhaler`, `class [1-4] medicines`.
- **Suspect source regex**: any `source_id` matching `drug|medicine|pharma|medwatch`.

Re-running with a stricter title-only regex (vs. the original title+summary scan) dropped noise: the initial title+summary scan produced 12 false-positive hits from terms like "sodium" appearing in device names or regulatory summary text.

## Findings

### medical_device bucket (424 issues)

| Scope | Count |
| --- | --- |
| Pharma-titled records in medical_device bucket | **2** |
| All 2 from `mhra-uk-alerts` | 2 |
| Rule 3 hits (fda_risk_class populated) on those 2 | 2 |
| Rule 2 vendor-allowlist hits | 0 |
| Rule 4 product-keyword hits | 0 |
| Rule 1 cisa-icsma source hits | 0 |

Both records:

- `[P1] frc=2 srcs=[mhra-uk-alerts]` — `Class 2 Medicines Recall: Mercury Pharmaceuticals Ltd, Paliperidone Mercury Pharma prolonged-release`
- `[P3] frc=1 srcs=[mhra-uk-alerts]` — `Class 2 Medicines Recall: Wockhardt UK Ltd, Heparin sodium 1,000 I.U./ml solution for injection or c…`

### Corpus-wide source scan (suspected pharmaceutical producers)

| source_id | Total records | Pharma-titled | MD bucket (pharma) | MD bucket (non-pharma) |
| --- | ---: | ---: | ---: | ---: |
| `mhra-uk-alerts` | 200 | 159 (79.5%) | 2 | 0 |
| `fda-medwatch` | 5 | 0 | 0 | 0 |

Notes:

- **`mhra-uk-alerts`** is the only corpus source producing pharmaceutical content. 159 of 200 records are UK medicines recalls (e.g., "Paracetamol 500mg Tablets", "Ranitidine 150mg Film-Coated Tablets", "Compound Sodium Lactate Solution for Infusion BP"). 41 are legitimate medical device alerts (e.g., "Sprint Fidelis ICD", "Accu-Chek Insight Insulin pump", "HeartStart MRx monitor/defibrillator") but none of them currently land in the `medical_device` bucket — they're in `healthcare_adjacent`. The source was nominally configured as "MHRA UK Medical Device Alerts" but the upstream GOV.UK search query is returning mixed device + medicines content.
- **`fda-medwatch`** currently has 5 records, all non-pharma device safety comms (Ivenix pump, Medline homecare bed, Olympus insufflation unit, Vantive dialysis tubing, FDA choking rescue comms — the last is arguably noise but not pharma). However, **FDA MedWatch is fundamentally a mixed drug+device+biologics+food RSS feed**; historical backfill or future ingest will pull in drug alerts. Precautionary disable recommended.

## Recommended action

### Disable both sources

- `mhra-uk-alerts` — 79.5% pharmaceutical content; 41 legitimate device records lost but all currently classified as `healthcare_adjacent`, not `medical_device`, so zero impact on the Medical devices dashboard view. Historical; current serious device safety is covered by CISA ICS-MA, FDA safety comms, and vendor PSIRTs.
- `fda-medwatch` — mixed RSS feed (drug + device + biologics + food); 5 records currently, all devices but source is fundamentally unsuitable for a device-only corpus. Device content from FDA MedWatch overlaps with `openfda-device-recalls` and `fda-safety-comms-historical`, which are device-specific.

Do **not** modify `healthcare_filter.py` Rule 3 — the rule is correct; the upstream data was wrong.

### Measurable impact

| Metric | Before | After (predicted) | Δ |
| --- | ---: | ---: | --- |
| Total corpus | 3,929 | 3,724 | −205 |
| medical_device bucket | 424 | 422 | −2 |
| Pharmaceutical-titled in corpus | 159 | 0 | −159 |

Medical device bucket drop is small (2 records) because the leakage was smaller than initially estimated. The larger benefit is removing 159 pharmaceutical-titled records from non-MD buckets — they were consuming storage / AI spend / dashboard noise with no user.

### Scope question: mixed-source MHRA

MHRA is a genuinely mixed source — 41 legitimate device alerts are disabled along with 159 medicines recalls. This follows the mission's source-level exclusion principle but does lose some device-only content. A future follow-up could re-enable `mhra-uk-alerts` with a tighter upstream search query (e.g., filter by `alert_type = "medical_device"` in the GOV.UK response) to recover those 41 records. Tracking as a potential post-grant enhancement.

## Decision

**Proceed to Phase 2** with both sources disabled. Under the ≤45 threshold. Rule 3 unchanged. No classifier code modification.
