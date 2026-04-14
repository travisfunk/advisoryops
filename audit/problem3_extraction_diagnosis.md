# Problem 3 residual — Phase 1 diagnosis (2026-04-13)

## TL;DR

- **378 FDA-derived medical_device records have empty `vendor` AND empty `affected_products`.** All 378.
- Deterministic extraction can cover nearly all of them without any new AI spend. Path C (both) strategy.
- Proceeding to Phase 2.

## Method

`scripts/diagnose_problem3.py` + `diagnose_problem3_part2.py` + `diagnose_problem3_part3.py`. Scanned `docs/feed_latest.json` (3,724 issues), filtered to `healthcare_category == "medical_device"` with an FDA source in `sources`.

## Gap analysis

| Metric | Count |
| --- | ---: |
| medical_device bucket (total) | 422 |
| FDA-derived medical_device | 378 |
| vendor empty | 378 |
| affected_products empty | 378 |
| both empty | 378 |
| both populated | 0 |

The gap is complete. Zero FDA-derived MD records have either field populated today.

## Lookup pathways

### Path A — enforcement-cache lookup (200 records, 53%)

200 of the 378 records have a `Z-NNNN-YYYY` recall number embedded in their title (e.g., `Z-0096-2019: GE Healthcare Finland Oy`). Every one of those 200 has a matching enforcement record at `outputs/fda_safety_comms_cache/enf_Z-NNNN-YYYY.json`.

Field population in enforcement records:

| Field | % populated |
| --- | ---: |
| `recalling_firm` | 100% |
| `product_description` | 100% |
| `code_info` | 100% |
| `reason_for_recall` | 100% |

This is the high-confidence path:

- vendor ← `recalling_firm` (verbatim)
- affected_products ← first sentence or first clause of `product_description` (the field starts with the device name and models before diverging into indications-for-use text)

### Path B — title + summary parsing (178 records)

The remaining 178 records all come from `openfda-recalls-historical` and do NOT have a Z-NNNN recall number in their title. They follow a strict title and summary format from the openFDA recall enrichment:

- Title: `<device_type> recall (<vendor>)` — e.g., `Automated External Defibrillators (Non-Wearable) recall (Philips Medical Systems)`
- Summary: `<narrative> | <product/models> | <vendor> | Device: <device_type>` — pipe-delimited tail after the AI-rewritten narrative.

Extraction from title alone hits **176 / 178** for vendor (98.9%). Extraction from the summary pipe-tail hits **174 / 178** for product and **174 / 178** for vendor (97.8%). Combined (vendor from title, product from summary) = **174 / 178** with both fields.

The 4 that miss are either:
- Title has `recall (` but vendor field ends without `)` (truncated),
- Summary has no `| ... | ... | Device:` pipe-tail (narrative-only summary).

### Path C — both (chosen strategy)

1. If recall number is in title → Path A (enforcement cache).
2. Otherwise → Path B (title regex → vendor; summary pipe-parse → product).
3. Fall back to Path B within Path A too: if enforcement `product_description` is awkward to slice into a product_name, the summary pipe-parse gives a cleaner product string.

## Predicted coverage

| Source | Vendor | affected_products |
| --- | ---: | ---: |
| Path A (enforcement cache, 200 records) | 200 / 200 | 200 / 200 |
| Path B (title + summary, 178 records) | 176 / 178 | 174 / 178 |
| **Total (378 records)** | **376 / 378 (99.5%)** | **374 / 378 (99.0%)** |

## Verification target

The mission's named test case:

- `UNK-42c8bda5d1c8ebae` — `Automated External Defibrillators (Non-Wearable) recall (Philips Medical Systems)`
- Summary: `Philips Heartstart MRx Monitor/Defibrillator models M3535A and M3536A may experience a critical delay...`

This record has no Z-NNNN in title (Path B). Title parse → vendor = `Philips Medical Systems`. Summary has no pipe-tail — it's entirely narrative — so product extraction needs a fallback from the narrative. Expected post-extraction:

- `vendor = "Philips Medical Systems"` ✓
- `affected_products` — will include "M3535A" and "M3536A" only if the narrative parser handles model-number extraction. Planning a lightweight model-number regex for narrative-only summaries: match tokens like `M3535A`, `PM1226`, `V1000` (alphanumeric model codes).

## Decision

**Path C deterministic extraction, no new AI spend.** Proceed to Phase 2.

## Non-goals reminder

- Rule 3 of the classifier stays untouched; this mission just fills structured fields the classifier already needed.
- Principle 11 (FDA classification authoritative) unchanged.
- No modifications to score.py, healthcare_filter.py, or community_build.py pipeline ordering.
