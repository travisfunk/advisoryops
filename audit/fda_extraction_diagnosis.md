# FDA risk class extraction — diagnosis (2026-04-12)

Phase 1 investigation into why 328 FDA-derived issues in the corpus have `fda_risk_class=null`.

## Totals

| | FDA-derived issues |
|---|---|
| Populated `fda_risk_class` | 178 |
| Null `fda_risk_class` | **328** |

Null-issue source breakdown:

| Source | Null count | Recoverable? |
|---|---:|---|
| `fda-safety-comms-historical` | 200 | **Yes** — enforcement cache has `classification: "Class I/II/III"` |
| `openfda-device-events` | 100 | **No** — MAUDE adverse-event feed carries no classification field |
| `openfda-recalls-historical` | 22 | **Partial** — some have `product_code`; enforcement cross-ref works for post-2013 recalls only |
| `fda-medwatch` | 5 | **No** — RSS feed with title/summary only |
| `openfda-device-recalls` | 1 | Edge case |

## Root cause

The extraction loop in `community_build.py:1873-1940` only attempts FDA risk-class extraction for issues whose sources include one of `{"openfda-device-recalls", "openfda-recalls-historical"}` — 23 of the 328 null cases. The other 305 null cases (primarily `fda-safety-comms-historical`) are never touched by the extraction loop.

Meanwhile, the enforcement cache at `outputs/fda_safety_comms_cache/enf_<recall_number>.json` contains exactly the data we need — in a different string format:

```json
// enf_Z-0001-2014.json
{
  "classification": "Class II",
  "recall_number": "Z-0001-2014",
  "recalling_firm": "Maquet Cardiovascular, LLC",
  ...
}
```

The issue titles from `fda-safety-comms-historical` follow the pattern `Z-NNNN-YYYY: <Firm Name>`, e.g., `"Z-0096-2019: GE Healthcare Finland Oy"`. The `Z-0096-2019` is the `recall_number` — a direct lookup key into the enforcement cache. Verified by spot-checking `enf_Z-0096-2019.json` exists and contains `classification: "Class II"`.

## Evidence — sample null issues with recoverable classifications

| issue_id | title | source | enforcement cache hit? | classification |
|---|---|---|---|---|
| UNK-18b8644018a3c194 | Z-0096-2019: GE Healthcare Finland Oy | fda-safety-comms-historical | yes | Class II |
| UNK-fb612c607170b248 | Z-0095-2019: GE Healthcare Finland Oy | fda-safety-comms-historical | yes | Class II |

## Evidence — null issues where data is genuinely absent

| issue_id | title | source | why unrecoverable |
|---|---|---|---|
| UNK-001ca7ea06434879 | 2919069-2008-00381 | openfda-device-events | MAUDE report; source payload is `{source, guid, title, summary="Malfunction"}` only. No classification field anywhere in the upstream record. |
| UNK-d5e608afbe914697 | Infusion Pump Software Correction: Fresenius Kabi... | fda-medwatch | RSS item with link only; no structured class in source |

## Recommended fix scope

Phase 2 should add two additional extraction paths. Both are additive; the existing `extract_risk_class_from_recall` stays unchanged.

1. **New helper `extract_risk_class_from_enforcement(record)`** in `fda_classification.py`. Parses the `classification` string (`"Class I"`, `"Class II"`, `"Class III"`) into the canonical `"1"` / `"2"` / `"3"` string. This mirrors `extract_risk_class_from_recall` but for enforcement records.

2. **Helper `lookup_class_by_recall_number(recall_number, cache_dir)`** that reads the enforcement cache file for a given recall number. Wraps file I/O + extraction.

3. **In `scripts/retag_corpus.py`**: before `_rescore_fda_floor`, add a pass that for each FDA-derived issue with null `fda_risk_class`, tries:
   - parse `Z-NNNN-YYYY` recall_number from the title,
   - call `lookup_class_by_recall_number` against `outputs/fda_safety_comms_cache/`,
   - if hit, set `fda_risk_class`.

This recovers the 200 fda-safety-comms-historical nulls plus any openfda-recalls-historical whose `product_res_number` is in the enforcement cache. The 100 device-events + 5 medwatch nulls remain null — source data genuinely lacks the field; would require external lookup or AI inference (out of scope).

## Target success criteria (revised based on Phase 1)

- Null fda_risk_class in FDA-derived issues: 328 → ~105 (68% reduction; the remaining ~105 are from sources whose upstream data genuinely lacks classification).
- medical_device P0 count: 8 → ~20-40 (after floor runs on newly-class-III-tagged issues).
- No changes to FDA floor logic, classifier rules, or thresholds.
