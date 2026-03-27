# AdvisoryOps — Release Notes

## Pass 1 Public Dataset (2026-03-22)

### Summary

| Metric | Value |
|--------|-------|
| Release date | 2026-03-25 |
| Validated sources | 58 |
| Issues (public feed) | 545 |
| Alerts (P0–P2, public feed) | 487 |
| Remediation packets | 686 |
| Automated tests | 601 |
| Pass rate (golden fixtures) | 14/14 (100%) |

### Sources

12 validated public sources across four categories:

- **CISA KEV** — CISA Known Exploited Vulnerabilities catalog
- **CISA ICS-Medical (ICSMA)** — ICS medical device advisories
- **NVD** — NIST National Vulnerability Database CVE feed
- **Vendor / community** — Siemens ProductCERT, Schneider Electric, ICS-CERT, Claroty, Dragos, Medigate, Nozomi

All sources validated with smoke tests in `tests/fixtures/golden/` (12 golden fixtures, 100% correlation and CVE coverage accuracy).

### Pipeline

The full deterministic pipeline is:

```
source-run → correlate → score (v2, healthcare-aware) → tag → community-build
```

Key stages:

1. **Discover** — fetch item lists from each source RSS/API
2. **Ingest** — normalize raw HTML/PDF/text to snapshot
3. **Extract** — LLM-assisted structured `AdvisoryRecord` extraction
4. **Correlate** — deterministic CVE-key deduplication across sources
5. **Score v2** — healthcare-aware priority scoring (P0–P3) with `why` explanations
6. **Tag** — keyword + healthcare/ICS taxonomy tags
7. **Recommend** — AI pattern selection from 8 playbook patterns (cached)
8. **Community build** — assembles public feed artifacts

### Scoring

Priority tiers (v2 scorer):

| Priority | Threshold | Criteria |
|----------|-----------|----------|
| P0 | score ≥ 150 | KEV + RCE + healthcare stacked, or multiple critical signals |
| P1 | score 100–149 | KEV source, or strong healthcare context (ICSMA + device) |
| P2 | score 60–99 | Moderate concern (significant keywords or healthcare context) |
| P3 | score < 60 | Low-signal / informational |

### Remediation Playbook

8 approved mitigation patterns:

- `PATCH_MANAGEMENT_EXPEDITED` — expedited patch deployment
- `SEGMENTATION_VLAN_ISOLATION` — VLAN-based network isolation
- `ACCESS_CONTROL_ACL_ALLOWLIST` — ACL allowlist restriction
- `MONITORING_ANOMALY_DETECTION` — anomaly detection + alerting
- `COMPENSATING_CONTROL_DISABLE_FEATURE` — disable vulnerable feature
- `VENDOR_COORDINATION_PATCH_REQUEST` — vendor patch coordination
- `MFA_PRIVILEGED_ACCESS` — MFA for privileged access
- `INCIDENT_RESPONSE_ACTIVATION` — IR plan activation

### Test Coverage

601 automated tests across 35 test modules covering:

- Source discovery and ingestion
- Advisory record extraction
- CVE correlation
- Healthcare-aware scoring (v2)
- Issue tagging
- Playbook loading
- Pattern recommendation (with AI cache)
- Remediation packet export (JSON, Markdown, CSV)
- Golden fixture evaluation harness (12 fixtures)
- Community build pipeline

### Known Limitations

- fixture-07 (hospital-manager advisory) is classified as `medical_device` by the deterministic heuristic due to CISA ICS-Medical source authority, but the expected category is `healthcare_it`. This ambiguity is a known limitation of the deterministic classifier.
- AI-assisted extraction (`extract`) and recommendation (`recommend`) require `OPENAI_API_KEY`. All other pipeline stages are fully deterministic.
- Source discovery is rate-limited; `--limit` flags prevent runaway API spend.
