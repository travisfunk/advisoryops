# AdvisoryOps — Release Notes

## v1.0 — Initial Public Release (April 2026)

### Summary

| Metric | Value |
|--------|-------|
| Release date | 2026-04-06 |
| Validated sources | 57 |
| Issues (public feed) | 1,990 |
| Healthcare-relevant issues | 234 |
| Alerts (P0-P2) | 757 |
| Remediation packets | 1,990 (all issues) |
| NVD-enriched issues | 1,138 |
| KEV required actions | 203 |
| Automated tests | 696 |
| Golden fixture pass rate | 14/14 (100%) |
| Full corpus rebuild cost | ~$1.40 |
| Total API cost (all builds) | ~$12.70 |

### What's new in this release

- **Healthcare relevance filter** — separates 234 medical device issues from 1,756 general IT vulnerabilities
- **NVD enrichment** — automated CVSS, CWE, and CPE lookup for 1,138 CVEs
- **KEV cross-reference** — 203 issues now carry CISA's required action and due date
- **Human-readable remediation steps** on all 1,990 issues
- **GitHub Pages dashboard** at https://travisfunk.github.io/advisoryops-dashboard/
- **57 sources** expanded from the original 12 gold sources

### Sources

57 enabled sources across 5 authority tiers. Highlights include CISA ICS-Medical, CISA KEV, FDA MedWatch, openFDA Device Recalls, NVD CVE API, CERT/CC, Health Canada, plus 30+ vendor PSIRTs and threat intelligence feeds. See `validated_sources.json` for the complete list.

### Pipeline

The full pipeline is:

```
Discover → Correlate → NVD Enrich → Tag/Score → Healthcare Filter → Recommend
```

Key stages:

1. **Discover** — fetch item lists from each source RSS/API
2. **Correlate** — deterministic CVE-key deduplication across sources
3. **NVD Enrich** — CVSS score, CWE IDs, CPE matches, and NVD description via NIST API
4. **Tag / Score** — healthcare-aware priority scoring (P0-P3) with keyword and ICS taxonomy tags
5. **Healthcare Filter** — classify issues as medical-device-relevant or general IT
6. **Recommend** — AI pattern selection from 8 playbook patterns with human-readable remediation steps

### Scoring

Priority tiers (v2 scorer):

| Priority | Threshold | Criteria |
|----------|-----------|----------|
| P0 | score >= 150 | KEV + RCE + healthcare stacked, or multiple critical signals |
| P1 | score 100-149 | KEV source, or strong healthcare context (ICSMA + device) |
| P2 | score 60-99 | Moderate concern (significant keywords or healthcare context) |
| P3 | score < 60 | Low-signal / informational |

Healthcare-aware factors boost scores for issues affecting medical devices, clinical infrastructure, and patient safety systems.

### Known limitations

- Some Apple NVD descriptions are vague ("The issue was addressed with improved memory handling") — that's Apple's style, not our pipeline
- FDA recall IDs lack human-readable descriptions and display as "FDA Device Recall: &lt;ID&gt;"
- Incremental builds are not yet supported — each run reprocesses the full corpus (~5 minutes, $1.40)
- Single maintainer; see CONTRIBUTING.md for ways to help

### Acknowledgments

Built on public data from CISA, NIST NVD, FDA, Health Canada, and the broader vulnerability disclosure community.
