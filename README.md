# AdvisoryOps

![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)
![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)
![Tests: 1165 passing](https://img.shields.io/badge/tests-1165_passing-brightgreen.svg)
[![Dashboard](https://img.shields.io/badge/dashboard-GitHub_Pages-blue.svg)](https://travisfunk.github.io/advisoryops/)

**Open-source healthcare medical device security intelligence pipeline.**
AdvisoryOps has 64 enabled public source configurations — CISA ICS-Medical, the Known Exploited Vulnerabilities catalog, FDA device recalls, NVD, CERT/CC, vendor PSIRTs, and more — and produces a prioritized, healthcare-aware feed of medical device vulnerabilities. Built for hospital security teams that can't afford commercial platforms like Claroty or TRIMEDX.


---

## What makes this different

1. **Healthcare-focused by design.** The default view is medical device issues, not general IT vulnerabilities. Scoring uses five healthcare-specific dimensions (source authority, device context, patch feasibility, clinical impact, FDA risk class). An FDA Class III cardiac device with no patch available gets a higher priority than a WordPress plugin bug with a patch — that's the point.

2. **Fully open stack.** The data sources are public, the analysis pipeline is open source, the feed outputs are free to consume, and the dashboard is a static HTML file served from GitHub Pages. Most alternatives lock the data, the analysis, or the delivery behind enterprise pricing. AdvisoryOps is Apache 2.0 and free forever.

3. **AI-assisted remediation guidance.** Optional recommendation generation selects from an 11-pattern approved mitigation playbook (VLAN isolation, ACL allowlisting, vendor case tracking, credential hardening, etc.), assigns tasks by role (infosec, netops, HTM/CE, vendor, clinical ops), and cites the underlying standards (NIST SP 800-82, IEC 62443, FDA guidance). Unknown pattern IDs are filtered. Packet generation is not guaranteed for every high-priority issue; the current build's packet count is recorded below.

---

## Why it exists

Medical device vulnerabilities are chronically under-tracked. Most vulnerability tools treat a pacemaker firmware advisory the same as a WordPress plugin bug. Infusion pumps, ventilators, patient monitors, and imaging systems have unique risk profiles — they sit on clinical networks, they can't always be patched on schedule, and when they fail the consequences are measured in patient safety, not just downtime.

Small and rural hospitals face the same threats as large health systems but with a fraction of the security staff and budget. Commercial medical device security platforms start at six figures per year. Meanwhile, the raw data — CISA advisories, FDA recalls, NVD records, KEV deadlines — is all public. What's missing is the pipeline to pull it together, score it for healthcare relevance, and present it in a way that a two-person security team can act on.

AdvisoryOps closes that gap. The data is free, the analysis is free, the dashboard is free. Apache 2.0 forever.

---

## Key finding: zero exact structured CVE-ID overlap in the current corpus

The full-corpus verifier compares every record classified as `medical_device` in the canonical archive with the **full CISA Known Exploited Vulnerabilities catalog**. In the production snapshot generated **2026-09-23 at 11:10 UTC**, 463 medical-device records contain 72 unique structured CVE IDs; none intersect the 1,721 unique CVEs in the full KEV catalog.

The previously reported **203 KEV-enriched issues** were a historical subset of AdvisoryOps issues carrying KEV fields, **not the full CISA KEV catalog**. The current enriched subset is 370 issues. It is not the input for the authoritative comparison.

Vendor checks are diagnostic only: the current report has zero normalized exact vendor matches and two partial substring pairs (Siemens Medical Solutions USA / Siemens and Sunquest Information Systems / Quest). Neither establishes that a medical-device CVE is in KEV. Only an exact structured CVE-ID match supports the strict overlap flag.

This finding is bounded by this corpus, its classification and structured identifiers, and the catalog snapshot. It does not establish that KEV has no medical-device coverage universally, that exploitation never occurs, or why a vulnerability is absent. Records without structured CVEs cannot contribute to the CVE intersection. AdvisoryOps combines specialized medical-device advisory and recall sources with KEV cross-references for that reason.

See [methodology and full-corpus reproduction](docs/kev_medical_device_analysis.md) and the [generated report](docs/kev_full_catalog_overlap.json).

---

## Live demo

**Dashboard:** [https://travisfunk.github.io/advisoryops/](https://travisfunk.github.io/advisoryops/)

The "Medical devices" view loads the complete medical-device subset (463 records in the dated snapshot below) with CVSS scores, EPSS exploit probabilities, KEV deadlines, FDA risk class badges, and AI-generated remediation guidance with role-split task assignments. Color-coded priority badges (P0-P3), click-to-expand detail panels, and a debounced search bar filtering by title, CVE, vendor, and product. No framework, no build step — single-file vanilla HTML/JS.

The dashboard also exposes two reviewer-facing transparency views: a **Sources** tab ranking published sources by medical-device-signal contribution, and a **Methodology** tab with live self-check counts refreshed from `meta.json` on every build (FDA coverage, vendor extraction coverage, strict KEV overlap, pharmaceutical-leak guard; test counts appear only when supplied) plus the exact commands any reviewer can run to reproduce each number. There's also a "This week" toggle on the Issues tab that filters to advisories from the last 7 days with a priority summary banner, for the operational "what changed this week" use case.

---

## Current scope

Snapshot: **2026-09-23, 11:10 UTC**, from [meta.json](docs/meta.json), [KEV report](docs/kev_full_catalog_overlap.json), and [source configuration](configs/sources.json). These are dated measurements; generated metadata is authoritative for later builds.

| Metric | Value |
|--------|-------|
| Enabled source configurations | 64 |
| Scheduled `gold_pass2` source IDs / candidate sources | 54 / 1 |
| Canonical issues in 32 archive shards | 10,880 |
| General dashboard serving window | 750 |
| Medical-device records (complete subset) | 463 |
| Medical-device unique structured CVEs | 72 |
| Canonical issues with nonempty `nvd_description` | 7,466 |
| KEV-enriched corpus issues | 370 |
| Full CISA KEV records / unique CVEs | 1,721 / 1,721 |
| Exact structured CVE-ID overlap | 0 |
| Vendor exact / partial pairs (diagnostic only) | 0 / 2 |
| Recommendation packets generated in this build | 0 |

Enabled configuration count is not a claim that every source yielded records in the scheduled run. The schedule uses `gold_pass2`, not the broader `full_public` set. NVD-description coverage is counted from the reconstructed canonical archive; it is not inferred from the bounded serving feed. Build cost and cumulative AI packet totals are not published current metrics.

### Repository structure

The production dashboard lives at `dashboard/index.html` in this repo. The pipeline's `community-build` command copies it to `docs/index.html` along with the generated data files so GitHub Pages can serve it. The canonical history lives in `docs/feed_archive/`; `docs/feed_latest.json` is a bounded serving projection. See [publication architecture](docs/publication.md) for the complete scheduled sequence and recovery steps.

---

## Quickstart

### Install

```bash
git clone https://github.com/travisfunk/advisoryops
cd advisoryops
pip install -e .
```

### Build the broader public source set locally

```bash
advisoryops community-build --set-id full_public --out-root-community outputs/community_public
```
This builder command alone is not the complete production publication sequence; the [scheduled workflow](.github/workflows/update-feed.yml) also reconstructs history, reconciles strict KEV flags, verifies the full catalog, and publishes archive shards.

Outputs: `issues_public.jsonl` · `alerts_public.jsonl` · `feed_latest.json` · `feed_healthcare.json` · `feed.csv` · `feed.xml` · `issues_public.xlsx` · `meta.json`
### Run individual pipeline stages

```bash
# Discover items from a specific source
advisoryops discover --source cisa-icsma --limit 20

# Correlate discovered signals into deduplicated issues
advisoryops correlate --out-root-discover outputs/discover --out-root-correlate outputs/correlate

# Score issues with healthcare-aware priority engine
advisoryops score --in-issues outputs/correlate/issues.jsonl --min-priority P1

# Generate a remediation packet (JSON, Markdown, or CSV) for one issue
advisoryops recommend --issue-id CVE-2024-1234 --format md --out outputs/packets

# Optional: AI-assisted deduplication (OPENAI_API_KEY required)
advisoryops correlate --ai-merge

# Optional: AI healthcare classifier for ambiguous issues
advisoryops score --ai-score

# Run golden fixture evaluation suite
advisoryops evaluate --fixtures tests/fixtures/golden --out outputs/eval
```

---

## Pipeline architecture
```mermaid
flowchart TD
    A[Configured Public Sources<br/>CISA · FDA · NVD · Vendor PSIRTs · Threat Intel] --> B[Discover<br/>Fetch & normalize feeds]
    B --> C[Correlate<br/>Dedupe by CVE / signal hash]
    C --> D[NVD Enrich<br/>CVSS · CWE · CPE · KEV]
    D --> E[Score<br/>Healthcare-aware priority P0-P3]
    E --> F[Healthcare Filter<br/>Tag medical device relevance]
    F --> G[Recommend<br/>Remediation steps from playbook]
    G --> H[Public Outputs<br/>JSON · CSV · XML · Excel · Dashboard]
    
    style A fill:#1e3a5f,stroke:#3b82f6,color:#fff
    style D fill:#1c1207,stroke:#92400e,color:#fcd34d
    style F fill:#0d3d3d,stroke:#5eead4,color:#5eead4
    style H fill:#0a1629,stroke:#3b82f6,color:#fff
```
```
┌─────────────────────────────────────────────────────────────────┐
│  DATA SOURCES (see configs/sources.json)                         │
│  CISA ICS-Medical · CISA KEV · FDA Recalls · CERT/CC · NVD     │
│  MS MSRC · Siemens · Philips · ABB · ZDI · more                │
└─────────────────────┬───────────────────────────────────────────┘
                      │ RSS/Atom · JSON feeds · CSV feeds
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│  1. DISCOVER  (discover.py + feed_parsers.py)                   │
│  HTTP fetch with retry/backoff → parse → keyword filter         │
│  Track seen GUIDs in state.json for new-item detection          │
│  Normalize all formats into a common signal shape               │
│  Output: outputs/discover/<source>/items.jsonl                  │
└─────────────────────┬───────────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│  2. CORRELATE  (correlate.py + ai_correlate.py)                 │
│  Pass 1 (deterministic): group by CVE ID or title+date hash    │
│  Pass 2 (optional AI): Jaccard similarity + GPT-4o-mini merge  │
│  Output: outputs/correlate/issues.jsonl                         │
└─────────────────────┬───────────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│  3. NVD ENRICH  (nvd_enrich.py)                                 │
│  CVE → CVSS base score, vector, CWE, affected products (CPE)   │
│  KEV cross-reference → required action, due date, ransomware    │
│  Coverage measured from the full canonical archive              │
│  Output: NVD fields merged into issues.jsonl                    │
└─────────────────────┬───────────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│  4. TAG + SCORE  (tag.py + score.py + ai_score.py)              │
│  Keyword heuristics: exploit, impact, RCE, KEV, ransomware     │
│  Healthcare scoring dimensions:                                 │
│    Source authority · Device context · Patch feasibility         │
│    Clinical impact (patient safety, ICU, PHI)                   │
│  Priority: P0 ≥ 150 · P1 ≥ 100 · P2 ≥ 60 · P3 < 60           │
│  Output: outputs/scored/issues_scored.jsonl + alerts.jsonl      │
└─────────────────────┬───────────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│  5. HEALTHCARE FILTER  (healthcare_filter.py)                   │
│  Tags issues as healthcare-relevant using device keywords,      │
│  ICS-Medical source, FDA recalls, clinical context signals      │
│  Complete medical_device subset retained for the dashboard      │
│  Output: feed_healthcare.json                                   │
└─────────────────────┬───────────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│  6. RECOMMEND  (recommend.py + playbook.py + packet_export.py)  │
│  AI selects from approved mitigation playbook patterns          │
│  Role-split tasks: infosec / netops / htm_ce / vendor / clinical│
│  Exports: JSON packet · Markdown report · CSV for ticket import │
│  Output: outputs/packets/<issue>_packet.{json,md,csv}           │
└─────────────────────────────────────────────────────────────────┘
```

### Key design choices

| Choice | Rationale |
|--------|-----------|
| **Feeds only, no scraping** | RSS/JSON/CSV feeds are reliable, legal, and don't break on DOM changes |
| **Deterministic first, AI second** | Group by CVE ID before calling any AI — keeps cost near zero for routine runs |
| **NVD enrichment + KEV cross-ref** | CVSS scores, CWE IDs, and KEV deadlines added automatically for every CVE |
| **Healthcare relevance filter** | Separates medical device issues from general IT vulnerabilities |
| **Playbook-constrained recommendations** | AI selects from an approved pattern list; hallucinated IDs are silently dropped |
| **On-disk AI response cache** | SHA-256 keyed; same issue never costs twice across runs |
| **JSONL everywhere** | Line-delimited JSON is git-diffable, stream-processable, and appendable |

---

## Source coverage

**64 enabled source configurations across 4 scopes (2026-09-23)** (see `configs/sources.json` for the authoritative, up-to-date list)

| Scope | Count | Examples |
|----------|-------|---------|
| advisory | 16 | CISA ICS-Medical, CISA ICS, CERT/CC, Health Canada recalls, ABB PSIRT, ZDI Published / Upcoming, Philips PSIRT, Siemens ProductCERT |
| dataset | 12 | CISA KEV (JSON + CSV), NVD CVE API, openFDA device recalls, openFDA device events, EPSS API, Tenable plugins, CWE catalog, MITRE ATT&CK ICS, CISA Vulnrichment |
| news | 27 | CISA Cybersecurity Advisories, CyberScoop Healthcare, Fortified Health Security, HIPAA Guide Cyber, MedTech Intelligence, Microsoft MSRC, NCSC UK, Krebs on Security, Dark Reading |
| threatintel | 9 | Cisco Talos, Google/Mandiant, Check Point Research, CrowdStrike, Abuse.ch URLhaus, Abuse.ch Feodo Tracker, Abuse.ch SSL Blacklist, SANS ISC Blocklist IPs, Binary Defense Banlist |

Pharmaceutical sources (`fda-medwatch`, `mhra-uk-alerts`) are explicitly disabled — medicines recalls belong to pharmacy workflows, not medical device security.

For a live ranked breakdown of which sources actually produce medical device signal (with cumulative coverage so the curation quality is measurable, not asserted), see the **Sources** tab on the [live dashboard](https://travisfunk.github.io/advisoryops/#sources).

To add a new source, add a record to `configs/sources.json` (page_type must be `rss_atom`, `json_feed`, or `csv_feed`) and run:

```bash
python scripts/smoke_test_all_sources.py
```

---

## Running tests

Fresh full run on **2026-09-23**, Python 3.11: `python -m pytest -o addopts= -q -rs` — **1,165 passed, 1 skipped**, including the live integration test. The skip is the contract check for an absent local pipeline output; the same assertion was separately verified against the complete published `docs/feed_healthcare.json`. Node.js is needed to execute the dashboard JavaScript behavior tests.

```bash
# Full suite — no API key required (all AI calls use injectable mocks)
python -m pytest            # configured suite (excludes live integration)

# Specific modules
python -m pytest tests/test_score_healthcare.py -v
python -m pytest tests/test_healthcare_filter.py -v
python -m pytest tests/test_nvd_enrich.py -v
python -m pytest tests/test_community_build.py -v
```

---

## Trust & provenance

Every AI-generated output carries an evidence trail:

- **Remediation recommendations** cite the specific advisory evidence that triggered each pattern selection, reference the standard behind the pattern (NIST SP 800-82, IEC 62443, FDA pre/postmarket guidance, CISA ICS-CERT best practices), and include a disclaimer requiring verification against vendor documentation before implementation.
- **Cross-source contradiction detection** compares severity, CVE lists, and patch status across contributing sources, surfacing where sources agree and diverge.
- **NVD enrichment** adds authoritative CVSS scores, CWE IDs, and KEV required actions with due dates — drawn directly from NIST and CISA data.
- A `generated_by` label on every output (`ai`, `deterministic`, or `hybrid`) makes clear what was extracted from source text versus inferred by a model.

> **Important:** The AI extracts, normalizes, compares, and recommends from approved mitigation patterns. It does not replace vendor guidance or make final operational decisions. All recommendations must be verified against vendor documentation and validated by qualified personnel before implementation in clinical environments.

---

## Documentation

- **[Architecture diagram](docs/architecture.md)** — data flow from configured sources through ingestion, correlation, enrichment, AI processing, and out to consumers
- **[Scoring internals](docs/scoring_internals.md)** — how the v2 healthcare-aware scoring works (5 dimensions, score ranges, priority thresholds)
- **[Feed schema](docs/schema.md)** — every field in the feed output with types and descriptions
- **[Feed contract](docs/feed_contract.json)** — schema contract between the pipeline and the dashboard, enforced by tests
- **[Playbook governance](docs/playbook_governance.md)** — how mitigation patterns are reviewed, approved, and cited
- **[KEV analysis](docs/kev_medical_device_analysis.md)** — exact structured CVE-ID comparison against the full KEV catalog, with scope and limitations

---

## Contributing

1. **Fork** the repo and create a feature branch (`git checkout -b feat/my-source`)
2. **Write tests first** — every new function needs at least one pytest test
3. **Feeds only** — new sources must use `rss_atom`, `json_feed`, or `csv_feed` page_type
4. **Run the full suite** before opening a PR: `python -m pytest -q`
5. **For new sources**: add to `configs/sources.json`, smoke-test, document in your PR

For bugs, open a GitHub issue with: steps to reproduce, Python version, and the relevant `outputs/*/meta.json` if applicable.

---

## License

Copyright 2026 Travis Funk and contributors.
Licensed under the **Apache License, Version 2.0** — see [LICENSE](LICENSE) for the full text.

Data sourced from CISA, FDA, NVD/NIST, and other US government publications is in the public domain and not subject to copyright.
