# AdvisoryOps

![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)
![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)

**Open-source healthcare cybersecurity intelligence pipeline.**
AdvisoryOps continuously monitors 58 live public sources — CISA ICS-Medical, the Known Exploited Vulnerabilities catalog, FDA device recalls, CERT/CC, NVD, and more — and produces a prioritized, healthcare-aware alert feed your team can act on.

> **Why it matters:** Medical device vulnerabilities are chronically under-tracked. Most SIEM tools treat a pacemaker firmware advisory the same as a WordPress plugin bug. AdvisoryOps understands the difference and scores accordingly.

---

## Quickstart

### Install

```bash
git clone https://github.com/travisfunk/advisoryops
cd advisoryops
pip install -e .
```

### Run the full community pipeline (one command)

```bash
advisoryops community-build --set-id gold_pass1 --out-root-community outputs/community_public
# Writes: issues_public.jsonl · alerts_public.jsonl · feed_latest.json · feed.csv · meta.json · dashboard.html
```

### View the dashboard

```bash
cd outputs/community_public
python -m http.server 8080
# Open: http://localhost:8080/dashboard.html
```

The dashboard is a single-file vanilla HTML/JS app — sortable issue table, color-coded priority badges, click-to-expand rows with CVE links, search/filter bar. No framework, no build step.

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

## Pipeline Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        DATA SOURCES (58 live)                   │
│  CISA ICS-Medical · CISA KEV · FDA Recalls · CERT/CC · NVD     │
│  MS MSRC · Cisco · Siemens · Philips · GitHub Security · more  │
└─────────────────────┬───────────────────────────────────────────┘
                      │ RSS/Atom · JSON feeds · CSV feeds
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│  1. DISCOVER  (discover.py + feed_parsers.py)                   │
│  HTTP fetch with retry/backoff → parse → keyword filter         │
│  Track seen GUIDs in state.json for new-item detection          │
│  Normalize all formats into a common signal shape:              │
│    source · guid · title · summary · published_date · link      │
│  Output: outputs/discover/<source>/items.jsonl                  │
└─────────────────────┬───────────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│  2. CORRELATE  (correlate.py + ai_correlate.py)                 │
│  Pass 1 (deterministic): group by CVE ID or SHA-256 of          │
│    normalized title + date → stable UNK-<hex> for non-CVEs     │
│  Pass 2 (optional AI): Jaccard similarity pre-filter then       │
│    GPT-4o-mini decides whether two issues are the same vuln     │
│    Union-Find builds transitive merge groups                     │
│    Writes merge_log.jsonl for audit/reproducibility             │
│  Output: outputs/correlate/issues.jsonl                         │
└─────────────────────┬───────────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│  3. TAG  (tag.py)                                               │
│  Deterministic keyword heuristics — no AI                       │
│    exploit: kev, active_exploitation, poc, ransomware           │
│    impact:  rce, priv_esc, auth_bypass, data_exfil             │
│  Output: outputs/tags/tags.jsonl                                │
└─────────────────────┬───────────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│  4. SCORE  (score.py + ai_score.py)                             │
│  v1 baseline: keyword regex scoring                             │
│    RCE +30 · KEV source +80 · actively exploited +40 · …       │
│  v2 healthcare dimensions (added on top of v1):                 │
│    Source authority: CISA ICS-Medical +20 · ICS +15            │
│    Device context:   infusion pump +25 · ventilator +25 · …    │
│    Patch feasibility: no patch +20 · EOL +15 · firmware +10    │
│    Clinical impact:  patient safety +25 · ICU +20 · PHI +15    │
│  Optional AI: --ai-score classifies ambiguous issues via GPT    │
│  Priority: P0 ≥ 150 · P1 ≥ 100 · P2 ≥ 60 · P3 < 60           │
│  Output: outputs/scored/issues_scored.jsonl + alerts.jsonl      │
└─────────────────────┬───────────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│  5. RECOMMEND  (recommend.py + playbook.py + packet_export.py)  │
│  AI selects 1-4 patterns from the approved mitigation playbook  │
│  (SEGMENTATION_VLAN_ISOLATION, ACCESS_CONTROL_ACL_ALLOWLIST,   │
│   VENDOR_PROCESS_OPEN_CASE_AND_TRACK, PATCHING_APPLY_VENDOR…)  │
│  Role-split tasks: infosec / netops / htm_ce / vendor / clinical│
│  Exports: JSON packet · Markdown report · CSV for ticket import │
│  Output: outputs/packets/<issue>_packet.{json,md,csv}           │
└─────────────────────┬───────────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│  6. COMMUNITY BUILD  (community_build.py)                       │
│  Orchestrates Discover → Correlate → Score → (Recommend)        │
│  for the validated gold source set and publishes:               │
│    issues_public.jsonl  · alerts_public.jsonl                   │
│    feed_latest.json     · feed.csv                              │
│    validated_sources.json · meta.json · dashboard.html          │
└─────────────────────────────────────────────────────────────────┘
```

### Key design choices

| Choice | Rationale |
|--------|-----------|
| **Feeds only, no scraping** | RSS/JSON/CSV feeds are reliable, legal, and don't break on DOM changes |
| **Deterministic first pass** | Group by CVE ID before calling any AI — keeps cost near zero for routine runs |
| **AI as a second pass only** | AI merge and AI score only run when deterministic scoring leaves uncertainty |
| **Playbook-constrained recommendations** | AI selects from an approved pattern list; hallucinated IDs are silently dropped |
| **On-disk AI response cache** | SHA-256 keyed; same issue never costs twice across runs |
| **JSONL everywhere** | Line-delimited JSON is git-diffable, stream-processable, and appendable |

---

## Source Coverage

**85 configured · 58 live (enabled=true) · 10 validated in gold_pass1 set**

| Category | Count | Examples |
|----------|-------|---------|
| CISA / US-CERT | 8 | ICS-Medical, ICS advisories, KEV (JSON + CSV), AA alerts, CERT/CC |
| FDA | 3 | MAUDE device events, device recalls, MedWatch |
| NVD / NIST | 2 | NVD recent CVEs, NVD modified CVEs feed |
| Vendor PSIRTs | 10 | Microsoft MSRC, Cisco PSIRT, Siemens ProductCERT, Philips, BD, Medtronic, Abbott |
| Threat Intelligence | 8 | AlienVault OTX, GitHub Security Advisories, EPSS, abuse.ch |
| Security News | 14 | Krebs on Security, BleepingComputer, Dark Reading, SANS ISC, SecurityWeek |
| Healthcare Orgs | 6 | H-ISAC, HHS 405(d), AHA, HSCC, FDA Safety Communications |

To add a new source, add a record to `configs/sources.json` (page_type must be `rss_atom`, `json_feed`, or `csv_feed`) and run:

```bash
python scripts/smoke_test_all_sources.py
```

---

## Project Layout

```
advisoryops/
├── src/advisoryops/           # Python package (pip install -e .)
│   ├── cli.py                 # argparse entry point — all CLI subcommands
│   ├── discover.py            # HTTP fetch + RSS/Atom/JSON/CSV parsing
│   ├── feed_parsers.py        # JSON feed + CSV feed normalizers
│   ├── source_run.py          # discover → optional ingest orchestrator
│   ├── ingest.py              # URL / text file / PDF → normalized snapshot
│   ├── extract.py             # AI extraction → AdvisoryRecord JSON
│   ├── correlate.py           # signal grouping → issues (+ AI merge pass)
│   ├── ai_correlate.py        # similarity pre-filter + AI merge decisions
│   ├── tag.py                 # exploit / impact keyword tagger
│   ├── score.py               # v1 keyword + v2 healthcare scorer
│   ├── ai_score.py            # AI healthcare relevance classifier
│   ├── recommend.py           # AI pattern selection engine
│   ├── playbook.py            # mitigation playbook loader + dataclasses
│   ├── packet_export.py       # JSON / Markdown / CSV packet formatters
│   ├── community_build.py     # end-to-end community feed builder
│   ├── community_manifest.py  # community source set manifest loader
│   ├── eval_harness.py        # golden fixture evaluation harness
│   ├── ai_cache.py            # on-disk SHA-256 keyed AI response cache
│   ├── models.py              # Pydantic AdvisoryRecord schema
│   ├── contradiction_detector.py  # cross-source contradiction detection
│   ├── change_tracker.py      # what-changed tracking between runs
│   ├── feedback.py            # recommendation feedback recorder
│   ├── source_weights.py      # source authority tier weights
│   ├── product_resolver.py    # product name/nickname lookup
│   ├── advisory_qa.py         # natural language advisory Q&A
│   ├── sources_config.py      # sources.json loader + SourceDef dataclasses
│   ├── mojibake.py            # UTF-8/cp1252 encoding artifact repair
│   └── util.py                # shared utilities (hashing, file I/O)
├── configs/
│   ├── sources.json                    # 85 source definitions (schema v1)
│   ├── community_public_sources.json   # validated gold source sets
│   ├── mitigation_playbook.json        # approved mitigation patterns
│   └── source_weights.json            # source authority tiers + weights
├── tests/                     # pytest suite (601 tests, all mocked — no API key needed)
├── scripts/
│   ├── smoke_test_all_sources.py       # batch connectivity + parse test
│   └── build_golden_fixtures.py        # golden fixture generator
└── outputs/                   # gitignored; created at runtime
    ├── discover/              # per-source raw + parsed artifacts
    ├── correlate/             # correlated issues.jsonl
    ├── scored/                # prioritized alerts
    ├── community_public/      # published feed + dashboard
    └── ai_cache/              # cached AI responses (skip re-billing)
```

---

## Running Tests

```bash
# Full suite — no API key required (all AI calls use injectable mocks)
python -m pytest

# Verbose output for a specific module
python -m pytest tests/test_score_healthcare.py -v
python -m pytest tests/test_ai_correlate.py -v
python -m pytest tests/test_community_build.py -v

# Quick smoke check
python -m pytest -q
```

---

## Trust & Provenance

Every AI-generated output in AdvisoryOps carries an evidence trail. Remediation recommendations cite the specific advisory evidence that triggered each pattern selection (rationale), reference the standard or guidance behind the pattern (basis — NIST SP 800-82, IEC 62443, FDA pre/postmarket guidance, CISA ICS-CERT best practices), and include a disclaimer requiring verification against vendor documentation before implementation. Cross-source contradiction detection compares severity, CVE lists, and patch status across contributing sources, surfacing agreements and disagreements so analysts see where sources diverge. A `generated_by` label on every output (`ai`, `deterministic`, or `hybrid`) makes clear what was extracted from source text versus inferred by a model. Analysts can flag recommendations directly from the dashboard or CLI (`advisoryops feedback --issue-id X --type incorrect --comment "..."`), creating an audit trail for continuous improvement.

> **Important:** The AI extracts, normalizes, compares, and recommends from approved mitigation patterns. It does not replace vendor guidance or make final operational decisions. All recommendations must be verified against vendor documentation and validated by qualified personnel before implementation in clinical environments.

---

## Contributing

1. **Fork** the repo and create a feature branch (`git checkout -b feat/my-source`)
2. **Write tests** first — every new function needs at least one pytest test
3. **Feeds only** — new sources must use `rss_atom`, `json_feed`, or `csv_feed` page_type
4. **Run the full suite** before opening a PR: `python -m pytest -q`
5. **For new sources**: add to `configs/sources.json`, smoke-test, document in your PR

For bugs, open a GitHub issue with: steps to reproduce, Python version, and the relevant `outputs/*/meta.json` if applicable.

---

## License

Copyright 2026 Travis Funk and contributors.
Licensed under the **Apache License, Version 2.0** — see [LICENSE](LICENSE) for the full text.

Data sourced from CISA, FDA, NVD/NIST, and other US government publications is in the public domain and not subject to copyright.
