# AdvisoryOps — Project Vision

## The Problem

Hospitals are drowning in cybersecurity advisories for medical devices. The alerts come from everywhere — CISA, FDA, vendor disclosures, CERT/CC, KEV, security researchers — and they're a mess. The same vulnerability shows up across multiple sources with different names, different severity ratings, inconsistent product references, and vague remediation language.

Meanwhile, the devices can't be patched like normal IT assets. A ventilator can't go offline for a Tuesday patch cycle. An infusion pump might be vendor-managed with a 6-month firmware update timeline. A diagnostic imaging system might never get patched at all.

Hospital security teams know the problems exist. What they don't have is a fast, reliable way to go from "we received an advisory" to "here's what we do right now to protect the device."

## What AdvisoryOps Does

AdvisoryOps is an advisory-to-action pipeline for healthcare cybersecurity.

**Ingest** — Pull from ~160 validated public sources covering medical device advisories, warnings, recalls, vulnerability disclosures, and cybersecurity alerts for patient care equipment. This is likely the most comprehensive source list for healthcare device security that exists.

**Normalize** — Use AI to clean up the mess. Standardize vendor names, device families, model numbers, version strings, severity, and remediation language across all sources. Make it consistent and machine-readable.

**Deduplicate and Correlate** — Combine the 5 different advisories about the same Baxter infusion pump vulnerability into one canonical issue. Show the evidence trail from every source, but give defenders one clear picture.

**Threat Rank for Healthcare** — A CVSS 7.5 means something very different on a ventilator in an ICU than on a back-office workstation. Rank issues by actual healthcare impact, not generic severity scores.

**Recommend Defensive Fixes** — This is the key. AI-driven, actionable recommendations: "Block port X with this ACL to protect the device while you wait on the vendor patch." Specific, safe, auditable actions that healthcare teams can execute now — not generic advice to "apply the latest update."

## Open Source + Commercial Model

### Open Source (Community Good)
- The full validated source list (~160 sources)
- The normalized, deduplicated advisory dataset
- The schema and data format
- Canonical issue records with evidence citations
- AI-recommended defensive actions for public advisories
- Evaluation methodology and benchmarks

This is not a thin teaser. The open layer is a standalone resource that any healthcare defender or researcher can use.

### Commercial (Enterprise Customers)
- **Inventory import** — Bring in your actual device inventory (make, model, location, network segment)
- **Alert fatigue elimination** — Only see issues that match equipment you actually have
- **Asset-to-vulnerability matching** — "These 12 issues affect YOUR environment, ranked by risk"
- **Facility-specific remediation** — Fix recommendations tuned to your network, your devices, your operational constraints
- **Workflow integration** — Route tasks to the right teams (InfoSec, Clinical Engineering, NetOps, vendors) with evidence and instructions

## Why AI / Why Now

The normalization, deduplication, threat ranking, and fix recommendation layers all require reasoning that rules alone can't handle. Medical device naming is too inconsistent. Source formats are too varied. Fix recommendations require understanding device context, network constraints, and healthcare operational realities. This is where LLM-driven analysis makes the difference between "here's another alert" and "here's what to do about it."

## Current Status

The prototype is real and working:
- 10 validated sources in the current gold set (of ~160 identified)
- 140 signals ingested, 121 issues built, 10 alerts generated
- Public outputs in JSONL, JSON, and CSV
- Source parsing, normalization, correlation, and scoring all functional

The foundation is built. The next step is the intelligence layer — the AI-driven analysis, deduplication, threat ranking, and fix recommendations that turn a data pipeline into a defensive tool.
