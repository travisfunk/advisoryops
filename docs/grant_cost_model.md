# AdvisoryOps AI Feature Cost Model

_Generated from actual feed_latest.json data (1990 total issues, 234 healthcare-relevant, 1 currently multi-source, 82 projected at steady state)_

**GPT-4o-mini pricing:** $0.150/1M input tokens, $0.600/1M output tokens

## Data Profile

| Metric | Value |
|--------|-------|
| Total issues in corpus | 1,990 |
| Healthcare-relevant issues | 234 |
| Multi-source HC (current corpus) | 1 |
| Multi-source HC (projected at 35%) | 82 |
| Corpus first_seen_at range | 2026-03-24 to 2026-03-25 (1.8 days, bulk load) |
| Est. new HC issues per week | ~55 |
| Est. new multi-source HC/week | ~19 |

## Token Analysis (from actual data)

### Task 1: Vendor Advisory Extraction
- System prompt: 52 tokens
- Advisory page content (estimated): ~3,000 tokens avg (5-20KB range)
- **Total input per issue: ~3,052 tokens**
- **Output per issue: ~400 tokens**

### Task 2: Clinical Impact Summarization
- System prompt: 56 tokens
- Content fields (measured avg): 693 tokens
- Content fields (95th pct): 4941 tokens
- **Total input per issue: ~749 tokens**
- **Output per issue: ~200 tokens**

### Task 3: Cross-Source Contradiction Detection
- System prompt: 51 tokens
- Source content (measured avg): 1441 tokens
- Source content (95th pct): 9018 tokens
- **Total input per issue: ~1,492 tokens**
- **Output per issue: ~270 tokens**

## Cost Summary

| Task | Per Issue | Full HC Run (234) | Weekly (incremental) | Monthly | Annual |
|------|----------|-------------------|---------------------|---------|--------|
| 1. Vendor Advisory Extraction | $0.0007 | $0.16 | $0.04 | $0.17 | $2.00 |
| 2. Clinical Impact Summary | $0.0002 | $0.05 | $0.01 | $0.06 | $0.66 |
| 3. Contradiction Detection | $0.0004 | $0.03 | $0.0073 | $0.03 | $0.38 |
| **TOTAL** | -- | **$0.25** | **$0.06** | **$0.25** | **$3.04** |

## Incremental vs. Full Rebuild

| Scenario | Cost |
|----------|------|
| Full corpus rebuild (all 3 tasks, all 234 HC issues) | $0.25 |
| Weekly incremental (~55 new HC issues) | $0.06 |
| Monthly incremental (4.33 weeks) | $0.25 |
| Annual incremental (52 weeks) | $3.04 |
| Annual with 1 full rebuild + 51 incremental weeks | $3.23 |

## Assumptions

- **Cache hit rate:** Previously processed issues cost $0 (only new issues are enriched)
- **Advisory page size:** 5-20KB (avg 12KB) for vendor advisory extraction
- **New issues per week:** ~55 HC issues (based on ~2000 CVEs/month from NIST, ~12% healthcare-relevant)
- **Multi-source ratio:** 35% projected at steady state (current corpus is from initial bulk load)
- **Token counting:** tiktoken (cl100k_base) for accurate GPT-4o-mini token counts
- **No retry costs:** Assumes single successful API call per issue
- **Pricing:** GPT-4o-mini at $0.150/1M input, $0.600/1M output (current as of 2025)

## Context: Existing AdvisoryOps Costs

| Item | Cost |
|------|------|
| Total development API spend to date | ~$12.70 |
| Full corpus rebuild (current pipeline) | ~$1.40 |
| **Proposed AI features (annual)** | **$3.04** |
| Proposed AI features (monthly) | $0.25 |
