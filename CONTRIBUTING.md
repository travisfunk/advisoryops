# Contributing to AdvisoryOps

## Why contributions matter

AdvisoryOps is a community resource built for healthcare security defenders — the people responsible for keeping medical devices safe in hospitals. The quality of the data in this feed directly affects the security of connected devices in clinical environments. Every correction you submit, every broken source you flag, and every new source you suggest improves the signal that reaches the people making real-time security decisions for patient care.

---

## Ways to contribute

### Reporting a bad merge

A merge error happens when two separate vulnerabilities — affecting different products, vendors, or CVEs — get combined into a single issue record by the correlation pipeline. This reduces signal quality and can make it look like a single device has an issue when it doesn't, or obscure that multiple devices are affected separately.

**What to look for:** An issue record whose title seems to combine unrelated advisories, or whose source list includes sources from very different vendors. For example: an issue titled "Philips IntelliSpace and Baxter Sigma Spectrum authentication bypass" where those are clearly unrelated products from unrelated advisories.

Use the [bad merge template](.github/ISSUE_TEMPLATE/bad_merge.md) to report these. Include both source IDs and a brief explanation of why they should be separate — for example: "CVE-2026-1234 affects only IntelliSpace Portal; CVE-2026-5678 affects only the Sigma Spectrum pump. They share no CVEs, vendor, or product family."

### Reporting a wrong product match

A product match error happens when an advisory gets attributed to the wrong product or vendor name. This is common because vendor naming is inconsistent across sources — a CISA advisory might say "Baxter International" while the vendor's own PSIRT says "Baxter Healthcare" and a research blog says "Baxter Spectrum WBM." All three refer to the same product, but without normalization they look different.

If you see an issue where the product or vendor name is clearly wrong — pointing to a different product family, a misread model number, or a naming collision between two unrelated vendors — use the [wrong product match template](.github/ISSUE_TEMPLATE/wrong_product_match.md). A source reference (direct link to the original advisory) is especially helpful here because the correct name is almost always visible in the primary source. Note that vendor naming is inconsistent across sources — context and source references are what allow us to confidently normalize a name.

### Reporting or suggesting sources

AdvisoryOps currently ingests 57 enabled sources covering medical device security, ICS/OT advisories, healthcare cybersecurity news, and threat intelligence. We want sources that publish structured, machine-readable feeds (RSS, JSON API, or structured CSV) and maintain a consistent publishing schedule.

Use the [source correction template](.github/ISSUE_TEMPLATE/source_correction.md) to report broken or outdated source URLs, or to suggest a new source. The `source_id` field in every issue record tells you exactly which source contributed that data — check the original advisory at that source before reporting a URL issue.

**What makes a good source suggestion:**
- Consistent publishing schedule — not one-off posts or irregular updates
- Machine-readable format — RSS, Atom, JSON API, or structured CSV
- Healthcare or medical device relevance — direct coverage of ICS/OT, medical device CVEs, FDA advisories, vendor PSIRTs with device exposure, or healthcare cybersecurity incidents
- Publicly accessible — no login, paywall, or subscription required
- Authoritative or research-grade — CISA, FDA, vendor PSIRTs, or recognized security research organizations

### What we don't accept via GitHub Issues

- Private or proprietary data, internal hospital inventory, or facility-specific device lists
- Requests to add authentication-required or subscription-only sources
- Vulnerability reports — if you've found a security issue in a medical device or software product, report it to the vendor's PSIRT or to CISA at cisa.gov/report
- Requests for facility-specific customization or enterprise workflow integration (these belong in the commercial layer)

---

## Data quality standards

Every issue record in AdvisoryOps cites its sources. The `sources` field lists every `source_id` that contributed to that issue, and the full source list is public in `configs/sources.json`. If an issue looks wrong, the `source_id` tells you exactly where the data came from — verify against the original advisory before submitting a report. High-quality reports include the source URL and quote the relevant text from the original advisory.

## Response time

This is a solo-maintained open source project developed as part of a research effort to improve medical device security intelligence for hospital defenders. Issues are reviewed on a best-effort basis. High-quality reports with clear evidence get prioritized — source URLs, quoted advisory text, and a specific explanation of what's wrong make a report immediately actionable.

---

## Code contributions

### Adding Sources

Sources are defined in `configs/sources.json` (individual source entries) and `configs/community_public_sources.json` (validated set manifest).

#### Steps

1. Add a new entry to `configs/sources.json`:

```json
{
  "source_id": "your-source-id",
  "name": "Human-readable name",
  "type": "rss|api|html",
  "url": "https://...",
  "category": "kev|icsma|nvd|vendor|community",
  "healthcare_relevant": true,
  "notes": "Optional context"
}
```

2. Run a smoke test to confirm discovery works:

```bash
python -c "from advisoryops.cli import main; import sys; sys.argv = ['advisoryops', 'source-run', '--source', 'your-source-id', '--limit', '5']; main()"
```

3. If the source consistently returns valid items, add it to the `candidates` list in `configs/community_public_sources.json` and open a PR.

4. A source graduates from `candidates` to `validated` after:
   - At least one successful pipeline run (discover → correlate → score)
   - No encoding or parsing errors
   - At least 5 real advisory items in the output

#### Source requirements

- Must be a public, stable URL (not behind auth)
- Must not require scraping JavaScript-rendered pages unless a static fallback exists
- RSS/Atom feeds are preferred; HTML scraping is acceptable for major vendor advisories

### Writing Tests

All tests live in `tests/`. The project uses `pytest`.

```bash
pytest tests/ -v
```

Test file naming follows the existing pattern: `test_<module_name>.py` maps to `src/advisoryops/<module_name>.py`.

**What to test:**
- **Unit tests**: Test pure functions with direct inputs and expected outputs. Avoid hitting the network or filesystem where possible.
- **Integration tests**: If your code calls `correlate()` or `score_issue_v2()`, use the golden fixture helpers in `tests/fixtures/golden/` or write to `tmp_path`.
- **AI-dependent code**: Use `_call_fn` injection (see `recommend.py` and `test_recommend.py`) to mock the AI call. Never make live API calls in CI tests.

The 12 golden fixtures in `tests/fixtures/golden/` form the regression baseline. If you change scoring behavior, run the eval harness and update affected `expected.json` files:

```bash
python -c "from advisoryops.cli import main; import sys; sys.argv = ['advisoryops', 'evaluate']; main()"
```

Expected accuracies: correlation 1.0, CVE coverage 1.0, scoring 1.0, healthcare >= 0.9.

### Submitting Pull Requests

1. **Fork and branch**: Create a feature branch from `main` with a descriptive name:
   ```
   feature/add-dragos-source
   fix/scoring-edge-case
   ```

2. **Make your changes**: Keep PRs focused — one feature or fix per PR.

3. **Run tests before opening the PR**:
   ```bash
   pytest tests/ -v
   ```
   All tests must pass.

4. **Update `RELEASE_NOTES.md`** if your change affects source count, issue count, or pipeline behavior.

5. **PR description** should include what changed and why, verification steps the reviewer can run, and any new test count or accuracy numbers.

6. **Do not commit `outputs/`**. The `.gitignore` excludes it, but double-check before pushing.

### Code Style

- Python 3.11+, `from __future__ import annotations`
- Type hints on all public functions
- Dataclasses for structured return types
- No external dependencies beyond what's in `pyproject.toml`

## Questions

Open a GitHub issue with the `question` label.
