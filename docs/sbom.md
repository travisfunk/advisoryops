# Device SBOM checks

Open **Device SBOM** in the dashboard, choose the device's JSON SBOM, optionally
enter a device name/asset ID, and select **Check components**. Review each linked
source advisory. **Download report (JSON)** saves the inventory, evidence, coverage,
and candidate findings locally. **Clear device** removes the import and findings.

## Supported imports

- CycloneDX 1.2–1.7 JSON: top-level and nested components, plus the metadata root
  component. Name, version, manufacturer, supplier, PURL, CPE, scope and references
  are retained. Included/excluded/test scope is not used to silently omit packages.
- SPDX 2.2/2.3 JSON: packages, versionInfo, supplier, SPDXID and external PURL/CPE
  references. Files, snippets, relationships and external document resolution are
  not imported. Supplier is not assumed to be the software manufacturer.
- 10 MiB and 10,000 component entries per document (before deduplication).
  Identical name/version/manufacturer/PURL/CPE/scope identities are deduplicated;
  different versions remain distinct. Missing names are skipped with a warning.
  Missing or conflicting versions and malformed identifiers are reported.

This is a component inventory reader, not a full SBOM schema validator. XML,
SPDX tag/value, SPDX 3.x and external/remote BOM resolution are unsupported.

## Matching and interpretation

Checks use `sbom_advisories.json`, generated from **every record** in the canonical
corpus during full archive publication. The browser verifies its count and snapshot
timestamp against `feed_archive/manifest.json`. It never substitutes the latest
750-record feed or medical-device subset when the catalog is unavailable.

The index uses affected-product labels and KEV product names. Component names,
PURL package names, and CPE vendor/product identities are normalized for case and
separator differences. Full trailing product names can match a vendor-prefixed
label; supplied manufacturer/CPE vendor evidence gates that prefix, including
when the declared name or PURL provides the fallback product name. Supplier and
PURL namespace are not treated as manufacturers. Short/generic names without a
specific full identity are deliberately not candidates. Titles and summaries are
not searched for component matches. No fuzzy matching is used. Manufacturer comparisons use the explicit alias policy below.

When the declared component manufacturer matches an advisory's vendor (normalized
`vendor` or `kev_vendor`), a whole-word component name inside a longer affected
product label is also a candidate. For example, **Medfusion 4000** can match
**Smiths-Medical Medfusion 4000 Wireless Syringe Infusion Pump** when the
manufacturer is Smiths Medical. These findings carry
`evidence_flags: ["partial product name"]`, also shown in the dashboard. Missing or
mismatched manufacturers, suppliers and inferred CPE vendors do not qualify this
rule. Word fragments such as **Medfusion 4000A** do not match **Medfusion 4000**.
Exact identity evidence takes precedence; a component/advisory pair appears once.

All findings are **review required**. The current feed's human-readable affected
products lack reliable per-component version ranges and ecosystem identifiers.
Advisory version text is preserved as evidence but **never evaluated**, even if it
looks machine-readable. Matching a name does not establish an exact package,
affected installed version, deployment condition, reachability or exploitability.
PURL package names can collide across ecosystems; results explicitly flag that
uncertainty. CPE identifiers are used as identity evidence, not CPE applicability
expressions. Do not treat candidate counts as confirmed vulnerable-device counts.

Coverage reports the catalog date, total advisories, advisories without product
metadata, components without candidates and skipped entries. **No match does not
mean safe.** It can mean missing identity data, a naming difference, an unsupported
identity, or a vulnerability outside the tracked corpus. There is no live lookup
against an external vulnerability service or automatic recheck after publication.
Import again to check a newer snapshot.

## Privacy and rendering

The selected SBOM and device name stay in the current page's memory. There are no
inventory POSTs, query-string lookups, localStorage/IndexedDB writes, inventory telemetry or
server-side inventory storage. Only same-origin public catalog/manifest GETs are
needed for a check. Reloading, clearing or closing the tab removes the import;
browser download history and downloaded reports are separate. Exported JSON
contains private inventory and should not be committed to this public repository.

Anonymous page-load measurement runs in a separate sandboxed frame. It cannot
read the SBOM, device name, findings, parent URL, or browser storage. See
[visit analytics](visit-analytics.md) for the exact isolation and provider details.

Imported text and advisory evidence are HTML-escaped. Source links accept only
HTTP(S). Errors, changed input and failed catalog checks clear previous findings
and disable export. The UI renders the first 200 findings; JSON contains all
findings, up to a 100,000-candidate guard. Larger checks fail and ask for a smaller
per-device SBOM rather than silently dropping findings.

## Publication and verification

The authored browser code is split by responsibility:

| File | Responsibility |
| --- | --- |
| `dashboard/sbom.js` | Pure inventory parsing, catalog indexing and candidate matching; no DOM or network access |
| `dashboard/sbom-ui.js` | Browser state, cancellation, rendering and local export |
| `src/advisoryops/sbom_catalog.py` | Allowlisted identity projection of public advisory records |
| `tests/dashboard_sbom_cases.js` | Executable parsing/matching regressions using Node's built-in assertions |
| `tests/dashboard_sbom_ui_cases.js` | Offline controller tests with an injected DOM/network harness |
| `tests/test_sbom.py` | Publication lifecycle, source/published asset parity and Node-test integration |

`_publish_to_docs` copies both browser scripts and the dashboard to `docs/`.
These served copies and the public advisory catalog are marked as generated in
`.gitattributes`, so GitHub collapses their diffs. Authored source remains visible.

`advisoryops.feed_archive publish` writes the catalog as part of its validated, staged full-history publication, with a 25 MiB size guard.
The existing daily workflow invokes both steps. Private SBOMs are never inputs to
that workflow. The catalog's stable issue ordering keeps changes reviewable.

Run the regression suite with `PYTHONPATH=src python -m pytest tests/ -q` or the
existing project environment. Node.js enables the executable browser-engine tests:
`node tests/dashboard_sbom_cases.js` and `node tests/dashboard_sbom_ui_cases.js`.
The read-only [test workflow](../.github/workflows/tests.yml) runs the offline Python and Node tests on pull requests and main-branch pushes (Python 3.11,
Node 22). It requires no API keys. No application dependencies were added.

Format references: [CycloneDX JSON](https://cyclonedx.org/docs/1.7/json/) and
[SPDX package information](https://spdx.github.io/spdx-spec/v2.3/package-information/).

## Catalog and report contracts

Both JSON documents carry `version: 1`. Catalogs contain `generated_at`,
`total_records`, `records_with_products`, `matching_policy` and `issues`.
`matching_policy` must be `product_identity_candidates_only`. Each issue is an
allowlisted projection; raw source documents, signals and private inventory are
never included. The generated catalog can be reproduced from the archive and checked-in source vendor evidence using
the normal publication command documented in [publication.md](publication.md).

Reports contain the device label, source SBOM format, catalog/check timestamps,
coverage counts, imported component inventory, warnings, skipped entry count,
`findings` and `unmatched_component_indexes`. Each finding links a zero-based
`component_index` to an `issue_id`, retains the matched product label and advisory
version text, and has `status: "review_required"`. The `evidence`, `evidence_flags`,
`limitation` and report `interpretation` fields explain what that result establishes. Schema
changes that break consumers must increment the relevant document version.


## Source vendor coverage

Publication fills empty `vendor` fields from explicit source signals and
`configs/sbom_vendor_sources.json`. This public evidence snapshot retains advisory
URLs, CVEs, vendor names and source URLs; it contains no inventory. It repairs
historical records whose vendor was dropped upstream. Existing vendor fields
remain authoritative. URL associations take precedence over CVE associations;
ambiguous multi-vendor associations stay unresolved. Product labels and AI prose
are never used to invent manufacturers.

The daily feed workflow runs `python -m advisoryops.source_vendors` before
publication to refresh the existing ICS-Medical CSV source and incorporate
CISA/CSAF and NVD caches. NVD parsing retains vendors from vulnerable CPE matches,
excluding non-vulnerable platform prerequisites. Multiple concrete CPE vendors
remain ambiguous rather than selecting the first. An offline refresh can use
`--csv /path/to/CISA_ICS_ADV_Master.csv --cache-root outputs`. Publication itself
has no network dependency; commit source evidence alongside the generated catalog.

Manufacturer comparisons strip punctuation, normalize case/spacing and remove
trailing legal suffixes (Inc., Incorporated, LLC, Corp., Corporation, Ltd.,
Limited, Co., Company, PLC, LLP and N.V.). Product normalization stays separate.
The following complete manufacturer names compare as equivalent in both directions:

| Canonical lookup name | Additional names |
| --- | --- |
| BD | Becton, Dickinson and Company; CareFusion |
| Stryker | Stryker Corporation; Physio-Control |
| Medtronic | Medtronic plc; Covidien |
| Philips | Koninklijke Philips N.V. |
| GE HealthCare | GE Healthcare; General Electric |
| Baxter | Baxter International; Hillrom; Hill-rom; Welch Allyn |
| Smiths Medical | Smiths Medical ASD; ICU Medical |
| Siemens Healthineers | Siemens Healthcare; Siemens |

The catalog's explicit `Becton, Dickinson and Company (BD)` and combined
`CareFusion, Becton, Dickinson and Company (BD)` spellings are included too.
These are candidate lookup equivalences requested for this checker, not an
assertion of current corporate ownership or vulnerability across a group's
products. Only complete names qualify; meaningful extra words are retained.
Raw vendor names and source URLs remain in findings. Product-specific evidence,
whole-word product boundaries and review-required status still apply. The real
published catalog regression covers every listed alias, suffix handling, and
unrelated-name rejection; symmetric comparison also has focused tests.

The October 16, 2026 repair raises vendor coverage (`vendor` or `kev_vendor`)
from 772 to 1,478 of 14,720 issues; among 6,474 issues with product labels,
coverage rises from 770 to 1,380. Missing source evidence still limits coverage.
The executable regression loads the actual published catalog and requires all
eight Medfusion 4000 CVEs, including CVE-2017-12718, to return candidates for
manufacturer `Smiths Medical` with `partial product name` evidence. A second
regression reproduces the catalog from the archive and source snapshot.


## Historical recovery and product-scoped vendor evidence

`configs/sbom_vendor_sources.json` version 2 records explicit vendor/product
pairs, source URLs, NVD check dates and recovery outcomes. The catalog remains
schema version 1 with additive `product_vendors`, `records_with_vendor_products`
and `vendor_evidence_checked_at` fields. Summary `vendor` values are not a license
to apply that manufacturer to every product in a multi-vendor advisory.

CPE extraction excludes non-vulnerable platform prerequisites, negated nodes,
and wildcard vendor/product identities. CSAF extraction follows vendor ancestry
and each CVE's `known_affected` product IDs; unresolved relationships stay unknown.
Authoritative CPE names recover historical display-name escaping/truncation errors
without deleting older labels. Partial matches use the resulting product-specific
bindings. Exported findings retain the matched vendor and vendor evidence URL.

NVD caches carry an identity schema version. Older flattened caches are refetched
or upgraded from raw configurations; modified NVD source records refresh current
caches too. Source identities survive correlation, baseline merging and feed
projection, including standalone builds without the checked-in snapshot. Stored
CSAF evidence cannot be replaced by a lower-authority CSV refresh; older NVD
cache files cannot roll back a newer persisted check.

Run a complete, resumable historical recovery with:

```bash
python -m advisoryops.source_vendors --recover-nvd --nvd-limit 0
```

The daily workflow checks at most 200 missing/stale CVEs, in 100-CVE batches,
with a 30-day recheck interval. Missing records go first, followed by the oldest
checks. Each completed batch is checkpointed; incomplete responses fail instead
of marking records checked. Public raw responses stay in ignored `outputs/`;
only the minimal evidence snapshot is committed. No API key is required for this
recovery command. Unknowns and multi-vendor identities are retained honestly.

For reproducible acceptance scenarios and current measured coverage, see the
[release audit](release-audit.md). These checks establish candidate-generation
behavior and data handling, not installed-version vulnerability applicability.
