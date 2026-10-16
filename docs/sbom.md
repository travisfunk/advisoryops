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
not searched for component matches. No fuzzy matching or curated aliases are used.

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
inventory POSTs, query-string lookups, localStorage/IndexedDB writes, telemetry or
server-side inventory storage. Only same-origin public catalog/manifest GETs are
needed for a check. Reloading, clearing or closing the tab removes the import;
browser download history and downloaded reports are separate. Exported JSON
contains private inventory and should not be committed to this public repository.

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
never included. The generated catalog can be reproduced from the archive using
the normal publication command documented in [publication.md](publication.md).

Reports contain the device label, source SBOM format, catalog/check timestamps,
coverage counts, imported component inventory, warnings, skipped entry count,
`findings` and `unmatched_component_indexes`. Each finding links a zero-based
`component_index` to an `issue_id`, retains the matched product label and advisory
version text, and has `status: "review_required"`. The `evidence`, `limitation` and
report `interpretation` fields explain what that result establishes. Schema
changes that break consumers must increment the relevant document version.
