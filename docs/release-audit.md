# AdvisoryOps release audit — October 16–17, 2026

## Assessment and scope

This is an internal engineering review with executable regression tests and
browser acceptance scenarios. It is suitable evidence for a guided technical
review of the public dashboard and private SBOM workflow. It is not an independent
penetration test, clinical validation, or end-user acceptance sign-off.

The review covers source identity extraction, historical NVD recovery,
correlation/feed publication, component matching, browser privacy and rendering,
local report export, failure handling, mobile layout, dashboard navigation and
public feature claims. Tests use synthetic inventory and public advisory data.
No real device inventory or credentials are included in the repository.

## Data checked

The canonical archive retains **14,720 issues**, independent of the dashboard's
bounded general-advisory serving window. The repaired SBOM catalog has:

| Measurement | Result |
| --- | ---: |
| Issues with product labels | 6,570 |
| Issues with a nonempty summary `vendor` | 5,479 |
| Product-labeled issues with a nonempty summary `vendor` | 5,477 |
| Issues with explicit product/vendor bindings | 6,177 |
| Product-labeled issues without such bindings | 393 |
| Catalog CVEs checked against NVD | 6,178 |
| NVD records with concrete vulnerable CPE pairs | 6,080 |
| NVD records without concrete vulnerable CPE pairs | 98 |

Summary vendor coverage was 772 before the initial repair and 1,478 after PR #26.
A summary vendor count is not the same as product-specific coverage: a multi-vendor
issue can have valid per-product evidence while its singular summary vendor stays
empty. Recovering authoritative product names also adds 96 previously unlabeled
issues; therefore the original 6,474-product denominator is not the current one.

The remaining 393 unbound product-labeled records comprise 389 records without
structured CVEs and four CVE records whose current NVD response supplies no usable
CPE pair: CVE-2026-0765, CVE-2026-0766, CVE-2026-0767 and CVE-2026-31404.
They remain unknown for manufacturer-gated partial matching. No manufacturer is
inferred from an AI summary to close that gap.

The [source evidence snapshot](../configs/sbom_vendor_sources.json) records each
source URL, identity pair and NVD check outcome. The catalog is reproducible from
that snapshot and the canonical archive. Every published binding was checked to
refer to a published product label and an HTTP(S) source URL. The roughly 10.6 MiB
catalog remains below its 25 MiB publication guard.

## Findings corrected

| Finding | Correction and verification |
| --- | --- |
| Historical source vendors were missing | Checked every catalog CVE with product evidence against NVD in resumable batches; retained concrete vulnerable vendor/product pairs and explicit unknown outcomes. |
| One advisory vendor could qualify unrelated products | Partial matching now requires product-specific bindings. Tests cover two vendors in one advisory, wrong manufacturers, exact-match vendor conflicts and unbound labels. |
| CSAF product trees could be applied too broadly | Follow vendor ancestry and each CVE's `known_affected` product IDs. Unresolved IDs/relationships do not create bindings. |
| Source vendors could disappear before publication | Promote vendor/source identities during correlation, retain them through feed projection and baseline merging, and test the actual source → issue → feed → catalog path without a repository snapshot. This also addresses the automated review finding on PR #26. |
| Old caches could stay permanently incomplete | Version identity extraction; upgrade raw caches or refetch old flattened caches once. Modified NVD records update current caches. |
| Refresh could downgrade evidence | Preserve CSAF evidence during CSV-only refresh; reject older NVD cache evidence when a newer persisted check exists. Prioritize missing records and then oldest checks. |
| Old CPE display parsing retained escapes/truncated names | Decode escaped punctuation and retain authoritative CPE names alongside earlier labels. Existing evidence labels are not silently deleted. |
| An FDA helper confused recall hazard and device risk class | Remove the recall-class conversion. Only explicit `device_class` populates device risk. Production builder tracing found no call to the incorrect helper; this fix does not claim to revalidate historical FDA metadata. [FDA describes recall classifications separately](https://www.fda.gov/medical-devices/postmarket-requirements-devices/recalls-corrections-and-removals-devices). |
| Name-based device class lookup selected the first match | Empty names and conflicting class results now return unknown; exact product-code lookup retains precedence. |
| Public wording overstated availability/cost | Clarify that the complete **published subset** is loaded, guidance is present where available, and optional AI API use can incur charges. Remove unsupported competitor-pricing assertions. |

## Executable checks

Local final build: **1,198 Python tests passed**, one optional test skipped and
one integration test deselected. All **31 Node matching cases** and **18 Chromium
acceptance checks** passed; the controller harness also runs in the Python suite.
CI and deployed-file verification are required before calling this release live.

Run from the repository root:

```bash
python -m pip install -e . pytest openpyxl
python -m pytest tests/ -q
node tests/dashboard_sbom_cases.js
node tests/dashboard_sbom_ui_cases.js
npm ci --ignore-scripts
npx playwright install --with-deps chromium
npm run test:browser
```

The pure matching suite includes the **actual** published
`docs/sbom_advisories.json`, not a Medfusion-only fixture. It requires all eight
Medfusion 4000 CVEs for manufacturer `Smiths Medical`, including CVE-2017-12718,
with `partial product name` evidence and `review_required` status. Wrong
manufacturers, larger model numbers, Unicode word boundaries, regular-expression
metacharacters, corporate suffixes and unrelated division names have negative
regressions. Manufacturer variants include `Smiths-Medical` and
`Smiths Medical ASD Inc.`.

Publication checks reproduce the catalog and require authored/served asset parity.
The broader Python suite also covers scoring, source parsing, source corrections,
review-baseline changes, recommendations and packet/Excel/feed exports. The
existing integration test is excluded from the offline suite; the optional
`test_feed_contract.py` pipeline-output test is skipped when no locally generated
pipeline feed is present, and it must not be counted as tested. Other optional
fixture-dependent tests may be skipped and must not be counted as tested.

`tests/browser_uat.cjs` runs **18 acceptance checks** against the real `docs/`
files served by an ephemeral loopback server:

- SBOM deep link, tab visibility and keyboard focus.
- Actual-catalog Medfusion results and evidence flags.
- Complete local JSON download, device association and vendor evidence provenance.
- Synthetic private component/device markers absent from all network requests and
  browser storage; all observed requests are GETs.
- A 320px mobile viewport without horizontal overflow, with desktop/mobile
  screenshots inspected for layout.
- Changing inputs invalidates old findings and downloads.
- Wrong-manufacturer no-match wording makes no safety claim.
- SPDX import follows the documented identity policy; supplier/originator fields
  do not become manufacturers automatically.
- Component HTML is escaped, with no executed event handler.
- Unsupported/malformed/oversized input fails without leaving stale exports.
- Catalog HTTP failure and manifest/catalog mismatch fail closed.
- Clear removes device/file/results.
- All dashboard tabs, advisory search/detail and local review controls work.
- No uncaught JavaScript errors occur during these flows.

The test workflow runs the offline suite and browser acceptance checks on pull
requests and main, and retains `outputs/uat/` screenshots plus `result.json` as a
GitHub Actions artifact. Chromium is automated; Firefox, Safari, real assistive
technology and representative hospital end users have not participated.

The locked browser-test dependencies were checked with `npm audit --package-lock-only`;
the registry reported zero known advisories at review time. This is limited to
the Node development dependency lockfile, not a complete supply-chain audit.

## Demonstration and review boundaries

Use the [synthetic CycloneDX demonstration file](../examples/sbom/medfusion-demo.cdx.json), with a component named `Medfusion 4000` and
manufacturer `Smiths Medical`, then show the eight candidates and downloaded
source-linked evidence. Explain that matching is product identity review;
installed-version ranges, deployment applicability and exploitability are not
evaluated. A no-match result does not establish safety.

The private browser check requires no account and sends no SBOM to a service.
Its user-requested JSON download contains inventory and should be handled as
private data. Public feed publication never accepts a private SBOM as input.

The public dashboard, recommendations and scores are decision-support software.
Historical source facts, clinical priority calibration and all AI-generated
wording have not received exhaustive independent validation. Zero packets in a
dated build must not be presented as a live demonstration of generated packets.
Authenticated third-party ticket delivery and paid AI provider calls are outside
this offline/browser acceptance run; do not present those as tested integrations.

An external reviewer should challenge source interpretation, false positives,
coverage gaps, scoring assumptions and privacy boundaries. This review provides
repeatable evidence and known limits; it does not establish that every possible
input or deployment behaves correctly.
