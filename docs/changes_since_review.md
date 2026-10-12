# Changes since your last review

The dashboard's **New or updated** filter helps returning readers find records
that differ from a baseline saved in their browser. On the first visit, it saves
the loaded records without labeling the whole feed new. On later visits, it shows
**NEW TO YOU** and **UPDATED** badges. Open an updated record to see the previous
and current values of each changed field.

Compared fields are priority, severity, vendor, affected products and versions,
CVEs, the strict medical-device KEV flag, FDA risk class, advisory text,
remediation guidance, recommended actions, source mitigations, and role assignments.
Whitespace and list ordering/duplicates are normalized. Routine discovery
timestamps, raw score fluctuations, and source-list ordering do not create alerts.
An advisory-text change does not establish that a patch is available; verify the
actual advisory and vendor instructions.

**Mark loaded records reviewed** advances the baseline for all loaded records in
the current scope, including records hidden by search or other filters. Merely
opening a record or returning to the site does not dismiss outstanding changes.
Read/unread status remains independent.

The medical-device scope compares the complete published medical-device feed.
The general scope compares only its bounded serving window, not the canonical
archive. Each scope has its own baseline. Records missing from a later window are
retained in the baseline; disappearance is never interpreted as resolution.
New to you means absent from the saved baseline, not newly published or newly
discovered by the vendor. The feature compares endpoint snapshots and cannot show
intermediate changes that occurred and reverted between reviews.

Baselines stay in this browser's local storage, with no login or server-side
tracking. Other browsers/devices and cleared storage start a new baseline. If
storage is blocked or full, the dashboard shows an unavailable message and disables
the change controls while keeping advisory browsing available. Corrupt or outdated
baselines are replaced on a successful load.

The change filter respects search, scope, and other issue filters, bypasses the
Latest limit, and is mutually exclusive with the publication-date **This week**
view. The change summary counts the loaded scope before search/priority filters.

## Verification

`python -m pytest tests/test_dashboard_changes.py tests/test_dashboard_html.py tests/test_dashboard_methodology.py -q`

The change behavior test executes the actual inline JavaScript in Node.js and
covers baseline creation, meaningful differences, normalization, explicit review,
retained missing records, separate scopes, corrupt storage, and blocked storage.
