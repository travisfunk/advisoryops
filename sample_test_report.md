# Backfill Sample Test Report

Generated: 2026-04-07T04:36:32.386826+00:00
Test root: outputs\_sample_test

## 1. NVD Backfill

  Backfill stats: {"status": "paused", "started_at": "2026-04-07T04:36:32.549221+00:00", "pages_fetched": 1, "cves_fetched": 200, "cves_new": 200, "cves_skipped": 0, "total_results": 342690, "finished_at": "2026-04-07T04:36:33.004639+00:00"}
  Cached files: 200
  Sample cached record:
{
  "nvd_description": "Delete or create a file via rpc.statd, due to invalid information.",
  "cvss_score": 5.0,
  "cvss_vector": "AV:N/AC:L/Au:N/C:N/I:P/A:N",
  "cvss_severity": "MEDIUM",
  "cwe_ids": [],
  "affected_products": [
    "Data General Dg Ux",
    "Ncr Mp-Ras",
    "Sgi Irix",
    "Ibm
  ... (truncated)
  Signals generated: 50
  Sample signal:
{
  "source": "nvd-historical",
  "guid": "CVE-1999-0019",
  "title": "CVE-1999-0019",
  "link": "http://sunsolve.sun.com/pub-cgi/retrieve.pl?doctype=coll&doc=secbull/135",
  "published_date": "1996-04-24T04:00:00.000",
  "summary": "Delete or create a file via rpc.statd, due to invalid information.
  ... (truncated)
  Published: 50 signals, 50 new

**Result: PASS — 200 cached, 50 signals**

---

## 2. CISA ICSMA Backfill

  Backfill stats: {"status": "completed", "started_at": "2026-04-07T04:36:33.352934+00:00", "csv_advisories": 182, "csaf_enriched": 172, "csaf_skipped_cached": 4, "csaf_not_found": 6, "advisories_total": 182, "finished_at": "2026-04-07T04:39:26.382702+00:00"}
  Cached files: 178
  Sample cached record:
{
  "advisory_id": "ICSMA-16-089-01",
  "title": "CareFusion Pyxis SupplyStation System Vulnerabilities",
  "vendor": "CareFusion, Becton, Dickinson and Company (BD)",
  "product": "Pyxis SupplyStation System",
  "products_affected": "Pyxis SupplyStation system software versions affected: Pyxis Supp
  ... (truncated)
  Signals generated: 178
  Sample signal:
{
  "source": "cisa-icsma-historical",
  "guid": "ICSMA-16-089-01",
  "title": "CareFusion Pyxis SupplyStation System Vulnerabilities",
  "link": "https://www.cisa.gov/news-events/ics-medical-advisories/icsma-16-089-01",
  "published_date": "3/29/2016",
  "summary": "CareFusion, Becton, Dickinson an
  ... (truncated)
  Published: 50 signals

**Result: PASS — 178 cached, 178 signals**

---

## 3. openFDA Recalls Backfill

  Backfill stats: {"status": "paused", "started_at": "2026-04-07T04:39:27.049351+00:00", "pages_fetched": 2, "recalls_fetched": 200, "recalls_new": 130, "recalls_skipped": 70, "cyber_relevant": 35, "total_results": 57781, "finished_at": "2026-04-07T04:39:29.329235+00:00"}
  Cached files: 130
  Cyber relevant: False
  Sample cached record:
{
  "cfres_id": "26623",
  "product_res_number": "Z-0003-04",
  "event_date_initiated": "2003-02-24",
  "event_date_posted": "2003-10-15",
  "recall_status": "Terminated",
  "event_date_terminated": "2013-07-01",
  "res_event_number": "25862",
  "product_code": "FMF",
  "k_numbers": [
    "K002921"

  ... (truncated)
  Signals generated (cyber only): 24
  Sample signal:
{
  "source": "openfda-recalls-historical",
  "guid": "27077",
  "title": "27077: Misys Healthcare Systems",
  "link": "https://api.fda.gov/device/recall.json?search=res_event_number:\"27077\"",
  "published_date": "2004-03-15",
  "summary": "Software defect.  Clinical Laboratory results failing qua
  ... (truncated)
  Published: 24 signals

**Result: PASS — 130 cached, 24 cyber-relevant signals**

---

## 4. FDA Safety Comms Backfill

  Backfill stats: {"status": "paused", "started_at": "2026-04-07T04:39:31.155217+00:00", "pages_fetched": 2, "records_fetched": 200, "records_new": 200, "records_skipped": 0, "cyber_relevant": 23, "total_results": 38509, "finished_at": "2026-04-07T04:39:34.789602+00:00"}
  Cached files: 200
  Cyber relevant: False
  Sample cached record:
{
  "status": "Terminated",
  "city": "Ocala",
  "state": "FL",
  "country": "United States",
  "classification": "Class II",
  "openfda": {},
  "product_type": "Devices",
  "event_id": "63085",
  "recalling_firm": "Winco Mfg., LLC",
  "address_1": "5516 SW 1st Ln",
  "address_2": "N/A",
  "postal_c
  ... (truncated)
  Signals generated (cyber only): 23
  Sample signal:
{
  "source": "fda-safety-comms-historical",
  "guid": "Z-0056-2013",
  "title": "Z-0056-2013: Beckman Coulter Inc.",
  "link": "https://api.fda.gov/device/enforcement.json?search=recall_number:\"Z-0056-2013\"",
  "published_date": "20121024",
  "summary": "The recall was initiated because Beckman C
  ... (truncated)
  Published: 23 signals

**Result: PASS — 200 cached, 23 cyber-relevant signals**

---

## 5. MHRA UK Backfill

  Backfill stats: {"status": "paused", "started_at": "2026-04-07T04:39:35.881005+00:00", "pages_fetched": 1, "records_fetched": 50, "records_new": 50, "records_skipped": 0, "total_results": 1381, "finished_at": "2026-04-07T04:39:36.182622+00:00"}
  Cached files: 50
  Sample cached record:
{
  "description": "Accord Healthcare limited is recalling a single batch due to an out of specification test result.",
  "format": "medical_safety_alert",
  "link": "/drug-device-alerts/class-2-medicines-recall-accord-healthcare-ltd-carmustine-100-mg-powder-and-solvent-for-concentrate-for-solution-
  ... (truncated)
  Signals generated: 50
  Sample signal:
{
  "source": "mhra-uk-alerts",
  "guid": "class-2-medicines-recall-accord-healthcare-ltd-carmustine-100-mg-powder-and-solvent-for-concentrate-for-solution-for-infusion-1-vial-100mg-powder-1-vial-of-3-ml-solvent-el-26-a-slash-05",
  "title": "Class 2 Medicines Recall: Accord Healthcare Ltd, Carmusti
  ... (truncated)
  Published: 50 signals

**Result: PASS — 50 cached, 50 signals**

---

## 6. Health Canada Backfill

  Backfill stats: {"status": "completed", "started_at": "2026-04-07T04:39:36.371892+00:00", "recalls_discovered": 15, "details_fetched": 15, "details_cached": 0, "details_failed": 0, "finished_at": "2026-04-07T04:39:41.595226+00:00"}
  Cached files: 15
  Sample cached record:
{
  "recall_id": "RA-76611",
  "title": "Novo-Gesic Forte (2021-10-06)",
  "date_published": "-62169984000",
  "url": "https://healthycanadians.gc.ca/recall-alert-rappel-avis/hc-sc/2021/76611r-eng.php",
  "categories": [
    "3"
  ],
  "summary": "<b>Product: </b>Novo-Gesic Forte <BR/>",
  "reason":
  ... (truncated)
  Signals generated: 15
  Sample signal:
{
  "source": "health-canada-recalls-historical",
  "guid": "RA-76611",
  "title": "Novo-Gesic Forte (2021-10-06)",
  "link": "https://healthycanadians.gc.ca/recall-alert-rappel-avis/hc-sc/2021/76611r-eng.php",
  "published_date": "-62169984000",
  "summary": "Novo-Gesic Forte (2021-10-06)",
  "fetc
  ... (truncated)
  Published: 15 signals

**Result: PASS — 15 cached, 15 signals**

---

## 7. Philips PSIRT Backfill

  Backfill stats: {"status": "completed", "started_at": "2026-04-07T04:39:41.690130+00:00", "pages_fetched": 9, "pages_failed": 10, "advisories_found": 113, "advisories_new": 14, "finished_at": "2026-04-07T04:39:55.031066+00:00"}
  Errors (10): showing first 3
    {'url': 'https://www.philips.com/a-w/security/security-advisories/archive-2025.html', 'error': 'HTTP Error 404: Not Found'}
    {'url': 'https://www.philips.com/a-w/security/security-advisories/archive-2024.html', 'error': 'HTTP Error 404: Not Found'}
    {'url': 'https://www.philips.com/a-w/security/security-advisories/archive-2023.html', 'error': 'HTTP Error 404: Not Found'}
  Cached files: 14
  Sample cached record:
{
  "advisory_id": "PHILIPS-Philips_Product_Security_Advisory",
  "title": "Philips Product Security Advisory",
  "link": "https://www.philips.com/a-w/security/security-advisories",
  "date": "2025",
  "cves": [],
  "vendor": "Philips",
  "summary": "Philips Product Security Advisory"
}
  Signals generated: 14
  Sample signal:
{
  "source": "philips-psirt",
  "guid": "PHILIPS-Philips_Product_Security_Advisory",
  "title": "Philips Product Security Advisory",
  "link": "https://www.philips.com/a-w/security/security-advisories",
  "published_date": "2025",
  "summary": "Philips Product Security Advisory",
  "fetched_at": "2
  ... (truncated)
  Published: 14 signals

**Result: PASS — 14 cached, 14 signals**

---

## 8. Siemens ProductCERT Backfill

  Backfill stats: {"status": "completed", "started_at": "2026-04-07T04:39:55.066360+00:00", "advisories_in_feed": 779, "csaf_fetched": 235, "csaf_cached": 0, "csaf_failed": 544, "finished_at": "2026-04-07T04:44:23.394924+00:00"}
  Cached files: 779
  Sample cached record:
{
  "advisory_id": "SSA-000072",
  "title": "Multiple File Parsing Vulnerabilities in Simcenter Femap",
  "published": "2024-02-13T00:00:00Z",
  "url": "https://cert-portal.siemens.com/productcert/csaf/ssa-000072.json",
  "vendor": "Siemens"
}
  Signals generated: 50
  Sample signal:
{
  "source": "siemens-productcert-psirt",
  "guid": "SSA-000072",
  "title": "Multiple File Parsing Vulnerabilities in Simcenter Femap",
  "link": "https://cert-portal.siemens.com/productcert/csaf/ssa-000072.json",
  "published_date": "2024-02-13T00:00:00Z",
  "summary": "Multiple File Parsing Vuln
  ... (truncated)
  Published: 50 signals

**Result: PASS — 779 cached, 50 signals**

---

## Summary

| # | Module | Result |
|---|--------|--------|
| | 1. NVD Backfill | **PASS** — 200 cached, 50 signals |
| | 2. CISA ICSMA Backfill | **PASS** — 178 cached, 178 signals |
| | 3. openFDA Recalls Backfill | **PASS** — 130 cached, 24 cyber-relevant signals |
| | 4. FDA Safety Comms Backfill | **PASS** — 200 cached, 23 cyber-relevant signals |
| | 5. MHRA UK Backfill | **PASS** — 50 cached, 50 signals |
| | 6. Health Canada Backfill | **PASS** — 15 cached, 15 signals |
| | 7. Philips PSIRT Backfill | **PASS** — 14 cached, 14 signals |
| | 8. Siemens ProductCERT Backfill | **PASS** — 779 cached, 50 signals |

**Total: 8 PASS, 0 WARN, 0 FAIL out of 8**
