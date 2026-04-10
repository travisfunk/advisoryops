# KEV / Medical Device Overlap Analysis

**Date:** 2026-04-09
**Finding:** Zero overlap between CISA KEV entries and medical device records

## Methodology

Compared all issues with KEV enrichment (kev_required_action populated) against all issues classified as medical_device by the healthcare filter. Checked overlap by:
1. CVE ID intersection
2. Vendor name intersection (partial string matching)

## Data

| Metric | Count |
|--------|-------|
| Total issues in corpus | 3,929 |
| KEV-enriched issues | 203 |
| Medical device issues | 856 |
| CVE overlap (KEV CVEs in medical device set) | 0 |
| Vendor overlap (KEV vendors matching medical device vendors) | 0 |

### KEV vendor distribution (top 20)

The 203 KEV entries span 88 unique vendors, dominated by enterprise IT: Cisco, Microsoft, Apple, Adobe, Fortinet, Ivanti, Google Chrome, VMware, Citrix, BeyondTrust, F5, etc.

### Medical device source distribution

Medical device records come primarily from: CISA ICS-Medical advisories (ICSMA), FDA MedWatch, openFDA device recalls, Health Canada recalls, Philips PSIRT, Siemens ProductCERT.

## Conclusion

The zero overlap is genuine, not a data quality bug. CISA's Known Exploited Vulnerabilities catalog tracks vulnerabilities that are actively exploited at scale in the wild. These tend to be in widely-deployed enterprise software and network infrastructure. Medical device vulnerabilities exist in the NVD and in CISA's ICSMA advisories, but they are not being added to KEV — likely because medical device exploitation at scale hasn't been observed or reported through CISA's KEV inclusion criteria.

## Implications for AdvisoryOps

This finding directly supports the grant narrative:

1. **The federal authoritative source for "known exploited" vulnerabilities has zero medical device coverage.** A hospital security team watching only KEV for patching deadlines would see nothing about their medical devices. This is precisely the gap AdvisoryOps fills.

2. **Medical device security intelligence requires dedicated sources.** The advisories that matter for medical devices (ICSMA, FDA recalls, vendor PSIRTs) exist in separate, specialized channels that general vulnerability platforms don't aggregate.

3. **The `is_kev_medical_device` feature is architecturally correct but reflects a real data gap.** If/when CISA adds medical device CVEs to KEV, the cross-reference will automatically surface them. The feature doesn't need a code fix — it needs the upstream data to exist.

4. **Post-extraction (Problem 3), the vendor overlap check should be re-run.** Once FDA-recall-derived issues have populated vendor fields (e.g., "Abiomed", "Medtronic"), the vendor-matching logic may find partial overlaps with KEV entries for enterprise infrastructure products that are also used in hospital environments (Cisco, Fortinet, Citrix). These would be real findings — IT infrastructure CVEs that affect hospital networks.
