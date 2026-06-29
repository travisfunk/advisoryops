# KEV / Medical Device Overlap Analysis

**Date:** 2026-04-09 (original), re-verified 2026-04-13
**Finding:** Zero overlap between CISA KEV entries and medical device records

## Methodology

Compared all issues with KEV enrichment (kev_required_action populated) against all issues classified as medical_device by the healthcare filter. Checked overlap by:
1. CVE ID intersection
2. Vendor name intersection (exact match, lowercased, stripped)
3. Vendor name intersection (partial substring match, length ≥ 4)

## Data

| Metric | 2026-04-09 | 2026-04-13 |
| --- | ---: | ---: |
| Total issues in corpus | 3,929 | 3,724 |
| KEV-enriched issues | 203 | 203 |
| Medical device issues | 856 | 422 |
| Unique KEV CVEs | — | 203 |
| Unique medical_device CVEs | — | 44 |
| CVE overlap | 0 | **0** |
| Vendor exact overlap | 0 | **0** |
| Vendor partial-match pairs (≥4 chars) | — | **0** |

The corpus shrank between the two checks because of two 2026-04-12 missions (medical_device classifier tightening + pharmaceutical exclusion). Zero overlap held through both.

### KEV vendor distribution

The 203 KEV entries span 88 unique vendors, dominated by enterprise IT: Cisco, Microsoft, Apple, Adobe, Fortinet, Ivanti, Google Chrome, VMware, Citrix, BeyondTrust, F5, etc. None overlap with the 151 unique vendors on the medical_device bucket, even allowing partial substring match.

### Medical device source distribution

Medical device records come primarily from: CISA ICS-Medical advisories (ICSMA), openFDA device recalls, FDA safety communications, Philips PSIRT, Siemens ProductCERT, Health Canada recalls.

## Conclusion

The zero overlap is genuine, not a data quality bug. CISA's Known Exploited Vulnerabilities catalog tracks vulnerabilities that are actively exploited at scale in the wild. These tend to be in widely-deployed enterprise software and network infrastructure. Medical device vulnerabilities exist in the NVD and in CISA's ICSMA advisories, but they are not being added to KEV — likely because medical device exploitation at scale hasn't been observed or reported through CISA's KEV inclusion criteria.

## Implications for AdvisoryOps

This finding directly supports the grant narrative:

1. **The federal authoritative source for "known exploited" vulnerabilities has zero medical device coverage.** A hospital security team watching only KEV for patching deadlines would see nothing about their medical devices. This is precisely the gap AdvisoryOps fills.

2. **Medical device security intelligence requires dedicated sources.** The advisories that matter for medical devices (ICSMA, FDA recalls, vendor PSIRTs) exist in separate, specialized channels that general vulnerability platforms don't aggregate.

3. **The `is_kev_medical_device` feature is architecturally correct but reflects a real data gap.** If/when CISA adds medical device CVEs to KEV, the cross-reference will automatically surface them. The feature doesn't need a code fix — it needs the upstream data to exist.

4. **Post-extraction (Problem 3), the vendor overlap check should be re-run.** Once FDA-recall-derived issues have populated vendor fields (e.g., "Abiomed", "Medtronic"), the vendor-matching logic may find partial overlaps with KEV entries for enterprise infrastructure products that are also used in hospital environments (Cisco, Fortinet, Citrix). These would be real findings — IT infrastructure CVEs that affect hospital networks. **Re-run 2026-04-13 after Problem 3 extraction landed: still zero overlap.** The FDA medical device vendors (Philips Medical Systems, Medtronic, St Jude Medical, etc.) do not appear in KEV even as partial matches.

## Verification

Anyone can reproduce the numbers above against the current corpus by running:

```python
import json
with open('docs/feed_latest.json', encoding='utf-8') as f:
    issues = json.load(f)
md = [i for i in issues if i.get('healthcare_category') == 'medical_device']
kev = [i for i in issues if i.get('kev_required_action') or i.get('kev_vulnerability_name')]
md_cves = {c.upper() for i in md for c in (i.get('cves') or [])}
kev_cves = {c.upper() for i in kev for c in (i.get('cves') or [])}
md_vendors = {(i.get('vendor') or '').lower().strip() for i in md if i.get('vendor')}
kev_vendors = {(i.get('vendor') or '').lower().strip() for i in kev if i.get('vendor')}
print(f'medical_device: {len(md)}')
print(f'kev-enriched: {len(kev)}')
print(f'CVE overlap: {len(md_cves & kev_cves)}')
print(f'vendor exact overlap: {len(md_vendors & kev_vendors)}')
```

As of 2026-04-13 this prints:

```
medical_device: 422
kev-enriched: 203
CVE overlap: 0
vendor exact overlap: 0
```

If a future rebuild produces non-zero overlap, the dashboard `is_kev_medical_device` badge will fire automatically, and `feed_medical_device_kev.json` will become non-empty.
