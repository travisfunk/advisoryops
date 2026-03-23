# AdvisoryOps Master Source List

**Last updated:** 2026-03-21
**Purpose:** Authoritative source list for Claude Code to use when expanding `configs/sources.json`.
**How to use:** Claude Code should read this file when working on Phase 1 (Source Expansion) tasks.

---

## How Sources Map to sources.json

Each source below needs these fields in `configs/sources.json`:
- `source_id`: lowercase-kebab-case (e.g., `cisa-icsma`)
- `name`: human-readable name
- `enabled`: true for public sources with working feeds, false for broken/unverified
- `scope`: one of `advisory`, `dataset`, `news`, `threatintel`
- `page_type`: one of `rss_atom`, `json_feed`, `csv_feed` (implemented); or `html_table`, `json_api` (future — set enabled=false)
- `entry_url`: direct feed/API URL
- `filters`: keyword filters for broad sources (e.g., Dark Reading needs healthcare keywords)
- `timeout_s`: 30 (default)
- `retries`: 2 (default)
- `rate_limit_rps`: 1.0 (default)

### Scope Guidelines
- `advisory` — official vulnerability advisories, recalls, safety notices (FDA, CISA, vendor PSIRTs)
- `dataset` — structured vulnerability data (KEV, NVD, EPSS, CVE feeds)
- `news` — cybersecurity news with healthcare/device coverage (Dark Reading, Krebs, etc.)
- `threatintel` — threat indicators, IOCs, malware feeds (Abuse.ch, blocklists, etc.)

### Filter Guidelines for Broad Sources
Sources that cover ALL cybersecurity (not just healthcare/medical) should have keyword filters:
```json
"filters": {
  "apply_to": ["title", "summary"],
  "keywords_any": ["medical", "healthcare", "hospital", "clinical", "patient", "FDA", "device", "IoMT", "PACS", "infusion", "ventilator", "imaging", "biomedical", "pharma", "HIPAA", "HHS", "health system"]
}
```

---

## SECTION 1: Public / Free — No API Key Required

### 1A: Government & Regulatory — Advisory/Dataset Sources

| source_id | Name | URL | Type | Scope |
|---|---|---|---|---|
| fda-medwatch | FDA MedWatch RSS | https://www.fda.gov/AboutFDA/ContactFDA/StayInformed/RSSFeeds/MedWatch/rss.xml | rss_atom | advisory |
| openfda-device-recalls | openFDA Device Recalls API | https://api.fda.gov/device/recall.json | json_feed | advisory |
| openfda-device-events | openFDA Device Events API | https://api.fda.gov/device/event.json | json_feed | advisory |
| cisa-icsma | CISA ICS Medical Advisories RSS | https://www.cisa.gov/cybersecurity-advisories/ics-medical-advisories.xml | rss_atom | advisory |
| cisa-icsa | CISA General ICS Advisories RSS | https://us-cert.cisa.gov/ics/advisories/advisories.xml | rss_atom | advisory |
| cisa-ncas-alerts | CISA NCAS Alerts RSS | https://us-cert.cisa.gov/ncas/alerts.xml | rss_atom | advisory |
| cisa-ncas-analysis | CISA NCAS Analysis Reports RSS | https://us-cert.cisa.gov/ncas/analysis-reports.xml | rss_atom | advisory |
| cisa-ncas-current-activity | CISA NCAS Current Activity RSS | https://us-cert.cisa.gov/ncas/current-activity.xml | rss_atom | advisory |
| cisa-kev-json | CISA KEV JSON | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json | json_feed | dataset |
| cisa-kev-csv | CISA KEV CSV | https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv | csv_feed | dataset |
| imdrf-consultations | IMDRF Consultations RSS | https://www.imdrf.org/consultations.xml | rss_atom | advisory |
| imdrf-documents | IMDRF Documents RSS | https://www.imdrf.org/documents.xml | rss_atom | advisory |
| imdrf-news | IMDRF News RSS | https://www.imdrf.org/news-events/news.xml | rss_atom | news |
| health-canada-recalls | Health Canada Recalls RSS | http://www.healthycanadians.gc.ca/recall-alert-rappel-avis/rss/feed-31-eng.xml | rss_atom | advisory |
| ncsc-uk | NCSC UK RSS | https://www.ncsc.gov.uk/section/information/rss | rss_atom | advisory |
| bsi-germany | BSI Germany RSS | https://www.bsi.bund.de/SiteGlobals/Functions/RSSFeed/RSSNewsfeed/RSSNewsfeed.xml | rss_atom | advisory |
| epss-data | EPSS Data CSV | https://www.first.org/epss/data | csv_feed | dataset |
| certcc-vulnotes | CERT/CC Vulnerability Notes | https://www.kb.cert.org/vuls/atomfeed/ | rss_atom | advisory |
| nist-cyber-insights | NIST Cybersecurity Insights RSS | https://www.nist.gov/blogs/cybersecurity-insights/rss.xml | rss_atom | advisory |
| osv-dev-api | OSV.dev Open Source Vulns API | https://api.osv.dev/v1/query | json_feed | dataset |

### 1B: Vendor PSIRTs & Security Research

| source_id | Name | URL | Type | Scope |
|---|---|---|---|---|
| abb-psirt | ABB PSIRT RSS | https://psirt.abb.com/rss/abbrssfeed.xml | rss_atom | advisory |
| claroty-team82 | Claroty Team82 Research RSS | https://claroty.com/blog/feed | rss_atom | advisory |
| armis-labs | Armis Labs Threat Research RSS | https://www.armis.com/blog/feed/ | rss_atom | advisory |
| asimily-blog | Asimily Blog RSS (IoMT) | https://asimily.com/blog/feed/ | rss_atom | news |
| forescout-vedere | Forescout Vedere Labs Dashboard | https://forescout.vederelabs.com/threat-actors-dashboard | json_feed | threatintel |
| deepstrike-blog | DeepStrike IoMT Blog | https://deepstrike.io/blog/feed | rss_atom | news |
| zdi-published | Zero Day Initiative Published RSS | https://www.zerodayinitiative.com/rss/published/ | rss_atom | advisory |
| zdi-upcoming | Zero Day Initiative Upcoming RSS | https://www.zerodayinitiative.com/rss/upcoming/ | rss_atom | advisory |
| google-project-zero | Google Project Zero RSS | https://googleprojectzero.blogspot.com/feeds/posts/default | rss_atom | advisory |
| microsoft-security-blog | Microsoft Security Blog RSS | https://www.microsoft.com/security/blog/feed/ | rss_atom | news |
| msrc-blog | Microsoft MSRC Blog RSS | https://msrc-blog.microsoft.com/feed/ | rss_atom | advisory |
| talos-intelligence | Cisco Talos Intelligence RSS | http://feeds.feedburner.com/feedburner/Talos | rss_atom | threatintel |
| mandiant-blog | FireEye / Mandiant Blog RSS | http://www.fireeye.com/blog/feed | rss_atom | threatintel |
| checkpoint-research | Check Point Research RSS | https://research.checkpoint.com/feed/ | rss_atom | threatintel |
| tenable-newest | Tenable Newest Plugins RSS | https://www.tenable.com/plugins/feeds?sort=newest | rss_atom | dataset |
| crowdstrike-blog | CrowdStrike Threat Intel Blog RSS | https://www.crowdstrike.com/blog/category/threat-intel-research/ | rss_atom | threatintel |

### 1C: Healthcare-Specific News & Blogs

| source_id | Name | URL | Type | Scope | Needs Filters? |
|---|---|---|---|---|---|
| cyberscoop-healthcare | CyberScoop Healthcare RSS | https://cyberscoop.com/news/healthcare/feed/ | rss_atom | news | No (pre-filtered) |
| hit-consultant-cyber | HIT Consultant Cybersecurity RSS | https://hitconsultant.net/tag/cybersecurity/feed/ | rss_atom | news | No |
| hipaa-guide-cyber | HIPAA Guide Cybersecurity RSS | https://www.hipaaguide.net/healthcare-cybersecurity/feed/ | rss_atom | news | No |
| fortified-health-security | Fortified Health Security Blog RSS | https://fortifiedhealthsecurity.com/feed/ | rss_atom | news | No |
| healthcare-it-news-security | Healthcare IT News Security RSS | https://www.healthcareitnews.com/taxonomy/term/6156/feed | rss_atom | news | No |
| compliance-junction-cyber | Compliance Junction Cybersecurity RSS | https://www.compliancejunction.com/category/cybersecurity/feed/ | rss_atom | news | No |
| beckers-hospital-cyber | Becker's Hospital Review Cyber RSS | https://www.beckershospitalreview.com/healthcare-information-technology/cybersecurity/feed/ | rss_atom | news | No |
| medtech-intelligence | MedTech Intelligence RSS | https://medtechintelligence.com/feed/ | rss_atom | news | No |
| bioworld-digital-health | BioWorld Digital Health RSS | https://www.bioworld.com/rss/21 | rss_atom | news | No |
| fierce-healthcare | Fierce Healthcare RSS | https://www.fiercehealthcare.com/rss | rss_atom | news | Yes (broad) |

### 1D: General Cybersecurity News (NEED keyword filters for healthcare relevance)

| source_id | Name | URL | Type | Scope |
|---|---|---|---|---|
| dark-reading | Dark Reading All RSS | https://www.darkreading.com/rss/all.xml | rss_atom | news |
| krebs-on-security | Krebs on Security RSS | http://krebsonsecurity.com/feed/ | rss_atom | news |
| wired-security | WIRED Security RSS | https://www.wired.com/feed/category/security/latest/rss | rss_atom | news |
| security-magazine-cyber | Security Magazine Cybersecurity RSS | https://www.securitymagazine.com/rss/topic/2666-cybersecurity | rss_atom | news |
| sans-isc | SANS ISC RSS | https://isc.sans.edu/rssfeed_full.xml | rss_atom | threatintel |
| seclists-rss | SecLists.org RSS | https://seclists.org/rss/ | rss_atom | threatintel |
| cshub-attacks | Cyber Security Hub Attacks RSS | https://www.cshub.com/rss/categories/attacks | rss_atom | news |
| cshub-malware | Cyber Security Hub Malware RSS | https://www.cshub.com/rss/categories/malware | rss_atom | news |
| infosec-malware-analysis | Infosec Institute Malware Analysis RSS | https://resources.infosecinstitute.com/topics/malware-analysis/feed/ | rss_atom | news |
| infosec-threat-intel | Infosec Institute Threat Intel RSS | https://resources.infosecinstitute.com/topics/threat-intelligence/feed/ | rss_atom | news |
| cvefeed-rss | CVEfeed RSS | https://cvefeed.io/rssfeed | rss_atom | dataset |
| threatpost | Threatpost RSS (may be defunct) | https://threatpost.com/feed/ | rss_atom | news |

### 1E: Threat Intelligence Feeds (IOCs, IPs, Malware)

| source_id | Name | URL | Type | Scope | Notes |
|---|---|---|---|---|---|
| urlhaus-recent | Abuse.ch URLhaus Recent URLs | https://urlhaus-api.abuse.ch/v1/urls/recent/ | json_feed | threatintel | |
| malwarebazaar-recent | Abuse.ch MalwareBazaar Recent | https://bazaar.abuse.ch/api/ | json_feed | threatintel | Limited public queries |
| threatfox-iocs | ThreatFox IOCs | https://threatfox.abuse.ch/api/v1/ | json_feed | threatintel | |
| cyber-cure-ips | Cyber Cure Infected IPs | https://feeds.cybercure.ai/infected_ips | csv_feed | threatintel | Plain text IP list |
| bambenek-c2 | Bambenek C2 IP Masterlist | http://osint.bambenekconsulting.com/feeds/c2-ipmasterlist.txt | csv_feed | threatintel | Plain text |
| sans-block-ips | SANS ISC Blocklist IPs | https://isc.sans.edu/block.txt | csv_feed | threatintel | Plain text |
| ellio-ip-feed | ELLIO Community IP Feed | https://feed.ellio.tech | csv_feed | threatintel | Plain text |
| binary-defense-banlist | Binary Defense Banlist | https://www.binarydefense.com/banlist.txt | csv_feed | threatintel | Plain text |
| ecrimelabs-metasploit | eCrimeLabs Metasploit CVE Feed | https://feeds.ecrimelabs.net/data/metasploit-cve | csv_feed | dataset | CVE list |

---

## SECTION 2: Free — Requires API Key (register for free)

These are free to use but need a key. Get the key, then uncomment in sources.json.

| source_id | Name | URL | Type | Scope | Get Key At |
|---|---|---|---|---|---|
| nvd-cve-api | NVD CVE API | https://services.nvd.nist.gov/rest/json/cves/2.0 | json_feed | dataset | https://nvd.nist.gov/developers/request-an-api-key |
| virustotal-api | VirusTotal Intelligence API | https://www.virustotal.com/api/v3/intelligence/search | json_feed | threatintel | https://virustotal.com/gui/join-us |
| vulners-api | Vulners.com Vuln API | https://vulners.com/api/v3/search/lucene/ | json_feed | dataset | https://vulners.com/api |
| vuldb-cti-api | VulDB CTI API | https://vuldb.com/?api | json_feed | dataset | https://vuldb.com/?api |

---

## SECTION 3: Commercial / Paid (commented out, placeholders only)

Keep these in sources.json as commented reference. Uncomment if/when subscription is acquired.

### 3A: Dark Web Monitoring

| source_id | Name | Vendor URL | Notes |
|---|---|---|---|
| flashpoint-ignite | Flashpoint Ignite Platform | https://flashpoint.io/ignite/ | Dark web forums, markets, actor comms. Strong healthcare. |
| cyberint-argos | Cyberint (Check Point ERM) | https://www.cyberint.com/ | Dark web actor comms, leaked data. |
| crowdstrike-falcon-intel | CrowdStrike Falcon Adversary Intel | https://www.crowdstrike.com/products/threat-intelligence/ | Healthcare adversary tracking. |
| mandiant-dtm | Google Mandiant Digital Threat Monitoring | https://www.mandiant.com/ | Compromised creds, device threats. |
| flare-darkweb | Flare Dark Web Monitoring | https://flare.io/ | Stealer logs, medical exposures. |
| lunar-webzio | Lunar by Webz.io | https://webz.io/lunar/ | Dark web hacker forums. |
| nordstellar | NordStellar Threat Exposure | https://nordstellar.com/ | Leaked/compromised data. |
| breachsense | Breachsense | https://www.breachsense.com/ | Stealer logs, ransomware leaks. |
| saga-munit | SAGA by Munit.io | https://www.munit.io/saga | Dark web forums, Telegram, markets. |
| cyrx360 | CyRx360 Dark Web Surveillance | https://www.cyrx360.com/ | Healthcare-tailored, HIPAA-compliant. |
| pivot-point-darkweb | Pivot Point Security Dark Web | https://www.pivotpointsecurity.com/ | Healthcare vuln/chatter detection. |
| constella-intel | Constella Intelligence | https://www.constella.ai/ | Identity fraud, device-linked creds. |
| spycloud | Spycloud Enterprise | https://spycloud.com/ | Leaked creds/vulns. |
| trendmicro-darkweb | Trend Micro Dark Web Monitoring | https://www.trendmicro.com/ | Free leak checker + enterprise. |
| caci-darkblue | CACI DarkBlue Intelligence Suite | https://www.caci.com/ | AI-powered dark web actor tracking. |
| socradar-darkweb | SOCRadar Dark Web Monitoring | https://socradar.io/ | Healthcare HIPAA focus. |

### 3B: IoMT / Medical Device Platforms (Full Enterprise)

| source_id | Name | Vendor URL | Notes |
|---|---|---|---|
| vulncheck-iomt | VulnCheck IoMT Advisories | https://docs.vulncheck.com/indices/iomt-security-advisories | IoMT-specific advisory index. |
| forescout-vedere-full | Forescout Vedere Labs (Full) | https://forescout.vederelabs.com/register | Enterprise threat feeds, VL-KEV. |
| armis-full | Armis (Full Platform) | https://www.armis.com/ | AI vuln database, IoMT focus. |
| asimily-full | Asimily (Full Platform) | https://asimily.com/ | IoMT exposure management. |
| claroty-full | Claroty (Full CPS Platform) | https://claroty.com/ | CPS library, healthcare CVEs. |
| recorded-future | Recorded Future Healthcare | https://www.recordedfuture.com/industry/healthcare | Healthcare threat intel. |
| bitsight | Bitsight Cyber Threat Intel | https://www.bitsight.com/ | Healthcare PHI risk scoring. |

### 3C: Other Commercial Threat Intel

| source_id | Name | Vendor URL | Notes |
|---|---|---|---|
| group-ib | Group-IB Threat Feeds | https://www.group-ib.com/ | IP/domain, malware, vuln feeds. |
| esentire-healthcare | eSentire Healthcare Intel | https://www.esentire.com/ | Code Grey healthcare reports. |
| trellix-healthcare | Trellix Healthcare Threat Intel | https://www.trellix.com/ | Annual healthcare threat reports. |

---

## SECTION 4: GitHub Aggregator Repos (reference only — not direct feeds)

These are curated lists of additional feeds. Useful for finding MORE sources but not direct polling targets.

| Name | URL | Notes |
|---|---|---|
| AllInfoSecNews Sources | https://github.com/foorilla/allinfosecnews_sources | 100+ infosec RSS feeds as JSON |
| Awesome Threat Intel RSS | https://github.com/thehappydinoa/awesome-threat-intel-rss | Curated RSS feed collection |
| Awesome Threat Intelligence | https://github.com/hslatman/awesome-threat-intelligence | Sources/APIs/tools list |
| Open-Source Threat Intel Feeds | https://github.com/Bert-JanP/Open-Source-Threat-Intel-Feeds | IOC/vuln feed collection |
| Awesome Vulnerability Research | https://github.com/sergey-pronin/awesome-vulnerability-research | Vuln research resources |
| Awesome Embedded Vuln Research | https://github.com/IamAlch3mist/Awesome-Embedded-Vulnerability-Research | Embedded/device vulns |

---

## SECTION 5: Telegram Channels (reference only — requires bot for parsing)

Not yet implemented. Kept here for future consideration if bot integration is worth the effort.

| Channel | Handle/Link | Subscribers | Relevance |
|---|---|---|---|
| Cyber Security News | t.me/cyber_security_channel | ~11k | Breaking cyber news |
| Android Security & Malware | t.me/androidMalware | ~12k | Mobile-connected medical apps |
| Malware Research | t.me/MalwareResearch | ~4k | Malware analysis articles |
| BugCrowd | t.me/BugCrowd | ~3k | Bug bounty / vuln disclosures |
| APT Intelligence | t.me/joinchat/H_eE5BLOna5xr7PR28iqpg | ~1k | State-sponsored healthcare attacks |
| Data Leak Monitor | Search Telegram | ~25k | Real-time leak detection |
| Daily Dark Web | Search Telegram | Unknown | Ransomware victim digests |
| Ransomlook | Search Telegram | Unknown | Daily ransomware posts |

---

## Summary Counts

| Category | Count |
|---|---|
| Section 1: Public / Free (no key) | ~75 sources |
| Section 2: Free with API key | 4 sources |
| Section 3: Commercial / Paid | ~26 sources |
| Section 4: GitHub repos (reference) | 6 repos |
| Section 5: Telegram (future) | 8 channels |
| **Total parseable sources** | **~105 direct + reference** |

**Note:** Many Section 1 sources are already in `sources.json`. Claude Code should diff this list against the current config to find what's missing and add it.
