# AdvisoryOps Master Source List (COMPLETE)

**Last updated:** 2026-03-21
**Purpose:** Authoritative, COMPLETE source list for Claude Code. Every parseable source from the full compilation.
**How to use:** Claude Code should diff this against `configs/sources.json` and add ALL missing sources.

---

## How Sources Map to sources.json

Each source needs these fields in `configs/sources.json`:
- `source_id`: lowercase-kebab-case (e.g., `cisa-icsma`)
- `name`: human-readable name
- `enabled`: true for sources with working feeds, false for unverified/broken/future
- `scope`: one of `advisory`, `dataset`, `news`, `threatintel`
- `page_type`: one of `rss_atom`, `json_feed`, `csv_feed` (implemented); or `html_table`, `html_generic`, `json_api`, `txt_feed` (future — set enabled=false)
- `entry_url`: direct feed/API URL
- `filters`: keyword filters for broad sources
- `timeout_s`: 30 (default)
- `retries`: 2 (default)
- `rate_limit_rps`: 1.0 (default)

### Scope Guidelines
- `advisory` — official vulnerability advisories, recalls, safety notices
- `dataset` — structured vulnerability data (KEV, NVD, EPSS, CVE feeds)
- `news` — cybersecurity news with healthcare/device coverage
- `threatintel` — threat indicators, IOCs, malware feeds

### Healthcare Keyword Filters (apply to broad/general sources)
```json
"filters": {
  "apply_to": ["title", "summary"],
  "keywords_any": ["medical", "healthcare", "hospital", "clinical", "patient", "FDA", "device", "IoMT", "PACS", "infusion", "ventilator", "imaging", "biomedical", "pharma", "HIPAA", "HHS", "health system"]
}
```

---

## SECTION 1: Public / Free — No API Key Required

### 1A: Government & Regulatory Sources

| # | source_id | Name | URL | page_type | scope | enabled | notes |
|---|---|---|---|---|---|---|---|
| 1 | fda-medwatch | FDA MedWatch RSS | https://www.fda.gov/AboutFDA/ContactFDA/StayInformed/RSSFeeds/MedWatch/rss.xml | rss_atom | advisory | true | |
| 2 | openfda-device-recalls | openFDA Device Recalls API | https://api.fda.gov/device/recall.json | json_feed | advisory | true | No key needed |
| 3 | openfda-device-events | openFDA Device Adverse Events API | https://api.fda.gov/device/event.json | json_feed | advisory | true | No key needed |
| 4 | cisa-icsma | CISA ICS Medical Advisories RSS | https://www.cisa.gov/cybersecurity-advisories/ics-medical-advisories.xml | rss_atom | advisory | true | |
| 5 | cisa-icsa | CISA General ICS Advisories RSS | https://us-cert.cisa.gov/ics/advisories/advisories.xml | rss_atom | advisory | true | |
| 6 | cisa-ncas-alerts | CISA NCAS Alerts RSS | https://us-cert.cisa.gov/ncas/alerts.xml | rss_atom | advisory | true | |
| 7 | cisa-ncas-analysis | CISA NCAS Analysis Reports RSS | https://us-cert.cisa.gov/ncas/analysis-reports.xml | rss_atom | advisory | true | |
| 8 | cisa-ncas-current-activity | CISA NCAS Current Activity RSS | https://us-cert.cisa.gov/ncas/current-activity.xml | rss_atom | advisory | true | |
| 9 | cisa-kev-json | CISA KEV JSON | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json | json_feed | dataset | true | |
| 10 | cisa-kev-csv | CISA KEV CSV | https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv | csv_feed | dataset | true | |
| 11 | certcc-vulnotes | CERT/CC Vulnerability Notes | https://www.kb.cert.org/vuls/atomfeed/ | rss_atom | advisory | true | |
| 12 | imdrf-consultations | IMDRF Consultations RSS | https://www.imdrf.org/consultations.xml | rss_atom | advisory | true | |
| 13 | imdrf-documents | IMDRF Documents RSS | https://www.imdrf.org/documents.xml | rss_atom | advisory | true | |
| 14 | imdrf-news | IMDRF News RSS | https://www.imdrf.org/news-events/news.xml | rss_atom | news | true | |
| 15 | health-canada-recalls | Health Canada Recalls RSS | http://www.healthycanadians.gc.ca/recall-alert-rappel-avis/rss/feed-31-eng.xml | rss_atom | advisory | true | |
| 16 | ncsc-uk | NCSC UK RSS | https://www.ncsc.gov.uk/section/information/rss | rss_atom | advisory | true | |
| 17 | bsi-germany | BSI Germany RSS | https://www.bsi.bund.de/SiteGlobals/Functions/RSSFeed/RSSNewsfeed/RSSNewsfeed.xml | rss_atom | advisory | true | |
| 18 | nist-cyber-insights | NIST Cybersecurity Insights RSS | https://www.nist.gov/blogs/cybersecurity-insights/rss.xml | rss_atom | advisory | true | |
| 19 | epss-data | EPSS Data CSV | https://epss.cyentia.com/epss_scores-current.csv.gz | csv_feed | dataset | false | Gzipped CSV, needs special handling |
| 20 | epss-api | EPSS API | https://api.first.org/data/v1/epss | json_feed | dataset | true | Free, no key |
| 21 | cis-advisories | Center for Internet Security Advisories RSS | https://www.cisecurity.org/feed/advisories | rss_atom | advisory | true | |
| 22 | osv-dev-api | OSV.dev Open Source Vulns API | https://api.osv.dev/v1/query | json_feed | dataset | false | POST-only API, needs custom handler |

### 1B: Vendor PSIRTs & Security Research

| # | source_id | Name | URL | page_type | scope | enabled | notes |
|---|---|---|---|---|---|---|---|
| 23 | abb-psirt | ABB PSIRT RSS | https://psirt.abb.com/rss/abbrssfeed.xml | rss_atom | advisory | true | |
| 24 | claroty-team82 | Claroty Team82 Research RSS | https://claroty.com/blog/feed | rss_atom | advisory | true | |
| 25 | armis-labs | Armis Labs Threat Research RSS | https://www.armis.com/blog/feed/ | rss_atom | advisory | true | |
| 26 | asimily-blog | Asimily Blog RSS (IoMT) | https://asimily.com/blog/feed/ | rss_atom | news | true | |
| 27 | zdi-published | Zero Day Initiative Published RSS | https://www.zerodayinitiative.com/rss/published/ | rss_atom | advisory | true | |
| 28 | zdi-upcoming | Zero Day Initiative Upcoming RSS | https://www.zerodayinitiative.com/rss/upcoming/ | rss_atom | advisory | true | |
| 29 | google-project-zero | Google Project Zero RSS | https://googleprojectzero.blogspot.com/feeds/posts/default | rss_atom | advisory | true | |
| 30 | microsoft-security-blog | Microsoft Security Blog RSS | https://www.microsoft.com/security/blog/feed/ | rss_atom | news | true | Needs filters |
| 31 | msrc-blog | Microsoft MSRC Blog RSS | https://msrc-blog.microsoft.com/feed/ | rss_atom | advisory | true | |
| 32 | talos-intelligence | Cisco Talos Intelligence RSS | http://feeds.feedburner.com/feedburner/Talos | rss_atom | threatintel | true | Needs filters |
| 33 | mandiant-blog | FireEye / Mandiant Blog RSS | http://www.fireeye.com/blog/feed | rss_atom | threatintel | true | Needs filters |
| 34 | checkpoint-research | Check Point Research RSS | https://research.checkpoint.com/feed/ | rss_atom | threatintel | true | Needs filters |
| 35 | tenable-newest | Tenable Newest Plugins RSS | https://www.tenable.com/plugins/feeds?sort=newest | rss_atom | dataset | true | Needs filters |
| 36 | crowdstrike-blog | CrowdStrike Threat Intel Blog | https://www.crowdstrike.com/blog/category/threat-intel-research/ | rss_atom | threatintel | true | Needs filters |
| 37 | forescout-vedere | Forescout Vedere Labs Dashboard | https://forescout.vederelabs.com/threat-actors-dashboard | json_feed | threatintel | false | Dashboard not feed, needs verification |
| 38 | deepstrike-blog | DeepStrike IoMT Blog | https://deepstrike.io/blog/feed | rss_atom | news | false | Feed existence unverified |

### 1C: Healthcare-Specific News & Blogs

| # | source_id | Name | URL | page_type | scope | enabled | notes |
|---|---|---|---|---|---|---|---|
| 39 | cyberscoop-healthcare | CyberScoop Healthcare RSS | https://cyberscoop.com/news/healthcare/feed/ | rss_atom | news | true | Pre-filtered |
| 40 | hit-consultant-cyber | HIT Consultant Cybersecurity RSS | https://hitconsultant.net/tag/cybersecurity/feed/ | rss_atom | news | true | |
| 41 | hipaa-guide-cyber | HIPAA Guide Cybersecurity RSS | https://www.hipaaguide.net/healthcare-cybersecurity/feed/ | rss_atom | news | true | |
| 42 | fortified-health-security | Fortified Health Security Blog RSS | https://fortifiedhealthsecurity.com/feed/ | rss_atom | news | true | |
| 43 | healthcare-it-news-security | Healthcare IT News Security RSS | https://www.healthcareitnews.com/taxonomy/term/6156/feed | rss_atom | news | true | |
| 44 | compliance-junction-cyber | Compliance Junction Cybersecurity RSS | https://www.compliancejunction.com/category/cybersecurity/feed/ | rss_atom | news | true | |
| 45 | beckers-hospital-cyber | Becker's Hospital Review Cyber RSS | https://www.beckershospitalreview.com/healthcare-information-technology/cybersecurity/feed/ | rss_atom | news | true | |
| 46 | medtech-intelligence | MedTech Intelligence RSS | https://medtechintelligence.com/feed/ | rss_atom | news | true | |
| 47 | bioworld-digital-health | BioWorld Digital Health RSS | https://www.bioworld.com/rss/21 | rss_atom | news | true | |
| 48 | fierce-healthcare | Fierce Healthcare RSS | https://www.fiercehealthcare.com/rss | rss_atom | news | true | Needs filters (broad) |

### 1D: General Cybersecurity News (NEED healthcare keyword filters)

| # | source_id | Name | URL | page_type | scope | enabled | notes |
|---|---|---|---|---|---|---|---|
| 49 | dark-reading | Dark Reading All RSS | https://www.darkreading.com/rss/all.xml | rss_atom | news | true | |
| 50 | krebs-on-security | Krebs on Security RSS | http://krebsonsecurity.com/feed/ | rss_atom | news | true | |
| 51 | wired-security | WIRED Security RSS | https://www.wired.com/feed/category/security/latest/rss | rss_atom | news | true | |
| 52 | security-magazine-cyber | Security Magazine Cybersecurity RSS | https://www.securitymagazine.com/rss/topic/2666-cybersecurity | rss_atom | news | true | |
| 53 | zdnet-security | ZDNet Security RSS | https://www.zdnet.com/topic/security/rss.xml | rss_atom | news | true | |
| 54 | sans-isc | SANS ISC RSS | https://isc.sans.edu/rssfeed_full.xml | rss_atom | threatintel | true | |
| 55 | seclists-rss | SecLists.org RSS | https://seclists.org/rss/ | rss_atom | threatintel | true | |
| 56 | cshub-attacks | Cyber Security Hub Attacks RSS | https://www.cshub.com/rss/categories/attacks | rss_atom | news | true | |
| 57 | cshub-malware | Cyber Security Hub Malware RSS | https://www.cshub.com/rss/categories/malware | rss_atom | news | true | |
| 58 | infosec-malware-analysis | Infosec Institute Malware Analysis RSS | https://resources.infosecinstitute.com/topics/malware-analysis/feed/ | rss_atom | news | true | |
| 59 | infosec-threat-intel | Infosec Institute Threat Intel RSS | https://resources.infosecinstitute.com/topics/threat-intelligence/feed/ | rss_atom | news | true | |
| 60 | cvefeed-rss | CVEfeed RSS | https://cvefeed.io/rssfeed | rss_atom | dataset | true | |
| 61 | threatpost | Threatpost RSS | https://threatpost.com/feed/ | rss_atom | news | false | Defunct as of late 2023 |

### 1E: Threat Intelligence Feeds (IOCs, IPs, Malware, Blocklists)

| # | source_id | Name | URL | page_type | scope | enabled | notes |
|---|---|---|---|---|---|---|---|
| 62 | urlhaus-recent | Abuse.ch URLhaus Recent URLs | https://urlhaus-api.abuse.ch/v1/urls/recent/ | json_feed | threatintel | true | |
| 63 | malwarebazaar-recent | Abuse.ch MalwareBazaar Recent | https://bazaar.abuse.ch/api/ | json_feed | threatintel | false | Limited public queries |
| 64 | threatfox-iocs | ThreatFox IOCs | https://threatfox.abuse.ch/api/v1/ | json_feed | threatintel | true | |
| 65 | ssl-blacklist | Abuse.ch SSL Blacklist | https://sslbl.abuse.ch/blacklist/sslblacklist.csv | csv_feed | threatintel | true | |
| 66 | feodo-tracker | Abuse.ch Feodo Tracker | https://feodotracker.abuse.ch/downloads/ipblocklist.csv | csv_feed | threatintel | true | |
| 67 | cyber-cure-ips | Cyber Cure Infected IPs | https://feeds.cybercure.ai/infected_ips | csv_feed | threatintel | true | Plain text IP list |
| 68 | bambenek-c2 | Bambenek C2 IP Masterlist | http://osint.bambenekconsulting.com/feeds/c2-ipmasterlist.txt | csv_feed | threatintel | true | |
| 69 | sans-block-ips | SANS ISC Blocklist IPs | https://isc.sans.edu/block.txt | csv_feed | threatintel | true | |
| 70 | ellio-ip-feed | ELLIO Community IP Feed | https://feed.ellio.tech | csv_feed | threatintel | true | |
| 71 | binary-defense-banlist | Binary Defense Banlist | https://www.binarydefense.com/banlist.txt | csv_feed | threatintel | true | |
| 72 | ecrimelabs-metasploit | eCrimeLabs Metasploit CVE Feed | https://feeds.ecrimelabs.net/data/metasploit-cve | csv_feed | dataset | true | |
| 73 | emerging-threats | Emerging Threats Rulesets | https://rules.emergingthreats.net/ | csv_feed | threatintel | false | Needs specific file path |
| 74 | alienvault-otx | AlienVault OTX Pulse Feed | https://otx.alienvault.com/api/v1/pulses/subscribed | json_feed | threatintel | false | Needs free API key (OTX account) |
| 75 | shadowserver-reports | Shadowserver Foundation Reports | https://www.shadowserver.org/ | json_feed | threatintel | false | Needs registration |
| 76 | circl-misp | CIRCL MISP Feeds | https://www.circl.lu/doc/misp/ | json_feed | threatintel | false | Needs MISP setup |

### 1F: Additional RSS Feeds Identified in Grok Deep Search

| # | source_id | Name | URL | page_type | scope | enabled | notes |
|---|---|---|---|---|---|---|---|
| 77 | nhs-digital-cyber | NHS Digital Cyber Alerts | https://digital.nhs.uk/ | json_feed | advisory | false | REST API, needs access request |
| 78 | levelblue-labs | LevelBlue Labs Open Threat Data | https://levelblue.com/ | json_feed | threatintel | false | Needs verification of feed endpoint |
| 79 | wiz-threat-landscape | Wiz Cloud Threat Landscape | https://threats.wiz.io/ | json_feed | threatintel | false | Cloud-specific, needs verification |

---

## SECTION 2: Free — Requires API Key (register for free)

| # | source_id | Name | URL | page_type | scope | Get Key At |
|---|---|---|---|---|---|---|
| 80 | nvd-cve-api | NVD CVE API | https://services.nvd.nist.gov/rest/json/cves/2.0 | json_feed | dataset | https://nvd.nist.gov/developers/request-an-api-key |
| 81 | virustotal-api | VirusTotal Intelligence API | https://www.virustotal.com/api/v3/intelligence/search | json_feed | threatintel | https://virustotal.com/gui/join-us |
| 82 | vulners-api | Vulners.com Vuln API | https://vulners.com/api/v3/search/lucene/ | json_feed | dataset | https://vulners.com/api |
| 83 | vuldb-cti-api | VulDB CTI API | https://vuldb.com/?api | json_feed | dataset | https://vuldb.com/?api |
| 84 | cve-search-circl | CVE Search (CIRCL) API | https://cve.circl.lu/api/ | json_feed | dataset | Free, may need registration |

---

## SECTION 3: Commercial / Paid (commented out, placeholders only)

### 3A: Dark Web Monitoring

| # | source_id | Name | Vendor URL |
|---|---|---|---|
| 85 | flashpoint-ignite | Flashpoint Ignite Platform | https://flashpoint.io/ignite/ |
| 86 | cyberint-argos | Cyberint (Check Point ERM) | https://www.cyberint.com/ |
| 87 | crowdstrike-falcon-intel | CrowdStrike Falcon Adversary Intel | https://www.crowdstrike.com/products/threat-intelligence/ |
| 88 | mandiant-dtm | Google Mandiant Digital Threat Monitoring | https://www.mandiant.com/ |
| 89 | flare-darkweb | Flare Dark Web Monitoring | https://flare.io/ |
| 90 | lunar-webzio | Lunar by Webz.io | https://webz.io/lunar/ |
| 91 | nordstellar | NordStellar Threat Exposure | https://nordstellar.com/ |
| 92 | breachsense | Breachsense | https://www.breachsense.com/ |
| 93 | saga-munit | SAGA by Munit.io | https://www.munit.io/saga |
| 94 | cyrx360 | CyRx360 Dark Web Surveillance | https://www.cyrx360.com/ |
| 95 | pivot-point-darkweb | Pivot Point Security Dark Web | https://www.pivotpointsecurity.com/ |
| 96 | constella-intel | Constella Intelligence | https://www.constella.ai/ |
| 97 | spycloud | Spycloud Enterprise | https://spycloud.com/ |
| 98 | trendmicro-darkweb | Trend Micro Dark Web Monitoring | https://www.trendmicro.com/ |
| 99 | caci-darkblue | CACI DarkBlue Intelligence Suite | https://www.caci.com/ |
| 100 | socradar-darkweb | SOCRadar Dark Web Monitoring | https://socradar.io/ |

### 3B: IoMT / Medical Device Platforms (Enterprise)

| # | source_id | Name | Vendor URL |
|---|---|---|---|
| 101 | vulncheck-iomt | VulnCheck IoMT Advisories | https://docs.vulncheck.com/indices/iomt-security-advisories |
| 102 | forescout-vedere-full | Forescout Vedere Labs (Full) | https://forescout.vederelabs.com/register |
| 103 | armis-full | Armis (Full Platform) | https://www.armis.com/ |
| 104 | asimily-full | Asimily (Full Platform) | https://asimily.com/ |
| 105 | claroty-full | Claroty (Full CPS Platform) | https://claroty.com/ |
| 106 | recorded-future | Recorded Future Healthcare | https://www.recordedfuture.com/industry/healthcare |
| 107 | bitsight | Bitsight Cyber Threat Intel | https://www.bitsight.com/ |
| 108 | trimedx | TRIMEDX Vuln Management (82 sources) | https://www.trimedx.com/ |
| 109 | medcrypt-helm | Medcrypt Helm | https://www.medcrypt.com/ |
| 110 | finite-state | Finite State Medical Device Security | https://finitestate.io/ |

### 3C: Other Commercial Threat Intel

| # | source_id | Name | Vendor URL |
|---|---|---|---|
| 111 | group-ib | Group-IB Threat Feeds | https://www.group-ib.com/ |
| 112 | esentire-healthcare | eSentire Healthcare Intel | https://www.esentire.com/ |
| 113 | trellix-healthcare | Trellix Healthcare Threat Intel | https://www.trellix.com/ |
| 114 | stellar-cyber | Stellar Cyber | https://stellarcyber.ai/ |
| 115 | efficientip-dns | EfficientIP DNS Threat Pulse | https://www.efficientip.com/ |
| 116 | netscout-atlas | NETSCOUT ATLAS Intelligence Feed | https://www.netscout.com/ |
| 117 | feedly-threat-intel | Feedly Threat Intelligence | https://feedly.com/ |

---

## SECTION 4: Reference-Only Sources (not direct feeds)

### GitHub Aggregator Repos
| # | Name | URL |
|---|---|---|
| 118 | AllInfoSecNews Sources | https://github.com/foorilla/allinfosecnews_sources |
| 119 | Awesome Threat Intel RSS | https://github.com/thehappydinoa/awesome-threat-intel-rss |
| 120 | Awesome Threat Intelligence | https://github.com/hslatman/awesome-threat-intelligence |
| 121 | Open-Source Threat Intel Feeds | https://github.com/Bert-JanP/Open-Source-Threat-Intel-Feeds |
| 122 | Awesome Vulnerability Research | https://github.com/sergey-pronin/awesome-vulnerability-research |
| 123 | Awesome Embedded Vuln Research | https://github.com/IamAlch3mist/Awesome-Embedded-Vulnerability-Research |

### Report/PDF Sources (not live feeds, periodic downloads)
| # | Name | URL | Notes |
|---|---|---|---|
| 124 | HSCC 405(d) HICP | https://healthsectorcouncil.org/ | Best practices PDF |
| 125 | HSCC MedTech Vuln Toolkit | https://healthsectorcouncil.org/medtech-vulnerability-communications-toolkit/ | PDF |
| 126 | HSCC Managing Legacy Tech | https://healthsectorcouncil.org/ | PDF |
| 127 | HSCC Model Contract v2 | https://healthsectorcouncil.org/model-contract-language-for-medtech-cybersecurity/ | PDF |
| 128 | HSCC Cyber Strategic Plan | https://healthsectorcouncil.org/cyber-strategic-plan/ | PDF |
| 129 | HSCC SMART Toolkit | https://healthsectorcouncil.org/smart-toolkit/ | PDF |
| 130 | RunSafe Medical Device Index | https://runsafesecurity.com/whitepaper/medical-device-index-2025/ | Annual whitepaper |
| 131 | Health-ISAC Annual Threat Report | https://health-isac.org/ | Annual PDF |
| 132 | ICIJ Medical Devices Database | https://medicaldevices.icij.org/ | Searchable, CSV export |
| 133 | EUDAMED Vigilance Reports | https://ec.europa.eu/tools/eudamed | EU portal |
| 134 | Australia TGA Known Vulns | https://www.tga.gov.au/ | Database, email alerts |

### Telegram Channels (future — requires bot)
| # | Channel | Handle |
|---|---|---|
| 135 | Cyber Security News | t.me/cyber_security_channel |
| 136 | Android Security & Malware | t.me/androidMalware |
| 137 | Malware Research | t.me/MalwareResearch |
| 138 | BugCrowd | t.me/BugCrowd |
| 139 | APT Intelligence | t.me/joinchat/H_eE5BLOna5xr7PR28iqpg |
| 140 | Data Leak Monitor | Search Telegram |
| 141 | Daily Dark Web | Search Telegram |
| 142 | Ransomlook | Search Telegram |

---

## Summary Counts

| Category | Count | Enabled (est.) |
|---|---|---|
| Section 1: Public/Free (no key) | 79 | ~65 |
| Section 2: Free with API key | 5 | 0 (need keys) |
| Section 3: Commercial/Paid | 33 | 0 (need subscriptions) |
| Section 4: Reference/Reports/Telegram | 25 | N/A |
| **Grand Total** | **142** | **~65 immediately** |

### Sources Code Should Add (not yet in sources.json as of Task 1.2)
After Task 1.2 added 34 sources (69 total), these are STILL MISSING from sources.json:

**From 1A (add immediately):**
- epss-api (#20)
- cis-advisories (#21)

**From 1B (add immediately):**
- (all should be present after Task 1.2)

**From 1D (add immediately):**
- zdnet-security (#53)

**From 1E (add immediately):**
- ssl-blacklist (#65)
- feodo-tracker (#66)
- emerging-threats (#73 — disabled)
- alienvault-otx (#74 — disabled, needs free key)
- shadowserver-reports (#75 — disabled)
- circl-misp (#76 — disabled)

**From 1F (add as disabled):**
- nhs-digital-cyber (#77)
- levelblue-labs (#78)
- wiz-threat-landscape (#79)

**From Section 2 (add as disabled with key placeholders):**
- nvd-cve-api (#80)
- virustotal-api (#81)
- vulners-api (#82)
- vuldb-cti-api (#83)
- cve-search-circl (#84)

**From Section 3 (add as disabled/commented):**
- All 33 commercial sources as disabled entries with notes

This brings the total `sources.json` entries to ~120+ (with ~70 enabled, ~50 disabled/placeholder).
