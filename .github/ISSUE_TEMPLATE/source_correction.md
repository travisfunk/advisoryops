---
name: "Report a source issue or suggest a new source"
about: "A source URL is broken, outdated, or you want to suggest a new source"
labels: ["sources"]
assignees: ''
---

## Source Issue / New Source Suggestion

**source_id:**
<!-- The source_id from configs/sources.json — or "new" if you are suggesting a new source -->


**issue_type:**
<!-- Select one by replacing [ ] with [x] -->
- [ ] Broken URL (returns 404 or error)
- [ ] Outdated URL (feed moved to a new address)
- [ ] Wrong feed type (URL works but returns wrong content format)
- [ ] Suggest new source


**current_url:**
<!-- The URL currently configured for this source (leave blank if suggesting a new source) -->


**correct_url:**
<!-- The correct or replacement URL -->


**source_name:**
<!-- Full human-readable name of the source (e.g., "Philips Product Security Advisory") -->


**scope:**
<!-- For new sources — select one by replacing [ ] with [x] -->
- [ ] advisory (structured vulnerability/safety advisories)
- [ ] dataset (recall databases, NVD-style structured data)
- [ ] news (security news with healthcare/ICS relevance)
- [ ] threatintel (IOCs, threat actor activity)


**healthcare_relevance:**
<!-- For new sources — select one by replacing [ ] with [x] -->
- [ ] high (directly covers medical devices, ICS/OT in healthcare, or FDA/CISA advisories)
- [ ] medium (covers healthcare IT broadly, or vendor PSIRTs with some medical device exposure)
- [ ] low (general cybersecurity with occasional healthcare relevance)


**notes:**
<!--
Why is this source valuable for medical device or healthcare security?
What makes a strong source for AdvisoryOps:
  - Consistent publishing schedule (not ad hoc)
  - Machine-readable format (RSS, JSON API, or structured CSV)
  - Direct relevance to medical devices, ICS/OT, or healthcare cybersecurity
  - Publicly accessible (no login or subscription required)
-->


---

- [ ] I have searched existing issues to avoid duplicates
