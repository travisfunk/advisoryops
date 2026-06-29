---
name: "Report a bad merge"
about: "Two advisories were incorrectly combined into one issue record"
labels: ["data-quality", "merge-error"]
assignees: ''
---

## Bad Merge Report

**issue_id:**
<!-- The merged issue ID you believe is wrong. Find this in the feed or dashboard. -->


**source_id_a:**
<!-- The source_id of the first advisory that was merged (e.g., cisa-icsma) -->


**source_id_b:**
<!-- The source_id of the second advisory that was merged (e.g., philips-psirt) -->


**why_wrong:**
<!--
Explain why you believe these two advisories should be separate issues.
Examples of valid reasons:
  - They describe different CVEs with no overlap
  - They affect completely different vendors or product families
  - One is a software vulnerability; the other is a hardware recall
  - The published dates are far apart with no editorial link between them
-->


**expected_behavior:**
<!--
What would you expect to see instead?
Examples:
  - Two separate issues, one for each CVE
  - Source B's advisory should appear as its own entry with its own issue_id
-->


**additional_context:**
<!-- Optional: paste relevant title/summary text, source URLs, or screenshots -->


---

- [ ] I have searched existing issues to avoid duplicates
