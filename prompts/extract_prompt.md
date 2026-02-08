You will extract a JSON record that matches the AdvisoryRecordMVP schema.
Rules:
- Use ONLY information present in ADVISORY_TEXT. Do not guess CVEs, scores, or products.
- If a field is unknown, set it to null (or empty list for list fields).
- Keep summary concise (1–3 sentences).
- Dates should be ISO "YYYY-MM-DD" if present; otherwise null.
- "publisher" for cisa.gov advisories should be "CISA" unless the text clearly indicates otherwise.
- Put actionable mitigations / workarounds / patches into recommended_actions. If none, [].
Return ONLY the JSON object.