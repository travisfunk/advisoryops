# AdvisoryOps Grant Strategy Document v2

**Last updated:** March 23, 2026
**Purpose:** Complete strategic foundation for the OpenAI Cybersecurity Grant application. Includes narrative, market data, competitive landscape, reviewer gap analysis, and development roadmap.
**Target:** OpenAI Cybersecurity Grant Program / Trusted Access for Cyber
**Applicant:** Travis Funkhouser — solo founder, 20+ year healthcare security veteran

---

## 1. PERSONAL NARRATIVE ARC

### The Thread That Connects Everything

Travis Funkhouser didn't decide to build AdvisoryOps from a whiteboard. He built it because he spent two decades watching hospitals struggle with the same problem — and nobody fixed it.

**Chapter 1: The Conficker Wake-Up Call (IU Health, 2009-2013)**

Indiana University Health — the largest healthcare system in Indiana. Eight campuses. 22,000+ employees. 125,000 networked devices. When Conficker hit, campuses went offline. The organization fell back to paper procedures for over a week.

The security team could push patches to IT-managed systems. But clinical engineering was a separate group. And some of their systems — like GE PACS — were Windows PCs on the hospital clinical network with radiology equipment attached, owned and managed by GE, not the hospital. The FDA at the time didn't allow hospitals to modify medical devices for security issues. So the infected radiology machines sat on the network spewing propagation traffic while GE took weeks to respond.

Travis's team improvised. They used VLANs to isolate each infected machine onto its own network segment and only allowed the required traffic off the VLAN to reach the server. It didn't fix the infected machines, but it stopped them from saturating the network.

**This is literally the SEGMENTATION_VLAN_ISOLATION pattern now codified in the AdvisoryOps mitigation playbook.** What took days of improvisation in 2009 is now a structured, parameterized defensive action that the system can recommend in seconds.

**The Dolphin Scanner Incident:** Barcode scanners used hospital-wide for medication administration — nurse scans a patient record, scans a medication, administers the medication. A firmware update from the vendor stripped the EHR patient ID from scans and injected bad data. Patient safety issue. Travis wrote a script to remotely connect to every Dolphin scanner by vendor MAC address, check the firmware banner, identify impacted devices, and push their MAC addresses to a wireless network blocklist. Manual, creative, effective — but entirely improvised because there was no system to tell them which devices were affected or what to do about it.

**The Infusion Pump Scanning Incident:** During network security assessments at IU Health, active vulnerability scanning caused infusion pumps (Alaris/Baxter models) to crash and reboot mid-therapy, triggering alarms and requiring clinical staff to manually intervene and reprogram each affected device. This is a well-documented industry problem — NIST, Armis, and multiple vendors have confirmed that standard security scanning tools can adversely affect fragile medical device firmware. It's why many hospitals simply don't scan their medical devices at all, leaving them as permanent blind spots.

NOTE: This sets up a key argument — the traditional scan-find-patch approach doesn't work for medical devices. You can't scan them safely, you often can't patch them, and the vendor may take months to respond. AdvisoryOps takes a fundamentally different approach: monitor the advisory ecosystem, normalize the intelligence, and recommend defensive actions that protect the device without touching it.

**The common thread across all incidents:** hospitals were left doing trial and error, piecing together information from forums, vendor contacts, and other practitioners. There was nothing to analyze all the advisory information, combine it, and produce usable front-line guidance.

**Chapter 2: Defining the Problem Industrially (ForeScout, 2014-2017)**

Travis joined ForeScout and built their healthcare vertical from scratch. He wrote the first medical device classification policy covering 200+ device types — the document that defined how ForeScout (and much of the industry) categorized medical devices for network access control.

This work gave him a systematic view of the problem: hospitals have thousands of device types from hundreds of vendors, running different firmware versions, with different patch cycles, different ownership models (hospital-managed vs. vendor-managed), and different patient safety implications. Generic vulnerability feeds don't help because they don't account for any of this context.

ForeScout went to IPO. The healthcare vertical Travis built drove 35% sales increases. But ForeScout is an enterprise product with enterprise pricing. The small and rural hospitals that need this most can't afford it.

KEY DETAIL FOR GAP #1: During years in healthcare security sales at both ForeScout and Attivo, Travis routinely encountered hospitals that achieved technical wins during POC/POV evaluations and met all requirements, but then the budget disappeared when it came time to actually procure. The technical need was validated repeatedly — the price point was the barrier.

**Chapter 3: Seeing What Attackers See (Attivo Networks, 2017-2022)**

At Attivo, Travis designed the first medical device decoys — deception technology that mimics medical devices on the network to detect attackers targeting healthcare infrastructure. This gave him the attacker's perspective: what do threat actors look for when they penetrate a hospital network? Medical devices — because they're often unpatched, running legacy OS, and connected to sensitive clinical systems.

He achieved a 100% technical win rate. He drove $6M+ in ARR growth focused on healthcare. Attivo was acquired by SentinelOne.

**Chapter 4: The Dark Web Perspective (Flashpoint, 2022-2023)**

At Flashpoint, Travis partnered with Fortune 500 healthcare clients on dark web threat intelligence. Key observation: stolen EMR records contain everything needed for identity theft and are significantly more valuable on the dark web than compromised credit cards — which is why hospitals are specifically targeted. Most of what surfaced was compromised admin credentials exposing access to hospital systems including medical devices, EHRs, and clinical networks. Also observed: threat actors discussing default passwords for medical devices on dark web forums.

This connects to AdvisoryOps: compromised admin credentials are how attackers get TO the medical devices. The advisory pipeline helps defenders lock down the devices before compromised credentials become a path to patient harm.

**Chapter 5: Building the Solution (AdvisoryOps, 2026)**

Every chapter taught Travis something:
- Conficker taught him that hospitals need pre-built defensive playbooks, not improvisation
- The Dolphin and pump incidents taught him that advisory information is fragmented and unusable
- ForeScout taught him that the problem is systemic and needs classification at scale
- Attivo taught him what attackers target and why medical devices are uniquely vulnerable
- Flashpoint taught him that hospitals are specifically targeted for their high-value data

AdvisoryOps is the system he wished existed at every one of those jobs.

---

## 2. MARKET DATA AND EVIDENCE

### The Advisory Flood
- 48,185 CVEs published in 2025 — an all-time record (source: Jerry Gamblin 2025 CVE Data Review)
- ~4,000 new CVEs per month, ~1,000 per week
- 29% of known exploited vulnerabilities were exploited within 24 hours of disclosure (source: VulnCheck 2026 report)
- CISA adds ~53 new KEV entries per month (source: VulnCheck Q1 2025)
- The EU Cyber Resilience Act (2026) will require manufacturers to notify authorities of actively exploited vulnerabilities within 24 hours

### Rural Hospital Financial Crisis
- 46% of rural hospitals have a negative operating margin; 432 are vulnerable to closure (source: Chartis 2025 State of the State)
- 182 rural hospitals have closed or converted since 2010 — approximately 10% of the nation's rural hospitals (source: Chartis)
- Over 400 — more than 20% of rural hospitals — are at risk of closure (source: Commonwealth Fund, Feb 2026)
- More than 70% of critical access hospitals are operating at a loss (source: American Hospital Association via NRHA)
- National median operating margin for rural hospitals: 1-2% (source: HFMA/Chartis 2025)
- Rural hospital revenue could drop by $87 billion over 10 years under current legislation (source: Urban Institute, June 2025)

### Healthcare Cybersecurity Budget and Staffing Crisis
- 56% of healthcare organizations devote less than 10% of their IT budgets to cybersecurity (source: HIMSS)
- Healthcare organizations allocate only ~6% of their IT budget to security (source: Asimily/industry consensus)
- 53% of organizations report a lack of in-house cybersecurity expertise (source: Proofpoint)
- 46% of organizations struggle with insufficient IT staffing (source: Proofpoint)
- Staffing shortages identified as the #1 cybersecurity challenge — smaller organizations (<500 beds) face the greatest difficulties with security teams too small to manage workload (source: KLAS Jan 2025 report)
- Only 51% of organizations even consider medical device security in their cybersecurity strategy (source: Proofpoint)
- Only 13% of healthcare organizations monitor cyber threats more than once per day (source: industry surveys)
- Only 37% of hospitals perform annual cybersecurity incident response exercises (source: JMIR)

### Patient Impact Evidence
- 25% of healthcare IT staff indicated that ransomware attacks led to increased patient mortality (source: Ponemon/Proofpoint)
- 70% of IT professionals reported supply chain cybersecurity attacks disrupted patient care (source: Proofpoint)
- 56% of organizations experienced delays in procedures or tests from cyberattacks in 2024 (source: Proofpoint)
- 28% of organizations reported higher patient mortality due to cyberattacks in 2024 (source: industry surveys)
- 273 million patient records exposed in 2024 (source: HHS/industry reporting)
- 22% of healthcare organizations experienced compromised medical devices causing transfers/downtime (source: Runsafe 2025)

### Key Real-World Incidents (For Proposal Use)
- WannaCry (2017): 81/236 NHS trusts disrupted; 6,900-19,000+ appointments cancelled; medical devices were entry points
- Springhill Medical Center (2019): Labor ward monitoring down during ransomware; infant brain damage/death alleged — first claimed ransomware death
- Düsseldorf University Hospital (2020): Patient died after ambulance diverted due to system crash
- Contec CMS8000 patient monitors (Jan 2025): Backdoor with hard-coded IP; hospitals told to unplug ethernet — CURRENT, happening now
- Hospira infusion pumps (2015): FDA's first-ever "discontinue use" advisory for a cyber issue — hospitals had to figure out fleet swaps with no playbook
- Baxter Sigma Spectrum (2022): Hard-coded creds, DoS risks, therapy interruption potential — same vendor class as Travis's IU Health pump experience

---

## 3. COMPETITIVE LANDSCAPE

### Enterprise Players (All Commercial, Enterprise-Priced)

**TRIMEDX** — Vulnerability management database aggregating from 82 intelligence sources. OEM-validated patches and compensating controls. Enterprise subscription (managed service model). Primarily serves large health systems.

**Claroty (Team82)** — CPS/IoMT security platform. AI-driven vulnerability attribution. Enterprise licensing.

**Armis** — AI-powered vulnerability intelligence. Cross-domain IT/OT/IoT/medical. Enterprise subscription.

**Forescout (Vedere Labs)** — Device classification and threat intelligence. Enterprise platform pricing.

### The Gap AdvisoryOps Fills

There is no free, open, comprehensive system that:
1. Aggregates 85+ medical device advisory sources into a single normalized feed
2. Deduplicates and correlates across sources using AI
3. Scores with healthcare-specific context
4. Recommends specific defensive actions from an approved playbook
5. Publishes everything as open data and open source

TODO FOR GAP #6: Verify this claim. Search for any existing open-source medical device advisory feeds, academic projects, or government initiatives that do something similar. If anything exists, document how AdvisoryOps differs.

### Positioning
AdvisoryOps is not competing with TRIMEDX or Claroty. It provides the public foundation layer beneath them. Enterprise customers who need facility-specific matching and workflow integration use commercial platforms. But the normalized feed, healthcare scoring, and defensive recommendations should be available to everyone.

---

## 4. GRANT REVIEWER GAP ANALYSIS

### Gap #1: Evidence Hospitals Would Use This
**Status:** Cannot be addressed until live API pipeline produces real output
**Plan:** 
- Complete live API validation on real advisory data first
- Review output quality — are summaries useful? Are recommendations sensible?
- Then demonstrate to trusted contacts in healthcare security
- Travis has extensive network from IU Health, ForeScout, Attivo, Flashpoint, and HIMSS circles
- Even informal feedback ("yes, we'd use this") is valuable
- Backup evidence: During healthcare security sales, Travis routinely encountered hospitals that achieved technical wins in POC/POV evaluations but couldn't procure due to budget constraints. The need was validated — the price was the barrier.
- TIMING: This is a pre-submission requirement. Do not submit the grant until at least 1-2 people have seen real output and provided feedback.

### Gap #2: Proving AI Is Essential, Not Just Nice-to-Have
**Status:** Requires live API runs to produce concrete before/after comparisons
**Plan:**
- Run deterministic-only pipeline on real data, capture output
- Run AI-enhanced pipeline on same data, capture output
- Document specific examples: "Advisory X and Advisory Y were treated as separate issues by deterministic correlation. AI merge correctly identified them as the same Philips ISCV vulnerability."
- Quantify: How many false duplicates eliminated? How many issues upgraded/downgraded in priority by healthcare classification? How many recommendations were playbook-appropriate?
- The before/after delta IS the grant justification

### Gap #3: Evaluation Methodology for AI Impact
**Plan for proposal:**
- Expand golden fixture set from 12 to 50+ (grant-funded work)
- Define clear metrics: dedup precision/recall, classification accuracy by category, recommendation appropriateness score (human-reviewed)
- Baseline: deterministic-only pipeline scores
- Treatment: AI-enhanced pipeline scores
- Publish methodology and results as open data
- Commit to quarterly evaluation runs with published results

### Gap #4: Solo Founder Risk
**Plan for proposal:**
- The system is designed for automated operation (scheduled pipeline runs, cached AI calls)
- Deterministic scoring and correlation work without any AI/API access — the system degrades gracefully
- Apache 2.0 licensing means the community can fork and maintain if needed
- Sustainability path: commercial tier funds ongoing development post-grant
- Community building strategy: publish on GitHub, engage Health-ISAC, present at HIMSS/BSides
- Be honest about this in the proposal — reviewers respect transparency about risks

### Gap #5: Responsible AI / Safety Considerations
**Plan for proposal:**
- Playbook-constrained approach: AI can ONLY recommend from approved patterns. Hallucinated pattern IDs are silently filtered. This is the key safety property.
- Human-in-the-loop: all AI-generated recommendations are clearly labeled as such. The dashboard presents evidence and recommendations — humans make the final decision.
- Failure mode for misclassification: if AI classifies a medical device issue as "not healthcare," the deterministic scoring still catches it if keywords match. AI classification only processes AMBIGUOUS issues where deterministic scoring found nothing. Clear medical device advisories (from CISA ICS-Medical, for example) are scored correctly without AI.
- The 91.7% healthcare accuracy (11/12 fixtures): the one miss is a genuinely ambiguous case. Document the failure mode and the mitigation.
- Draft playbooks generated by AI are explicitly marked as "AI-generated — requires human review" before promotion to approved status

### Gap #6: Competitive Differentiation Verification
**Status:** TODO
**Plan:** Search for existing open-source medical device advisory feeds, academic projects, government initiatives. Verify the claim that nothing equivalent exists. If something does exist, document how AdvisoryOps differs. Do this BEFORE writing the proposal.

### Gap #7: Source Count Honesty
**Plan for proposal:**
- Be transparent: 85 configured, 51 live/smoke-tested, 10-12 in the validated gold set for community builds
- Document how many sources actually contributed to the current 230-issue corpus
- Explain the progression: gold set is the validated core; the remaining 39 live sources are being evaluated for inclusion
- The 85-source master list is a research contribution even if not all are active — it's the most comprehensive public list of medical device advisory sources

### Gap #8: User Persona / Workflow Description
**Plan — write this for the proposal:**
"Sarah is the sole IT security person at a 200-bed rural hospital in Kansas. Her hospital operates at a 2% margin. She's also responsible for network administration and help desk escalation. She has no budget for Claroty or TRIMEDX. Every morning she opens the AdvisoryOps dashboard on her browser. Today it shows a new P0 alert: a Baxter Sigma Spectrum infusion pump vulnerability with active exploitation reported. The dashboard shows her the advisory merged from two sources (CISA and Baxter's own PSIRT), scored P0 because it affects life-sustaining devices with no patch available. The recommended actions are: isolate pump VLANs to permit only required traffic, add ACL rules blocking the exploited port, and open a Baxter support case with the evidence linked. She clicks 'Export remediation packet' and gets a JSON file she can paste into her ServiceNow instance, with tasks pre-split by role — one for her NetOps colleague, one for clinical engineering, one for the Baxter vendor contact. What would have taken her 4 hours of reading advisories, cross-referencing sources, and writing up remediation steps took 10 minutes."

### Gap #9: Timeline with Concrete Milestones
**Plan for proposal (6-month timeline):**
- Month 1: Live API validation complete. 20-advisory test set processed. Output quality reviewed and prompts tuned. First real before/after metrics captured.
- Month 2: Historical backfill — full advisory corpus from all validated sources processed through AI pipeline. Public corpus published to GitHub with 2,000+ normalized issues. Source expansion from 51 to 80+ live sources.
- Month 3: Tier 1 AI features live — plain-language summaries, advisory Q&A. Evaluation harness expanded to 50+ golden fixtures. First quarterly evaluation report published.
- Month 4: Model comparison study — GPT-4o-mini vs GPT-4o vs GPT-5.3-Codex across all pipeline stages. Cost/quality tradeoff analysis published.
- Month 5: Cross-advisory trend intelligence feature. AI-generated draft playbook capability. Community outreach — Health-ISAC engagement, HIMSS abstract submission.
- Month 6: Final evaluation report. Published benchmark comparisons. Complete public dataset snapshot. Grant impact summary.

### Gap #10: Post-Grant Sustainability
**Plan for proposal:**
- The system runs in deterministic-only mode with zero API cost — all scoring, correlation, and dashboard features work without AI
- AI-enhanced features degrade gracefully: cached results remain available forever; only NEW advisories need API calls
- Ongoing API cost for new advisories: ~$10-15/month (trivially fundable from personal budget or commercial tier revenue)
- Commercial tier (inventory matching, facility-specific remediation) provides sustainable revenue path
- Open-source community contributions reduce maintenance burden on solo founder
- The normalized public dataset has standalone value even if the AI layer stops running

---

## 5. AI FEATURE TIERS

### What AI Does Today (Built, Tested with Mocks, Needs Live Validation)
- **Dedup merge decisions** — "are these two advisories about the same vulnerability?"
- **Healthcare classification** — "is this ambiguous advisory about a medical device?"
- **Fix recommendations** — "which playbook patterns should we recommend?"

### Tier 1 — Must Have Before Grant Submission
Build these, validate with real API calls, capture results as evidence.

1. **Live API validation on real data** — Run the existing AI functions on 20 real advisories. Capture output. Review quality. Tune prompts. This is the minimum viable proof.

2. **AI-generated plain-language advisory summaries** — Replace raw RSS summaries with 2-3 sentence summaries written for hospital security staff. Example: "A vulnerability in Baxter Sigma Spectrum pumps allows an attacker on the same network to crash the wireless module, interrupting therapy. Affects firmware prior to 8.0. Baxter recommends segmentation and firmware update."

3. **Natural language Q&A ("Ask about this advisory")** — Similar to Ask A Nurse concept. Analyst asks: "Does this affect our Philips MX800 monitors?" or "What ports should I block?" System answers from advisory evidence.

4. **Before/after metrics** — Deterministic-only vs. AI-enhanced output comparison with concrete numbers.

### Tier 2 — Grant-Funded Development (What Credits Would Be Used For)

5. **AI-generated draft playbooks** — For novel vulnerability types not covered by the 8 existing patterns. Clearly marked as AI-generated, requiring human review before approval.

6. **Cross-advisory trend intelligence** — "6 Baxter advisories in 12 months across 3 product lines suggests a systemic firmware quality issue." Spotting patterns across the corpus.

7. **Regulatory context mapping** — Auto-flag HIPAA/HITECH implications. "This vulnerability is relevant to HIPAA §164.312(e)(1) — transmission security."

8. **Executive summary generation** — Weekly top-5 issues briefed in plain language for CISO/board consumption.

9. **Facility-specific risk narratives** (commercial tier) — "You have 47 affected pumps across 3 campuses. Prioritize the 12 ICU pumps this week."

---

## 6. DEVELOPMENT SEQUENCE (What To Build Before Writing the Grant)

### Phase 7: Live API Validation (Next Claude Code Sessions)
1. Select 20 real advisories from existing discovery data as test set
2. Run ai_merge_decision on real issue pairs — review output
3. Run classify_healthcare_relevance on ambiguous issues — review output
4. Run recommend_mitigations on scored issues — review output
5. Cache captures everything — total cost ~$1-2
6. Document: what worked, what needs prompt tuning, what surprised you

### Phase 8: Tier 1 AI Features
1. Build advisory summarizer (new AI function, uses ai_cache)
2. Build advisory Q&A (new AI function, uses ai_cache)
3. Integrate summaries into dashboard
4. Run before/after comparison on test set
5. Capture metrics for grant application

### Phase 9: Grant Preparation
1. Verify competitive differentiation (Gap #6 search)
2. Show system to 1-2 trusted contacts, get feedback (Gap #1)
3. Finalize proposal text using this strategy doc
4. Submit

---

## 7. APPLICATION FORM FIELDS (Reference)

From https://openai.com/form/cybersecurity-grant-program/

**Step 1: Applicant Information**
- First name, Last name, Email (use professional email)
- Company or University
- Role / Title
- LinkedIn
- Other team members and roles
- Additional notes (datasets, collaboration interests)

**Step 2: Project Proposal**
- Project title (one descriptive sentence)
- Project proposal (plaintext, up to 3000 words max)
- What problem are you trying to solve? (200 words max — separate field)
- Link to PDF version (optional)
- Link to relevant papers (optional)
- Project timeline (milestone format)
- Requested funding / API credits / resources needed (justify clearly)

**Key guidance from OpenAI:**
- "A small, well-executed project tends to have more impact than something big but spread thin"
- "Clearly define your goals, methodology, and why your team is uniquely positioned"
- "All projects should be intended to be licensed or distributed for maximal public benefit"
- "Offensive-security projects will not be considered"
- They look at proposals as they come in (rolling review)

---

## 8. PROPOSAL OUTLINE (For When We're Ready to Write)

### Opening (200 words)
Personal hook — Conficker at IU Health, improvised VLAN isolation, the realization that hospitals need a system, not improvisation. "I built that system."

### Problem Statement (200 words — separate form field)
48K CVEs, 29% exploited day-one. 46% of rural hospitals in the red. 56% of healthcare orgs spend <10% of IT budget on security. 53% lack in-house expertise. Medical devices can't be scanned safely, can't be patched on IT schedules, often vendor-managed. Advisory-to-action pipeline is manual, slow, fragmented. Patient deaths documented (Springhill, Düsseldorf).

### What AdvisoryOps Does (400 words)
Pipeline walkthrough with concrete example (real advisory, real output). Show the before/after of deterministic vs. AI-enhanced.

### What Already Exists (300 words)
258 tests, 51 live sources, working dashboard, AI pipeline with cached results. Not a proposal — a request to accelerate a working system.

### Why AI Models Are Essential (300 words)
Three specific places + concrete evidence from live API runs showing the delta.

### Public Benefit and Sharing Plan (400 words)
Everything that's open, Apache 2.0, GitHub Pages. The dataset that doesn't exist elsewhere.

### What the Grant Unlocks — Tier 2 Features (300 words)
Historical backfill, model comparison, trend intelligence, draft playbooks, expanded eval.

### Timeline with Milestones (200 words)
Concrete deliverables per month.

### Team and Credibility (300 words)
Narrative from Section 1, compressed. Credentials. Client list.

### Resource Request (200 words)
API credits primary. $5-10K covers 2+ years. Infrastructure is zero-cost by design.

### Closing (100 words)
Working defensive system, 20 years on the front lines, open for every hospital regardless of budget.

---

## 9. OTHER PROJECTS

### Ask A Nurse App
Travis has a mostly-completed AI-powered healthcare app called "Ask A Nurse." This should be finished and included in portfolio for:
- Demonstrating pattern of building intelligent healthcare applications
- Strengthening "AI in Healthcare" professional positioning
- Learning experience that informed AdvisoryOps approach
- Details: TBD (source code review in separate session)

---

## 10. KEY PHRASES AND FRAMING

### Do Use
- "Advisory-to-action pipeline" (not "alert feed")
- "Healthcare defenders" (not "users")
- "Approved mitigation patterns" (not "AI-generated advice")
- "The system I wished existed at every job I've held"
- "Public foundation layer" (not "free tier")
- "Defensive-only" (they exclude offensive security)
- "Evidence-cited recommendations" (shows auditability)
- "Working code, not a concept"

### Don't Use
- Startup jargon (TAM, ARR, runway, moat)
- Academic jargon (novel contribution, state of the art)
- Overpromising ("will revolutionize" — say "improves")
- Vague AI claims ("leveraging AI" — say specifically what the model does)
