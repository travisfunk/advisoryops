# DOC-03 Mitigation Playbook (v1)

## 0) Purpose
This document defines the **approved mitigation patterns** AdvisoryOps is allowed to recommend.  
The system must choose from these patterns and fill in parameters (ports, subnets, vendor contacts, validation steps, etc.) rather than inventing ad-hoc remediation advice.

This keeps outputs:
- consistent (repeatable across facilities)
- safe (defensive-only, avoids dual-use guidance)
- auditable (verification evidence is standardized)

---


## 0.1 Current extraction fields (as of 2026-02-08)

The mitigation playbook is driven by the extractor’s canonical output `advisory_record.json` (strict 13-key schema; DOC-02).  
For now, the most relevant inputs are:

- `impact`, `exploitation`, `severity`
- `mitigations` (list)
- `references` (links for source-of-truth)

As the extended contract matures, this document may reference additional fields, but the above are guaranteed today.


## 1) Versioning & governance
- **Current playbook version:** v1.0
- Patterns are **append-first**: add new patterns before changing existing ones.
- Breaking changes require:
  - What changed
  - Why
  - Migration notes

---

## 2) Roles (task ownership hints)
- **infosec:** central security governance, risk decisions, tracking, evidence collection
- **netops:** VLAN/ACL/firewall/NAC/network telemetry
- **htm_ce:** clinical engineering / modality ownership (device operations + vendor coordination)
- **it_ops:** server/endpoint ops where applicable (controller workstations, jump hosts)
- **vendor:** OEM maintenance, patching, validation, proprietary procedures
- **clinical_ops:** downtime coordination, patient-safety communications, workflow signoff

---

## 3) Pattern schema (YAML shape)
A mitigation pattern is defined with:
- **id:** stable identifier
- **name / intent**
- **when_to_use:** applicability rules (conditions and constraints)
- **inputs_required:** parameters the packet must request or infer
- **steps:** ordered actions (role-tagged)
- **verification:** how we prove it worked
- **rollback:** how to safely revert
- **safety_notes:** healthcare caveats (downtime, vendor-managed constraints)

**Canonical YAML fields:**
- id: string (ALL_CAPS_WITH_UNDERSCORES)
- name: string
- category: one of (segmentation, access_control, host_hardening, protocol_hardening, monitoring, vendor_process, patching, governance, communication)
- severity_fit: list (critical/high/medium/low)
- when_to_use:
  - conditions: list of strings
  - constraints: list of strings (e.g., vendor_managed, no_admin_access, patch_window_limited)
- inputs_required: list of strings
- steps:
  - role: role enum
    action: short string
    details: string (what to do)
- verification:
  - evidence: list of strings
- rollback:
  - steps: list of strings
- safety_notes: list of strings

---

## 4) How AdvisoryOps uses this playbook
AdvisoryOps must:
1) Determine patch feasibility/ownership (customer vs vendor-only)
2) Select mitigations ONLY from patterns in this doc
3) Parameterize steps using facility context (subnets, VLANs, ports, vendor contact, maintenance window)
4) Emit tasks split by role with verification and rollback

## 5) Pattern catalog (v1)

### 5.1 SEGMENTATION_VLAN_ISOLATION
- **Category:** segmentation
- **Intent:** isolate impacted devices into a dedicated VLAN/zone with restricted routing.

**When to use**
- Device is network-reachable and lateral movement risk exists.
- Patch is delayed or vendor-managed.

**Inputs required**
- Current VLAN/subnet, target VLAN/subnet, required peers (PACS, EHR interfaces, time/NTP, DNS), maintenance window.

**Steps**
- netops: define target VLAN/VRF/zone for modality/devices.
- netops: move ports/WiFi profiles to target VLAN where applicable.
- infosec: approve segmentation plan and document residual risk.
- htm_ce: coordinate downtime and validate modality workflows after move.

**Verification evidence**
- Network diagram/update or change record
- Before/after routing reachability test results
- Validation signoff (HTM/clinical)

**Rollback**
- Move ports back to original VLAN
- Restore original routing/ACLs

**Safety notes**
- Validate clinical workflows (DICOM, HL7, vendor remote support) before/after.

---

### 5.2 ACCESS_CONTROL_ACL_ALLOWLIST
- **Category:** access_control
- **Intent:** restrict ingress/egress to minimum required services/peers.

**When to use**
- Known exploited or high risk; patch not immediate.
- You can’t fully isolate but can tightly control flows.

**Inputs required**
- Required peers (IP/FQDN), required ports/protocols, device management access requirements.

**Steps**
- netops: implement ACL/firewall policy (allowlist required flows; deny all else).
- infosec: review allowlist rationale; record in packet with citations.
- htm_ce: validate device functionality and vendor support paths.

**Verification evidence**
- Firewall/ACL rule export or ticket attachment
- Flow tests (allowed traffic succeeds; blocked traffic fails)
- Monitoring confirmation (no unexpected egress)

**Rollback**
- Disable policy / revert to previous rule set

**Safety notes**
- Be careful blocking time sync, DNS, and vendor-required update channels.

---

### 5.3 ACCESS_CONTROL_NAC_POLICY
- **Category:** access_control
- **Intent:** enforce device identity/posture and limit where a device can connect.

**When to use**
- Facilities with NAC (e.g., ISE/ClearPass) and unmanaged devices.

**Inputs required**
- NAC platform, device profiling method, allowed switch ports/WiFi SSIDs, VLAN assignment rules.

**Steps**
- netops: create/adjust NAC policy for the device class or MAC/OUI.
- infosec: define policy intent (quarantine, restricted VLAN, alert-only).
- htm_ce: coordinate port changes with clinical owners.

**Verification evidence**
- NAC policy screenshot/export
- Test device authentication result
- VLAN assignment confirmation

**Rollback**
- Revert NAC policy changes; remove quarantine assignment

**Safety notes**
- Avoid “hard quarantine” without clinical signoff for life-safety devices.

---

### 5.4 ACCESS_CONTROL_REMOTE_ACCESS_RESTRICT
- **Category:** access_control
- **Intent:** restrict vendor remote access to approved jump hosts/VPN and approved windows.

**When to use**
- Vendor-managed or vendor-supported devices where remote access is required.

**Inputs required**
- Vendor remote method, jump host details, approved maintenance windows, MFA requirements.

**Steps**
- infosec: require vendor remote through controlled method (VPN + MFA where possible).
- netops: restrict remote access IP ranges and ports; enforce time windows if possible.
- htm_ce: coordinate vendor access scheduling and document case/ticket.

**Verification evidence**
- Jump host/VPN logs showing approved session
- Time-window policy evidence
- Vendor case reference ID

**Rollback**
- Restore prior access paths only with explicit approval

**Safety notes**
- Don’t break emergency vendor support; use documented exceptions with approval.

### 5.9 VENDOR_PROCESS_OPEN_CASE_AND_TRACK
- **Category:** vendor_process
- **Intent:** formalize vendor engagement when customer cannot patch/modify.

**When to use**
- Vendor-managed systems (no admin access / contractual restrictions).
- Patch requires OEM service.

**Inputs required**
- Vendor support channel, contract details, device identifiers (serial/model), urgency, downtime window.

**Steps**
- htm_ce: open vendor case; request patch/mitigation guidance and timeline.
- infosec: provide security context (KEV, known exploited) and required risk controls.
- vendor: provide remediation plan and validation steps.
- infosec: track until closure; document risk acceptance if delayed.

**Verification evidence**
- Vendor case ID
- Vendor-provided remediation notes
- Closure confirmation and validation signoff

**Rollback**
- N/A (process pattern)

**Safety notes**
- Escalate when patient care is impacted or when exploitability is high.

---

### 5.10 PATCHING_APPLY_VENDOR_OR_CUSTOMER
- **Category:** patching
- **Intent:** apply approved patch/update/firmware per vendor guidance.

**When to use**
- Patch is available and feasible within clinical constraints.

**Inputs required**
- Target versions, approved maintenance window, backup/restore plan, validation test checklist.

**Steps**
- vendor or it_ops/htm_ce: apply patch per OEM procedure.
- htm_ce: run modality validation tests.
- infosec: record patched version and close compensating controls if no longer needed.

**Verification evidence**
- Before/after version proof
- Change record
- Validation checklist completed

**Rollback**
- OEM-supported rollback procedure; restore from backup image where applicable

**Safety notes**
- Never patch life-safety systems without downtime and validation plan.

---

### 5.11 GOVERNANCE_RISK_ACCEPTANCE
- **Category:** governance
- **Intent:** document and time-bound residual risk when remediation is not feasible.

**When to use**
- Vendor delays patch, clinical constraints prevent mitigation, or device is end-of-life.

**Inputs required**
- Business owner, clinical owner, compensating controls in place, review date.

**Steps**
- infosec: draft risk acceptance with residual risk statement.
- clinical_ops: acknowledge patient care considerations.
- leadership: approve with review date and conditions.

**Verification evidence**
- Signed approval (or ticket approval chain)
- Review date set
- Compensating controls documented

**Rollback**
- Re-open packet when a viable remediation becomes available

**Safety notes**
- Must be time-bound; avoid indefinite acceptance without re-review.

---

### 5.12 COMMUNICATION_CLINICAL_DOWNTIME_NOTICE
- **Category:** communication
- **Intent:** ensure clinical stakeholders are informed for downtime-sensitive changes.

**When to use**
- Any change requiring downtime or workflow changes for clinical systems.

**Inputs required**
- Affected modality, downtime window, fallback procedures, contacts.

**Steps**
- htm_ce + clinical_ops: communicate planned downtime and workflows.
- infosec: include security rationale and urgency level.
- netops/it_ops: confirm technical readiness.

**Verification evidence**
- Notice sent + acknowledgements
- Downtime window recorded
- Post-change validation signoff

**Rollback**
- Reschedule change if clinical operations cannot support window

**Safety notes**
- Patient care > speed. Use emergency change only with explicit approval.

---

## 6) Selection guidance (how to pick patterns)
1) If a patch exists and is feasible: apply PATCHING_APPLY_VENDOR_OR_CUSTOMER (+ verification).
2) If patch is delayed or vendor-only:
   - Prefer SEGMENTATION_VLAN_ISOLATION and/or ACCESS_CONTROL_ACL_ALLOWLIST
   - Add monitoring patterns for high/exploited issues
   - Open VENDOR_PROCESS_OPEN_CASE_AND_TRACK immediately
3) If no viable remediation exists (EOL or blocked):
   - Apply strongest feasible compensating controls + GOVERNANCE_RISK_ACCEPTANCE (time-bound)

---

## 7) Changelog
- 2026-02-06: Initial v1.0 mitigation pattern catalog and selection guidance.
