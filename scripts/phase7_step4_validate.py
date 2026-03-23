"""Phase 7 Step 4: Run AI functions on real advisories and save raw responses.

Runs with caching enabled so repeat runs are free.
All raw API responses are saved to outputs/phase7_validation/.
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "src"))
OUT = ROOT / "outputs" / "phase7_validation"
OUT.mkdir(parents=True, exist_ok=True)

MODEL = "gpt-4o-mini"
# Cost estimate: gpt-4o-mini is ~$0.15/1M input, $0.60/1M output tokens
INPUT_COST_PER_1K  = 0.00015
OUTPUT_COST_PER_1K = 0.00060
AVG_OUTPUT_FRACTION = 0.25  # rough estimate

def estimate_cost(tokens: int) -> float:
    input_t  = tokens * (1 - AVG_OUTPUT_FRACTION)
    output_t = tokens * AVG_OUTPUT_FRACTION
    return (input_t / 1000) * INPUT_COST_PER_1K + (output_t / 1000) * OUTPUT_COST_PER_1K


def strip_html(s: str) -> str:
    s = re.sub(r"<[^>]+>", " ", s or "")
    s = re.sub(r"\s+", " ", s).strip()
    return s


def save_raw(name: str, data: dict) -> Path:
    p = OUT / f"{name}.json"
    p.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    return p


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Load real advisories
# ---------------------------------------------------------------------------

def load_issues() -> list[dict]:
    issues_path = ROOT / "outputs" / "correlate" / "issues.jsonl"
    issues = [
        json.loads(l)
        for l in issues_path.read_text(encoding="utf-8").splitlines()
        if l.strip()
    ]

    # Fix HTML summaries for ICSMA issues
    for i in issues:
        if i.get("summary") and "<" in i.get("summary", ""):
            i["summary"] = strip_html(i["summary"])
        # Use signal title when issue_id is just the CVE
        sigs = i.get("signals", [])
        if sigs and sigs[0].get("title") and sigs[0]["title"] != i["issue_id"]:
            i["title"] = sigs[0]["title"]

    return issues


def select_5_issues(issues: list[dict]) -> list[dict]:
    icsma = [i for i in issues if "cisa-icsma" in i.get("sources", [])
             and i.get("summary") and len(i["summary"]) > 80][:2]
    kev_both = [i for i in issues
                if "cisa-kev-json" in i.get("sources", [])
                and "cisa-kev-csv" in i.get("sources", [])
                and len(i.get("summary", "") or "") > 80][:2]
    kev_csv_only = [i for i in issues
                    if "cisa-kev-csv" in i.get("sources", [])
                    and "cisa-kev-json" not in i.get("sources", [])
                    and "cisa-icsma" not in i.get("sources", [])
                    and len(i.get("summary", "") or "") > 80][:1]
    return icsma + kev_both + kev_csv_only


# ---------------------------------------------------------------------------
# 4A: Correlate + find_merge_candidates + ai_merge_decision
# ---------------------------------------------------------------------------

def run_correlate_and_merge(selected: list[dict]) -> dict:
    print("\n" + "="*60)
    print("4A: find_merge_candidates + ai_merge_decision")
    print("="*60)

    from advisoryops.ai_correlate import find_merge_candidates, ai_merge_decision

    candidates = find_merge_candidates(selected)
    print(f"Issues fed in: {len(selected)}")
    print(f"Candidate pairs found: {len(candidates)}")

    # If no candidates from heuristic, force-test ai_merge_decision on the two
    # ICSMA issues (same source → most plausible near-duplicate pair) so the
    # API call path is always exercised during validation.
    if not candidates:
        print("\n  (No heuristic candidates — forcing ai_merge_decision on the two")
        print("   ICSMA issues to validate the API call path)")
        icsma_issues = [i for i in selected if "cisa-icsma" in i.get("sources", [])]
        if len(icsma_issues) >= 2:
            candidates = [(icsma_issues[0]["issue_id"], icsma_issues[1]["issue_id"], 0.0)]
            print(f"  Forced pair: {candidates[0][0]} <-> {candidates[0][1]}")
        else:
            candidates = [(selected[0]["issue_id"], selected[1]["issue_id"], 0.0)]
            print(f"  Forced pair: {candidates[0][0]} <-> {candidates[0][1]}")

    merge_results = []
    for a_id, b_id, score in candidates:
        issue_a = next((i for i in selected if i["issue_id"] == a_id), None)
        issue_b = next((i for i in selected if i["issue_id"] == b_id), None)
        if not issue_a or not issue_b:
            continue

        print(f"\n  Pair: {a_id} <-> {b_id}  (heuristic score={score:.2f})")
        decision = ai_merge_decision(
            issue_a, issue_b,
            model=MODEL,
            cache_root=str(ROOT / "outputs" / "ai_cache"),
        )

        result = {
            "issue_a": a_id,
            "issue_b": b_id,
            "heuristic_score": score,
            "decision": {
                "same_issue": decision.same_issue,
                "confidence": decision.confidence,
                "reasoning": decision.reasoning,
                "model": decision.model,
                "tokens_used": decision.tokens_used,
                "estimated_cost_usd": estimate_cost(decision.tokens_used),
                # Provenance fields
                "evidence_sources": decision.evidence_sources,
                "confidence_by_field": decision.confidence_by_field,
                "extracted_facts": decision.extracted_facts,
                "inferred_facts": decision.inferred_facts,
                "evidence_gaps": decision.evidence_gaps,
                "insufficient_evidence": decision.insufficient_evidence,
                "handling_warnings": decision.handling_warnings,
            },
        }
        merge_results.append(result)

        print(f"    same_issue:       {decision.same_issue}")
        print(f"    confidence:       {decision.confidence:.2f}")
        print(f"    reasoning:        {decision.reasoning}")
        print(f"    evidence_sources: {decision.evidence_sources}")
        print(f"    confidence_by_field: {decision.confidence_by_field}")
        print(f"    evidence_gaps:    {decision.evidence_gaps}")
        print(f"    insufficient_ev:  {decision.insufficient_evidence}")
        print(f"    handling_warnings:{decision.handling_warnings}")
        print(f"    tokens:           {decision.tokens_used}")
        print(f"    est. cost:        ${estimate_cost(decision.tokens_used):.6f}")

    output = {
        "timestamp": utc_now(),
        "model": MODEL,
        "total_issues": len(selected),
        "candidates_found": len(candidates),
        "decisions": merge_results,
    }
    p = save_raw("4a_merge_decisions", output)
    print(f"\nSaved: {p}")
    return output


# ---------------------------------------------------------------------------
# 4B: classify_healthcare_relevance on 3 issues
# ---------------------------------------------------------------------------

def run_classify(selected: list[dict]) -> dict:
    print("\n" + "="*60)
    print("4B: classify_healthcare_relevance (3 issues)")
    print("="*60)

    from advisoryops.ai_score import classify_healthcare_relevance

    # Pick first 3
    to_classify = selected[:3]
    results = []

    for issue in to_classify:
        iid = issue["issue_id"]
        title = issue.get("title", iid)
        print(f"\n  Issue: {iid} — {title[:60]}")

        cls = classify_healthcare_relevance(
            issue,
            model=MODEL,
            cache_root=str(ROOT / "outputs" / "ai_cache"),
        )

        result = {
            "issue_id": iid,
            "title": title,
            "classification": {
                "category": cls.category,
                "confidence": cls.confidence,
                "reasoning": cls.reasoning,
                "device_types": cls.device_types,
                "model": cls.model,
                "tokens_used": cls.tokens_used,
                "from_cache": cls.from_cache,
                "estimated_cost_usd": estimate_cost(cls.tokens_used),
                # Provenance fields
                "evidence_sources": cls.evidence_sources,
                "confidence_by_field": cls.confidence_by_field,
                "extracted_facts": cls.extracted_facts,
                "inferred_facts": cls.inferred_facts,
                "evidence_gaps": cls.evidence_gaps,
                "insufficient_evidence": cls.insufficient_evidence,
                "handling_warnings": cls.handling_warnings,
            },
        }
        results.append(result)

        print(f"    category:         {cls.category}")
        print(f"    confidence:       {cls.confidence:.2f}")
        print(f"    reasoning:        {cls.reasoning}")
        print(f"    device_types:     {cls.device_types}")
        print(f"    evidence_sources: {cls.evidence_sources}")
        print(f"    confidence_by_field: {cls.confidence_by_field}")
        print(f"    evidence_gaps:    {cls.evidence_gaps}")
        print(f"    insufficient_ev:  {cls.insufficient_evidence}")
        print(f"    handling_warnings:{cls.handling_warnings}")
        print(f"    tokens:           {cls.tokens_used}  (from_cache={cls.from_cache})")
        print(f"    est. cost:        ${estimate_cost(cls.tokens_used):.6f}")

    output = {
        "timestamp": utc_now(),
        "model": MODEL,
        "classifications": results,
    }
    p = save_raw("4b_healthcare_classifications", output)
    print(f"\nSaved: {p}")
    return output


# ---------------------------------------------------------------------------
# 4C: recommend_mitigations on 2 highest-scored issues
# ---------------------------------------------------------------------------

def run_recommend(selected: list[dict]) -> dict:
    print("\n" + "="*60)
    print("4C: recommend_mitigations (2 highest-scored issues)")
    print("="*60)

    from advisoryops.score import score_issue_v2
    from advisoryops.recommend import recommend_mitigations
    from advisoryops.playbook import load_playbook

    playbook = load_playbook()
    print(f"Playbook loaded: {len(playbook.patterns)} patterns")

    # Score all 5, pick top 2
    scored = []
    for issue in selected:
        sr = score_issue_v2(issue)
        issue["score"] = sr.score
        issue["priority"] = sr.priority
        scored.append((sr.score, issue))

    scored.sort(key=lambda t: -t[0])
    top2 = [i for _, i in scored[:2]]

    print(f"\nScored all {len(selected)} issues:")
    for _, i in scored:
        print(f"  {i['issue_id']:25s}  score={i['score']:3d}  priority={i['priority']}")

    results = []
    for issue in top2:
        iid = issue["issue_id"]
        title = issue.get("title", iid)
        print(f"\n  Recommending for: {iid} — {title[:60]}")
        print(f"  score={issue['score']}  priority={issue['priority']}")

        packet = recommend_mitigations(
            issue,
            playbook,
            model=MODEL,
            cache_root=str(ROOT / "outputs" / "ai_cache"),
        )

        patterns_list = [
            {
                "pattern_id": p.pattern_id,
                "why_selected": p.why_selected,
                "parameters": p.parameters,
                "priority_order": p.priority_order,
            }
            for p in packet.recommended_patterns
        ]

        result = {
            "issue_id": iid,
            "title": title,
            "score": issue["score"],
            "priority": issue["priority"],
            "packet": {
                "recommended_patterns": patterns_list,
                "tasks_by_role": packet.tasks_by_role,
                "reasoning": packet.reasoning,
                "citations": packet.citations,
                "model": packet.model,
                "tokens_used": packet.tokens_used,
                "from_cache": packet.from_cache,
                "estimated_cost_usd": estimate_cost(packet.tokens_used),
                # Provenance fields
                "evidence_sources": packet.evidence_sources,
                "confidence_by_field": packet.confidence_by_field,
                "extracted_facts": packet.extracted_facts,
                "inferred_facts": packet.inferred_facts,
                "evidence_gaps": packet.evidence_gaps,
                "insufficient_evidence": packet.insufficient_evidence,
                "handling_warnings": packet.handling_warnings,
            },
        }
        results.append(result)

        print(f"    patterns:         {[p['pattern_id'] for p in patterns_list]}")
        print(f"    roles:            {list(packet.tasks_by_role.keys())}")
        print(f"    reasoning:        {packet.reasoning[:100]}")
        print(f"    evidence_sources: {packet.evidence_sources}")
        print(f"    confidence_by_field: {packet.confidence_by_field}")
        print(f"    evidence_gaps:    {packet.evidence_gaps}")
        print(f"    insufficient_ev:  {packet.insufficient_evidence}")
        print(f"    handling_warnings:{packet.handling_warnings}")
        print(f"    tokens:           {packet.tokens_used}  (from_cache={packet.from_cache})")
        print(f"    est. cost:        ${estimate_cost(packet.tokens_used):.6f}")
        for role, tasks in packet.tasks_by_role.items():
            print(f"    {role}: {len(tasks)} task(s)")

    output = {
        "timestamp": utc_now(),
        "model": MODEL,
        "recommendations": results,
    }
    p = save_raw("4c_recommendations", output)
    print(f"\nSaved: {p}")
    return output


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print("\n" + "="*60)
    print("PHASE 7 STEP 4: AI VALIDATION ON REAL DATA")
    print(f"Model: {MODEL}")
    print(f"Output dir: {OUT}")
    print("="*60)

    # Load and select
    issues = load_issues()
    selected = select_5_issues(issues)
    assert len(selected) == 5, f"Expected 5 issues, got {len(selected)}"

    print(f"\nSelected 5 advisories:")
    for idx, i in enumerate(selected, 1):
        print(f"  [{idx}] {i['issue_id']:25s}  sources={i['sources']}  title={str(i.get('title',''))[:50]}")

    # Save selection manifest
    manifest = [
        {
            "issue_id": i["issue_id"],
            "title": str(i.get("title", "")),
            "sources": i["sources"],
            "summary_preview": str(i.get("summary", ""))[:200],
        }
        for i in selected
    ]
    save_raw("selected_issues", {"issues": manifest})

    # 4A: Merge candidates
    merge_out = run_correlate_and_merge(selected)

    # 4B: Healthcare classification
    classify_out = run_classify(selected)

    # 4C: Recommendations
    recommend_out = run_recommend(selected)

    # Summary
    total_tokens = (
        sum(d["decision"]["tokens_used"] for d in merge_out["decisions"])
        + sum(c["classification"]["tokens_used"] for c in classify_out["classifications"])
        + sum(r["packet"]["tokens_used"] for r in recommend_out["recommendations"])
    )
    total_cost = estimate_cost(total_tokens)

    print("\n" + "="*60)
    print("STEP 4 SUMMARY")
    print("="*60)
    print(f"  Merge candidate pairs evaluated: {len(merge_out['decisions'])}")
    print(f"  Healthcare classifications run:  {len(classify_out['classifications'])}")
    print(f"  Recommendations generated:       {len(recommend_out['recommendations'])}")
    print(f"  Total tokens used:               {total_tokens}")
    print(f"  Estimated total cost:            ${total_cost:.4f}")
    print(f"\n  Output files in: {OUT}")
    for f in sorted(OUT.iterdir()):
        size = f.stat().st_size
        print(f"    {f.name} ({size:,} bytes)")


if __name__ == "__main__":
    main()
