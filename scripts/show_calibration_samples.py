"""Show full content of the 7 calibration samples for Feature 3."""
from __future__ import annotations

import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
FEED = REPO_ROOT / "outputs" / "community_public" / "feed_healthcare.json"

CALIBRATION_IDS = [
    # Best samples (Feature 3 must handle well)
    ("UNK-e3c0cfc277b79391", "BEST: openfda_recall rich — Abiomed Impella"),
    ("CVE-2017-9657", "BEST: cisa_icsma rich — Philips IntelliVue MX40"),
    ("UNK-fd1c8d91372d6266", "BEST: fda_enforcement rich — GE MRI software"),
    ("UNK-ff52a388059f8f57", "BEST: fda_enforcement sparse — GE SIGNA Premier"),
    ("UNK-b5ee08b43a5ba57e", "BEST: openfda_recall sparse — Beckman Coulter"),
    # Edge cases (Feature 3 must gracefully decline)
    ("UNK-a45ba818c051d9e6", "EDGE: philips_psirt sparse — Philips Tasy EMR (32 chars)"),
    ("UNK-f1bf060323435d4c", "EDGE: international sparse — Ombrelle (0 chars, false positive)"),
]


def main():
    with open(FEED, "r", encoding="utf-8") as f:
        data = json.load(f)
    issues = data if isinstance(data, list) else data.get("issues", [])
    by_id = {i.get("issue_id"): i for i in issues}

    for issue_id, label in CALIBRATION_IDS:
        print("=" * 78)
        print(label)
        print("=" * 78)
        issue = by_id.get(issue_id)
        if not issue:
            print(f"  NOT FOUND: {issue_id}")
            print()
            continue

        print(f"issue_id:    {issue.get('issue_id')}")
        print(f"priority:    {issue.get('priority')}    score: {issue.get('score')}")
        print(f"source:      {issue.get('highest_authority_source')}")
        print(f"all sources: {issue.get('sources')}")
        print(f"fda_class:   {issue.get('fda_risk_class') or '(none)'}")
        print(f"category:    {issue.get('healthcare_category') or '(none)'}")
        cves = issue.get('cves') or []
        if cves:
            print(f"CVEs:        {', '.join(cves[:5])}")
        print(f"vendor:      {issue.get('vendor') or '(none)'}")

        print(f"\nTITLE:")
        print(f"  {issue.get('title') or '(empty)'}")

        summary = issue.get('summary') or ''
        print(f"\nSUMMARY ({len(summary)} chars):")
        if not summary:
            print("  (empty)")
        else:
            # Print full summary, wrapped at 76 chars
            import textwrap
            wrapped = textwrap.fill(summary, width=76, initial_indent="  ", subsequent_indent="  ")
            print(wrapped)

        # Show actions/remediation if present
        actions = issue.get('actions') or []
        if actions:
            print(f"\nACTIONS ({len(actions)}):")
            for a in actions[:5]:
                print(f"  - {a}")

        # Show remediation steps
        steps = issue.get('remediation_steps') or []
        if steps:
            print(f"\nREMEDIATION STEPS ({len(steps)}):")
            for s in steps[:3]:
                if isinstance(s, dict):
                    text = s.get('text') or s.get('description') or str(s)
                else:
                    text = str(s)
                print(f"  - {text[:200]}")

        print()

    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())