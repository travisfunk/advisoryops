"""One-shot corpus cleanup for Problem 9 (pharmaceutical exclusion).

Drops records sourced from disabled pharmaceutical sources (fda-medwatch,
mhra-uk-alerts) plus any belt-and-suspenders medical_device-tagged records
whose titles match pharmaceutical patterns. Updates the published feeds
under docs/ and outputs/community_public/ plus meta.json counts.

XML / CSV / XLSX derived artifacts under outputs/community_public/ are left
for the next full build to regenerate.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

PHARMA_SOURCE_IDS = frozenset({"fda-medwatch", "mhra-uk-alerts"})

PHARMA_TITLE = re.compile(
    r"(medicines?\s+recall|drug\s+recall|pharmaceutical\s+recall"
    r"|solution\s+for\s+injection|oral\s+tablet|oral\s+solution"
    r"|\bampoule\b|hydrochloride|prolonged-release"
    r"|\bmg/ml\b|\bi\.u\./ml\b|injection\s+bp|\bsyrup\b"
    r"|film-coated\s+tablets?|\binhaler\b"
    r"|class\s+[1-4]\s+medicines)",
    re.IGNORECASE,
)

JSON_LIST_TARGETS = [
    REPO / "docs" / "feed_latest.json",
    REPO / "docs" / "feed_healthcare.json",
    REPO / "docs" / "feed_medical_device_kev.json",
    REPO / "outputs" / "community_public" / "feed_latest.json",
    REPO / "outputs" / "community_public" / "feed_healthcare.json",
    REPO / "outputs" / "community_public" / "feed_medical_device_kev.json",
]

JSONL_TARGETS = [
    REPO / "outputs" / "community_public" / "issues_public.jsonl",
    REPO / "outputs" / "community_public" / "alerts_public.jsonl",
]

META_TARGETS = [
    REPO / "docs" / "meta.json",
    REPO / "outputs" / "community_public" / "meta.json",
]


def is_pharma(issue):
    srcs = set(issue.get("sources") or [])
    if srcs & PHARMA_SOURCE_IDS:
        return True
    if issue.get("healthcare_category") == "medical_device":
        title = str(issue.get("title") or "")
        if PHARMA_TITLE.search(title):
            return True
    return False


def clean_json_list(path: Path) -> tuple[int, int]:
    if not path.exists():
        return 0, 0
    with path.open(encoding="utf-8") as f:
        items = json.load(f)
    before = len(items)
    kept = [i for i in items if not is_pharma(i)]
    after = len(kept)
    with path.open("w", encoding="utf-8") as f:
        json.dump(kept, f, indent=2, ensure_ascii=False)
        f.write("\n")
    return before, after


def clean_jsonl(path: Path) -> tuple[int, int]:
    if not path.exists():
        return 0, 0
    kept_lines = []
    before = 0
    with path.open(encoding="utf-8") as f:
        for line in f:
            stripped = line.strip()
            if not stripped:
                continue
            before += 1
            item = json.loads(stripped)
            if not is_pharma(item):
                kept_lines.append(stripped)
    after = len(kept_lines)
    with path.open("w", encoding="utf-8") as f:
        for line in kept_lines:
            f.write(line + "\n")
    return before, after


def update_meta(path: Path, new_counts: dict) -> None:
    if not path.exists():
        return
    with path.open(encoding="utf-8") as f:
        meta = json.load(f)
    counts = meta.setdefault("counts", {})
    for key, value in new_counts.items():
        if key in counts:
            counts[key] = value
    with path.open("w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2, ensure_ascii=False)
        f.write("\n")


def main():
    print("=== JSON list cleanup ===")
    for p in JSON_LIST_TARGETS:
        before, after = clean_json_list(p)
        print(f"  {p.relative_to(REPO)}: {before} -> {after} (-{before - after})")

    print("\n=== JSONL cleanup ===")
    jsonl_results = {}
    for p in JSONL_TARGETS:
        before, after = clean_jsonl(p)
        jsonl_results[p.name] = after
        print(f"  {p.relative_to(REPO)}: {before} -> {after} (-{before - after})")

    # Recompute counts from cleaned files
    latest_path = REPO / "outputs" / "community_public" / "feed_latest.json"
    healthcare_path = REPO / "outputs" / "community_public" / "feed_healthcare.json"
    with latest_path.open(encoding="utf-8") as f:
        latest_count = len(json.load(f))
    with healthcare_path.open(encoding="utf-8") as f:
        hc_count = len(json.load(f))
    issues_public = jsonl_results.get("issues_public.jsonl", latest_count)
    alerts_public = jsonl_results.get("alerts_public.jsonl", 0)

    new_counts = {
        "issues_public": issues_public,
        "alerts_public": alerts_public,
        "latest": latest_count,
        "healthcare": hc_count,
    }
    print(f"\n=== meta.json counts update ===")
    for k, v in new_counts.items():
        print(f"  {k}: {v}")

    for p in META_TARGETS:
        update_meta(p, new_counts)

    # Verify zero pharma-titled records remain in medical_device bucket
    with latest_path.open(encoding="utf-8") as f:
        latest = json.load(f)
    md = [i for i in latest if i.get("healthcare_category") == "medical_device"]
    md_pharma = [i for i in md if PHARMA_TITLE.search(str(i.get("title") or ""))]
    md_pharma_src = [i for i in md if set(i.get("sources") or []) & PHARMA_SOURCE_IDS]
    print(f"\n=== Verification ===")
    print(f"  medical_device bucket (post-clean): {len(md)}")
    print(f"  pharma-titled remaining in MD bucket: {len(md_pharma)}")
    print(f"  pharma-source remaining in MD bucket: {len(md_pharma_src)}")
    if md_pharma or md_pharma_src:
        print("  WARNING: pharma records still present!")
    else:
        print("  PASS: no pharmaceutical records in medical_device bucket")


if __name__ == "__main__":
    main()
