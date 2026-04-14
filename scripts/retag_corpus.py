#!/usr/bin/env python3
"""Re-run healthcare_filter classification against the existing corpus.

Loads the already-emitted JSON artifacts in ``outputs/community_public/``,
re-runs ``classify_healthcare_category`` on every healthcare-relevant
issue, writes the updated artifacts back in place, and then calls
``_publish_to_docs`` to copy them into ``docs/``.

No API calls, no AI, no pipeline run. Deterministic and free — the
classifier is pure Python over already-available fields.

Usage:
    python scripts/retag_corpus.py
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List

import re

from advisoryops.community_build import _publish_to_docs
from advisoryops.enrichment.fda_classification import (
    extract_vendor_products_for_issue,
    lookup_class_by_recall_number,
)
from advisoryops.healthcare_filter import classify_healthcare_category
from advisoryops.score import (
    _apply_fda_clinical_floor,
    _actions_for_priority,
    _priority_from_score,
)


REPO_ROOT = Path(__file__).resolve().parent.parent
COMMUNITY_ROOT = REPO_ROOT / "outputs" / "community_public"
ENFORCEMENT_CACHE = REPO_ROOT / "outputs" / "fda_safety_comms_cache"

_FDA_FLOOR_MARKERS = (
    "FDA Class III auto-floored",
    "FDA Class II auto-floored",
    "FDA Class I clinical-severity boost",
)

_FDA_SOURCES = frozenset({
    "openfda-recalls-historical",
    "openfda-device-recalls",
    "openfda-device-events",
    "fda-medwatch",
    "fda-safety-comms-historical",
})

_RECALL_NUMBER_RE = re.compile(r"\bZ-\d{4}-\d{2,4}\b")


def _extract_vendor_and_products(issue: Dict[str, Any]) -> Dict[str, int]:
    """Fill missing ``vendor`` and ``affected_products`` on FDA-derived rows.

    Returns a dict with integer flags indicating which fields were just
    populated (``{"vendor": 1, "products": 1}``). Silent on rows whose
    classifier has not yet concluded medical_device — the caller runs this
    before classification so the pre-medical_device rows get filled too.
    """
    sources = issue.get("sources") or []
    if not any(s in _FDA_SOURCES for s in sources):
        return {"vendor": 0, "products": 0}

    has_vendor = bool(issue.get("vendor"))
    has_products = bool(issue.get("affected_products"))
    if has_vendor and has_products:
        return {"vendor": 0, "products": 0}

    vendor, products = extract_vendor_products_for_issue(
        issue, cache_dir=ENFORCEMENT_CACHE,
    )
    out = {"vendor": 0, "products": 0}
    if not has_vendor and vendor:
        issue["vendor"] = vendor
        out["vendor"] = 1
    if not has_products and products:
        issue["affected_products"] = products
        out["products"] = 1
    return out


def _extract_fda_risk_class(issue: Dict[str, Any]) -> bool:
    """Fill missing ``fda_risk_class`` from the enforcement cache.

    Returns True iff the issue was updated. Looks for a recall number of the
    form ``Z-NNNN-YYYY`` in the title (and, as a fallback, the summary) and
    queries the enforcement cache keyed by that recall number.
    """
    if issue.get("fda_risk_class"):
        return False
    sources = issue.get("sources") or []
    if not any(s in _FDA_SOURCES for s in sources):
        return False

    for field in ("title", "summary"):
        text = str(issue.get(field) or "")
        m = _RECALL_NUMBER_RE.search(text)
        if not m:
            continue
        rc = lookup_class_by_recall_number(m.group(), cache_dir=ENFORCEMENT_CACHE)
        if rc:
            issue["fda_risk_class"] = rc
            return True
    return False


def _rescore_fda_floor(issue: Dict[str, Any]) -> None:
    """Re-apply the FDA clinical-severity floor to an already-scored issue.

    Idempotent: if the issue's ``why`` already records an FDA-floor entry,
    skip to avoid double-boosting Class I on repeated runs.
    """
    if issue.get("fda_risk_class") not in ("1", "2", "3"):
        return
    why = issue.get("why") or []
    if any(any(m in w for m in _FDA_FLOOR_MARKERS) for w in why):
        return

    score = issue.get("score")
    if not isinstance(score, int):
        return

    new_score = _apply_fda_clinical_floor(issue, score, why)
    if new_score == score:
        return

    # Strip stale "priority: ..." trailing entry and append fresh one.
    why = [w for w in why if not (isinstance(w, str) and w.startswith("priority:"))]
    priority = _priority_from_score(new_score)
    why.append(f"priority: {priority} (score={new_score})")

    issue["score"] = new_score
    issue["priority"] = priority
    issue["actions"] = _actions_for_priority(priority)
    issue["why"] = why


def _retag_issue_list(issues: List[Dict[str, Any]]) -> Counter:
    """Reclassify every healthcare_relevant issue in place. Return counts.

    Order matters:
      1. Back-fill ``fda_risk_class`` from the enforcement cache (so the floor
         below has a class to act on).
      2. Back-fill ``vendor`` + ``affected_products`` on FDA-derived rows
         (so Rule 2 vendor-allowlist and Rule 4 product-keyword matches can
         fire correctly in step 3).
      3. Reclassify healthcare_category (Rule 3 now sees the filled class).
      4. Re-apply the FDA clinical-severity floor to score/priority/why.
    """
    counts: Counter = Counter()
    vendor_filled = 0
    products_filled = 0
    for issue in issues:
        _extract_fda_risk_class(issue)
        fill = _extract_vendor_and_products(issue)
        vendor_filled += fill["vendor"]
        products_filled += fill["products"]
        if issue.get("healthcare_relevant"):
            issue["healthcare_category"] = classify_healthcare_category(issue)
            counts[issue["healthcare_category"]] += 1
        else:
            counts["not_healthcare"] += 1
        _rescore_fda_floor(issue)
    counts["_vendor_filled"] = vendor_filled
    counts["_products_filled"] = products_filled
    return counts


def _retag_json_file(path: Path) -> Counter:
    if not path.exists():
        print(f"  skipped (missing): {path.name}")
        return Counter()
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict) and "issues" in data:
        issues = data["issues"]
        before = Counter(i.get("healthcare_category") for i in issues if i.get("healthcare_relevant"))
        after = _retag_issue_list(issues)
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    elif isinstance(data, list):
        before = Counter(i.get("healthcare_category") for i in data if i.get("healthcare_relevant"))
        after = _retag_issue_list(data)
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    else:
        print(f"  skipped (unexpected shape): {path.name}")
        return Counter()
    print(f"  {path.name}: {sum(after.values())} rows reclassified")
    print(f"    before: {dict(before)}")
    print(f"    after:  {dict(after)}")
    return after


def _retag_jsonl_file(path: Path) -> Counter:
    if not path.exists():
        print(f"  skipped (missing): {path.name}")
        return Counter()
    issues = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    before = Counter(i.get("healthcare_category") for i in issues if i.get("healthcare_relevant"))
    after = _retag_issue_list(issues)
    with path.open("w", encoding="utf-8") as fh:
        for issue in issues:
            fh.write(json.dumps(issue, ensure_ascii=False))
            fh.write("\n")
    print(f"  {path.name}: {sum(after.values())} rows reclassified")
    print(f"    before: {dict(before)}")
    print(f"    after:  {dict(after)}")
    return after


def main() -> None:
    if not COMMUNITY_ROOT.exists():
        raise SystemExit(f"Community root does not exist: {COMMUNITY_ROOT}")

    print(f"Re-tagging corpus at {COMMUNITY_ROOT}")
    print()

    _retag_json_file(COMMUNITY_ROOT / "feed_latest.json")
    _retag_json_file(COMMUNITY_ROOT / "feed_healthcare.json")
    _retag_jsonl_file(COMMUNITY_ROOT / "issues_public.jsonl")

    print()
    print("Copying to docs/...")
    _publish_to_docs(COMMUNITY_ROOT, REPO_ROOT)


if __name__ == "__main__":
    main()
