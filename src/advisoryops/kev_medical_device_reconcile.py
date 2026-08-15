"""Reconcile the public KEV/medical-device flag against the full CISA KEV catalog.

The normal correlation stage intentionally limits per-source signals for performance.
That means its historical ``is_kev_medical_device`` flag cannot establish full-catalog
membership. This post-build stage re-evaluates every published medical-device record
using exact CVE IDs from the complete raw CISA KEV discovery dataset, corrects the
legacy +40 cross-reference bonus when necessary, and regenerates affected public
artifacts before the nightly workflow commits ``docs/``.
"""
from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Set

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_KEV_BONUS = 40
_KEV_WHY_PREFIX = "kev-medical-device:"
_KEV_WHY = "kev-medical-device: actively exploited medical device (+40)"


def _read_jsonl(path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        obj = json.loads(line)
        if isinstance(obj, dict):
            rows.append(obj)
    return rows


def _cves_from_values(values: Iterable[Any]) -> Set[str]:
    cves: Set[str] = set()
    for value in values:
        if value is None:
            continue
        cves.update(match.upper() for match in _CVE_RE.findall(str(value)))
    return cves


def _structured_cves(record: Dict[str, Any], *, kev_record: bool = False) -> Set[str]:
    """Return explicitly assigned CVEs, excluding incidental prose mentions."""
    values: List[Any] = []
    structured = record.get("cves") or []
    if isinstance(structured, str):
        values.append(structured)
    elif isinstance(structured, list):
        values.extend(structured)

    if kev_record:
        values.append(record.get("guid"))
    else:
        values.append(record.get("issue_id"))
    return _cves_from_values(values)


def kev_cve_set(kev_rows: Iterable[Dict[str, Any]]) -> Set[str]:
    cves: Set[str] = set()
    for row in kev_rows:
        cves.update(_structured_cves(row, kev_record=True))
    return cves


def strict_kev_medical_device(record: Dict[str, Any], kev_cves: Set[str]) -> bool:
    if record.get("healthcare_category") != "medical_device":
        return False
    return bool(_structured_cves(record) & kev_cves)


def _priority_from_score(score: int) -> str:
    if score >= 150:
        return "P0"
    if score >= 100:
        return "P1"
    if score >= 60:
        return "P2"
    return "P3"


def _actions_for_priority(priority: str) -> List[str]:
    if priority == "P0":
        return ["notify", "ingest", "track"]
    if priority == "P1":
        return ["ingest", "track"]
    if priority == "P2":
        return ["track"]
    return ["log"]


def reconcile_rows(
    rows: List[Dict[str, Any]],
    kev_cves: Set[str],
) -> Dict[str, int]:
    """Mutate published rows so the KEV/medical-device flag has one strict meaning."""
    flags_corrected = 0
    bonuses_added = 0
    bonuses_removed = 0
    strict_count = 0

    for row in rows:
        strict = strict_kev_medical_device(row, kev_cves)
        old_flag = bool(row.get("is_kev_medical_device", False))
        if old_flag != strict:
            flags_corrected += 1

        why_raw = row.get("why") or []
        why = list(why_raw) if isinstance(why_raw, list) else []
        had_bonus = any(str(item).startswith(_KEV_WHY_PREFIX) for item in why)

        score = int(row.get("score", 0) or 0)
        score_changed = False
        why = [item for item in why if not str(item).startswith(_KEV_WHY_PREFIX)]

        if strict:
            strict_count += 1
            if not had_bonus:
                score += _KEV_BONUS
                bonuses_added += 1
                score_changed = True
            why.append(_KEV_WHY)
        elif had_bonus:
            score = max(0, score - _KEV_BONUS)
            bonuses_removed += 1
            score_changed = True

        row["is_kev_medical_device"] = strict

        if score_changed:
            priority = _priority_from_score(score)
            why = [item for item in why if not str(item).startswith("priority:")]
            why.append(f"priority: {priority} (score={score})")
            row["score"] = score
            row["priority"] = priority
            row["actions"] = _actions_for_priority(priority)

        row["why"] = why

    return {
        "strict_kev_medical_device": strict_count,
        "legacy_flags_corrected": flags_corrected,
        "bonuses_added": bonuses_added,
        "bonuses_removed": bonuses_removed,
    }


def _write_json(path: Path, rows: List[Dict[str, Any]]) -> None:
    path.write_text(json.dumps(rows, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _update_meta(meta_path: Path, stats: Dict[str, int], *, kev_unique_cves: int) -> None:
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    if not isinstance(meta, dict):
        raise ValueError(f"{meta_path}: expected a JSON object")

    counts = meta.setdefault("counts", {})
    if isinstance(counts, dict):
        counts["kev_medical_device"] = stats["strict_kev_medical_device"]

    methodology = meta.setdefault("methodology_stats", {})
    if not isinstance(methodology, dict):
        raise ValueError(f"{meta_path}: methodology_stats must be a JSON object")

    methodology["kev_medical_device_feed_count"] = stats["strict_kev_medical_device"]
    methodology["kev_medical_device_legacy_flags_corrected"] = stats["legacy_flags_corrected"]
    methodology["kev_medical_device_score_bonuses_added"] = stats["bonuses_added"]
    methodology["kev_medical_device_score_bonuses_removed"] = stats["bonuses_removed"]
    methodology["kev_medical_device_reconciled"] = True
    methodology["kev_medical_device_definition"] = (
        "healthcare_category == medical_device AND exact structured CVE ID is present "
        "in the full CISA Known Exploited Vulnerabilities catalog"
    )
    methodology["kev_medical_device_catalog_unique_cves"] = kev_unique_cves
    methodology["kev_medical_device_reconciled_at"] = datetime.now(timezone.utc).isoformat()

    meta_path.write_text(json.dumps(meta, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def run(
    *,
    docs_dir: Path,
    kev_path: Path,
    min_kev_cves: int = 1000,
) -> Dict[str, int]:
    feed_path = docs_dir / "feed_latest.json"
    meta_path = docs_dir / "meta.json"

    rows = json.loads(feed_path.read_text(encoding="utf-8"))
    if not isinstance(rows, list) or not rows:
        raise RuntimeError(f"{feed_path}: expected a non-empty JSON array")

    kev_rows = _read_jsonl(kev_path)
    kev_cves = kev_cve_set(kev_rows)
    if len(kev_cves) < min_kev_cves:
        raise RuntimeError(
            f"CISA KEV input appears truncated: only {len(kev_cves)} unique CVEs; "
            f"expected at least {min_kev_cves}"
        )

    stats = reconcile_rows(rows, kev_cves)

    # Use the builder's canonical writers/sort order so this stage changes
    # classification semantics, not public artifact formats.
    from .community_build import _sort_feed_entries, _write_csv, _write_rss

    rows = _sort_feed_entries(rows)
    medical_device_rows = [
        row for row in rows if row.get("healthcare_category") == "medical_device"
    ]
    kev_medical_rows = [
        row for row in rows if row.get("is_kev_medical_device") is True
    ]

    # Invariant: every row in the KEV-medical feed must satisfy the exact test.
    if any(not strict_kev_medical_device(row, kev_cves) for row in kev_medical_rows):
        raise RuntimeError("KEV medical-device reconciliation invariant failed")

    _write_json(feed_path, rows)
    _write_json(docs_dir / "feed_healthcare.json", medical_device_rows)
    _write_json(docs_dir / "feed_medical_device_kev.json", kev_medical_rows)
    _write_csv(docs_dir / "feed.csv", rows)

    _write_rss(docs_dir / "feed.xml", rows, top=50)
    _write_rss(
        docs_dir / "feed_healthcare.xml",
        medical_device_rows,
        top=100,
        title="AdvisoryOps — Healthcare Medical Device Advisories",
        description="Healthcare and medical device cybersecurity advisories",
    )
    _write_rss(
        docs_dir / "feed_kev_medical_device.xml",
        kev_medical_rows,
        top=100,
        title="AdvisoryOps — Actively Exploited Medical Device Vulnerabilities",
        description="Medical device vulnerabilities in CISA's Known Exploited Vulnerabilities catalog",
    )
    class_3_rows = [row for row in rows if row.get("fda_risk_class") == "3"]
    _write_rss(
        docs_dir / "feed_class_3.xml",
        class_3_rows,
        top=100,
        title="AdvisoryOps — FDA Class III Medical Device Advisories",
        description="Advisories affecting FDA Class III (highest-risk) medical devices",
    )
    p0_p1_rows = [row for row in rows if row.get("priority") in ("P0", "P1")]
    _write_rss(
        docs_dir / "feed_p0_p1.xml",
        p0_p1_rows,
        top=100,
        title="AdvisoryOps — High Priority Advisories",
        description="P0 and P1 priority cybersecurity advisories requiring immediate attention",
    )

    _update_meta(meta_path, stats, kev_unique_cves=len(kev_cves))
    return stats


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--docs-dir", type=Path, default=Path("docs"))
    parser.add_argument(
        "--kev-jsonl",
        type=Path,
        default=Path("outputs/discover/cisa-kev-json/items.jsonl"),
    )
    parser.add_argument("--min-kev-cves", type=int, default=1000)
    args = parser.parse_args()

    stats = run(
        docs_dir=args.docs_dir,
        kev_path=args.kev_jsonl,
        min_kev_cves=args.min_kev_cves,
    )
    print("Strict KEV / medical-device reconciliation:")
    print(f"  Strict KEV medical-device rows: {stats['strict_kev_medical_device']}")
    print(f"  Legacy flags corrected:         {stats['legacy_flags_corrected']}")
    print(f"  +40 bonuses added:              {stats['bonuses_added']}")
    print(f"  +40 bonuses removed:            {stats['bonuses_removed']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
