#!/usr/bin/env python3
"""
Task 1.3 — Smoke test all enabled sources with limit=5.

Runs discover() against every enabled source concurrently, records pass/fail,
item counts, and errors.  Writes a JSON report alongside the console table.

Usage (from repo root):
    python scripts/smoke_test_all_sources.py
    python scripts/smoke_test_all_sources.py --limit 3 --workers 6
    python scripts/smoke_test_all_sources.py --out outputs/my_smoke

Success criteria (Task 1.3):
    - Prints table: source_id | status | items_found | error_if_any
    - Final line: "X/Y sources passed smoke test"
    - At least 50 sources produce valid output (status=PASS)
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

# Allow running from repo root without editable install
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from advisoryops.discover import discover
from advisoryops.sources_config import load_sources_config


def smoke_one(
    source_id: str,
    out_root: str,
    limit: int,
) -> tuple[str, str, int, str | None, float]:
    """
    Attempt discover for one source.
    Returns: (source_id, status, items_found, error_msg, elapsed_s)
    status is "PASS" if the source was reachable and parseable, "FAIL" otherwise.
    items_found reflects post-filter count; 0 is still PASS (sparse feed or tight filter).
    """
    t0 = time.time()
    try:
        _, feed_path, _, _ = discover(source_id, limit=limit, out_root=out_root)
        feed = json.loads(Path(feed_path).read_text(encoding="utf-8"))
        items_found = len(feed.get("items", []))
        return source_id, "PASS", items_found, None, round(time.time() - t0, 2)
    except Exception as exc:
        short = f"{type(exc).__name__}: {str(exc)}"
        short = short[:140]
        return source_id, "FAIL", 0, short, round(time.time() - t0, 2)


def main() -> int:
    ap = argparse.ArgumentParser(description="Smoke test all enabled sources (Task 1.3)")
    ap.add_argument("--out", default="outputs/smoke_test",
                    help="Output root for discover artifacts (default: outputs/smoke_test)")
    ap.add_argument("--limit", type=int, default=5,
                    help="Items per source to fetch (default: 5)")
    ap.add_argument("--workers", type=int, default=8,
                    help="Concurrent workers (default: 8)")
    ap.add_argument("--report", default="outputs/smoke_test_report.json",
                    help="JSON report path (default: outputs/smoke_test_report.json)")
    args = ap.parse_args()

    cfg = load_sources_config()
    enabled = [s for s in cfg.sources if s.enabled]

    print(f"\nSmoke-testing {len(enabled)} enabled sources  "
          f"(limit={args.limit}, workers={args.workers})")
    print(f"Artifacts -> {args.out}\n")

    COL_ID = 38
    COL_ST = 5
    COL_N  = 6
    header = f"{'source_id':<{COL_ID}}  {'stat':<{COL_ST}}  {'items':>{COL_N}}  error"
    sep    = "-" * 96
    print(header)
    print(sep)

    live_results: list[dict] = []

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        future_to_src = {
            pool.submit(smoke_one, s.source_id, args.out, args.limit): s
            for s in enabled
        }
        for fut in as_completed(future_to_src):
            src = future_to_src[fut]
            source_id, status, items_found, error, elapsed = fut.result()
            icon = "PASS" if status == "PASS" else "FAIL"
            err_col = (error or "")[:55]
            print(f"{source_id:<{COL_ID}}  {icon:<{COL_ST}}  {items_found:>{COL_N}}  {err_col}")
            live_results.append({
                "source_id": source_id,
                "name": src.name,
                "scope": src.scope,
                "page_type": src.page_type,
                "status": status,
                "items_found": items_found,
                "error": error,
                "elapsed_s": elapsed,
            })

    # --- sorted final table ---
    live_results.sort(key=lambda r: (r["status"], r["source_id"]))
    passed = [r for r in live_results if r["status"] == "PASS"]
    failed = [r for r in live_results if r["status"] == "FAIL"]

    print(f"\n{'='*96}")
    print("FINAL RESULTS (sorted)\n")
    print(header)
    print(sep)
    for r in live_results:
        icon = "PASS" if r["status"] == "PASS" else "FAIL"
        err_col = (r["error"] or "")[:55]
        print(f"{r['source_id']:<{COL_ID}}  {icon:<{COL_ST}}  {r['items_found']:>{COL_N}}  {err_col}")

    print(sep)
    print(f"\n{len(passed)}/{len(enabled)} sources passed smoke test")

    if failed:
        print(f"\nFailed sources ({len(failed)}) — review and disable if persistently broken:")
        for r in failed:
            print(f"  FAIL  {r['source_id']:<{COL_ID}}  {r['error']}")

    # --- JSON report ---
    report = {
        "smoke_test_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total_enabled": len(enabled),
        "passed": len(passed),
        "failed": len(failed),
        "pass_rate": round(len(passed) / len(enabled), 3) if enabled else 0.0,
        "results": live_results,
    }
    rpt_path = Path(args.report)
    rpt_path.parent.mkdir(parents=True, exist_ok=True)
    rpt_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"\nJSON report -> {rpt_path}")

    return 0 if len(passed) >= 50 else 1


if __name__ == "__main__":
    sys.exit(main())
