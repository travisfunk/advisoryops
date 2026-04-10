#!/usr/bin/env python3
"""FDA device enforcement historical backfill launcher.

Pulls all ~38,500 enforcement records. Estimated time: 20-40 minutes.

Usage:
    python scripts/backfill_fda_enforcement.py                # Basic (first 25K)
    python scripts/backfill_fda_enforcement.py --historical   # Full archive via date ranges
    python scripts/backfill_fda_enforcement.py --limit 1000   # Test with limit
"""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from backfill_common import base_argparser, print_summary, setup_logging


def main():
    parser = base_argparser("FDA device enforcement full backfill")
    parser.add_argument(
        "--historical", action="store_true",
        help="Use date-range queries to pull the full 38K+ archive (bypasses 25K skip limit)",
    )
    args = parser.parse_args()

    logger = setup_logging("fda_enforcement")

    if args.historical:
        from advisoryops.sources.fda_safety_comms_backfill import run_backfill_date_ranges, ENFORCEMENT_DATE_RANGES

        print()
        print("FDA Enforcement — Full Historical Backfill (date-range mode)")
        print("-" * 60)
        print(f"  Date ranges: {len(ENFORCEMENT_DATE_RANGES)}")
        for s, e in ENFORCEMENT_DATE_RANGES:
            print(f"    {s} – {e}")
        print()

        start = time.monotonic()
        logger.info("Starting FDA enforcement date-range backfill")
        stats = run_backfill_date_ranges()
        print_summary("FDA Enforcement (date-range)", stats, start)
    else:
        from advisoryops.sources.fda_safety_comms_backfill import run_backfill

        logger.info("Starting FDA enforcement backfill (limit=%s)", args.limit or "all")
        start = time.monotonic()
        stats = run_backfill(max_results=args.limit)
        print_summary("FDA Enforcement", stats, start)

    return 0


if __name__ == "__main__":
    sys.exit(main())
