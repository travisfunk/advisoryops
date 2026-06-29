#!/usr/bin/env python3
"""openFDA device recalls historical backfill launcher.

Pulls all ~60,000 device recalls. Estimated time: 30-60 minutes.

Usage:
    python scripts/backfill_openfda_recalls.py                # Basic (first 25K)
    python scripts/backfill_openfda_recalls.py --historical   # Full archive via date ranges
    python scripts/backfill_openfda_recalls.py --limit 1000   # Test with limit
"""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from backfill_common import base_argparser, print_summary, setup_logging


def main():
    parser = base_argparser("openFDA device recalls full backfill")
    parser.add_argument(
        "--historical", action="store_true",
        help="Use date-range queries to pull the full 57K+ archive (bypasses 25K skip limit)",
    )
    args = parser.parse_args()

    logger = setup_logging("openfda_recalls")

    if args.historical:
        from advisoryops.sources.openfda_backfill import run_backfill_date_ranges, RECALL_DATE_RANGES

        print()
        print("openFDA Recalls — Full Historical Backfill (date-range mode)")
        print("-" * 60)
        print(f"  Date ranges: {len(RECALL_DATE_RANGES)}")
        for s, e in RECALL_DATE_RANGES:
            print(f"    {s} – {e}")
        print()

        start = time.monotonic()
        logger.info("Starting openFDA recalls date-range backfill")
        stats = run_backfill_date_ranges()
        print_summary("openFDA Recalls (date-range)", stats, start)
    else:
        from advisoryops.sources.openfda_backfill import run_backfill

        logger.info("Starting openFDA recalls backfill (limit=%s)", args.limit or "all")
        start = time.monotonic()
        stats = run_backfill(max_results=args.limit)
        print_summary("openFDA Recalls", stats, start)

    return 0


if __name__ == "__main__":
    sys.exit(main())
