#!/usr/bin/env python3
"""NVD historical backfill launcher.

Pulls all 240,000+ CVEs from the NVD API 2.0.
Estimated time: 24-48 hours with API key, longer without.
Estimated storage: ~1.2 GB (5KB per CVE * 240K)

Usage:
    python scripts/backfill_nvd.py              # Full pull (with confirmation)
    python scripts/backfill_nvd.py --yes        # Skip confirmation
    python scripts/backfill_nvd.py --limit 5000 # Test with 5K records
"""
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from backfill_common import base_argparser, format_duration, print_summary, setup_logging


def main():
    parser = base_argparser("NVD CVE 2.0 full historical backfill")
    parser.add_argument("--yes", "-y", action="store_true", help="Skip confirmation prompt")
    args = parser.parse_args()

    logger = setup_logging("nvd")

    from advisoryops.sources.nvd_backfill import run_backfill

    has_key = bool(os.environ.get("NVD_API_KEY"))
    rate = "50 req/30s" if has_key else "5 req/30s (set NVD_API_KEY for faster)"
    est_time = "24-48 hours" if has_key else "7-14 days"
    est_storage = "~1.2 GB"

    if args.limit:
        est_pages = args.limit // 2000 + 1
        est_time = format_duration(est_pages * (30 / 50 if has_key else 30 / 5))
        est_storage = f"~{args.limit * 5 // 1024} MB"

    print()
    print("NVD Historical Backfill")
    print("-" * 40)
    print(f"  API key:    {'Yes' if has_key else 'No'}")
    print(f"  Rate limit: {rate}")
    print(f"  Target:     {args.limit or '240,000+'} CVEs")
    print(f"  Est. time:  {est_time}")
    print(f"  Est. disk:  {est_storage}")
    print(f"  Cache dir:  outputs/nvd_cache/")
    print(f"  Log file:   logs/nvd_backfill.log")
    print()

    if not args.limit and not args.yes:
        resp = input(f"Pull {args.limit or '240,000+'} CVEs? This will take {est_time}. Continue? [y/N] ")
        if resp.strip().lower() not in ("y", "yes"):
            print("Aborted.")
            return 1

    start = time.monotonic()
    logger.info("Starting NVD backfill (limit=%s)", args.limit or "all")

    stats = run_backfill(max_results=args.limit)

    print_summary("NVD", stats, start)
    return 0


if __name__ == "__main__":
    sys.exit(main())
