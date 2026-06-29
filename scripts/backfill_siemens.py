#!/usr/bin/env python3
"""Siemens ProductCERT advisory backfill launcher.

Pulls all ~779 advisories from the CSAF ROLIE feed.
Estimated time: 10-20 minutes (individual CSAF fetches).

Usage:
    python scripts/backfill_siemens.py
"""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from backfill_common import base_argparser, print_summary, setup_logging


def main():
    parser = base_argparser("Siemens ProductCERT CSAF backfill")
    args = parser.parse_args()

    logger = setup_logging("siemens")
    logger.info("Starting Siemens ProductCERT backfill")

    from advisoryops.sources.siemens_productcert_backfill import run_backfill

    start = time.monotonic()
    stats = run_backfill()
    print_summary("Siemens ProductCERT", stats, start)
    return 0


if __name__ == "__main__":
    sys.exit(main())
