#!/usr/bin/env python3
"""Master backfill launcher — runs all 8 backfill modules in sequence.

Runs the fast modules first, NVD last (longest).
Each module is resumable — if interrupted, re-run and it picks up where it left off.

Usage:
    python scripts/backfill_all.py              # All modules, NVD with confirmation
    python scripts/backfill_all.py --yes        # Skip NVD confirmation
    python scripts/backfill_all.py --skip-nvd   # Skip NVD (run the 7 fast ones)
    python scripts/backfill_all.py --limit 200  # Limit each module to 200 records
"""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from backfill_common import base_argparser, format_duration, print_summary, setup_logging

MODULES = [
    # (name, import_path, function, supports_limit, est_time)
    ("CISA ICSMA",         "advisoryops.sources.cisa_icsma_backfill",         "run_backfill", False, "3-5 min"),
    ("MHRA UK",            "advisoryops.sources.mhra_uk_backfill",            "run_backfill", True,  "2-5 min"),
    ("Health Canada",      "advisoryops.sources.health_canada_backfill",      "run_backfill", True,  "1-2 min"),
    ("Philips PSIRT",      "advisoryops.sources.philips_psirt_backfill",      "run_backfill", False, "1-3 min"),
    ("Siemens ProductCERT","advisoryops.sources.siemens_productcert_backfill","run_backfill", False, "10-20 min"),
    ("openFDA Recalls",    "advisoryops.sources.openfda_backfill",            "run_backfill", True,  "30-60 min"),
    ("FDA Enforcement",    "advisoryops.sources.fda_safety_comms_backfill",   "run_backfill", True,  "20-40 min"),
    # NVD last — it's the long one
    ("NVD",                "advisoryops.sources.nvd_backfill",                "run_backfill", True,  "24-48 hours"),
]


def main():
    parser = base_argparser("Run all 8 backfill modules in sequence")
    parser.add_argument("--yes", "-y", action="store_true", help="Skip NVD confirmation prompt")
    parser.add_argument("--skip-nvd", action="store_true", dest="skip_nvd", help="Skip the NVD backfill (longest)")
    args = parser.parse_args()

    logger = setup_logging("backfill_all")

    print()
    print("=" * 60)
    print("  AdvisoryOps Full Backfill")
    print("=" * 60)
    print()
    print("  Modules to run:")
    for name, _, _, supports_limit, est in MODULES:
        skip = " (SKIP)" if name == "NVD" and args.skip_nvd else ""
        limit_note = f" (limit={args.limit})" if args.limit and supports_limit else ""
        print(f"    - {name}: ~{est}{limit_note}{skip}")
    print()

    overall_start = time.monotonic()
    results = {}

    for name, module_path, fn_name, supports_limit, est in MODULES:
        if name == "NVD" and args.skip_nvd:
            print(f"\n--- Skipping {name} (--skip-nvd) ---")
            results[name] = {"status": "skipped"}
            continue

        if name == "NVD" and not args.limit and not args.yes:
            print()
            resp = input(f"Pull 240,000+ NVD CVEs? ~24-48 hours. Continue? [y/N] ")
            if resp.strip().lower() not in ("y", "yes"):
                print("Skipping NVD.")
                results[name] = {"status": "skipped"}
                continue

        print()
        print(f"{'=' * 60}")
        print(f"  {name} (est. {est})")
        print(f"{'=' * 60}")

        try:
            import importlib
            mod = importlib.import_module(module_path)
            fn = getattr(mod, fn_name)

            kwargs = {}
            if args.limit and supports_limit:
                kwargs["max_results"] = args.limit

            start = time.monotonic()
            logger.info("Starting %s backfill", name)
            stats = fn(**kwargs)
            elapsed = time.monotonic() - start

            results[name] = stats
            print_summary(name, stats, start)
            logger.info("%s completed in %s: %s", name, format_duration(elapsed), stats.get("status"))

        except Exception as exc:
            logger.error("%s failed: %s", name, exc)
            results[name] = {"status": "error", "error": str(exc)}
            print(f"\n  ERROR: {exc}")
            print("  Continuing with next module...")

    # Overall summary
    overall_elapsed = time.monotonic() - overall_start
    print()
    print("=" * 60)
    print("  OVERALL BACKFILL SUMMARY")
    print("=" * 60)
    print(f"  Total time: {format_duration(overall_elapsed)}")
    print()
    print(f"  {'Module':<25} {'Status':<15} {'Detail'}")
    print(f"  {'-'*25} {'-'*15} {'-'*30}")
    for name, stats in results.items():
        status = stats.get("status", "unknown")
        detail = ""
        for key in ("cves_fetched", "records_fetched", "advisories_total",
                     "recalls_fetched", "advisories_found", "advisories_in_feed",
                     "recalls_discovered"):
            if key in stats:
                detail = f"{stats[key]} records"
                break
        errors = stats.get("errors") or []
        if errors:
            detail += f" ({len(errors)} errors)"
        print(f"  {name:<25} {status:<15} {detail}")
    print("=" * 60)

    failed = sum(1 for s in results.values() if s.get("status") == "error")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
