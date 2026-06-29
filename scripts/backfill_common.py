"""Shared utilities for backfill launcher scripts."""
from __future__ import annotations

import argparse
import logging
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# Ensure project src is on path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

LOG_DIR = Path("logs")


def setup_logging(name: str, *, level: int = logging.INFO) -> logging.Logger:
    """Configure logging to both console and file."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    log_file = LOG_DIR / f"{name}_backfill.log"

    logger = logging.getLogger()
    logger.setLevel(level)

    fmt = logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s")

    # Console handler
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(fmt)
    logger.addHandler(ch)

    # File handler
    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    return logging.getLogger(name)


def base_argparser(description: str) -> argparse.ArgumentParser:
    """Create a base argument parser with --limit and --resume flags."""
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument(
        "--limit", type=int, default=None,
        help="Maximum records to fetch (default: all)",
    )
    parser.add_argument(
        "--resume", action="store_true",
        help="Resume from last saved progress (default behavior — included for clarity)",
    )
    return parser


def format_duration(seconds: float) -> str:
    """Format seconds into human-readable duration."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        return f"{seconds / 60:.1f}m"
    else:
        h = int(seconds // 3600)
        m = int((seconds % 3600) // 60)
        return f"{h}h {m}m"


def print_summary(name: str, stats: dict, start_time: float) -> None:
    """Print a final summary of the backfill run."""
    elapsed = time.monotonic() - start_time
    print()
    print("=" * 60)
    print(f"  {name} Backfill Summary")
    print("=" * 60)
    print(f"  Status:   {stats.get('status', 'unknown')}")
    for key, val in stats.items():
        if key in ("status", "errors", "started_at", "finished_at"):
            continue
        print(f"  {key}: {val}")
    errors = stats.get("errors") or []
    if errors:
        print(f"  Errors:   {len(errors)}")
        for e in errors[:5]:
            print(f"    - {e}")
        if len(errors) > 5:
            print(f"    ... and {len(errors) - 5} more")
    print(f"  Elapsed:  {format_duration(elapsed)}")
    print("=" * 60)
