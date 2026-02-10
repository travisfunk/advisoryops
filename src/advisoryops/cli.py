from __future__ import annotations

import argparse
from pathlib import Path

from .discover import discover
from .extract import extract_advisory_record
from .ingest import ingest_pdf_file, ingest_text_file, ingest_url
from .source_run import source_run


def cmd_discover(args: argparse.Namespace) -> int:
    discover(
        args.source,
        limit=args.limit,
        out_root=args.out_root,
        show_links=args.show_links,
    )
    return 0


def cmd_ingest(args: argparse.Namespace) -> int:
    if args.url:
        advisory_id, out_dir = ingest_url(args.url)
    elif args.text_file:
        advisory_id, out_dir = ingest_text_file(Path(args.text_file))
    elif args.pdf_file:
        advisory_id, out_dir = ingest_pdf_file(Path(args.pdf_file))
    else:
        raise SystemExit("Provide one of --url, --text-file, or --pdf-file")

    print(f"advisory_id: {advisory_id}")
    print(f"output_dir:  {out_dir}")
    return 0


def cmd_extract(args: argparse.Namespace) -> int:
    out_path = extract_advisory_record(args.advisory_id, model=args.model)
    print(f"Wrote: {out_path}")
    return 0


def cmd_source_run(args: argparse.Namespace) -> int:
    source_run(
        args.source,
        limit=args.limit,
        ingest=args.ingest,
        dry_run=args.dry_run,
        ingest_mode=args.ingest_mode,
        out_root_discover=args.out_root_discover,
        out_root_runs=args.out_root_runs,
        show_links=args.show_links,
        reset_state=args.reset_state,
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="advisoryops", description="AdvisoryOps MVP CLI")
    sub = p.add_subparsers(dest="cmd", required=True)

    p_dis = sub.add_parser("discover", help="Discover items from configured sources (configs/sources.json)")
    p_dis.add_argument("--source", required=True, help="source_id from configs/sources.json")
    p_dis.add_argument("--limit", type=int, default=50)
    p_dis.add_argument("--out-root", default="outputs/discover")
    p_dis.add_argument("--show-links", action="store_true")
    p_dis.set_defaults(fn=cmd_discover)

    p_ing = sub.add_parser("ingest", help="Ingest URL/text/PDF -> normalized snapshot + hashes")
    p_ing.add_argument("--url", help="Public advisory URL (best-effort HTML text)")
    p_ing.add_argument("--text-file", help="Path to a .txt file")
    p_ing.add_argument("--pdf-file", help="Path to a .pdf file")
    p_ing.set_defaults(fn=cmd_ingest)

    p_ext = sub.add_parser("extract", help="Extract AdvisoryRecord.json from ingested snapshot")
    p_ext.add_argument("--advisory-id", dest="advisory_id", required=True, help="e.g., adv_deadbeefcaf0")
    p_ext.add_argument("--model", help="Override model (else OPENAI_MODEL or default)")
    p_ext.set_defaults(fn=cmd_extract)

    p_sr = sub.add_parser("source-run", help="Discover + optional ingest from a configured source (configs/sources.json)")
    p_sr.add_argument("--source", required=True, help="source_id from configs/sources.json")
    p_sr.add_argument("--limit", type=int, required=True, help="Max items to consider/ingest (required to control spend)")
    p_sr.add_argument("--ingest", action="store_true", help="Fetch item URLs and write outputs/ingest artifacts")
    p_sr.add_argument("--dry-run", action="store_true", help="If --ingest, print planned URLs but do not fetch them")
    p_sr.add_argument("--ingest-mode", choices=["new", "all"], default="new", help="Ingest only new items (default) or top N regardless of state")
    p_sr.add_argument("--out-root-discover", default="outputs/discover")
    p_sr.add_argument("--out-root-runs", default="outputs/source_runs")
    p_sr.add_argument("--show-links", action="store_true")
    p_sr.add_argument("--reset-state", action="store_true", help="Delete outputs/discover/<source>/state.json before discovery (force items treated as new)")
    p_sr.set_defaults(fn=cmd_source_run)

    return p


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())