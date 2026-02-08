from __future__ import annotations
import argparse
from pathlib import Path
from .discover import discover
from .extract import extract_advisory_record
from .ingest import ingest_pdf_file, ingest_text_file, ingest_url
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
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="advisoryops", description="AdvisoryOps MVP CLI")
    sub = p.add_subparsers(dest="cmd", required=True)
    p_dis = sub.add_parser("discover", help="Discover advisories via RSS/Atom feeds")
    p_dis.add_argument("--source", required=True, choices=["cisa-icsma", "cisa-icsa", "fda-medwatch"])
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
    p_ext.add_argument("--advisory-id", required=True, help="e.g., adv_deadbeefcaf0")
    p_ext.add_argument("--model", help="Override model (else OPENAI_MODEL or default)")
    p_ext.set_defaults(fn=cmd_extract)
    return p
def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.fn(args)
if __name__ == "__main__":
    raise SystemExit(main())
