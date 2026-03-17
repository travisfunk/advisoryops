from __future__ import annotations

import argparse
from pathlib import Path

from .discover import discover
from .extract import extract_advisory_record
from .ingest import ingest_pdf_file, ingest_text_file, ingest_url
from .source_run import source_run
from .correlate import correlate
from .community_build import build_community_feed


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


def cmd_tag(args) -> int:
    """
    Tag correlated Issues into a strict JSONL tag artifact (outputs/tags).
    """
    from .tag import tag_issues

    out_tags, out_meta = tag_issues(
        in_issues=args.in_issues,
        out_root_tags=args.out_root_tags,
    )

    print("")
    print(f"Wrote tags: {out_tags}")
    print(f"Wrote meta: {out_meta}")
    return 0

def cmd_score(args) -> int:
    """
    Score correlated Issues into priority/actions and write outputs/scored artifacts.
    """
    from .score import score_issues

    out_scored, out_alerts, out_meta = score_issues(
        in_issues=args.in_issues,
        out_root_scored=args.out_root_scored,
        min_priority=args.min_priority,
        top=int(args.top),
    )

    print("")
    print(f"Wrote scored issues: {out_scored}")
    print(f"Wrote alerts:       {out_alerts}")
    print(f"Wrote score meta:   {out_meta}")
    return 0
def cmd_correlate(args) -> int:
    """
    Correlate discovered items across sources into Issues.
    """
    from .correlate import correlate
from .community_build import build_community_feed
    import inspect

    sources = []
    if getattr(args, "sources", ""):
        sources = [s.strip() for s in args.sources.split(",") if s.strip()]

    kwargs = {
        "out_root_discover": args.out_root_discover,
        "sources": sources or None,
    }

    sig = inspect.signature(correlate)

    # CLI flag is named --out-root-correlate; correlate() may use a different kwarg name.
    if "out_root_correlate" in sig.parameters:
        kwargs["out_root_correlate"] = args.out_root_correlate
    elif "out_root_issues" in sig.parameters:
        kwargs["out_root_issues"] = args.out_root_correlate
    elif "out_root" in sig.parameters:
        kwargs["out_root"] = args.out_root_correlate
    else:
        raise TypeError("correlate() signature missing expected output-root parameter")

    result = correlate(**kwargs)

    print("")
    print(f"Correlate result: {result}")
    return 0
def cmd_community_build(args) -> int:
    """
    Build the first combined community/public feed from the validated source set.
    """
    out_issues, out_alerts, out_meta = build_community_feed(
        set_id=args.set_id,
        refresh=args.refresh,
        refresh_limit=args.refresh_limit,
        out_root_discover=args.out_root_discover,
        out_root_runs=args.out_root_runs,
        out_root_community=args.out_root_community,
        only_new=args.only_new,
        limit_per_source=args.limit_per_source,
        limit_issues=args.limit_issues,
        min_priority=args.min_priority,
        top=int(args.top),
        latest=int(args.latest),
    )

    print("")
    print(f"Wrote public issues: {out_issues}")
    print(f"Wrote public alerts: {out_alerts}")
    print(f"Wrote community meta: {out_meta}")
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


    p_corr = sub.add_parser("correlate", help="Correlate discovered items across sources into Issues")
    p_corr.add_argument("--sources", default="", help="Comma-separated list of source_ids (default: all under outputs/discover)")
    p_corr.add_argument("--out-root-discover", default="outputs/discover")
    p_corr.add_argument("--out-root-correlate", default="outputs/correlate")
    p_corr.set_defaults(fn=cmd_correlate)


    p_score = sub.add_parser("score", help="Score correlated issues into priority/actions (writes outputs/scored)")
    p_score.add_argument("--in-issues", default="outputs/correlate/issues.jsonl", help="Input issues JSONL (default: outputs/correlate/issues.jsonl)")
    p_score.add_argument("--out-root-scored", default="outputs/scored", help="Output root for scored artifacts (default: outputs/scored)")
    p_score.add_argument("--min-priority", default="P1", choices=["P0","P1","P2","P3"], help="Minimum priority to include in alerts.jsonl (default: P1)")
    p_score.add_argument("--top", type=int, default=50, help="Maximum number of alerts to write (0 = no limit; default: 50)")
    p_score.set_defaults(fn=cmd_score)


    p_tag = sub.add_parser("tag", help="Tag correlated issues (writes outputs/tags/tags.jsonl + meta.json)")
    p_tag.add_argument("--in-issues", default="outputs/correlate/issues.jsonl", help="Input issues JSONL (default: outputs/correlate/issues.jsonl)")
    p_tag.add_argument("--out-root-tags", default="outputs/tags", help="Output root for tags artifacts (default: outputs/tags)")
    p_tag.set_defaults(fn=cmd_tag)

    p_comm = sub.add_parser("community-build", help="Build the combined community/public feed from the validated source manifest")
    p_comm.add_argument("--set-id", default="gold_pass1", help="Validated set id from configs/community_public_sources.json (default: gold_pass1)")
    p_comm.add_argument("--refresh", action="store_true", help="Refresh selected sources into discover outputs before building the community feed")
    p_comm.add_argument("--refresh-limit", type=int, default=10, help="Per-source discover limit when --refresh is used (default: 10)")
    p_comm.add_argument("--out-root-discover", default="outputs/discover", help="Discover root to read/write source items (default: outputs/discover)")
    p_comm.add_argument("--out-root-runs", default="outputs/source_runs", help="Source-run report root when --refresh is used (default: outputs/source_runs)")
    p_comm.add_argument("--out-root-community", default="outputs/community_public", help="Output root for community/public artifacts (default: outputs/community_public)")
    p_comm.add_argument("--only-new", action="store_true", help="Use new_items.jsonl instead of items.jsonl when correlating source outputs")
    p_comm.add_argument("--limit-per-source", type=int, default=200, help="Maximum discovered items to load per source during correlation (default: 200)")
    p_comm.add_argument("--limit-issues", type=int, default=0, help="Optional cap on total issues built (default: 0 = no cap)")
    p_comm.add_argument("--min-priority", default="P2", choices=["P0", "P1", "P2", "P3"], help="Minimum priority to include in alerts_public.jsonl (default: P2)")
    p_comm.add_argument("--top", type=int, default=100, help="Maximum number of alert rows to keep (0 = no cap; default: 100)")
    p_comm.add_argument("--latest", type=int, default=50, help="Maximum number of rows to write to feed_latest.json (default: 50)")
    p_comm.set_defaults(fn=cmd_community_build)

    return p


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())