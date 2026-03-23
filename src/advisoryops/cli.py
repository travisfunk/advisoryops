"""AdvisoryOps command-line interface.

This module is the single entry point for all CLI subcommands. It wires argparse
argument definitions to the underlying pipeline functions and is installed as the
``advisoryops`` console script via pyproject.toml / setup.cfg.

Pipeline subcommands (in pipeline order):
  discover        — fetch + parse one source feed → outputs/discover/<source>/
  ingest          — download and normalize a URL/text/PDF advisory
  extract         — AI extraction of an ingested advisory → AdvisoryRecord JSON
  source-run      — discover + optional ingest in one step
  correlate       — group discover outputs into deduplicated Issues
  tag             — deterministic exploit/impact tagging of Issues
  score           — priority scoring of Issues (v1 keyword or v2 healthcare-aware)
  recommend       — AI pattern selection → remediation packet (JSON/MD/CSV)
  evaluate        — run golden fixture evaluation harness
  community-build — end-to-end public feed builder (discover→correlate→score)

Usage::

    advisoryops discover --source cisa-icsma --limit 20
    advisoryops community-build --set-id gold_pass1 --out-root-community outputs/community_public
"""
from __future__ import annotations

import argparse
from pathlib import Path

from .discover import discover
from .extract import extract_advisory_record
from .ingest import ingest_pdf_file, ingest_text_file, ingest_url
from .source_run import source_run
from .correlate import correlate
from .community_build import build_community_feed
from .product_resolver import resolve_product
from .advisory_qa import answer_question


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
        scoring_version=args.scoring_version,
        ai_score=args.ai_score,
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
    import inspect

    sources = []
    if getattr(args, "sources", ""):
        sources = [s.strip() for s in args.sources.split(",") if s.strip()]

    kwargs = {
        "out_root_discover": args.out_root_discover,
        "sources": sources or None,
        "ai_merge": args.ai_merge,
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
def cmd_evaluate(args) -> int:
    """
    Run golden fixture evaluation and write summary reports.
    """
    from .eval_harness import evaluate

    summary_json, summary_md, fixtures_out = evaluate(
        fixtures_dir=args.fixtures,
        out_dir=args.out,
    )

    print("")
    print(f"Wrote summary JSON: {summary_json}")
    print(f"Wrote summary MD:   {summary_md}")
    print(f"Wrote per-fixture:  {fixtures_out}/")
    return 0


def cmd_recommend(args) -> int:
    """
    Generate a remediation packet for a scored issue and export it.
    """
    import json as _json
    from pathlib import Path as _Path
    from .playbook import load_playbook
    from .recommend import recommend_mitigations
    from .packet_export import export_json, export_markdown, export_csv_tasks, _safe_stem

    # ── Load issue ────────────────────────────────────────────────────────────
    in_issues = _Path(args.in_issues)
    if not in_issues.exists():
        raise SystemExit(f"Issues file not found: {in_issues}")

    issue = None
    with in_issues.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            obj = _json.loads(line)
            if obj.get("issue_id") == args.issue_id:
                issue = obj
                break

    if issue is None:
        raise SystemExit(
            f"Issue '{args.issue_id}' not found in {in_issues}.\n"
            f"Use --in-issues to specify a different file."
        )

    # ── Recommend ─────────────────────────────────────────────────────────────
    pb = load_playbook()
    packet = recommend_mitigations(
        issue,
        pb,
        model=args.model,
        no_cache=args.no_cache,
    )

    # ── Export ────────────────────────────────────────────────────────────────
    out_dir = _Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = _safe_stem(packet.issue_id)

    fmt = args.format.lower()
    if fmt == "json":
        out_path = export_json(packet, out_dir / f"{stem}_packet.json")
    elif fmt == "md":
        out_path = export_markdown(packet, pb, out_dir / f"{stem}_packet.md")
    elif fmt == "csv":
        out_path = export_csv_tasks(packet, pb, out_dir / f"{stem}_packet.csv")
    else:
        raise SystemExit(f"Unknown format: {fmt!r}")

    print(f"Wrote {fmt.upper()} packet: {out_path}")
    print(f"  Issue:    {packet.issue_id}")
    print(f"  Patterns: {[r.pattern_id for r in packet.recommended_patterns]}")
    print(f"  Cached:   {packet.from_cache}")
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
        recommend=args.recommend,
    )

    print("")
    print(f"Wrote public issues: {out_issues}")
    print(f"Wrote public alerts: {out_alerts}")
    print(f"Wrote community meta: {out_meta}")
    return 0

def cmd_ask(args: argparse.Namespace) -> int:
    """Answer a natural-language question against the advisory corpus."""
    import json as _json

    response = answer_question(
        args.question,
        issues_path=args.issues_path,
        top_k=args.top_k,
        model=args.model,
    )

    if args.json:
        print(_json.dumps(response, indent=2, ensure_ascii=False))
        return 0

    print(f"Question: {response['question']}")
    print(f"Answer: {response['answer']}")
    print()

    issues = response.get("supporting_issues") or []
    if issues:
        print("Supporting issues:")
        for si in issues:
            pri = si.get("priority") or "?"
            print(f"  [{pri}] {si['issue_id']}: {si['title']}")
        print()

    gaps = response.get("evidence_gaps") or []
    if gaps:
        print("Evidence gaps: " + "; ".join(gaps))
    else:
        print("Evidence gaps: (none)")

    return 0


def cmd_lookup(args: argparse.Namespace) -> int:
    """Look up issues by product name / nickname."""
    import json as _json

    results = resolve_product(
        args.product,
        issues_path=args.issues_path,
        top=args.top,
    )

    if not results:
        print(f"No matches found for: {args.product!r}")
        return 0

    print(f"Found {len(results)} match(es) for {args.product!r}:\n")
    for r in results:
        sources = ", ".join(r.get("sources") or []) or "(none)"
        print(
            f"  [{r['priority'] or '?':>2}] score={r['score']:>4}  "
            f"{r['issue_id']}  (matched: {r['match_field']})"
        )
        print(f"        {r['title']}")
        print(f"        sources: {sources}")
        print()

    if args.json:
        print(_json.dumps(results, indent=2, ensure_ascii=False))

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
    p_corr.add_argument("--ai-merge", action="store_true", dest="ai_merge",
                        help="Run AI-assisted merge pass after deterministic correlation (requires OPENAI_API_KEY)")
    p_corr.set_defaults(fn=cmd_correlate)


    p_score = sub.add_parser("score", help="Score correlated issues into priority/actions (writes outputs/scored)")
    p_score.add_argument("--in-issues", default="outputs/correlate/issues.jsonl", help="Input issues JSONL (default: outputs/correlate/issues.jsonl)")
    p_score.add_argument("--out-root-scored", default="outputs/scored", help="Output root for scored artifacts (default: outputs/scored)")
    p_score.add_argument("--min-priority", default="P1", choices=["P0","P1","P2","P3"], help="Minimum priority to include in alerts.jsonl (default: P1)")
    p_score.add_argument("--top", type=int, default=50, help="Maximum number of alerts to write (0 = no limit; default: 50)")
    p_score.add_argument("--scoring-version", default="v2", choices=["v1", "v2"], dest="scoring_version", help="Scoring algorithm version: v2 (default, healthcare-aware) or v1 (legacy keyword-only)")
    p_score.add_argument("--ai-score", action="store_true", dest="ai_score",
                         help="Run AI healthcare classification for issues without deterministic device/clinical signals (requires OPENAI_API_KEY)")
    p_score.set_defaults(fn=cmd_score)


    p_tag = sub.add_parser("tag", help="Tag correlated issues (writes outputs/tags/tags.jsonl + meta.json)")
    p_tag.add_argument("--in-issues", default="outputs/correlate/issues.jsonl", help="Input issues JSONL (default: outputs/correlate/issues.jsonl)")
    p_tag.add_argument("--out-root-tags", default="outputs/tags", help="Output root for tags artifacts (default: outputs/tags)")
    p_tag.set_defaults(fn=cmd_tag)

    p_eval = sub.add_parser("evaluate", help="Run golden fixture evaluation harness (writes outputs/eval/)")
    p_eval.add_argument("--fixtures", default="tests/fixtures/golden",
                        help="Golden fixtures directory (default: tests/fixtures/golden)")
    p_eval.add_argument("--out", default="outputs/eval",
                        help="Output directory for reports (default: outputs/eval)")
    p_eval.set_defaults(fn=cmd_evaluate)

    p_rec = sub.add_parser("recommend", help="Generate a remediation packet for a scored issue")
    p_rec.add_argument("--issue-id", dest="issue_id", required=True, help="Issue ID to look up (e.g. CVE-2024-1234)")
    p_rec.add_argument("--in-issues", dest="in_issues", default="outputs/scored/issues_scored.jsonl",
                       help="JSONL file to search for the issue (default: outputs/scored/issues_scored.jsonl)")
    p_rec.add_argument("--format", default="json", choices=["json", "md", "csv"],
                       help="Output format: json (default), md (markdown), or csv")
    p_rec.add_argument("--out", default="outputs/packets", help="Output directory (default: outputs/packets)")
    p_rec.add_argument("--model", default="gpt-4o-mini", help="AI model to use (default: gpt-4o-mini)")
    p_rec.add_argument("--no-cache", dest="no_cache", action="store_true",
                       help="Bypass AI response cache (always call API)")
    p_rec.set_defaults(fn=cmd_recommend)

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
    p_comm.add_argument("--recommend", action="store_true",
                        help="Generate JSON remediation packets for P0/P1 alerts (requires OPENAI_API_KEY)")
    p_comm.set_defaults(fn=cmd_community_build)

    p_ask = sub.add_parser(
        "ask",
        help="Ask a natural-language question against the advisory corpus",
    )
    p_ask.add_argument(
        "--question", required=True,
        help='Question to answer (e.g. "Which infusion pumps have critical vulnerabilities?")',
    )
    p_ask.add_argument(
        "--issues-path",
        dest="issues_path",
        default="outputs/community_public_expanded/correlate/issues.jsonl",
        help=(
            "Path to the correlated issues JSONL file "
            "(default: outputs/community_public_expanded/correlate/issues.jsonl)"
        ),
    )
    p_ask.add_argument(
        "--top-k", dest="top_k", type=int, default=5,
        help="Number of issues to use as context for the AI answer (default: 5)",
    )
    p_ask.add_argument(
        "--model", default="gpt-4o-mini",
        help="OpenAI model to use (default: gpt-4o-mini)",
    )
    p_ask.add_argument(
        "--json", action="store_true",
        help="Output the full structured JSON response instead of human-readable format",
    )
    p_ask.set_defaults(fn=cmd_ask)

    p_lookup = sub.add_parser(
        "lookup",
        help="Look up issues by product name or nickname",
    )
    p_lookup.add_argument(
        "--product", required=True,
        help='Product name or nickname to search for (e.g. "Sigma Spectrum")',
    )
    p_lookup.add_argument(
        "--issues-path",
        dest="issues_path",
        default="outputs/community_public_expanded/correlate/issues.jsonl",
        help=(
            "Path to the correlated issues JSONL file "
            "(default: outputs/community_public_expanded/correlate/issues.jsonl)"
        ),
    )
    p_lookup.add_argument(
        "--top", type=int, default=20,
        help="Maximum number of results to return (default: 20)",
    )
    p_lookup.add_argument(
        "--json", action="store_true",
        help="Also print results as a JSON array after the human-readable summary",
    )
    p_lookup.set_defaults(fn=cmd_lookup)

    return p


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
