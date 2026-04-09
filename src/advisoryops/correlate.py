"""Stage 2 of the pipeline: signal correlation → deduplicated Issues.

Reads all ``items.jsonl`` files (one per source under ``outputs/discover/``)
and groups raw signals into deduplicated **Issues**.

Two-pass architecture
---------------------
Pass 1 — Deterministic grouping (always runs, zero cost):
  * Signals with a CVE ID in their guid/title/summary/link are grouped under
    that CVE as the ``issue_id`` (e.g. ``"CVE-2024-12345"``).
  * Signals without a CVE are grouped by a SHA-256 of their normalized title
    + published_date, producing a stable ``UNK-<hex16>`` issue_id.
  * Multiple sources reporting the same CVE are automatically merged — this
    is the primary deduplication mechanism.

Pass 2 — AI merge (optional, ``--ai-merge`` flag):
  * ``find_merge_candidates`` from ``ai_correlate.py`` computes Jaccard
    similarity pre-filter to find pairs worth asking about.
  * ``ai_merge_decision`` calls GPT-4o-mini for each candidate pair.
  * A Union-Find structure builds transitive merge groups so A→B + B→C
    correctly collapses A, B, C into one issue.
  * The surviving issue_id is chosen by: CVE IDs > UNK IDs (alphabetic).
  * A ``merge_log.jsonl`` audit trail is written for reproducibility.

Output:
  outputs/correlate/issues.jsonl   — one Issue per line, sorted by issue_id
  outputs/correlate/meta.json      — run metadata + counts

Issue schema (each line of issues.jsonl)::

    issue_id       — CVE-YYYY-NNNNN or UNK-<hex16>
    issue_type     — "cve" or "unknown"
    cves           — sorted list of CVE IDs found in this issue
    title          — longest / most canonical title seen across signals
    summary        — longest summary seen across signals
    canonical_link — NVD link preferred; else first link
    links          — sorted list of all links seen
    sources        — sorted list of source_ids that contributed signals
    published_dates — sorted list of all date strings seen
    first_seen_at  — earliest fetched_at timestamp across signals
    last_seen_at   — most recent fetched_at timestamp across signals
    counts         — {signals, sources, links}
    signals        — list of contributing signal records (for audit)
    merged_from    — list of absorbed issue_ids (only present after AI merge)
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple


_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)


def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", errors="ignore")).hexdigest()


def _text(x: Any) -> str:
    if x is None:
        return ""
    if isinstance(x, str):
        return x.strip()
    return str(x).strip()


def _norm_title(s: str) -> str:
    s = _text(s).lower()
    s = re.sub(r"[\s\-_]+", " ", s)
    s = re.sub(r"[^a-z0-9 .:/]+", "", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s


def _extract_cves(*parts: str) -> List[str]:
    found: Set[str] = set()
    for p in parts:
        for m in _CVE_RE.findall(_text(p)):
            found.add(m.upper())
    return sorted(found)


def _load_jsonl(path: Path) -> Iterable[Dict[str, Any]]:
    if not path.exists():
        return []
    items: List[Dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                items.append(obj)
        except Exception:
            # best-effort: skip bad lines
            continue
    return items


def _ensure_signal_id(item: Dict[str, Any], *, source_id: str) -> None:
    if item.get("signal_id"):
        return
    guid = _text(item.get("guid")) or _text(item.get("link")) or _text(item.get("title"))
    if not guid:
        return
    item["signal_id"] = _sha256_hex(f"{source_id}|{guid}")


@dataclass
class _IssueBuilder:
    issue_id: str
    issue_type: str
    cves: Set[str] = field(default_factory=set)
    sources: Set[str] = field(default_factory=set)
    links: Set[str] = field(default_factory=set)
    titles: Set[str] = field(default_factory=set)
    summaries: Set[str] = field(default_factory=set)
    published_dates: Set[str] = field(default_factory=set)
    first_seen_at: Optional[str] = None
    last_seen_at: Optional[str] = None
    signals: List[Dict[str, Any]] = field(default_factory=list)

    def add_signal(self, it: Dict[str, Any]) -> None:
        src = _text(it.get("source"))
        fetched_at = _text(it.get("fetched_at"))
        pub = _text(it.get("published_date"))
        link = _text(it.get("link"))
        title = _text(it.get("title"))
        summ = _text(it.get("summary"))
        guid = _text(it.get("guid"))
        sid = _text(it.get("signal_id"))

        if src:
            self.sources.add(src)
        if link:
            self.links.add(link)
        if title:
            self.titles.add(title)
        if summ:
            self.summaries.add(summ)
        if pub:
            self.published_dates.add(pub)

        if fetched_at:
            if (self.first_seen_at is None) or (fetched_at < self.first_seen_at):
                self.first_seen_at = fetched_at
            if (self.last_seen_at is None) or (fetched_at > self.last_seen_at):
                self.last_seen_at = fetched_at

        sig = {
            "source": src,
            "signal_id": sid,
            "guid": guid,
            "link": link,
            "title": title,
            "published_date": pub,
            "fetched_at": fetched_at,
        }
        # Passthrough KEV fields from discover items
        for key in ("kev_required_action", "kev_due_date", "kev_vendor",
                     "kev_product", "kev_vulnerability_name"):
            val = it.get(key)
            if val:
                sig[key] = val
        self.signals.append(sig)

    def to_obj(self) -> Dict[str, Any]:
        # canonical title/summary: pick the longest (cheap + deterministic)
        # canonical title/summary: deterministic
        title = ""
        if self.issue_type == "cve":
            needle = self.issue_id.upper()
            for t in sorted(self.titles):
                if needle and needle in (t or "").upper():
                    title = t
                    break
            if not title:
                title = self.issue_id
        else:
            title = max(self.titles, key=len) if self.titles else ""
        summary = max(self.summaries, key=len) if self.summaries else ""

        def _prefer_link(links: List[str]) -> str:
            # Prefer NVD for CVE issues when present
            for l in links:
                if "nvd.nist.gov/vuln/detail/" in l:
                    return l
            return links[0] if links else ""

        links_sorted = sorted(self.links)
        signals_sorted = sorted(
            self.signals,
            key=lambda r: (r.get("source", ""), r.get("signal_id", ""), r.get("guid", ""), r.get("link", "")),
        )

        return {
            "issue_id": self.issue_id,
            "issue_type": self.issue_type,
            "cves": sorted(self.cves),
            "title": title,
            "summary": summary,
            "canonical_link": _prefer_link(links_sorted),
            "links": links_sorted,
            "sources": sorted(self.sources),
            "published_dates": sorted(self.published_dates),
            "first_seen_at": self.first_seen_at,
            "last_seen_at": self.last_seen_at,
            "counts": {
                "signals": len(self.signals),
                "sources": len(self.sources),
                "links": len(self.links),
            },
            "signals": signals_sorted,
        }


# ===========================================================================
# AI merge helpers (Task 2.3)
# ===========================================================================

_MERGE_CONFIDENCE_THRESHOLD = 0.70  # minimum confidence to act on a same_issue=True decision


def _survivor_priority(issue_id: str) -> tuple:
    """Lower tuple = higher priority = chosen as the surviving issue_id."""
    return (0, issue_id) if issue_id.upper().startswith("CVE-") else (1, issue_id)


class _UnionFind:
    """Disjoint-set structure for transitive merge groups."""

    def __init__(self, keys: Iterable[str]) -> None:
        self._parent: Dict[str, str] = {k: k for k in keys}

    def find(self, k: str) -> str:
        while self._parent[k] != k:
            self._parent[k] = self._parent[self._parent[k]]  # path compression
            k = self._parent[k]
        return k

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra == rb:
            return
        # Higher priority (lower tuple) becomes the canonical root
        if _survivor_priority(ra) <= _survivor_priority(rb):
            self._parent[rb] = ra
        else:
            self._parent[ra] = rb

    def groups(self) -> Dict[str, List[str]]:
        """Return {root: [all members]} for every group."""
        result: Dict[str, List[str]] = {}
        for k in self._parent:
            r = self.find(k)
            result.setdefault(r, []).append(k)
        return result


def _merge_issues_group(
    issues: List[Dict[str, Any]],
    *,
    survivor_id: str,
) -> Dict[str, Any]:
    """Merge a group of issue dicts into a single issue keyed by *survivor_id*.

    The surviving issue collects the union of CVEs, sources, links, signals, etc.
    from all members.  ``merged_from`` lists the IDs that were absorbed.
    """
    absorbed_ids = sorted(iss["issue_id"] for iss in issues if iss["issue_id"] != survivor_id)

    cves: Set[str] = set()
    sources: Set[str] = set()
    links: Set[str] = set()
    published_dates: Set[str] = set()
    titles: Set[str] = set()
    summaries: Set[str] = set()
    first_seen_ats: List[str] = []
    last_seen_ats: List[str] = []
    all_signals: List[Dict[str, Any]] = []

    for iss in issues:
        cves.update(iss.get("cves") or [])
        sources.update(iss.get("sources") or [])
        links.update(iss.get("links") or [])
        published_dates.update(iss.get("published_dates") or [])
        if iss.get("title"):
            titles.add(iss["title"])
        if iss.get("summary"):
            summaries.add(iss["summary"])
        if iss.get("first_seen_at"):
            first_seen_ats.append(iss["first_seen_at"])
        if iss.get("last_seen_at"):
            last_seen_ats.append(iss["last_seen_at"])
        all_signals.extend(iss.get("signals") or [])

    issue_type = "cve" if any(iss.get("issue_type") == "cve" for iss in issues) else "unknown"

    # Canonical title: for CVE survivors prefer one that contains the CVE ID
    title = ""
    if issue_type == "cve" and survivor_id.upper().startswith("CVE-"):
        needle = survivor_id.upper()
        for t in sorted(titles):
            if needle in (t or "").upper():
                title = t
                break
    if not title:
        title = max(titles, key=len) if titles else ""

    summary = max(summaries, key=len) if summaries else ""

    links_sorted = sorted(links)

    def _prefer_link(ls: List[str]) -> str:
        for lnk in ls:
            if "nvd.nist.gov/vuln/detail/" in lnk:
                return lnk
        return ls[0] if ls else ""

    # Deduplicate signals by signal_id (fall back to full JSON key)
    seen_sig_keys: Set[str] = set()
    deduped_signals: List[Dict[str, Any]] = []
    for sig in all_signals:
        sig_key = sig.get("signal_id") or json.dumps(sig, sort_keys=True)
        if sig_key not in seen_sig_keys:
            seen_sig_keys.add(sig_key)
            deduped_signals.append(sig)

    signals_sorted = sorted(
        deduped_signals,
        key=lambda r: (r.get("source", ""), r.get("signal_id", ""), r.get("guid", ""), r.get("link", "")),
    )

    return {
        "issue_id": survivor_id,
        "issue_type": issue_type,
        "cves": sorted(cves),
        "title": title,
        "summary": summary,
        "canonical_link": _prefer_link(links_sorted),
        "links": links_sorted,
        "sources": sorted(sources),
        "published_dates": sorted(published_dates),
        "first_seen_at": min(first_seen_ats) if first_seen_ats else None,
        "last_seen_at": max(last_seen_ats) if last_seen_ats else None,
        "counts": {
            "signals": len(signals_sorted),
            "sources": len(sources),
            "links": len(links_sorted),
        },
        "signals": signals_sorted,
        "merged_from": absorbed_ids,
    }


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _apply_ai_merge(
    issue_objs: List[Dict[str, Any]],
    *,
    out_root: Path,
    model: str = "gpt-4o-mini",
    cache_root: str = "outputs/ai_cache",
    _decision_fn: Optional[Callable[[Dict[str, Any], Dict[str, Any]], Any]] = None,
) -> Tuple[List[Dict[str, Any]], Path]:
    """Run the AI merge pass on already-correlated issue dicts.

    Parameters
    ----------
    issue_objs:
        List of issue dicts from the deterministic correlate pass.
    out_root:
        Directory where merge_log.jsonl will be written (same dir as issues.jsonl).
    model:
        OpenAI model to use for merge decisions.
    cache_root:
        On-disk cache root for AI responses.
    _decision_fn:
        Injectable decision function for testing.  Signature:
        ``(issue_a, issue_b) -> MergeDecision``.  Defaults to
        ``ai_merge_decision`` from ``ai_correlate``.

    Returns
    -------
    (merged_issue_list, merge_log_path)
    """
    from advisoryops.ai_correlate import find_merge_candidates, ai_merge_decision  # lazy import

    if _decision_fn is None:
        def _decision_fn(a: Dict[str, Any], b: Dict[str, Any]) -> Any:
            return ai_merge_decision(a, b, model=model, cache_root=cache_root)

    by_id: Dict[str, Dict[str, Any]] = {iss["issue_id"]: iss for iss in issue_objs}

    candidates = find_merge_candidates(issue_objs)
    print(f"  AI merge: {len(issue_objs)} issues, {len(candidates)} candidate pairs")

    uf = _UnionFind(by_id.keys())
    log_entries: List[Dict[str, Any]] = []

    for id_a, id_b, sim_score in candidates:
        decision = _decision_fn(by_id[id_a], by_id[id_b])
        do_merge = decision.same_issue and decision.confidence >= _MERGE_CONFIDENCE_THRESHOLD

        log_entries.append({
            "ts": _utc_now_iso(),
            "candidate_a": id_a,
            "candidate_b": id_b,
            "similarity_score": round(sim_score, 4),
            "same_issue": decision.same_issue,
            "confidence": round(decision.confidence, 4),
            "reasoning": decision.reasoning,
            "model": decision.model,
            "tokens_used": decision.tokens_used,
            "merged": do_merge,
        })

        if do_merge:
            uf.union(id_a, id_b)

    # Write merge log
    out_root.mkdir(parents=True, exist_ok=True)
    merge_log_path = out_root / "merge_log.jsonl"
    lines = [json.dumps(e, ensure_ascii=False) for e in log_entries]
    merge_log_path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")

    # Build output issue list
    groups = uf.groups()
    merged_count = sum(1 for members in groups.values() if len(members) > 1)
    absorbed_total = sum(len(members) - 1 for members in groups.values() if len(members) > 1)
    print(f"  AI merge: {merged_count} groups merged, {absorbed_total} issues absorbed")

    result: List[Dict[str, Any]] = []
    for survivor_id, members in sorted(groups.items()):
        if len(members) == 1:
            result.append(by_id[survivor_id])
        else:
            group_issues = [by_id[m] for m in members]
            result.append(_merge_issues_group(group_issues, survivor_id=survivor_id))

    # Stable deterministic order
    result.sort(key=lambda iss: iss["issue_id"])
    return result, merge_log_path


# ===========================================================================


def correlate(
    *,
    out_root_discover: str = "outputs/discover",
    out_root_issues: str = "outputs/issues",
    sources: Optional[List[str]] = None,
    only_new: bool = False,
    limit_per_source: int = 200,
    limit_issues: int = 0,
    dry_run: bool = False,
    ai_merge: bool = False,
    ai_merge_model: str = "gpt-4o-mini",
    ai_merge_cache_root: str = "outputs/ai_cache",
    _ai_decision_fn: Optional[Callable] = None,
) -> Tuple[Optional[Path], Optional[Path]]:
    if limit_per_source <= 0:
        raise ValueError("--limit-per-source must be > 0")
    if limit_issues < 0:
        raise ValueError("--limit-issues must be >= 0")

    discover_root = Path(out_root_discover)
    issues_root = Path(out_root_issues)

    if not discover_root.exists():
        raise ValueError(f"discover root not found: {discover_root}")

    # determine sources to scan
    if sources:
        src_ids = sources
    else:
        src_ids = sorted([p.name for p in discover_root.iterdir() if p.is_dir()])

    issues: Dict[str, _IssueBuilder] = {}
    scanned_sources = 0
    loaded_signals = 0

    fname = "new_items.jsonl" if only_new else "items.jsonl"

    for src_id in src_ids:
        src_dir = discover_root / src_id
        if not src_dir.exists():
            continue

        path = src_dir / fname
        if not path.exists():
            continue

        scanned_sources += 1
        items = list(_load_jsonl(path))[:limit_per_source]

        for it in items:
            it = dict(it)
            it["source"] = _text(it.get("source")) or src_id
            _ensure_signal_id(it, source_id=it["source"])

            cves = _extract_cves(
                _text(it.get("guid")),
                _text(it.get("title")),
                _text(it.get("summary")),
                _text(it.get("link")),
            )

            pub = _text(it.get("published_date"))
            title_norm = _norm_title(_text(it.get("title")))

            if cves:
                # A single signal may reference multiple CVEs (e.g. a batch advisory).
                # Each CVE gets its own IssueBuilder; they all share the same signal.
                for cve in cves:
                    b = issues.get(cve)
                    if not b:
                        b = _IssueBuilder(issue_id=cve, issue_type="cve")
                        issues[cve] = b
                    b.cves.add(cve)
                    b.add_signal(it)
                    loaded_signals += 1
            else:
                # No CVE found — use a SHA-256 of source + normalized title +
                # published date as a stable, collision-resistant group key.
                # Prefix with "UNK-" so these are clearly distinguished from
                # CVE-based issues downstream.
                #
                # Triage fix for Problem 2 (see docs/session_state.md): include
                # source_id in the key basis so signals from different sources
                # never collide regardless of title. Without this, threat intel
                # feeds emitting signals with empty/placeholder titles merged
                # into giant fake issues (e.g. Impella FDA recall with hundreds
                # of unrelated IOCs from urlhaus, feodo, ssl-blacklist).
                # Full architectural fix (separating threatintel from advisory
                # routing entirely) is deferred to post-grant work.
                key_basis = f"{it['source']}|{title_norm}|{pub}"
                issue_id = "UNK-" + _sha256_hex(key_basis)[:16]
                b = issues.get(issue_id)
                if not b:
                    b = _IssueBuilder(issue_id=issue_id, issue_type="unknown")
                    issues[issue_id] = b
                b.add_signal(it)
                loaded_signals += 1

            if limit_issues and len(issues) >= limit_issues:
                break

        if limit_issues and len(issues) >= limit_issues:
            break

    out_issues = issues_root / "issues.jsonl"
    out_meta = issues_root / "meta.json"

    print("Correlation summary:")
    print(f"  Discover root:   {discover_root}")
    print(f"  Issues root:     {issues_root}")
    print(f"  Sources scanned: {scanned_sources}")
    print(f"  Signals loaded:  {loaded_signals}")
    print(f"  Issues built:    {len(issues)}")
    print(f"  Mode:            {'only-new' if only_new else 'items'}")
    if dry_run:
        print("  Dry-run:         True (no files written)")
        return None, None

    issues_root.mkdir(parents=True, exist_ok=True)

    # Deterministic order after deterministic pass
    issue_objs = [issues[k].to_obj() for k in sorted(issues.keys())]

    # --- Optional AI merge second pass ---
    merge_log_path: Optional[Path] = None
    issues_after_merge = len(issue_objs)
    merges_performed = 0

    if ai_merge:
        print(f"  AI merge:        enabled (model={ai_merge_model})")
        issue_objs, merge_log_path = _apply_ai_merge(
            issue_objs,
            out_root=issues_root,
            model=ai_merge_model,
            cache_root=ai_merge_cache_root,
            _decision_fn=_ai_decision_fn,
        )
        issues_after_merge = len(issue_objs)
        merges_performed = sum(1 for iss in issue_objs if iss.get("merged_from"))

    meta = {
        "out_root_discover": str(discover_root),
        "out_root_issues": str(issues_root),
        "only_new": bool(only_new),
        "limit_per_source": int(limit_per_source),
        "limit_issues": int(limit_issues),
        "scanned_sources": int(scanned_sources),
        "loaded_signals": int(loaded_signals),
        "built_issues": int(len(issues)),
        "ai_merge": {
            "enabled": bool(ai_merge),
            "model": ai_merge_model if ai_merge else None,
            "issues_before": int(len(issues)),
            "issues_after": int(issues_after_merge),
            "merges_performed": int(merges_performed),
            "merge_log": str(merge_log_path) if merge_log_path else None,
        },
        "outputs": {
            "issues_jsonl": str(out_issues),
            "meta_json": str(out_meta),
        },
    }

    lines = [json.dumps(o, ensure_ascii=False, sort_keys=True) for o in issue_objs]
    out_issues.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    out_meta.write_text(json.dumps(meta, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    print("")
    print(f"Wrote: {out_issues}")
    print(f"Wrote: {out_meta}")
    if merge_log_path:
        print(f"Wrote: {merge_log_path}")

    return out_issues, out_meta
