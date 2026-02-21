from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple


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

        self.signals.append(
            {
                "source": src,
                "signal_id": sid,
                "guid": guid,
                "link": link,
                "title": title,
                "published_date": pub,
                "fetched_at": fetched_at,
            }
        )

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


def correlate(
    *,
    out_root_discover: str = "outputs/discover",
    out_root_issues: str = "outputs/issues",
    sources: Optional[List[str]] = None,
    only_new: bool = False,
    limit_per_source: int = 200,
    limit_issues: int = 0,
    dry_run: bool = False,
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
                for cve in cves:
                    b = issues.get(cve)
                    if not b:
                        b = _IssueBuilder(issue_id=cve, issue_type="cve")
                        issues[cve] = b
                    b.cves.add(cve)
                    b.add_signal(it)
                    loaded_signals += 1
            else:
                # fallback: stable key based on normalized title + published date
                key_basis = f"{title_norm}|{pub}"
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

    meta = {
        "out_root_discover": str(discover_root),
        "out_root_issues": str(issues_root),
        "only_new": bool(only_new),
        "limit_per_source": int(limit_per_source),
        "limit_issues": int(limit_issues),
        "scanned_sources": int(scanned_sources),
        "loaded_signals": int(loaded_signals),
        "built_issues": int(len(issues)),
        "outputs": {
            "issues_jsonl": str(out_issues),
            "meta_json": str(out_meta),
        },
    }

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

    # deterministic order
    issue_objs = [issues[k].to_obj() for k in sorted(issues.keys())]

    lines = [json.dumps(o, ensure_ascii=False, sort_keys=True) for o in issue_objs]
    out_issues.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    out_meta.write_text(json.dumps(meta, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    print("")
    print(f"Wrote: {out_issues}")
    print(f"Wrote: {out_meta}")

    return out_issues, out_meta
