from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _read_jsonl(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(f"Input issues file not found: {path}")
    out: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            out.append(json.loads(line))
    return out


def _write_jsonl(path: Path, rows: Iterable[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n")


_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)


def _extract_cves(issue: Dict[str, Any]) -> List[str]:
    # Prefer explicit field if present
    cves = issue.get("cves")
    if isinstance(cves, list) and cves:
        return sorted({str(c).upper() for c in cves if str(c)})
    # Else detect from issue_id/title/summary
    hay = " ".join([
        str(issue.get("issue_id") or ""),
        str(issue.get("title") or ""),
        str(issue.get("summary") or ""),
    ])
    found = {m.group(0).upper() for m in _CVE_RE.finditer(hay)}
    return sorted(found)


def _infer_exploit(issue: Dict[str, Any]) -> Dict[str, bool]:
    # Deterministic heuristics (no GPT yet)
    sources = issue.get("sources") or []
    src_text = " ".join(str(s) for s in sources).lower() if isinstance(sources, list) else str(sources).lower()
    title = str(issue.get("title") or "")
    summary = str(issue.get("summary") or "")
    text = f"{src_text}\n{title}\n{summary}".lower()

    kev = ("cisa-kev" in src_text) or ("kev" in src_text) or ("known exploited" in text)
    active = ("actively exploited" in text) or ("active exploitation" in text)
    poc = ("proof of concept" in text) or (re.search(r"\bpoc\b", text) is not None)
    ransomware = ("ransomware" in text)

    return {
        "kev": bool(kev),
        "active_exploitation": bool(active),
        "poc": bool(poc),
        "ransomware": bool(ransomware),
    }


def _infer_impact(issue: Dict[str, Any]) -> Dict[str, bool]:
    title = str(issue.get("title") or "")
    summary = str(issue.get("summary") or "")
    text = f"{title}\n{summary}".lower()

    rce = ("remote code execution" in text) or (re.search(r"\brce\b", text) is not None) or ("code execution" in text)
    priv_esc = ("privilege escalation" in text) or ("priv esc" in text)
    auth_bypass = ("authentication bypass" in text) or ("auth bypass" in text)
    data_exfil = ("data exfiltration" in text) or ("exfiltration" in text)

    return {
        "rce": bool(rce),
        "priv_esc": bool(priv_esc),
        "auth_bypass": bool(auth_bypass),
        "data_exfil": bool(data_exfil),
    }


def _tag_issue(issue: Dict[str, Any]) -> Dict[str, Any]:
    issue_id = str(issue.get("issue_id") or "")
    cves = _extract_cves(issue)
    exploit = _infer_exploit(issue)
    impact = _infer_impact(issue)

    # Simple confidence: higher when CVE or KEV
    conf = 0.4
    if cves:
        conf += 0.2
    if exploit.get("kev"):
        conf += 0.3
    if exploit.get("active_exploitation"):
        conf += 0.1
    conf = max(0.0, min(1.0, conf))

    return {
        "issue_id": issue_id,
        "cves": cves,
        "exploit": exploit,
        "impact": impact,
        "confidence": {"overall": round(conf, 2)},
    }


def tag_issues(
    *,
    in_issues: str = "outputs/correlate/issues.jsonl",
    out_root_tags: str = "outputs/tags",
) -> Tuple[Path, Path]:
    started_at = _utc_now_iso()

    in_path = Path(in_issues)
    out_root = Path(out_root_tags)
    out_root.mkdir(parents=True, exist_ok=True)

    issues = _read_jsonl(in_path)
    tags: List[Dict[str, Any]] = [_tag_issue(i) for i in issues]

    # Deterministic order by issue_id
    tags.sort(key=lambda r: str(r.get("issue_id", "")))

    out_tags = out_root / "tags.jsonl"
    out_meta = out_root / "meta.json"

    _write_jsonl(out_tags, tags)

    meta = {
        "started_at": started_at,
        "finished_at": _utc_now_iso(),
        "inputs": {"in_issues": str(in_path)},
        "outputs": {"tags_jsonl": str(out_tags), "meta_json": str(out_meta)},
        "counts": {"issues_in": len(issues), "tags_out": len(tags)},
        "schema": {
            "required_keys": ["issue_id", "cves", "exploit", "impact", "confidence"],
            "exploit_keys": ["kev", "active_exploitation", "poc", "ransomware"],
            "impact_keys": ["rce", "priv_esc", "auth_bypass", "data_exfil"],
        },
    }
    out_meta.write_text(json.dumps(meta, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    print("Tag summary:")
    print(f"  Input:   {in_path}")
    print(f"  Tags:    {out_tags}")
    print(f"  Meta:    {out_meta}")
    print(f"  Issues:  {len(issues)}")

    return out_tags, out_meta
