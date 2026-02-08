from __future__ import annotations
import re
import tempfile
import time
from html import unescape
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from .util import (
    advisory_id_from_hash,
    ensure_dir,
    normalize_text,
    sha256_text,
    utc_now_iso,
    write_json,
)
OUTPUT_ROOT = Path("outputs/ingest")
DEFAULT_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AdvisoryOpsMVP/0.0.1"
# ---- HTML best-effort extraction (no extra deps) ----
_script_style_re = re.compile(r"(?is)<(script|style).*?>.*?</\1>")
_tag_re = re.compile(r"(?s)<[^>]+>")
_ws_re = re.compile(r"[ \t\f\v]+")
def _html_to_text(html: str) -> str:
    if not html:
        return ""
    html = _script_style_re.sub(" ", html)
    html = re.sub(r"(?is)<br\s*/?>", "\n", html)
    html = re.sub(r"(?is)</p\s*>", "\n", html)
    html = re.sub(r"(?is)</div\s*>", "\n", html)
    text = _tag_re.sub(" ", html)
    text = unescape(text)
    lines = []
    for line in text.splitlines():
        line = _ws_re.sub(" ", line).strip()
        if line:
            lines.append(line)
    return "\n".join(lines).strip()
# ---- HTTP fetching (retries + sane timeouts) ----
def _build_session(retries: int) -> requests.Session:
    retry = Retry(
        total=retries,
        connect=retries,
        read=retries,
        status=retries,
        backoff_factor=0.75,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset(["GET", "HEAD"]),
        raise_on_status=False,
        respect_retry_after_header=True,
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=10, pool_maxsize=10)
    s = requests.Session()
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    s.headers.update(
        {
            "User-Agent": DEFAULT_UA,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        }
    )
    return s
def _http_get(
    url: str,
    connect_timeout_s: int,
    read_timeout_s: int,
    retries: int,
) -> Tuple[requests.Response, Dict[str, Any]]:
    session = _build_session(retries=retries)
    t0 = time.monotonic()
    r = session.get(url, timeout=(connect_timeout_s, read_timeout_s), allow_redirects=True)
    elapsed_ms = int((time.monotonic() - t0) * 1000)
    meta = {
        "requested_url": url,
        "final_url": r.url,
        "status_code": r.status_code,
        "elapsed_ms": elapsed_ms,
        "content_type": r.headers.get("Content-Type", ""),
        "content_length": r.headers.get("Content-Length", ""),
        "headers": {
            k: v
            for k, v in r.headers.items()
            if k.lower()
            in {
                "content-type",
                "content-length",
                "last-modified",
                "etag",
                "cache-control",
                "date",
                "server",
            }
        },
    }
    return r, meta
# ---- PDF ----
def _read_pdf_text(pdf_path: str) -> str:
    from pypdf import PdfReader
    reader = PdfReader(pdf_path)
    parts = []
    for page in reader.pages:
        try:
            parts.append(page.extract_text() or "")
        except Exception:
            parts.append("")
    return "\n".join(parts).strip()
# ---- Ingest core ----
def ingest_from_text(
    raw_text: str,
    source_id: str,
    content_type: str = "text",
    extra_source_fields: Optional[Dict[str, Any]] = None,
    raw_artifacts: Optional[Dict[str, bytes]] = None,
) -> Tuple[str, Path]:
    raw_text = raw_text or ""
    norm = normalize_text(raw_text)
    content_hash = sha256_text(norm)
    advisory_id = advisory_id_from_hash(content_hash)
    out_dir = OUTPUT_ROOT / advisory_id
    ensure_dir(out_dir)
    raw_path = out_dir / "raw.txt"
    norm_path = out_dir / "normalized.txt"
    raw_path.write_text(raw_text, encoding="utf8", errors="ignore")
    norm_path.write_text(norm, encoding="utf8", errors="ignore")
    artifacts_written: Dict[str, str] = {}
    if raw_artifacts:
        for name, blob in raw_artifacts.items():
            p = out_dir / name
            p.write_bytes(blob)
            artifacts_written[name] = str(p)
    source_obj: Dict[str, Any] = {
        "advisory_id": advisory_id,
        "source_id": source_id,
        "content_hash": content_hash,
        "content_type": content_type,
        "created_utc": utc_now_iso(),
        "raw_path": str(raw_path),
        "normalized_path": str(norm_path),
    }
    if artifacts_written:
        source_obj["artifacts"] = artifacts_written
    if extra_source_fields:
        source_obj.update(extra_source_fields)
    write_json(out_dir / "source.json", source_obj)
    return advisory_id, out_dir
# THESE NAMES ARE REQUIRED BY cli.py
def ingest_text_file(path: Path) -> Tuple[str, Path]:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(str(p))
    raw_text = p.read_text(encoding="utf8", errors="ignore")
    return ingest_from_text(
        raw_text,
        source_id=f"text-file:{p.name}",
        content_type="text",
        extra_source_fields={"text_file": str(p)},
    )
def ingest_pdf_file(path: Path) -> Tuple[str, Path]:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(str(p))
    pdf_bytes = p.read_bytes()
    text = _read_pdf_text(str(p))
    return ingest_from_text(
        text,
        source_id=f"pdf-file:{p.name}",
        content_type="pdf",
        extra_source_fields={"pdf_file": str(p)},
        raw_artifacts={"raw.pdf": pdf_bytes},
    )
def ingest_url(
    url: str,
    connect_timeout_s: int = 10,
    read_timeout_s: int = 180,
    retries: int = 5,
) -> Tuple[str, Path]:
    if not url or not url.strip():
        raise ValueError("URL is required")
    try:
        r, fetch_meta = _http_get(
            url=url,
            connect_timeout_s=connect_timeout_s,
            read_timeout_s=read_timeout_s,
            retries=retries,
        )
    except requests.exceptions.RequestException as e:
        raise RuntimeError(
            f"Fetch failed after retries (connect={connect_timeout_s}s read={read_timeout_s}s retries={retries}) "
            f"url={url} err={type(e).__name__}: {e}"
        ) from e
    if r.status_code >= 400:
        snippet = ""
        try:
            if not r.encoding:
                r.encoding = r.apparent_encoding or "utf-8"
            snippet = (r.text or "")[:500].replace("\r", " ").replace("\n", " ").strip()
        except Exception:
            snippet = ""
        raise RuntimeError(
            f"HTTP {r.status_code} fetching {fetch_meta.get('final_url') or url} "
            f"(elapsed {fetch_meta.get('elapsed_ms')}ms) snippet='{snippet}'"
        )
    ct = (r.headers.get("Content-Type") or "").lower()
    is_pdf = ("application/pdf" in ct) or (r.url.lower().endswith(".pdf")) or (url.lower().endswith(".pdf"))
    if is_pdf:
        pdf_bytes = r.content
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as tmp:
            tmp.write(pdf_bytes)
            tmp_path = tmp.name
        try:
            text = _read_pdf_text(tmp_path)
        finally:
            try:
                Path(tmp_path).unlink()
            except Exception:
                pass
        return ingest_from_text(
            text,
            source_id=f"url:{url}",
            content_type="pdf",
            extra_source_fields={"fetch": fetch_meta},
            raw_artifacts={"raw.pdf": pdf_bytes},
        )
    if not r.encoding:
        r.encoding = r.apparent_encoding or "utf-8"
    html = r.text or ""
    extracted = _html_to_text(html)
    return ingest_from_text(
        extracted,
        source_id=f"url:{url}",
        content_type="html",
        extra_source_fields={"fetch": fetch_meta},
        raw_artifacts={"raw.html": r.content},
    )