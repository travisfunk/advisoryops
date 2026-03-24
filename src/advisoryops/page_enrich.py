"""Page content enrichment — fetch advisory web pages for richer mitigation text.

RSS summaries are often sparse (just a CVE ID and title). The actual mitigation
guidance lives on the linked advisory pages. This module fetches, caches, and
strips those pages to provide richer text for source mitigation extraction.

Cache strategy:
    URL content is cached to ``outputs/page_cache/<sha256>.txt`` — fetch once,
    reuse forever. This prevents repeated HTTP hits and keeps the pipeline
    resumable.

Robots.txt:
    Before fetching, we check the site's robots.txt. If the URL is disallowed,
    we skip it silently.
"""
from __future__ import annotations

import hashlib
import html as html_mod
import logging
import re
import urllib.error
import urllib.request
import urllib.robotparser
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)

_DEFAULT_CACHE_DIR = Path("outputs/page_cache")
_USER_AGENT = "AdvisoryOps/1.0 (security advisory aggregator; +https://github.com/advisoryops)"
_TIMEOUT = 15
_MAX_PAGE_CHARS = 8000

# Simple HTML tag stripper
_TAG_RE = re.compile(r"<[^>]+>")
_MULTI_WS_RE = re.compile(r"\s{3,}")
_MULTI_NL_RE = re.compile(r"\n{3,}")

# robots.txt cache (per-process)
_robots_cache: Dict[str, Optional[urllib.robotparser.RobotFileParser]] = {}


def _url_hash(url: str) -> str:
    return hashlib.sha256(url.encode("utf-8")).hexdigest()


def _strip_html(raw_html: str) -> str:
    """Remove HTML tags and decode entities, returning plain text."""
    text = _TAG_RE.sub(" ", raw_html)
    text = html_mod.unescape(text)
    text = _MULTI_WS_RE.sub(" ", text)
    text = _MULTI_NL_RE.sub("\n\n", text)
    return text.strip()


def _check_robots(url: str) -> bool:
    """Check robots.txt for the given URL. Returns True if allowed."""
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        if base in _robots_cache:
            rp = _robots_cache[base]
            if rp is None:
                return True  # failed to fetch robots.txt — assume allowed
            return rp.can_fetch(_USER_AGENT, url)

        robots_url = f"{base}/robots.txt"
        rp = urllib.robotparser.RobotFileParser()
        rp.set_url(robots_url)
        try:
            rp.read()
            _robots_cache[base] = rp
            return rp.can_fetch(_USER_AGENT, url)
        except Exception:
            _robots_cache[base] = None
            return True
    except Exception:
        return True


def _fetch_page(url: str, *, timeout: int = _TIMEOUT) -> Optional[str]:
    """Fetch a single URL and return stripped plain text, or None on failure."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            # Only process HTML/text responses
            content_type = resp.headers.get("Content-Type", "")
            if "html" not in content_type and "text" not in content_type:
                return None
            raw = resp.read()
            # Try to detect encoding
            charset = "utf-8"
            if "charset=" in content_type:
                charset = content_type.split("charset=")[-1].split(";")[0].strip()
            try:
                html_text = raw.decode(charset, errors="replace")
            except (LookupError, UnicodeDecodeError):
                html_text = raw.decode("utf-8", errors="replace")
            return _strip_html(html_text)
    except (urllib.error.URLError, urllib.error.HTTPError, OSError, Exception) as exc:
        logger.debug("Failed to fetch %s: %s", url, exc)
        return None


def _get_cached(url: str, cache_dir: Path) -> Optional[str]:
    """Read cached page text, or None if not cached."""
    path = cache_dir / f"{_url_hash(url)}.txt"
    if path.exists():
        try:
            return path.read_text(encoding="utf-8")
        except Exception:
            return None
    return None


def _put_cache(url: str, text: str, cache_dir: Path) -> None:
    """Write page text to cache."""
    cache_dir.mkdir(parents=True, exist_ok=True)
    path = cache_dir / f"{_url_hash(url)}.txt"
    try:
        path.write_text(text, encoding="utf-8")
    except Exception as exc:
        logger.debug("Failed to cache %s: %s", url, exc)


def _collect_urls(issue: Dict[str, Any]) -> List[str]:
    """Collect and deduplicate all URLs from an issue."""
    urls: List[str] = []
    seen: Set[str] = set()

    def _add(u: str) -> None:
        u = u.strip()
        if u and u.startswith("http") and u not in seen:
            seen.add(u)
            urls.append(u)

    # canonical_link
    _add(str(issue.get("canonical_link") or ""))

    # links (may be list of strings or list of dicts)
    for link in issue.get("links") or []:
        if isinstance(link, str):
            _add(link)
        elif isinstance(link, dict):
            _add(str(link.get("url") or link.get("href") or ""))

    # signals
    for sig in issue.get("signals") or []:
        _add(str(sig.get("link") or ""))

    return urls


def enrich_issue_from_links(
    issue: Dict[str, Any],
    *,
    cache_dir: str | Path = _DEFAULT_CACHE_DIR,
    timeout: int = _TIMEOUT,
    max_chars_per_page: int = _MAX_PAGE_CHARS,
) -> str:
    """Fetch advisory page content for an issue and return enriched text.

    Args:
        issue:              Scored issue dict.
        cache_dir:          Directory for page content cache.
        timeout:            HTTP timeout per request (seconds).
        max_chars_per_page: Truncate each page to this many chars.

    Returns:
        Concatenated plain text from all fetched pages. Empty string if
        no pages could be fetched.
    """
    cache_path = Path(cache_dir)
    urls = _collect_urls(issue)

    if not urls:
        return ""

    texts: List[str] = []
    for url in urls:
        # Check cache first
        cached = _get_cached(url, cache_path)
        if cached is not None:
            texts.append(cached[:max_chars_per_page])
            continue

        # Check robots.txt
        if not _check_robots(url):
            logger.debug("Blocked by robots.txt: %s", url)
            continue

        # Fetch
        text = _fetch_page(url, timeout=timeout)
        if text:
            truncated = text[:max_chars_per_page]
            _put_cache(url, truncated, cache_path)
            texts.append(truncated)

    return "\n\n---\n\n".join(texts)
