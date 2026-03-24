"""Deterministic IOC (Indicator of Compromise) extraction.

Extracts IOCs from issue text using regex — no AI needed. Fast enough to
run on every issue in the corpus.

Supported IOC types:
    * CVE IDs        (CVE-YYYY-NNNNN)
    * IPv4 addresses (basic format validation)
    * Domain names   (basic validation, excludes common false positives)
    * File hashes    (MD5, SHA-1, SHA-256)
    * URLs           (http/https)
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Set

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

_CVE_RE = re.compile(r"\b(CVE-\d{4}-\d{4,})\b", re.I)

_IPV4_RE = re.compile(
    r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"
)

_HASH_MD5_RE = re.compile(r"\b([a-fA-F0-9]{32})\b")
_HASH_SHA1_RE = re.compile(r"\b([a-fA-F0-9]{40})\b")
_HASH_SHA256_RE = re.compile(r"\b([a-fA-F0-9]{64})\b")

_URL_RE = re.compile(
    r"\bhttps?://[^\s<>\"')\]}{]+",
    re.I,
)

_DOMAIN_RE = re.compile(
    r"\b([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*"
    r"\.[a-zA-Z]{2,})\b"
)

# Common false-positive domains to exclude
_DOMAIN_EXCLUDE = {
    "example.com", "example.org", "example.net",
    "localhost.localdomain",
    # Generic TLDs that are often version strings
}

# Common false-positive hash patterns (all-zeros, etc.)
_HASH_EXCLUDE = {
    "0" * 32, "0" * 40, "0" * 64,
    "d41d8cd98f00b204e9800998ecf8427e",  # MD5 of empty string
}


def _valid_ipv4(ip: str) -> bool:
    """Check that each octet is 0-255 and it's not obviously a version string."""
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    for p in parts:
        try:
            val = int(p)
            if val < 0 or val > 255:
                return False
        except ValueError:
            return False
    # Exclude common non-IOC IPs
    if ip.startswith("0.") or ip.startswith("127.") or ip.startswith("255."):
        return False
    # Exclude version-like patterns (e.g., 3.5.16.10)
    if all(int(p) < 32 for p in parts):
        return False
    return True


def _valid_domain(domain: str) -> bool:
    """Basic domain validation — exclude obvious false positives."""
    if domain.lower() in _DOMAIN_EXCLUDE:
        return False
    # Must have at least one dot
    if "." not in domain:
        return False
    # TLD must be at least 2 chars and alphabetic
    tld = domain.rsplit(".", 1)[-1]
    if not tld.isalpha() or len(tld) < 2:
        return False
    # Exclude version-like strings (e.g., "v2.3.4.5")
    if domain[0].isdigit():
        return False
    return True


def extract_iocs(
    issue: Dict[str, Any],
) -> List[Dict[str, str]]:
    """Extract IOCs from an issue's text fields.

    Scans title, summary, and signal titles/guids for IOCs.
    Returns a deduplicated list of IOC dicts.

    Args:
        issue: Scored issue dict.

    Returns:
        List of dicts, each with: type, value, source.
    """
    iocs: List[Dict[str, str]] = []
    seen: Set[str] = set()

    def _add(ioc_type: str, value: str, source: str) -> None:
        key = f"{ioc_type}:{value}"
        if key not in seen:
            seen.add(key)
            iocs.append({"type": ioc_type, "value": value, "source": source})

    # Collect text blocks with their source attribution
    text_blocks: List[tuple[str, str]] = []

    # Main issue text
    sources_list = issue.get("sources") or []
    default_source = sources_list[0] if sources_list else "unknown"

    title = str(issue.get("title") or "")
    summary = str(issue.get("summary") or "")
    text_blocks.append((title + " " + summary, default_source))

    # Per-signal text
    for sig in issue.get("signals", []):
        sig_source = str(sig.get("source") or default_source)
        sig_text = str(sig.get("title") or "") + " " + str(sig.get("guid") or "")
        if sig_text.strip():
            text_blocks.append((sig_text, sig_source))

    for text, source in text_blocks:
        if not text.strip():
            continue

        # CVE IDs
        for m in _CVE_RE.finditer(text):
            _add("cve", m.group(1).upper(), source)

        # SHA-256 (check first — longer hashes before shorter)
        for m in _HASH_SHA256_RE.finditer(text):
            val = m.group(1).lower()
            if val not in _HASH_EXCLUDE:
                _add("hash_sha256", val, source)

        # SHA-1
        for m in _HASH_SHA1_RE.finditer(text):
            val = m.group(1).lower()
            if val not in _HASH_EXCLUDE and f"hash_sha256:{val}" not in seen:
                # Don't match substrings of SHA-256
                start = m.start()
                end = m.end()
                if end < len(text) and text[end:end+24].replace(" ", "").isalnum():
                    continue  # likely part of a longer hash
                _add("hash_sha1", val, source)

        # MD5
        for m in _HASH_MD5_RE.finditer(text):
            val = m.group(1).lower()
            if val not in _HASH_EXCLUDE:
                # Don't match substrings of longer hashes
                is_substring = any(
                    val in entry.split(":", 1)[1]
                    for entry in seen
                    if entry.startswith("hash_sha")
                )
                if is_substring:
                    continue
                _add("hash_md5", val, source)

        # URLs
        for m in _URL_RE.finditer(text):
            url = m.group(0).rstrip(".,;:)")
            _add("url", url, source)

        # IPv4
        for m in _IPV4_RE.finditer(text):
            ip = m.group(1)
            if _valid_ipv4(ip):
                _add("ip", ip, source)

        # Domains (only from URLs or explicit mentions, not every word)
        for m in _DOMAIN_RE.finditer(text):
            domain = m.group(1).lower()
            if _valid_domain(domain):
                _add("domain", domain, source)

    return iocs
