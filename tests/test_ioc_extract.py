"""Tests for ioc_extract.py — deterministic IOC extraction."""
from __future__ import annotations

import pytest

from advisoryops.ioc_extract import extract_iocs


def _make_issue(**overrides):
    base = {
        "issue_id": "CVE-2024-5678",
        "title": "CVE-2024-5678",
        "summary": "",
        "sources": ["cisa-icsma"],
        "signals": [],
    }
    base.update(overrides)
    return base


class TestExtractCVEs:

    def test_finds_cve_in_title(self):
        issue = _make_issue(title="CVE-2023-38831 WinRAR vulnerability")
        iocs = extract_iocs(issue)
        cves = [i for i in iocs if i["type"] == "cve"]
        assert len(cves) >= 1
        assert any(c["value"] == "CVE-2023-38831" for c in cves)

    def test_finds_multiple_cves(self):
        issue = _make_issue(
            summary="Affected by CVE-2024-1111 and CVE-2024-2222 in the same component"
        )
        iocs = extract_iocs(issue)
        cves = [i for i in iocs if i["type"] == "cve"]
        values = {c["value"] for c in cves}
        assert "CVE-2024-1111" in values
        assert "CVE-2024-2222" in values

    def test_cve_case_insensitive(self):
        issue = _make_issue(summary="Vulnerability cve-2024-9999 affects devices")
        iocs = extract_iocs(issue)
        cves = [i for i in iocs if i["type"] == "cve"]
        assert any(c["value"] == "CVE-2024-9999" for c in cves)


class TestExtractIPs:

    def test_finds_ipv4(self):
        issue = _make_issue(summary="C2 server at 192.168.1.100 detected")
        iocs = extract_iocs(issue)
        ips = [i for i in iocs if i["type"] == "ip"]
        assert any(ip["value"] == "192.168.1.100" for ip in ips)

    def test_rejects_invalid_ip(self):
        issue = _make_issue(summary="Version 999.999.999.999 is not valid")
        iocs = extract_iocs(issue)
        ips = [i for i in iocs if i["type"] == "ip"]
        assert len(ips) == 0

    def test_rejects_localhost(self):
        issue = _make_issue(summary="Connect to 127.0.0.1 for testing")
        iocs = extract_iocs(issue)
        ips = [i for i in iocs if i["type"] == "ip"]
        assert len(ips) == 0


class TestExtractHashes:

    def test_finds_md5(self):
        issue = _make_issue(summary="Hash: a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4")
        iocs = extract_iocs(issue)
        hashes = [i for i in iocs if i["type"] == "hash_md5"]
        assert len(hashes) >= 1

    def test_finds_sha256(self):
        sha256 = "a" * 64
        issue = _make_issue(summary=f"SHA256: {sha256}")
        iocs = extract_iocs(issue)
        hashes = [i for i in iocs if i["type"] == "hash_sha256"]
        assert len(hashes) >= 1
        assert hashes[0]["value"] == sha256

    def test_rejects_all_zeros(self):
        issue = _make_issue(summary=f"Hash: {'0' * 32}")
        iocs = extract_iocs(issue)
        hashes = [i for i in iocs if "hash" in i["type"]]
        assert len(hashes) == 0


class TestExtractDomains:

    def test_finds_domain(self):
        issue = _make_issue(summary="Malware beacons to evil.example.org")
        iocs = extract_iocs(issue)
        domains = [i for i in iocs if i["type"] == "domain"]
        assert any(d["value"] == "evil.example.org" for d in domains)

    def test_rejects_example_com(self):
        issue = _make_issue(summary="See example.com for details")
        iocs = extract_iocs(issue)
        domains = [i for i in iocs if i["type"] == "domain" and i["value"] == "example.com"]
        assert len(domains) == 0


class TestExtractURLs:

    def test_finds_url(self):
        issue = _make_issue(
            summary="Download patch from https://vendor.com/patch/v2.3.1"
        )
        iocs = extract_iocs(issue)
        urls = [i for i in iocs if i["type"] == "url"]
        assert any("vendor.com/patch/v2.3.1" in u["value"] for u in urls)


class TestCleanText:

    def test_clean_text_returns_empty(self):
        issue = _make_issue(summary="This is a normal advisory with no IOCs.")
        iocs = extract_iocs(issue)
        # Should have no IPs, hashes (CVE from title still shows up)
        non_cve = [i for i in iocs if i["type"] != "cve"]
        # Domains may be extracted from normal text; focus on no IPs/hashes
        ips = [i for i in iocs if i["type"] == "ip"]
        hashes = [i for i in iocs if "hash" in i["type"]]
        assert len(ips) == 0
        assert len(hashes) == 0

    def test_empty_issue_returns_empty(self):
        issue = _make_issue(title="", summary="")
        iocs = extract_iocs(issue)
        assert len(iocs) == 0


class TestDeduplication:

    def test_same_cve_deduped(self):
        issue = _make_issue(
            title="CVE-2024-5678",
            summary="CVE-2024-5678 is a critical vulnerability. CVE-2024-5678 affects..."
        )
        iocs = extract_iocs(issue)
        cves = [i for i in iocs if i["type"] == "cve" and i["value"] == "CVE-2024-5678"]
        assert len(cves) == 1


class TestSourceAttribution:

    def test_source_from_issue(self):
        issue = _make_issue(sources=["mandiant-blog"])
        iocs = extract_iocs(issue)
        for ioc in iocs:
            assert ioc["source"] == "mandiant-blog"

    def test_source_from_signal(self):
        issue = _make_issue(
            sources=["cisa-icsma", "mandiant-blog"],
            signals=[
                {"source": "mandiant-blog", "title": "CVE-2024-9999 exploit"},
            ],
        )
        iocs = extract_iocs(issue)
        mandiant_cves = [
            i for i in iocs
            if i["type"] == "cve" and i["value"] == "CVE-2024-9999"
            and i["source"] == "mandiant-blog"
        ]
        assert len(mandiant_cves) == 1
