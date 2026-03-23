from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from html.parser import HTMLParser
from pathlib import Path

from advisoryops.community_build import build_community_feed, _DASHBOARD_HTML, _generate_dashboard


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def test_build_community_feed_from_existing_discover_outputs(tmp_path: Path, monkeypatch) -> None:
    discover_root = tmp_path / "discover"
    out_root = tmp_path / "community"

    src_a = discover_root / "cisa-icsma"
    src_b = discover_root / "openfda-device-recalls"

    _write_jsonl(
        src_a / "items.jsonl",
        [
            {
                "source": "cisa-icsma",
                "guid": "https://example.test/advisory/CVE-2026-1000",
                "title": "Medical device bulletin for CVE-2026-1000",
                "summary": "Known exploited vulnerability in imaging software",
                "link": "https://nvd.nist.gov/vuln/detail/CVE-2026-1000",
                "published_date": "2026-03-17",
                "fetched_at": "2026-03-17T12:00:00Z",
            }
        ],
    )
    _write_jsonl(
        src_b / "items.jsonl",
        [
            {
                "source": "openfda-device-recalls",
                "guid": "res_event_number:97617",
                "title": "Cybersecurity recall for infusion pump controller",
                "summary": "Remote code execution risk; workaround available",
                "link": "https://api.fda.gov/device/recall.json?search=res_event_number:%2297617%22",
                "published_date": "2026-03-16",
                "fetched_at": "2026-03-17T12:05:00Z",
            }
        ],
    )

    monkeypatch.chdir(tmp_path)
    (tmp_path / "configs").mkdir(parents=True, exist_ok=True)

    (tmp_path / "configs" / "sources.json").write_text(
        (Path(__file__).resolve().parents[1] / "configs" / "sources.json").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    (tmp_path / "configs" / "community_public_sources.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "validated_sets": [
                    {
                        "set_id": "gold_pass1",
                        "name": "Gold Pass 1",
                        "description": "test",
                        "source_ids": ["cisa-icsma", "openfda-device-recalls"],
                    }
                ],
                "candidate_sources": [],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    issues_public, alerts_public, meta_path = build_community_feed(
        set_id="gold_pass1",
        refresh=False,
        out_root_discover=str(discover_root),
        out_root_runs=str(tmp_path / "source_runs"),
        out_root_community=str(out_root),
        only_new=False,
        limit_per_source=50,
        limit_issues=0,
        min_priority="P3",
        top=100,
        latest=10,
    )

    assert issues_public.exists()
    assert alerts_public.exists()
    assert meta_path.exists()
    assert (out_root / "feed_latest.json").exists()
    assert (out_root / "feed.csv").exists()
    assert (out_root / "validated_sources.json").exists()

    issues_rows = [json.loads(line) for line in issues_public.read_text(encoding="utf-8").splitlines() if line.strip()]
    alerts_rows = [json.loads(line) for line in alerts_public.read_text(encoding="utf-8").splitlines() if line.strip()]
    meta = json.loads(meta_path.read_text(encoding="utf-8"))

    assert len(issues_rows) == 2
    assert len(alerts_rows) >= 1
    assert meta["counts"]["validated_sources"] == 2
    assert meta["counts"]["issues_public"] == 2
    # Without --recommend the packet count must be present and zero
    assert meta["counts"]["packets"] == 0
    assert meta["outputs"]["packets_dir"] is None


# ---------------------------------------------------------------------------
# Mock call_fn for recommend_mitigations
# ---------------------------------------------------------------------------

def _mock_recommend_call_fn():
    """Zero-argument callable that returns a valid structured recommendation."""
    return {
        "result": {
            "selected_patterns": [
                {
                    "pattern_id": "SEGMENTATION_VLAN_ISOLATION",
                    "why_selected": "Unpatched device requires network isolation.",
                    "parameters": {"vlan_id": "unknown", "device_type": "medical device"},
                    "priority_order": 1,
                }
            ],
            "reasoning": "Network segmentation is the primary interim control for this unpatched device.",
        },
        "model": "gpt-4o-mini",
        "tokens_used": 100,
    }


def _setup_community_env(tmp_path: Path, monkeypatch, source_signals: list) -> tuple:
    """Write discovery data and config files; return (discover_root, out_root)."""
    discover_root = tmp_path / "discover"
    out_root = tmp_path / "community"

    src_a = discover_root / "cisa-icsma"
    _write_jsonl(src_a / "items.jsonl", source_signals)

    monkeypatch.chdir(tmp_path)
    (tmp_path / "configs").mkdir(parents=True, exist_ok=True)

    (tmp_path / "configs" / "sources.json").write_text(
        (Path(__file__).resolve().parents[1] / "configs" / "sources.json").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    (tmp_path / "configs" / "community_public_sources.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "validated_sets": [
                    {
                        "set_id": "gold_pass1",
                        "name": "Gold Pass 1",
                        "description": "test",
                        "source_ids": ["cisa-icsma"],
                    }
                ],
                "candidate_sources": [],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    # Also copy the mitigation playbook so load_playbook() works
    playbook_src = Path(__file__).resolve().parents[1] / "configs" / "mitigation_playbook.json"
    if playbook_src.exists():
        (tmp_path / "configs" / "mitigation_playbook.json").write_text(
            playbook_src.read_text(encoding="utf-8"), encoding="utf-8"
        )

    return discover_root, out_root


def test_build_community_feed_recommend_generates_packets(tmp_path: Path, monkeypatch) -> None:
    """--recommend generates JSON packets for qualifying alerts."""
    signals = [
        {
            "source": "cisa-icsma",
            "guid": "https://example.test/advisory/CVE-2026-2000",
            "title": "Medical device remote code execution CVE-2026-2000",
            "summary": (
                "An actively exploited vulnerability allows remote code execution "
                "in an implantable medical device firmware. No patch available. "
                "Vendor recommends network segmentation immediately."
            ),
            "link": "https://nvd.nist.gov/vuln/detail/CVE-2026-2000",
            "published_date": "2026-03-17",
            "fetched_at": "2026-03-17T12:00:00Z",
        }
    ]
    discover_root, out_root = _setup_community_env(tmp_path, monkeypatch, signals)

    _, _, meta_path = build_community_feed(
        set_id="gold_pass1",
        refresh=False,
        out_root_discover=str(discover_root),
        out_root_runs=str(tmp_path / "source_runs"),
        out_root_community=str(out_root),
        only_new=False,
        limit_per_source=50,
        limit_issues=0,
        min_priority="P3",  # catch everything so the issue qualifies
        top=100,
        latest=10,
        recommend=True,
        recommend_priorities=("P0", "P1", "P2", "P3"),  # accept all priorities
        _recommend_call_fn=_mock_recommend_call_fn,
    )

    packets_dir = out_root / "packets"
    meta = json.loads(meta_path.read_text(encoding="utf-8"))

    # packets/ directory must exist
    assert packets_dir.exists(), "packets/ dir not created"

    # At least one packet file
    packet_files = list(packets_dir.glob("*.json"))
    assert len(packet_files) >= 1, f"No packet files in {packets_dir}"

    # meta.json reports packet count
    assert meta["counts"]["packets"] >= 1, f"meta counts.packets wrong: {meta['counts']}"
    assert meta["outputs"]["packets_dir"] is not None

    # Verify packet JSON is valid and has required fields
    packet = json.loads(packet_files[0].read_text(encoding="utf-8"))
    assert "schema_version" in packet
    assert "issue_id" in packet
    assert "recommended_patterns" in packet
    assert len(packet["recommended_patterns"]) >= 1
    assert packet["recommended_patterns"][0]["pattern_id"] == "SEGMENTATION_VLAN_ISOLATION"


def test_build_community_feed_recommend_false_no_packets(tmp_path: Path, monkeypatch) -> None:
    """Without --recommend, no packets/ dir is created and meta shows 0 packets."""
    signals = [
        {
            "source": "cisa-icsma",
            "guid": "CVE-2026-3000",
            "title": "CVE-2026-3000 vulnerability",
            "summary": "Some vulnerability description.",
            "link": "https://nvd.nist.gov/vuln/detail/CVE-2026-3000",
            "published_date": "2026-03-17",
            "fetched_at": "2026-03-17T12:00:00Z",
        }
    ]
    discover_root, out_root = _setup_community_env(tmp_path, monkeypatch, signals)

    _, _, meta_path = build_community_feed(
        set_id="gold_pass1",
        refresh=False,
        out_root_discover=str(discover_root),
        out_root_runs=str(tmp_path / "source_runs"),
        out_root_community=str(out_root),
        only_new=False,
        limit_per_source=50,
        limit_issues=0,
        min_priority="P3",
        top=100,
        latest=10,
        recommend=False,
    )

    meta = json.loads(meta_path.read_text(encoding="utf-8"))

    assert not (out_root / "packets").exists(), "packets/ dir should not be created without --recommend"
    assert meta["counts"]["packets"] == 0
    assert meta["outputs"]["packets_dir"] is None


def test_build_community_feed_rss_feed_xml(tmp_path: Path, monkeypatch) -> None:
    """build_community_feed writes a valid RSS 2.0 feed.xml with correct structure."""
    signals = [
        {
            "source": "cisa-icsma",
            "guid": "https://example.test/advisory/CVE-2026-5001",
            "title": "Remote code execution in infusion pump CVE-2026-5001",
            "summary": "An actively exploited buffer overflow allows unauthenticated remote code execution.",
            "link": "https://nvd.nist.gov/vuln/detail/CVE-2026-5001",
            "published_date": "2026-03-20",
            "fetched_at": "2026-03-20T09:00:00Z",
        },
        {
            "source": "cisa-icsma",
            "guid": "https://example.test/advisory/CVE-2026-5002",
            "title": "Denial of service in patient monitor CVE-2026-5002",
            "summary": "A crafted network packet causes device reboot.",
            "link": "https://nvd.nist.gov/vuln/detail/CVE-2026-5002",
            "published_date": "2026-03-19",
            "fetched_at": "2026-03-20T09:01:00Z",
        },
    ]
    discover_root, out_root = _setup_community_env(tmp_path, monkeypatch, signals)

    build_community_feed(
        set_id="gold_pass1",
        refresh=False,
        out_root_discover=str(discover_root),
        out_root_runs=str(tmp_path / "source_runs"),
        out_root_community=str(out_root),
        only_new=False,
        limit_per_source=50,
        limit_issues=0,
        min_priority="P3",
        top=100,
        latest=10,
    )

    feed_xml = out_root / "feed.xml"
    assert feed_xml.exists(), "feed.xml was not written"

    # Must parse as valid XML
    tree = ET.parse(str(feed_xml))
    root = tree.getroot()

    assert root.tag == "rss", f"Root tag should be 'rss', got '{root.tag}'"
    assert root.get("version") == "2.0"

    channel = root.find("channel")
    assert channel is not None, "<channel> element missing"

    # Required channel elements
    assert channel.findtext("title"), "<channel><title> missing or empty"
    assert channel.findtext("link"), "<channel><link> missing or empty"
    assert channel.findtext("description"), "<channel><description> missing or empty"

    items = channel.findall("item")
    assert len(items) >= 1, "No <item> elements in feed"

    # Each item must have title, link, description; category should match priority
    for item in items:
        assert item.findtext("title") is not None
        assert item.findtext("link") is not None
        assert item.findtext("description") is not None
        category = item.findtext("category")
        if category is not None:
            assert category.startswith("P"), f"category should be a priority like P0-P3, got '{category}'"

    # Description must be truncated to ≤ 500 chars
    for item in items:
        desc = item.findtext("description") or ""
        assert len(desc) <= 500, f"description exceeds 500 chars: {len(desc)}"


def test_build_community_feed_recommend_no_qualifying_alerts(tmp_path: Path, monkeypatch) -> None:
    """--recommend with no qualifying priorities writes 0 packets but doesn't crash."""
    signals = [
        {
            "source": "cisa-icsma",
            "guid": "CVE-2026-4000",
            "title": "CVE-2026-4000 minor issue",
            "summary": "Low-severity informational notice.",
            "link": "https://nvd.nist.gov/vuln/detail/CVE-2026-4000",
            "published_date": "2026-03-17",
            "fetched_at": "2026-03-17T12:00:00Z",
        }
    ]
    discover_root, out_root = _setup_community_env(tmp_path, monkeypatch, signals)

    _, _, meta_path = build_community_feed(
        set_id="gold_pass1",
        refresh=False,
        out_root_discover=str(discover_root),
        out_root_runs=str(tmp_path / "source_runs"),
        out_root_community=str(out_root),
        only_new=False,
        limit_per_source=50,
        limit_issues=0,
        min_priority="P3",
        top=100,
        latest=10,
        recommend=True,
        recommend_priorities=(),  # no priorities match → 0 packets
        _recommend_call_fn=_mock_recommend_call_fn,
    )

    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    assert meta["counts"]["packets"] == 0
    # packets_dir is still set (created even when empty)
    assert meta["outputs"]["packets_dir"] is not None


# ---------------------------------------------------------------------------
# Dashboard tests
# ---------------------------------------------------------------------------

class _StrictHTMLParser(HTMLParser):
    """Minimal HTML parser that tracks open tags to detect unclosed elements."""

    VOID_ELEMENTS = frozenset([
        "area", "base", "br", "col", "embed", "hr", "img", "input",
        "link", "meta", "source", "track", "wbr",
    ])

    def __init__(self):
        super().__init__()
        self.errors: list[str] = []
        self._stack: list[str] = []

    def handle_starttag(self, tag: str, attrs):
        if tag.lower() not in self.VOID_ELEMENTS:
            self._stack.append(tag.lower())

    def handle_endtag(self, tag: str):
        tag = tag.lower()
        if tag in self.VOID_ELEMENTS:
            return
        if self._stack and self._stack[-1] == tag:
            self._stack.pop()
        elif tag in self._stack:
            # mis-nested — pop up to the matching tag
            while self._stack and self._stack[-1] != tag:
                self.errors.append(f"implicitly closed <{self._stack.pop()}>")
            if self._stack:
                self._stack.pop()
        else:
            self.errors.append(f"unexpected </{tag}>")


def test_dashboard_written_by_build_community_feed(tmp_path: Path, monkeypatch) -> None:
    """build_community_feed writes dashboard.html alongside other artifacts."""
    signals = [
        {
            "source": "cisa-icsma",
            "guid": "https://example.test/advisory/CVE-2026-6001",
            "title": "Patient monitor denial of service CVE-2026-6001",
            "summary": "A crafted network packet causes device reboot.",
            "link": "https://nvd.nist.gov/vuln/detail/CVE-2026-6001",
            "published_date": "2026-03-20",
            "fetched_at": "2026-03-20T09:00:00Z",
        },
    ]
    discover_root, out_root = _setup_community_env(tmp_path, monkeypatch, signals)

    build_community_feed(
        set_id="gold_pass1",
        refresh=False,
        out_root_discover=str(discover_root),
        out_root_runs=str(tmp_path / "source_runs"),
        out_root_community=str(out_root),
        only_new=False,
        limit_per_source=50,
        limit_issues=0,
        min_priority="P3",
        top=100,
        latest=10,
    )

    dashboard = out_root / "dashboard.html"
    assert dashboard.exists(), "dashboard.html was not written"
    html = dashboard.read_text(encoding="utf-8")
    assert "<!DOCTYPE html>" in html
    assert "AdvisoryOps" in html


def test_dashboard_html_contains_trust_layer_sections() -> None:
    """The dashboard template contains CSS classes for all trust layer sections."""
    html = _DASHBOARD_HTML
    assert "handling-warnings" in html
    assert "evidence-gaps" in html
    assert "source-consensus" in html
    assert "evidence-completeness" in html
    assert "evidence-bar" in html
    assert "fact-badge" in html
    assert "authority-badge" in html


def test_dashboard_html_valid_structure() -> None:
    """Parse the dashboard HTML and verify no gross structural errors."""
    parser = _StrictHTMLParser()
    parser.feed(_DASHBOARD_HTML)
    # Allow minor browser-tolerant issues but no major unclosed tags
    # (script/style content may confuse a simple parser, so we're lenient)
    major_errors = [e for e in parser.errors if "script" not in e and "style" not in e]
    assert len(major_errors) == 0, f"HTML structure errors: {major_errors}"


def test_generate_dashboard_writes_file(tmp_path: Path) -> None:
    """_generate_dashboard writes a non-empty HTML file."""
    out = tmp_path / "dashboard.html"
    _generate_dashboard(out)
    assert out.exists()
    html = out.read_text(encoding="utf-8")
    assert len(html) > 1000
    assert "handling-warnings" in html


def test_dashboard_feed_entry_includes_trust_fields(tmp_path: Path, monkeypatch) -> None:
    """feed_latest.json includes trust layer fields from scored issues."""
    signals = [
        {
            "source": "cisa-icsma",
            "guid": "https://example.test/advisory/CVE-2026-7001",
            "title": "Infusion pump remote code execution CVE-2026-7001",
            "summary": "Buffer overflow allows remote code execution on infusion pump.",
            "link": "https://nvd.nist.gov/vuln/detail/CVE-2026-7001",
            "published_date": "2026-03-20",
            "fetched_at": "2026-03-20T09:00:00Z",
        },
    ]
    discover_root, out_root = _setup_community_env(tmp_path, monkeypatch, signals)

    build_community_feed(
        set_id="gold_pass1",
        refresh=False,
        out_root_discover=str(discover_root),
        out_root_runs=str(tmp_path / "source_runs"),
        out_root_community=str(out_root),
        only_new=False,
        limit_per_source=50,
        limit_issues=0,
        min_priority="P3",
        top=100,
        latest=10,
    )

    latest = json.loads((out_root / "feed_latest.json").read_text(encoding="utf-8"))
    assert len(latest) >= 1
    entry = latest[0]
    # Trust layer fields must be present (may be empty but must exist)
    for field in ("handling_warnings", "evidence_gaps", "unknowns",
                  "source_consensus", "source_authority_weight",
                  "highest_authority_source"):
        assert field in entry, f"Missing trust field: {field}"


def test_dashboard_meta_includes_dashboard_path(tmp_path: Path, monkeypatch) -> None:
    """meta.json includes the dashboard_html output path."""
    signals = [
        {
            "source": "cisa-icsma",
            "guid": "CVE-2026-8001",
            "title": "CVE-2026-8001 test issue",
            "summary": "Test summary.",
            "link": "https://nvd.nist.gov/vuln/detail/CVE-2026-8001",
            "published_date": "2026-03-20",
            "fetched_at": "2026-03-20T09:00:00Z",
        },
    ]
    discover_root, out_root = _setup_community_env(tmp_path, monkeypatch, signals)

    _, _, meta_path = build_community_feed(
        set_id="gold_pass1",
        refresh=False,
        out_root_discover=str(discover_root),
        out_root_runs=str(tmp_path / "source_runs"),
        out_root_community=str(out_root),
        only_new=False,
        limit_per_source=50,
        limit_issues=0,
        min_priority="P3",
        top=100,
        latest=10,
    )

    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    assert "dashboard_html" in meta["outputs"]
