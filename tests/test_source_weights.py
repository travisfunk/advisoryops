"""Tests for source authority weighting (Task 8.6 / Session I).

Covers:
- load_source_weights() loads the JSON and returns a SourceWeights object
- get_weight() returns correct weights for known source_ids
- get_weight() returns 0.5 for unknown source_ids
- get_tier() returns correct tiers for known source_ids
- get_tier() returns default 3 for unknown source_ids
- Scored issue output includes source_authority_weight and highest_authority_source
- A CISA-sourced issue scores higher than the same issue sourced only from a news blog
- Existing score fields are unchanged (backward compat)
- All 5 tiers are represented with the correct weights
- New sources added (bsi-news, nhs-digital-cyber, etc.) are tiered correctly
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

import pytest

from advisoryops.source_weights import (
    SourceWeights,
    get_tier,
    get_weight,
    load_source_weights,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def clear_weight_cache():
    """Clear the lru_cache before every test so config changes are picked up."""
    load_source_weights.cache_clear()
    yield
    load_source_weights.cache_clear()


@pytest.fixture
def weights() -> SourceWeights:
    return load_source_weights()


# ---------------------------------------------------------------------------
# load_source_weights
# ---------------------------------------------------------------------------

class TestLoadSourceWeights:
    def test_returns_source_weights_instance(self, weights):
        assert isinstance(weights, SourceWeights)

    def test_tier_1_cisa_icsma(self, weights):
        assert weights.weight_for("cisa-icsma") == 1.0
        assert weights.tier_for("cisa-icsma") == 1

    def test_tier_1_cisa_kev(self, weights):
        assert weights.weight_for("cisa-kev-json") == 1.0
        assert weights.weight_for("cisa-kev-csv") == 1.0

    def test_tier_1_fda(self, weights):
        assert weights.weight_for("fda-medwatch") == 1.0
        assert weights.tier_for("fda-medwatch") == 1

    def test_tier_1_bsi_news(self, weights):
        """BSI (Germany) should be tier 1 — added in schema_version 2."""
        assert weights.weight_for("bsi-news") == 1.0
        assert weights.tier_for("bsi-news") == 1

    def test_tier_1_nhs_digital(self, weights):
        """NHS Digital should be tier 1 — added in schema_version 2."""
        assert weights.weight_for("nhs-digital-cyber") == 1.0
        assert weights.tier_for("nhs-digital-cyber") == 1

    def test_tier_2_vendor_psirt(self, weights):
        assert weights.weight_for("abb-psirt") == pytest.approx(0.85)
        assert weights.tier_for("abb-psirt") == 2

    def test_tier_2_abb_alerts(self, weights):
        """ABB vendor advisory feed — added in schema_version 2."""
        assert weights.weight_for("abb-alerts-html") == pytest.approx(0.85)
        assert weights.tier_for("abb-alerts-html") == 2

    def test_tier_2_schneider(self, weights):
        assert weights.weight_for("se-security-notifications") == pytest.approx(0.85)
        assert weights.tier_for("se-security-notifications") == 2

    def test_tier_2_nvd(self, weights):
        assert weights.weight_for("nvd-cve-api") == pytest.approx(0.85)

    def test_tier_3_claroty(self, weights):
        assert weights.weight_for("claroty-team82") == pytest.approx(0.70)
        assert weights.tier_for("claroty-team82") == 3

    def test_tier_3_forescout(self, weights):
        assert weights.weight_for("forescout-vedere") == pytest.approx(0.70)
        assert weights.tier_for("forescout-vedere") == 3

    def test_tier_4_dark_reading(self, weights):
        assert weights.weight_for("dark-reading") == pytest.approx(0.50)
        assert weights.tier_for("dark-reading") == 4

    def test_tier_4_krebs(self, weights):
        assert weights.weight_for("krebs-on-security") == pytest.approx(0.50)

    def test_tier_5_urlhaus(self, weights):
        assert weights.weight_for("urlhaus-recent") == pytest.approx(0.35)
        assert weights.tier_for("urlhaus-recent") == 5

    def test_tier_5_malwarebazaar(self, weights):
        assert weights.weight_for("malwarebazaar-recent") == pytest.approx(0.35)

    def test_unknown_source_returns_zero_from_weight_for(self, weights):
        """weight_for() with no default returns 0.0 for unrecognised sources."""
        assert weights.weight_for("no-such-source-xyz") == 0.0

    def test_healthcare_tier1_medical_contains_cisa_icsma(self, weights):
        assert weights.is_healthcare_medical("cisa-icsma")

    def test_healthcare_tier1_medical_contains_nhs(self, weights):
        assert weights.is_healthcare_medical("nhs-digital-cyber")

    def test_healthcare_tier1_medical_not_contains_news(self, weights):
        assert not weights.is_healthcare_medical("dark-reading")

    def test_base_authority_points_set(self, weights):
        assert weights.base_authority_points == 30

    def test_healthcare_bonus_set(self, weights):
        assert weights.healthcare_bonus == 50

    def test_max_weight_picks_highest(self, weights):
        sources = ["dark-reading", "cisa-icsma", "urlhaus-recent"]
        assert weights.max_weight(sources) == pytest.approx(1.0)

    def test_max_weight_empty_returns_default(self, weights):
        assert weights.max_weight([]) == 0.0
        assert weights.max_weight([], default=0.5) == 0.5

    def test_all_sources_json_are_tiered(self):
        """Every source_id in sources.json must appear in source_weights.json."""
        sources_path = Path("configs/sources.json")
        weights_path = Path("configs/source_weights.json")
        if not sources_path.exists() or not weights_path.exists():
            pytest.skip("Config files not found")

        source_ids = {s["source_id"] for s in json.load(sources_path.open())["sources"]}
        cfg = json.load(weights_path.open())
        tiered: set = set()
        for td in cfg["tiers"].values():
            tiered.update(td["sources"])

        missing = source_ids - tiered
        assert missing == set(), (
            f"These source_ids are in sources.json but not tiered in "
            f"source_weights.json: {sorted(missing)}"
        )


# ---------------------------------------------------------------------------
# get_weight()
# ---------------------------------------------------------------------------

class TestGetWeight:
    def test_known_source_from_source_weights(self, weights):
        assert get_weight("cisa-icsma", weights) == pytest.approx(1.0)

    def test_known_source_from_dict(self):
        d = {"cisa-icsma": 1.0, "dark-reading": 0.50}
        assert get_weight("cisa-icsma", d) == pytest.approx(1.0)
        assert get_weight("dark-reading", d) == pytest.approx(0.50)

    def test_unknown_source_returns_default_05(self, weights):
        assert get_weight("no-such-source-abc", weights) == pytest.approx(0.5)

    def test_unknown_source_dict_returns_default_05(self):
        assert get_weight("no-such-source-abc", {}) == pytest.approx(0.5)

    def test_custom_default(self, weights):
        assert get_weight("no-such-source", weights, default=0.9) == pytest.approx(0.9)

    def test_tier_3_source_correct_weight(self, weights):
        assert get_weight("claroty-team82", weights) == pytest.approx(0.70)

    def test_tier_5_source_correct_weight(self, weights):
        assert get_weight("urlhaus-recent", weights) == pytest.approx(0.35)


# ---------------------------------------------------------------------------
# get_tier()
# ---------------------------------------------------------------------------

class TestGetTier:
    def test_tier_1_from_source_weights(self, weights):
        assert get_tier("cisa-icsma", weights) == 1
        assert get_tier("fda-medwatch", weights) == 1

    def test_tier_2_from_source_weights(self, weights):
        assert get_tier("abb-psirt", weights) == 2
        assert get_tier("nvd-cve-api", weights) == 2

    def test_tier_3_from_source_weights(self, weights):
        assert get_tier("claroty-team82", weights) == 3
        assert get_tier("armis-labs", weights) == 3

    def test_tier_4_from_source_weights(self, weights):
        assert get_tier("dark-reading", weights) == 4
        assert get_tier("krebs-on-security", weights) == 4

    def test_tier_5_from_source_weights(self, weights):
        assert get_tier("urlhaus-recent", weights) == 5
        assert get_tier("threatfox-iocs", weights) == 5

    def test_unknown_source_returns_default_3(self, weights):
        assert get_tier("no-such-source-xyz", weights) == 3

    def test_custom_default(self, weights):
        assert get_tier("no-such-source", weights, default=5) == 5

    def test_list_dict_format(self):
        """get_tier() also accepts a List[dict] with source_id/tier keys."""
        cfg_list = [
            {"source_id": "my-source", "tier": 2},
            {"source_id": "other-source", "tier": 4},
        ]
        assert get_tier("my-source", cfg_list) == 2
        assert get_tier("other-source", cfg_list) == 4
        assert get_tier("unknown", cfg_list) == 3  # default


# ---------------------------------------------------------------------------
# Scored issue output fields
# ---------------------------------------------------------------------------

def _make_issue(issue_id: str, sources: list, title: str = "", summary: str = "") -> dict:
    return {
        "issue_id": issue_id,
        "issue_type": "cve",
        "title": title or f"Test issue {issue_id}",
        "summary": summary or f"Test summary for {issue_id}.",
        "sources": sources,
        "cves": [issue_id] if issue_id.startswith("CVE") else [],
        "links": [],
        "published_dates": ["2024-06-01"],
    }


def _run_score_issues(issues: list, tmp_path: Path, weights=None) -> list:
    """Write a temp JSONL, call score_issues(), return rows from output."""
    in_file = tmp_path / "issues.jsonl"
    in_file.write_text(
        "\n".join(json.dumps(i) for i in issues) + "\n", encoding="utf-8"
    )
    out_root = tmp_path / "scored"

    from advisoryops.score import score_issues
    score_issues(
        in_issues=str(in_file),
        out_root_scored=str(out_root),
        min_priority="P3",
        top=0,
        scoring_version="v2",
        _weights=weights,
    )

    rows = [
        json.loads(line)
        for line in (out_root / "issues_scored.jsonl").read_text().splitlines()
        if line.strip()
    ]
    return rows


class TestScoredIssueOutputFields:
    def test_source_authority_weight_present(self, tmp_path, weights):
        issues = [_make_issue("CVE-2024-0001", ["cisa-icsma"])]
        rows = _run_score_issues(issues, tmp_path, weights=weights)
        assert len(rows) == 1
        assert "source_authority_weight" in rows[0]

    def test_highest_authority_source_present(self, tmp_path, weights):
        issues = [_make_issue("CVE-2024-0002", ["cisa-icsma"])]
        rows = _run_score_issues(issues, tmp_path, weights=weights)
        assert "highest_authority_source" in rows[0]

    def test_cisa_icsma_weight_is_1(self, tmp_path, weights):
        issues = [_make_issue("CVE-2024-0003", ["cisa-icsma"])]
        rows = _run_score_issues(issues, tmp_path, weights=weights)
        assert rows[0]["source_authority_weight"] == pytest.approx(1.0)
        assert rows[0]["highest_authority_source"] == "cisa-icsma"

    def test_dark_reading_weight_is_half(self, tmp_path, weights):
        issues = [_make_issue("CVE-2024-0004", ["dark-reading"])]
        rows = _run_score_issues(issues, tmp_path, weights=weights)
        assert rows[0]["source_authority_weight"] == pytest.approx(0.50)
        assert rows[0]["highest_authority_source"] == "dark-reading"

    def test_unknown_source_defaults_to_05(self, tmp_path, weights):
        issues = [_make_issue("CVE-2024-0005", ["totally-unknown-feed"])]
        rows = _run_score_issues(issues, tmp_path, weights=weights)
        assert rows[0]["source_authority_weight"] == pytest.approx(0.5)

    def test_no_sources_defaults_to_05(self, tmp_path, weights):
        issues = [_make_issue("CVE-2024-0006", [])]
        rows = _run_score_issues(issues, tmp_path, weights=weights)
        assert rows[0]["source_authority_weight"] == pytest.approx(0.5)
        assert rows[0]["highest_authority_source"] == ""

    def test_multi_source_picks_highest(self, tmp_path, weights):
        """When an issue has multiple sources, highest weight wins."""
        issues = [_make_issue("CVE-2024-0007", ["dark-reading", "cisa-icsma", "urlhaus-recent"])]
        rows = _run_score_issues(issues, tmp_path, weights=weights)
        assert rows[0]["source_authority_weight"] == pytest.approx(1.0)
        assert rows[0]["highest_authority_source"] == "cisa-icsma"


# ---------------------------------------------------------------------------
# CISA vs news blog — scoring differential
# ---------------------------------------------------------------------------

class TestScoringDifferential:
    """An issue sourced from CISA must score higher than the identical issue
    sourced only from a news blog (dark-reading)."""

    _BASE_ISSUE = {
        "issue_id": "CVE-2024-9999",
        "issue_type": "cve",
        "title": "Remote Code Execution in hospital device",
        "summary": "A vulnerability allows unauthenticated remote code execution on network-connected hospital equipment.",
        "cves": ["CVE-2024-9999"],
        "links": [],
        "published_dates": ["2024-06-01"],
    }

    def test_cisa_scores_higher_than_news(self, tmp_path, weights):
        cisa_issue = dict(self._BASE_ISSUE, sources=["cisa-icsma"])
        news_issue = dict(self._BASE_ISSUE,
                          issue_id="CVE-2024-9998",
                          sources=["dark-reading"])

        from advisoryops.score import score_issue_v2
        cisa_result = score_issue_v2(cisa_issue, _weights=weights)
        news_result = score_issue_v2(news_issue, _weights=weights)

        assert cisa_result.score > news_result.score, (
            f"CISA score ({cisa_result.score}) should exceed news score ({news_result.score})"
        )

    def test_cisa_icsma_gets_healthcare_source_bonus(self, weights):
        from advisoryops.score import score_issue_v2
        issue = dict(self._BASE_ISSUE, sources=["cisa-icsma"])
        result = score_issue_v2(issue, _weights=weights)
        has_hc_bonus = any("healthcare-source" in w for w in result.why)
        assert has_hc_bonus, f"Expected healthcare-source bonus; got: {result.why}"

    def test_dark_reading_gets_no_healthcare_bonus(self, weights):
        from advisoryops.score import score_issue_v2
        issue = dict(self._BASE_ISSUE, sources=["dark-reading"])
        result = score_issue_v2(issue, _weights=weights)
        has_hc_bonus = any("healthcare-source" in w for w in result.why)
        assert not has_hc_bonus, f"Should NOT get healthcare bonus; got: {result.why}"


# ---------------------------------------------------------------------------
# Backward compat — existing score fields still present
# ---------------------------------------------------------------------------

class TestBackwardCompat:
    def test_existing_fields_unchanged(self, tmp_path, weights):
        issues = [_make_issue("CVE-2024-1234", ["cisa-icsma"],
                              summary="Remote code execution vulnerability.")]
        rows = _run_score_issues(issues, tmp_path, weights=weights)
        row = rows[0]

        # All original fields must still be present
        assert "score" in row
        assert "priority" in row
        assert "actions" in row
        assert "why" in row
        assert "unknowns" in row
        # New fields also present
        assert "source_authority_weight" in row
        assert "highest_authority_source" in row
        # Types are correct
        assert isinstance(row["score"], int)
        assert row["priority"] in ("P0", "P1", "P2", "P3")
        assert isinstance(row["actions"], list)
        assert isinstance(row["why"], list)
        assert isinstance(row["unknowns"], list)
        assert isinstance(row["source_authority_weight"], float)
        assert isinstance(row["highest_authority_source"], str)
