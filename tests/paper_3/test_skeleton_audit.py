"""Structural audit for ``docs/paper_3/skeleton_v1_0.json``.

Locks the Paper 3 v1.0 structural scaffold against silent drift. The
skeleton is the load-bearing decision artifact for the paper: it
declares section structure, word budgets, pre-registered numbers, and
anchor-test dependencies. Subsequent sessions add prose against this
scaffold (Session 065 onwards).

These tests are structural only — they do NOT validate prose content
(none yet) or verify external bibkey resolution (that lives in
``test_citation_existence.py``).

Distinct from Session 057's ``docs/paper_3/skeleton_audit_v1.json``,
which audits the *evidence* skeleton of injection scenarios. Naming
collision noted: both use the word "skeleton" but for different
artifacts (paper structure vs evidence-record structure).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
SKELETON_PATH = REPO_ROOT / "docs" / "paper_3" / "skeleton_v1_0.json"


# Expected top-level shape. Bumping these constants is the deliberate
# Architecture Decision Record moment for any restructuring.
EXPECTED_KIND = "paper_structure_skeleton"
EXPECTED_PAPER_ID = "paper_3_v1_0"
EXPECTED_SECTION_COUNT = 12  # abstract + 11 numbered
EXPECTED_NUMBERED_SECTIONS = 11
EXPECTED_TARGET_WORDS_CORE = 8650
EXPECTED_BUILD_SESSION = 64
EXPECTED_BUILD_START_TEST_FLOOR = 3737
EXPECTED_FIGURES = 6
EXPECTED_TABLES = 2
EXPECTED_ANCHOR_TESTS = 3
EXPECTED_VERIFIED_BIBKEYS = 2
EXPECTED_UNVERIFIED_BIBKEYS = 5

# Sections that the three-leg story attaches to.
FINDING_SECTION_IDS = (
    "finding_1_byte_stability",
    "finding_2_oracle_passthrough",
    "finding_3_llm_path_bound",
)


@pytest.fixture(scope="module")
def skeleton() -> dict:
    return json.loads(SKELETON_PATH.read_text(encoding="utf-8"))


# ============================================================================
# Top-level shape
# ============================================================================


class TestTopLevelShape:
    def test_skeleton_file_exists(self) -> None:
        assert SKELETON_PATH.exists(), (
            f"Skeleton missing at {SKELETON_PATH}; Session 064 deliverable"
        )

    def test_skeleton_parses_as_json(self, skeleton: dict) -> None:
        assert isinstance(skeleton, dict)

    def test_kind_field_disambiguates_from_evidence_skeleton(
        self, skeleton: dict
    ) -> None:
        """The ``kind`` field disambiguates this paper-structure
        skeleton from Session 057's evidence-skeleton audit at
        ``docs/paper_3/skeleton_audit_v1.json``."""
        assert skeleton.get("kind") == EXPECTED_KIND, (
            f"kind field must be {EXPECTED_KIND!r} to distinguish from "
            "the evidence-skeleton audit artifact"
        )

    def test_paper_id_locked(self, skeleton: dict) -> None:
        assert skeleton["paper_id"] == EXPECTED_PAPER_ID

    def test_build_session_locked(self, skeleton: dict) -> None:
        assert skeleton["build_session"] == EXPECTED_BUILD_SESSION

    def test_build_start_test_floor_locked(self, skeleton: dict) -> None:
        assert skeleton["build_start_test_floor"] == EXPECTED_BUILD_START_TEST_FLOOR

    def test_target_words_core_locked(self, skeleton: dict) -> None:
        assert skeleton["target_words_core"] == EXPECTED_TARGET_WORDS_CORE

    def test_required_top_level_keys_present(self, skeleton: dict) -> None:
        required = {
            "kind", "paper_id", "working_title", "short_title",
            "author", "venue", "target_words_core",
            "build_session", "build_start_test_floor", "skeleton_version",
            "framing_choice", "section_order_choice",
            "contribution_claims", "three_leg_story", "sections",
            "figures", "tables", "numbers_preregistered",
            "bibkeys_required_verified", "bibkeys_needed_unverified",
            "anchor_tests_required",
        }
        missing = required - set(skeleton.keys())
        assert not missing, f"Missing required top-level keys: {missing}"


# ============================================================================
# Sections
# ============================================================================


class TestSections:
    def test_section_count_locked(self, skeleton: dict) -> None:
        assert len(skeleton["sections"]) == EXPECTED_SECTION_COUNT

    def test_abstract_is_first_and_unnumbered(self, skeleton: dict) -> None:
        first = skeleton["sections"][0]
        assert first["section_id"] == "abstract"
        assert first["section_number"] is None

    def test_numbered_sections_are_one_through_eleven(self, skeleton: dict) -> None:
        numbered = [
            s for s in skeleton["sections"] if s["section_number"] is not None
        ]
        assert len(numbered) == EXPECTED_NUMBERED_SECTIONS
        assert [s["section_number"] for s in numbered] == list(range(1, 12))

    def test_target_words_sum_matches_core_budget(self, skeleton: dict) -> None:
        total = sum(s["target_words"] for s in skeleton["sections"])
        assert total == EXPECTED_TARGET_WORDS_CORE, (
            f"Target words sum to {total}, expected "
            f"{EXPECTED_TARGET_WORDS_CORE}"
        )

    def test_each_section_has_required_fields(self, skeleton: dict) -> None:
        required_per_section = {
            "section_id", "section_number", "title", "target_words",
            "narrative_arc", "claims", "numbers_preregistered",
            "bibkeys_required", "figures", "tables", "subsections",
        }
        for sec in skeleton["sections"]:
            missing = required_per_section - set(sec.keys())
            assert not missing, (
                f"Section {sec.get('section_id', '?')!r} missing fields: "
                f"{missing}"
            )

    def test_all_three_findings_present(self, skeleton: dict) -> None:
        section_ids = {s["section_id"] for s in skeleton["sections"]}
        for expected in FINDING_SECTION_IDS:
            assert expected in section_ids, (
                f"Three-leg story section {expected!r} missing"
            )

    def test_finding_2_is_load_bearing(self, skeleton: dict) -> None:
        """§6 (Oracle passthrough) is the load-bearing section per the
        brief; it carries the decoupling principle and the architectural
        anchor."""
        f2 = next(
            s for s in skeleton["sections"]
            if s["section_id"] == "finding_2_oracle_passthrough"
        )
        assert f2.get("load_bearing") is True
        assert f2["target_words"] == 1500, (
            "Finding 2 word budget locked at 1500 (largest section)"
        )

    def test_references_section_is_last(self, skeleton: dict) -> None:
        last = skeleton["sections"][-1]
        assert last["section_id"] == "references"
        assert last["section_number"] == 11


# ============================================================================
# Figures and tables
# ============================================================================


class TestFiguresAndTables:
    def test_figure_count_locked(self, skeleton: dict) -> None:
        assert len(skeleton["figures"]) == EXPECTED_FIGURES

    def test_table_count_locked(self, skeleton: dict) -> None:
        assert len(skeleton["tables"]) == EXPECTED_TABLES

    def test_each_figure_has_required_fields(self, skeleton: dict) -> None:
        required = {"id", "type", "purpose", "source", "host_section"}
        for fig in skeleton["figures"]:
            assert required <= set(fig.keys()), (
                f"Figure {fig.get('id', '?')!r} missing fields: "
                f"{required - set(fig.keys())}"
            )

    def test_each_table_has_required_fields(self, skeleton: dict) -> None:
        required = {"id", "purpose", "source", "host_section"}
        for tbl in skeleton["tables"]:
            assert required <= set(tbl.keys()), (
                f"Table {tbl.get('id', '?')!r} missing fields: "
                f"{required - set(tbl.keys())}"
            )

    def test_figure_host_sections_are_valid(self, skeleton: dict) -> None:
        """Every figure's host_section must point at a section that
        exists in the section list."""
        section_numbers = {
            s["section_number"] for s in skeleton["sections"]
            if s["section_number"] is not None
        }
        for fig in skeleton["figures"]:
            assert fig["host_section"] in section_numbers, (
                f"Figure {fig['id']!r} hosted in non-existent section "
                f"{fig['host_section']}"
            )

    def test_code_snippet_figures_lock_line_anchors(self, skeleton: dict) -> None:
        """Figures 5 and 6 are the code-snippet anchors; their purpose
        text must reference the load-bearing line locations."""
        figs_by_id = {f["id"]: f for f in skeleton["figures"]}
        assert "light_skeptic.py:185" in figs_by_id["fig_5"]["purpose"]
        assert "oracle.py:88-115" in figs_by_id["fig_6"]["purpose"]


# ============================================================================
# Pre-registered numbers
# ============================================================================


class TestPreRegisteredNumbers:
    def test_each_number_has_required_fields(self, skeleton: dict) -> None:
        required = {"value", "source", "lock_target"}
        for num in skeleton["numbers_preregistered"]:
            assert required <= set(num.keys()), (
                f"Number {num.get('value', '?')!r} missing fields: "
                f"{required - set(num.keys())}"
            )

    def test_llm_path_drift_integer_locked(self, skeleton: dict) -> None:
        """The exact LLM-path drift integer pulled from
        LEAKAGE_REPORT_20260510-193950-f401a8.md §3. Brief originally
        said '~74%'; precise value is 73 of 98 (74.49%)."""
        values = {n["value"] for n in skeleton["numbers_preregistered"]}
        assert "73" in values, "LLM-path divergence count 73 not locked"
        assert "73/98" in values, "LLM-path ratio 73/98 not locked"
        assert "74.49%" in values, "LLM-path rate 74.49% not locked"

    def test_narrow_byte_stability_count_locked(
        self, skeleton: dict
    ) -> None:
        values = {n["value"] for n in skeleton["numbers_preregistered"]}
        assert "98/98" in values, "Narrow byte-stability 98/98 not locked"
        assert "101/0" in values, "Full-chain fires 101/0 not locked"

    def test_code_anchor_line_locations_locked(self, skeleton: dict) -> None:
        values = {n["value"] for n in skeleton["numbers_preregistered"]}
        assert "185" in values, "light_skeptic.py:185 not locked"
        assert "88-115" in values, "oracle.py:88-115 not locked"

    def test_test_floor_locked_at_session_063_handoff(
        self, skeleton: dict
    ) -> None:
        values = {n["value"] for n in skeleton["numbers_preregistered"]}
        assert "3737" in values, "Test floor 3737 not locked"


# ============================================================================
# Bibkeys
# ============================================================================


class TestBibkeys:
    def test_verified_bibkey_count_locked(self, skeleton: dict) -> None:
        assert (
            len(skeleton["bibkeys_required_verified"])
            == EXPECTED_VERIFIED_BIBKEYS
        )

    def test_unverified_bibkey_count_locked(self, skeleton: dict) -> None:
        assert (
            len(skeleton["bibkeys_needed_unverified"])
            == EXPECTED_UNVERIFIED_BIBKEYS
        )

    def test_each_verified_bibkey_has_required_fields(
        self, skeleton: dict
    ) -> None:
        required = {"bibkey", "role", "status", "source", "verified_session"}
        for entry in skeleton["bibkeys_required_verified"]:
            assert required <= set(entry.keys()), (
                f"Verified bibkey {entry.get('bibkey', '?')!r} missing: "
                f"{required - set(entry.keys())}"
            )
            assert entry["status"] == "VERIFIED"

    def test_each_unverified_bibkey_has_required_fields(
        self, skeleton: dict
    ) -> None:
        required = {
            "slug", "description", "lock_target_sections",
            "verification_required_before_commit",
        }
        for entry in skeleton["bibkeys_needed_unverified"]:
            assert required <= set(entry.keys()), (
                f"Unverified bibkey {entry.get('slug', '?')!r} missing: "
                f"{required - set(entry.keys())}"
            )

    def test_unverified_bibkeys_use_needed_suffix(
        self, skeleton: dict
    ) -> None:
        """``-needed`` suffix prevents an unverified slug from
        accidentally matching a real cite key in the prose."""
        for entry in skeleton["bibkeys_needed_unverified"]:
            assert entry["slug"].endswith("-needed"), (
                f"Unverified bibkey slug must end in -needed: "
                f"{entry['slug']}"
            )

    def test_verified_bibkeys_do_not_use_needed_suffix(
        self, skeleton: dict
    ) -> None:
        for entry in skeleton["bibkeys_required_verified"]:
            assert not entry["bibkey"].endswith("-needed"), (
                f"Verified bibkey must not use -needed suffix: "
                f"{entry['bibkey']}"
            )


# ============================================================================
# Anchor tests
# ============================================================================


class TestAnchorTests:
    def test_anchor_test_count_locked(self, skeleton: dict) -> None:
        assert (
            len(skeleton["anchor_tests_required"]) == EXPECTED_ANCHOR_TESTS
        )

    def test_each_anchor_test_has_required_fields(
        self, skeleton: dict
    ) -> None:
        required = {"path", "status", "session_064_action", "locks"}
        for entry in skeleton["anchor_tests_required"]:
            assert required <= set(entry.keys()), (
                f"Anchor test {entry.get('path', '?')!r} missing: "
                f"{required - set(entry.keys())}"
            )

    def test_existing_light_skeptic_anchor_referenced(
        self, skeleton: dict
    ) -> None:
        paths = {a["path"] for a in skeleton["anchor_tests_required"]}
        expected = "ares/dialectic/tests/agents/test_light_skeptic_anchor.py"
        assert expected in paths

    def test_new_oracle_passthrough_anchor_referenced(
        self, skeleton: dict
    ) -> None:
        paths = {a["path"] for a in skeleton["anchor_tests_required"]}
        expected = (
            "ares/dialectic/tests/agents/"
            "test_oracle_supporting_fact_ids_passthrough.py"
        )
        assert expected in paths

    def test_new_paired_trial_byte_stability_anchor_referenced(
        self, skeleton: dict
    ) -> None:
        paths = {a["path"] for a in skeleton["anchor_tests_required"]}
        expected = (
            "tests/dialectic/measurement/"
            "test_paired_trial_byte_stability.py"
        )
        assert expected in paths


# ============================================================================
# Three-leg story
# ============================================================================


class TestThreeLegStory:
    def test_three_legs_present(self, skeleton: dict) -> None:
        legs = skeleton["three_leg_story"]
        assert set(legs.keys()) == {
            "leg_1_narrow_byte_stable",
            "leg_2_sibling_passthrough",
            "leg_3_llm_path_bound",
        }

    def test_leg_1_locks_anchor_test_path(self, skeleton: dict) -> None:
        leg_1 = skeleton["three_leg_story"]["leg_1_narrow_byte_stable"]
        assert "test_light_skeptic_anchor.py" in leg_1["anchor_test"]

    def test_leg_2_locks_new_oracle_anchor_test_path(
        self, skeleton: dict
    ) -> None:
        leg_2 = skeleton["three_leg_story"]["leg_2_sibling_passthrough"]
        assert (
            "test_oracle_supporting_fact_ids_passthrough.py"
            in leg_2["anchor_test_new_this_session"]
        )

    def test_leg_3_locks_exact_integer(self, skeleton: dict) -> None:
        leg_3 = skeleton["three_leg_story"]["leg_3_llm_path_bound"]
        assert "73 of 98" in leg_3["exact_integer"]
        assert "74.49%" in leg_3["exact_integer"]


# ============================================================================
# Decisions documented from the brief
# ============================================================================


class TestDecisionsDocumented:
    def test_framing_choice_locked(self, skeleton: dict) -> None:
        assert "Decision Determinism" in skeleton["framing_choice"]
        assert "Explanation Drift" in skeleton["framing_choice"]

    def test_section_order_is_skeptic_first(self, skeleton: dict) -> None:
        assert "Skeptic-first" in skeleton["section_order_choice"]

    def test_venue_is_aisec_at_ccs(self, skeleton: dict) -> None:
        assert "AISec" in skeleton["venue"]
        assert "CCS" in skeleton["venue"]

    def test_phasing_decision_is_option_a(self, skeleton: dict) -> None:
        assert "Option A" in skeleton["session_064_phasing_decision"]

    def test_code_snippet_placement_inline(self, skeleton: dict) -> None:
        assert "inline" in skeleton["session_064_code_snippet_placement"]

    def test_phase7_callback_out_of_scope(self, skeleton: dict) -> None:
        assert (
            "out of scope"
            in skeleton["session_064_phase7_visualization_callback"]
        )

    def test_session_064_prose_out_of_scope(self, skeleton: dict) -> None:
        out_of_scope = skeleton["out_of_scope_session_064"]
        assert any("prose" in item.lower() for item in out_of_scope)
