"""Structural audit of docs/paper_5/skeleton_v1_0.json (Paper 5 SSOT)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SKELETON = REPO_ROOT / "docs" / "paper_5" / "skeleton_v1_0.json"

# Section order is locked: two unnumbered front sections, then numbered 1..11.
EXPECTED_SECTION_IDS = [
    "in_plain_terms",          # unnumbered front matter (section_number None)
    "abstract",                # unnumbered (section_number None)
    "introduction",            # 1
    "background_threat_model", # 2
    "ares_harness_architecture",  # 3
    "action_gate_guarantee",   # 4
    "methodology",             # 5
    "results",                 # 6  (load-bearing -- the dual-spine headline)
    "positioning_vs_sota",     # 7
    "discussion",              # 8
    "limitations",             # 9
    "future_work",             # 10
    "references",              # 11
]


@pytest.fixture
def skeleton() -> dict:
    return json.loads(SKELETON.read_text(encoding="utf-8"))


class TestMeta:
    def test_skeleton_file_exists(self):
        assert SKELETON.exists()

    def test_parses_as_json(self, skeleton):
        assert isinstance(skeleton, dict)

    def test_kind_disambiguates(self, skeleton):
        assert skeleton["kind"] == "paper_structure_skeleton"

    def test_paper_id_locked(self, skeleton):
        assert skeleton["paper_id"] == "paper_5_v1_0"

    def test_framing_choice_locked(self, skeleton):
        fc = skeleton["framing_choice"].lower()
        assert "guarantee" in fc and "regime" in fc

    def test_evidence_base_declares_no_new_measurement(self, skeleton):
        assert "no new measurement" in skeleton["evidence_base"].lower()

    def test_build_start_test_floor(self, skeleton):
        assert skeleton["build_start_test_floor"] == 4476

    def test_required_top_level_keys(self, skeleton):
        for key in (
            "working_title", "short_title", "author", "venue",
            "target_words_core", "section_count_numbered", "framing_choice",
            "framing_rationale", "evidence_base", "contribution_claims",
            "result_findings", "sections", "figures", "tables",
            "numbers_preregistered", "bibkeys_required_verified",
            "bibkeys_needed_unverified", "anchor_tests_required",
        ):
            assert key in skeleton, f"missing top-level key: {key}"


class TestSections:
    def test_section_order_locked(self, skeleton):
        ids = [s["section_id"] for s in skeleton["sections"]]
        assert ids == EXPECTED_SECTION_IDS

    def test_in_plain_terms_first_and_unnumbered(self, skeleton):
        s0 = skeleton["sections"][0]
        assert s0["section_id"] == "in_plain_terms"
        assert s0["section_number"] is None

    def test_abstract_second_and_unnumbered(self, skeleton):
        s1 = skeleton["sections"][1]
        assert s1["section_id"] == "abstract"
        assert s1["section_number"] is None

    def test_numbered_one_through_eleven(self, skeleton):
        nums = sorted(
            s["section_number"]
            for s in skeleton["sections"]
            if s["section_number"] is not None
        )
        assert nums == list(range(1, 12))

    def test_section_count_numbered_is_eleven(self, skeleton):
        assert skeleton["section_count_numbered"] == 11

    def test_references_section_is_last(self, skeleton):
        last = skeleton["sections"][-1]
        assert last["section_id"] == "references"
        assert last["section_number"] == 11

    def test_each_section_has_required_fields(self, skeleton):
        for s in skeleton["sections"]:
            for field in (
                "section_id", "section_number", "title", "target_words",
                "claims", "numbers_preregistered", "bibkeys_required",
                "figures", "tables",
            ):
                assert field in s, f"{s.get('section_id')} missing {field}"

    def test_results_is_load_bearing(self, skeleton):
        results = next(s for s in skeleton["sections"] if s["section_id"] == "results")
        assert results.get("load_bearing") is True

    def test_target_words_sum_within_budget(self, skeleton):
        total = sum(s["target_words"] for s in skeleton["sections"])
        assert abs(total - skeleton["target_words_core"]) <= 400


class TestFiguresTables:
    def test_figure_count_locked(self, skeleton):
        assert len(skeleton["figures"]) == 6

    def test_table_count_locked(self, skeleton):
        assert len(skeleton["tables"]) == 4

    def test_each_figure_has_required_fields(self, skeleton):
        for f in skeleton["figures"]:
            for field in ("id", "type", "purpose", "source", "host_section"):
                assert field in f, f"{f.get('id')} missing {field}"

    def test_each_table_has_required_fields(self, skeleton):
        for t in skeleton["tables"]:
            for field in ("id", "purpose", "source", "host_section"):
                assert field in t, f"{t.get('id')} missing {field}"

    def test_figure_host_sections_valid(self, skeleton):
        valid = {s["section_number"] for s in skeleton["sections"]}
        for f in skeleton["figures"]:
            assert f["host_section"] in valid

    def test_table_host_sections_valid(self, skeleton):
        valid = {s["section_number"] for s in skeleton["sections"]}
        for t in skeleton["tables"]:
            assert t["host_section"] in valid

    def test_figures_listed_in_their_host_section(self, skeleton):
        by_num = {s["section_number"]: s for s in skeleton["sections"]}
        for f in skeleton["figures"]:
            assert f["id"] in by_num[f["host_section"]]["figures"]

    def test_tables_listed_in_their_host_section(self, skeleton):
        by_num = {s["section_number"]: s for s in skeleton["sections"]}
        for t in skeleton["tables"]:
            assert t["id"] in by_num[t["host_section"]]["tables"]


class TestNumbers:
    def test_each_number_has_required_fields(self, skeleton):
        for n in skeleton["numbers_preregistered"]:
            for field in ("value", "source", "lock_target"):
                assert field in n, f"number {n} missing {field}"

    def test_guarantee_numbers_locked(self, skeleton):
        values = {str(n["value"]) for n in skeleton["numbers_preregistered"]}
        for required in ("0.0", "0.2", "0.95", "2", "0.3", "0.45", "20", "$3.8"):
            assert required in values, f"registry missing {required}"

    def test_section_numbers_preregistered_are_subset_of_top_level(self, skeleton):
        top = {str(n["value"]) for n in skeleton["numbers_preregistered"]}
        for s in skeleton["sections"]:
            for tok in s["numbers_preregistered"]:
                assert tok in top, f"{s['section_id']} cites {tok} not in registry"


class TestBibkeys:
    def test_reused_verified_keys_present(self, skeleton):
        keys = {b["bibkey"] for b in skeleton["bibkeys_required_verified"]}
        for k in ("greshake-2023", "gmys-casiano-2026a", "gmys-casiano-2026d"):
            assert k in keys, f"missing verified bibkey {k}"

    def test_each_verified_bibkey_has_fields(self, skeleton):
        for b in skeleton["bibkeys_required_verified"]:
            assert b["bibkey"] and b["role"]
            assert b["status"] == "VERIFIED"

    def test_unverified_use_needed_marker(self, skeleton):
        for u in skeleton["bibkeys_needed_unverified"]:
            assert u["slug"] and u["verification_instructions"]


class TestAnchors:
    def test_anchor_tests_reference_existing_locks(self, skeleton):
        paths = {a["path"] for a in skeleton["anchor_tests_required"]}
        assert "tests/paper_5/test_prereg_bands_match_code.py" in paths
        assert "tests/harness/test_action_gate_invariants.py" in paths

    def test_each_anchor_has_fields(self, skeleton):
        for a in skeleton["anchor_tests_required"]:
            for field in ("path", "status", "locks"):
                assert field in a
