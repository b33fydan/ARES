import json
from pathlib import Path
import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SKELETON = REPO_ROOT / "docs" / "paper_4" / "skeleton_v1_0.json"

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
        assert skeleton["paper_id"] == "paper_4_v1_0"
    def test_framing_choice_locked(self, skeleton):
        assert "trilemma" in skeleton["framing_choice"].lower()
    def test_required_top_level_keys(self, skeleton):
        for key in ("working_title", "short_title", "author", "venue",
                    "target_words_core", "section_count_numbered",
                    "contribution_claims", "three_finding_story", "sections",
                    "figures", "tables", "numbers_preregistered",
                    "bibkeys_required_verified", "bibkeys_needed_unverified",
                    "anchor_tests_required"):
            assert key in skeleton, key

class TestSections:
    def test_section_count_locked(self, skeleton):
        assert skeleton["section_count_numbered"] == 12
    def test_abstract_first_and_unnumbered(self, skeleton):
        s0 = skeleton["sections"][0]
        assert s0["section_id"] == "abstract"
        assert s0["section_number"] is None
    def test_numbered_one_through_twelve(self, skeleton):
        nums = [s["section_number"] for s in skeleton["sections"]
                if s["section_number"] is not None]
        assert nums == list(range(1, 13))
    def test_references_section_is_last(self, skeleton):
        assert skeleton["sections"][-1]["section_id"] == "references"
        assert skeleton["sections"][-1]["section_number"] == 12
    def test_each_section_has_required_fields(self, skeleton):
        for s in skeleton["sections"]:
            for f in ("section_id", "section_number", "title",
                      "target_words", "claims", "numbers_preregistered",
                      "bibkeys_required", "figures", "tables"):
                assert f in s, (s["section_id"], f)
    def test_three_findings_present(self, skeleton):
        ids = {s["section_id"] for s in skeleton["sections"]}
        assert {"finding_1_empty_corner", "finding_2_oov_defeat",
                "finding_3_independent_audit"} <= ids
    def test_finding_2_is_load_bearing(self, skeleton):
        f2 = next(s for s in skeleton["sections"]
                  if s["section_id"] == "finding_2_oov_defeat")
        assert f2.get("load_bearing") is True
    def test_target_words_sum_within_budget(self, skeleton):
        total = sum(s["target_words"] for s in skeleton["sections"])
        assert abs(total - skeleton["target_words_core"]) <= 400

class TestFiguresTables:
    def test_figure_count_locked(self, skeleton):
        assert len(skeleton["figures"]) == 6
    def test_table_count_locked(self, skeleton):
        assert len(skeleton["tables"]) == 4
    def test_each_figure_has_required_fields(self, skeleton):
        for fig in skeleton["figures"]:
            for f in ("id", "type", "purpose", "host_section", "source"):
                assert f in fig, (fig.get("id"), f)
    def test_figure_host_sections_valid(self, skeleton):
        valid = {s["section_number"] for s in skeleton["sections"]
                 if s["section_number"] is not None}
        for fig in skeleton["figures"]:
            assert fig["host_section"] in valid
    def test_each_table_has_required_fields(self, skeleton):
        for tbl in skeleton["tables"]:
            for f in ("id", "purpose", "host_section", "source"):
                assert f in tbl, (tbl.get("id"), f)
    def test_table_host_sections_valid(self, skeleton):
        valid = {s["section_number"] for s in skeleton["sections"]
                 if s["section_number"] is not None}
        for tbl in skeleton["tables"]:
            assert tbl["host_section"] in valid
    def test_figures_listed_in_their_host_section(self, skeleton):
        by_num = {s["section_number"]: s for s in skeleton["sections"]
                  if s["section_number"] is not None}
        for fig in skeleton["figures"]:
            host = by_num[fig["host_section"]]
            assert fig["id"] in host["figures"], (fig["id"], host["section_id"])
    def test_tables_listed_in_their_host_section(self, skeleton):
        by_num = {s["section_number"]: s for s in skeleton["sections"]
                  if s["section_number"] is not None}
        for tbl in skeleton["tables"]:
            host = by_num[tbl["host_section"]]
            assert tbl["id"] in host["tables"], (tbl["id"], host["section_id"])

class TestNumbers:
    def test_each_number_has_required_fields(self, skeleton):
        for n in skeleton["numbers_preregistered"]:
            assert "value" in n and "source" in n and "lock_target" in n
    def test_trilemma_cap_locked(self, skeleton):
        vals = {str(n["value"]) for n in skeleton["numbers_preregistered"]}
        assert "0.25" in vals
        assert "SUPPORTED_STRONG" in vals
        assert "ROBUST" in vals
        assert "0.0005" in vals
    def test_section_numbers_preregistered_are_subset_of_top_level(self, skeleton):
        top_vals = {str(n["value"]) for n in skeleton["numbers_preregistered"]}
        for s in skeleton["sections"]:
            for v in s.get("numbers_preregistered", []):
                assert str(v) in top_vals, (
                    s["section_id"], v,
                    f"'{v}' not in top-level numbers_preregistered"
                )

class TestBibkeys:
    def test_verified_keys_present(self, skeleton):
        keys = {b["bibkey"] for b in skeleton["bibkeys_required_verified"]}
        for reused in ("greshake-2023", "guo-2024", "jacovi-goldberg-2020",
                       "reiter-1978", "berdoz-rugli-wattenhofer-2026"):
            assert reused in keys, reused
    def test_each_verified_bibkey_has_fields(self, skeleton):
        for b in skeleton["bibkeys_required_verified"]:
            for f in ("bibkey", "role", "status"):
                assert f in b
            assert b["status"] == "VERIFIED"
    def test_unverified_use_needed_marker(self, skeleton):
        for b in skeleton["bibkeys_needed_unverified"]:
            assert "slug" in b and "verification_instructions" in b

class TestAnchors:
    def test_anchor_tests_reference_existing_locks(self, skeleton):
        paths = {a["path"] for a in skeleton["anchor_tests_required"]}
        assert any("test_oov_prereg_bands_match_code" in p for p in paths)
        assert any("test_read_depth_oov_no_network_anchor" in p for p in paths)
