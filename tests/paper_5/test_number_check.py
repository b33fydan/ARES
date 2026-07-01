"""Number-check resolvers + the two subset locks + dormant prose lock."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from docs.paper_5 import number_check as nc

REPO = Path(nc.__file__).resolve().parents[2]
SKELETON = REPO / "docs" / "paper_5" / "skeleton_v1_0.json"
SOURCE = REPO / "docs" / "paper_5" / "source" / "PAPER5_DRAFT_v1_0_source.md"


def _sk() -> dict:
    return json.loads(SKELETON.read_text(encoding="utf-8"))


class TestResolvers:
    def test_max_undefended_asr_zero(self):
        assert nc._resolve_max_undefended_asr() == 0.0

    def test_full_defense_asr_zero(self):
        assert nc._resolve_full_defense_asr() == 0.0

    def test_full_defense_gate_denials_two(self):
        assert nc._resolve_full_defense_gate_denials() == 2

    def test_undefended_and_gate_off_denials_zero(self):
        assert nc._resolve_undefended_gate_denials() == 0
        assert nc._resolve_gate_off_gate_denials() == 0

    def test_utilities(self):
        assert nc._resolve_undefended_utility() == 0.5
        assert nc._resolve_full_defense_utility() == 0.3
        assert nc._resolve_gate_off_utility() == 0.45
        assert nc._resolve_sonnet_ii_utility() == 0.75

    def test_conclusion_integrity_and_echo(self):
        assert nc._resolve_conclusion_integrity() == 0.95
        assert nc._resolve_echo_rate() == 0.05

    def test_benign_false_block(self):
        assert nc._resolve_benign_false_block() == 0.2
        assert nc._resolve_benign_denials() == 4

    def test_protocol_counts(self):
        assert nc._resolve_n() == 20
        assert nc._resolve_eligible_injection_count() == 9
        assert nc._resolve_rollouts() == 96
        assert nc._resolve_tau_asr() == 0.2

    def test_contingency_and_fallback(self):
        assert nc._resolve_selected_cell_is_null() is True
        assert nc._resolve_fallback_cell() == ("haiku-4-5", "important_instructions", "banking")


class TestHarness:
    def test_run_checks_all_pass(self):
        results = nc.run_checks(nc.default_claims(_sk()))
        failed = [r.label for r in results if not r.passed]
        assert not failed, f"failing claims: {failed}"

    def test_main_exits_zero(self, tmp_path):
        out = tmp_path / "report.md"
        assert nc.main(["--out-report", str(out)]) == 0


class TestSkeletonSourceConsistency:
    # Every registry number in `covered` must be backed by a passing resolver.
    COVERED = {
        "0.0", "0.5", "0.75", "0.3", "0.45",
        "0.95", "0.05", "0.2", "2", "0", "4", "20", "9", "96",
    }

    def test_covered_skeleton_numbers_have_passing_resolvers(self):
        results = nc.run_checks(nc.default_claims(_sk()))
        resolved = {str(r.actual) for r in results if r.passed}
        for n in _sk()["numbers_preregistered"]:
            v = str(n["value"])
            if v in self.COVERED:
                assert v in resolved, f"registry {v} has no passing resolver"


@pytest.mark.skipif(not SOURCE.exists(), reason="Phase-3 prose not yet authored")
class TestProse:
    def _source_text(self) -> str:
        return SOURCE.read_text(encoding="utf-8")

    def test_source_contains_all_prose_substrings(self):
        results = nc.check_prose_substrings(self._source_text(), nc.prose_substring_claims())
        missing = [r.label for r in results if not r.passed]
        assert not missing, f"missing prose substrings: {missing}"

    def test_main_source_mode_exits_zero(self, tmp_path):
        out = tmp_path / "report.md"
        assert nc.main(["--out-report", str(out), "--source", str(SOURCE)]) == 0
