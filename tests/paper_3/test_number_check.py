"""Smoke + resolver tests for ``docs/paper_3/number_check.py``.

Session 064 scope: the script + its resolvers must run clean against
the current source state (skeleton, leakage runs, source files). Prose
substring checks are dormant in this session and exercised only
through synthetic fixtures.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]


# ============================================================================
# Run-clean smoke test
# ============================================================================


class TestSkeletonModeRunsClean:
    """The script's default mode (skeleton-only, no --docx) must
    succeed against the current source state. If a future change
    breaks any resolver, this test fires first."""

    def test_main_exits_zero(self, tmp_path):
        from docs.paper_3.number_check import main
        out = tmp_path / "report.md"
        rc = main(["--out-report", str(out)])
        assert rc == 0, "number_check failed in skeleton mode"

    def test_report_file_written(self, tmp_path):
        from docs.paper_3.number_check import main
        out = tmp_path / "report.md"
        main(["--out-report", str(out)])
        assert out.exists(), "Report file not written"
        text = out.read_text(encoding="utf-8")
        assert "Paper 3 number_check report" in text
        assert "**Overall: PASS" in text


# ============================================================================
# Resolver-level checks
# ============================================================================


class TestResolvers:
    def test_narrow_pair_count_is_98(self):
        from docs.paper_3.number_check import _resolve_narrow_pair_count
        assert _resolve_narrow_pair_count() == 98

    def test_narrow_byte_stable_count_is_98(self):
        from docs.paper_3.number_check import (
            _resolve_narrow_byte_stable_count,
        )
        assert _resolve_narrow_byte_stable_count() == 98

    def test_llm_path_divergence_count_is_73(self):
        from docs.paper_3.number_check import (
            _resolve_llm_path_divergence_count,
        )
        assert _resolve_llm_path_divergence_count() == 73

    def test_llm_path_no_divergence_count_is_25(self):
        from docs.paper_3.number_check import (
            _resolve_llm_path_no_divergence_count,
        )
        assert _resolve_llm_path_no_divergence_count() == 25

    def test_architect_first_diverging_count_is_39(self):
        from docs.paper_3.number_check import (
            _resolve_llm_path_first_diverging_at,
        )
        assert _resolve_llm_path_first_diverging_at("architect") == 39

    def test_skeptic_llm_first_diverging_count_is_34(self):
        from docs.paper_3.number_check import (
            _resolve_llm_path_first_diverging_at,
        )
        assert _resolve_llm_path_first_diverging_at("skeptic_llm") == 34

    def test_light_skeptic_anchor_line_is_185(self):
        from docs.paper_3.number_check import (
            _resolve_light_skeptic_anchor_line_number,
        )
        assert _resolve_light_skeptic_anchor_line_number() == 185

    def test_oracle_passthrough_range_start_is_89(self):
        from docs.paper_3.number_check import (
            _resolve_oracle_passthrough_line_range,
        )
        start, _end = _resolve_oracle_passthrough_line_range()
        assert start == 89

    def test_oracle_passthrough_range_end_is_116(self):
        from docs.paper_3.number_check import (
            _resolve_oracle_passthrough_line_range,
        )
        _start, end = _resolve_oracle_passthrough_line_range()
        assert end == 116

    def test_leakage_run_count_at_least_three(self):
        from docs.paper_3.number_check import _resolve_leakage_run_count
        assert _resolve_leakage_run_count() >= 3

    def test_test_floor_from_skeleton_is_3737(self):
        from docs.paper_3.number_check import _resolve_test_floor_from_skeleton
        skeleton = json.loads(
            (REPO_ROOT / "docs" / "paper_3" / "skeleton_v1_0.json")
            .read_text(encoding="utf-8")
        )
        assert _resolve_test_floor_from_skeleton(skeleton) == 3737

    def test_verdict_class_passthrough_map_resolves_from_source(self):
        """Session 065 patch: §6.6 lock. The resolver reads oracle.py
        and asserts the per-verdict-class supporting_facts source. If
        oracle.py drifts, this fires."""
        from docs.paper_3.number_check import (
            _resolve_verdict_class_passthrough_map,
        )
        actual = _resolve_verdict_class_passthrough_map()
        assert actual == {
            "THREAT_CONFIRMED": "architect",
            "THREAT_DISMISSED": "skeptic",
            "INCONCLUSIVE": "union",
        }

    def test_verdict_class_passthrough_map_raises_when_branch_missing(
        self, tmp_path, monkeypatch,
    ):
        """If a verdict-class branch goes missing from oracle.py, the
        resolver must raise loudly, not silently return a partial map."""
        from docs.paper_3 import number_check

        # Replace ORACLE_PY with a fake source missing the
        # THREAT_DISMISSED branch.
        fake_oracle = tmp_path / "oracle_fake.py"
        fake_oracle.write_text(
            "supporting_facts = frozenset(arch_facts)\n"
            "supporting_facts = frozenset(arch_facts | skep_facts)\n",
            encoding="utf-8",
        )
        monkeypatch.setattr(number_check, "ORACLE_PY", fake_oracle)

        with pytest.raises(LookupError, match="THREAT_DISMISSED"):
            number_check._resolve_verdict_class_passthrough_map()


# ============================================================================
# Claim table + check engine
# ============================================================================


class TestClaimsTable:
    def test_default_claims_returns_at_least_twelve(self):
        """Session 065 patch added the verdict_class_passthrough_map
        claim, bringing the count from 11 to 12."""
        from docs.paper_3.number_check import default_claims
        skeleton = json.loads(
            (REPO_ROOT / "docs" / "paper_3" / "skeleton_v1_0.json")
            .read_text(encoding="utf-8")
        )
        claims = default_claims(skeleton)
        assert len(claims) >= 12

    def test_run_checks_all_pass_against_current_state(self):
        from docs.paper_3.number_check import default_claims, run_checks
        skeleton = json.loads(
            (REPO_ROOT / "docs" / "paper_3" / "skeleton_v1_0.json")
            .read_text(encoding="utf-8")
        )
        results = run_checks(default_claims(skeleton))
        failed = [r for r in results if not r.passed]
        assert not failed, (
            f"Claims failing against current source state: "
            f"{[r.label for r in failed]}"
        )

    def test_run_checks_catches_broken_resolver(self):
        """A resolver that returns the wrong value must produce
        passed=False — the engine isn't permissive."""
        from docs.paper_3.number_check import Claim, run_checks

        def _broken_resolver():
            return 9999

        broken = Claim(
            label="broken",
            expected=42,
            resolver=_broken_resolver,
        )
        results = run_checks((broken,))
        assert len(results) == 1
        assert not results[0].passed
        assert results[0].actual == 9999

    def test_run_checks_handles_resolver_exception(self):
        """Exceptions in a resolver must surface in the report with
        passed=False, not crash the entire check."""
        from docs.paper_3.number_check import Claim, run_checks

        def _exploding_resolver():
            raise RuntimeError("intentional test failure")

        boom = Claim(
            label="boom",
            expected=1,
            resolver=_exploding_resolver,
        )
        results = run_checks((boom,))
        assert len(results) == 1
        assert not results[0].passed
        assert "ERROR" in results[0].label


# ============================================================================
# Prose-substring engine (dormant in Session 064 — synthetic fixtures)
# ============================================================================


class TestProseSubstringEngine:
    def test_substring_present_passes(self):
        from docs.paper_3.number_check import check_prose_substrings
        results = check_prose_substrings(
            "The narrow result was 98/98 paired trials.",
            ("98/98",),
        )
        assert len(results) == 1
        assert results[0].passed

    def test_substring_absent_fails(self):
        from docs.paper_3.number_check import check_prose_substrings
        results = check_prose_substrings(
            "Some prose without the lock substring.",
            ("98/98",),
        )
        assert len(results) == 1
        assert not results[0].passed

    def test_prose_substring_claims_seeded_with_key_locks(self):
        """The substring list seeded for Session 065+ must contain
        the key locked-number tokens (98, 73, 185, etc.)."""
        from docs.paper_3.number_check import prose_substring_claims
        subs = prose_substring_claims()
        for required in ("98", "98/98", "73", "73/98", "185", "88-115"):
            assert required in subs, f"Seeded substring {required!r} missing"

    def test_prose_substring_claims_include_load_bearing_anchor(self):
        from docs.paper_3.number_check import prose_substring_claims
        subs = prose_substring_claims()
        assert "_ = architect_output" in subs, (
            "Light Skeptic anchor substring must appear in prose lock list"
        )
        assert "supporting_fact_ids" in subs, (
            "Oracle passthrough symbol must appear in prose lock list"
        )

    def test_prose_substring_claims_include_section_6_6_locks(self):
        """Session 065 patch: §6.6 prose must reference the
        non-passthrough branches and their line numbers."""
        from docs.paper_3.number_check import prose_substring_claims
        subs = prose_substring_claims()
        for required in (
            "THREAT_DISMISSED", "INCONCLUSIVE",
            "102", "105", "109", "101-111",
        ):
            assert required in subs, (
                f"§6.6 substring lock {required!r} missing from "
                f"prose_substring_claims"
            )


# ============================================================================
# Report rendering
# ============================================================================


class TestReportRendering:
    def test_renders_pass_status_when_all_pass(self):
        from docs.paper_3.number_check import (
            CheckResult,
            render_report,
        )
        results = (
            CheckResult(
                label="one", expected=1, actual=1, passed=True,
            ),
            CheckResult(
                label="two", expected=2, actual=2, passed=True,
            ),
        )
        text = render_report(results)
        assert "**Overall: PASS (2 / 2 claims validated)**" in text

    def test_renders_fail_status_when_any_fail(self):
        from docs.paper_3.number_check import CheckResult, render_report
        results = (
            CheckResult(
                label="one", expected=1, actual=2, passed=False,
            ),
        )
        text = render_report(results)
        assert "**Overall: FAIL" in text

    def test_report_mentions_dormant_prose_check_section(self):
        from docs.paper_3.number_check import render_report
        text = render_report(())
        assert "Session 065+ activation" in text
