"""Tests for Paper 2 number_check.py.

Covers:
    * Clean run on the real results root → all claims validated, exit 0.
    * Broken fixture (wrong expected) → exit 1 and report shows FAIL.
    * Individual resolvers produce expected types.
    * Report is written and parseable.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
RESULTS_ROOT = REPO_ROOT / "results"


class TestCleanRun:
    def test_main_exits_zero_on_real_data(self, tmp_path, capsys):
        from docs.paper_2.number_check import main
        out_report = tmp_path / "report.md"
        code = main([
            "--results-root", str(RESULTS_ROOT),
            "--out-report", str(out_report),
        ])
        assert code == 0
        assert out_report.exists()
        text = out_report.read_text(encoding="utf-8")
        assert "PASS" in text
        # No ✗ marks in a clean run.
        assert "✗" not in text

    def test_report_contains_all_claims(self, tmp_path):
        from docs.paper_2.number_check import default_claims, main
        out_report = tmp_path / "report.md"
        main([
            "--results-root", str(RESULTS_ROOT),
            "--out-report", str(out_report),
        ])
        text = out_report.read_text(encoding="utf-8")
        for claim in default_claims():
            assert claim.label in text

    def test_run_checks_returns_all_passing(self):
        from docs.paper_2.number_check import default_claims, run_checks
        results = run_checks(default_claims(), RESULTS_ROOT)
        assert all(r.passed for r in results)


class TestBrokenFixture:
    def test_broken_claim_fails(self, tmp_path):
        """Hand-construct a broken claim and verify the checker flags it."""
        from docs.paper_2.number_check import Claim, render_report, run_checks
        broken = (
            Claim(
                label="Intentionally wrong",
                expected=999.0,
                resolver=lambda _root: 0.0,
                tolerance=1e-4,
            ),
        )
        results = run_checks(broken, RESULTS_ROOT)
        assert len(results) == 1
        assert results[0].passed is False
        report = render_report(results)
        assert "FAIL" in report
        assert "✗" in report

    def test_broken_fixture_makes_main_exit_one(self, tmp_path, monkeypatch):
        import docs.paper_2.number_check as nc

        def _fake_claims():
            return (
                nc.Claim(
                    label="Will always fail",
                    expected=42.0,
                    resolver=lambda _root: 0.0,
                    tolerance=1e-6,
                ),
            )

        monkeypatch.setattr(nc, "default_claims", _fake_claims)

        out_report = tmp_path / "report.md"
        code = nc.main([
            "--results-root", str(RESULTS_ROOT),
            "--out-report", str(out_report),
        ])
        assert code == 1

    def test_unresolvable_source_file_flags_error(self, tmp_path):
        """A resolver raising an exception shows up as an error in report."""
        from docs.paper_2.number_check import Claim, run_checks

        def _raises(_root):
            raise FileNotFoundError("no such file")

        broken = (
            Claim(
                label="Missing source",
                expected=1.0,
                resolver=_raises,
                tolerance=1e-4,
            ),
        )
        results = run_checks(broken, tmp_path)
        assert len(results) == 1
        assert results[0].passed is False
        assert "ERROR" in results[0].label


class TestResolvers:
    def test_total_scenarios_is_27(self):
        from docs.paper_2.number_check import _resolve_s048_total_scenarios
        assert _resolve_s048_total_scenarios(RESULTS_ROOT) == 27

    def test_category_counts(self):
        from docs.paper_2.number_check import _resolve_s048_category_count
        assert _resolve_s048_category_count(RESULTS_ROOT, "direct") == 4
        assert _resolve_s048_category_count(RESULTS_ROOT, "framing") == 19
        assert _resolve_s048_category_count(RESULTS_ROOT, "propagation") == 4

    def test_s050_temporal_n_is_5(self):
        from docs.paper_2.number_check import _resolve_s050_family_n
        assert _resolve_s050_family_n(RESULTS_ROOT, "temporal") == 5

    def test_s050_authority_n_is_6(self):
        from docs.paper_2.number_check import _resolve_s050_family_n
        assert _resolve_s050_family_n(RESULTS_ROOT, "authority") == 6

    def test_s050_finding_11_light_ge_0_75(self):
        """A structural sanity check on the Finding-11 md parser."""
        from docs.paper_2.number_check import _resolve_s050_finding_11_light
        value = _resolve_s050_finding_11_light(RESULTS_ROOT)
        assert 0.0 <= value <= 1.0
        assert value >= 0.75  # Session 050 landed at 0.84


class TestDefaultClaims:
    def test_default_claims_non_empty(self):
        from docs.paper_2.number_check import default_claims
        assert len(default_claims()) > 0

    def test_default_claims_all_have_labels(self):
        from docs.paper_2.number_check import default_claims
        for claim in default_claims():
            assert claim.label
            assert callable(claim.resolver)


class TestReportRendering:
    def test_render_report_reflects_counts(self):
        from docs.paper_2.number_check import CheckResult, render_report
        results = (
            CheckResult("A", 1.0, 1.0, 1e-4, True),
            CheckResult("B", 2.0, 3.0, 1e-4, False),
        )
        report = render_report(results)
        assert "1 / 2" in report
        assert "FAIL" in report
        assert "✓" in report
        assert "✗" in report

    def test_all_pass_report_shows_pass(self):
        from docs.paper_2.number_check import CheckResult, render_report
        results = (
            CheckResult("A", 1.0, 1.0, 1e-4, True),
            CheckResult("B", 2.0, 2.0, 1e-4, True),
        )
        report = render_report(results)
        assert "PASS" in report
        assert "2 / 2" in report
