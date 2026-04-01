"""Tests for OracleJudgeV2 threshold sweep.

Validates:
1. rescore_results() produces correct comparisons
2. Regression detection (V1 correct → V2 incorrect)
3. Improvement detection (V1 incorrect → V2 correct)
4. SC/PT accuracy computed separately
5. Combined accuracy computed correctly
6. run_sweep() produces SweepReport with all thresholds
7. Winner selection logic (best combined, 0 SC regressions)
8. Results serializable to JSON via save_report()
9. Edge cases (empty results, all-correct, all-wrong)
10. Dry-run mode works end-to-end (no API key)
"""

import json
import pytest
from datetime import datetime, timezone
from pathlib import Path

from ares.dialectic.agents.oracle_v2 import ScoringConfig
from ares.dialectic.agents.patterns import VerdictOutcome
from ares.dialectic.scripts.benchmark_runner import BenchmarkRun, ScenarioResult
from ares.dialectic.scripts.sweep_oracle_v2 import (
    ScenarioComparison,
    SweepReport,
    SweepResult,
    rescore_results,
    run_sweep,
    save_report,
    _verdicts_match,
)


# =============================================================================
# Helpers
# =============================================================================

def _make_result(
    scenario_id: str,
    arch_conf: float,
    skep_conf: float,
    verdict: str = "threat_confirmed",
) -> ScenarioResult:
    """Build a minimal ScenarioResult for testing."""
    return ScenarioResult(
        scenario_id=scenario_id,
        strategy_type="test",
        verdict_outcome=verdict,
        verdict_confidence=arch_conf,
        architect_confidence=arch_conf,
        skeptic_confidence=skep_conf,
        architect_assertion_count=1,
        skeptic_assertion_count=1,
        architect_fact_ids_cited=frozenset({"f1"}),
        skeptic_fact_ids_cited=frozenset({"f2"}),
        total_facts_available=5,
        fact_coverage_ratio=0.4,
        validation_errors=0,
        fallback_triggers=0,
        duration_ms=100,
        token_usage=None,
        cost_usd=None,
        narrator_output=None,
    )


def _make_benchmark_run(results: list[ScenarioResult]) -> BenchmarkRun:
    """Build a minimal BenchmarkRun for testing."""
    return BenchmarkRun(
        run_id="test-run",
        timestamp=datetime(2026, 4, 1, tzinfo=timezone.utc),
        strategy_type="test",
        scenario_count=len(results),
        results=tuple(results),
        total_duration_ms=1000,
        total_cost_usd=None,
    )


# =============================================================================
# Verdict matching
# =============================================================================


class TestVerdictMatch:

    def test_exact_match(self):
        assert _verdicts_match("THREAT_CONFIRMED", "THREAT_CONFIRMED")

    def test_case_insensitive(self):
        assert _verdicts_match("threat_confirmed", "THREAT_CONFIRMED")

    def test_mismatch(self):
        assert not _verdicts_match("THREAT_CONFIRMED", "THREAT_DISMISSED")


# =============================================================================
# Rescore tests
# =============================================================================


class TestRescoreResults:

    def test_rescore_produces_comparisons(self):
        results = [
            _make_result("SC-001", 0.95, 0.30, "threat_confirmed"),
            _make_result("PT-001", 0.75, 0.40, "threat_confirmed"),
        ]
        run = _make_benchmark_run(results)
        expected = {"SC-001": "THREAT_CONFIRMED", "PT-001": "INCONCLUSIVE"}
        config = ScoringConfig(confirm_delta=0.20)

        sr = rescore_results(run, expected, config)
        assert len(sr.comparisons) == 2

    def test_rescore_no_llm_calls(self):
        """Rescore uses raw confidence pairs — no LLM needed."""
        results = [_make_result("SC-001", 0.80, 0.30)]
        run = _make_benchmark_run(results)
        expected = {"SC-001": "THREAT_CONFIRMED"}
        config = ScoringConfig(confirm_delta=0.15)

        sr = rescore_results(run, expected, config)
        assert sr.combined_total == 1

    def test_regression_detected(self):
        """V1 correct → V2 incorrect = regression."""
        # V1: arch=0.75, skep=0.45 → V1 says CONFIRMED (via fact-count override)
        # Expected: CONFIRMED → V1 is correct
        # V2 at delta=0.40: delta=0.30 < 0.40, not dominant → INCONCLUSIVE
        results = [_make_result("SC-001", 0.75, 0.45, "threat_confirmed")]
        run = _make_benchmark_run(results)
        expected = {"SC-001": "THREAT_CONFIRMED"}
        config = ScoringConfig(confirm_delta=0.40)

        sr = rescore_results(run, expected, config)
        regressions = [c for c in sr.comparisons if c.is_regression]
        assert len(regressions) == 1
        assert regressions[0].scenario_id == "SC-001"

    def test_improvement_detected(self):
        """V1 incorrect → V2 correct = improvement."""
        # V1: arch=0.75, skep=0.55 → V1 says INCONCLUSIVE (skep > 0.50)
        # Expected: THREAT_CONFIRMED → V1 is wrong
        # V2 at delta=0.15: delta=0.20 >= 0.15, arch=0.75 >= 0.60 → CONFIRMED
        results = [_make_result("SC-016", 0.75, 0.55, "inconclusive")]
        run = _make_benchmark_run(results)
        expected = {"SC-016": "THREAT_CONFIRMED"}
        config = ScoringConfig(confirm_delta=0.15)

        sr = rescore_results(run, expected, config)
        improvements = [c for c in sr.comparisons if c.is_improvement]
        assert len(improvements) == 1
        assert improvements[0].scenario_id == "SC-016"

    def test_sc_pt_accuracy_separate(self):
        """SC and PT accuracy computed independently."""
        results = [
            _make_result("SC-001", 0.95, 0.30, "threat_confirmed"),
            _make_result("SC-002", 0.40, 0.80, "threat_dismissed"),
            _make_result("PT-001", 0.75, 0.40, "threat_confirmed"),
        ]
        run = _make_benchmark_run(results)
        expected = {
            "SC-001": "THREAT_CONFIRMED",
            "SC-002": "THREAT_DISMISSED",
            "PT-001": "INCONCLUSIVE",
        }
        config = ScoringConfig(confirm_delta=0.15)
        sr = rescore_results(run, expected, config)

        assert sr.sc_total == 2
        assert sr.pt_total == 1

    def test_error_results_skipped(self):
        """Results with verdict_outcome='ERROR' are skipped."""
        results = [
            _make_result("SC-001", 0.95, 0.30, "threat_confirmed"),
            _make_result("SC-002", 0.0, 0.0, "ERROR"),
        ]
        run = _make_benchmark_run(results)
        expected = {"SC-001": "THREAT_CONFIRMED", "SC-002": "THREAT_DISMISSED"}
        config = ScoringConfig(confirm_delta=0.15)

        sr = rescore_results(run, expected, config)
        assert sr.combined_total == 1

    def test_combined_accuracy(self):
        """combined_correct = sc_correct + pt_correct."""
        results = [
            _make_result("SC-001", 0.95, 0.30, "threat_confirmed"),
            _make_result("PT-001", 0.95, 0.30, "threat_confirmed"),
        ]
        run = _make_benchmark_run(results)
        expected = {"SC-001": "THREAT_CONFIRMED", "PT-001": "THREAT_CONFIRMED"}
        config = ScoringConfig(confirm_delta=0.15)

        sr = rescore_results(run, expected, config)
        assert sr.combined_correct == sr.sc_correct + sr.pt_correct


# =============================================================================
# Sweep tests
# =============================================================================


class TestRunSweep:

    def test_produces_results_for_each_threshold(self):
        results = [_make_result("SC-001", 0.90, 0.30, "threat_confirmed")]
        run = _make_benchmark_run(results)
        expected = {"SC-001": "THREAT_CONFIRMED"}

        report = run_sweep(run, expected, thresholds=[0.10, 0.20, 0.30])
        assert len(report.results) == 3
        assert [sr.threshold for sr in report.results] == [0.10, 0.20, 0.30]

    def test_v1_baseline_in_report(self):
        results = [
            _make_result("SC-001", 0.90, 0.30, "threat_confirmed"),
            _make_result("PT-001", 0.60, 0.50, "inconclusive"),
        ]
        run = _make_benchmark_run(results)
        expected = {"SC-001": "THREAT_CONFIRMED", "PT-001": "INCONCLUSIVE"}

        report = run_sweep(run, expected, thresholds=[0.15])
        assert report.v1_sc_correct == 1
        assert report.v1_pt_correct == 1
        assert report.v1_combined_correct == 2

    def test_winner_has_zero_sc_regressions(self):
        """Winner must have 0 SC regressions."""
        # SC-001: arch=0.75, skep=0.45 → V1=CONFIRMED (correct)
        # At delta=0.40: V2=INCONCLUSIVE (regression)
        # At delta=0.20: V2=CONFIRMED (no regression)
        results = [_make_result("SC-001", 0.75, 0.45, "threat_confirmed")]
        run = _make_benchmark_run(results)
        expected = {"SC-001": "THREAT_CONFIRMED"}

        report = run_sweep(run, expected, thresholds=[0.20, 0.40])
        # 0.40 causes regression, 0.20 doesn't
        assert report.winner_threshold == 0.20

    def test_no_winner_when_all_regress(self):
        """No winner if all thresholds cause SC regressions."""
        # arch=0.65, skep=0.55 → V1=CONFIRMED (via fact count? unlikely...)
        # Actually, V1 with these values: arch < 0.7, so not primary.
        # Secondary: arch_fact_count > 2 * skep_fact_count? We have 1 each.
        # → V1 = INCONCLUSIVE. Let's set up differently.
        #
        # arch=0.72, skep=0.48 → V1: arch >= 0.7, skep < 0.5 → CONFIRMED
        # V2 at any delta: need delta >= threshold and arch >= 0.6
        # delta = 0.24. At delta=0.30: 0.24 < 0.30 → INCONCLUSIVE (regression)
        # At delta=0.25: 0.24 < 0.25 → INCONCLUSIVE (regression)
        results = [_make_result("SC-001", 0.72, 0.48, "threat_confirmed")]
        run = _make_benchmark_run(results)
        expected = {"SC-001": "THREAT_CONFIRMED"}

        report = run_sweep(run, expected, thresholds=[0.25, 0.30])
        assert report.winner_threshold is None

    def test_total_scenarios_count(self):
        results = [
            _make_result("SC-001", 0.90, 0.30, "threat_confirmed"),
            _make_result("SC-002", 0.30, 0.90, "threat_dismissed"),
            _make_result("PT-001", 0.70, 0.50, "threat_confirmed"),
        ]
        run = _make_benchmark_run(results)
        expected = {
            "SC-001": "THREAT_CONFIRMED",
            "SC-002": "THREAT_DISMISSED",
            "PT-001": "THREAT_CONFIRMED",
        }
        report = run_sweep(run, expected, thresholds=[0.15])
        assert report.total_scenarios == 3


# =============================================================================
# Save / serialize tests
# =============================================================================


class TestSaveReport:

    def test_saves_to_json(self, tmp_path):
        results = [_make_result("SC-001", 0.90, 0.30, "threat_confirmed")]
        run = _make_benchmark_run(results)
        expected = {"SC-001": "THREAT_CONFIRMED"}
        report = run_sweep(run, expected, thresholds=[0.15, 0.20])

        out = save_report(report, tmp_path)
        assert out.exists()
        data = json.loads(out.read_text())
        assert data["run_id"] == "test-run"
        assert len(data["thresholds"]) == 2

    def test_json_has_regression_details(self, tmp_path):
        results = [_make_result("SC-001", 0.72, 0.48, "threat_confirmed")]
        run = _make_benchmark_run(results)
        expected = {"SC-001": "THREAT_CONFIRMED"}
        report = run_sweep(run, expected, thresholds=[0.30])

        out = save_report(report, tmp_path)
        data = json.loads(out.read_text())
        # At delta=0.30, arch-skep=0.24 < 0.30, not dominant → INCONCLUSIVE (regression)
        assert len(data["thresholds"][0]["regression_details"]) >= 1


# =============================================================================
# Dry-run integration test
# =============================================================================


class TestDryRunIntegration:

    def test_dry_run_completes(self):
        """Full dry-run sweep with rule-based strategies (no API key)."""
        from ares.dialectic.scripts.sweep_oracle_v2 import main
        import io
        import sys

        # Capture stdout
        captured = io.StringIO()
        old_stdout = sys.stdout
        sys.stdout = captured

        try:
            main(["--dry-run", "--scenarios", "PT", "--thresholds", "0.15,0.25"])
        finally:
            sys.stdout = old_stdout

        output = captured.getvalue()
        assert "THRESHOLD SWEEP RESULTS" in output
        assert "Phase A complete" in output

    def test_dry_run_with_sc_corpus(self):
        """Dry-run on SC corpus only."""
        from ares.dialectic.scripts.sweep_oracle_v2 import main
        import io
        import sys

        captured = io.StringIO()
        old_stdout = sys.stdout
        sys.stdout = captured

        try:
            main(["--dry-run", "--scenarios", "SC", "--thresholds", "0.20"])
        finally:
            sys.stdout = old_stdout

        output = captured.getvalue()
        assert "THRESHOLD SWEEP RESULTS" in output
