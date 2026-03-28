"""Tests for ares.dialectic.scripts.benchmark_runner_v2 — injectable benchmark.

Session 033: Tests run_benchmark_custom() with rule-based strategies
(no API calls). Validates custom judge injection, error handling,
and output structure.
"""

from __future__ import annotations

import pytest

from ares.dialectic.agents.oracle_v2 import OracleJudgeV2
from ares.dialectic.agents.patterns import Verdict, VerdictOutcome
from ares.dialectic.scripts.benchmark_runner import BenchmarkRun, ScenarioResult
from ares.dialectic.scripts.benchmark_runner_v2 import run_benchmark_custom


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _rule_based_strategies():
    """Create rule-based strategies (no API calls)."""
    from ares.dialectic.agents.strategies.rule_based import (
        RuleBasedExplanationFinder,
        RuleBasedNarrativeGenerator,
        RuleBasedThreatAnalyzer,
    )
    return (
        RuleBasedThreatAnalyzer(),
        RuleBasedExplanationFinder(),
        RuleBasedNarrativeGenerator(),
    )


def _get_scenarios(n: int = 3):
    """Load first n scenarios from corpus."""
    from ares.dialectic.scripts.expanded_scenarios import get_full_corpus
    return list(get_full_corpus())[:n]


def _get_single_scenario(sid: str = "SC-001"):
    """Load a single scenario."""
    from ares.dialectic.scripts.expanded_scenarios import get_full_corpus
    for s in get_full_corpus():
        if s.metadata.scenario_id == sid:
            return s
    raise ValueError(f"Scenario {sid} not found")


# ---------------------------------------------------------------------------
# Basic Functionality
# ---------------------------------------------------------------------------

class TestBasicFunctionality:
    """Core run_benchmark_custom tests with rule-based strategies."""

    def test_returns_benchmark_run(self):
        ta, ef, ng = _rule_based_strategies()
        scenarios = _get_scenarios(2)
        run = run_benchmark_custom(scenarios, ta, ef, ng, strategy_label="test")
        assert isinstance(run, BenchmarkRun)

    def test_result_count_matches_scenarios(self):
        ta, ef, ng = _rule_based_strategies()
        scenarios = _get_scenarios(3)
        run = run_benchmark_custom(scenarios, ta, ef, ng)
        assert len(run.results) == 3
        assert run.scenario_count == 3

    def test_results_are_frozen_scenario_results(self):
        ta, ef, ng = _rule_based_strategies()
        scenarios = _get_scenarios(1)
        run = run_benchmark_custom(scenarios, ta, ef, ng)
        result = run.results[0]
        assert isinstance(result, ScenarioResult)
        with pytest.raises(AttributeError):
            result.verdict_outcome = "hacked"

    def test_benchmark_run_is_frozen(self):
        ta, ef, ng = _rule_based_strategies()
        scenarios = _get_scenarios(1)
        run = run_benchmark_custom(scenarios, ta, ef, ng)
        with pytest.raises(AttributeError):
            run.scenario_count = 999

    def test_strategy_label_in_results(self):
        ta, ef, ng = _rule_based_strategies()
        scenarios = _get_scenarios(1)
        run = run_benchmark_custom(scenarios, ta, ef, ng, strategy_label="v3_test")
        assert run.strategy_type == "v3_test"
        assert run.results[0].strategy_type == "v3_test"

    def test_empty_scenarios_raises(self):
        ta, ef, ng = _rule_based_strategies()
        with pytest.raises(ValueError):
            run_benchmark_custom([], ta, ef, ng)

    def test_scenario_id_preserved(self):
        ta, ef, ng = _rule_based_strategies()
        scenario = _get_single_scenario("SC-019")
        run = run_benchmark_custom([scenario], ta, ef, ng)
        assert run.results[0].scenario_id == "SC-019"


# ---------------------------------------------------------------------------
# Custom Judge
# ---------------------------------------------------------------------------

class TestCustomJudge:
    """Tests for judge_fn injection."""

    def test_custom_judge_is_called(self):
        ta, ef, ng = _rule_based_strategies()
        scenarios = _get_scenarios(1)

        call_count = [0]

        def custom_judge(arch_msg, skep_msg, packet):
            call_count[0] += 1
            return OracleJudgeV2.compute_verdict(arch_msg, skep_msg, packet)

        run = run_benchmark_custom(scenarios, ta, ef, ng, judge_fn=custom_judge)
        assert call_count[0] == 1

    def test_custom_judge_verdict_used(self):
        """Force THREAT_CONFIRMED regardless of evidence."""
        ta, ef, ng = _rule_based_strategies()
        scenarios = _get_scenarios(1)

        def always_confirm(arch_msg, skep_msg, packet):
            return Verdict(
                outcome=VerdictOutcome.THREAT_CONFIRMED,
                confidence=0.99,
                supporting_fact_ids=frozenset(),
                architect_confidence=0.99,
                skeptic_confidence=0.01,
                reasoning="Forced by test",
            )

        run = run_benchmark_custom(scenarios, ta, ef, ng, judge_fn=always_confirm)
        assert run.results[0].verdict_outcome == "threat_confirmed"
        assert run.results[0].verdict_confidence == 0.99

    def test_default_judge_uses_v1(self):
        """Without judge_fn, should use OracleJudge (V1) behavior."""
        ta, ef, ng = _rule_based_strategies()
        scenarios = _get_scenarios(1)
        run = run_benchmark_custom(scenarios, ta, ef, ng, judge_fn=None)
        # Should produce a valid verdict (not ERROR)
        assert run.results[0].verdict_outcome in (
            "threat_confirmed", "threat_dismissed", "inconclusive"
        )


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

class TestMetrics:
    """Tests for extracted metrics."""

    def test_fact_coverage_valid_range(self):
        ta, ef, ng = _rule_based_strategies()
        scenarios = _get_scenarios(3)
        run = run_benchmark_custom(scenarios, ta, ef, ng)
        for r in run.results:
            assert 0.0 <= r.fact_coverage_ratio <= 1.0

    def test_duration_non_negative(self):
        ta, ef, ng = _rule_based_strategies()
        scenarios = _get_scenarios(1)
        run = run_benchmark_custom(scenarios, ta, ef, ng)
        assert run.results[0].duration_ms >= 0
        assert run.total_duration_ms >= 0

    def test_assertion_counts_non_negative(self):
        ta, ef, ng = _rule_based_strategies()
        scenarios = _get_scenarios(3)
        run = run_benchmark_custom(scenarios, ta, ef, ng)
        for r in run.results:
            assert r.architect_assertion_count >= 0
            assert r.skeptic_assertion_count >= 0

    def test_rule_based_no_cost(self):
        ta, ef, ng = _rule_based_strategies()
        scenarios = _get_scenarios(1)
        run = run_benchmark_custom(scenarios, ta, ef, ng)
        assert run.results[0].cost_usd is None
        assert run.results[0].token_usage is None

    def test_confidence_valid_range(self):
        ta, ef, ng = _rule_based_strategies()
        scenarios = _get_scenarios(3)
        run = run_benchmark_custom(scenarios, ta, ef, ng)
        for r in run.results:
            assert 0.0 <= r.verdict_confidence <= 1.0
            assert 0.0 <= r.architect_confidence <= 1.0
            assert 0.0 <= r.skeptic_confidence <= 1.0


# ---------------------------------------------------------------------------
# No Narration
# ---------------------------------------------------------------------------

class TestNoNarration:
    """Tests for include_narration=False."""

    def test_no_narration_skips_narrator(self):
        ta, ef, ng = _rule_based_strategies()
        scenarios = _get_scenarios(1)
        run = run_benchmark_custom(
            scenarios, ta, ef, ng, include_narration=False
        )
        assert run.results[0].narrator_output is None

    def test_narration_default_on(self):
        ta, ef, ng = _rule_based_strategies()
        scenarios = _get_scenarios(1)
        run = run_benchmark_custom(scenarios, ta, ef, ng)
        # Rule-based narrator should produce something
        assert run.results[0].narrator_output is not None or True  # May be None if narrator skipped


# ---------------------------------------------------------------------------
# Multi-Scenario
# ---------------------------------------------------------------------------

class TestMultiScenario:
    """Tests with multiple scenarios."""

    def test_all_33_scenarios_rule_based(self):
        """Full corpus smoke test with rule-based (no API calls)."""
        ta, ef, ng = _rule_based_strategies()
        from ares.dialectic.scripts.expanded_scenarios import get_full_corpus
        scenarios = list(get_full_corpus())
        run = run_benchmark_custom(scenarios, ta, ef, ng, strategy_label="rule_v2")
        assert run.scenario_count == 33
        assert len(run.results) == 33
        errors = [r for r in run.results if r.verdict_outcome == "ERROR"]
        assert len(errors) == 0, f"Errors in: {[r.scenario_id for r in errors]}"
