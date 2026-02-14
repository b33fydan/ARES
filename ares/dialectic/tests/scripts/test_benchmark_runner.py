"""Tests for the benchmark runner — execution, metrics, and validation."""

from __future__ import annotations

import uuid

import pytest
from ares.dialectic.scripts.benchmark_runner import (
    BenchmarkRun,
    ScenarioResult,
    run_benchmark,
)
from ares.dialectic.scripts.scenario_corpus import get_all_scenarios, get_scenario_by_id

ALL_SCENARIOS = get_all_scenarios()


def test_run_benchmark_returns_benchmark_run():
    run = run_benchmark(ALL_SCENARIOS, strategy_type="rule_based")
    assert isinstance(run, BenchmarkRun)


def test_run_benchmark_correct_scenario_count():
    run = run_benchmark(ALL_SCENARIOS, strategy_type="rule_based")
    assert run.scenario_count == 12
    assert len(run.results) == 12


def test_all_results_are_frozen():
    run = run_benchmark(ALL_SCENARIOS, strategy_type="rule_based")
    for r in run.results:
        assert isinstance(r, ScenarioResult)
        with pytest.raises(AttributeError):
            r.scenario_id = "tampered"


def test_benchmark_run_is_frozen():
    run = run_benchmark(ALL_SCENARIOS, strategy_type="rule_based")
    with pytest.raises(AttributeError):
        run.run_id = "tampered"


def test_rule_based_has_no_token_usage():
    run = run_benchmark(ALL_SCENARIOS, strategy_type="rule_based")
    for r in run.results:
        assert r.token_usage is None
        assert r.cost_usd is None


def test_rule_based_has_no_validation_errors():
    run = run_benchmark(ALL_SCENARIOS, strategy_type="rule_based")
    for r in run.results:
        assert r.validation_errors == 0
        assert r.fallback_triggers == 0


def test_fact_coverage_ratio_valid_range():
    run = run_benchmark(ALL_SCENARIOS, strategy_type="rule_based")
    for r in run.results:
        assert 0.0 <= r.fact_coverage_ratio <= 1.0


def test_duration_non_negative():
    run = run_benchmark(ALL_SCENARIOS, strategy_type="rule_based")
    for r in run.results:
        assert r.duration_ms >= 0
    assert run.total_duration_ms >= 0


def test_strategy_type_recorded():
    run = run_benchmark(ALL_SCENARIOS, strategy_type="rule_based")
    assert run.strategy_type == "rule_based"
    for r in run.results:
        assert r.strategy_type == "rule_based"


def test_run_id_is_uuid_format():
    run = run_benchmark(ALL_SCENARIOS, strategy_type="rule_based")
    uuid.UUID(run.run_id)  # Raises ValueError if not valid UUID


def test_empty_scenarios_raises():
    with pytest.raises(ValueError):
        run_benchmark([], strategy_type="rule_based")


def test_invalid_strategy_type_raises():
    with pytest.raises(ValueError):
        run_benchmark(ALL_SCENARIOS, strategy_type="invalid")


def test_llm_without_client_raises():
    with pytest.raises(ValueError):
        run_benchmark(ALL_SCENARIOS, strategy_type="llm", client=None)


def test_single_scenario_runs():
    sc = get_scenario_by_id("SC-001")
    run = run_benchmark([sc], strategy_type="rule_based")
    assert run.scenario_count == 1
    assert len(run.results) == 1
    assert run.results[0].scenario_id == "SC-001"


def test_verdict_outcome_is_string():
    run = run_benchmark(ALL_SCENARIOS, strategy_type="rule_based")
    valid = {"threat_confirmed", "threat_dismissed", "inconclusive"}
    for r in run.results:
        assert r.verdict_outcome in valid


def test_narrator_output_present_when_included():
    run = run_benchmark(
        ALL_SCENARIOS, strategy_type="rule_based", include_narration=True
    )
    for r in run.results:
        assert r.narrator_output is not None


def test_narrator_output_none_when_excluded():
    run = run_benchmark(
        ALL_SCENARIOS, strategy_type="rule_based", include_narration=False
    )
    for r in run.results:
        assert r.narrator_output is None


def test_architect_and_skeptic_confidence_valid():
    run = run_benchmark(ALL_SCENARIOS, strategy_type="rule_based")
    for r in run.results:
        assert 0.0 <= r.architect_confidence <= 1.0
        assert 0.0 <= r.skeptic_confidence <= 1.0


def test_assertion_counts_non_negative():
    run = run_benchmark(ALL_SCENARIOS, strategy_type="rule_based")
    for r in run.results:
        assert r.architect_assertion_count >= 0
        assert r.skeptic_assertion_count >= 0


def test_total_cost_none_for_rule_based():
    run = run_benchmark(ALL_SCENARIOS, strategy_type="rule_based")
    assert run.total_cost_usd is None
