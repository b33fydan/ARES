"""Tests for the multi-turn benchmark report generator."""

from __future__ import annotations

import uuid

import pytest
from ares.dialectic.scripts.multi_turn_benchmark import (
    MultiTurnBenchmarkRun,
    MultiTurnScenarioResult,
    RoundSnapshot,
)
from ares.dialectic.scripts.multi_turn_benchmark_report import (
    generate_comparison_report,
    generate_multi_turn_report,
)


# =============================================================================
# Helpers
# =============================================================================


def _make_scenario_result(**overrides):
    """Create a MultiTurnScenarioResult with sensible defaults."""
    defaults = dict(
        scenario_id="SC-001",
        scenario_name="Privilege Escalation",
        expected_verdict="inconclusive",
        verdict_outcome="inconclusive",
        verdict_confidence=0.75,
        architect_confidence=0.8,
        skeptic_confidence=0.3,
        coverage=0.67,
        narrator_output="Test narrative",
        duration_ms=100,
        rounds_used=2,
        max_rounds_configured=3,
        termination_reason="max_turns_exceeded",
        round_snapshots=(
            RoundSnapshot(
                round_number=1,
                architect_confidence=0.8,
                skeptic_confidence=0.3,
                architect_new_fact_count=3,
                skeptic_new_fact_count=2,
                architect_assertion_count=2,
                skeptic_assertion_count=1,
            ),
            RoundSnapshot(
                round_number=2,
                architect_confidence=0.82,
                skeptic_confidence=0.35,
                architect_new_fact_count=1,
                skeptic_new_fact_count=0,
                architect_assertion_count=2,
                skeptic_assertion_count=1,
            ),
        ),
        validation_errors=0,
        fallback_triggers=0,
        token_usage={"input_tokens": 1000, "output_tokens": 500},
        cost_usd=0.01,
    )
    defaults.update(overrides)
    return MultiTurnScenarioResult(**defaults)


def _make_benchmark_run(results=None):
    """Create a MultiTurnBenchmarkRun with sensible defaults."""
    if results is None:
        results = (
            _make_scenario_result(
                scenario_id="SC-001",
                scenario_name="Privilege Escalation",
            ),
            _make_scenario_result(
                scenario_id="SC-002",
                scenario_name="Process Chain Attack",
                verdict_outcome="threat_confirmed",
                expected_verdict="threat_confirmed",
                rounds_used=3,
                termination_reason="confidence_stabilized",
            ),
        )
    return MultiTurnBenchmarkRun(
        run_id=str(uuid.uuid4()),
        timestamp="2026-03-04T00:00:00",
        strategy_type="multi_turn_llm",
        max_rounds=3,
        confidence_delta=0.05,
        require_new_evidence=True,
        scenario_count=len(results),
        results=results,
        total_cost_usd=sum(r.cost_usd for r in results),
        total_duration_ms=sum(r.duration_ms for r in results),
    )


def _make_single_turn_run(results=None):
    """Create a mock single-turn BenchmarkRun-like object."""
    from ares.dialectic.scripts.benchmark_runner import BenchmarkRun, ScenarioResult
    from datetime import datetime

    if results is None:
        results = (
            ScenarioResult(
                scenario_id="SC-001",
                strategy_type="llm",
                verdict_outcome="inconclusive",
                verdict_confidence=0.70,
                architect_confidence=0.75,
                skeptic_confidence=0.35,
                architect_assertion_count=2,
                skeptic_assertion_count=1,
                architect_fact_ids_cited=frozenset({"f-1", "f-2"}),
                skeptic_fact_ids_cited=frozenset({"f-1"}),
                total_facts_available=5,
                fact_coverage_ratio=0.40,
                validation_errors=0,
                fallback_triggers=0,
                duration_ms=50,
                token_usage={"input_tokens": 500, "output_tokens": 200},
                cost_usd=0.005,
                narrator_output="Single-turn narrative",
            ),
            ScenarioResult(
                scenario_id="SC-002",
                strategy_type="llm",
                verdict_outcome="threat_confirmed",
                verdict_confidence=0.85,
                architect_confidence=0.90,
                skeptic_confidence=0.25,
                architect_assertion_count=3,
                skeptic_assertion_count=2,
                architect_fact_ids_cited=frozenset({"f-1", "f-2", "f-3"}),
                skeptic_fact_ids_cited=frozenset({"f-1"}),
                total_facts_available=6,
                fact_coverage_ratio=0.50,
                validation_errors=0,
                fallback_triggers=0,
                duration_ms=60,
                token_usage={"input_tokens": 600, "output_tokens": 300},
                cost_usd=0.006,
                narrator_output="Single-turn narrative",
            ),
        )

    return BenchmarkRun(
        run_id=str(uuid.uuid4()),
        timestamp=datetime.utcnow(),
        strategy_type="llm",
        scenario_count=len(results),
        results=results,
        total_duration_ms=sum(r.duration_ms for r in results),
        total_cost_usd=sum(r.cost_usd for r in results if r.cost_usd),
    )


# =============================================================================
# Multi-turn report tests
# =============================================================================


def test_generate_multi_turn_report_returns_string():
    """Report generates a non-empty string."""
    run = _make_benchmark_run()
    report = generate_multi_turn_report(run)
    assert isinstance(report, str)
    assert len(report) > 0


def test_generate_multi_turn_report_includes_scenario_names():
    """Report includes scenario names."""
    run = _make_benchmark_run()
    report = generate_multi_turn_report(run)
    assert "Privilege Escalation" in report
    assert "Process Chain Attack" in report


def test_generate_multi_turn_report_includes_rounds_used():
    """Report includes rounds used per scenario."""
    run = _make_benchmark_run()
    report = generate_multi_turn_report(run)
    # Should show average rounds and per-scenario rounds
    assert "Rounds" in report or "rounds" in report


def test_generate_multi_turn_report_includes_termination_reasons():
    """Report includes termination reason distribution."""
    run = _make_benchmark_run()
    report = generate_multi_turn_report(run)
    assert "TERMINATION REASON" in report
    assert "max_turns_exceeded" in report


def test_generate_multi_turn_report_includes_round_snapshots():
    """Report includes round snapshot evolution section."""
    run = _make_benchmark_run()
    report = generate_multi_turn_report(run)
    assert "ROUND SNAPSHOT" in report
    assert "Round 1" in report
    assert "Round 2" in report


def test_generate_multi_turn_report_includes_aggregate_metrics():
    """Report includes aggregate metrics section."""
    run = _make_benchmark_run()
    report = generate_multi_turn_report(run)
    assert "AGGREGATE METRICS" in report
    assert "match rate" in report.lower() or "Match" in report


def test_generate_multi_turn_report_includes_anomaly_flags():
    """Report includes anomaly flags section."""
    run = _make_benchmark_run()
    report = generate_multi_turn_report(run)
    assert "ANOMALY FLAGS" in report


# =============================================================================
# Comparison report tests
# =============================================================================


def test_generate_comparison_report_returns_string():
    """Comparison report generates a non-empty string."""
    st_run = _make_single_turn_run()
    mt_run = _make_benchmark_run()
    report = generate_comparison_report(st_run, mt_run)
    assert isinstance(report, str)
    assert len(report) > 0


def test_generate_comparison_report_includes_both_match_rates():
    """Comparison report shows both single-turn and multi-turn match rates."""
    st_run = _make_single_turn_run()
    mt_run = _make_benchmark_run()
    report = generate_comparison_report(st_run, mt_run)
    assert "Single-turn" in report
    assert "Multi-turn" in report


def test_generate_comparison_report_includes_cost_delta():
    """Comparison report shows cost comparison."""
    st_run = _make_single_turn_run()
    mt_run = _make_benchmark_run()
    report = generate_comparison_report(st_run, mt_run)
    assert "Cost" in report or "cost" in report


def test_generate_comparison_report_handles_mismatched_scenarios():
    """Comparison report handles when runs have different scenario sets."""
    # Single-turn has SC-001 and SC-002
    st_run = _make_single_turn_run()
    # Multi-turn has only SC-001
    mt_run = _make_benchmark_run(
        results=(
            _make_scenario_result(scenario_id="SC-001"),
        ),
    )
    report = generate_comparison_report(st_run, mt_run)
    assert isinstance(report, str)
    assert "SC-001" in report
    assert "SC-002" in report  # Should still appear from ST side


def test_generate_comparison_report_includes_per_scenario_table():
    """Comparison report includes per-scenario verdict comparison."""
    st_run = _make_single_turn_run()
    mt_run = _make_benchmark_run()
    report = generate_comparison_report(st_run, mt_run)
    assert "SC-001" in report
    assert "SC-002" in report
    assert "COMPARISON" in report
