"""Tests for the benchmark report generator."""

from __future__ import annotations

import pytest
from ares.dialectic.scripts.benchmark_report import generate_report
from ares.dialectic.scripts.benchmark_runner import run_benchmark
from ares.dialectic.scripts.scenario_corpus import get_all_scenarios, get_scenario_by_id

ALL_SCENARIOS = get_all_scenarios()


def test_report_generates_string():
    run = run_benchmark(ALL_SCENARIOS, strategy_type="rule_based")
    report = generate_report(run, ALL_SCENARIOS)
    assert isinstance(report, str)
    assert len(report) > 0


def test_report_includes_all_scenario_ids():
    run = run_benchmark(ALL_SCENARIOS, strategy_type="rule_based")
    report = generate_report(run, ALL_SCENARIOS)
    for s in ALL_SCENARIOS:
        assert s.metadata.scenario_id in report


def test_report_includes_run_id():
    run = run_benchmark(ALL_SCENARIOS, strategy_type="rule_based")
    report = generate_report(run, ALL_SCENARIOS)
    assert run.run_id in report


def test_report_includes_strategy_type():
    run = run_benchmark(ALL_SCENARIOS, strategy_type="rule_based")
    report = generate_report(run, ALL_SCENARIOS)
    assert "rule_based" in report


def test_report_single_scenario():
    sc = get_scenario_by_id("SC-001")
    run = run_benchmark([sc], strategy_type="rule_based")
    report = generate_report(run, [sc])
    assert "SC-001" in report


def test_delta_report_generates():
    run1 = run_benchmark(ALL_SCENARIOS, strategy_type="rule_based")
    run2 = run_benchmark(ALL_SCENARIOS, strategy_type="rule_based")
    report = generate_report(run2, ALL_SCENARIOS, baseline_run=run1)
    assert isinstance(report, str)
    assert len(report) > 0


def test_report_flags_verdict_mismatch():
    """Report should flag scenarios where actual != expected."""
    run = run_benchmark(ALL_SCENARIOS, strategy_type="rule_based")
    report = generate_report(run, ALL_SCENARIOS)
    # Report should contain the anomaly flags section
    assert "ANOMALY FLAGS" in report
    assert len(report) > 100


def test_report_includes_aggregate_metrics():
    run = run_benchmark(ALL_SCENARIOS, strategy_type="rule_based")
    report = generate_report(run, ALL_SCENARIOS)
    assert "duration" in report.lower() or "total" in report.lower()


def test_report_includes_fact_coverage():
    run = run_benchmark(ALL_SCENARIOS, strategy_type="rule_based")
    report = generate_report(run, ALL_SCENARIOS)
    assert "coverage" in report.lower()


def test_report_includes_verdict_distribution():
    run = run_benchmark(ALL_SCENARIOS, strategy_type="rule_based")
    report = generate_report(run, ALL_SCENARIOS)
    assert "VERDICT DISTRIBUTION" in report
