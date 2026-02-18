"""Tests for the benchmark runner — execution, metrics, and validation."""

from __future__ import annotations

import uuid
from unittest.mock import MagicMock, patch

import pytest
from ares.dialectic.agents.strategies.observability import LLMCallLogger, LLMCallRecord
from ares.dialectic.scripts.benchmark_runner import (
    BenchmarkRun,
    ScenarioResult,
    _extract_llm_metrics,
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


# =============================================================================
# Session 012 — call_logger wiring, LLM metrics, per-scenario error handling
# =============================================================================


def _make_mock_cycle_result():
    """Create a minimal mock CycleResult for benchmark runner tests."""
    mock = MagicMock()
    mock.architect_message.get_all_fact_ids.return_value = frozenset({"f-1"})
    mock.architect_message.assertions = []
    mock.skeptic_message.get_all_fact_ids.return_value = frozenset({"f-1"})
    mock.skeptic_message.assertions = []
    mock.narrator_message = None
    mock.verdict.outcome.value = "threat_confirmed"
    mock.verdict.confidence = 0.8
    mock.verdict.architect_confidence = 0.9
    mock.verdict.skeptic_confidence = 0.3
    return mock


def _make_call_record(**overrides):
    """Create an LLMCallRecord with sensible defaults."""
    defaults = dict(
        timestamp="2026-02-18T00:00:00+00:00",
        strategy_type="ThreatAnalyzer",
        model="claude-sonnet-4-20250514",
        system_prompt="test",
        user_prompt="test",
        raw_response="[]",
        parsed_result=[],
        validated_result=[],
        validation_errors=(),
        fallback_used=False,
        fallback_reason=None,
        input_tokens=100,
        output_tokens=50,
        latency_ms=100.0,
        error=None,
    )
    defaults.update(overrides)
    return LLMCallRecord(**defaults)


# --- 4.1 call_logger wiring tests ---


@patch("ares.dialectic.scripts.benchmark_runner.run_cycle_with_strategies")
def test_llm_strategies_receive_call_logger(mock_run):
    """LLM strategy constructors receive the call_logger argument."""
    mock_run.return_value = _make_mock_cycle_result()
    call_logger = LLMCallLogger()
    client = MagicMock()
    sc = get_scenario_by_id("SC-001")

    run_benchmark([sc], strategy_type="llm", client=client, call_logger=call_logger)

    # Inspect the strategies passed to run_cycle_with_strategies
    call_kwargs = mock_run.call_args.kwargs
    assert call_kwargs["threat_analyzer"]._call_logger is call_logger
    assert call_kwargs["explanation_finder"]._call_logger is call_logger
    assert call_kwargs["narrative_generator"]._call_logger is call_logger


@patch("ares.dialectic.scripts.benchmark_runner.run_cycle_with_strategies")
def test_llm_results_have_token_usage_and_cost(mock_run):
    """LLM results populate token_usage and cost_usd from call_logger records."""
    call_logger = LLMCallLogger()
    client = MagicMock()
    sc = get_scenario_by_id("SC-001")

    def side_effect(**kwargs):
        call_logger.record(_make_call_record(
            strategy_type="ThreatAnalyzer",
            input_tokens=1000, output_tokens=500,
        ))
        call_logger.record(_make_call_record(
            strategy_type="ExplanationFinder",
            input_tokens=800, output_tokens=400,
        ))
        call_logger.record(_make_call_record(
            strategy_type="NarrativeGenerator",
            input_tokens=600, output_tokens=300,
        ))
        return _make_mock_cycle_result()

    mock_run.side_effect = side_effect
    run = run_benchmark(
        [sc], strategy_type="llm", client=client, call_logger=call_logger,
    )

    result = run.results[0]
    assert result.token_usage is not None
    assert result.token_usage["input_tokens"] == 2400
    assert result.token_usage["output_tokens"] == 1200
    assert result.cost_usd is not None
    assert result.cost_usd > 0


@patch("ares.dialectic.scripts.benchmark_runner.run_cycle_with_strategies")
def test_total_cost_usd_aggregates_per_scenario(mock_run):
    """BenchmarkRun.total_cost_usd sums per-scenario costs."""
    call_logger = LLMCallLogger()
    client = MagicMock()

    def side_effect(**kwargs):
        call_logger.record(
            _make_call_record(input_tokens=1_000_000, output_tokens=0),
        )
        return _make_mock_cycle_result()

    mock_run.side_effect = side_effect

    scenarios = [get_scenario_by_id("SC-001"), get_scenario_by_id("SC-002")]
    run = run_benchmark(
        scenarios, strategy_type="llm", client=client, call_logger=call_logger,
    )

    assert run.total_cost_usd is not None
    # Each scenario: 1M input tokens * $3/MTok = $3.00
    assert abs(run.total_cost_usd - 6.0) < 0.01


@patch("ares.dialectic.scripts.benchmark_runner.run_cycle_with_strategies")
def test_llm_metrics_include_validation_errors_and_fallbacks(mock_run):
    """LLM metrics extract validation_errors and fallback_triggers from records."""
    call_logger = LLMCallLogger()
    client = MagicMock()
    sc = get_scenario_by_id("SC-001")

    def side_effect(**kwargs):
        call_logger.record(_make_call_record(
            validation_errors=("hallucinated fact_id",),
            fallback_used=True,
        ))
        call_logger.record(_make_call_record(
            validation_errors=("bad type", "empty"),
            fallback_used=False,
        ))
        return _make_mock_cycle_result()

    mock_run.side_effect = side_effect
    run = run_benchmark(
        [sc], strategy_type="llm", client=client, call_logger=call_logger,
    )

    result = run.results[0]
    assert result.validation_errors == 3  # 1 + 2
    assert result.fallback_triggers == 1  # only first record


def test_extract_llm_metrics_with_records():
    """_extract_llm_metrics correctly aggregates from a record slice."""
    call_logger = LLMCallLogger()
    # Pre-existing record from a previous scenario
    call_logger.record(_make_call_record(input_tokens=999, output_tokens=999))

    start_index = len(call_logger.records)

    # Records for "current scenario"
    call_logger.record(_make_call_record(
        input_tokens=100, output_tokens=50,
        validation_errors=("err1",), fallback_used=False,
    ))
    call_logger.record(_make_call_record(
        input_tokens=200, output_tokens=100,
        validation_errors=("err2", "err3"), fallback_used=True,
    ))

    val_errors, fallbacks, token_usage, cost_usd = _extract_llm_metrics(
        call_logger, start_index,
    )

    assert val_errors == 3
    assert fallbacks == 1
    assert token_usage["input_tokens"] == 300
    assert token_usage["output_tokens"] == 150
    expected_cost = (300 / 1_000_000) * 3.0 + (150 / 1_000_000) * 15.0
    assert abs(cost_usd - expected_cost) < 1e-10


# --- 4.2 Per-scenario error handling tests ---


@patch("ares.dialectic.scripts.benchmark_runner.run_cycle_with_strategies")
def test_scenario_error_does_not_crash_run(mock_run):
    """A single scenario failure doesn't prevent other scenarios from running."""
    call_count = 0

    def side_effect(**kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise RuntimeError("Simulated failure")
        return _make_mock_cycle_result()

    mock_run.side_effect = side_effect

    scenarios = [get_scenario_by_id("SC-001"), get_scenario_by_id("SC-002")]
    run = run_benchmark(scenarios, strategy_type="rule_based")

    assert len(run.results) == 2
    assert run.results[1].verdict_outcome != "ERROR"


@patch("ares.dialectic.scripts.benchmark_runner.run_cycle_with_strategies")
def test_error_scenario_has_error_outcome(mock_run):
    """Failed scenario produces verdict_outcome='ERROR'."""
    mock_run.side_effect = RuntimeError("Simulated failure")

    sc = get_scenario_by_id("SC-001")
    run = run_benchmark([sc], strategy_type="rule_based")

    assert run.results[0].verdict_outcome == "ERROR"
    assert run.results[0].verdict_confidence == 0.0


@patch("ares.dialectic.scripts.benchmark_runner.run_cycle_with_strategies")
def test_error_scenario_has_error_in_narrator_output(mock_run):
    """Failed scenario includes the error message in narrator_output."""
    mock_run.side_effect = RuntimeError("Simulated failure")

    sc = get_scenario_by_id("SC-001")
    run = run_benchmark([sc], strategy_type="rule_based")

    assert run.results[0].narrator_output is not None
    assert "RuntimeError" in run.results[0].narrator_output
    assert "Simulated failure" in run.results[0].narrator_output


@patch("ares.dialectic.scripts.benchmark_runner.run_cycle_with_strategies")
def test_error_narrator_output_truncated_to_500_chars(mock_run):
    """Error narrator output is truncated to 500 characters."""
    mock_run.side_effect = RuntimeError("x" * 1000)

    sc = get_scenario_by_id("SC-001")
    run = run_benchmark([sc], strategy_type="rule_based")

    assert len(run.results[0].narrator_output) <= 500


@patch("ares.dialectic.scripts.benchmark_runner.run_cycle_with_strategies")
def test_all_scenarios_present_after_error(mock_run):
    """All scenarios are accounted for even when some fail."""
    call_count = 0

    def side_effect(**kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 2:
            raise ValueError("Middle scenario failed")
        return _make_mock_cycle_result()

    mock_run.side_effect = side_effect

    scenarios = [
        get_scenario_by_id("SC-001"),
        get_scenario_by_id("SC-002"),
        get_scenario_by_id("SC-003"),
    ]
    run = run_benchmark(scenarios, strategy_type="rule_based")

    assert run.scenario_count == 3
    assert len(run.results) == 3
    outcomes = [r.verdict_outcome for r in run.results]
    assert outcomes.count("ERROR") == 1
    assert outcomes[1] == "ERROR"


@patch("ares.dialectic.scripts.benchmark_runner.run_cycle_with_strategies")
def test_error_scenario_has_zero_metrics(mock_run):
    """Failed scenario has zeroed-out numeric metrics."""
    mock_run.side_effect = RuntimeError("fail")

    sc = get_scenario_by_id("SC-001")
    run = run_benchmark([sc], strategy_type="rule_based")

    r = run.results[0]
    assert r.architect_confidence == 0.0
    assert r.skeptic_confidence == 0.0
    assert r.architect_assertion_count == 0
    assert r.skeptic_assertion_count == 0
    assert r.architect_fact_ids_cited == frozenset()
    assert r.skeptic_fact_ids_cited == frozenset()
    assert r.fact_coverage_ratio == 0.0
    assert r.validation_errors == 0
    assert r.fallback_triggers == 0


# --- 4.3 Edge cases ---


@patch("ares.dialectic.scripts.benchmark_runner.run_cycle_with_strategies")
def test_llm_with_no_call_logger_works(mock_run):
    """LLM path with call_logger=None behaves as before (fields stay 0/None)."""
    mock_run.return_value = _make_mock_cycle_result()
    client = MagicMock()
    sc = get_scenario_by_id("SC-001")

    run = run_benchmark(
        [sc], strategy_type="llm", client=client, call_logger=None,
    )

    assert run.results[0].token_usage is None
    assert run.results[0].cost_usd is None
    assert run.results[0].validation_errors == 0
    assert run.results[0].fallback_triggers == 0


def test_empty_scenarios_still_raises():
    """Empty scenarios list still raises ValueError after changes."""
    with pytest.raises(ValueError, match="must not be empty"):
        run_benchmark([], strategy_type="rule_based")


@patch("ares.dialectic.scripts.benchmark_runner.run_cycle_with_strategies")
def test_llm_per_scenario_metrics_isolated(mock_run):
    """Each scenario's metrics come from only its own logger records."""
    call_logger = LLMCallLogger()
    client = MagicMock()
    call_index = 0

    def side_effect(**kwargs):
        nonlocal call_index
        call_index += 1
        if call_index == 1:
            call_logger.record(
                _make_call_record(input_tokens=1000, output_tokens=500),
            )
        else:
            call_logger.record(
                _make_call_record(input_tokens=2000, output_tokens=1000),
            )
        return _make_mock_cycle_result()

    mock_run.side_effect = side_effect

    scenarios = [get_scenario_by_id("SC-001"), get_scenario_by_id("SC-002")]
    run = run_benchmark(
        scenarios, strategy_type="llm", client=client, call_logger=call_logger,
    )

    # First scenario: 1000 input, 500 output
    assert run.results[0].token_usage["input_tokens"] == 1000
    assert run.results[0].token_usage["output_tokens"] == 500
    # Second scenario: 2000 input, 1000 output
    assert run.results[1].token_usage["input_tokens"] == 2000
    assert run.results[1].token_usage["output_tokens"] == 1000
