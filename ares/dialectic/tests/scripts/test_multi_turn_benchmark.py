"""Tests for the multi-turn benchmark runner — dataclasses, execution, and error handling."""

from __future__ import annotations

import uuid
from unittest.mock import MagicMock, patch

import pytest
from ares.dialectic.agents.patterns import VerdictOutcome
from ares.dialectic.agents.strategies.observability import LLMCallLogger, LLMCallRecord
from ares.dialectic.coordinator.cycle import TerminationReason
from ares.dialectic.scripts.multi_turn_benchmark import (
    MultiTurnBenchmarkRun,
    MultiTurnScenarioResult,
    RoundSnapshot,
    _extract_llm_metrics,
    run_multi_turn_benchmark,
)
from ares.dialectic.scripts.scenario_corpus import get_all_scenarios, get_scenario_by_id

ALL_SCENARIOS = get_all_scenarios()


# =============================================================================
# Helpers
# =============================================================================


def _make_mock_verdict(**overrides):
    """Create a minimal mock Verdict."""
    mock = MagicMock()
    # Do NOT set mock.outcome to a real enum — can't set .value on enums.
    # Let it stay a MagicMock and just set .value on it.
    mock.outcome.value = overrides.get("outcome_value", "inconclusive")
    mock.confidence = overrides.get("confidence", 0.75)
    mock.architect_confidence = overrides.get("architect_confidence", 0.8)
    mock.skeptic_confidence = overrides.get("skeptic_confidence", 0.3)
    mock.supporting_fact_ids = overrides.get("supporting_fact_ids", frozenset({"f-1"}))
    return mock


def _make_mock_debate_round(round_number=1, **overrides):
    """Create a minimal mock DebateRound."""
    mock = MagicMock()
    mock.round_number = round_number
    mock.thesis.confidence = overrides.get("architect_confidence", 0.8)
    mock.antithesis.confidence = overrides.get("skeptic_confidence", 0.3)
    mock.thesis.get_all_fact_ids.return_value = overrides.get(
        "thesis_fact_ids", {"f-1"}
    )
    mock.antithesis.get_all_fact_ids.return_value = overrides.get(
        "antithesis_fact_ids", {"f-1"}
    )
    mock.thesis.assertions = overrides.get("thesis_assertions", [MagicMock()])
    mock.antithesis.assertions = overrides.get("antithesis_assertions", [MagicMock()])
    return mock


def _make_scenario_result_tuple(
    rounds_count=2,
    termination_reason=TerminationReason.MAX_TURNS_EXCEEDED,
    outcome_value="inconclusive",
):
    """Create the tuple returned by _run_single_scenario."""
    verdict = _make_mock_verdict(outcome_value=outcome_value)
    rounds = [_make_mock_debate_round(i + 1) for i in range(rounds_count)]
    snapshots = tuple(
        RoundSnapshot(
            round_number=i + 1,
            architect_confidence=0.8,
            skeptic_confidence=0.3,
            architect_new_fact_count=1,
            skeptic_new_fact_count=1,
            architect_assertion_count=1,
            skeptic_assertion_count=1,
        )
        for i in range(rounds_count)
    )
    return (
        verdict,
        rounds,
        termination_reason,
        "Test narrative output",
        {"f-1", "f-2"},
        snapshots,
    )


def _make_call_record(**overrides):
    """Create an LLMCallRecord with sensible defaults."""
    defaults = dict(
        timestamp="2026-03-04T00:00:00+00:00",
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


# =============================================================================
# Dataclass Tests
# =============================================================================


class TestRoundSnapshot:
    """Tests for the RoundSnapshot frozen dataclass."""

    def test_round_snapshot_is_frozen(self):
        snap = RoundSnapshot(
            round_number=1,
            architect_confidence=0.8,
            skeptic_confidence=0.3,
            architect_new_fact_count=2,
            skeptic_new_fact_count=1,
            architect_assertion_count=3,
            skeptic_assertion_count=2,
        )
        with pytest.raises(AttributeError):
            snap.round_number = 99

    def test_round_snapshot_fields_populated(self):
        snap = RoundSnapshot(
            round_number=2,
            architect_confidence=0.85,
            skeptic_confidence=0.45,
            architect_new_fact_count=3,
            skeptic_new_fact_count=0,
            architect_assertion_count=4,
            skeptic_assertion_count=1,
        )
        assert snap.round_number == 2
        assert snap.architect_confidence == 0.85
        assert snap.skeptic_confidence == 0.45
        assert snap.architect_new_fact_count == 3
        assert snap.skeptic_new_fact_count == 0
        assert snap.architect_assertion_count == 4
        assert snap.skeptic_assertion_count == 1


class TestMultiTurnScenarioResult:
    """Tests for the MultiTurnScenarioResult frozen dataclass."""

    def _make_result(self, **overrides):
        defaults = dict(
            scenario_id="SC-001",
            scenario_name="Test Scenario",
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
            round_snapshots=(),
            validation_errors=0,
            fallback_triggers=0,
            token_usage={"input_tokens": 0, "output_tokens": 0},
            cost_usd=0.0,
        )
        defaults.update(overrides)
        return MultiTurnScenarioResult(**defaults)

    def test_multi_turn_scenario_result_is_frozen(self):
        result = self._make_result()
        with pytest.raises(AttributeError):
            result.scenario_id = "tampered"

    def test_multi_turn_scenario_result_verdict_matches_true(self):
        result = self._make_result(
            expected_verdict="inconclusive",
            verdict_outcome="inconclusive",
        )
        assert result.verdict_matches is True

    def test_multi_turn_scenario_result_verdict_matches_false(self):
        result = self._make_result(
            expected_verdict="threat_confirmed",
            verdict_outcome="inconclusive",
        )
        assert result.verdict_matches is False

    def test_verdict_matches_case_insensitive(self):
        result = self._make_result(
            expected_verdict="THREAT_CONFIRMED",
            verdict_outcome="threat_confirmed",
        )
        assert result.verdict_matches is True


class TestMultiTurnBenchmarkRun:
    """Tests for the MultiTurnBenchmarkRun frozen dataclass."""

    def _make_scenario_result(self, **overrides):
        defaults = dict(
            scenario_id="SC-001",
            scenario_name="Test",
            expected_verdict="inconclusive",
            verdict_outcome="inconclusive",
            verdict_confidence=0.75,
            architect_confidence=0.8,
            skeptic_confidence=0.3,
            coverage=0.5,
            narrator_output="",
            duration_ms=100,
            rounds_used=2,
            max_rounds_configured=3,
            termination_reason="max_turns_exceeded",
            round_snapshots=(),
            validation_errors=0,
            fallback_triggers=0,
            token_usage={"input_tokens": 0, "output_tokens": 0},
            cost_usd=0.01,
        )
        defaults.update(overrides)
        return MultiTurnScenarioResult(**defaults)

    def _make_run(self, results=None):
        if results is None:
            results = (
                self._make_scenario_result(
                    scenario_id="SC-001",
                    verdict_outcome="inconclusive",
                    expected_verdict="inconclusive",
                    rounds_used=2,
                ),
                self._make_scenario_result(
                    scenario_id="SC-002",
                    verdict_outcome="threat_confirmed",
                    expected_verdict="threat_confirmed",
                    rounds_used=3,
                ),
                self._make_scenario_result(
                    scenario_id="SC-003",
                    verdict_outcome="threat_confirmed",
                    expected_verdict="inconclusive",
                    rounds_used=1,
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
            total_cost_usd=0.03,
            total_duration_ms=300,
        )

    def test_multi_turn_benchmark_run_is_frozen(self):
        run = self._make_run()
        with pytest.raises(AttributeError):
            run.run_id = "tampered"

    def test_multi_turn_benchmark_run_match_rate(self):
        run = self._make_run()
        # 2 out of 3 match
        assert abs(run.match_rate - 2 / 3) < 1e-6

    def test_multi_turn_benchmark_run_avg_rounds_used(self):
        run = self._make_run()
        # (2 + 3 + 1) / 3 = 2.0
        assert abs(run.avg_rounds_used - 2.0) < 1e-6

    def test_multi_turn_benchmark_run_matches(self):
        run = self._make_run()
        assert run.matches == 2


# =============================================================================
# Benchmark Function Tests
# =============================================================================


@patch("ares.dialectic.scripts.multi_turn_benchmark._run_single_scenario")
def test_run_multi_turn_benchmark_returns_benchmark_run(mock_run):
    """run_multi_turn_benchmark returns a MultiTurnBenchmarkRun."""
    mock_run.return_value = _make_scenario_result_tuple()
    client = MagicMock()
    sc = get_scenario_by_id("SC-001")

    run = run_multi_turn_benchmark([sc], client=client)
    assert isinstance(run, MultiTurnBenchmarkRun)


@patch("ares.dialectic.scripts.multi_turn_benchmark._run_single_scenario")
def test_run_multi_turn_benchmark_processes_all_scenarios(mock_run):
    """All scenarios produce results."""
    mock_run.return_value = _make_scenario_result_tuple()
    client = MagicMock()
    scenarios = [get_scenario_by_id("SC-001"), get_scenario_by_id("SC-002")]

    run = run_multi_turn_benchmark(scenarios, client=client)
    assert run.scenario_count == 2
    assert len(run.results) == 2


def test_run_multi_turn_benchmark_empty_scenarios_raises():
    """Empty scenarios list raises ValueError."""
    client = MagicMock()
    with pytest.raises(ValueError, match="must not be empty"):
        run_multi_turn_benchmark([], client=client)


@patch("ares.dialectic.scripts.multi_turn_benchmark._run_single_scenario")
def test_results_have_rounds_used(mock_run):
    """Each result has rounds_used populated."""
    mock_run.return_value = _make_scenario_result_tuple(rounds_count=2)
    client = MagicMock()
    sc = get_scenario_by_id("SC-001")

    run = run_multi_turn_benchmark([sc], client=client)
    assert run.results[0].rounds_used == 2


@patch("ares.dialectic.scripts.multi_turn_benchmark._run_single_scenario")
def test_results_have_termination_reason(mock_run):
    """Each result has termination_reason populated."""
    mock_run.return_value = _make_scenario_result_tuple(
        termination_reason=TerminationReason.CONFIDENCE_STABILIZED,
    )
    client = MagicMock()
    sc = get_scenario_by_id("SC-001")

    run = run_multi_turn_benchmark([sc], client=client)
    assert run.results[0].termination_reason == "confidence_stabilized"


@patch("ares.dialectic.scripts.multi_turn_benchmark._run_single_scenario")
def test_results_have_round_snapshots(mock_run):
    """Each result has round_snapshots populated."""
    mock_run.return_value = _make_scenario_result_tuple(rounds_count=3)
    client = MagicMock()
    sc = get_scenario_by_id("SC-001")

    run = run_multi_turn_benchmark([sc], client=client)
    assert len(run.results[0].round_snapshots) == 3


@patch("ares.dialectic.scripts.multi_turn_benchmark._run_single_scenario")
def test_round_snapshots_ordered_by_round_number(mock_run):
    """Round snapshots are in order by round_number."""
    mock_run.return_value = _make_scenario_result_tuple(rounds_count=3)
    client = MagicMock()
    sc = get_scenario_by_id("SC-001")

    run = run_multi_turn_benchmark([sc], client=client)
    snapshots = run.results[0].round_snapshots
    round_numbers = [s.round_number for s in snapshots]
    assert round_numbers == [1, 2, 3]


@patch("ares.dialectic.scripts.multi_turn_benchmark._run_single_scenario")
def test_max_rounds_respected(mock_run):
    """max_rounds parameter is passed through to results."""
    mock_run.return_value = _make_scenario_result_tuple(rounds_count=2)
    client = MagicMock()
    sc = get_scenario_by_id("SC-001")

    run = run_multi_turn_benchmark([sc], client=client, max_rounds=5)
    assert run.max_rounds == 5
    assert run.results[0].max_rounds_configured == 5


@patch("ares.dialectic.scripts.multi_turn_benchmark._run_single_scenario")
def test_verdict_outcome_populated(mock_run):
    """Verdict outcome is populated from the verdict."""
    mock_run.return_value = _make_scenario_result_tuple(
        outcome_value="threat_confirmed",
    )
    client = MagicMock()
    sc = get_scenario_by_id("SC-001")

    run = run_multi_turn_benchmark([sc], client=client)
    assert run.results[0].verdict_outcome == "threat_confirmed"


@patch("ares.dialectic.scripts.multi_turn_benchmark._run_single_scenario")
def test_expected_verdict_from_scenario_metadata(mock_run):
    """Expected verdict is pulled from scenario metadata."""
    mock_run.return_value = _make_scenario_result_tuple()
    client = MagicMock()
    sc = get_scenario_by_id("SC-001")

    run = run_multi_turn_benchmark([sc], client=client)
    assert run.results[0].expected_verdict == sc.metadata.expected_verdict


@patch("ares.dialectic.scripts.multi_turn_benchmark._run_single_scenario")
def test_scenario_name_from_metadata(mock_run):
    """Scenario name is pulled from scenario metadata."""
    mock_run.return_value = _make_scenario_result_tuple()
    client = MagicMock()
    sc = get_scenario_by_id("SC-001")

    run = run_multi_turn_benchmark([sc], client=client)
    assert run.results[0].scenario_name == sc.metadata.name


@patch("ares.dialectic.scripts.multi_turn_benchmark._run_single_scenario")
def test_strategy_type_is_multi_turn_llm(mock_run):
    """Strategy type is always 'multi_turn_llm'."""
    mock_run.return_value = _make_scenario_result_tuple()
    client = MagicMock()
    sc = get_scenario_by_id("SC-001")

    run = run_multi_turn_benchmark([sc], client=client)
    assert run.strategy_type == "multi_turn_llm"


# =============================================================================
# LLM Metrics Tests
# =============================================================================


@patch("ares.dialectic.scripts.multi_turn_benchmark._run_single_scenario")
def test_llm_metrics_captured_per_scenario(mock_run):
    """LLM metrics are extracted per scenario from call_logger."""
    call_logger = LLMCallLogger()
    client = MagicMock()
    sc = get_scenario_by_id("SC-001")

    def side_effect(scenario, **kwargs):
        call_logger.record(
            _make_call_record(input_tokens=1000, output_tokens=500)
        )
        call_logger.record(
            _make_call_record(input_tokens=800, output_tokens=400)
        )
        return _make_scenario_result_tuple()

    mock_run.side_effect = side_effect
    run = run_multi_turn_benchmark([sc], client=client, call_logger=call_logger)

    result = run.results[0]
    assert result.token_usage["input_tokens"] == 1800
    assert result.token_usage["output_tokens"] == 900
    assert result.cost_usd > 0


@patch("ares.dialectic.scripts.multi_turn_benchmark._run_single_scenario")
def test_total_cost_aggregated(mock_run):
    """Total cost is sum of per-scenario costs."""
    call_logger = LLMCallLogger()
    client = MagicMock()

    def side_effect(scenario, **kwargs):
        call_logger.record(
            _make_call_record(input_tokens=1_000_000, output_tokens=0)
        )
        return _make_scenario_result_tuple()

    mock_run.side_effect = side_effect
    scenarios = [get_scenario_by_id("SC-001"), get_scenario_by_id("SC-002")]
    run = run_multi_turn_benchmark(
        scenarios, client=client, call_logger=call_logger,
    )

    # Each scenario: 1M input tokens * $3/MTok = $3.00
    assert abs(run.total_cost_usd - 6.0) < 0.01


@patch("ares.dialectic.scripts.multi_turn_benchmark._run_single_scenario")
def test_call_logger_none_works(mock_run):
    """call_logger=None produces zero cost and empty token usage."""
    mock_run.return_value = _make_scenario_result_tuple()
    client = MagicMock()
    sc = get_scenario_by_id("SC-001")

    run = run_multi_turn_benchmark([sc], client=client, call_logger=None)
    assert run.results[0].token_usage == {"input_tokens": 0, "output_tokens": 0}
    assert run.results[0].cost_usd == 0.0


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


@patch("ares.dialectic.scripts.multi_turn_benchmark._run_single_scenario")
def test_llm_metrics_include_validation_errors_and_fallbacks(mock_run):
    """Validation errors and fallback triggers extracted from logger."""
    call_logger = LLMCallLogger()
    client = MagicMock()
    sc = get_scenario_by_id("SC-001")

    def side_effect(scenario, **kwargs):
        call_logger.record(_make_call_record(
            validation_errors=("hallucinated fact_id",),
            fallback_used=True,
        ))
        call_logger.record(_make_call_record(
            validation_errors=("bad type", "empty"),
            fallback_used=False,
        ))
        return _make_scenario_result_tuple()

    mock_run.side_effect = side_effect
    run = run_multi_turn_benchmark(
        [sc], client=client, call_logger=call_logger,
    )

    result = run.results[0]
    assert result.validation_errors == 3
    assert result.fallback_triggers == 1


@patch("ares.dialectic.scripts.multi_turn_benchmark._run_single_scenario")
def test_per_scenario_metrics_isolated(mock_run):
    """Each scenario's metrics come from only its own logger records."""
    call_logger = LLMCallLogger()
    client = MagicMock()
    call_index = 0

    def side_effect(scenario, **kwargs):
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
        return _make_scenario_result_tuple()

    mock_run.side_effect = side_effect

    scenarios = [get_scenario_by_id("SC-001"), get_scenario_by_id("SC-002")]
    run = run_multi_turn_benchmark(
        scenarios, client=client, call_logger=call_logger,
    )

    assert run.results[0].token_usage["input_tokens"] == 1000
    assert run.results[0].token_usage["output_tokens"] == 500
    assert run.results[1].token_usage["input_tokens"] == 2000
    assert run.results[1].token_usage["output_tokens"] == 1000


# =============================================================================
# Error Handling Tests (Session 012 pattern)
# =============================================================================


@patch("ares.dialectic.scripts.multi_turn_benchmark._run_single_scenario")
def test_scenario_error_does_not_crash_run(mock_run):
    """A single scenario failure doesn't prevent other scenarios from running."""
    call_count = 0

    def side_effect(scenario, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise RuntimeError("Simulated failure")
        return _make_scenario_result_tuple()

    mock_run.side_effect = side_effect
    client = MagicMock()
    scenarios = [get_scenario_by_id("SC-001"), get_scenario_by_id("SC-002")]

    run = run_multi_turn_benchmark(scenarios, client=client)
    assert len(run.results) == 2
    assert run.results[1].verdict_outcome != "ERROR"


@patch("ares.dialectic.scripts.multi_turn_benchmark._run_single_scenario")
def test_error_scenario_has_error_outcome(mock_run):
    """Failed scenario produces verdict_outcome='ERROR'."""
    mock_run.side_effect = RuntimeError("Simulated failure")
    client = MagicMock()
    sc = get_scenario_by_id("SC-001")

    run = run_multi_turn_benchmark([sc], client=client)
    assert run.results[0].verdict_outcome == "ERROR"
    assert run.results[0].verdict_confidence == 0.0


@patch("ares.dialectic.scripts.multi_turn_benchmark._run_single_scenario")
def test_error_scenario_has_error_in_narrator_output(mock_run):
    """Failed scenario includes the error message in narrator_output."""
    mock_run.side_effect = RuntimeError("Simulated failure")
    client = MagicMock()
    sc = get_scenario_by_id("SC-001")

    run = run_multi_turn_benchmark([sc], client=client)
    assert "RuntimeError" in run.results[0].narrator_output
    assert "Simulated failure" in run.results[0].narrator_output


@patch("ares.dialectic.scripts.multi_turn_benchmark._run_single_scenario")
def test_all_scenarios_present_after_error(mock_run):
    """All scenarios are accounted for even when some fail."""
    call_count = 0

    def side_effect(scenario, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 2:
            raise ValueError("Middle scenario failed")
        return _make_scenario_result_tuple()

    mock_run.side_effect = side_effect
    client = MagicMock()
    scenarios = [
        get_scenario_by_id("SC-001"),
        get_scenario_by_id("SC-002"),
        get_scenario_by_id("SC-003"),
    ]

    run = run_multi_turn_benchmark(scenarios, client=client)
    assert run.scenario_count == 3
    assert len(run.results) == 3
    outcomes = [r.verdict_outcome for r in run.results]
    assert outcomes.count("ERROR") == 1
    assert outcomes[1] == "ERROR"


@patch("ares.dialectic.scripts.multi_turn_benchmark._run_single_scenario")
def test_error_scenario_has_zero_rounds(mock_run):
    """Failed scenario has rounds_used=0 and empty snapshots."""
    mock_run.side_effect = RuntimeError("fail")
    client = MagicMock()
    sc = get_scenario_by_id("SC-001")

    run = run_multi_turn_benchmark([sc], client=client)
    r = run.results[0]
    assert r.rounds_used == 0
    assert r.round_snapshots == ()
    assert r.termination_reason == "ERROR"


@patch("ares.dialectic.scripts.multi_turn_benchmark._run_single_scenario")
def test_error_scenario_narrator_output_truncated(mock_run):
    """Error narrator output is truncated to 500 characters."""
    mock_run.side_effect = RuntimeError("x" * 1000)
    client = MagicMock()
    sc = get_scenario_by_id("SC-001")

    run = run_multi_turn_benchmark([sc], client=client)
    assert len(run.results[0].narrator_output) <= 500


# =============================================================================
# Agent Isolation
# =============================================================================


@patch("ares.dialectic.scripts.multi_turn_benchmark._run_single_scenario")
def test_fresh_agents_per_scenario(mock_run):
    """Each scenario gets fresh strategy instances (agent isolation)."""
    call_args_list = []

    def side_effect(scenario, **kwargs):
        call_args_list.append(kwargs.copy())
        return _make_scenario_result_tuple()

    mock_run.side_effect = side_effect
    client = MagicMock()
    scenarios = [get_scenario_by_id("SC-001"), get_scenario_by_id("SC-002")]

    run_multi_turn_benchmark(scenarios, client=client)

    # Each scenario should get its own set of strategy instances
    assert len(call_args_list) == 2
    # Strategy objects should be different instances
    assert (
        call_args_list[0]["threat_analyzer"]
        is not call_args_list[1]["threat_analyzer"]
    )
    assert (
        call_args_list[0]["explanation_finder"]
        is not call_args_list[1]["explanation_finder"]
    )


# =============================================================================
# Run configuration tests
# =============================================================================


@patch("ares.dialectic.scripts.multi_turn_benchmark._run_single_scenario")
def test_confidence_delta_passed_through(mock_run):
    """confidence_delta is recorded in the run."""
    mock_run.return_value = _make_scenario_result_tuple()
    client = MagicMock()
    sc = get_scenario_by_id("SC-001")

    run = run_multi_turn_benchmark(
        [sc], client=client, confidence_delta=0.1,
    )
    assert run.confidence_delta == 0.1


@patch("ares.dialectic.scripts.multi_turn_benchmark._run_single_scenario")
def test_require_new_evidence_passed_through(mock_run):
    """require_new_evidence is recorded in the run."""
    mock_run.return_value = _make_scenario_result_tuple()
    client = MagicMock()
    sc = get_scenario_by_id("SC-001")

    run = run_multi_turn_benchmark(
        [sc], client=client, require_new_evidence=False,
    )
    assert run.require_new_evidence is False


@patch("ares.dialectic.scripts.multi_turn_benchmark._run_single_scenario")
def test_run_id_is_uuid_format(mock_run):
    """run_id is a valid UUID."""
    mock_run.return_value = _make_scenario_result_tuple()
    client = MagicMock()
    sc = get_scenario_by_id("SC-001")

    run = run_multi_turn_benchmark([sc], client=client)
    uuid.UUID(run.run_id)  # Raises ValueError if not valid UUID


@patch("ares.dialectic.scripts.multi_turn_benchmark._run_single_scenario")
def test_duration_non_negative(mock_run):
    """Duration values are non-negative."""
    mock_run.return_value = _make_scenario_result_tuple()
    client = MagicMock()
    sc = get_scenario_by_id("SC-001")

    run = run_multi_turn_benchmark([sc], client=client)
    assert run.total_duration_ms >= 0
    for r in run.results:
        assert r.duration_ms >= 0


# =============================================================================
# Live LLM Tests (skipped by default)
# =============================================================================


@pytest.mark.live_llm
def test_multi_turn_benchmark_single_scenario_live():
    """Run ONE scenario through live multi-turn LLM benchmark."""
    import os
    from ares.dialectic.agents.strategies.client import AnthropicClient
    from ares.dialectic.agents.strategies.observability import LLMCallLogger

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        pytest.skip("ANTHROPIC_API_KEY not set")

    client = AnthropicClient(api_key=api_key)
    call_logger = LLMCallLogger()
    sc = get_scenario_by_id("SC-001")

    run = run_multi_turn_benchmark(
        [sc], client=client, call_logger=call_logger, max_rounds=2,
    )

    assert isinstance(run, MultiTurnBenchmarkRun)
    assert run.scenario_count == 1
    assert len(run.results) == 1
    result = run.results[0]
    assert result.rounds_used >= 1
    assert result.termination_reason != "ERROR"
    assert len(result.round_snapshots) >= 1


@pytest.mark.live_llm
def test_multi_turn_benchmark_full_run_live():
    """Run all 12 scenarios through live multi-turn LLM benchmark."""
    import os
    from ares.dialectic.agents.strategies.client import AnthropicClient
    from ares.dialectic.agents.strategies.observability import LLMCallLogger

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        pytest.skip("ANTHROPIC_API_KEY not set")

    client = AnthropicClient(api_key=api_key)
    call_logger = LLMCallLogger()

    run = run_multi_turn_benchmark(
        list(ALL_SCENARIOS),
        client=client,
        call_logger=call_logger,
        max_rounds=3,
    )

    assert isinstance(run, MultiTurnBenchmarkRun)
    assert run.scenario_count == 12
    assert len(run.results) == 12

    # At least some scenarios should succeed
    non_error = [r for r in run.results if r.verdict_outcome != "ERROR"]
    assert len(non_error) > 0
