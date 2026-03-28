"""Tests for selective_escalation pipeline — Session 024.

All tests are deterministic — LLM calls are mocked.
Tests cover pipeline routing, result construction, summary computation,
escalation reason classification, cost tracking, edge cases, and report formatting.
"""

from __future__ import annotations

import pytest
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

from ares.dialectic.scripts.selective_escalation import (
    SelectiveResult,
    SelectiveSummary,
    _classify_escalation_reason,
    format_selective_report,
    run_selective_escalation,
)
from ares.dialectic.agents.patterns import Verdict, VerdictOutcome
from ares.dialectic.coordinator.escalation import EscalationGate
from ares.dialectic.coordinator.miscalibration import MiscalibrationDetector
from ares.dialectic.evidence.fact import EntityType, Fact
from ares.dialectic.evidence.packet import EvidencePacket, TimeWindow
from ares.dialectic.evidence.provenance import Provenance, SourceType
from ares.dialectic.scripts.scenario_corpus import BenchmarkScenario, ScenarioMetadata
from ares.dialectic.scripts.benchmark_runner import BenchmarkRun, ScenarioResult
from ares.dialectic.scripts.multi_turn_benchmark import (
    MultiTurnBenchmarkRun,
    MultiTurnScenarioResult,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ts() -> datetime:
    return datetime(2026, 1, 1, 12, 0, 0)


def _make_packet(n_facts: int = 3) -> EvidencePacket:
    tw = TimeWindow(start=_ts() - timedelta(hours=1), end=_ts())
    pkt = EvidencePacket(packet_id="pkt-001", time_window=tw)
    for i in range(n_facts):
        pkt.add_fact(Fact(
            fact_id=f"f{i}",
            entity_id="host-1",
            entity_type=EntityType.NODE,
            field="event",
            value=f"val-{i}",
            timestamp=_ts(),
            provenance=Provenance(
                source_type=SourceType.SYSLOG,
                source_id="src",
                extracted_at=_ts(),
            ),
        ))
    pkt.freeze()
    return pkt


def _make_scenario(
    scenario_id: str = "SC-001",
    name: str = "test-scenario",
    expected_verdict: str = "threat_confirmed",
    n_facts: int = 3,
) -> BenchmarkScenario:
    return BenchmarkScenario(
        metadata=ScenarioMetadata(
            scenario_id=scenario_id,
            name=name,
            description="test",
            mitre_attack_ids=("T1078",),
            mitre_tactic="initial-access",
            difficulty_tier=1,
            expected_verdict=expected_verdict,
            expected_winner="ARCHITECT",
            fact_count=n_facts,
            notes="test scenario",
        ),
        packet=_make_packet(n_facts),
    )


def _make_st_scenario_result(
    scenario_id: str = "SC-001",
    verdict: str = "threat_confirmed",
    confidence: float = 0.85,
    arch_confidence: float = 0.85,
    skep_confidence: float = 0.20,
    cost: float = 0.001,
    n_facts: int = 3,
) -> ScenarioResult:
    return ScenarioResult(
        scenario_id=scenario_id,
        strategy_type="llm",
        verdict_outcome=verdict,
        verdict_confidence=confidence,
        architect_confidence=arch_confidence,
        skeptic_confidence=skep_confidence,
        architect_assertion_count=2,
        skeptic_assertion_count=1,
        architect_fact_ids_cited=frozenset(f"f{i}" for i in range(n_facts)),
        skeptic_fact_ids_cited=frozenset(),
        total_facts_available=n_facts,
        fact_coverage_ratio=1.0,
        validation_errors=0,
        fallback_triggers=0,
        duration_ms=100,
        token_usage={"input_tokens": 500, "output_tokens": 200},
        cost_usd=cost,
        narrator_output="test",
    )


def _make_mt_scenario_result(
    scenario_id: str = "SC-001",
    name: str = "test-scenario",
    expected_verdict: str = "threat_confirmed",
    verdict: str = "threat_confirmed",
    confidence: float = 0.80,
    cost: float = 0.005,
) -> MultiTurnScenarioResult:
    return MultiTurnScenarioResult(
        scenario_id=scenario_id,
        scenario_name=name,
        expected_verdict=expected_verdict,
        verdict_outcome=verdict,
        verdict_confidence=confidence,
        architect_confidence=0.80,
        skeptic_confidence=0.30,
        coverage=1.0,
        narrator_output="test",
        duration_ms=500,
        rounds_used=2,
        max_rounds_configured=3,
        termination_reason="confidence_stabilized",
        round_snapshots=(),
        validation_errors=0,
        fallback_triggers=0,
        token_usage={"input_tokens": 1000, "output_tokens": 500},
        cost_usd=cost,
    )


def _make_benchmark_run(
    results: list[ScenarioResult],
) -> BenchmarkRun:
    return BenchmarkRun(
        run_id="test-run",
        timestamp=_ts(),
        strategy_type="llm",
        scenario_count=len(results),
        results=tuple(results),
        total_duration_ms=100,
        total_cost_usd=sum(r.cost_usd or 0 for r in results),
    )


def _make_mt_benchmark_run(
    results: list[MultiTurnScenarioResult],
) -> MultiTurnBenchmarkRun:
    return MultiTurnBenchmarkRun(
        run_id="test-mt-run",
        timestamp=_ts().isoformat(),
        strategy_type="multi_turn_llm",
        max_rounds=3,
        confidence_delta=0.05,
        require_new_evidence=True,
        scenario_count=len(results),
        results=tuple(results),
        total_cost_usd=sum(r.cost_usd for r in results),
        total_duration_ms=500,
    )


# ===========================================================================
# Escalation reason classification
# ===========================================================================

class TestEscalationReasonClassification:
    """Tests for _classify_escalation_reason."""

    def test_both_triggered(self) -> None:
        assert _classify_escalation_reason(True, True) == "both"

    def test_uncertainty_only(self) -> None:
        assert _classify_escalation_reason(True, False) == "uncertainty"

    def test_miscalibration_only(self) -> None:
        assert _classify_escalation_reason(False, True) == "miscalibration"

    def test_none_triggered(self) -> None:
        assert _classify_escalation_reason(False, False) == "none"


# ===========================================================================
# SelectiveResult construction and immutability
# ===========================================================================

class TestSelectiveResult:
    """Tests for SelectiveResult."""

    def test_construction(self) -> None:
        r = SelectiveResult(
            scenario_id="SC-001",
            scenario_name="test",
            expected_verdict=VerdictOutcome.THREAT_CONFIRMED,
            single_turn_verdict=VerdictOutcome.THREAT_CONFIRMED,
            single_turn_confidence=0.85,
            escalated=False,
            escalation_reason="none",
            final_verdict=VerdictOutcome.THREAT_CONFIRMED,
            final_correct=True,
            cost=0.001,
        )
        assert r.scenario_id == "SC-001"
        assert r.final_correct is True

    def test_frozen(self) -> None:
        r = SelectiveResult(
            scenario_id="SC-001",
            scenario_name="test",
            expected_verdict=VerdictOutcome.THREAT_CONFIRMED,
            single_turn_verdict=VerdictOutcome.THREAT_CONFIRMED,
            single_turn_confidence=0.85,
            escalated=False,
            escalation_reason="none",
            final_verdict=VerdictOutcome.THREAT_CONFIRMED,
            final_correct=True,
            cost=0.001,
        )
        with pytest.raises(AttributeError):
            r.cost = 999  # type: ignore[misc]


# ===========================================================================
# SelectiveSummary computation
# ===========================================================================

class TestSelectiveSummary:
    """Tests for SelectiveSummary."""

    def test_accuracy_delta_positive(self) -> None:
        s = SelectiveSummary(
            total_scenarios=10,
            escalated_count=3,
            escalation_rate=0.3,
            single_turn_accuracy=0.7,
            selective_accuracy=0.8,
            accuracy_delta=0.1,
            total_cost=0.05,
            single_turn_cost=0.03,
            cost_ratio=0.05 / 0.03,
            results=(),
        )
        assert s.accuracy_delta == pytest.approx(0.1)
        assert s.selective_accuracy > s.single_turn_accuracy

    def test_accuracy_delta_negative(self) -> None:
        s = SelectiveSummary(
            total_scenarios=10,
            escalated_count=3,
            escalation_rate=0.3,
            single_turn_accuracy=0.8,
            selective_accuracy=0.7,
            accuracy_delta=-0.1,
            total_cost=0.05,
            single_turn_cost=0.03,
            cost_ratio=0.05 / 0.03,
            results=(),
        )
        assert s.accuracy_delta < 0

    def test_frozen(self) -> None:
        s = SelectiveSummary(
            total_scenarios=1,
            escalated_count=0,
            escalation_rate=0.0,
            single_turn_accuracy=1.0,
            selective_accuracy=1.0,
            accuracy_delta=0.0,
            total_cost=0.001,
            single_turn_cost=0.001,
            cost_ratio=1.0,
            results=(),
        )
        with pytest.raises(AttributeError):
            s.total_scenarios = 99  # type: ignore[misc]

    def test_results_is_tuple(self) -> None:
        s = SelectiveSummary(
            total_scenarios=0,
            escalated_count=0,
            escalation_rate=0.0,
            single_turn_accuracy=0.0,
            selective_accuracy=0.0,
            accuracy_delta=0.0,
            total_cost=0.0,
            single_turn_cost=0.0,
            cost_ratio=1.0,
            results=(),
        )
        assert isinstance(s.results, tuple)


# ===========================================================================
# Pipeline routing (mocked)
# ===========================================================================

class TestPipelineRouting:
    """Test pipeline routing with mocked LLM calls."""

    @patch("ares.dialectic.scripts.multi_turn_benchmark.run_multi_turn_benchmark")
    @patch("ares.dialectic.scripts.benchmark_runner.run_benchmark")
    def test_no_escalation_accepted(self, mock_st, mock_mt) -> None:
        """High-confidence correct verdict -> no escalation."""
        scenario = _make_scenario(expected_verdict="threat_confirmed")
        st_result = _make_st_scenario_result(
            verdict="threat_confirmed", confidence=0.85, cost=0.001,
        )
        mock_st.return_value = _make_benchmark_run([st_result])

        mock_logger = MagicMock()
        mock_logger.records = []

        summary = run_selective_escalation(
            [scenario],
            client=MagicMock(),
            call_logger=mock_logger,
        )

        assert summary.total_scenarios == 1
        assert summary.escalated_count == 0
        assert summary.results[0].escalated is False
        assert summary.results[0].final_correct is True
        mock_mt.assert_not_called()

    @patch("ares.dialectic.scripts.multi_turn_benchmark.run_multi_turn_benchmark")
    @patch("ares.dialectic.scripts.benchmark_runner.run_benchmark")
    def test_uncertainty_escalation(self, mock_st, mock_mt) -> None:
        """Mid-confidence verdict -> escalated for uncertainty."""
        scenario = _make_scenario(expected_verdict="threat_confirmed")
        st_result = _make_st_scenario_result(
            verdict="threat_confirmed", confidence=0.50, cost=0.001,
        )
        mock_st.return_value = _make_benchmark_run([st_result])

        mt_result = _make_mt_scenario_result(
            verdict="threat_confirmed", cost=0.005,
        )
        mock_mt.return_value = _make_mt_benchmark_run([mt_result])

        mock_logger = MagicMock()
        mock_logger.records = []

        summary = run_selective_escalation(
            [scenario],
            client=MagicMock(),
            call_logger=mock_logger,
        )

        assert summary.escalated_count == 1
        assert summary.results[0].escalated is True
        assert "uncertainty" in summary.results[0].escalation_reason

    @patch("ares.dialectic.scripts.multi_turn_benchmark.run_multi_turn_benchmark")
    @patch("ares.dialectic.scripts.benchmark_runner.run_benchmark")
    def test_escalation_flips_verdict(self, mock_st, mock_mt) -> None:
        """Single-turn wrong, multi-turn correct -> good flip."""
        scenario = _make_scenario(expected_verdict="threat_confirmed")
        st_result = _make_st_scenario_result(
            verdict="threat_dismissed", confidence=0.50, cost=0.001,
        )
        mock_st.return_value = _make_benchmark_run([st_result])

        mt_result = _make_mt_scenario_result(
            verdict="threat_confirmed", cost=0.005,
        )
        mock_mt.return_value = _make_mt_benchmark_run([mt_result])

        mock_logger = MagicMock()
        mock_logger.records = []

        summary = run_selective_escalation(
            [scenario],
            client=MagicMock(),
            call_logger=mock_logger,
        )

        assert summary.results[0].single_turn_verdict == VerdictOutcome.THREAT_DISMISSED
        assert summary.results[0].final_verdict == VerdictOutcome.THREAT_CONFIRMED
        assert summary.results[0].final_correct is True
        assert summary.selective_accuracy > summary.single_turn_accuracy


# ===========================================================================
# Cost tracking
# ===========================================================================

class TestCostTracking:
    """Test cost calculation."""

    @patch("ares.dialectic.scripts.multi_turn_benchmark.run_multi_turn_benchmark")
    @patch("ares.dialectic.scripts.benchmark_runner.run_benchmark")
    def test_cost_no_escalation(self, mock_st, mock_mt) -> None:
        """No escalation -> cost = single-turn cost."""
        scenario = _make_scenario()
        st_result = _make_st_scenario_result(confidence=0.85, cost=0.010)
        mock_st.return_value = _make_benchmark_run([st_result])

        mock_logger = MagicMock()
        mock_logger.records = []

        summary = run_selective_escalation(
            [scenario],
            client=MagicMock(),
            call_logger=mock_logger,
        )

        assert summary.total_cost == pytest.approx(0.010)
        assert summary.cost_ratio == pytest.approx(1.0)

    @patch("ares.dialectic.scripts.multi_turn_benchmark.run_multi_turn_benchmark")
    @patch("ares.dialectic.scripts.benchmark_runner.run_benchmark")
    def test_cost_with_escalation(self, mock_st, mock_mt) -> None:
        """Escalation adds multi-turn cost."""
        scenario = _make_scenario()
        st_result = _make_st_scenario_result(confidence=0.50, cost=0.010)
        mock_st.return_value = _make_benchmark_run([st_result])

        mt_result = _make_mt_scenario_result(cost=0.020)
        mock_mt.return_value = _make_mt_benchmark_run([mt_result])

        mock_logger = MagicMock()
        mock_logger.records = []

        summary = run_selective_escalation(
            [scenario],
            client=MagicMock(),
            call_logger=mock_logger,
        )

        assert summary.total_cost == pytest.approx(0.030)
        assert summary.single_turn_cost == pytest.approx(0.010)
        assert summary.cost_ratio == pytest.approx(3.0)


# ===========================================================================
# Edge cases
# ===========================================================================

class TestEdgeCases:
    """Edge case tests."""

    def test_empty_scenarios_raises(self) -> None:
        with pytest.raises(ValueError, match="scenarios must not be empty"):
            run_selective_escalation([], client=MagicMock())

    def test_no_client_raises(self) -> None:
        with pytest.raises(ValueError, match="client is required"):
            run_selective_escalation([_make_scenario()])


# ===========================================================================
# Report formatting
# ===========================================================================

class TestReportFormatting:
    """Tests for format_selective_report."""

    def test_report_contains_header(self) -> None:
        s = SelectiveSummary(
            total_scenarios=1,
            escalated_count=0,
            escalation_rate=0.0,
            single_turn_accuracy=1.0,
            selective_accuracy=1.0,
            accuracy_delta=0.0,
            total_cost=0.001,
            single_turn_cost=0.001,
            cost_ratio=1.0,
            results=(
                SelectiveResult(
                    scenario_id="SC-001",
                    scenario_name="test",
                    expected_verdict=VerdictOutcome.THREAT_CONFIRMED,
                    single_turn_verdict=VerdictOutcome.THREAT_CONFIRMED,
                    single_turn_confidence=0.85,
                    escalated=False,
                    escalation_reason="none",
                    final_verdict=VerdictOutcome.THREAT_CONFIRMED,
                    final_correct=True,
                    cost=0.001,
                ),
            ),
        )
        report = format_selective_report(s)
        assert "SELECTIVE ESCALATION REPORT" in report

    def test_report_contains_accuracy(self) -> None:
        s = SelectiveSummary(
            total_scenarios=1,
            escalated_count=0,
            escalation_rate=0.0,
            single_turn_accuracy=0.8,
            selective_accuracy=0.9,
            accuracy_delta=0.1,
            total_cost=0.001,
            single_turn_cost=0.001,
            cost_ratio=1.0,
            results=(),
        )
        report = format_selective_report(s)
        assert "Accuracy Comparison" in report
        assert "Delta" in report

    def test_report_contains_cost(self) -> None:
        s = SelectiveSummary(
            total_scenarios=1,
            escalated_count=0,
            escalation_rate=0.0,
            single_turn_accuracy=1.0,
            selective_accuracy=1.0,
            accuracy_delta=0.0,
            total_cost=0.050,
            single_turn_cost=0.030,
            cost_ratio=0.05 / 0.03,
            results=(),
        )
        report = format_selective_report(s)
        assert "Cost Comparison" in report
        assert "Cost ratio" in report

    def test_report_shows_good_flips(self) -> None:
        s = SelectiveSummary(
            total_scenarios=1,
            escalated_count=1,
            escalation_rate=1.0,
            single_turn_accuracy=0.0,
            selective_accuracy=1.0,
            accuracy_delta=1.0,
            total_cost=0.010,
            single_turn_cost=0.005,
            cost_ratio=2.0,
            results=(
                SelectiveResult(
                    scenario_id="SC-001",
                    scenario_name="test",
                    expected_verdict=VerdictOutcome.THREAT_CONFIRMED,
                    single_turn_verdict=VerdictOutcome.THREAT_DISMISSED,
                    single_turn_confidence=0.50,
                    escalated=True,
                    escalation_reason="uncertainty",
                    final_verdict=VerdictOutcome.THREAT_CONFIRMED,
                    final_correct=True,
                    cost=0.010,
                ),
            ),
        )
        report = format_selective_report(s)
        assert "GOOD FLIPS" in report
