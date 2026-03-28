"""Tests for miscalibration_analysis script — Session 023.

Tests covering combined gate analysis logic, report formatting,
pattern summary aggregation, and edge cases.
"""

from __future__ import annotations

import pytest
from datetime import datetime, timedelta

from ares.dialectic.scripts.miscalibration_analysis import (
    CombinedGateAnalysis,
    CombinedGateResult,
    ScenarioInput,
    format_combined_report,
    get_miscalibration_patterns_summary,
    run_combined_gate_analysis,
)
from ares.dialectic.coordinator.escalation import EscalationGate
from ares.dialectic.coordinator.miscalibration import (
    MiscalibrationDetector,
    MiscalibrationPattern,
    MiscalibrationRecommendation,
)
from ares.dialectic.agents.patterns import Verdict, VerdictOutcome
from ares.dialectic.evidence.fact import EntityType, Fact
from ares.dialectic.evidence.packet import EvidencePacket, TimeWindow
from ares.dialectic.evidence.provenance import Provenance, SourceType
from ares.dialectic.messages.assertions import Assertion, AssertionType
from ares.dialectic.messages.protocol import (
    DialecticalMessage,
    MessageType,
    Phase,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ts() -> datetime:
    return datetime(2026, 1, 1, 12, 0, 0)


def _make_fact(fact_id: str) -> Fact:
    return Fact(
        fact_id=fact_id,
        entity_id="host-1",
        entity_type=EntityType.NODE,
        field="event",
        value="test",
        timestamp=_ts(),
        provenance=Provenance(
            source_type=SourceType.SYSLOG,
            source_id="test-src",
            extracted_at=_ts(),
        ),
    )


def _make_packet(fact_ids: list[str]) -> EvidencePacket:
    tw = TimeWindow(start=_ts() - timedelta(hours=1), end=_ts())
    pkt = EvidencePacket(packet_id="pkt-001", time_window=tw)
    for fid in fact_ids:
        pkt.add_fact(_make_fact(fid))
    pkt.freeze()
    return pkt


def _make_assertion(fact_ids: tuple[str, ...] = ("f1",)) -> Assertion:
    return Assertion(
        assertion_id="a1",
        assertion_type=AssertionType.ASSERT,
        fact_ids=fact_ids,
        interpretation="test claim",
    )


def _make_message(
    confidence: float = 0.80,
    assertions: list[Assertion] | None = None,
    source_agent: str = "architect",
) -> DialecticalMessage:
    return DialecticalMessage(
        message_id="msg-001",
        timestamp=_ts(),
        source_agent=source_agent,
        target_agent="oracle",
        confidence=confidence,
        assertions=assertions or [],
        phase=Phase.THESIS,
        message_type=MessageType.HYPOTHESIS,
    )


def _make_verdict(confidence: float = 0.80) -> Verdict:
    return Verdict(
        outcome=VerdictOutcome.THREAT_CONFIRMED,
        confidence=confidence,
        supporting_fact_ids=frozenset({"f1"}),
        architect_confidence=confidence,
        skeptic_confidence=0.20,
        reasoning="Test verdict",
    )


def _make_scenario(
    name: str,
    verdict_confidence: float = 0.80,
    is_error: bool = False,
    arch_confidence: float = 0.80,
    skep_confidence: float = 0.20,
    fact_ids: list[str] | None = None,
    assertion_fact_ids: tuple[str, ...] | None = None,
) -> ScenarioInput:
    fids = fact_ids or ["f1", "f2", "f3"]
    afids = assertion_fact_ids or ("f1", "f2", "f3")
    return ScenarioInput(
        scenario_name=name,
        verdict=_make_verdict(verdict_confidence),
        architect_message=_make_message(
            confidence=arch_confidence,
            assertions=[_make_assertion(afids)],
        ),
        skeptic_message=_make_message(
            confidence=skep_confidence,
            source_agent="skeptic",
        ),
        packet=_make_packet(fids),
        is_error=is_error,
    )


# ===========================================================================
# Combined gate analysis
# ===========================================================================

class TestCombinedGateAnalysis:
    """Tests for run_combined_gate_analysis."""

    def test_no_errors_zero_capture_rate(self) -> None:
        """All correct -> combined capture rate 0 (no errors to catch)."""
        scenarios = [_make_scenario("s1"), _make_scenario("s2")]
        result = run_combined_gate_analysis(scenarios)
        assert result.total_scenarios == 2
        assert result.total_errors == 0
        assert result.combined_capture_rate == 0.0

    def test_error_caught_by_escalation(self) -> None:
        """Error in uncertainty band -> caught by escalation gate."""
        # Confidence 0.50 is in default band [0.35, 0.65]
        scenario = _make_scenario("s1", verdict_confidence=0.50, is_error=True)
        result = run_combined_gate_analysis([scenario])
        assert result.total_errors == 1
        assert result.escalation_capture_rate > 0

    def test_error_caught_by_miscalibration(self) -> None:
        """Error with evidence starvation -> caught by miscalibration."""
        # High confidence + only 1 fact cited -> starvation
        scenario = _make_scenario(
            "s1",
            verdict_confidence=0.85,
            is_error=True,
            fact_ids=["f1"],
            assertion_fact_ids=("f1",),
        )
        detector = MiscalibrationDetector(min_facts_for_confidence=3)
        result = run_combined_gate_analysis(
            [scenario], miscalibration_detector=detector
        )
        assert result.total_errors == 1
        assert result.miscalibration_capture_rate > 0

    def test_error_caught_by_neither(self) -> None:
        """Error with high confidence + good evidence -> caught by neither."""
        scenario = _make_scenario(
            "s1",
            verdict_confidence=0.85,
            is_error=True,
            fact_ids=["f1", "f2", "f3"],
            assertion_fact_ids=("f1", "f2", "f3"),
        )
        result = run_combined_gate_analysis([scenario])
        assert result.caught_by_neither == 1

    def test_empty_scenarios(self) -> None:
        """No scenarios -> zero everything."""
        result = run_combined_gate_analysis([])
        assert result.total_scenarios == 0
        assert result.total_errors == 0
        assert result.combined_capture_rate == 0.0

    def test_per_scenario_results_length(self) -> None:
        """Per-scenario results match input count."""
        scenarios = [_make_scenario(f"s{i}") for i in range(5)]
        result = run_combined_gate_analysis(scenarios)
        assert len(result.per_scenario_results) == 5

    def test_combined_rate_counts_union(self) -> None:
        """Combined rate = (esc_only + misc_only + both) / total_errors."""
        # Two errors: one caught by escalation (conf=0.50), one by neither (conf=0.85)
        s1 = _make_scenario("s1", verdict_confidence=0.50, is_error=True)
        s2 = _make_scenario("s2", verdict_confidence=0.85, is_error=True)
        result = run_combined_gate_analysis([s1, s2])
        assert result.total_errors == 2
        # s1 in band -> caught by escalation. s2 not -> depends on misc.
        caught = result.caught_by_escalation_only + result.caught_by_miscalibration_only + result.caught_by_both
        assert result.combined_capture_rate == pytest.approx(caught / 2)


# ===========================================================================
# Report formatting
# ===========================================================================

class TestReportFormatting:
    """Tests for format_combined_report."""

    def test_report_contains_header(self) -> None:
        scenarios = [_make_scenario("test-1")]
        analysis = run_combined_gate_analysis(scenarios)
        report = format_combined_report(analysis)
        assert "COMBINED GATE ANALYSIS REPORT" in report

    def test_report_contains_scenario_names(self) -> None:
        scenarios = [_make_scenario("brute-force-login")]
        analysis = run_combined_gate_analysis(scenarios)
        report = format_combined_report(analysis)
        assert "brute-force-login" in report

    def test_report_contains_error_tag(self) -> None:
        scenarios = [_make_scenario("bad-scenario", is_error=True)]
        analysis = run_combined_gate_analysis(scenarios)
        report = format_combined_report(analysis)
        assert "[ERROR]" in report

    def test_report_capture_rates(self) -> None:
        scenarios = [_make_scenario("s1")]
        analysis = run_combined_gate_analysis(scenarios)
        report = format_combined_report(analysis)
        assert "Capture Rates" in report


# ===========================================================================
# Pattern summary
# ===========================================================================

class TestPatternSummary:
    """Tests for get_miscalibration_patterns_summary."""

    def test_all_patterns_in_summary(self) -> None:
        """Summary contains all four pattern keys."""
        scenarios = [_make_scenario("s1")]
        summary = get_miscalibration_patterns_summary(scenarios)
        assert set(summary.keys()) == set(MiscalibrationPattern)

    def test_counts_are_non_negative(self) -> None:
        scenarios = [_make_scenario("s1")]
        summary = get_miscalibration_patterns_summary(scenarios)
        assert all(v >= 0 for v in summary.values())

    def test_starvation_counted(self) -> None:
        """Evidence starvation scenario increments count."""
        scenario = _make_scenario(
            "s1",
            verdict_confidence=0.85,
            fact_ids=["f1"],
            assertion_fact_ids=("f1",),
        )
        detector = MiscalibrationDetector(min_facts_for_confidence=3)
        summary = get_miscalibration_patterns_summary([scenario], detector=detector)
        assert summary[MiscalibrationPattern.EVIDENCE_STARVATION] == 1

    def test_empty_scenarios_all_zero(self) -> None:
        summary = get_miscalibration_patterns_summary([])
        assert all(v == 0 for v in summary.values())


# ===========================================================================
# Immutability
# ===========================================================================

class TestAnalysisImmutability:
    """Test that analysis output types are frozen."""

    def test_combined_gate_result_frozen(self) -> None:
        scenarios = [_make_scenario("s1")]
        analysis = run_combined_gate_analysis(scenarios)
        with pytest.raises(AttributeError):
            analysis.total_scenarios = 99  # type: ignore[misc]

    def test_per_scenario_result_frozen(self) -> None:
        scenarios = [_make_scenario("s1")]
        analysis = run_combined_gate_analysis(scenarios)
        with pytest.raises(AttributeError):
            analysis.per_scenario_results[0].scenario_name = "x"  # type: ignore[misc]
