"""Tests for escalation analysis — Session 022.

Tests cover:
1. compute_escalation_metrics with synthetic verdicts
2. sweep_thresholds returns correct number of results
3. format_sweep_report produces readable output
4. Integration: rule-based pipeline → OracleJudge → EscalationGate on full corpus
5. Threshold properties (wider band → more escalations)
"""

from __future__ import annotations

import pytest

from ares.dialectic.agents.patterns import Verdict, VerdictOutcome
from ares.dialectic.coordinator.escalation import EscalationDecision
from ares.dialectic.scripts.escalation_analysis import (
    EscalationMetrics,
    ScenarioEscalationResult,
    compute_escalation_metrics,
    format_sweep_report,
    sweep_thresholds,
)


# =============================================================================
# Helpers
# =============================================================================


def _make_verdict(
    outcome: VerdictOutcome,
    confidence: float,
    architect_confidence: float = 0.5,
    skeptic_confidence: float = 0.5,
) -> Verdict:
    return Verdict(
        outcome=outcome,
        confidence=confidence,
        supporting_fact_ids=frozenset(),
        architect_confidence=architect_confidence,
        skeptic_confidence=skeptic_confidence,
        reasoning="test",
    )


def _make_scenario_verdicts():
    """Create a spread of scenario verdicts for testing."""
    return [
        ("S-01", "THREAT_CONFIRMED", "threat_confirmed",
         _make_verdict(VerdictOutcome.THREAT_CONFIRMED, 0.90, 0.90, 0.30)),
        ("S-02", "THREAT_DISMISSED", "threat_dismissed",
         _make_verdict(VerdictOutcome.THREAT_DISMISSED, 0.85, 0.20, 0.85)),
        ("S-03", "INCONCLUSIVE", "inconclusive",
         _make_verdict(VerdictOutcome.INCONCLUSIVE, 0.50, 0.55, 0.45)),
        ("S-04", "INCONCLUSIVE", "threat_confirmed",
         _make_verdict(VerdictOutcome.THREAT_CONFIRMED, 0.75, 0.75, 0.40)),
        ("S-05", "THREAT_CONFIRMED", "inconclusive",
         _make_verdict(VerdictOutcome.INCONCLUSIVE, 0.55, 0.60, 0.50)),
        ("S-06", "THREAT_DISMISSED", "threat_dismissed",
         _make_verdict(VerdictOutcome.THREAT_DISMISSED, 0.60, 0.25, 0.60)),
    ]


# =============================================================================
# compute_escalation_metrics
# =============================================================================


class TestComputeEscalationMetrics:
    """Test compute_escalation_metrics with synthetic data."""

    def test_basic_counts(self):
        sv = _make_scenario_verdicts()
        m = compute_escalation_metrics(sv, threshold_low=0.35, threshold_high=0.65)
        assert m.total_scenarios == 6

    def test_escalation_identifies_mid_confidence(self):
        sv = _make_scenario_verdicts()
        m = compute_escalation_metrics(sv, threshold_low=0.35, threshold_high=0.65)
        # S-03 (0.50), S-05 (0.55), S-06 (0.60) should escalate
        assert m.escalated_count == 3
        assert m.resolved_count == 3

    def test_error_capture(self):
        sv = _make_scenario_verdicts()
        m = compute_escalation_metrics(sv, threshold_low=0.35, threshold_high=0.65)
        # Errors: S-04 (wrong, conf 0.75 → RESOLVED), S-05 (wrong, conf 0.55 → ESCALATED)
        assert m.errors_total == 2
        assert m.errors_captured == 1  # S-05
        assert m.errors_missed == 1  # S-04

    def test_error_capture_rate(self):
        sv = _make_scenario_verdicts()
        m = compute_escalation_metrics(sv, threshold_low=0.35, threshold_high=0.65)
        assert m.error_capture_rate == pytest.approx(0.5)  # 1/2

    def test_resolved_accuracy(self):
        sv = _make_scenario_verdicts()
        m = compute_escalation_metrics(sv, threshold_low=0.35, threshold_high=0.65)
        # Resolved: S-01 (correct), S-02 (correct), S-04 (wrong) → 2/3
        assert m.resolved_accuracy == pytest.approx(2 / 3)

    def test_escalation_rate(self):
        sv = _make_scenario_verdicts()
        m = compute_escalation_metrics(sv, threshold_low=0.35, threshold_high=0.65)
        assert m.escalation_rate == pytest.approx(3 / 6)

    def test_thresholds_recorded(self):
        sv = _make_scenario_verdicts()
        m = compute_escalation_metrics(sv, threshold_low=0.40, threshold_high=0.70)
        assert m.threshold_low == 0.40
        assert m.threshold_high == 0.70

    def test_per_scenario_populated(self):
        sv = _make_scenario_verdicts()
        m = compute_escalation_metrics(sv, threshold_low=0.35, threshold_high=0.65)
        assert len(m.per_scenario) == 6
        assert all(isinstance(r, ScenarioEscalationResult) for r in m.per_scenario)

    def test_per_scenario_frozen(self):
        sv = _make_scenario_verdicts()
        m = compute_escalation_metrics(sv, threshold_low=0.35, threshold_high=0.65)
        with pytest.raises(AttributeError):
            m.per_scenario[0].decision = EscalationDecision.RESOLVED  # type: ignore[misc]

    def test_empty_scenarios(self):
        m = compute_escalation_metrics([], threshold_low=0.35, threshold_high=0.65)
        assert m.total_scenarios == 0
        assert m.escalation_rate == 0.0
        assert m.error_capture_rate == 0.0

    def test_all_correct_no_errors(self):
        sv = [
            ("S-01", "THREAT_CONFIRMED", "threat_confirmed",
             _make_verdict(VerdictOutcome.THREAT_CONFIRMED, 0.90)),
        ]
        m = compute_escalation_metrics(sv)
        assert m.errors_total == 0
        assert m.error_capture_rate == 0.0
        assert m.resolved_accuracy == 1.0


# =============================================================================
# sweep_thresholds
# =============================================================================


class TestSweepThresholds:
    """Test sweep_thresholds across multiple bands."""

    def test_default_bands_count(self):
        sv = _make_scenario_verdicts()
        results = sweep_thresholds(sv)
        assert len(results) == 9  # default band count

    def test_custom_bands(self):
        sv = _make_scenario_verdicts()
        bands = [(0.35, 0.65), (0.30, 0.70)]
        results = sweep_thresholds(sv, bands=bands)
        assert len(results) == 2

    def test_wider_band_escalates_more(self):
        sv = _make_scenario_verdicts()
        bands = [(0.45, 0.55), (0.30, 0.70)]
        results = sweep_thresholds(sv, bands=bands)
        assert results[1].escalated_count >= results[0].escalated_count

    def test_each_result_is_escalation_metrics(self):
        sv = _make_scenario_verdicts()
        results = sweep_thresholds(sv)
        assert all(isinstance(r, EscalationMetrics) for r in results)


# =============================================================================
# format_sweep_report
# =============================================================================


class TestFormatSweepReport:
    """Test sweep report formatting."""

    def test_report_contains_header(self):
        sv = _make_scenario_verdicts()
        results = sweep_thresholds(sv)
        report = format_sweep_report(results)
        assert "ESCALATION GATE THRESHOLD SWEEP" in report

    def test_report_contains_all_bands(self):
        sv = _make_scenario_verdicts()
        bands = [(0.35, 0.65), (0.30, 0.70)]
        results = sweep_thresholds(sv, bands=bands)
        report = format_sweep_report(results)
        assert "[0.35,0.65]" in report
        assert "[0.30,0.70]" in report

    def test_report_shows_percentages(self):
        sv = _make_scenario_verdicts()
        results = sweep_thresholds(sv, bands=[(0.35, 0.65)])
        report = format_sweep_report(results)
        assert "%" in report

    def test_empty_results_produces_report(self):
        report = format_sweep_report([])
        assert "ESCALATION GATE THRESHOLD SWEEP" in report


# =============================================================================
# Integration: rule-based pipeline → OracleJudge → EscalationGate
# =============================================================================


class TestCorpusIntegration:
    """Run the escalation gate against the full 33-scenario corpus
    using the rule-based pipeline to generate verdicts."""

    def _run_corpus_through_gate(self):
        """Run all 33 scenarios through rule-based pipeline and gate."""
        from ares.dialectic.agents.strategies.live_cycle import (
            run_cycle_with_strategies,
        )
        from ares.dialectic.agents.strategies.rule_based import (
            RuleBasedExplanationFinder,
            RuleBasedNarrativeGenerator,
            RuleBasedThreatAnalyzer,
        )
        from ares.dialectic.scripts.expanded_scenarios import get_full_corpus

        scenarios = list(get_full_corpus())
        scenario_verdicts = []

        for scenario in scenarios:
            cycle_result = run_cycle_with_strategies(
                packet=scenario.packet,
                threat_analyzer=RuleBasedThreatAnalyzer(),
                explanation_finder=RuleBasedExplanationFinder(),
                narrative_generator=RuleBasedNarrativeGenerator(),
                include_narration=False,
            )
            scenario_verdicts.append((
                scenario.metadata.scenario_id,
                scenario.metadata.expected_verdict,
                cycle_result.verdict.outcome.value,
                cycle_result.verdict,
            ))

        return scenarios, scenario_verdicts

    def test_corpus_has_33_scenarios(self):
        _, sv = self._run_corpus_through_gate()
        assert len(sv) == 33

    def test_default_thresholds_produce_valid_metrics(self):
        _, sv = self._run_corpus_through_gate()
        m = compute_escalation_metrics(sv)
        assert 0.0 <= m.escalation_rate <= 1.0
        assert m.escalated_count + m.resolved_count == 33
        assert m.errors_captured <= m.errors_total

    def test_sweep_covers_target_range_properties(self):
        """Verify wider bands produce more escalations (monotonicity)."""
        _, sv = self._run_corpus_through_gate()
        narrow = compute_escalation_metrics(sv, 0.45, 0.55)
        wide = compute_escalation_metrics(sv, 0.30, 0.75)
        assert wide.escalated_count >= narrow.escalated_count

    def test_resolved_accuracy_at_default_thresholds(self):
        """Resolved scenarios should have reasonable accuracy."""
        _, sv = self._run_corpus_through_gate()
        m = compute_escalation_metrics(sv)
        # Rule-based is less accurate than LLM, but resolved should still be decent
        assert m.resolved_accuracy >= 0.3  # Very conservative bound
