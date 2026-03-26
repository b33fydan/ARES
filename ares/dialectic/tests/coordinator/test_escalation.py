"""Tests for the escalation gate — Session 022.

Tests cover:
1. Basic threshold logic (RESOLVED vs ESCALATED)
2. Boundary conditions (exactly at thresholds — inclusive)
3. All three verdict outcome types
4. Configurable threshold bands
5. Frozen dataclass invariants on EscalationResult
6. Gate construction validation
7. Confidence edge cases (0.0, 1.0)
8. Escalation rate on synthetic corpus sweep
"""

from __future__ import annotations

import pytest

from ares.dialectic.agents.patterns import Verdict, VerdictOutcome
from ares.dialectic.coordinator.escalation import (
    EscalationDecision,
    EscalationGate,
    EscalationResult,
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
    """Create a Verdict with minimal required fields."""
    return Verdict(
        outcome=outcome,
        confidence=confidence,
        supporting_fact_ids=frozenset(),
        architect_confidence=architect_confidence,
        skeptic_confidence=skeptic_confidence,
        reasoning="test verdict",
    )


# =============================================================================
# Gate construction
# =============================================================================


class TestGateConstruction:
    """Test EscalationGate initialization and validation."""

    def test_default_thresholds(self):
        gate = EscalationGate()
        assert gate.threshold_low == 0.35
        assert gate.threshold_high == 0.65

    def test_custom_thresholds(self):
        gate = EscalationGate(threshold_low=0.40, threshold_high=0.70)
        assert gate.threshold_low == 0.40
        assert gate.threshold_high == 0.70

    def test_low_must_be_less_than_high(self):
        with pytest.raises(ValueError, match="must be less than"):
            EscalationGate(threshold_low=0.65, threshold_high=0.35)

    def test_equal_thresholds_rejected(self):
        with pytest.raises(ValueError, match="must be less than"):
            EscalationGate(threshold_low=0.50, threshold_high=0.50)

    def test_low_below_zero_rejected(self):
        with pytest.raises(ValueError, match="threshold_low"):
            EscalationGate(threshold_low=-0.1, threshold_high=0.65)

    def test_high_above_one_rejected(self):
        with pytest.raises(ValueError, match="threshold_high"):
            EscalationGate(threshold_low=0.35, threshold_high=1.1)

    def test_low_at_zero_valid(self):
        gate = EscalationGate(threshold_low=0.0, threshold_high=0.5)
        assert gate.threshold_low == 0.0

    def test_high_at_one_valid(self):
        gate = EscalationGate(threshold_low=0.5, threshold_high=1.0)
        assert gate.threshold_high == 1.0

    def test_narrow_band_valid(self):
        gate = EscalationGate(threshold_low=0.49, threshold_high=0.51)
        assert gate.threshold_high - gate.threshold_low == pytest.approx(0.02)

    def test_repr(self):
        gate = EscalationGate(threshold_low=0.35, threshold_high=0.65)
        r = repr(gate)
        assert "0.35" in r
        assert "0.65" in r


# =============================================================================
# Basic threshold logic
# =============================================================================


class TestBasicThresholdLogic:
    """Test core RESOLVED/ESCALATED routing."""

    def test_high_confidence_threat_confirmed_resolves(self):
        gate = EscalationGate()
        verdict = _make_verdict(VerdictOutcome.THREAT_CONFIRMED, 0.90, 0.90, 0.30)
        result = gate.evaluate(verdict)
        assert result.decision == EscalationDecision.RESOLVED

    def test_high_confidence_threat_dismissed_resolves(self):
        gate = EscalationGate()
        verdict = _make_verdict(VerdictOutcome.THREAT_DISMISSED, 0.90, 0.20, 0.90)
        result = gate.evaluate(verdict)
        assert result.decision == EscalationDecision.RESOLVED

    def test_mid_confidence_inconclusive_escalates(self):
        gate = EscalationGate()
        verdict = _make_verdict(VerdictOutcome.INCONCLUSIVE, 0.50, 0.60, 0.40)
        result = gate.evaluate(verdict)
        assert result.decision == EscalationDecision.ESCALATED

    def test_low_confidence_resolves(self):
        gate = EscalationGate()
        verdict = _make_verdict(VerdictOutcome.THREAT_DISMISSED, 0.20, 0.10, 0.20)
        result = gate.evaluate(verdict)
        assert result.decision == EscalationDecision.RESOLVED

    def test_very_high_confidence_resolves(self):
        gate = EscalationGate()
        verdict = _make_verdict(VerdictOutcome.THREAT_CONFIRMED, 1.0, 1.0, 0.0)
        result = gate.evaluate(verdict)
        assert result.decision == EscalationDecision.RESOLVED

    def test_zero_confidence_resolves(self):
        gate = EscalationGate()
        verdict = _make_verdict(VerdictOutcome.THREAT_DISMISSED, 0.0, 0.0, 0.0)
        result = gate.evaluate(verdict)
        assert result.decision == EscalationDecision.RESOLVED


# =============================================================================
# Boundary conditions (inclusive)
# =============================================================================


class TestBoundaryConditions:
    """Test that threshold boundaries are inclusive (conservative)."""

    def test_exactly_at_low_threshold_escalates(self):
        gate = EscalationGate()  # 0.35/0.65
        verdict = _make_verdict(VerdictOutcome.INCONCLUSIVE, 0.35)
        result = gate.evaluate(verdict)
        assert result.decision == EscalationDecision.ESCALATED

    def test_exactly_at_high_threshold_escalates(self):
        gate = EscalationGate()
        verdict = _make_verdict(VerdictOutcome.INCONCLUSIVE, 0.65)
        result = gate.evaluate(verdict)
        assert result.decision == EscalationDecision.ESCALATED

    def test_just_below_low_threshold_resolves(self):
        gate = EscalationGate()
        verdict = _make_verdict(VerdictOutcome.INCONCLUSIVE, 0.349)
        result = gate.evaluate(verdict)
        assert result.decision == EscalationDecision.RESOLVED

    def test_just_above_high_threshold_resolves(self):
        gate = EscalationGate()
        verdict = _make_verdict(VerdictOutcome.INCONCLUSIVE, 0.651)
        result = gate.evaluate(verdict)
        assert result.decision == EscalationDecision.RESOLVED

    def test_custom_thresholds_boundary_low(self):
        gate = EscalationGate(threshold_low=0.40, threshold_high=0.70)
        verdict = _make_verdict(VerdictOutcome.INCONCLUSIVE, 0.40)
        assert gate.evaluate(verdict).decision == EscalationDecision.ESCALATED

    def test_custom_thresholds_boundary_high(self):
        gate = EscalationGate(threshold_low=0.40, threshold_high=0.70)
        verdict = _make_verdict(VerdictOutcome.INCONCLUSIVE, 0.70)
        assert gate.evaluate(verdict).decision == EscalationDecision.ESCALATED

    def test_custom_thresholds_just_outside_low(self):
        gate = EscalationGate(threshold_low=0.40, threshold_high=0.70)
        verdict = _make_verdict(VerdictOutcome.INCONCLUSIVE, 0.399)
        assert gate.evaluate(verdict).decision == EscalationDecision.RESOLVED

    def test_custom_thresholds_just_outside_high(self):
        gate = EscalationGate(threshold_low=0.40, threshold_high=0.70)
        verdict = _make_verdict(VerdictOutcome.INCONCLUSIVE, 0.701)
        assert gate.evaluate(verdict).decision == EscalationDecision.RESOLVED


# =============================================================================
# All three verdict outcome types
# =============================================================================


class TestVerdictOutcomeTypes:
    """Test escalation logic works for all VerdictOutcome values."""

    def test_threat_confirmed_in_band_escalates(self):
        gate = EscalationGate()
        verdict = _make_verdict(VerdictOutcome.THREAT_CONFIRMED, 0.50, 0.50, 0.30)
        result = gate.evaluate(verdict)
        assert result.decision == EscalationDecision.ESCALATED

    def test_threat_dismissed_in_band_escalates(self):
        gate = EscalationGate()
        verdict = _make_verdict(VerdictOutcome.THREAT_DISMISSED, 0.50, 0.20, 0.50)
        result = gate.evaluate(verdict)
        assert result.decision == EscalationDecision.ESCALATED

    def test_inconclusive_in_band_escalates(self):
        gate = EscalationGate()
        verdict = _make_verdict(VerdictOutcome.INCONCLUSIVE, 0.50, 0.50, 0.50)
        result = gate.evaluate(verdict)
        assert result.decision == EscalationDecision.ESCALATED

    def test_threat_confirmed_above_band_resolves(self):
        gate = EscalationGate()
        verdict = _make_verdict(VerdictOutcome.THREAT_CONFIRMED, 0.85, 0.85, 0.30)
        result = gate.evaluate(verdict)
        assert result.decision == EscalationDecision.RESOLVED

    def test_threat_dismissed_above_band_resolves(self):
        gate = EscalationGate()
        verdict = _make_verdict(VerdictOutcome.THREAT_DISMISSED, 0.85, 0.20, 0.85)
        result = gate.evaluate(verdict)
        assert result.decision == EscalationDecision.RESOLVED

    def test_inconclusive_above_band_resolves(self):
        gate = EscalationGate()
        verdict = _make_verdict(VerdictOutcome.INCONCLUSIVE, 0.80, 0.85, 0.75)
        result = gate.evaluate(verdict)
        assert result.decision == EscalationDecision.RESOLVED


# =============================================================================
# EscalationResult invariants
# =============================================================================


class TestEscalationResultInvariants:
    """Test EscalationResult frozen dataclass properties."""

    def test_result_is_frozen(self):
        gate = EscalationGate()
        verdict = _make_verdict(VerdictOutcome.INCONCLUSIVE, 0.50)
        result = gate.evaluate(verdict)
        with pytest.raises(AttributeError):
            result.decision = EscalationDecision.RESOLVED  # type: ignore[misc]

    def test_result_contains_original_verdict(self):
        gate = EscalationGate()
        verdict = _make_verdict(VerdictOutcome.THREAT_CONFIRMED, 0.90, 0.90, 0.30)
        result = gate.evaluate(verdict)
        assert result.verdict is verdict

    def test_result_records_confidence(self):
        gate = EscalationGate()
        verdict = _make_verdict(VerdictOutcome.INCONCLUSIVE, 0.525)
        result = gate.evaluate(verdict)
        assert result.verdict_confidence == 0.525

    def test_result_records_thresholds(self):
        gate = EscalationGate(threshold_low=0.40, threshold_high=0.70)
        verdict = _make_verdict(VerdictOutcome.INCONCLUSIVE, 0.55)
        result = gate.evaluate(verdict)
        assert result.threshold_low == 0.40
        assert result.threshold_high == 0.70

    def test_result_has_reason_for_escalation(self):
        gate = EscalationGate()
        verdict = _make_verdict(VerdictOutcome.INCONCLUSIVE, 0.50)
        result = gate.evaluate(verdict)
        assert "within escalation band" in result.reason
        assert "per-claim debate" in result.reason

    def test_result_has_reason_for_resolution_above(self):
        gate = EscalationGate()
        verdict = _make_verdict(VerdictOutcome.THREAT_CONFIRMED, 0.90)
        result = gate.evaluate(verdict)
        assert "above escalation band" in result.reason

    def test_result_has_reason_for_resolution_below(self):
        gate = EscalationGate()
        verdict = _make_verdict(VerdictOutcome.THREAT_DISMISSED, 0.20)
        result = gate.evaluate(verdict)
        assert "below escalation band" in result.reason

    def test_reason_includes_confidence_value(self):
        gate = EscalationGate()
        verdict = _make_verdict(VerdictOutcome.INCONCLUSIVE, 0.525)
        result = gate.evaluate(verdict)
        assert "0.525" in result.reason

    def test_reason_includes_outcome_name(self):
        gate = EscalationGate()
        verdict = _make_verdict(VerdictOutcome.THREAT_CONFIRMED, 0.50)
        result = gate.evaluate(verdict)
        assert "threat_confirmed" in result.reason


# =============================================================================
# Escalation decision enum
# =============================================================================


class TestEscalationDecisionEnum:
    """Test EscalationDecision enum values."""

    def test_resolved_value(self):
        assert EscalationDecision.RESOLVED.value == "resolved"

    def test_escalated_value(self):
        assert EscalationDecision.ESCALATED.value == "escalated"

    def test_exactly_two_members(self):
        assert len(EscalationDecision) == 2


# =============================================================================
# Threshold sweep — escalation rate properties
# =============================================================================


class TestThresholdSweep:
    """Test escalation rate behavior across threshold configurations."""

    def _make_spread_verdicts(self) -> list[Verdict]:
        """Create a set of verdicts spanning the confidence range."""
        verdicts = []
        for conf_x10 in range(0, 11):
            conf = conf_x10 / 10.0
            if conf <= 0.3:
                outcome = VerdictOutcome.THREAT_DISMISSED
            elif conf >= 0.7:
                outcome = VerdictOutcome.THREAT_CONFIRMED
            else:
                outcome = VerdictOutcome.INCONCLUSIVE
            verdicts.append(_make_verdict(outcome, conf))
        return verdicts

    def test_wider_band_escalates_more(self):
        verdicts = self._make_spread_verdicts()
        narrow = EscalationGate(threshold_low=0.45, threshold_high=0.55)
        wide = EscalationGate(threshold_low=0.30, threshold_high=0.70)

        narrow_esc = sum(
            1 for v in verdicts if narrow.evaluate(v).decision == EscalationDecision.ESCALATED
        )
        wide_esc = sum(
            1 for v in verdicts if wide.evaluate(v).decision == EscalationDecision.ESCALATED
        )
        assert wide_esc >= narrow_esc

    def test_zero_width_impossible(self):
        """Equal thresholds are rejected at construction."""
        with pytest.raises(ValueError):
            EscalationGate(threshold_low=0.50, threshold_high=0.50)

    def test_full_range_escalates_everything(self):
        verdicts = self._make_spread_verdicts()
        gate = EscalationGate(threshold_low=0.0, threshold_high=1.0)
        escalated = sum(
            1 for v in verdicts if gate.evaluate(v).decision == EscalationDecision.ESCALATED
        )
        assert escalated == len(verdicts)

    def test_minimal_band_escalates_few(self):
        verdicts = self._make_spread_verdicts()
        gate = EscalationGate(threshold_low=0.49, threshold_high=0.51)
        escalated = sum(
            1 for v in verdicts if gate.evaluate(v).decision == EscalationDecision.ESCALATED
        )
        assert escalated <= 2  # Only 0.5 hits this narrow band


# =============================================================================
# Integration with real Verdict construction
# =============================================================================


class TestIntegrationWithVerdict:
    """Test gate works with Verdicts as OracleJudge would produce them."""

    def test_threat_confirmed_confidence_is_architect(self):
        """For THREAT_CONFIRMED, OracleJudge sets confidence = architect_confidence."""
        verdict = Verdict(
            outcome=VerdictOutcome.THREAT_CONFIRMED,
            confidence=0.85,
            supporting_fact_ids=frozenset({"f1", "f2"}),
            architect_confidence=0.85,
            skeptic_confidence=0.30,
            reasoning="Architect claims prevail",
        )
        gate = EscalationGate()
        result = gate.evaluate(verdict)
        assert result.decision == EscalationDecision.RESOLVED
        assert result.verdict_confidence == 0.85

    def test_threat_dismissed_confidence_is_skeptic(self):
        """For THREAT_DISMISSED, OracleJudge sets confidence = skeptic_confidence."""
        verdict = Verdict(
            outcome=VerdictOutcome.THREAT_DISMISSED,
            confidence=0.90,
            supporting_fact_ids=frozenset({"f3"}),
            architect_confidence=0.20,
            skeptic_confidence=0.90,
            reasoning="Skeptic explanation prevails",
        )
        gate = EscalationGate()
        result = gate.evaluate(verdict)
        assert result.decision == EscalationDecision.RESOLVED
        assert result.verdict_confidence == 0.90

    def test_inconclusive_confidence_is_average(self):
        """For INCONCLUSIVE, OracleJudge sets confidence = avg(arch, skep)."""
        verdict = Verdict(
            outcome=VerdictOutcome.INCONCLUSIVE,
            confidence=0.525,  # avg(0.45, 0.60)
            supporting_fact_ids=frozenset({"f1", "f2", "f3"}),
            architect_confidence=0.45,
            skeptic_confidence=0.60,
            reasoning="Neither side prevails",
        )
        gate = EscalationGate()
        result = gate.evaluate(verdict)
        assert result.decision == EscalationDecision.ESCALATED
        assert result.verdict_confidence == 0.525

    def test_weak_threat_confirmed_in_band_escalates(self):
        """A weak THREAT_CONFIRMED (low architect confidence) should escalate."""
        verdict = Verdict(
            outcome=VerdictOutcome.THREAT_CONFIRMED,
            confidence=0.55,
            supporting_fact_ids=frozenset({"f1"}),
            architect_confidence=0.55,
            skeptic_confidence=0.45,
            reasoning="Marginal threat confirmation",
        )
        gate = EscalationGate()
        result = gate.evaluate(verdict)
        assert result.decision == EscalationDecision.ESCALATED
