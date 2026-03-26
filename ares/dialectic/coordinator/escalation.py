"""Escalation Gate — confidence-based routing for selective escalation.

Session 022: Deterministic gate that examines Oracle verdict confidence
and routes scenarios to either RESOLVED (accept single-turn verdict) or
ESCALATED (send to per-claim debate).

The gate operates on the Verdict produced by OracleJudge.compute_verdict().
It is fully deterministic — no LLM involvement. The threshold band is
configurable; defaults are calibrated to the 33-scenario corpus.

Design source: Phase 3 Battle Plan (Tribunal synthesis — GPT 5.4 Pro,
Gemini 3.1 Pro, Perplexity — unanimous on selective escalation direction).

Public API:
    EscalationDecision  — enum: RESOLVED, ESCALATED
    EscalationResult    — frozen dataclass with decision + diagnostics
    EscalationGate      — the gate itself; call .evaluate(verdict) -> EscalationResult
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from ares.dialectic.agents.patterns import Verdict, VerdictOutcome


class EscalationDecision(Enum):
    """Binary routing decision from the escalation gate.

    RESOLVED: Accept the single-turn verdict as-is. No further debate needed.
    ESCALATED: Verdict confidence is in the uncertainty band. Route to
               per-claim debate for deeper analysis.
    """

    RESOLVED = "resolved"
    ESCALATED = "escalated"


@dataclass(frozen=True)
class EscalationResult:
    """Immutable result from the escalation gate evaluation.

    Captures the decision plus all inputs that drove it, enabling
    full auditability of the routing logic.

    Attributes:
        decision: RESOLVED or ESCALATED.
        verdict: The original Verdict from OracleJudge.
        verdict_confidence: The confidence value that was thresholded.
        threshold_low: Lower bound of the escalation band.
        threshold_high: Upper bound of the escalation band.
        reason: Human-readable explanation of the routing decision.
    """

    decision: EscalationDecision
    verdict: Verdict
    verdict_confidence: float
    threshold_low: float
    threshold_high: float
    reason: str


class EscalationGate:
    """Confidence-based escalation gate.

    Examines the Oracle's verdict confidence and routes to ESCALATED
    if confidence falls within the uncertainty band [threshold_low, threshold_high].
    Scenarios outside the band are RESOLVED.

    The gate is intentionally simple and deterministic. All intelligence
    lives in the Oracle (verdict computation) and the downstream per-claim
    debate (Sessions 023-024). The gate is just a router.

    Threshold semantics:
        - Boundaries are INCLUSIVE: confidence == threshold_low → ESCALATED
        - confidence == threshold_high → ESCALATED
        - This is conservative: borderline cases get extra scrutiny

    Args:
        threshold_low: Lower bound of escalation band. Default 0.35.
        threshold_high: Upper bound of escalation band. Default 0.65.

    Raises:
        ValueError: If thresholds are invalid (low >= high, out of [0,1]).
    """

    def __init__(
        self,
        threshold_low: float = 0.35,
        threshold_high: float = 0.65,
    ) -> None:
        if not 0.0 <= threshold_low <= 1.0:
            raise ValueError(
                f"threshold_low must be in [0.0, 1.0], got {threshold_low}"
            )
        if not 0.0 <= threshold_high <= 1.0:
            raise ValueError(
                f"threshold_high must be in [0.0, 1.0], got {threshold_high}"
            )
        if threshold_low >= threshold_high:
            raise ValueError(
                f"threshold_low ({threshold_low}) must be less than "
                f"threshold_high ({threshold_high})"
            )
        self._threshold_low = threshold_low
        self._threshold_high = threshold_high

    @property
    def threshold_low(self) -> float:
        """Lower bound of escalation band."""
        return self._threshold_low

    @property
    def threshold_high(self) -> float:
        """Upper bound of escalation band."""
        return self._threshold_high

    def evaluate(self, verdict: Verdict) -> EscalationResult:
        """Evaluate a verdict and produce an escalation decision.

        The decision is purely based on the verdict's confidence value:
        - If confidence is in [threshold_low, threshold_high] → ESCALATED
        - Otherwise → RESOLVED

        For INCONCLUSIVE verdicts, confidence = avg(architect, skeptic).
        For THREAT_CONFIRMED, confidence = architect_confidence.
        For THREAT_DISMISSED, confidence = skeptic_confidence.
        (These are set by OracleJudge.compute_verdict, not by this gate.)

        Args:
            verdict: The Verdict from OracleJudge.compute_verdict().

        Returns:
            EscalationResult with the routing decision and diagnostics.
        """
        conf = verdict.confidence
        in_band = self._threshold_low <= conf <= self._threshold_high

        if in_band:
            decision = EscalationDecision.ESCALATED
            reason = (
                f"Verdict confidence {conf:.3f} is within escalation band "
                f"[{self._threshold_low:.2f}, {self._threshold_high:.2f}]. "
                f"Outcome '{verdict.outcome.value}' routed to per-claim debate."
            )
        else:
            decision = EscalationDecision.RESOLVED
            if conf < self._threshold_low:
                reason = (
                    f"Verdict confidence {conf:.3f} is below escalation band "
                    f"(< {self._threshold_low:.2f}). "
                    f"Outcome '{verdict.outcome.value}' accepted as-is."
                )
            else:
                reason = (
                    f"Verdict confidence {conf:.3f} is above escalation band "
                    f"(> {self._threshold_high:.2f}). "
                    f"Outcome '{verdict.outcome.value}' accepted as-is."
                )

        return EscalationResult(
            decision=decision,
            verdict=verdict,
            verdict_confidence=conf,
            threshold_low=self._threshold_low,
            threshold_high=self._threshold_high,
            reason=reason,
        )

    def __repr__(self) -> str:
        return (
            f"EscalationGate(threshold_low={self._threshold_low}, "
            f"threshold_high={self._threshold_high})"
        )
