"""Escalation gate analysis — threshold sweep and escalation rate metrics.

Session 022: Analyzes how the EscalationGate performs across the scenario
corpus at various threshold bands. Computes escalation rate, error capture
rate, and identifies optimal thresholds.

Designed to work with both rule-based verdicts (offline, no API key)
and live LLM benchmark results.

Public API:
    compute_escalation_metrics()  -> EscalationMetrics for a single threshold
    sweep_thresholds()            -> list of EscalationMetrics across bands
    format_sweep_report()         -> formatted report string
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from ares.dialectic.agents.patterns import Verdict
from ares.dialectic.coordinator.escalation import (
    EscalationDecision,
    EscalationGate,
)


@dataclass(frozen=True)
class ScenarioEscalationResult:
    """Escalation analysis for a single scenario.

    Attributes:
        scenario_id: Scenario identifier.
        expected_verdict: Expected verdict string.
        actual_verdict: Actual verdict string.
        verdict_confidence: The confidence value the gate thresholds on.
        decision: RESOLVED or ESCALATED.
        is_correct: Whether the actual verdict matches expected.
        is_error_captured: True if the verdict is wrong AND the gate escalated it.
    """

    scenario_id: str
    expected_verdict: str
    actual_verdict: str
    verdict_confidence: float
    decision: EscalationDecision
    is_correct: bool
    is_error_captured: bool


@dataclass(frozen=True)
class EscalationMetrics:
    """Aggregate metrics for a single threshold configuration.

    Attributes:
        threshold_low: Lower bound of escalation band.
        threshold_high: Upper bound of escalation band.
        total_scenarios: Number of scenarios evaluated.
        escalated_count: Number routed to ESCALATED.
        resolved_count: Number routed to RESOLVED.
        escalation_rate: Fraction escalated.
        errors_total: Total wrong answers.
        errors_captured: Wrong answers that were escalated (could be corrected).
        errors_missed: Wrong answers that were resolved (accepted as-is).
        error_capture_rate: Fraction of errors that would be sent to per-claim debate.
        resolved_accuracy: Accuracy among RESOLVED scenarios only.
        per_scenario: Per-scenario detail.
    """

    threshold_low: float
    threshold_high: float
    total_scenarios: int
    escalated_count: int
    resolved_count: int
    escalation_rate: float
    errors_total: int
    errors_captured: int
    errors_missed: int
    error_capture_rate: float
    resolved_accuracy: float
    per_scenario: tuple[ScenarioEscalationResult, ...]


def compute_escalation_metrics(
    scenario_verdicts: Sequence[tuple[str, str, str, Verdict]],
    threshold_low: float = 0.35,
    threshold_high: float = 0.65,
) -> EscalationMetrics:
    """Compute escalation metrics for a given threshold band.

    Args:
        scenario_verdicts: Sequence of (scenario_id, expected_verdict,
            actual_verdict, verdict) tuples.
        threshold_low: Lower bound of escalation band.
        threshold_high: Upper bound of escalation band.

    Returns:
        EscalationMetrics with aggregate and per-scenario results.
    """
    gate = EscalationGate(
        threshold_low=threshold_low,
        threshold_high=threshold_high,
    )

    results = []
    for scenario_id, expected, actual, verdict in scenario_verdicts:
        esc_result = gate.evaluate(verdict)
        is_correct = actual.lower() == expected.lower()
        is_error_captured = (not is_correct) and (
            esc_result.decision == EscalationDecision.ESCALATED
        )

        results.append(ScenarioEscalationResult(
            scenario_id=scenario_id,
            expected_verdict=expected,
            actual_verdict=actual,
            verdict_confidence=verdict.confidence,
            decision=esc_result.decision,
            is_correct=is_correct,
            is_error_captured=is_error_captured,
        ))

    total = len(results)
    escalated = sum(1 for r in results if r.decision == EscalationDecision.ESCALATED)
    resolved = total - escalated
    errors_total = sum(1 for r in results if not r.is_correct)
    errors_captured = sum(1 for r in results if r.is_error_captured)
    errors_missed = errors_total - errors_captured

    resolved_correct = sum(
        1 for r in results
        if r.decision == EscalationDecision.RESOLVED and r.is_correct
    )
    resolved_accuracy = resolved_correct / resolved if resolved > 0 else 1.0

    return EscalationMetrics(
        threshold_low=threshold_low,
        threshold_high=threshold_high,
        total_scenarios=total,
        escalated_count=escalated,
        resolved_count=resolved,
        escalation_rate=escalated / total if total > 0 else 0.0,
        errors_total=errors_total,
        errors_captured=errors_captured,
        errors_missed=errors_missed,
        error_capture_rate=errors_captured / errors_total if errors_total > 0 else 0.0,
        resolved_accuracy=resolved_accuracy,
        per_scenario=tuple(results),
    )


def sweep_thresholds(
    scenario_verdicts: Sequence[tuple[str, str, str, Verdict]],
    bands: Sequence[tuple[float, float]] | None = None,
) -> list[EscalationMetrics]:
    """Sweep multiple threshold bands and compute metrics for each.

    Args:
        scenario_verdicts: Sequence of (scenario_id, expected_verdict,
            actual_verdict, verdict) tuples.
        bands: Optional list of (low, high) threshold pairs to test.
            If None, uses a default sweep from narrow to wide.

    Returns:
        List of EscalationMetrics, one per band.
    """
    if bands is None:
        bands = [
            (0.35, 0.55),
            (0.35, 0.60),
            (0.35, 0.65),
            (0.35, 0.70),
            (0.35, 0.75),
            (0.30, 0.70),
            (0.30, 0.75),
            (0.40, 0.70),
            (0.40, 0.75),
        ]

    return [
        compute_escalation_metrics(scenario_verdicts, low, high)
        for low, high in bands
    ]


def format_sweep_report(metrics_list: list[EscalationMetrics]) -> str:
    """Format a threshold sweep report.

    Args:
        metrics_list: List of EscalationMetrics from sweep_thresholds().

    Returns:
        Formatted report string.
    """
    lines = []
    lines.append(f"\n{'=' * 85}")
    lines.append("  ESCALATION GATE THRESHOLD SWEEP")
    lines.append(f"{'=' * 85}")
    lines.append(
        f"{'Band':>12} {'Esc Rate':>10} {'Esc#':>5} {'Res#':>5} "
        f"{'Errors':>7} {'Captured':>9} {'Missed':>7} "
        f"{'Capture%':>9} {'Res Acc':>8}"
    )
    lines.append("-" * 85)

    for m in metrics_list:
        band = f"[{m.threshold_low:.2f},{m.threshold_high:.2f}]"
        lines.append(
            f"{band:>12} {m.escalation_rate:>9.1%} {m.escalated_count:>5} "
            f"{m.resolved_count:>5} {m.errors_total:>7} "
            f"{m.errors_captured:>9} {m.errors_missed:>7} "
            f"{m.error_capture_rate:>8.0%} {m.resolved_accuracy:>7.1%}"
        )

    # Highlight bands in target range (15-25% escalation)
    target = [m for m in metrics_list if 0.15 <= m.escalation_rate <= 0.25]
    if target:
        lines.append(f"\nBands in target range (15-25% escalation rate):")
        for m in target:
            lines.append(
                f"  [{m.threshold_low:.2f}, {m.threshold_high:.2f}] — "
                f"{m.escalation_rate:.1%} escalation, "
                f"{m.error_capture_rate:.0%} error capture, "
                f"{m.resolved_accuracy:.1%} resolved accuracy"
            )
    else:
        lines.append("\nNo bands in target range (15-25% escalation rate).")

    return "\n".join(lines)
