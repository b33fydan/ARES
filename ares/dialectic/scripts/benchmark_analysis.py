"""Benchmark analysis extension — error classification and per-tier accuracy.

Session 021: Adds FP/FN/Miscalibrated classification for every wrong answer
and per-tier accuracy breakdown to benchmark output.

Does NOT modify existing benchmark scripts — this is a new analysis layer
that consumes the existing result types.

Public API:
    classify_error()              -> ErrorType enum value
    analyze_benchmark_errors()    -> list of ErrorClassification
    compute_tier_accuracy()       -> dict of tier -> TierAccuracy
    format_analysis_report()      -> formatted string
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional, Sequence

from ares.dialectic.scripts.scenario_corpus import BenchmarkScenario


# =============================================================================
# Error types
# =============================================================================


class ErrorType(Enum):
    """Classification of wrong benchmark answers.

    FP: False Positive — benign activity classified as threat.
        Operational cost: alert fatigue, wasted analyst time.
    FN: False Negative — genuine threat classified as benign.
        Operational cost: missed attack, potential breach.
    MISCALIBRATED: Clear case classified as INCONCLUSIVE, or ambiguous
        case forced to a binary verdict.
        Operational cost: decision paralysis or false confidence.
    CORRECT: Not an error — verdict matches expected.
    """

    FALSE_POSITIVE = "FP"
    FALSE_NEGATIVE = "FN"
    MISCALIBRATED = "MISCALIBRATED"
    CORRECT = "CORRECT"


@dataclass(frozen=True)
class ErrorClassification:
    """Classification of a single scenario result.

    Attributes:
        scenario_id: Scenario identifier (e.g., "SC-001").
        expected_verdict: Expected verdict from scenario metadata.
        actual_verdict: Actual verdict from the benchmark run.
        error_type: Classification of the error (or CORRECT).
        explanation: Human-readable explanation of why this is classified as such.
    """

    scenario_id: str
    expected_verdict: str
    actual_verdict: str
    error_type: ErrorType
    explanation: str


@dataclass(frozen=True)
class TierAccuracy:
    """Accuracy metrics for a single difficulty tier.

    Attributes:
        tier: Difficulty tier number (1-4).
        tier_name: Human-readable tier name.
        total: Total scenarios in this tier.
        correct: Number of correct verdicts.
        accuracy: Fraction correct (0.0-1.0).
        fp_count: False positives in this tier.
        fn_count: False negatives in this tier.
        miscalibrated_count: Miscalibrated verdicts in this tier.
    """

    tier: int
    tier_name: str
    total: int
    correct: int
    accuracy: float
    fp_count: int
    fn_count: int
    miscalibrated_count: int


# =============================================================================
# Tier name mapping
# =============================================================================

TIER_NAMES = {
    1: "CLEAR_THREAT",
    2: "AMBIGUOUS",
    3: "CLEAR_BENIGN",
    4: "MIXED_SIGNALS",
}


# =============================================================================
# Classification logic
# =============================================================================


def classify_error(
    expected_verdict: str,
    actual_verdict: str,
    difficulty_tier: int,
) -> ErrorType:
    """Classify a single verdict result as FP, FN, MISCALIBRATED, or CORRECT.

    Rules:
    - If verdicts match: CORRECT
    - Expected THREAT_DISMISSED, got THREAT_CONFIRMED: FALSE_POSITIVE
    - Expected THREAT_CONFIRMED, got THREAT_DISMISSED: FALSE_NEGATIVE
    - Expected binary, got INCONCLUSIVE (clear tier): MISCALIBRATED
    - Expected INCONCLUSIVE, got binary (ambiguous tier): MISCALIBRATED
    - Other mismatches: classified by direction of error

    Args:
        expected_verdict: Expected verdict string.
        actual_verdict: Actual verdict string.
        difficulty_tier: Difficulty tier (1-4).

    Returns:
        ErrorType classification.
    """
    exp = expected_verdict.upper()
    act = actual_verdict.upper()

    if act == "ERROR":
        return ErrorType.MISCALIBRATED

    if exp == act:
        return ErrorType.CORRECT

    # False Positive: benign classified as threat
    if exp == "THREAT_DISMISSED" and act == "THREAT_CONFIRMED":
        return ErrorType.FALSE_POSITIVE

    # False Negative: threat classified as benign
    if exp == "THREAT_CONFIRMED" and act == "THREAT_DISMISSED":
        return ErrorType.FALSE_NEGATIVE

    # Miscalibrated: clear case went INCONCLUSIVE, or ambiguous forced binary
    if exp == "INCONCLUSIVE" and act in ("THREAT_CONFIRMED", "THREAT_DISMISSED"):
        return ErrorType.MISCALIBRATED

    if exp in ("THREAT_CONFIRMED", "THREAT_DISMISSED") and act == "INCONCLUSIVE":
        return ErrorType.MISCALIBRATED

    # Fallback for any other mismatch
    return ErrorType.MISCALIBRATED


def _get_explanation(error_type: ErrorType, expected: str, actual: str) -> str:
    """Generate human-readable explanation for an error classification."""
    if error_type == ErrorType.CORRECT:
        return "Verdict matches expected"
    if error_type == ErrorType.FALSE_POSITIVE:
        return f"False positive: benign scenario ({expected}) classified as {actual}"
    if error_type == ErrorType.FALSE_NEGATIVE:
        return f"False negative: threat scenario ({expected}) classified as {actual}"
    return f"Miscalibrated: expected {expected}, got {actual}"


# =============================================================================
# Analysis functions
# =============================================================================


def analyze_benchmark_errors(
    scenarios: Sequence[BenchmarkScenario],
    results: Sequence,
) -> list[ErrorClassification]:
    """Classify errors for every scenario result.

    Args:
        scenarios: List of BenchmarkScenario instances.
        results: List of result objects with scenario_id and verdict_outcome attrs.
            Works with both ScenarioResult and MultiTurnScenarioResult.

    Returns:
        List of ErrorClassification for each scenario.
    """
    # Build lookup for expected verdicts and tiers
    meta_by_id = {
        s.metadata.scenario_id: s.metadata for s in scenarios
    }

    classifications = []
    for r in results:
        meta = meta_by_id.get(r.scenario_id)
        if meta is None:
            continue

        expected = meta.expected_verdict
        actual = r.verdict_outcome
        error_type = classify_error(expected, actual, meta.difficulty_tier)
        explanation = _get_explanation(error_type, expected, actual)

        classifications.append(ErrorClassification(
            scenario_id=r.scenario_id,
            expected_verdict=expected,
            actual_verdict=actual,
            error_type=error_type,
            explanation=explanation,
        ))

    return classifications


def compute_tier_accuracy(
    scenarios: Sequence[BenchmarkScenario],
    classifications: Sequence[ErrorClassification],
) -> dict[int, TierAccuracy]:
    """Compute per-tier accuracy breakdown.

    Args:
        scenarios: List of BenchmarkScenario instances.
        classifications: List of ErrorClassification from analyze_benchmark_errors.

    Returns:
        Dict mapping tier number to TierAccuracy.
    """
    meta_by_id = {s.metadata.scenario_id: s.metadata for s in scenarios}
    class_by_id = {c.scenario_id: c for c in classifications}

    # Group by tier
    tier_data: dict[int, list[ErrorClassification]] = {}
    for sid, meta in meta_by_id.items():
        tier = meta.difficulty_tier
        if tier not in tier_data:
            tier_data[tier] = []
        cls = class_by_id.get(sid)
        if cls is not None:
            tier_data[tier].append(cls)

    result = {}
    for tier, items in sorted(tier_data.items()):
        total = len(items)
        correct = sum(1 for c in items if c.error_type == ErrorType.CORRECT)
        fp = sum(1 for c in items if c.error_type == ErrorType.FALSE_POSITIVE)
        fn = sum(1 for c in items if c.error_type == ErrorType.FALSE_NEGATIVE)
        misc = sum(1 for c in items if c.error_type == ErrorType.MISCALIBRATED)
        accuracy = correct / total if total > 0 else 0.0

        result[tier] = TierAccuracy(
            tier=tier,
            tier_name=TIER_NAMES.get(tier, f"TIER_{tier}"),
            total=total,
            correct=correct,
            accuracy=accuracy,
            fp_count=fp,
            fn_count=fn,
            miscalibrated_count=misc,
        )

    return result


def format_analysis_report(
    label: str,
    classifications: list[ErrorClassification],
    tier_accuracy: dict[int, TierAccuracy],
) -> str:
    """Format a complete analysis report.

    Args:
        label: Run label (e.g., "Single-Turn LLM").
        classifications: Error classifications for all scenarios.
        tier_accuracy: Per-tier accuracy breakdown.

    Returns:
        Formatted report string.
    """
    lines = []
    lines.append(f"\n{'=' * 70}")
    lines.append(f"  ERROR ANALYSIS: {label}")
    lines.append(f"{'=' * 70}")

    # Summary counts
    fp = sum(1 for c in classifications if c.error_type == ErrorType.FALSE_POSITIVE)
    fn = sum(1 for c in classifications if c.error_type == ErrorType.FALSE_NEGATIVE)
    misc = sum(1 for c in classifications if c.error_type == ErrorType.MISCALIBRATED)
    correct = sum(1 for c in classifications if c.error_type == ErrorType.CORRECT)
    total = len(classifications)

    lines.append(f"\nSummary: {correct}/{total} correct")
    lines.append(f"  False Positives (FP):  {fp}")
    lines.append(f"  False Negatives (FN):  {fn}")
    lines.append(f"  Miscalibrated:         {misc}")

    # Per-tier breakdown
    lines.append(f"\n{'Tier':<20} {'Total':>6} {'Correct':>8} {'Acc':>7} {'FP':>4} {'FN':>4} {'Misc':>5}")
    lines.append("-" * 58)
    for tier in sorted(tier_accuracy):
        ta = tier_accuracy[tier]
        lines.append(
            f"{ta.tier_name:<20} {ta.total:>6} {ta.correct:>8} "
            f"{ta.accuracy:>6.0%} {ta.fp_count:>4} {ta.fn_count:>4} "
            f"{ta.miscalibrated_count:>5}"
        )

    # Wrong answers detail
    wrong = [c for c in classifications if c.error_type != ErrorType.CORRECT]
    if wrong:
        lines.append(f"\nWrong Answers ({len(wrong)}):")
        for c in wrong:
            lines.append(
                f"  {c.scenario_id}: {c.error_type.value} — {c.explanation}"
            )

    return "\n".join(lines)
