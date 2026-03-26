"""Calibration metrics — quantifying confidence quality.

Session 024: Provides Brier score and Expected Calibration Error (ECE)
to measure how well verdict confidences correspond to actual correctness.

Brier score: Mean squared error between confidence and binary correctness.
  Lower is better. 0.0 = perfect calibration.

ECE: Weighted average of |accuracy - avg_confidence| across equal-width bins.
  Lower is better. Measures systematic calibration error.

Overconfidence/underconfidence ratios: Proportion of predictions in bins
where avg_confidence > accuracy (overconfident) or < accuracy (underconfident).

Public API:
    BinDetail              — frozen dataclass with per-bin breakdown
    CalibrationResult      — frozen dataclass with aggregate metrics
    CalibrationEvaluator   — the evaluator; call .evaluate() -> CalibrationResult
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence, Tuple


@dataclass(frozen=True)
class BinDetail:
    """Per-bin calibration breakdown.

    Attributes:
        bin_lower: Lower bound of the bin (inclusive).
        bin_upper: Upper bound of the bin (exclusive, except last bin).
        count: Number of predictions in this bin.
        avg_confidence: Mean confidence of predictions in bin.
        accuracy: Fraction correct in bin.
        calibration_gap: |accuracy - avg_confidence|.
    """

    bin_lower: float
    bin_upper: float
    count: int
    avg_confidence: float
    accuracy: float
    calibration_gap: float


@dataclass(frozen=True)
class CalibrationResult:
    """Aggregate calibration metrics.

    Attributes:
        brier_score: Mean squared error between confidence and correctness.
        expected_calibration_error: Weighted avg of calibration gaps.
        bin_count: Number of bins used for ECE.
        bin_details: Per-bin breakdown.
        overconfidence_ratio: Proportion of predictions in overconfident bins.
        underconfidence_ratio: Proportion in underconfident bins.
        n_samples: Total predictions evaluated.
    """

    brier_score: float
    expected_calibration_error: float
    bin_count: int
    bin_details: Tuple[BinDetail, ...]
    overconfidence_ratio: float
    underconfidence_ratio: float
    n_samples: int


class CalibrationEvaluator:
    """Computes calibration metrics from (confidence, correctness) pairs.

    Args:
        n_bins: Number of equal-width bins for ECE calculation. Default 10.
    """

    def __init__(self, n_bins: int = 10) -> None:
        if n_bins < 1:
            raise ValueError(f"n_bins must be >= 1, got {n_bins}")
        self._n_bins = n_bins

    @property
    def n_bins(self) -> int:
        """Number of bins for ECE calculation."""
        return self._n_bins

    def evaluate(
        self,
        predictions: Sequence[tuple[float, bool]],
    ) -> CalibrationResult:
        """Compute calibration metrics from predictions.

        Args:
            predictions: Sequence of (confidence, was_correct) pairs.
                confidence must be in [0, 1].

        Returns:
            CalibrationResult with Brier score, ECE, and bin details.
        """
        n = len(predictions)
        if n == 0:
            return CalibrationResult(
                brier_score=0.0,
                expected_calibration_error=0.0,
                bin_count=self._n_bins,
                bin_details=(),
                overconfidence_ratio=0.0,
                underconfidence_ratio=0.0,
                n_samples=0,
            )

        # Brier score: mean((confidence - correct)^2)
        brier = sum(
            (conf - (1.0 if correct else 0.0)) ** 2
            for conf, correct in predictions
        ) / n

        # Bin predictions
        bin_width = 1.0 / self._n_bins
        bins: list[list[tuple[float, bool]]] = [[] for _ in range(self._n_bins)]

        for conf, correct in predictions:
            idx = int(conf / bin_width)
            # Handle conf == 1.0 edge case
            if idx >= self._n_bins:
                idx = self._n_bins - 1
            bins[idx].append((conf, correct))

        # Compute per-bin details
        bin_details: list[BinDetail] = []
        ece = 0.0
        overconf_count = 0
        underconf_count = 0

        for i, bin_preds in enumerate(bins):
            bin_lower = i * bin_width
            bin_upper = (i + 1) * bin_width
            count = len(bin_preds)

            if count == 0:
                bin_details.append(BinDetail(
                    bin_lower=bin_lower,
                    bin_upper=bin_upper,
                    count=0,
                    avg_confidence=0.0,
                    accuracy=0.0,
                    calibration_gap=0.0,
                ))
                continue

            avg_conf = sum(c for c, _ in bin_preds) / count
            acc = sum(1 for _, correct in bin_preds if correct) / count
            gap = abs(acc - avg_conf)

            ece += (count / n) * gap

            if avg_conf > acc:
                overconf_count += count
            elif avg_conf < acc:
                underconf_count += count

            bin_details.append(BinDetail(
                bin_lower=bin_lower,
                bin_upper=bin_upper,
                count=count,
                avg_confidence=avg_conf,
                accuracy=acc,
                calibration_gap=gap,
            ))

        overconf_ratio = overconf_count / n if n > 0 else 0.0
        underconf_ratio = underconf_count / n if n > 0 else 0.0

        return CalibrationResult(
            brier_score=brier,
            expected_calibration_error=ece,
            bin_count=self._n_bins,
            bin_details=tuple(bin_details),
            overconfidence_ratio=overconf_ratio,
            underconfidence_ratio=underconf_ratio,
            n_samples=n,
        )

    def __repr__(self) -> str:
        return f"CalibrationEvaluator(n_bins={self._n_bins})"
