"""Tests for CalibrationEvaluator — Session 024.

Comprehensive tests covering perfect calibration, perfect miscalibration,
hand-computed Brier scores, ECE with different bin counts, overconfidence
vs underconfidence detection, edge cases, and immutability.
"""

from __future__ import annotations

import pytest

from ares.dialectic.coordinator.calibration import (
    BinDetail,
    CalibrationEvaluator,
    CalibrationResult,
)


# ===========================================================================
# Construction and defaults
# ===========================================================================

class TestCalibrationEvaluatorConstruction:
    """Test construction and defaults."""

    def test_default_bins(self) -> None:
        e = CalibrationEvaluator()
        assert e.n_bins == 10

    def test_custom_bins(self) -> None:
        e = CalibrationEvaluator(n_bins=5)
        assert e.n_bins == 5

    def test_invalid_bins_raises(self) -> None:
        with pytest.raises(ValueError, match="n_bins"):
            CalibrationEvaluator(n_bins=0)

    def test_repr(self) -> None:
        e = CalibrationEvaluator(n_bins=5)
        assert "CalibrationEvaluator" in repr(e)
        assert "5" in repr(e)


# ===========================================================================
# Perfect calibration
# ===========================================================================

class TestPerfectCalibration:
    """Test scenarios with perfect calibration."""

    def test_perfect_all_correct_confidence_one(self) -> None:
        """All correct with confidence 1.0 -> Brier = 0."""
        e = CalibrationEvaluator()
        preds = [(1.0, True)] * 10
        result = e.evaluate(preds)
        assert result.brier_score == pytest.approx(0.0)

    def test_perfect_all_wrong_confidence_zero(self) -> None:
        """All wrong with confidence 0.0 -> Brier = 0."""
        e = CalibrationEvaluator()
        preds = [(0.0, False)] * 10
        result = e.evaluate(preds)
        assert result.brier_score == pytest.approx(0.0)

    def test_perfect_calibration_mixed(self) -> None:
        """Confidence matches actual rate -> Brier near 0, ECE near 0."""
        e = CalibrationEvaluator(n_bins=2)
        # Low bin: conf=0.25, 25% correct; High bin: conf=0.75, 75% correct
        preds = (
            [(0.25, True)] * 25 + [(0.25, False)] * 75 +
            [(0.75, True)] * 75 + [(0.75, False)] * 25
        )
        result = e.evaluate(preds)
        assert result.expected_calibration_error == pytest.approx(0.0, abs=0.01)


# ===========================================================================
# Perfect miscalibration
# ===========================================================================

class TestPerfectMiscalibration:
    """Test scenarios with maximum miscalibration."""

    def test_always_confident_always_wrong(self) -> None:
        """Confidence 1.0 but always wrong -> Brier = 1.0."""
        e = CalibrationEvaluator()
        preds = [(1.0, False)] * 10
        result = e.evaluate(preds)
        assert result.brier_score == pytest.approx(1.0)

    def test_always_unconfident_always_right(self) -> None:
        """Confidence 0.0 but always correct -> Brier = 1.0."""
        e = CalibrationEvaluator()
        preds = [(0.0, True)] * 10
        result = e.evaluate(preds)
        assert result.brier_score == pytest.approx(1.0)


# ===========================================================================
# Hand-computed Brier scores
# ===========================================================================

class TestBrierScoreCalculation:
    """Tests with hand-computed Brier scores."""

    def test_brier_single_correct(self) -> None:
        """Single correct prediction: (0.8-1.0)^2 = 0.04."""
        e = CalibrationEvaluator()
        result = e.evaluate([(0.8, True)])
        assert result.brier_score == pytest.approx(0.04)

    def test_brier_single_incorrect(self) -> None:
        """Single incorrect prediction: (0.8-0.0)^2 = 0.64."""
        e = CalibrationEvaluator()
        result = e.evaluate([(0.8, False)])
        assert result.brier_score == pytest.approx(0.64)

    def test_brier_two_predictions(self) -> None:
        """Two predictions: ((0.9-1)^2 + (0.6-0)^2) / 2 = (0.01+0.36)/2 = 0.185."""
        e = CalibrationEvaluator()
        result = e.evaluate([(0.9, True), (0.6, False)])
        assert result.brier_score == pytest.approx(0.185)

    def test_brier_half_confidence(self) -> None:
        """All at 0.5: Brier = (0.5-c)^2 = 0.25 regardless of correctness."""
        e = CalibrationEvaluator()
        result = e.evaluate([(0.5, True), (0.5, False)])
        assert result.brier_score == pytest.approx(0.25)


# ===========================================================================
# ECE calculation
# ===========================================================================

class TestECECalculation:
    """Tests for Expected Calibration Error."""

    def test_ece_empty_bins_skipped(self) -> None:
        """Empty bins don't contribute to ECE."""
        e = CalibrationEvaluator(n_bins=10)
        # All predictions in the [0.9, 1.0) bin, all correct
        preds = [(0.95, True)] * 10
        result = e.evaluate(preds)
        # avg_conf=0.95, accuracy=1.0, gap=0.05, weight=1.0 -> ECE=0.05
        assert result.expected_calibration_error == pytest.approx(0.05)

    def test_ece_two_bins(self) -> None:
        """Two populated bins with known gaps."""
        e = CalibrationEvaluator(n_bins=2)
        # bin [0.0, 0.5): conf=0.3, all correct -> acc=1.0, gap=0.7
        # bin [0.5, 1.0): conf=0.8, all wrong -> acc=0.0, gap=0.8
        preds = [(0.3, True)] * 5 + [(0.8, False)] * 5
        result = e.evaluate(preds)
        expected_ece = 0.5 * 0.7 + 0.5 * 0.8  # 0.75
        assert result.expected_calibration_error == pytest.approx(expected_ece)

    def test_ece_different_bin_counts(self) -> None:
        """More bins generally changes ECE."""
        preds = [(0.3, True), (0.7, False), (0.5, True), (0.9, True)]
        e5 = CalibrationEvaluator(n_bins=5)
        e10 = CalibrationEvaluator(n_bins=10)
        r5 = e5.evaluate(preds)
        r10 = e10.evaluate(preds)
        # Different binnings should generally produce different ECE
        assert isinstance(r5.expected_calibration_error, float)
        assert isinstance(r10.expected_calibration_error, float)

    def test_bin_count_matches_n_bins(self) -> None:
        e = CalibrationEvaluator(n_bins=5)
        result = e.evaluate([(0.5, True)])
        assert result.bin_count == 5
        assert len(result.bin_details) == 5


# ===========================================================================
# Overconfidence vs underconfidence
# ===========================================================================

class TestOverUnderConfidence:
    """Tests for overconfidence and underconfidence detection."""

    def test_overconfidence_detected(self) -> None:
        """High confidence, low accuracy -> overconfident."""
        e = CalibrationEvaluator(n_bins=2)
        # bin [0.5, 1.0): all confident, all wrong
        preds = [(0.9, False)] * 10
        result = e.evaluate(preds)
        assert result.overconfidence_ratio == 1.0
        assert result.underconfidence_ratio == 0.0

    def test_underconfidence_detected(self) -> None:
        """Low confidence, high accuracy -> underconfident."""
        e = CalibrationEvaluator(n_bins=2)
        # bin [0.0, 0.5): all unconfident, all correct
        preds = [(0.1, True)] * 10
        result = e.evaluate(preds)
        assert result.underconfidence_ratio == 1.0
        assert result.overconfidence_ratio == 0.0

    def test_perfectly_calibrated_neither(self) -> None:
        """When avg_conf == accuracy -> neither over nor under."""
        e = CalibrationEvaluator(n_bins=1)
        # 50% correct at confidence 0.5 -> perfectly calibrated
        preds = [(0.5, True), (0.5, False)]
        result = e.evaluate(preds)
        assert result.overconfidence_ratio == 0.0
        assert result.underconfidence_ratio == 0.0

    def test_mixed_over_and_under(self) -> None:
        """Some bins overconfident, some underconfident."""
        e = CalibrationEvaluator(n_bins=2)
        # Low bin: conf=0.1, all correct -> underconfident (5 samples)
        # High bin: conf=0.9, all wrong -> overconfident (5 samples)
        preds = [(0.1, True)] * 5 + [(0.9, False)] * 5
        result = e.evaluate(preds)
        assert result.overconfidence_ratio == pytest.approx(0.5)
        assert result.underconfidence_ratio == pytest.approx(0.5)


# ===========================================================================
# Edge cases
# ===========================================================================

class TestEdgeCases:
    """Edge case tests."""

    def test_empty_predictions(self) -> None:
        """No predictions -> zeros everywhere."""
        e = CalibrationEvaluator()
        result = e.evaluate([])
        assert result.brier_score == 0.0
        assert result.expected_calibration_error == 0.0
        assert result.n_samples == 0
        assert result.bin_details == ()

    def test_single_prediction(self) -> None:
        """Single prediction works correctly."""
        e = CalibrationEvaluator()
        result = e.evaluate([(0.7, True)])
        assert result.n_samples == 1
        assert result.brier_score == pytest.approx(0.09)

    def test_all_same_confidence(self) -> None:
        """All predictions at same confidence level."""
        e = CalibrationEvaluator(n_bins=10)
        preds = [(0.75, True)] * 6 + [(0.75, False)] * 4
        result = e.evaluate(preds)
        assert result.n_samples == 10
        # All in bin 7 ([0.7, 0.8)): avg_conf=0.75, acc=0.6
        # ECE = |0.6-0.75| = 0.15
        assert result.expected_calibration_error == pytest.approx(0.15)

    def test_confidence_exactly_one(self) -> None:
        """Confidence 1.0 goes in last bin, not out of range."""
        e = CalibrationEvaluator(n_bins=10)
        result = e.evaluate([(1.0, True)])
        assert result.n_samples == 1
        # Should be in the last bin [0.9, 1.0]
        last_bin = result.bin_details[-1]
        assert last_bin.count == 1

    def test_confidence_exactly_zero(self) -> None:
        """Confidence 0.0 goes in first bin."""
        e = CalibrationEvaluator(n_bins=10)
        result = e.evaluate([(0.0, False)])
        first_bin = result.bin_details[0]
        assert first_bin.count == 1

    def test_n_samples_correct(self) -> None:
        e = CalibrationEvaluator()
        preds = [(0.5, True)] * 42
        result = e.evaluate(preds)
        assert result.n_samples == 42


# ===========================================================================
# BinDetail correctness
# ===========================================================================

class TestBinDetailCorrectness:
    """Tests for individual BinDetail fields."""

    def test_bin_boundaries(self) -> None:
        """Bin boundaries are correct."""
        e = CalibrationEvaluator(n_bins=4)
        result = e.evaluate([(0.5, True)])
        assert result.bin_details[0].bin_lower == pytest.approx(0.0)
        assert result.bin_details[0].bin_upper == pytest.approx(0.25)
        assert result.bin_details[1].bin_lower == pytest.approx(0.25)
        assert result.bin_details[1].bin_upper == pytest.approx(0.5)
        assert result.bin_details[3].bin_lower == pytest.approx(0.75)
        assert result.bin_details[3].bin_upper == pytest.approx(1.0)

    def test_bin_accuracy_correct(self) -> None:
        """Bin accuracy is fraction correct."""
        e = CalibrationEvaluator(n_bins=2)
        # 3 correct + 1 wrong in high bin
        preds = [(0.8, True)] * 3 + [(0.8, False)] * 1
        result = e.evaluate(preds)
        high_bin = result.bin_details[1]
        assert high_bin.accuracy == pytest.approx(0.75)

    def test_bin_avg_confidence(self) -> None:
        """Bin avg_confidence is mean of confidences."""
        e = CalibrationEvaluator(n_bins=2)
        preds = [(0.6, True), (0.8, True)]
        result = e.evaluate(preds)
        high_bin = result.bin_details[1]
        assert high_bin.avg_confidence == pytest.approx(0.7)
        assert high_bin.count == 2

    def test_bin_calibration_gap(self) -> None:
        """Calibration gap = |accuracy - avg_confidence|."""
        e = CalibrationEvaluator(n_bins=2)
        # High bin: conf=0.9, all wrong -> acc=0, gap=0.9
        preds = [(0.9, False)] * 4
        result = e.evaluate(preds)
        high_bin = result.bin_details[1]
        assert high_bin.calibration_gap == pytest.approx(0.9)

    def test_empty_bin_zeroed(self) -> None:
        """Empty bins have count=0 and zero metrics."""
        e = CalibrationEvaluator(n_bins=10)
        # Only populate last bin
        result = e.evaluate([(0.95, True)])
        empty_bin = result.bin_details[0]
        assert empty_bin.count == 0
        assert empty_bin.avg_confidence == 0.0
        assert empty_bin.accuracy == 0.0
        assert empty_bin.calibration_gap == 0.0


# ===========================================================================
# Immutability
# ===========================================================================

class TestImmutability:
    """Test that all output types are frozen."""

    def test_calibration_result_frozen(self) -> None:
        e = CalibrationEvaluator()
        result = e.evaluate([(0.5, True)])
        with pytest.raises(AttributeError):
            result.brier_score = 0.0  # type: ignore[misc]

    def test_bin_detail_frozen(self) -> None:
        detail = BinDetail(
            bin_lower=0.0, bin_upper=0.1,
            count=5, avg_confidence=0.05,
            accuracy=0.6, calibration_gap=0.55,
        )
        with pytest.raises(AttributeError):
            detail.count = 10  # type: ignore[misc]

    def test_bin_details_is_tuple(self) -> None:
        e = CalibrationEvaluator()
        result = e.evaluate([(0.5, True)])
        assert isinstance(result.bin_details, tuple)
