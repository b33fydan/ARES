"""Tests for benchmark analysis — error classification and per-tier accuracy.

Session 021: Validates FP/FN/Miscalibrated classification logic and
tier accuracy computation.
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from ares.dialectic.scripts.benchmark_analysis import (
    ErrorType,
    classify_error,
    analyze_benchmark_errors,
    compute_tier_accuracy,
    format_analysis_report,
)


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------


@dataclass(frozen=True)
class _MockResult:
    """Minimal result object for testing."""
    scenario_id: str
    verdict_outcome: str


@dataclass(frozen=True)
class _MockMetadata:
    scenario_id: str
    expected_verdict: str
    difficulty_tier: int
    name: str = ""
    description: str = ""
    mitre_attack_ids: tuple = ()
    mitre_tactic: str = ""
    expected_winner: str = ""
    fact_count: int = 0
    notes: str = ""


@dataclass(frozen=True)
class _MockScenario:
    metadata: _MockMetadata
    packet: object = None


# ------------------------------------------------------------------
# classify_error
# ------------------------------------------------------------------


class TestClassifyError:
    """Error classification logic."""

    def test_correct_verdict_returns_correct(self):
        assert classify_error("THREAT_CONFIRMED", "THREAT_CONFIRMED", 1) == ErrorType.CORRECT

    def test_benign_classified_as_threat_is_fp(self):
        assert classify_error("THREAT_DISMISSED", "THREAT_CONFIRMED", 3) == ErrorType.FALSE_POSITIVE

    def test_threat_classified_as_benign_is_fn(self):
        assert classify_error("THREAT_CONFIRMED", "THREAT_DISMISSED", 1) == ErrorType.FALSE_NEGATIVE

    def test_inconclusive_expected_threat_confirmed_is_miscalibrated(self):
        assert classify_error("INCONCLUSIVE", "THREAT_CONFIRMED", 2) == ErrorType.MISCALIBRATED

    def test_inconclusive_expected_threat_dismissed_is_miscalibrated(self):
        assert classify_error("INCONCLUSIVE", "THREAT_DISMISSED", 2) == ErrorType.MISCALIBRATED

    def test_threat_confirmed_got_inconclusive_is_miscalibrated(self):
        assert classify_error("THREAT_CONFIRMED", "INCONCLUSIVE", 1) == ErrorType.MISCALIBRATED

    def test_threat_dismissed_got_inconclusive_is_miscalibrated(self):
        assert classify_error("THREAT_DISMISSED", "INCONCLUSIVE", 3) == ErrorType.MISCALIBRATED

    def test_error_verdict_is_miscalibrated(self):
        assert classify_error("THREAT_CONFIRMED", "ERROR", 1) == ErrorType.MISCALIBRATED

    def test_case_insensitive_correct(self):
        assert classify_error("threat_confirmed", "THREAT_CONFIRMED", 1) == ErrorType.CORRECT


# ------------------------------------------------------------------
# analyze_benchmark_errors
# ------------------------------------------------------------------


class TestAnalyzeBenchmarkErrors:
    """Error analysis across a full result set."""

    def test_all_correct_returns_all_correct(self):
        scenarios = [
            _MockScenario(metadata=_MockMetadata("SC-001", "THREAT_CONFIRMED", 1)),
            _MockScenario(metadata=_MockMetadata("SC-002", "THREAT_DISMISSED", 3)),
        ]
        results = [
            _MockResult("SC-001", "THREAT_CONFIRMED"),
            _MockResult("SC-002", "THREAT_DISMISSED"),
        ]
        cls = analyze_benchmark_errors(scenarios, results)
        assert all(c.error_type == ErrorType.CORRECT for c in cls)

    def test_mixed_errors_classified_correctly(self):
        scenarios = [
            _MockScenario(metadata=_MockMetadata("SC-001", "THREAT_CONFIRMED", 1)),
            _MockScenario(metadata=_MockMetadata("SC-002", "THREAT_DISMISSED", 3)),
            _MockScenario(metadata=_MockMetadata("SC-003", "INCONCLUSIVE", 2)),
        ]
        results = [
            _MockResult("SC-001", "THREAT_DISMISSED"),   # FN
            _MockResult("SC-002", "THREAT_CONFIRMED"),   # FP
            _MockResult("SC-003", "THREAT_CONFIRMED"),   # MISCALIBRATED
        ]
        cls = analyze_benchmark_errors(scenarios, results)
        types = {c.scenario_id: c.error_type for c in cls}
        assert types["SC-001"] == ErrorType.FALSE_NEGATIVE
        assert types["SC-002"] == ErrorType.FALSE_POSITIVE
        assert types["SC-003"] == ErrorType.MISCALIBRATED

    def test_empty_results_returns_empty(self):
        assert analyze_benchmark_errors([], []) == []


# ------------------------------------------------------------------
# compute_tier_accuracy
# ------------------------------------------------------------------


class TestComputeTierAccuracy:
    """Per-tier accuracy computation."""

    def test_single_tier_all_correct(self):
        scenarios = [
            _MockScenario(metadata=_MockMetadata("SC-001", "THREAT_CONFIRMED", 1)),
            _MockScenario(metadata=_MockMetadata("SC-002", "THREAT_CONFIRMED", 1)),
        ]
        cls = [
            _make_cls("SC-001", "THREAT_CONFIRMED", "THREAT_CONFIRMED", ErrorType.CORRECT),
            _make_cls("SC-002", "THREAT_CONFIRMED", "THREAT_CONFIRMED", ErrorType.CORRECT),
        ]
        tiers = compute_tier_accuracy(scenarios, cls)
        assert tiers[1].accuracy == 1.0
        assert tiers[1].total == 2

    def test_multiple_tiers_computed(self):
        scenarios = [
            _MockScenario(metadata=_MockMetadata("SC-001", "THREAT_CONFIRMED", 1)),
            _MockScenario(metadata=_MockMetadata("SC-002", "INCONCLUSIVE", 2)),
            _MockScenario(metadata=_MockMetadata("SC-003", "THREAT_DISMISSED", 3)),
        ]
        cls = [
            _make_cls("SC-001", "THREAT_CONFIRMED", "THREAT_CONFIRMED", ErrorType.CORRECT),
            _make_cls("SC-002", "INCONCLUSIVE", "THREAT_CONFIRMED", ErrorType.MISCALIBRATED),
            _make_cls("SC-003", "THREAT_DISMISSED", "THREAT_DISMISSED", ErrorType.CORRECT),
        ]
        tiers = compute_tier_accuracy(scenarios, cls)
        assert tiers[1].accuracy == 1.0
        assert tiers[2].accuracy == 0.0
        assert tiers[3].accuracy == 1.0

    def test_tier_fp_fn_counts(self):
        scenarios = [
            _MockScenario(metadata=_MockMetadata("SC-001", "THREAT_CONFIRMED", 1)),
            _MockScenario(metadata=_MockMetadata("SC-002", "THREAT_DISMISSED", 1)),
        ]
        cls = [
            _make_cls("SC-001", "THREAT_CONFIRMED", "THREAT_DISMISSED", ErrorType.FALSE_NEGATIVE),
            _make_cls("SC-002", "THREAT_DISMISSED", "THREAT_CONFIRMED", ErrorType.FALSE_POSITIVE),
        ]
        tiers = compute_tier_accuracy(scenarios, cls)
        assert tiers[1].fn_count == 1
        assert tiers[1].fp_count == 1


# ------------------------------------------------------------------
# format_analysis_report
# ------------------------------------------------------------------


class TestFormatAnalysisReport:
    """Report formatting."""

    def test_report_is_string(self):
        cls = [
            _make_cls("SC-001", "THREAT_CONFIRMED", "THREAT_CONFIRMED", ErrorType.CORRECT),
        ]
        tiers = {1: _make_tier(1, "CLEAR_THREAT", 1, 1)}
        report = format_analysis_report("Test Run", cls, tiers)
        assert isinstance(report, str)
        assert "Test Run" in report

    def test_report_includes_fp_fn_counts(self):
        cls = [
            _make_cls("SC-001", "THREAT_DISMISSED", "THREAT_CONFIRMED", ErrorType.FALSE_POSITIVE),
            _make_cls("SC-002", "THREAT_CONFIRMED", "THREAT_DISMISSED", ErrorType.FALSE_NEGATIVE),
        ]
        tiers = {1: _make_tier(1, "CLEAR_THREAT", 2, 0)}
        report = format_analysis_report("Test", cls, tiers)
        assert "False Positives (FP):  1" in report
        assert "False Negatives (FN):  1" in report

    def test_report_includes_wrong_answers_detail(self):
        cls = [
            _make_cls("SC-001", "THREAT_DISMISSED", "THREAT_CONFIRMED", ErrorType.FALSE_POSITIVE),
        ]
        tiers = {3: _make_tier(3, "CLEAR_BENIGN", 1, 0)}
        report = format_analysis_report("Test", cls, tiers)
        assert "SC-001: FP" in report


# ------------------------------------------------------------------
# Helper factories
# ------------------------------------------------------------------


def _make_cls(sid, expected, actual, error_type):
    from ares.dialectic.scripts.benchmark_analysis import ErrorClassification
    return ErrorClassification(
        scenario_id=sid,
        expected_verdict=expected,
        actual_verdict=actual,
        error_type=error_type,
        explanation="test",
    )


def _make_tier(tier, name, total, correct):
    from ares.dialectic.scripts.benchmark_analysis import TierAccuracy
    return TierAccuracy(
        tier=tier, tier_name=name, total=total, correct=correct,
        accuracy=correct / total if total > 0 else 0.0,
        fp_count=0, fn_count=0, miscalibrated_count=0,
    )
