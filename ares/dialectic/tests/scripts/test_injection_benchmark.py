"""Tests for ares.dialectic.scripts.run_injection_benchmark — injection
benchmark runner, result types, metric calculations, and reporting.

Covers:
    1. Result types frozen (3 tests)
    2. Metric calculations (5 tests)
    3. Category mapping (2 tests)
    4. Report generation (2 tests)
    5. Dry-run integration (2 tests)
"""

from __future__ import annotations

import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

from ares.dialectic.coordinator.firewall import OracleFirewall
from ares.dialectic.scripts.run_injection_benchmark import (
    INJECTION_CATEGORIES,
    InjectionBenchmarkRun,
    InjectionResult,
    print_injection_report,
    run_injection_benchmark,
    save_injection_report,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_result(
    scenario_id: str = "INJ-001",
    category: str = "DIRECT",
    detected: bool = True,
    hot_swap: bool = False,
    correct: bool = True,
    taint: float = 0.85,
    violations: int = 3,
    violation_types: tuple[str, ...] = ("INSTRUCTION_INJECTION",),
    verdict: str = "THREAT_CONFIRMED",
    expected: str = "THREAT_CONFIRMED",
    arch: float = 0.75,
    skep: float = 0.30,
    ms: int = 50,
) -> InjectionResult:
    """Build an InjectionResult with sensible defaults."""
    return InjectionResult(
        scenario_id=scenario_id,
        injection_category=category,
        injection_detected=detected,
        hot_swap_triggered=hot_swap,
        verdict_correct=correct,
        taint_score=taint,
        violations_found=violations,
        violation_types=violation_types,
        verdict_outcome=verdict,
        expected_verdict=expected,
        architect_confidence=arch,
        skeptic_confidence=skep,
        duration_ms=ms,
    )


def _make_run(
    results: tuple[InjectionResult, ...] | None = None,
    detection_rate: float = 0.75,
    category_detection: dict | None = None,
    verdict_accuracy: float = 0.83,
    false_positives: int = 0,
    hot_swaps: int = 0,
    total_ms: int = 500,
    strategy_label: str = "test",
) -> InjectionBenchmarkRun:
    """Build an InjectionBenchmarkRun with sensible defaults."""
    if results is None:
        results = (_make_result(),)
    if category_detection is None:
        category_detection = {"DIRECT": 1.0, "FRAMING": 0.5, "PROPAGATION": 0.75}
    return InjectionBenchmarkRun(
        run_id="test-run-001",
        timestamp=datetime(2026, 4, 5, 12, 0, 0, tzinfo=timezone.utc),
        strategy_label=strategy_label,
        results=results,
        detection_rate=detection_rate,
        category_detection=category_detection,
        verdict_accuracy=verdict_accuracy,
        false_positive_count=false_positives,
        hot_swap_count=hot_swaps,
        total_duration_ms=total_ms,
    )


def _rule_based_strategies():
    """Create rule-based strategies (no API calls)."""
    from ares.dialectic.agents.strategies.rule_based import (
        RuleBasedExplanationFinder,
        RuleBasedThreatAnalyzer,
    )
    return RuleBasedThreatAnalyzer(), RuleBasedExplanationFinder()


# ---------------------------------------------------------------------------
# 1. Result types frozen
# ---------------------------------------------------------------------------

class TestResultTypesFrozen:
    """Verify frozen dataclass constraints on result types."""

    def test_injection_result_is_frozen(self):
        r = _make_result()
        with pytest.raises(AttributeError):
            r.taint_score = 0.0

    def test_injection_benchmark_run_is_frozen(self):
        run = _make_run()
        with pytest.raises(AttributeError):
            run.detection_rate = 0.0

    def test_both_serialize_correctly(self):
        """Both types should be constructible and their fields accessible."""
        r = _make_result(scenario_id="INJ-003", category="DIRECT", taint=0.92)
        assert r.scenario_id == "INJ-003"
        assert r.injection_category == "DIRECT"
        assert r.taint_score == 0.92

        run = _make_run(
            results=(r,),
            detection_rate=1.0,
            verdict_accuracy=1.0,
        )
        assert run.run_id == "test-run-001"
        assert len(run.results) == 1
        assert run.detection_rate == 1.0


# ---------------------------------------------------------------------------
# 2. Metric calculations
# ---------------------------------------------------------------------------

class TestMetricCalculations:
    """Verify aggregate metric calculations."""

    def test_detection_rate_is_detected_over_total(self):
        results = (
            _make_result(scenario_id="INJ-001", detected=True),
            _make_result(scenario_id="INJ-002", detected=True),
            _make_result(scenario_id="INJ-003", detected=False),
            _make_result(scenario_id="INJ-004", detected=True),
        )
        detected = sum(1 for r in results if r.injection_detected)
        total = len(results)
        rate = detected / total
        assert rate == pytest.approx(0.75)

    def test_verdict_accuracy_is_correct_over_total(self):
        results = (
            _make_result(scenario_id="INJ-001", correct=True),
            _make_result(scenario_id="INJ-002", correct=False),
            _make_result(scenario_id="INJ-003", correct=True),
        )
        correct = sum(1 for r in results if r.verdict_correct)
        total = len(results)
        accuracy = correct / total
        assert accuracy == pytest.approx(2.0 / 3.0)

    def test_category_detection_calculated_per_category(self):
        from ares.dialectic.scripts.run_injection_benchmark import (
            _compute_category_detection,
        )

        results = (
            _make_result(scenario_id="INJ-001", category="DIRECT", detected=True),
            _make_result(scenario_id="INJ-002", category="DIRECT", detected=True),
            _make_result(scenario_id="INJ-005", category="FRAMING", detected=False),
            _make_result(scenario_id="INJ-006", category="FRAMING", detected=True),
            _make_result(scenario_id="INJ-009", category="PROPAGATION", detected=True),
            _make_result(scenario_id="INJ-010", category="PROPAGATION", detected=False),
        )

        cat_det = _compute_category_detection(results)
        assert cat_det["DIRECT"] == pytest.approx(1.0)
        assert cat_det["FRAMING"] == pytest.approx(0.5)
        assert cat_det["PROPAGATION"] == pytest.approx(0.5)

    def test_false_positive_count_zero_for_clean(self):
        run = _make_run(false_positives=0)
        assert run.false_positive_count == 0

    def test_hot_swap_count_tracks_correctly(self):
        results = (
            _make_result(scenario_id="INJ-001", hot_swap=True),
            _make_result(scenario_id="INJ-002", hot_swap=False),
            _make_result(scenario_id="INJ-003", hot_swap=True),
        )
        count = sum(1 for r in results if r.hot_swap_triggered)
        assert count == 2

        run = _make_run(results=results, hot_swaps=count)
        assert run.hot_swap_count == 2


# ---------------------------------------------------------------------------
# 3. Category mapping
# ---------------------------------------------------------------------------

class TestCategoryMapping:
    """Verify INJECTION_CATEGORIES completeness and correctness."""

    def test_all_12_ids_have_category(self):
        expected_ids = {f"INJ-{i:03d}" for i in range(1, 13)}
        assert set(INJECTION_CATEGORIES.keys()) == expected_ids

    def test_categories_are_exactly_three(self):
        categories = set(INJECTION_CATEGORIES.values())
        assert categories == {"DIRECT", "FRAMING", "PROPAGATION"}


# ---------------------------------------------------------------------------
# 4. Report generation
# ---------------------------------------------------------------------------

class TestReportGeneration:
    """Verify report functions don't crash and produce valid output."""

    def test_print_injection_report_does_not_crash(self, capsys):
        results = tuple(
            _make_result(
                scenario_id=f"INJ-{i:03d}",
                category=INJECTION_CATEGORIES[f"INJ-{i:03d}"],
                detected=(i % 2 == 1),
                correct=(i <= 8),
                taint=0.1 * i,
                violations=i,
            )
            for i in range(1, 13)
        )
        run = _make_run(
            results=results,
            detection_rate=6.0 / 12.0,
            verdict_accuracy=8.0 / 12.0,
        )

        print_injection_report(run)
        captured = capsys.readouterr()
        assert "INJECTION RESILIENCE BENCHMARK" in captured.out
        assert "CATEGORY SUMMARY" in captured.out
        assert "OVERALL" in captured.out
        assert "Detection rate" in captured.out

    def test_save_injection_report_writes_valid_json(self):
        results = (
            _make_result(scenario_id="INJ-001"),
            _make_result(scenario_id="INJ-002", detected=False, taint=0.2),
        )
        run = _make_run(results=results, detection_rate=0.5)

        with tempfile.TemporaryDirectory() as tmpdir:
            out_path = save_injection_report(run, Path(tmpdir))
            assert out_path.exists()
            assert out_path.name == "results.json"

            data = json.loads(out_path.read_text())
            assert data["run_id"] == "test-run-001"
            assert data["detection_rate"] == 0.5
            assert len(data["results"]) == 2
            assert data["results"][0]["scenario_id"] == "INJ-001"
            assert isinstance(data["results"][0]["violation_types"], list)


# ---------------------------------------------------------------------------
# 5. Dry-run integration
# ---------------------------------------------------------------------------

class TestDryRunIntegration:
    """Run with rule-based strategies + real firewall on injection corpus."""

    def test_runs_all_12_scenarios_without_errors(self):
        ta, ef = _rule_based_strategies()
        firewall = OracleFirewall()

        run = run_injection_benchmark(
            threat_analyzer=ta,
            explanation_finder=ef,
            firewall=firewall,
            include_clean_check=False,
            strategy_label="rule_based",
        )

        assert isinstance(run, InjectionBenchmarkRun)
        assert len(run.results) == 12

        # Every result should have a non-ERROR outcome
        for r in run.results:
            assert r.verdict_outcome != "ERROR", (
                f"{r.scenario_id} produced ERROR"
            )
            assert r.injection_category in ("DIRECT", "FRAMING", "PROPAGATION")
            assert 0.0 <= r.taint_score <= 1.0
            assert r.duration_ms >= 0

    def test_results_cover_all_12_scenario_ids(self):
        ta, ef = _rule_based_strategies()
        firewall = OracleFirewall()

        run = run_injection_benchmark(
            threat_analyzer=ta,
            explanation_finder=ef,
            firewall=firewall,
            include_clean_check=False,
            strategy_label="rule_based",
        )

        result_ids = {r.scenario_id for r in run.results}
        expected_ids = {f"INJ-{i:03d}" for i in range(1, 13)}
        assert result_ids == expected_ids
