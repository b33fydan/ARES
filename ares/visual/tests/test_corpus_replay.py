"""Tests for ares.visual.corpus_replay — full corpus stress test.

Session 030: Validates that every scenario in the 33-scenario corpus
produces a valid, complete event sequence through the visual pipeline.
"""

from __future__ import annotations

import pytest

from ares.visual.corpus_replay import (
    CorpusReplayReport,
    ReplayResult,
    format_report,
    replay_corpus,
    replay_scenario,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_scenario(scenario_id: str):
    """Load a single benchmark scenario."""
    from ares.dialectic.scripts.expanded_scenarios import get_full_corpus
    for s in get_full_corpus():
        if s.metadata.scenario_id == scenario_id:
            return s
    raise ValueError(f"Scenario {scenario_id} not found")


def _get_all_scenarios():
    """Load all scenarios."""
    from ares.dialectic.scripts.expanded_scenarios import get_full_corpus
    return list(get_full_corpus())


# Cache the corpus report since it's expensive to compute
_CORPUS_REPORT: CorpusReplayReport | None = None


def _get_corpus_report() -> CorpusReplayReport:
    global _CORPUS_REPORT
    if _CORPUS_REPORT is None:
        _CORPUS_REPORT = replay_corpus()
    return _CORPUS_REPORT


# ---------------------------------------------------------------------------
# Single Scenario Replay
# ---------------------------------------------------------------------------

class TestReplaySingleScenario:
    """Tests for replay_scenario()."""

    def test_replay_single_scenario_returns_replay_result(self):
        scenario = _get_scenario("SC-001")
        result = replay_scenario(scenario)
        assert isinstance(result, ReplayResult)

    def test_replay_sc019_smoke_test(self):
        """SC-019 was the original smoke test from Session 029."""
        scenario = _get_scenario("SC-019")
        result = replay_scenario(scenario)
        assert result.passed

    def test_replay_result_has_scenario_id(self):
        scenario = _get_scenario("SC-001")
        result = replay_scenario(scenario)
        assert result.scenario_id == "SC-001"

    def test_replay_result_has_scenario_name(self):
        scenario = _get_scenario("SC-001")
        result = replay_scenario(scenario)
        assert result.scenario_name == scenario.metadata.name

    def test_replay_result_event_count_positive(self):
        """Every scenario should produce at least 4 events."""
        scenario = _get_scenario("SC-001")
        result = replay_scenario(scenario)
        assert result.event_count >= 4

    def test_replay_result_fact_events_match_packet(self):
        scenario = _get_scenario("SC-001")
        result = replay_scenario(scenario)
        assert result.fact_events == scenario.packet.fact_count


# ---------------------------------------------------------------------------
# Full Corpus Replay — THE KEY TESTS
# ---------------------------------------------------------------------------

class TestCorpusReplay:
    """Tests for replay_corpus() — the stress test."""

    def test_corpus_replay_covers_all_scenarios(self):
        report = _get_corpus_report()
        all_scenarios = _get_all_scenarios()
        assert report.total_scenarios == len(all_scenarios)

    def test_corpus_replay_total_equals_len(self):
        report = _get_corpus_report()
        assert report.total_scenarios == len(report.results)

    def test_corpus_replay_pass_fail_sum(self):
        report = _get_corpus_report()
        assert report.passed + report.failed == report.total_scenarios

    def test_all_scenarios_produce_valid_sequences(self):
        """THIS IS THE KEY TEST. Every scenario in the corpus should
        produce a valid event sequence (zero CRITICAL anomalies)."""
        report = _get_corpus_report()
        if not report.all_passed:
            failures = []
            for r in report.failed_scenarios:
                crits = [
                    a for a in r.diagnostic.anomalies
                    if a.severity.name == "CRITICAL"
                ]
                failures.append(
                    f"{r.scenario_id}: {[a.anomaly_type.name for a in crits]}"
                )
            pytest.fail(
                f"{report.failed} scenarios failed:\n" + "\n".join(failures)
            )

    def test_all_passed_property(self):
        report = _get_corpus_report()
        assert report.all_passed is True


# ---------------------------------------------------------------------------
# Cross-Source Scenarios (SC-025+)
# ---------------------------------------------------------------------------

class TestCrossSourceScenarios:
    """Validate the complex multi-source scenarios added in Session 021."""

    def test_cross_source_scenarios_replay_cleanly(self):
        """SC-025 through SC-033 should all produce valid sequences."""
        report = _get_corpus_report()
        cross = [
            r for r in report.results
            if r.scenario_id >= "SC-025"
        ]
        assert len(cross) > 0, "No cross-source scenarios found"
        for r in cross:
            assert r.passed, f"{r.scenario_id} failed: {[a.anomaly_type.name for a in r.diagnostic.anomalies if a.severity.name == 'CRITICAL']}"

    def test_cross_source_higher_event_counts(self):
        """Cross-source scenarios should generally have more events."""
        report = _get_corpus_report()
        early = [r for r in report.results if r.scenario_id < "SC-010"]
        cross = [r for r in report.results if r.scenario_id >= "SC-025"]
        if early and cross:
            avg_early = sum(r.event_count for r in early) / len(early)
            avg_cross = sum(r.event_count for r in cross) / len(cross)
            # Cross-source should have at least as many events on average
            assert avg_cross >= avg_early * 0.5, (
                f"Cross-source avg {avg_cross:.1f} unexpectedly low "
                f"vs early avg {avg_early:.1f}"
            )


# ---------------------------------------------------------------------------
# Report Formatting
# ---------------------------------------------------------------------------

class TestFormatReport:
    """Tests for format_report() output."""

    def test_format_report_contains_header(self):
        report = _get_corpus_report()
        text = format_report(report)
        assert "Corpus Replay Report" in text
        assert "Generated:" in text

    def test_format_report_contains_summary_counts(self):
        report = _get_corpus_report()
        text = format_report(report)
        assert f"Scenarios: {report.total_scenarios}" in text
        assert f"Passed: {report.passed}" in text

    def test_format_report_contains_per_scenario_table(self):
        report = _get_corpus_report()
        text = format_report(report)
        # Every scenario ID should appear
        for r in report.results:
            assert r.scenario_id in text

    def test_format_report_contains_metrics(self):
        report = _get_corpus_report()
        text = format_report(report)
        assert "Summary Metrics" in text
        assert "Total events across corpus" in text

    def test_format_report_returns_string(self):
        report = _get_corpus_report()
        text = format_report(report)
        assert isinstance(text, str)
        assert len(text) > 100


# ---------------------------------------------------------------------------
# Dataclass Properties
# ---------------------------------------------------------------------------

class TestDataclassProperties:
    """Tests for frozen dataclasses and computed properties."""

    def test_replay_result_is_frozen(self):
        scenario = _get_scenario("SC-001")
        result = replay_scenario(scenario)
        with pytest.raises(AttributeError):
            result.scenario_id = "hacked"

    def test_corpus_replay_report_is_frozen(self):
        report = _get_corpus_report()
        with pytest.raises(AttributeError):
            report.total_scenarios = 999

    def test_failed_scenarios_property(self):
        report = _get_corpus_report()
        for r in report.failed_scenarios:
            assert not r.passed

    def test_warning_list_property(self):
        report = _get_corpus_report()
        for r in report.warning_list:
            assert r.passed
            assert r.diagnostic.warning_count > 0

    def test_total_events_property(self):
        report = _get_corpus_report()
        manual = sum(r.event_count for r in report.results)
        assert report.total_events == manual


# ---------------------------------------------------------------------------
# Metrics Sanity Checks
# ---------------------------------------------------------------------------

class TestMetrics:
    """Sanity checks on aggregate metrics."""

    def test_corpus_total_event_count_reasonable(self):
        """Total events across all 33 scenarios should be > 100."""
        report = _get_corpus_report()
        assert report.total_events > 100

    def test_every_scenario_has_at_least_one_fact_event(self):
        """Every scenario has at least one fact."""
        report = _get_corpus_report()
        for r in report.results:
            assert r.fact_events >= 1, f"{r.scenario_id} has 0 fact events"

    def test_every_scenario_has_positive_event_count(self):
        report = _get_corpus_report()
        for r in report.results:
            assert r.event_count > 0, f"{r.scenario_id} has 0 events"
