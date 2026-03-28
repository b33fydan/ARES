"""Tests for ares.visual.benchmark_replayer — real data replay pipeline.

Session 035: Tests BenchmarkResultReplayer with a synthetic fixture
(does not depend on v4_corpus_v2.json existing).
"""

from __future__ import annotations

import json
import tempfile
from dataclasses import dataclass
from pathlib import Path

import pytest

from ares.visual.benchmark_replayer import BenchmarkResultReplayer


# ---------------------------------------------------------------------------
# Synthetic fixture — minimal benchmark results
# ---------------------------------------------------------------------------

def _make_fixture(tmp_path: Path, n_scenarios: int = 3) -> Path:
    """Create a synthetic benchmark results JSON for testing."""
    results = []
    for i in range(1, n_scenarios + 1):
        sid = f"SC-{i:03d}"
        # Alternate verdicts for variety
        if i % 3 == 1:
            verdict = "threat_confirmed"
        elif i % 3 == 2:
            verdict = "threat_dismissed"
        else:
            verdict = "inconclusive"

        results.append({
            "scenario_id": sid,
            "strategy_type": "test",
            "verdict_outcome": verdict,
            "verdict_confidence": 0.7 + i * 0.05,
            "architect_confidence": 0.6 + i * 0.05,
            "skeptic_confidence": 0.3 + i * 0.02,
            "architect_assertion_count": i,
            "skeptic_assertion_count": max(1, i - 1),
            "architect_fact_ids_cited": [f"sc{i:03d}-f{j}" for j in range(1, i + 2)],
            "skeptic_fact_ids_cited": [f"sc{i:03d}-f1"],
            "total_facts_available": i + 2,
            "fact_coverage_ratio": 0.8,
            "validation_errors": 0,
            "fallback_triggers": 0,
            "duration_ms": 100 * i,
            "token_usage": None,
            "cost_usd": None,
            "narrator_output": None,
        })

    data = {
        "run_id": "test-run",
        "timestamp": "2026-01-01T00:00:00",
        "strategy_type": "test",
        "scenario_count": n_scenarios,
        "results": results,
        "total_duration_ms": 1000,
        "total_cost_usd": None,
    }

    path = tmp_path / "test_results.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Construction and Loading
# ---------------------------------------------------------------------------

class TestConstruction:

    def test_loads_from_json(self, tmp_path):
        path = _make_fixture(tmp_path)
        replayer = BenchmarkResultReplayer(str(path), corpus={})
        assert len(replayer.scenario_ids) == 3

    def test_missing_file_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            BenchmarkResultReplayer(str(tmp_path / "nonexistent.json"), corpus={})

    def test_repr(self, tmp_path):
        path = _make_fixture(tmp_path)
        replayer = BenchmarkResultReplayer(str(path), corpus={})
        r = repr(replayer)
        assert "test_results.json" in r
        assert "3 scenarios" in r


# ---------------------------------------------------------------------------
# Single Scenario Replay
# ---------------------------------------------------------------------------

class TestReplayScenario:

    def test_returns_list_of_tuples(self, tmp_path):
        path = _make_fixture(tmp_path)
        replayer = BenchmarkResultReplayer(str(path), corpus={})
        events = replayer.replay_scenario("SC-001")
        assert isinstance(events, list)
        assert all(isinstance(e, tuple) and len(e) == 2 for e in events)

    def test_timestamps_are_non_negative(self, tmp_path):
        path = _make_fixture(tmp_path)
        replayer = BenchmarkResultReplayer(str(path), corpus={})
        events = replayer.replay_scenario("SC-001")
        for ts, _ in events:
            assert ts >= 0

    def test_timestamps_are_monotonically_increasing(self, tmp_path):
        path = _make_fixture(tmp_path)
        replayer = BenchmarkResultReplayer(str(path), corpus={})
        events = replayer.replay_scenario("SC-001")
        timestamps = [ts for ts, _ in events]
        for i in range(1, len(timestamps)):
            assert timestamps[i] >= timestamps[i - 1]

    def test_starts_with_scenario_start(self, tmp_path):
        path = _make_fixture(tmp_path)
        replayer = BenchmarkResultReplayer(str(path), corpus={})
        events = replayer.replay_scenario("SC-001")
        _, first = events[0]
        assert first.event_type == "scenario_start"

    def test_ends_with_scenario_end(self, tmp_path):
        path = _make_fixture(tmp_path)
        replayer = BenchmarkResultReplayer(str(path), corpus={})
        events = replayer.replay_scenario("SC-001")
        _, last = events[-1]
        assert last.event_type == "scenario_end"

    def test_contains_confidence_update(self, tmp_path):
        path = _make_fixture(tmp_path)
        replayer = BenchmarkResultReplayer(str(path), corpus={})
        events = replayer.replay_scenario("SC-001")
        types = [e.event_type for _, e in events]
        assert "confidence_update" in types

    def test_contains_verdict_rendered(self, tmp_path):
        path = _make_fixture(tmp_path)
        replayer = BenchmarkResultReplayer(str(path), corpus={})
        events = replayer.replay_scenario("SC-001")
        types = [e.event_type for _, e in events]
        assert "verdict_rendered" in types

    def test_contains_fact_cited(self, tmp_path):
        path = _make_fixture(tmp_path)
        replayer = BenchmarkResultReplayer(str(path), corpus={})
        events = replayer.replay_scenario("SC-001")
        types = [e.event_type for _, e in events]
        assert types.count("fact_cited") == 2  # architect + skeptic

    def test_missing_scenario_raises(self, tmp_path):
        path = _make_fixture(tmp_path)
        replayer = BenchmarkResultReplayer(str(path), corpus={})
        with pytest.raises(KeyError):
            replayer.replay_scenario("SC-999")

    def test_speed_scales_delays(self, tmp_path):
        path = _make_fixture(tmp_path)
        replayer = BenchmarkResultReplayer(str(path), corpus={})
        normal = replayer.replay_scenario("SC-001", speed=1.0)
        fast = replayer.replay_scenario("SC-001", speed=2.0)
        # Fast should have smaller timestamps
        normal_end = normal[-1][0]
        fast_end = fast[-1][0]
        assert fast_end < normal_end


# ---------------------------------------------------------------------------
# All-Scenario Replay
# ---------------------------------------------------------------------------

class TestReplayAll:

    def test_replays_all_scenarios(self, tmp_path):
        path = _make_fixture(tmp_path)
        replayer = BenchmarkResultReplayer(str(path), corpus={})
        events = replayer.replay_all()
        sids = {e.scenario_id for _, e in events if hasattr(e, "scenario_id")}
        assert "SC-001" in sids
        assert "SC-002" in sids
        assert "SC-003" in sids

    def test_filter_by_scenario_ids(self, tmp_path):
        path = _make_fixture(tmp_path)
        replayer = BenchmarkResultReplayer(str(path), corpus={})
        events = replayer.replay_all(scenario_ids=["SC-002"])
        sids = {e.scenario_id for _, e in events if hasattr(e, "scenario_id")}
        assert "SC-002" in sids
        assert "SC-001" not in sids

    def test_includes_accuracy_milestones(self, tmp_path):
        path = _make_fixture(tmp_path)
        replayer = BenchmarkResultReplayer(str(path), corpus={})
        events = replayer.replay_all()
        milestones = [e for _, e in events if e.event_type == "accuracy_milestone"]
        assert len(milestones) == 3  # one per scenario

    def test_accuracy_milestone_counts_correct(self, tmp_path):
        path = _make_fixture(tmp_path)
        replayer = BenchmarkResultReplayer(str(path), corpus={})
        events = replayer.replay_all()
        milestones = [e for _, e in events if e.event_type == "accuracy_milestone"]
        last = milestones[-1]
        assert last.scenarios_completed == 3
        assert 0.0 <= last.running_accuracy <= 1.0


# ---------------------------------------------------------------------------
# Showcase Scenarios
# ---------------------------------------------------------------------------

class TestShowcaseScenarios:

    def test_returns_list_of_ids(self, tmp_path):
        path = _make_fixture(tmp_path, n_scenarios=10)
        replayer = BenchmarkResultReplayer(str(path), corpus={})
        showcase = replayer.get_showcase_scenarios()
        assert isinstance(showcase, list)
        assert len(showcase) >= 1

    def test_showcase_scenarios_exist_in_results(self, tmp_path):
        path = _make_fixture(tmp_path, n_scenarios=10)
        replayer = BenchmarkResultReplayer(str(path), corpus={})
        showcase = replayer.get_showcase_scenarios()
        all_ids = set(replayer.scenario_ids)
        for sid in showcase:
            assert sid in all_ids


# ---------------------------------------------------------------------------
# Integration with real corpus
# ---------------------------------------------------------------------------

class TestRealCorpusIntegration:

    def test_loads_v4_results_if_available(self):
        """Smoke test with real v4 data (skips if file missing)."""
        path = Path("ares/dialectic/scripts/benchmark_results/v4_corpus_v2.json")
        if not path.exists():
            pytest.skip("v4_corpus_v2.json not available")

        replayer = BenchmarkResultReplayer(str(path))
        assert len(replayer.scenario_ids) == 33

    def test_replay_real_scenario(self):
        path = Path("ares/dialectic/scripts/benchmark_results/v4_corpus_v2.json")
        if not path.exists():
            pytest.skip("v4_corpus_v2.json not available")

        replayer = BenchmarkResultReplayer(str(path))
        events = replayer.replay_scenario("SC-010")
        assert len(events) > 5
        types = [e.event_type for _, e in events]
        assert "scenario_start" in types
        assert "verdict_rendered" in types

    def test_showcase_from_real_data(self):
        path = Path("ares/dialectic/scripts/benchmark_results/v4_corpus_v2.json")
        if not path.exists():
            pytest.skip("v4_corpus_v2.json not available")

        replayer = BenchmarkResultReplayer(str(path))
        showcase = replayer.get_showcase_scenarios()
        assert 5 <= len(showcase) <= 7
