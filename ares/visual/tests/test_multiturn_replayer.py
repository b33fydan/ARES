"""Tests for ares.visual.multiturn_replayer — multi-turn visual replay.

Session 037: Tests with synthetic multi-turn benchmark data.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ares.visual.multiturn_replayer import MultiTurnReplayer


# ---------------------------------------------------------------------------
# Synthetic fixture
# ---------------------------------------------------------------------------

def _make_fixture(tmp_path: Path, n_scenarios: int = 3) -> Path:
    """Create synthetic multi-turn benchmark results."""
    results = []
    for i in range(1, n_scenarios + 1):
        sid = f"SC-{i:03d}"
        verdicts = ["threat_confirmed", "threat_dismissed", "inconclusive"]
        verdict = verdicts[i % 3]

        snapshots = [
            {
                "round_number": 1,
                "architect_confidence": 0.80 - i * 0.05,
                "skeptic_confidence": 0.30 + i * 0.05,
                "architect_new_fact_count": i + 2,
                "skeptic_new_fact_count": i + 1,
                "architect_assertion_count": 3,
                "skeptic_assertion_count": 2,
            },
            {
                "round_number": 2,
                "architect_confidence": 0.65 - i * 0.03,
                "skeptic_confidence": 0.40 + i * 0.03,
                "architect_new_fact_count": 0,
                "skeptic_new_fact_count": 0,
                "architect_assertion_count": 2,
                "skeptic_assertion_count": 1,
            },
        ]

        results.append({
            "scenario_id": sid,
            "scenario_name": f"Test Scenario {i}",
            "expected_verdict": verdict.upper(),
            "verdict_outcome": verdict,
            "verdict_confidence": 0.6,
            "architect_confidence": snapshots[-1]["architect_confidence"],
            "skeptic_confidence": snapshots[-1]["skeptic_confidence"],
            "rounds_used": 2,
            "max_rounds_configured": 3,
            "termination_reason": "no_new_evidence",
            "coverage": 0.9,
            "total_facts_available": i + 4,
            "round_snapshots": snapshots,
            "validation_errors": 0,
            "fallback_triggers": 0,
            "duration_ms": 200 * i,
            "token_usage": None,
            "cost_usd": None,
        })

    data = {
        "run_id": "test-mt",
        "timestamp": "2026-01-01T00:00:00",
        "strategy_type": "multi_turn_llm",
        "max_rounds": 3,
        "confidence_delta": 0.05,
        "require_new_evidence": True,
        "scenario_count": n_scenarios,
        "total_duration_ms": 1000,
        "total_cost_usd": None,
        "match_rate": 1.0,
        "avg_rounds_used": 2.0,
        "results": results,
    }

    path = tmp_path / "mt_test.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------

class TestConstruction:

    def test_loads_from_json(self, tmp_path):
        path = _make_fixture(tmp_path)
        replayer = MultiTurnReplayer(str(path), corpus={})
        assert len(replayer.scenario_ids) == 3

    def test_missing_file_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            MultiTurnReplayer(str(tmp_path / "missing.json"), corpus={})

    def test_max_rounds(self, tmp_path):
        path = _make_fixture(tmp_path)
        replayer = MultiTurnReplayer(str(path), corpus={})
        assert replayer.max_rounds == 3

    def test_repr(self, tmp_path):
        path = _make_fixture(tmp_path)
        replayer = MultiTurnReplayer(str(path), corpus={})
        assert "mt_test.json" in repr(replayer)


# ---------------------------------------------------------------------------
# Single Scenario Replay
# ---------------------------------------------------------------------------

class TestReplayScenario:

    def test_returns_list_of_tuples(self, tmp_path):
        path = _make_fixture(tmp_path)
        replayer = MultiTurnReplayer(str(path), corpus={})
        events = replayer.replay_scenario("SC-001")
        assert isinstance(events, list)
        assert all(isinstance(e, tuple) and len(e) == 2 for e in events)

    def test_starts_with_scenario_start(self, tmp_path):
        path = _make_fixture(tmp_path)
        replayer = MultiTurnReplayer(str(path), corpus={})
        events = replayer.replay_scenario("SC-001")
        assert events[0][1].event_type == "scenario_start"

    def test_ends_with_scenario_end(self, tmp_path):
        path = _make_fixture(tmp_path)
        replayer = MultiTurnReplayer(str(path), corpus={})
        events = replayer.replay_scenario("SC-001")
        assert events[-1][1].event_type == "scenario_end"

    def test_contains_round_events(self, tmp_path):
        path = _make_fixture(tmp_path)
        replayer = MultiTurnReplayer(str(path), corpus={})
        events = replayer.replay_scenario("SC-001")
        types = [e.event_type for _, e in events]
        assert "round_start" in types
        assert "round_confidence" in types
        assert types.count("round_start") == 2  # 2 rounds in fixture
        assert types.count("round_confidence") == 2

    def test_contains_debate_evolution(self, tmp_path):
        path = _make_fixture(tmp_path)
        replayer = MultiTurnReplayer(str(path), corpus={})
        events = replayer.replay_scenario("SC-001")
        types = [e.event_type for _, e in events]
        assert "debate_evolution" in types

    def test_contains_verdict(self, tmp_path):
        path = _make_fixture(tmp_path)
        replayer = MultiTurnReplayer(str(path), corpus={})
        events = replayer.replay_scenario("SC-001")
        types = [e.event_type for _, e in events]
        assert "verdict_rendered" in types

    def test_timestamps_monotonic(self, tmp_path):
        path = _make_fixture(tmp_path)
        replayer = MultiTurnReplayer(str(path), corpus={})
        events = replayer.replay_scenario("SC-001")
        timestamps = [ts for ts, _ in events]
        for i in range(1, len(timestamps)):
            assert timestamps[i] >= timestamps[i - 1]

    def test_speed_scales_delays(self, tmp_path):
        path = _make_fixture(tmp_path)
        replayer = MultiTurnReplayer(str(path), corpus={})
        normal = replayer.replay_scenario("SC-001", speed=1.0)
        fast = replayer.replay_scenario("SC-001", speed=2.0)
        assert fast[-1][0] < normal[-1][0]

    def test_missing_scenario_raises(self, tmp_path):
        path = _make_fixture(tmp_path)
        replayer = MultiTurnReplayer(str(path), corpus={})
        with pytest.raises(KeyError):
            replayer.replay_scenario("SC-999")

    def test_debate_evolution_has_trajectory(self, tmp_path):
        path = _make_fixture(tmp_path)
        replayer = MultiTurnReplayer(str(path), corpus={})
        events = replayer.replay_scenario("SC-001")
        evo = [e for _, e in events if e.event_type == "debate_evolution"][0]
        assert len(evo.confidence_trajectory) == 2  # 2 rounds


# ---------------------------------------------------------------------------
# All-Scenario Replay
# ---------------------------------------------------------------------------

class TestReplayAll:

    def test_replays_all(self, tmp_path):
        path = _make_fixture(tmp_path)
        replayer = MultiTurnReplayer(str(path), corpus={})
        events = replayer.replay_all()
        sids = {e.scenario_id for _, e in events if hasattr(e, "scenario_id")}
        assert len(sids) == 3

    def test_includes_accuracy_milestones(self, tmp_path):
        path = _make_fixture(tmp_path)
        replayer = MultiTurnReplayer(str(path), corpus={})
        events = replayer.replay_all()
        milestones = [e for _, e in events if e.event_type == "accuracy_milestone"]
        assert len(milestones) == 3

    def test_filter_by_ids(self, tmp_path):
        path = _make_fixture(tmp_path)
        replayer = MultiTurnReplayer(str(path), corpus={})
        events = replayer.replay_all(scenario_ids=["SC-002"])
        sids = {e.scenario_id for _, e in events if hasattr(e, "scenario_id")}
        assert "SC-002" in sids
        assert "SC-001" not in sids


# ---------------------------------------------------------------------------
# Integration with real data
# ---------------------------------------------------------------------------

class TestRealData:

    def test_loads_existing_multiturn_v1(self):
        """Smoke test with the original 12-scenario multi-turn data."""
        path = Path("ares/dialectic/scripts/benchmark_results/multi_turn_v1.json")
        if not path.exists():
            pytest.skip("multi_turn_v1.json not available")

        replayer = MultiTurnReplayer(str(path), corpus={})
        assert len(replayer.scenario_ids) > 0

    def test_replay_from_v1_data(self):
        path = Path("ares/dialectic/scripts/benchmark_results/multi_turn_v1.json")
        if not path.exists():
            pytest.skip("multi_turn_v1.json not available")

        replayer = MultiTurnReplayer(str(path), corpus={})
        sid = replayer.scenario_ids[0]
        events = replayer.replay_scenario(sid)
        types = [e.event_type for _, e in events]
        assert "round_start" in types
        assert "round_confidence" in types
        assert "verdict_rendered" in types
