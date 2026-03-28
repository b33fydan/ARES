"""Tests for ares.visual.events_multiturn — per-round debate events.

Session 037: Validates multi-turn event construction, serialization,
and round-trip deserialization.
"""

from __future__ import annotations

import pytest

from ares.visual.events_multiturn import (
    DebateEvolutionEvent,
    RoundConfidenceEvent,
    RoundStartEvent,
    mt_event_from_dict,
)


class TestRoundStartEvent:

    def test_construction(self):
        e = RoundStartEvent(
            event_type="round_start", timestamp_ms=100,
            scenario_id="SC-001", round_number=1, max_rounds=3,
        )
        assert e.round_number == 1
        assert e.max_rounds == 3

    def test_to_dict(self):
        e = RoundStartEvent(
            event_type="round_start", timestamp_ms=100,
            scenario_id="SC-001", round_number=2, max_rounds=3,
        )
        d = e.to_dict()
        assert d["event_type"] == "round_start"
        assert d["round_number"] == 2

    def test_frozen(self):
        e = RoundStartEvent(
            event_type="round_start", timestamp_ms=0,
            scenario_id="X", round_number=1, max_rounds=3,
        )
        with pytest.raises(AttributeError):
            e.round_number = 5

    def test_round_trip(self):
        e = RoundStartEvent(
            event_type="round_start", timestamp_ms=50,
            scenario_id="SC-005", round_number=3, max_rounds=3,
        )
        d = e.to_dict()
        e2 = mt_event_from_dict(d)
        assert e2 == e


class TestRoundConfidenceEvent:

    def test_construction(self):
        e = RoundConfidenceEvent(
            event_type="round_confidence", timestamp_ms=200,
            scenario_id="SC-001", round_number=1,
            architect_confidence=0.85, skeptic_confidence=0.30,
            architect_new_facts=6, skeptic_new_facts=4,
            architect_assertions=3, skeptic_assertions=2,
        )
        assert e.architect_confidence == 0.85

    def test_to_dict(self):
        e = RoundConfidenceEvent(
            event_type="round_confidence", timestamp_ms=200,
            scenario_id="SC-001", round_number=2,
            architect_confidence=0.65, skeptic_confidence=0.45,
            architect_new_facts=0, skeptic_new_facts=0,
            architect_assertions=2, skeptic_assertions=1,
        )
        d = e.to_dict()
        assert d["architect_new_facts"] == 0
        assert d["round_number"] == 2

    def test_frozen(self):
        e = RoundConfidenceEvent(
            event_type="round_confidence", timestamp_ms=0,
            scenario_id="X", round_number=1,
            architect_confidence=0.0, skeptic_confidence=0.0,
            architect_new_facts=0, skeptic_new_facts=0,
            architect_assertions=0, skeptic_assertions=0,
        )
        with pytest.raises(AttributeError):
            e.architect_confidence = 1.0

    def test_round_trip(self):
        e = RoundConfidenceEvent(
            event_type="round_confidence", timestamp_ms=300,
            scenario_id="SC-010", round_number=1,
            architect_confidence=0.92, skeptic_confidence=0.31,
            architect_new_facts=10, skeptic_new_facts=8,
            architect_assertions=4, skeptic_assertions=3,
        )
        d = e.to_dict()
        e2 = mt_event_from_dict(d)
        assert e2 == e


class TestDebateEvolutionEvent:

    def test_construction(self):
        e = DebateEvolutionEvent(
            event_type="debate_evolution", timestamp_ms=500,
            scenario_id="SC-001", total_rounds=3,
            termination_reason="max_turns_exceeded",
            confidence_trajectory=((0.85, 0.30), (0.65, 0.45), (0.55, 0.50)),
            verdict_outcome="inconclusive", expected_verdict="threat_confirmed",
            is_correct=False,
        )
        assert e.total_rounds == 3
        assert len(e.confidence_trajectory) == 3

    def test_to_dict_converts_trajectory(self):
        e = DebateEvolutionEvent(
            event_type="debate_evolution", timestamp_ms=500,
            scenario_id="SC-001", total_rounds=2,
            termination_reason="no_new_evidence",
            confidence_trajectory=((0.90, 0.20), (0.85, 0.25)),
            verdict_outcome="threat_confirmed",
            expected_verdict="threat_confirmed", is_correct=True,
        )
        d = e.to_dict()
        assert isinstance(d["confidence_trajectory"], list)
        assert isinstance(d["confidence_trajectory"][0], list)

    def test_frozen(self):
        e = DebateEvolutionEvent(
            event_type="debate_evolution", timestamp_ms=0,
            scenario_id="X", total_rounds=1,
            termination_reason="test", confidence_trajectory=(),
            verdict_outcome="", expected_verdict="", is_correct=False,
        )
        with pytest.raises(AttributeError):
            e.total_rounds = 99

    def test_round_trip(self):
        e = DebateEvolutionEvent(
            event_type="debate_evolution", timestamp_ms=800,
            scenario_id="SC-002", total_rounds=2,
            termination_reason="no_new_evidence",
            confidence_trajectory=((0.85, 0.30), (0.65, 0.30)),
            verdict_outcome="threat_confirmed",
            expected_verdict="threat_confirmed", is_correct=True,
        )
        d = e.to_dict()
        e2 = mt_event_from_dict(d)
        assert e2 == e


class TestMtEventFromDict:

    def test_unknown_type_raises(self):
        with pytest.raises(ValueError):
            mt_event_from_dict({"event_type": "bogus"})

    def test_all_types_registered(self):
        from ares.visual.events_multiturn import _MT_EVENT_REGISTRY
        assert "round_start" in _MT_EVENT_REGISTRY
        assert "round_confidence" in _MT_EVENT_REGISTRY
        assert "debate_evolution" in _MT_EVENT_REGISTRY
