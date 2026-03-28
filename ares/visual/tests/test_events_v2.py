"""Tests for ares.visual.events_v2 — extended event types.

Session 035: Validates v2 event construction, serialization, and immutability.
"""

from __future__ import annotations

import pytest

from ares.visual.events_v2 import (
    AccuracyMilestoneEvent,
    ConfidenceUpdateEvent,
    DebateSummaryEvent,
    FactCitedEvent,
    v2_event_from_dict,
)


class TestConfidenceUpdateEvent:

    def test_construction(self):
        e = ConfidenceUpdateEvent(
            event_type="confidence_update", timestamp_ms=100,
            scenario_id="SC-001", architect_confidence=0.75,
            skeptic_confidence=0.40, delta=0.35,
        )
        assert e.architect_confidence == 0.75
        assert e.delta == 0.35

    def test_to_dict(self):
        e = ConfidenceUpdateEvent(
            event_type="confidence_update", timestamp_ms=100,
            scenario_id="SC-001", architect_confidence=0.8,
            skeptic_confidence=0.3, delta=0.5,
        )
        d = e.to_dict()
        assert d["event_type"] == "confidence_update"
        assert d["delta"] == 0.5

    def test_frozen(self):
        e = ConfidenceUpdateEvent(
            event_type="confidence_update", timestamp_ms=0,
            scenario_id="X", architect_confidence=0.0,
            skeptic_confidence=0.0, delta=0.0,
        )
        with pytest.raises(AttributeError):
            e.delta = 1.0

    def test_round_trip(self):
        e = ConfidenceUpdateEvent(
            event_type="confidence_update", timestamp_ms=50,
            scenario_id="SC-005", architect_confidence=0.6,
            skeptic_confidence=0.8, delta=-0.2,
        )
        d = e.to_dict()
        e2 = v2_event_from_dict(d)
        assert e2 == e


class TestFactCitedEvent:

    def test_construction(self):
        e = FactCitedEvent(
            event_type="fact_cited", timestamp_ms=200,
            scenario_id="SC-002", agent_role="architect",
            fact_ids=("f1", "f2"), coverage_ratio=0.67,
        )
        assert e.agent_role == "architect"
        assert len(e.fact_ids) == 2

    def test_to_dict_converts_tuple_to_list(self):
        e = FactCitedEvent(
            event_type="fact_cited", timestamp_ms=200,
            scenario_id="SC-002", agent_role="skeptic",
            fact_ids=("f1",), coverage_ratio=0.5,
        )
        d = e.to_dict()
        assert isinstance(d["fact_ids"], list)

    def test_frozen(self):
        e = FactCitedEvent(
            event_type="fact_cited", timestamp_ms=0,
            scenario_id="X", agent_role="architect",
            fact_ids=(), coverage_ratio=0.0,
        )
        with pytest.raises(AttributeError):
            e.agent_role = "hacked"

    def test_round_trip(self):
        e = FactCitedEvent(
            event_type="fact_cited", timestamp_ms=300,
            scenario_id="SC-003", agent_role="architect",
            fact_ids=("f1", "f2", "f3"), coverage_ratio=1.0,
        )
        d = e.to_dict()
        e2 = v2_event_from_dict(d)
        assert e2 == e


class TestDebateSummaryEvent:

    def test_construction(self):
        e = DebateSummaryEvent(
            event_type="debate_summary", timestamp_ms=500,
            scenario_id="SC-010",
            architect_assertion_count=3, skeptic_assertion_count=2,
            verdict_outcome="threat_confirmed", verdict_confidence=0.9,
            expected_verdict="threat_confirmed", is_correct=True,
        )
        assert e.is_correct is True

    def test_to_dict(self):
        e = DebateSummaryEvent(
            event_type="debate_summary", timestamp_ms=0,
            scenario_id="SC-001",
            architect_assertion_count=1, skeptic_assertion_count=1,
            verdict_outcome="inconclusive", verdict_confidence=0.5,
            expected_verdict="inconclusive", is_correct=True,
        )
        d = e.to_dict()
        assert d["is_correct"] is True

    def test_frozen(self):
        e = DebateSummaryEvent(
            event_type="debate_summary", timestamp_ms=0,
            scenario_id="X",
            architect_assertion_count=0, skeptic_assertion_count=0,
            verdict_outcome="", verdict_confidence=0.0,
            expected_verdict="", is_correct=False,
        )
        with pytest.raises(AttributeError):
            e.is_correct = True


class TestAccuracyMilestoneEvent:

    def test_construction(self):
        e = AccuracyMilestoneEvent(
            event_type="accuracy_milestone", timestamp_ms=1000,
            scenarios_completed=10, scenarios_correct=8,
            running_accuracy=0.8,
        )
        assert e.running_accuracy == 0.8

    def test_to_dict(self):
        e = AccuracyMilestoneEvent(
            event_type="accuracy_milestone", timestamp_ms=500,
            scenarios_completed=5, scenarios_correct=4,
            running_accuracy=0.8,
        )
        d = e.to_dict()
        assert d["scenarios_completed"] == 5

    def test_frozen(self):
        e = AccuracyMilestoneEvent(
            event_type="accuracy_milestone", timestamp_ms=0,
            scenarios_completed=0, scenarios_correct=0,
            running_accuracy=0.0,
        )
        with pytest.raises(AttributeError):
            e.running_accuracy = 1.0


class TestV2EventFromDict:

    def test_unknown_type_raises(self):
        with pytest.raises(ValueError):
            v2_event_from_dict({"event_type": "bogus"})

    def test_all_types_registered(self):
        from ares.visual.events_v2 import _V2_EVENT_REGISTRY
        assert "confidence_update" in _V2_EVENT_REGISTRY
        assert "fact_cited" in _V2_EVENT_REGISTRY
        assert "debate_summary" in _V2_EVENT_REGISTRY
        assert "accuracy_milestone" in _V2_EVENT_REGISTRY
