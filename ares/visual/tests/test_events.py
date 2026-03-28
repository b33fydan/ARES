"""Tests for visual event schema — Session 029.

Tests covering event construction, to_dict() serialization,
event_from_dict() round-trip, immutability, and validation.
"""

from __future__ import annotations

import json
import pytest

from ares.visual.events import (
    AssertionFormedEvent,
    ClaimAuditEvent,
    FactIngestedEvent,
    MiscalibrationCheckEvent,
    ScenarioEndEvent,
    ScenarioStartEvent,
    VerdictRenderedEvent,
    VisualEvent,
    event_from_dict,
)


# ===========================================================================
# Construction
# ===========================================================================

class TestEventConstruction:
    """Test each event type constructs correctly."""

    def test_scenario_start_event(self) -> None:
        e = ScenarioStartEvent(
            event_type="scenario_start",
            timestamp_ms=0,
            scenario_id="SC-001",
            scenario_name="Test",
            expected_verdict="THREAT_CONFIRMED",
            fact_count=5,
            source_types=("syslog", "netflow"),
        )
        assert e.event_type == "scenario_start"
        assert e.fact_count == 5

    def test_fact_ingested_event(self) -> None:
        e = FactIngestedEvent(
            event_type="fact_ingested",
            timestamp_ms=200,
            scenario_id="SC-001",
            fact_id="f1",
            entity_type="node",
            entity_id="host-1",
            source_type="syslog",
            field_name="event",
            source_index=0,
            fact_index=0,
        )
        assert e.fact_id == "f1"
        assert e.source_index == 0

    def test_assertion_formed_event(self) -> None:
        e = AssertionFormedEvent(
            event_type="assertion_formed",
            timestamp_ms=1000,
            scenario_id="SC-001",
            assertion_id="a1",
            assertion_type="assert",
            content="suspicious login",
            cited_fact_ids=("f1", "f2"),
            confidence=0.85,
        )
        assert e.cited_fact_ids == ("f1", "f2")
        assert e.confidence == 0.85

    def test_verdict_rendered_event(self) -> None:
        e = VerdictRenderedEvent(
            event_type="verdict_rendered",
            timestamp_ms=2000,
            scenario_id="SC-001",
            outcome="THREAT_CONFIRMED",
            confidence=0.80,
            correct=True,
        )
        assert e.correct is True

    def test_miscalibration_check_event(self) -> None:
        e = MiscalibrationCheckEvent(
            event_type="miscalibration_check",
            timestamp_ms=2500,
            scenario_id="SC-001",
            flagged=True,
            patterns_triggered=("evidence_starvation",),
            risk_score=0.25,
            recommendation="inspect",
        )
        assert e.flagged is True

    def test_claim_audit_event(self) -> None:
        e = ClaimAuditEvent(
            event_type="claim_audit",
            timestamp_ms=3000,
            scenario_id="SC-001",
            claims_total=3,
            claims_supported=1,
            claims_weak=1,
            claims_unsupported=1,
            audit_verdict="miscalibrated",
        )
        assert e.claims_total == 3

    def test_scenario_end_event(self) -> None:
        e = ScenarioEndEvent(
            event_type="scenario_end",
            timestamp_ms=4000,
            scenario_id="SC-001",
            duration_ms=4000,
        )
        assert e.duration_ms == 4000


# ===========================================================================
# Serialization (to_dict)
# ===========================================================================

class TestSerialization:
    """Test to_dict() produces valid JSON-serializable dicts."""

    def test_scenario_start_to_dict(self) -> None:
        e = ScenarioStartEvent(
            event_type="scenario_start",
            timestamp_ms=0,
            scenario_id="SC-001",
            scenario_name="Test",
            expected_verdict="THREAT_CONFIRMED",
            fact_count=5,
            source_types=("syslog",),
        )
        d = e.to_dict()
        assert d["event_type"] == "scenario_start"
        assert d["source_types"] == ["syslog"]
        assert isinstance(d["source_types"], list)

    def test_fact_ingested_to_dict(self) -> None:
        e = FactIngestedEvent(
            event_type="fact_ingested",
            timestamp_ms=200,
            scenario_id="SC-001",
            fact_id="f1",
            entity_type="node",
            entity_id="host-1",
            source_type="syslog",
            field_name="event",
            source_index=0,
            fact_index=0,
        )
        d = e.to_dict()
        assert json.dumps(d)  # Must be JSON-serializable

    def test_assertion_to_dict_converts_tuple_to_list(self) -> None:
        e = AssertionFormedEvent(
            event_type="assertion_formed",
            timestamp_ms=1000,
            scenario_id="SC-001",
            assertion_id="a1",
            assertion_type="assert",
            content="claim",
            cited_fact_ids=("f1", "f2"),
            confidence=0.5,
        )
        d = e.to_dict()
        assert isinstance(d["cited_fact_ids"], list)

    def test_all_events_json_serializable(self) -> None:
        events = [
            ScenarioStartEvent("scenario_start", 0, "SC-001", "Test", "THREAT_CONFIRMED", 1, ("syslog",)),
            FactIngestedEvent("fact_ingested", 100, "SC-001", "f1", "node", "h1", "syslog", "ev", 0, 0),
            AssertionFormedEvent("assertion_formed", 200, "SC-001", "a1", "assert", "claim", ("f1",), 0.8),
            VerdictRenderedEvent("verdict_rendered", 300, "SC-001", "THREAT_CONFIRMED", 0.8, True),
            MiscalibrationCheckEvent("miscalibration_check", 400, "SC-001", False, (), 0.0, "pass"),
            ScenarioEndEvent("scenario_end", 500, "SC-001", 500),
        ]
        for e in events:
            payload = json.dumps(e.to_dict())
            assert isinstance(payload, str)


# ===========================================================================
# Deserialization (event_from_dict)
# ===========================================================================

class TestDeserialization:
    """Test event_from_dict round-trips correctly."""

    def test_round_trip_scenario_start(self) -> None:
        original = ScenarioStartEvent("scenario_start", 0, "SC-001", "Test", "THREAT_CONFIRMED", 3, ("syslog",))
        d = original.to_dict()
        restored = event_from_dict(d)
        assert restored == original

    def test_round_trip_fact_ingested(self) -> None:
        original = FactIngestedEvent("fact_ingested", 200, "SC-001", "f1", "node", "h1", "syslog", "ev", 0, 0)
        d = original.to_dict()
        restored = event_from_dict(d)
        assert restored == original

    def test_round_trip_assertion_formed(self) -> None:
        original = AssertionFormedEvent("assertion_formed", 500, "SC-001", "a1", "assert", "claim", ("f1", "f2"), 0.8)
        d = original.to_dict()
        restored = event_from_dict(d)
        assert restored == original

    def test_round_trip_verdict(self) -> None:
        original = VerdictRenderedEvent("verdict_rendered", 1000, "SC-001", "INCONCLUSIVE", 0.5, False)
        d = original.to_dict()
        restored = event_from_dict(d)
        assert restored == original

    def test_round_trip_miscalibration(self) -> None:
        original = MiscalibrationCheckEvent("miscalibration_check", 1500, "SC-001", True, ("evidence_starvation",), 0.25, "inspect")
        d = original.to_dict()
        restored = event_from_dict(d)
        assert restored == original

    def test_round_trip_claim_audit(self) -> None:
        original = ClaimAuditEvent("claim_audit", 2000, "SC-001", 3, 1, 1, 1, "miscalibrated")
        d = original.to_dict()
        restored = event_from_dict(d)
        assert restored == original

    def test_round_trip_scenario_end(self) -> None:
        original = ScenarioEndEvent("scenario_end", 3000, "SC-001", 3000)
        d = original.to_dict()
        restored = event_from_dict(d)
        assert restored == original

    def test_unknown_event_type_raises(self) -> None:
        with pytest.raises(ValueError, match="Unknown event_type"):
            event_from_dict({"event_type": "not_a_real_event"})


# ===========================================================================
# Immutability
# ===========================================================================

class TestImmutability:
    """Test all event types are frozen."""

    def test_scenario_start_frozen(self) -> None:
        e = ScenarioStartEvent("scenario_start", 0, "SC-001", "Test", "THREAT_CONFIRMED", 1, ())
        with pytest.raises(AttributeError):
            e.fact_count = 99  # type: ignore[misc]

    def test_fact_ingested_frozen(self) -> None:
        e = FactIngestedEvent("fact_ingested", 100, "SC-001", "f1", "node", "h1", "syslog", "ev", 0, 0)
        with pytest.raises(AttributeError):
            e.fact_id = "f99"  # type: ignore[misc]

    def test_verdict_frozen(self) -> None:
        e = VerdictRenderedEvent("verdict_rendered", 1000, "SC-001", "THREAT_CONFIRMED", 0.8, True)
        with pytest.raises(AttributeError):
            e.correct = False  # type: ignore[misc]

    def test_claim_audit_frozen(self) -> None:
        e = ClaimAuditEvent("claim_audit", 2000, "SC-001", 3, 1, 1, 1, "confirmed")
        with pytest.raises(AttributeError):
            e.claims_total = 99  # type: ignore[misc]
