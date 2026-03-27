"""Tests for ScenarioReplayer — Session 029.

Tests covering event sequence, event counts, timestamp ordering,
timing delays, integration with corpus scenarios, and edge cases.
"""

from __future__ import annotations

import pytest
from datetime import datetime, timedelta

from ares.visual.replayer import ScenarioReplayer
from ares.visual.events import (
    AssertionFormedEvent,
    ClaimAuditEvent,
    FactIngestedEvent,
    MiscalibrationCheckEvent,
    ScenarioEndEvent,
    ScenarioStartEvent,
    VerdictRenderedEvent,
)
from ares.dialectic.evidence.fact import EntityType, Fact
from ares.dialectic.evidence.packet import EvidencePacket, TimeWindow
from ares.dialectic.evidence.provenance import Provenance, SourceType
from ares.dialectic.scripts.scenario_corpus import BenchmarkScenario, ScenarioMetadata


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ts() -> datetime:
    return datetime(2026, 1, 1, 12, 0, 0)


def _make_fact(
    fact_id: str,
    entity_id: str = "host-1",
    source_type: SourceType = SourceType.SYSLOG,
    field: str = "event",
) -> Fact:
    return Fact(
        fact_id=fact_id,
        entity_id=entity_id,
        entity_type=EntityType.NODE,
        field=field,
        value="test-value",
        timestamp=_ts(),
        provenance=Provenance(
            source_type=source_type,
            source_id="src",
            extracted_at=_ts(),
        ),
    )


def _make_scenario(
    scenario_id: str = "SC-TEST",
    name: str = "Test Scenario",
    expected_verdict: str = "THREAT_CONFIRMED",
    facts: list[Fact] | None = None,
) -> BenchmarkScenario:
    tw = TimeWindow(start=_ts() - timedelta(hours=1), end=_ts())
    pkt = EvidencePacket(packet_id=f"pkt-{scenario_id}", time_window=tw)
    for f in (facts or [_make_fact("f1"), _make_fact("f2", entity_id="host-2")]):
        pkt.add_fact(f)
    pkt.freeze()
    return BenchmarkScenario(
        metadata=ScenarioMetadata(
            scenario_id=scenario_id,
            name=name,
            description="test",
            mitre_attack_ids=("T1078",),
            mitre_tactic="initial-access",
            difficulty_tier=1,
            expected_verdict=expected_verdict,
            expected_winner="ARCHITECT",
            fact_count=pkt.fact_count,
            notes="test scenario",
        ),
        packet=pkt,
    )


# ===========================================================================
# Construction
# ===========================================================================

class TestReplayerConstruction:
    """Test ScenarioReplayer construction."""

    def test_default_delays(self) -> None:
        r = ScenarioReplayer()
        assert r.fact_delay_ms == 200
        assert r.assertion_delay_ms == 500
        assert r.verdict_delay_ms == 1000
        assert r.check_delay_ms == 500

    def test_custom_delays(self) -> None:
        r = ScenarioReplayer(fact_delay_ms=100, assertion_delay_ms=300)
        assert r.fact_delay_ms == 100
        assert r.assertion_delay_ms == 300

    def test_repr(self) -> None:
        r = ScenarioReplayer()
        assert "ScenarioReplayer" in repr(r)


# ===========================================================================
# Event sequence
# ===========================================================================

class TestEventSequence:
    """Test replay produces correct event sequence."""

    def test_starts_with_scenario_start(self) -> None:
        r = ScenarioReplayer()
        events = r.replay(_make_scenario())
        assert isinstance(events[0], ScenarioStartEvent)
        assert events[0].event_type == "scenario_start"

    def test_ends_with_scenario_end(self) -> None:
        r = ScenarioReplayer()
        events = r.replay(_make_scenario())
        assert isinstance(events[-1], ScenarioEndEvent)
        assert events[-1].event_type == "scenario_end"

    def test_facts_before_assertions(self) -> None:
        r = ScenarioReplayer()
        events = r.replay(_make_scenario())
        fact_indices = [i for i, e in enumerate(events) if isinstance(e, FactIngestedEvent)]
        assertion_indices = [i for i, e in enumerate(events) if isinstance(e, AssertionFormedEvent)]
        if fact_indices and assertion_indices:
            assert max(fact_indices) < min(assertion_indices)

    def test_verdict_after_assertions(self) -> None:
        r = ScenarioReplayer()
        events = r.replay(_make_scenario())
        verdict_idx = [i for i, e in enumerate(events) if isinstance(e, VerdictRenderedEvent)]
        assertion_idx = [i for i, e in enumerate(events) if isinstance(e, AssertionFormedEvent)]
        if verdict_idx and assertion_idx:
            assert min(verdict_idx) > max(assertion_idx)

    def test_miscalibration_after_verdict(self) -> None:
        r = ScenarioReplayer()
        events = r.replay(_make_scenario())
        verdict_idx = [i for i, e in enumerate(events) if isinstance(e, VerdictRenderedEvent)]
        misc_idx = [i for i, e in enumerate(events) if isinstance(e, MiscalibrationCheckEvent)]
        assert len(verdict_idx) == 1
        assert len(misc_idx) == 1
        assert misc_idx[0] > verdict_idx[0]

    def test_always_has_miscalibration_check(self) -> None:
        r = ScenarioReplayer()
        events = r.replay(_make_scenario())
        misc_events = [e for e in events if isinstance(e, MiscalibrationCheckEvent)]
        assert len(misc_events) == 1


# ===========================================================================
# Event counts
# ===========================================================================

class TestEventCounts:
    """Test event counts match scenario content."""

    def test_fact_count_matches_packet(self) -> None:
        facts = [_make_fact(f"f{i}", entity_id=f"h{i}") for i in range(5)]
        scenario = _make_scenario(facts=facts)
        r = ScenarioReplayer()
        events = r.replay(scenario)
        fact_events = [e for e in events if isinstance(e, FactIngestedEvent)]
        assert len(fact_events) == 5

    def test_single_fact_scenario(self) -> None:
        scenario = _make_scenario(facts=[_make_fact("f1")])
        r = ScenarioReplayer()
        events = r.replay(scenario)
        fact_events = [e for e in events if isinstance(e, FactIngestedEvent)]
        assert len(fact_events) == 1

    def test_has_at_least_start_and_end(self) -> None:
        r = ScenarioReplayer()
        events = r.replay(_make_scenario())
        assert len(events) >= 2  # At minimum: start + end


# ===========================================================================
# Timestamps
# ===========================================================================

class TestTimestamps:
    """Test timestamp ordering and delays."""

    def test_timestamps_monotonically_increasing(self) -> None:
        r = ScenarioReplayer()
        events = r.replay(_make_scenario())
        timestamps = [e.timestamp_ms for e in events]
        for i in range(1, len(timestamps)):
            assert timestamps[i] >= timestamps[i - 1]

    def test_scenario_start_at_zero(self) -> None:
        r = ScenarioReplayer()
        events = r.replay(_make_scenario())
        assert events[0].timestamp_ms == 0

    def test_fact_delay_respected(self) -> None:
        r = ScenarioReplayer(fact_delay_ms=100)
        facts = [_make_fact(f"f{i}", entity_id=f"h{i}") for i in range(3)]
        events = r.replay(_make_scenario(facts=facts))
        fact_events = [e for e in events if isinstance(e, FactIngestedEvent)]
        for i in range(1, len(fact_events)):
            delta = fact_events[i].timestamp_ms - fact_events[i - 1].timestamp_ms
            assert delta == 100

    def test_end_duration_equals_timestamp(self) -> None:
        r = ScenarioReplayer()
        events = r.replay(_make_scenario())
        end = events[-1]
        assert isinstance(end, ScenarioEndEvent)
        assert end.duration_ms == end.timestamp_ms


# ===========================================================================
# Scenario ID propagation
# ===========================================================================

class TestScenarioIdPropagation:
    """Test all events carry the correct scenario_id."""

    def test_all_events_have_scenario_id(self) -> None:
        r = ScenarioReplayer()
        events = r.replay(_make_scenario(scenario_id="SC-042"))
        for event in events:
            assert event.scenario_id == "SC-042"


# ===========================================================================
# Integration with corpus
# ===========================================================================

class TestCorpusIntegration:
    """Test replay works with actual corpus scenarios."""

    def test_replay_sc001(self) -> None:
        from ares.dialectic.scripts.scenario_corpus import get_scenario_by_id
        scenario = get_scenario_by_id("SC-001")
        r = ScenarioReplayer()
        events = r.replay(scenario)
        assert len(events) > 0
        assert isinstance(events[0], ScenarioStartEvent)
        assert events[0].scenario_id == "SC-001"

    def test_replay_sc019(self) -> None:
        from ares.dialectic.scripts.expanded_scenarios import get_expanded_scenario_by_id
        scenario = get_expanded_scenario_by_id("SC-019")
        r = ScenarioReplayer()
        events = r.replay(scenario)
        assert len(events) > 0
        assert isinstance(events[0], ScenarioStartEvent)

    def test_replay_produces_verdict(self) -> None:
        from ares.dialectic.scripts.scenario_corpus import get_scenario_by_id
        scenario = get_scenario_by_id("SC-002")
        r = ScenarioReplayer()
        events = r.replay(scenario)
        verdicts = [e for e in events if isinstance(e, VerdictRenderedEvent)]
        assert len(verdicts) == 1
        assert verdicts[0].outcome in ("threat_confirmed", "threat_dismissed", "inconclusive")

    def test_replay_source_types_populated(self) -> None:
        from ares.dialectic.scripts.scenario_corpus import get_scenario_by_id
        scenario = get_scenario_by_id("SC-001")
        r = ScenarioReplayer()
        events = r.replay(scenario)
        start = events[0]
        assert isinstance(start, ScenarioStartEvent)
        assert len(start.source_types) > 0


# ===========================================================================
# Edge cases
# ===========================================================================

class TestEdgeCases:
    """Edge case tests."""

    def test_events_are_tuple(self) -> None:
        r = ScenarioReplayer()
        events = r.replay(_make_scenario())
        assert isinstance(events, tuple)

    def test_all_events_have_to_dict(self) -> None:
        r = ScenarioReplayer()
        events = r.replay(_make_scenario())
        for event in events:
            d = event.to_dict()
            assert isinstance(d, dict)
            assert "event_type" in d
