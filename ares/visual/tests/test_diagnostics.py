"""Tests for ares.visual.diagnostics — event sequence validation.

Session 030: Tests that validate_sequence correctly detects structural
and data anomalies in ARES visual event sequences.
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from ares.visual.diagnostics import (
    AnomalySeverity,
    AnomalyType,
    DiagnosticResult,
    SequenceAnomaly,
    validate_sequence,
)
from ares.visual.events import (
    AssertionFormedEvent,
    FactIngestedEvent,
    MiscalibrationCheckEvent,
    ScenarioEndEvent,
    ScenarioStartEvent,
    VerdictRenderedEvent,
)


# ---------------------------------------------------------------------------
# Helpers — synthetic event builders
# ---------------------------------------------------------------------------

def _start(scenario_id: str = "SC-TEST", fact_count: int = 2) -> ScenarioStartEvent:
    return ScenarioStartEvent(
        event_type="scenario_start",
        timestamp_ms=0,
        scenario_id=scenario_id,
        scenario_name="Test Scenario",
        expected_verdict="THREAT_CONFIRMED",
        fact_count=fact_count,
        source_types=("syslog",),
    )


def _fact(fact_id: str = "f1", ts: int = 100) -> FactIngestedEvent:
    return FactIngestedEvent(
        event_type="fact_ingested",
        timestamp_ms=ts,
        scenario_id="SC-TEST",
        fact_id=fact_id,
        entity_type="node",
        entity_id="user-1",
        source_type="syslog",
        field_name="command_line",
        source_index=0,
        fact_index=0,
    )


def _assertion(
    assertion_id: str = "a1",
    cited: tuple = ("f1",),
    confidence: float = 0.8,
    ts: int = 500,
) -> AssertionFormedEvent:
    return AssertionFormedEvent(
        event_type="assertion_formed",
        timestamp_ms=ts,
        scenario_id="SC-TEST",
        assertion_id=assertion_id,
        assertion_type="ASSERT",
        content="Test assertion",
        cited_fact_ids=cited,
        confidence=confidence,
    )


def _verdict(ts: int = 1000) -> VerdictRenderedEvent:
    return VerdictRenderedEvent(
        event_type="verdict_rendered",
        timestamp_ms=ts,
        scenario_id="SC-TEST",
        outcome="THREAT_CONFIRMED",
        confidence=0.85,
        correct=True,
    )


def _misc(ts: int = 1200) -> MiscalibrationCheckEvent:
    return MiscalibrationCheckEvent(
        event_type="miscalibration_check",
        timestamp_ms=ts,
        scenario_id="SC-TEST",
        flagged=False,
        patterns_triggered=(),
        risk_score=0.1,
        recommendation="accept",
    )


def _end(ts: int = 1500) -> ScenarioEndEvent:
    return ScenarioEndEvent(
        event_type="scenario_end",
        timestamp_ms=ts,
        scenario_id="SC-TEST",
        duration_ms=ts,
    )


@dataclass
class _MockPacket:
    """Minimal mock matching the interface validate_sequence needs."""
    fact_count: int


def _valid_sequence(n_facts: int = 2):
    """Build a well-formed event sequence with n_facts facts."""
    events = [_start(fact_count=n_facts)]
    for i in range(n_facts):
        events.append(_fact(fact_id=f"f{i}", ts=100 + i * 100))
    events.append(_assertion(cited=(f"f0",), ts=500))
    events.append(_verdict(ts=1000))
    events.append(_misc(ts=1200))
    events.append(_end(ts=1500))
    return events, _MockPacket(fact_count=n_facts)


# ---------------------------------------------------------------------------
# Valid Sequences
# ---------------------------------------------------------------------------

class TestValidSequences:
    """Validate that well-formed sequences pass cleanly."""

    def test_valid_sequence_returns_no_critical_anomalies(self):
        events, packet = _valid_sequence()
        result = validate_sequence(events, packet, "SC-TEST")
        assert result.critical_count == 0

    def test_valid_sequence_is_valid_true(self):
        events, packet = _valid_sequence()
        result = validate_sequence(events, packet, "SC-TEST")
        assert result.is_valid is True

    def test_valid_sequence_counts_fact_events(self):
        events, packet = _valid_sequence(n_facts=3)
        result = validate_sequence(events, packet, "SC-TEST")
        assert result.fact_events == 3

    def test_valid_sequence_counts_assertion_events(self):
        events, packet = _valid_sequence()
        result = validate_sequence(events, packet, "SC-TEST")
        assert result.assertion_events == 1

    def test_valid_sequence_total_events(self):
        events, packet = _valid_sequence(n_facts=2)
        result = validate_sequence(events, packet, "SC-TEST")
        # start + 2 facts + 1 assertion + verdict + misc + end = 7
        assert result.total_events == 7


# ---------------------------------------------------------------------------
# Missing Bookends
# ---------------------------------------------------------------------------

class TestMissingBookends:
    """Detect missing scenario_start and scenario_end."""

    def test_missing_scenario_start_is_critical(self):
        events = [_fact(), _verdict(), _end()]
        packet = _MockPacket(fact_count=1)
        result = validate_sequence(events, packet, "SC-TEST")
        types = [a.anomaly_type for a in result.anomalies]
        assert AnomalyType.MISSING_SCENARIO_START in types
        assert not result.is_valid

    def test_missing_scenario_end_is_critical(self):
        events = [_start(fact_count=1), _fact(), _assertion(), _verdict()]
        packet = _MockPacket(fact_count=1)
        result = validate_sequence(events, packet, "SC-TEST")
        types = [a.anomaly_type for a in result.anomalies]
        assert AnomalyType.MISSING_SCENARIO_END in types
        assert not result.is_valid


# ---------------------------------------------------------------------------
# Missing / Multiple Verdicts
# ---------------------------------------------------------------------------

class TestVerdictChecks:
    """Detect missing or duplicate verdicts."""

    def test_missing_verdict_is_critical(self):
        events = [_start(fact_count=1), _fact(), _end()]
        packet = _MockPacket(fact_count=1)
        result = validate_sequence(events, packet, "SC-TEST")
        types = [a.anomaly_type for a in result.anomalies]
        assert AnomalyType.MISSING_VERDICT in types
        assert not result.is_valid

    def test_multiple_verdicts_detected(self):
        events = [
            _start(fact_count=1),
            _fact(),
            _assertion(),
            _verdict(ts=800),
            _verdict(ts=900),
            _end(),
        ]
        packet = _MockPacket(fact_count=1)
        result = validate_sequence(events, packet, "SC-TEST")
        types = [a.anomaly_type for a in result.anomalies]
        assert AnomalyType.WRONG_EVENT_ORDER in types


# ---------------------------------------------------------------------------
# Fact Count Mismatch
# ---------------------------------------------------------------------------

class TestFactCountMismatch:
    """Detect fact count disagreements with packet."""

    def test_fewer_fact_events_than_packet_is_critical(self):
        events = [_start(fact_count=3), _fact(), _assertion(), _verdict(), _end()]
        packet = _MockPacket(fact_count=3)
        result = validate_sequence(events, packet, "SC-TEST")
        types = [a.anomaly_type for a in result.anomalies]
        assert AnomalyType.FACT_COUNT_MISMATCH in types
        assert not result.is_valid

    def test_more_fact_events_than_packet_is_critical(self):
        events = [
            _start(fact_count=1),
            _fact(fact_id="f0"),
            _fact(fact_id="f1"),
            _assertion(),
            _verdict(),
            _end(),
        ]
        packet = _MockPacket(fact_count=1)
        result = validate_sequence(events, packet, "SC-TEST")
        types = [a.anomaly_type for a in result.anomalies]
        assert AnomalyType.FACT_COUNT_MISMATCH in types

    def test_exact_fact_match_no_anomaly(self):
        events, packet = _valid_sequence(n_facts=2)
        result = validate_sequence(events, packet, "SC-TEST")
        types = [a.anomaly_type for a in result.anomalies]
        assert AnomalyType.FACT_COUNT_MISMATCH not in types


# ---------------------------------------------------------------------------
# Ordering Violations
# ---------------------------------------------------------------------------

class TestOrderingViolations:
    """Detect events in wrong lifecycle order."""

    def test_fact_after_verdict_is_critical(self):
        events = [
            _start(fact_count=2),
            _fact(fact_id="f0", ts=100),
            _assertion(ts=500),
            _verdict(ts=800),
            _fact(fact_id="f1", ts=900),  # After verdict!
            _end(),
        ]
        packet = _MockPacket(fact_count=2)
        result = validate_sequence(events, packet, "SC-TEST")
        types = [a.anomaly_type for a in result.anomalies]
        assert AnomalyType.WRONG_EVENT_ORDER in types
        assert not result.is_valid

    def test_assertion_before_any_fact_is_ordering_violation(self):
        events = [
            _start(fact_count=1),
            _assertion(ts=50),  # Before any fact!
            _fact(ts=100),
            _verdict(),
            _end(),
        ]
        packet = _MockPacket(fact_count=1)
        result = validate_sequence(events, packet, "SC-TEST")
        types = [a.anomaly_type for a in result.anomalies]
        assert AnomalyType.WRONG_EVENT_ORDER in types


# ---------------------------------------------------------------------------
# Warnings
# ---------------------------------------------------------------------------

class TestWarnings:
    """Detect non-critical anomalies."""

    def test_zero_assertions_is_warning(self):
        events = [_start(fact_count=1), _fact(), _verdict(), _end()]
        packet = _MockPacket(fact_count=1)
        result = validate_sequence(events, packet, "SC-TEST")
        types = [a.anomaly_type for a in result.anomalies]
        assert AnomalyType.ZERO_ASSERTIONS in types
        # Should be WARNING, not CRITICAL
        for a in result.anomalies:
            if a.anomaly_type == AnomalyType.ZERO_ASSERTIONS:
                assert a.severity == AnomalySeverity.WARNING

    def test_high_event_count_is_warning(self):
        n = 55
        events = [_start(fact_count=n)]
        for i in range(n):
            events.append(_fact(fact_id=f"f{i}", ts=100 + i * 10))
        events.append(_assertion(cited=("f0",), ts=700))
        events.append(_verdict(ts=800))
        events.append(_end(ts=900))
        packet = _MockPacket(fact_count=n)
        result = validate_sequence(events, packet, "SC-TEST")
        types = [a.anomaly_type for a in result.anomalies]
        assert AnomalyType.HIGH_EVENT_COUNT in types
        assert result.is_valid  # Warnings don't break validity

    def test_duplicate_fact_event_is_warning(self):
        events = [
            _start(fact_count=2),
            _fact(fact_id="f0", ts=100),
            _fact(fact_id="f0", ts=200),  # Duplicate!
            _assertion(ts=500),
            _verdict(),
            _end(),
        ]
        packet = _MockPacket(fact_count=2)
        result = validate_sequence(events, packet, "SC-TEST")
        types = [a.anomaly_type for a in result.anomalies]
        assert AnomalyType.DUPLICATE_FACT_EVENT in types

    def test_orphaned_assertion_is_warning(self):
        events = [
            _start(fact_count=1),
            _fact(fact_id="f0", ts=100),
            _assertion(cited=("f0", "f_missing"), ts=500),
            _verdict(),
            _end(),
        ]
        packet = _MockPacket(fact_count=1)
        result = validate_sequence(events, packet, "SC-TEST")
        types = [a.anomaly_type for a in result.anomalies]
        assert AnomalyType.ORPHANED_ASSERTION in types


# ---------------------------------------------------------------------------
# Edge Cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    """Edge cases for empty and minimal sequences."""

    def test_empty_event_list_all_critical(self):
        result = validate_sequence([], _MockPacket(fact_count=1), "SC-TEST")
        assert result.critical_count >= 3  # missing start, end, verdict
        assert not result.is_valid

    def test_single_event_only_scenario_start(self):
        events = [_start(fact_count=1)]
        packet = _MockPacket(fact_count=1)
        result = validate_sequence(events, packet, "SC-TEST")
        types = [a.anomaly_type for a in result.anomalies]
        assert AnomalyType.MISSING_SCENARIO_END in types
        assert AnomalyType.MISSING_VERDICT in types


# ---------------------------------------------------------------------------
# Property Tests
# ---------------------------------------------------------------------------

class TestProperties:
    """Tests for computed properties on result dataclasses."""

    def test_critical_count_property(self):
        events = []
        result = validate_sequence(events, _MockPacket(fact_count=1), "SC-TEST")
        assert result.critical_count == result.total_events + len(
            [a for a in result.anomalies if a.severity == AnomalySeverity.CRITICAL]
        ) or result.critical_count >= 0
        # Just verify it returns an int matching manual count
        manual = sum(1 for a in result.anomalies if a.severity == AnomalySeverity.CRITICAL)
        assert result.critical_count == manual

    def test_warning_count_property(self):
        events, packet = _valid_sequence()
        result = validate_sequence(events, packet, "SC-TEST")
        manual = sum(1 for a in result.anomalies if a.severity == AnomalySeverity.WARNING)
        assert result.warning_count == manual

    def test_diagnostic_result_is_frozen(self):
        events, packet = _valid_sequence()
        result = validate_sequence(events, packet, "SC-TEST")
        with pytest.raises(AttributeError):
            result.scenario_id = "hacked"

    def test_sequence_anomaly_is_frozen(self):
        anomaly = SequenceAnomaly(
            anomaly_type=AnomalyType.MISSING_VERDICT,
            severity=AnomalySeverity.CRITICAL,
            description="test",
            event_index=None,
        )
        with pytest.raises(AttributeError):
            anomaly.description = "hacked"

    def test_scenario_id_propagated(self):
        events, packet = _valid_sequence()
        result = validate_sequence(events, packet, "MY-ID")
        assert result.scenario_id == "MY-ID"


# ---------------------------------------------------------------------------
# Integration with real corpus
# ---------------------------------------------------------------------------

class TestRealCorpus:
    """Validate against actual corpus scenarios."""

    def test_sc001_produces_valid_sequence(self):
        from ares.dialectic.scripts.expanded_scenarios import get_full_corpus
        from ares.visual.replayer import ScenarioReplayer

        scenario = next(
            s for s in get_full_corpus()
            if s.metadata.scenario_id == "SC-001"
        )
        replayer = ScenarioReplayer()
        events = replayer.replay(scenario)
        result = validate_sequence(events, scenario.packet, "SC-001")
        assert result.is_valid
        assert result.fact_events == scenario.packet.fact_count

    def test_sc019_produces_valid_sequence(self):
        from ares.dialectic.scripts.expanded_scenarios import get_full_corpus
        from ares.visual.replayer import ScenarioReplayer

        scenario = next(
            s for s in get_full_corpus()
            if s.metadata.scenario_id == "SC-019"
        )
        replayer = ScenarioReplayer()
        events = replayer.replay(scenario)
        result = validate_sequence(events, scenario.packet, "SC-019")
        assert result.is_valid
