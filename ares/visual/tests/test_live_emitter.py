"""Tests for LiveAnalysisEmitter — mocked LLM, zero API cost.

Session 039: Validates the full event emission pipeline by mocking
run_cycle_with_strategies. Tests the emitter, not the dialectical engine.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime
from typing import List, Optional
from unittest.mock import MagicMock, patch

import pytest

from ares.dialectic.agents.patterns import (
    AnomalyPattern,
    BenignExplanation,
    Verdict,
    VerdictOutcome,
)
from ares.dialectic.evidence.fact import EntityType, Fact
from ares.dialectic.evidence.packet import EvidencePacket, TimeWindow
from ares.dialectic.evidence.provenance import Provenance, SourceType
from ares.dialectic.messages.assertions import Assertion, AssertionType
from ares.dialectic.messages.protocol import DialecticalMessage, Phase
from ares.dialectic.coordinator.orchestrator import CycleError, CycleResult
from ares.dialectic.scripts.scenario_corpus import BenchmarkScenario, ScenarioMetadata
from ares.visual.live_emitter import LiveAnalysisEmitter, LiveScenarioResult


# =========================================================================
# HELPERS — inline, not shared conftest
# =========================================================================

_TW = TimeWindow(start=datetime(2026, 3, 29), end=datetime(2026, 3, 29, 1))


def _make_fact(fact_id: str, entity_id: str = "ent-1") -> Fact:
    return Fact(
        fact_id=fact_id,
        entity_id=entity_id,
        entity_type=EntityType.NODE,
        field="test_field",
        value=f"value-{fact_id}",
        timestamp="2026-03-29T00:00:00Z",
        provenance=Provenance(
            source_type=SourceType.PROCESS_LIST,
            source_id="test-src-001",
        ),
    )


def _make_packet(fact_count: int = 4) -> EvidencePacket:
    packet = EvidencePacket(packet_id="pkt-test", time_window=_TW)
    for i in range(fact_count):
        packet.add_fact(_make_fact(f"fact-{i:03d}", entity_id=f"ent-{i % 3}"))
    packet.freeze()
    return packet


def _make_scenario(
    scenario_id: str = "SC-TEST",
    name: str = "Test Scenario",
    fact_count: int = 4,
    expected_verdict: str = "THREAT_CONFIRMED",
) -> BenchmarkScenario:
    packet = _make_packet(fact_count)
    meta = ScenarioMetadata(
        scenario_id=scenario_id,
        name=name,
        description="Test scenario",
        mitre_attack_ids=("T1059",),
        mitre_tactic="execution",
        difficulty_tier=1,
        expected_verdict=expected_verdict,
        expected_winner="ARCHITECT",
        fact_count=fact_count,
        notes="test",
    )
    return BenchmarkScenario(metadata=meta, packet=packet)


def _make_cycle_result(
    packet,
    outcome: VerdictOutcome = VerdictOutcome.THREAT_CONFIRMED,
    arch_conf: float = 0.92,
    skep_conf: float = 0.25,
    arch_facts: tuple = ("fact-000", "fact-001", "fact-002"),
    skep_facts: tuple = ("fact-001", "fact-003"),
) -> CycleResult:
    """Create a mock CycleResult with realistic structure."""
    arch_assertion = Assertion(
        assertion_id="assert-a1",
        assertion_type=AssertionType.ASSERT,
        fact_ids=arch_facts,
        interpretation="Suspicious process detected",
    )
    now = datetime.utcnow()
    arch_msg = DialecticalMessage(
        message_id="msg-arch",
        timestamp=now,
        source_agent="ares-arch-test",
        target_agent="ares-skep-test",
        phase=Phase.THESIS,
        assertions=[arch_assertion],
        confidence=arch_conf,
    )

    skep_assertion = Assertion(
        assertion_id="assert-s1",
        assertion_type=AssertionType.ALT,
        fact_ids=skep_facts,
        interpretation="Scheduled maintenance explains this",
    )
    skep_msg = DialecticalMessage(
        message_id="msg-skep",
        timestamp=now,
        source_agent="ares-skep-test",
        target_agent="ares-arch-test",
        phase=Phase.ANTITHESIS,
        assertions=[skep_assertion],
        confidence=skep_conf,
    )

    verdict = Verdict(
        outcome=outcome,
        confidence=max(arch_conf, skep_conf),
        supporting_fact_ids=frozenset(arch_facts),
        architect_confidence=arch_conf,
        skeptic_confidence=skep_conf,
        reasoning="Mock verdict reasoning",
    )

    now = datetime.utcnow()
    return CycleResult(
        cycle_id="cycle-test",
        packet_id=packet.packet_id,
        verdict=verdict,
        architect_message=arch_msg,
        skeptic_message=skep_msg,
        narrator_message=None,
        started_at=now,
        completed_at=now,
        duration_ms=100,
    )


class MockSendCollector:
    """Collects all events sent via the emitter."""

    def __init__(self):
        self.events: List[dict] = []
        self.raw: List[str] = []

    async def __call__(self, payload: str) -> None:
        self.raw.append(payload)
        self.events.append(json.loads(payload))

    @property
    def types(self) -> List[str]:
        return [e["event_type"] for e in self.events]


# Patch target for run_cycle_with_strategies
_CYCLE_PATH = "ares.dialectic.agents.strategies.live_cycle.run_cycle_with_strategies"


# =========================================================================
# TESTS
# =========================================================================

class TestLiveAnalysisEmitterConstruction:

    def test_constructs_with_send_fn(self):
        c = MockSendCollector()
        em = LiveAnalysisEmitter(send_fn=c, speed=1.0)
        assert em.scenarios_completed == 0
        assert em.scenarios_correct == 0

    def test_custom_speed(self):
        c = MockSendCollector()
        em = LiveAnalysisEmitter(send_fn=c, speed=0.5)
        assert em._speed == 0.5


class TestSingleScenarioLive:
    """Single scenario with mocked cycle runner."""

    @pytest.fixture
    def collector(self):
        return MockSendCollector()

    @pytest.fixture
    def emitter(self, collector):
        return LiveAnalysisEmitter(send_fn=collector, speed=0.001)

    @pytest.fixture
    def scenario(self):
        return _make_scenario(fact_count=4, expected_verdict="THREAT_CONFIRMED")

    def _run(self, emitter, scenario, collector, outcome=VerdictOutcome.THREAT_CONFIRMED):
        cr = _make_cycle_result(scenario.packet, outcome=outcome)
        with patch(_CYCLE_PATH, return_value=cr):
            return asyncio.get_event_loop().run_until_complete(
                emitter.analyze_scenario_live(
                    scenario, MagicMock(), MagicMock(), MagicMock(),
                )
            )

    def test_returns_live_scenario_result(self, emitter, scenario, collector):
        r = self._run(emitter, scenario, collector)
        assert isinstance(r, LiveScenarioResult)
        assert r.scenario_id == "SC-TEST"
        assert r.error is None

    def test_scenario_start_first(self, emitter, scenario, collector):
        self._run(emitter, scenario, collector)
        assert collector.types[0] == "scenario_start"
        assert collector.events[0]["scenario_id"] == "SC-TEST"
        assert collector.events[0]["fact_count"] == 4

    def test_all_facts_before_cited(self, emitter, scenario, collector):
        self._run(emitter, scenario, collector)
        ingested_idx = [i for i, t in enumerate(collector.types) if t == "fact_ingested"]
        cited_idx = [i for i, t in enumerate(collector.types) if t == "fact_cited"]
        assert ingested_idx, "Should have fact_ingested"
        assert cited_idx, "Should have fact_cited"
        assert max(ingested_idx) < min(cited_idx)

    def test_correct_event_order(self, emitter, scenario, collector):
        self._run(emitter, scenario, collector)
        required_order = [
            "scenario_start",
            "fact_ingested",
            "analysis_status",
            "fact_cited",
            "confidence_update",
            "debate_summary",
            "verdict_rendered",
            "accuracy_milestone",
            "scenario_end",
        ]
        positions = {}
        for rt in required_order:
            for i, t in enumerate(collector.types):
                if t == rt and rt not in positions:
                    positions[rt] = i
                    break
        assert len(positions) == len(required_order), (
            f"Missing: {set(required_order) - set(positions.keys())}"
        )
        prev = -1
        for rt in required_order:
            assert positions[rt] > prev, f"{rt} out of order"
            prev = positions[rt]

    def test_fact_ingested_count(self, emitter, scenario, collector):
        self._run(emitter, scenario, collector)
        ingested = [e for e in collector.events if e["event_type"] == "fact_ingested"]
        assert len(ingested) == 4

    def test_verdict_rendered(self, emitter, scenario, collector):
        self._run(emitter, scenario, collector)
        verdicts = [e for e in collector.events if e["event_type"] == "verdict_rendered"]
        assert len(verdicts) == 1
        assert verdicts[0]["outcome"] == "threat_confirmed"

    def test_confidence_values(self, emitter, scenario, collector):
        self._run(emitter, scenario, collector)
        confs = [e for e in collector.events if e["event_type"] == "confidence_update"]
        assert len(confs) == 1
        assert confs[0]["architect_confidence"] == 0.92
        assert confs[0]["skeptic_confidence"] == 0.25
        assert "delta" in confs[0]

    def test_accuracy_milestone(self, emitter, scenario, collector):
        self._run(emitter, scenario, collector)
        ms = [e for e in collector.events if e["event_type"] == "accuracy_milestone"]
        assert len(ms) == 1
        assert ms[0]["scenarios_completed"] == 1

    def test_analysis_status_emitted(self, emitter, scenario, collector):
        self._run(emitter, scenario, collector)
        status = [e for e in collector.events if e["event_type"] == "analysis_status"]
        assert len(status) == 1
        assert status[0]["status"] == "analyzing"

    def test_result_duration_nonnegative(self, emitter, scenario, collector):
        r = self._run(emitter, scenario, collector)
        assert r.duration_ms >= 0

    def test_all_events_json_serializable(self, emitter, scenario, collector):
        self._run(emitter, scenario, collector)
        for raw in collector.raw:
            parsed = json.loads(raw)
            assert "event_type" in parsed

    def test_correct_verdict_increments_correct(self, emitter, scenario, collector):
        self._run(emitter, scenario, collector, outcome=VerdictOutcome.THREAT_CONFIRMED)
        assert emitter.scenarios_correct == 1

    def test_wrong_verdict_does_not_increment(self, emitter, collector):
        sc = _make_scenario(expected_verdict="THREAT_DISMISSED")
        self._run(emitter, sc, collector, outcome=VerdictOutcome.THREAT_CONFIRMED)
        assert emitter.scenarios_correct == 0


class TestMultipleScenarios:

    @pytest.fixture
    def collector(self):
        return MockSendCollector()

    @pytest.fixture
    def emitter(self, collector):
        return LiveAnalysisEmitter(send_fn=collector, speed=0.001)

    def test_accuracy_across_scenarios(self, emitter, collector):
        s1 = _make_scenario("SC-A", fact_count=3)
        s2 = _make_scenario("SC-B", fact_count=3)
        cr1 = _make_cycle_result(s1.packet)
        cr2 = _make_cycle_result(s2.packet)
        with patch(_CYCLE_PATH, side_effect=[cr1, cr2]):
            results = asyncio.get_event_loop().run_until_complete(
                emitter.analyze_multiple_live(
                    [s1, s2], MagicMock(), MagicMock(), MagicMock(),
                )
            )
        assert len(results) == 2
        assert emitter.scenarios_completed == 2

    def test_results_per_scenario(self, emitter, collector):
        s1 = _make_scenario("SC-X", fact_count=3)
        s2 = _make_scenario("SC-Y", fact_count=5)
        cr1 = _make_cycle_result(s1.packet)
        cr2 = _make_cycle_result(s2.packet)
        with patch(_CYCLE_PATH, side_effect=[cr1, cr2]):
            results = asyncio.get_event_loop().run_until_complete(
                emitter.analyze_multiple_live(
                    [s1, s2], MagicMock(), MagicMock(), MagicMock(),
                )
            )
        assert [r.scenario_id for r in results] == ["SC-X", "SC-Y"]

    def test_milestones_count(self, emitter, collector):
        scenarios = [_make_scenario(f"SC-{i}", fact_count=3) for i in range(3)]
        crs = [_make_cycle_result(s.packet) for s in scenarios]
        with patch(_CYCLE_PATH, side_effect=crs):
            asyncio.get_event_loop().run_until_complete(
                emitter.analyze_multiple_live(
                    scenarios, MagicMock(), MagicMock(), MagicMock(),
                )
            )
        ms = [e for e in collector.events if e["event_type"] == "accuracy_milestone"]
        assert len(ms) == 3
        assert ms[0]["scenarios_completed"] == 1
        assert ms[1]["scenarios_completed"] == 2
        assert ms[2]["scenarios_completed"] == 3


class TestErrorHandling:

    @pytest.fixture
    def collector(self):
        return MockSendCollector()

    @pytest.fixture
    def emitter(self, collector):
        return LiveAnalysisEmitter(send_fn=collector, speed=0.001)

    def test_error_emits_scenario_end(self, emitter, collector):
        scenario = _make_scenario(fact_count=3)
        with patch(_CYCLE_PATH, side_effect=RuntimeError("API timeout")):
            r = asyncio.get_event_loop().run_until_complete(
                emitter.analyze_scenario_live(
                    scenario, MagicMock(), MagicMock(), MagicMock(),
                )
            )
        assert r.error is not None
        assert "API timeout" in r.error
        assert r.verdict_outcome == "error"
        assert "scenario_start" in collector.types
        assert "scenario_end" in collector.types

    def test_error_increments_completed(self, emitter, collector):
        scenario = _make_scenario(fact_count=2)
        with patch(_CYCLE_PATH, side_effect=RuntimeError("fail")):
            asyncio.get_event_loop().run_until_complete(
                emitter.analyze_scenario_live(
                    scenario, MagicMock(), MagicMock(), MagicMock(),
                )
            )
        assert emitter.scenarios_completed == 1
        assert emitter.scenarios_correct == 0


class TestLiveScenarioResult:

    def test_frozen(self):
        r = LiveScenarioResult(
            scenario_id="SC-001", verdict_outcome="threat_confirmed",
            verdict_confidence=0.92, architect_confidence=0.95,
            skeptic_confidence=0.20, correct=True, duration_ms=3200, error=None,
        )
        with pytest.raises(AttributeError):
            r.scenario_id = "changed"

    def test_fields(self):
        r = LiveScenarioResult(
            scenario_id="SC-010", verdict_outcome="inconclusive",
            verdict_confidence=0.55, architect_confidence=0.60,
            skeptic_confidence=0.50, correct=False, duration_ms=5000, error=None,
        )
        assert r.scenario_id == "SC-010"
        assert not r.correct
        assert r.duration_ms == 5000
