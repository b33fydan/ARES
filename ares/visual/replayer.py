"""Scenario Replayer — converts ARES scenarios into visual event sequences.

Session 029: Takes a benchmark scenario, runs it through the existing
single-turn pipeline (rule-based, no LLM calls), and produces a
chronological sequence of VisualEvents with synthetic timestamps
for visual playback.

Public API:
    ScenarioReplayer  — call .replay(scenario) -> tuple[VisualEvent, ...]
"""

from __future__ import annotations

from typing import Tuple

from ares.dialectic.coordinator.claim_audit import ClaimAuditor
from ares.dialectic.coordinator.miscalibration import MiscalibrationDetector
from ares.dialectic.coordinator.orchestrator import DialecticalOrchestrator
from ares.dialectic.scripts.scenario_corpus import BenchmarkScenario
from ares.visual.events import (
    AssertionFormedEvent,
    ClaimAuditEvent,
    FactIngestedEvent,
    MiscalibrationCheckEvent,
    ScenarioEndEvent,
    ScenarioStartEvent,
    VerdictRenderedEvent,
    VisualEvent,
)


class ScenarioReplayer:
    """Replays an ARES scenario as a sequence of timed visual events.

    Uses rule-based strategies only (no LLM calls).
    Processes a scenario through the existing pipeline:
    EvidencePacket -> Orchestrator -> Verdict -> MiscalibrationDetector -> ClaimAuditor

    Outputs a tuple of VisualEvents with synthetic timestamps
    that space out the events for visual effect.

    Args:
        fact_delay_ms: Delay between fact ingestion events.
        assertion_delay_ms: Delay between assertion events.
        verdict_delay_ms: Delay before verdict.
        check_delay_ms: Delay before miscalibration check.
    """

    def __init__(
        self,
        fact_delay_ms: int = 200,
        assertion_delay_ms: int = 500,
        verdict_delay_ms: int = 1000,
        check_delay_ms: int = 500,
    ) -> None:
        self._fact_delay_ms = fact_delay_ms
        self._assertion_delay_ms = assertion_delay_ms
        self._verdict_delay_ms = verdict_delay_ms
        self._check_delay_ms = check_delay_ms

    @property
    def fact_delay_ms(self) -> int:
        """Delay between fact ingestion events."""
        return self._fact_delay_ms

    @property
    def assertion_delay_ms(self) -> int:
        """Delay between assertion events."""
        return self._assertion_delay_ms

    @property
    def verdict_delay_ms(self) -> int:
        """Delay before verdict event."""
        return self._verdict_delay_ms

    @property
    def check_delay_ms(self) -> int:
        """Delay before miscalibration check event."""
        return self._check_delay_ms

    def replay(self, scenario: BenchmarkScenario) -> Tuple[VisualEvent, ...]:
        """Process a scenario and return the full event sequence.

        Args:
            scenario: A BenchmarkScenario with .metadata and .packet.

        Returns:
            Tuple of VisualEvents in chronological order with synthetic timestamps.
        """
        events: list[VisualEvent] = []
        clock_ms = 0
        sid = scenario.metadata.scenario_id
        packet = scenario.packet

        # 1. Scenario start
        source_types = tuple(sorted({
            f.provenance.source_type.value
            for f in packet.get_all_facts()
        }))
        events.append(ScenarioStartEvent(
            event_type="scenario_start",
            timestamp_ms=clock_ms,
            scenario_id=sid,
            scenario_name=scenario.metadata.name,
            expected_verdict=scenario.metadata.expected_verdict,
            fact_count=packet.fact_count,
            source_types=source_types,
        ))

        # 2. Fact ingestion
        source_type_index: dict[str, int] = {}
        for st in source_types:
            source_type_index[st] = len(source_type_index)

        for i, fact in enumerate(packet.get_all_facts()):
            clock_ms += self._fact_delay_ms
            src_type = fact.provenance.source_type.value
            events.append(FactIngestedEvent(
                event_type="fact_ingested",
                timestamp_ms=clock_ms,
                scenario_id=sid,
                fact_id=fact.fact_id,
                entity_type=fact.entity_type.value,
                entity_id=fact.entity_id,
                source_type=src_type,
                field_name=fact.field,
                source_index=source_type_index.get(src_type, 0),
                fact_index=i,
            ))

        # 3. Run orchestrator (rule-based)
        orchestrator = DialecticalOrchestrator(include_narration=False)
        cycle_result = orchestrator.run_cycle(packet)

        # 4. Assertion events
        for assertion in cycle_result.architect_message.assertions:
            clock_ms += self._assertion_delay_ms
            events.append(AssertionFormedEvent(
                event_type="assertion_formed",
                timestamp_ms=clock_ms,
                scenario_id=sid,
                assertion_id=assertion.assertion_id,
                assertion_type=assertion.assertion_type.value,
                content=assertion.interpretation,
                cited_fact_ids=assertion.fact_ids,
                confidence=assertion.confidence if hasattr(assertion, 'confidence') and assertion.confidence is not None else cycle_result.verdict.architect_confidence,
            ))

        # 5. Verdict
        clock_ms += self._verdict_delay_ms
        verdict = cycle_result.verdict
        expected = scenario.metadata.expected_verdict.lower()
        actual = verdict.outcome.value.lower()
        events.append(VerdictRenderedEvent(
            event_type="verdict_rendered",
            timestamp_ms=clock_ms,
            scenario_id=sid,
            outcome=verdict.outcome.value,
            confidence=verdict.confidence,
            correct=(actual == expected),
        ))

        # 6. Miscalibration check
        clock_ms += self._check_delay_ms
        detector = MiscalibrationDetector()
        misc_result = detector.detect(
            verdict,
            cycle_result.architect_message,
            cycle_result.skeptic_message,
            packet,
        )
        events.append(MiscalibrationCheckEvent(
            event_type="miscalibration_check",
            timestamp_ms=clock_ms,
            scenario_id=sid,
            flagged=misc_result.flagged,
            patterns_triggered=tuple(p.value for p in misc_result.patterns_triggered),
            risk_score=misc_result.risk_score,
            recommendation=misc_result.recommendation.value,
        ))

        # 7. Claim audit (only if flagged)
        if misc_result.flagged:
            clock_ms += self._check_delay_ms
            auditor = ClaimAuditor()
            audit_result = auditor.audit(
                cycle_result.architect_message,
                packet,
            )
            events.append(ClaimAuditEvent(
                event_type="claim_audit",
                timestamp_ms=clock_ms,
                scenario_id=sid,
                claims_total=audit_result.claims_total,
                claims_supported=audit_result.claims_supported,
                claims_weak=audit_result.claims_weak,
                claims_unsupported=audit_result.claims_unsupported,
                audit_verdict=audit_result.audit_verdict.value,
            ))

        # 8. Scenario end
        clock_ms += self._check_delay_ms
        events.append(ScenarioEndEvent(
            event_type="scenario_end",
            timestamp_ms=clock_ms,
            scenario_id=sid,
            duration_ms=clock_ms,
        ))

        return tuple(events)

    def __repr__(self) -> str:
        return (
            f"ScenarioReplayer("
            f"fact_delay={self._fact_delay_ms}ms, "
            f"assertion_delay={self._assertion_delay_ms}ms)"
        )
