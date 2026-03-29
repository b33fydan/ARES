"""Live Analysis Emitter — bridge between real-time LLM execution and WebSocket.

Session 039: Unlike the BenchmarkResultReplayer (which replays saved data),
this emitter makes LIVE API calls via run_cycle_with_strategies() and
streams events as the analysis actually happens.

The viewer watches the Architect reason, the Skeptic respond, and the
Oracle judge — all happening for the first time.

Public API:
    LiveAnalysisEmitter  — Runs live LLM analysis, emits events in real-time
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple, TYPE_CHECKING

from ares.visual.events import (
    FactIngestedEvent,
    ScenarioEndEvent,
    ScenarioStartEvent,
    VerdictRenderedEvent,
)
from ares.visual.events_v2 import (
    AccuracyMilestoneEvent,
    ConfidenceUpdateEvent,
    DebateSummaryEvent,
    FactCitedEvent,
)

if TYPE_CHECKING:
    from ares.dialectic.agents.strategies.protocol import (
        ExplanationFinder,
        NarrativeGenerator,
        ThreatAnalyzer,
    )
    from ares.dialectic.scripts.scenario_corpus import BenchmarkScenario

logger = logging.getLogger("ares.visual.live_emitter")


@dataclass(frozen=True)
class LiveScenarioResult:
    """Immutable result of a single live analysis run.

    Attributes:
        scenario_id: Which scenario was analyzed.
        verdict_outcome: The verdict string (e.g. "threat_confirmed").
        verdict_confidence: Overall confidence.
        architect_confidence: Architect's confidence.
        skeptic_confidence: Skeptic's confidence.
        correct: Whether the verdict matched expected.
        duration_ms: Wall-clock time for the LLM call.
        error: Error message if the analysis failed, else None.
    """

    scenario_id: str
    verdict_outcome: str
    verdict_confidence: float
    architect_confidence: float
    skeptic_confidence: float
    correct: bool
    duration_ms: int
    error: Optional[str]


def _ts() -> int:
    """Current time in milliseconds."""
    return int(time.time() * 1000)


class LiveAnalysisEmitter:
    """Runs live LLM analysis on scenarios and emits events in real-time.

    Unlike the BenchmarkResultReplayer (which replays saved JSON),
    this emitter makes LIVE API calls and streams events as the
    analysis actually happens.

    Args:
        send_fn: Async callable that sends a JSON string to all clients.
        speed: Delay multiplier between events (1.0 = natural timing).
    """

    def __init__(
        self,
        send_fn,
        speed: float = 1.0,
    ) -> None:
        self._send = send_fn
        self._speed = speed
        self._scenarios_completed = 0
        self._scenarios_correct = 0

    @property
    def scenarios_completed(self) -> int:
        return self._scenarios_completed

    @property
    def scenarios_correct(self) -> int:
        return self._scenarios_correct

    async def _emit(self, event) -> None:
        """Serialize and send an event."""
        await self._send(json.dumps(event.to_dict()))

    async def _delay(self, ms: float) -> None:
        """Sleep for ms milliseconds, scaled by speed."""
        await asyncio.sleep((ms / 1000.0) * self._speed)

    async def emit_analysis_status(self, scenario_id: str, status: str) -> None:
        """Emit an analysis_status event (custom, for HUD indicator)."""
        payload = json.dumps({
            "event_type": "analysis_status",
            "scenario_id": scenario_id,
            "status": status,
            "timestamp_ms": _ts(),
        })
        await self._send(payload)

    async def analyze_scenario_live(
        self,
        scenario: "BenchmarkScenario",
        threat_analyzer: "ThreatAnalyzer",
        explanation_finder: "ExplanationFinder",
        narrative_generator: "NarrativeGenerator",
    ) -> LiveScenarioResult:
        """Run a LIVE analysis on a single scenario and emit events.

        Sequence:
        1. Emit scenario_start
        2. Emit fact_ingested for each fact (staggered ~200ms)
        3. Emit analysis_status "analyzing"
        4. Call run_cycle_with_strategies() — LIVE LLM CALL
        5. Emit fact_cited for architect + skeptic
        6. Emit confidence_update
        7. Emit debate_summary
        8. Emit verdict_rendered
        9. Emit accuracy_milestone
        10. Emit scenario_end

        Returns:
            LiveScenarioResult with timing and correctness data.
        """
        meta = scenario.metadata
        packet = scenario.packet

        # --- 1. scenario_start ---
        source_types = set()
        all_facts = []
        for fid in sorted(packet.fact_ids):
            fact = packet.get_fact(fid)
            all_facts.append(fact)
            if fact.provenance and hasattr(fact.provenance, 'source_type'):
                st = fact.provenance.source_type
                source_types.add(st.value if hasattr(st, 'value') else str(st))

        await self._emit(ScenarioStartEvent(
            event_type="scenario_start",
            timestamp_ms=_ts(),
            scenario_id=meta.scenario_id,
            scenario_name=meta.name,
            expected_verdict=meta.expected_verdict,
            fact_count=len(all_facts),
            source_types=tuple(sorted(source_types)) if source_types else ("unknown",),
        ))
        await self._delay(200)

        # --- 2. fact_ingested (staggered) ---
        for i, fact in enumerate(all_facts):
            src = "unknown"
            if fact.provenance and hasattr(fact.provenance, 'source_type'):
                st = fact.provenance.source_type
                src = st.value if hasattr(st, 'value') else str(st)

            await self._emit(FactIngestedEvent(
                event_type="fact_ingested",
                timestamp_ms=_ts(),
                scenario_id=meta.scenario_id,
                fact_id=fact.fact_id,
                entity_type=fact.entity_type.value if hasattr(fact.entity_type, 'value') else str(fact.entity_type),
                entity_id=fact.entity_id,
                source_type=src,
                field_name=fact.field,
                source_index=i % 3,
                fact_index=i,
            ))
            await self._delay(200)

        # --- 3. analysis_status: analyzing ---
        await self.emit_analysis_status(meta.scenario_id, "analyzing")

        # --- 4. LIVE LLM CALL ---
        from ares.dialectic.agents.strategies.live_cycle import (
            run_cycle_with_strategies,
        )
        from ares.dialectic.coordinator.orchestrator import CycleError

        cycle_start = time.monotonic()
        error_msg: Optional[str] = None
        try:
            result = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: run_cycle_with_strategies(
                    packet,
                    threat_analyzer=threat_analyzer,
                    explanation_finder=explanation_finder,
                    narrative_generator=narrative_generator,
                    include_narration=False,
                ),
            )
        except (CycleError, Exception) as e:
            error_msg = str(e)
            logger.error("LLM call failed for %s: %s", meta.scenario_id, e)

            # Emit error scenario_end
            await self._emit(ScenarioEndEvent(
                event_type="scenario_end",
                timestamp_ms=_ts(),
                scenario_id=meta.scenario_id,
                duration_ms=int((time.monotonic() - cycle_start) * 1000),
            ))
            self._scenarios_completed += 1
            return LiveScenarioResult(
                scenario_id=meta.scenario_id,
                verdict_outcome="error",
                verdict_confidence=0.0,
                architect_confidence=0.0,
                skeptic_confidence=0.0,
                correct=False,
                duration_ms=int((time.monotonic() - cycle_start) * 1000),
                error=error_msg,
            )

        duration_ms = int((time.monotonic() - cycle_start) * 1000)

        # --- 5. fact_cited ---
        arch_fact_ids = sorted(result.architect_message.get_all_fact_ids())
        skep_fact_ids = sorted(result.skeptic_message.get_all_fact_ids())

        if arch_fact_ids:
            await self._emit(FactCitedEvent(
                event_type="fact_cited",
                timestamp_ms=_ts(),
                scenario_id=meta.scenario_id,
                agent_role="architect",
                fact_ids=tuple(arch_fact_ids),
                coverage_ratio=len(arch_fact_ids) / max(1, len(all_facts)),
            ))
            await self._delay(300)

        if skep_fact_ids:
            await self._emit(FactCitedEvent(
                event_type="fact_cited",
                timestamp_ms=_ts(),
                scenario_id=meta.scenario_id,
                agent_role="skeptic",
                fact_ids=tuple(skep_fact_ids),
                coverage_ratio=len(skep_fact_ids) / max(1, len(all_facts)),
            ))
            await self._delay(300)

        # --- 6. confidence_update ---
        arch_conf = result.verdict.architect_confidence
        skep_conf = result.verdict.skeptic_confidence
        delta = arch_conf - skep_conf

        await self._emit(ConfidenceUpdateEvent(
            event_type="confidence_update",
            timestamp_ms=_ts(),
            scenario_id=meta.scenario_id,
            architect_confidence=arch_conf,
            skeptic_confidence=skep_conf,
            delta=delta,
        ))
        await self._delay(300)

        # --- 7. debate_summary ---
        arch_assertions = len(result.architect_message.assertions)
        skep_assertions = len(result.skeptic_message.assertions)
        outcome_str = result.verdict.outcome.value
        is_correct = outcome_str.upper() == meta.expected_verdict.upper()

        await self._emit(DebateSummaryEvent(
            event_type="debate_summary",
            timestamp_ms=_ts(),
            scenario_id=meta.scenario_id,
            architect_assertion_count=arch_assertions,
            skeptic_assertion_count=skep_assertions,
            verdict_outcome=outcome_str,
            verdict_confidence=result.verdict.confidence,
            expected_verdict=meta.expected_verdict,
            is_correct=is_correct,
        ))
        await self._delay(200)

        # --- 8. verdict_rendered ---
        await self._emit(VerdictRenderedEvent(
            event_type="verdict_rendered",
            timestamp_ms=_ts(),
            scenario_id=meta.scenario_id,
            outcome=outcome_str,
            confidence=result.verdict.confidence,
            correct=is_correct,
        ))
        await self._delay(200)

        # --- 9. accuracy_milestone ---
        self._scenarios_completed += 1
        if is_correct:
            self._scenarios_correct += 1

        await self._emit(AccuracyMilestoneEvent(
            event_type="accuracy_milestone",
            timestamp_ms=_ts(),
            scenarios_completed=self._scenarios_completed,
            scenarios_correct=self._scenarios_correct,
            running_accuracy=self._scenarios_correct / self._scenarios_completed,
        ))
        await self._delay(100)

        # --- 10. scenario_end ---
        await self._emit(ScenarioEndEvent(
            event_type="scenario_end",
            timestamp_ms=_ts(),
            scenario_id=meta.scenario_id,
            duration_ms=duration_ms,
        ))

        return LiveScenarioResult(
            scenario_id=meta.scenario_id,
            verdict_outcome=outcome_str,
            verdict_confidence=result.verdict.confidence,
            architect_confidence=arch_conf,
            skeptic_confidence=skep_conf,
            correct=is_correct,
            duration_ms=duration_ms,
            error=None,
        )

    async def analyze_multiple_live(
        self,
        scenarios: List["BenchmarkScenario"],
        threat_analyzer: "ThreatAnalyzer",
        explanation_finder: "ExplanationFinder",
        narrative_generator: "NarrativeGenerator",
    ) -> List[LiveScenarioResult]:
        """Run live analysis on multiple scenarios sequentially.

        Args:
            scenarios: List of BenchmarkScenario to analyze.
            threat_analyzer: Architect strategy.
            explanation_finder: Skeptic strategy.
            narrative_generator: Oracle narrator strategy.

        Returns:
            List of LiveScenarioResult for each scenario.
        """
        results: List[LiveScenarioResult] = []
        for scenario in scenarios:
            r = await self.analyze_scenario_live(
                scenario, threat_analyzer, explanation_finder, narrative_generator,
            )
            results.append(r)
            # Inter-scenario gap
            await self._delay(3000)
        return results
