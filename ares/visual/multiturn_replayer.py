"""Multi-turn benchmark replayer — visualizes debate evolution per round.

Session 037: Converts multi-turn benchmark JSON (with round_snapshots)
into timed visual events that show confidence shifting across debate
rounds. Works alongside the single-turn BenchmarkResultReplayer.

Public API:
    MultiTurnReplayer  — Load multi-turn results, replay as timed events
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ares.visual.events import (
    FactIngestedEvent,
    ScenarioEndEvent,
    ScenarioStartEvent,
    VerdictRenderedEvent,
)
from ares.visual.events_v2 import AccuracyMilestoneEvent
from ares.visual.events_multiturn import (
    DebateEvolutionEvent,
    RoundConfidenceEvent,
    RoundStartEvent,
)


AnyEvent = Any


class MultiTurnReplayer:
    """Replays multi-turn benchmark results as timed visual events.

    Produces per-round confidence events showing how the Architect and
    Skeptic adjust positions across debate rounds.

    Args:
        results_path: Path to multi-turn benchmark results JSON.
        corpus: Optional dict of scenario_id -> BenchmarkScenario.
    """

    def __init__(
        self,
        results_path: str,
        corpus: Optional[Dict[str, Any]] = None,
    ) -> None:
        self._results_path = Path(results_path)
        self._data = self.load_results()
        self._results_by_id = {r["scenario_id"]: r for r in self._data["results"]}

        if corpus is not None:
            self._corpus = corpus
        else:
            self._corpus = self._load_default_corpus()

    def load_results(self) -> Dict[str, Any]:
        """Load and parse multi-turn benchmark results JSON."""
        if not self._results_path.exists():
            raise FileNotFoundError(f"Results file not found: {self._results_path}")
        return json.loads(self._results_path.read_text(encoding="utf-8"))

    @property
    def scenario_ids(self) -> List[str]:
        """All scenario IDs in the results."""
        return [r["scenario_id"] for r in self._data["results"]]

    @property
    def max_rounds(self) -> int:
        """Configured max rounds for this benchmark run."""
        return self._data.get("max_rounds", 3)

    def replay_scenario(
        self,
        scenario_id: str,
        speed: float = 1.0,
        base_time_ms: int = 0,
    ) -> List[Tuple[int, AnyEvent]]:
        """Generate timed event sequence for a single multi-turn scenario.

        Event sequence per scenario:
        1. scenario_start
        2. fact_ingested (N facts, staggered)
        3. For each round:
           - round_start
           - round_confidence (per-round arch/skep snapshot)
        4. debate_evolution (summary of full trajectory)
        5. verdict_rendered
        6. scenario_end

        Args:
            scenario_id: e.g., "SC-001".
            speed: Playback speed multiplier.
            base_time_ms: Starting timestamp offset.

        Returns:
            List of (timestamp_ms, event) tuples.

        Raises:
            KeyError: If scenario_id not in results.
        """
        if scenario_id not in self._results_by_id:
            raise KeyError(f"Scenario {scenario_id!r} not in multi-turn results")

        result = self._results_by_id[scenario_id]
        scenario = self._corpus.get(scenario_id)
        events: List[Tuple[int, AnyEvent]] = []

        def _t(offset_ms: int) -> int:
            return base_time_ms + int(offset_ms / speed)

        clock = 0
        sid = scenario_id
        max_rounds = self._data.get("max_rounds", 3)

        # Metadata
        name = result.get("scenario_name", scenario.metadata.name if scenario else sid)
        expected = result.get("expected_verdict", scenario.metadata.expected_verdict if scenario else "unknown")
        total_facts = result.get("total_facts_available", 0)
        if total_facts == 0 and scenario:
            total_facts = scenario.packet.fact_count
        source_types = self._get_source_types(scenario) if scenario else ()

        # 1. scenario_start
        events.append((_t(clock), ScenarioStartEvent(
            event_type="scenario_start",
            timestamp_ms=_t(clock),
            scenario_id=sid,
            scenario_name=name,
            expected_verdict=expected,
            fact_count=total_facts,
            source_types=source_types,
        )))

        # 2. fact_ingested (from corpus if available)
        if scenario:
            source_type_index: dict[str, int] = {}
            all_facts = list(scenario.packet.get_all_facts())
            for f in all_facts:
                st = f.provenance.source_type.value
                if st not in source_type_index:
                    source_type_index[st] = len(source_type_index)

            for i, fact in enumerate(all_facts):
                clock += 150  # Slightly faster than single-turn for pacing
                events.append((_t(clock), FactIngestedEvent(
                    event_type="fact_ingested",
                    timestamp_ms=_t(clock),
                    scenario_id=sid,
                    fact_id=fact.fact_id,
                    entity_type=fact.entity_type.value,
                    entity_id=fact.entity_id,
                    source_type=fact.provenance.source_type.value,
                    field_name=fact.field,
                    source_index=source_type_index.get(fact.provenance.source_type.value, 0),
                    fact_index=i,
                )))

        # 3. Per-round events
        snapshots = result.get("round_snapshots", [])
        rounds_used = result.get("rounds_used", len(snapshots))

        for snap in snapshots:
            rn = snap["round_number"]

            # round_start
            clock += 600
            events.append((_t(clock), RoundStartEvent(
                event_type="round_start",
                timestamp_ms=_t(clock),
                scenario_id=sid,
                round_number=rn,
                max_rounds=max_rounds,
            )))

            # round_confidence
            clock += 800
            events.append((_t(clock), RoundConfidenceEvent(
                event_type="round_confidence",
                timestamp_ms=_t(clock),
                scenario_id=sid,
                round_number=rn,
                architect_confidence=snap["architect_confidence"],
                skeptic_confidence=snap["skeptic_confidence"],
                architect_new_facts=snap.get("architect_new_fact_count", 0),
                skeptic_new_facts=snap.get("skeptic_new_fact_count", 0),
                architect_assertions=snap.get("architect_assertion_count", 0),
                skeptic_assertions=snap.get("skeptic_assertion_count", 0),
            )))

        # 4. debate_evolution
        clock += 500
        trajectory = tuple(
            (snap["architect_confidence"], snap["skeptic_confidence"])
            for snap in snapshots
        )
        actual = result["verdict_outcome"]
        is_correct = actual == expected.lower() if expected != "unknown" else False

        events.append((_t(clock), DebateEvolutionEvent(
            event_type="debate_evolution",
            timestamp_ms=_t(clock),
            scenario_id=sid,
            total_rounds=rounds_used,
            termination_reason=result.get("termination_reason", "unknown"),
            confidence_trajectory=trajectory,
            verdict_outcome=actual,
            expected_verdict=expected.lower() if expected != "unknown" else "",
            is_correct=is_correct,
        )))

        # 5. verdict_rendered
        clock += 500
        events.append((_t(clock), VerdictRenderedEvent(
            event_type="verdict_rendered",
            timestamp_ms=_t(clock),
            scenario_id=sid,
            outcome=actual,
            confidence=result.get("verdict_confidence", 0.0),
            correct=is_correct,
        )))

        # 6. scenario_end
        clock += 300
        events.append((_t(clock), ScenarioEndEvent(
            event_type="scenario_end",
            timestamp_ms=_t(clock),
            scenario_id=sid,
            duration_ms=clock,
        )))

        return events

    def replay_all(
        self,
        speed: float = 1.0,
        scenario_ids: Optional[List[str]] = None,
    ) -> List[Tuple[int, AnyEvent]]:
        """Generate timed events for all (or selected) multi-turn scenarios.

        Includes running accuracy milestones between scenarios.
        """
        ids = scenario_ids if scenario_ids is not None else self.scenario_ids
        all_events: List[Tuple[int, AnyEvent]] = []
        base_time = 0
        correct_count = 0

        for i, sid in enumerate(ids):
            if sid not in self._results_by_id:
                continue

            scenario_events = self.replay_scenario(sid, speed=speed, base_time_ms=base_time)
            all_events.extend(scenario_events)

            result = self._results_by_id[sid]
            scenario = self._corpus.get(sid)
            expected = result.get("expected_verdict",
                                  scenario.metadata.expected_verdict.lower() if scenario else "")
            if isinstance(expected, str):
                expected = expected.lower()
            if result["verdict_outcome"] == expected:
                correct_count += 1

            completed = i + 1
            accuracy = correct_count / completed if completed > 0 else 0.0
            last_ts = scenario_events[-1][0] if scenario_events else base_time

            all_events.append((last_ts + int(100 / speed), AccuracyMilestoneEvent(
                event_type="accuracy_milestone",
                timestamp_ms=last_ts + int(100 / speed),
                scenarios_completed=completed,
                scenarios_correct=correct_count,
                running_accuracy=accuracy,
            )))

            base_time = last_ts + int(2500 / speed)

        return all_events

    @staticmethod
    def _get_source_types(scenario) -> Tuple[str, ...]:
        """Extract sorted source types from a scenario's packet."""
        if scenario is None:
            return ()
        return tuple(sorted({
            f.provenance.source_type.value
            for f in scenario.packet.get_all_facts()
        }))

    def _load_default_corpus(self) -> Dict[str, Any]:
        """Load corpus_v2 as default metadata source."""
        try:
            from ares.dialectic.scripts.scenario_corpus_v2 import get_full_corpus_v2
            return {s.metadata.scenario_id: s for s in get_full_corpus_v2()}
        except ImportError:
            return {}

    def __repr__(self) -> str:
        n = len(self._data.get("results", []))
        return f"MultiTurnReplayer({self._results_path.name}, {n} scenarios)"
