"""Benchmark Result Replayer — replays real LLM data as visual events.

Session 035: Unlike ScenarioReplayer (which generates synthetic events
from scenario metadata), this replayer consumes actual benchmark JSON
output and produces events with real LLM confidence values, real fact
citations, and real verdicts.

Public API:
    BenchmarkResultReplayer  — Load results, replay as timed events
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
    VisualEvent,
)
from ares.visual.events_v2 import (
    AccuracyMilestoneEvent,
    ConfidenceUpdateEvent,
    DebateSummaryEvent,
    FactCitedEvent,
    V2Event,
)


AnyEvent = Any  # Union of VisualEvent and V2Event


class BenchmarkResultReplayer:
    """Replays real benchmark results as timed event sequences.

    Args:
        results_path: Path to benchmark results JSON.
        corpus: Optional dict of scenario_id -> BenchmarkScenario for metadata.
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
        """Load and parse benchmark results JSON.

        Returns:
            Parsed JSON dict with 'results' key.

        Raises:
            FileNotFoundError: If the results file doesn't exist.
        """
        if not self._results_path.exists():
            raise FileNotFoundError(f"Results file not found: {self._results_path}")
        return json.loads(self._results_path.read_text(encoding="utf-8"))

    @property
    def scenario_ids(self) -> List[str]:
        """All scenario IDs in the results."""
        return [r["scenario_id"] for r in self._data["results"]]

    def replay_scenario(
        self,
        scenario_id: str,
        speed: float = 1.0,
        base_time_ms: int = 0,
    ) -> List[Tuple[int, AnyEvent]]:
        """Generate timed event sequence for a single scenario.

        Args:
            scenario_id: e.g., "SC-001".
            speed: Playback speed multiplier (0.5 = half speed).
            base_time_ms: Starting timestamp offset.

        Returns:
            List of (timestamp_ms, event) tuples in chronological order.

        Raises:
            KeyError: If scenario_id not found in results.
        """
        if scenario_id not in self._results_by_id:
            raise KeyError(f"Scenario {scenario_id!r} not in benchmark results")

        result = self._results_by_id[scenario_id]
        scenario = self._corpus.get(scenario_id)
        events: List[Tuple[int, AnyEvent]] = []

        def _t(offset_ms: int) -> int:
            return base_time_ms + int(offset_ms / speed)

        clock = 0
        sid = scenario_id

        # Scenario metadata
        name = scenario.metadata.name if scenario else scenario_id
        expected = scenario.metadata.expected_verdict if scenario else "unknown"
        fact_count = result["total_facts_available"]
        source_types = self._get_source_types(scenario) if scenario else ()

        # 1. scenario_start
        events.append((_t(clock), ScenarioStartEvent(
            event_type="scenario_start",
            timestamp_ms=_t(clock),
            scenario_id=sid,
            scenario_name=name,
            expected_verdict=expected,
            fact_count=fact_count,
            source_types=source_types,
        )))

        # 2. fact_ingested (one per fact, staggered)
        if scenario:
            source_type_index: dict[str, int] = {}
            all_facts = list(scenario.packet.get_all_facts())
            for f in all_facts:
                st = f.provenance.source_type.value
                if st not in source_type_index:
                    source_type_index[st] = len(source_type_index)

            for i, fact in enumerate(all_facts):
                clock += 200
                src_type = fact.provenance.source_type.value
                events.append((_t(clock), FactIngestedEvent(
                    event_type="fact_ingested",
                    timestamp_ms=_t(clock),
                    scenario_id=sid,
                    fact_id=fact.fact_id,
                    entity_type=fact.entity_type.value,
                    entity_id=fact.entity_id,
                    source_type=src_type,
                    field_name=fact.field,
                    source_index=source_type_index.get(src_type, 0),
                    fact_index=i,
                )))

        # 3. fact_cited (architect)
        clock += 500
        arch_facts = tuple(sorted(result.get("architect_fact_ids_cited", [])))
        arch_coverage = len(arch_facts) / fact_count if fact_count > 0 else 0.0
        events.append((_t(clock), FactCitedEvent(
            event_type="fact_cited",
            timestamp_ms=_t(clock),
            scenario_id=sid,
            agent_role="architect",
            fact_ids=arch_facts,
            coverage_ratio=arch_coverage,
        )))

        # 4. fact_cited (skeptic)
        clock += 300
        skep_facts = tuple(sorted(result.get("skeptic_fact_ids_cited", [])))
        skep_coverage = len(skep_facts) / fact_count if fact_count > 0 else 0.0
        events.append((_t(clock), FactCitedEvent(
            event_type="fact_cited",
            timestamp_ms=_t(clock),
            scenario_id=sid,
            agent_role="skeptic",
            fact_ids=skep_facts,
            coverage_ratio=skep_coverage,
        )))

        # 5. confidence_update
        clock += 300
        arch_conf = result["architect_confidence"]
        skep_conf = result["skeptic_confidence"]
        events.append((_t(clock), ConfidenceUpdateEvent(
            event_type="confidence_update",
            timestamp_ms=_t(clock),
            scenario_id=sid,
            architect_confidence=arch_conf,
            skeptic_confidence=skep_conf,
            delta=arch_conf - skep_conf,
        )))

        # 6. debate_summary
        clock += 200
        actual = result["verdict_outcome"]
        is_correct = actual == expected.lower() if expected != "unknown" else False
        events.append((_t(clock), DebateSummaryEvent(
            event_type="debate_summary",
            timestamp_ms=_t(clock),
            scenario_id=sid,
            architect_assertion_count=result.get("architect_assertion_count", 0),
            skeptic_assertion_count=result.get("skeptic_assertion_count", 0),
            verdict_outcome=actual,
            verdict_confidence=result["verdict_confidence"],
            expected_verdict=expected.lower() if expected != "unknown" else "",
            is_correct=is_correct,
        )))

        # 7. verdict_rendered
        clock += 500
        events.append((_t(clock), VerdictRenderedEvent(
            event_type="verdict_rendered",
            timestamp_ms=_t(clock),
            scenario_id=sid,
            outcome=actual,
            confidence=result["verdict_confidence"],
            correct=is_correct,
        )))

        # 8. scenario_end
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
        """Generate timed event sequence for all (or selected) scenarios.

        Args:
            speed: Playback speed multiplier.
            scenario_ids: Optional list of scenario IDs to replay.

        Returns:
            List of (timestamp_ms, event) tuples.
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

            # Running accuracy milestone
            result = self._results_by_id[sid]
            scenario = self._corpus.get(sid)
            expected = scenario.metadata.expected_verdict.lower() if scenario else ""
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

            # Inter-scenario gap
            base_time = last_ts + int(2000 / speed)

        return all_events

    def get_showcase_scenarios(self) -> List[str]:
        """Return 5-7 scenario IDs that make the best visual stories.

        Criteria:
        - Highest fact count (most nodes in the graph)
        - Correct verdicts with strong confidence (decisive analysis)
        - Mix of CONFIRMED, DISMISSED, INCONCLUSIVE
        - At least one scenario the system got WRONG
        """
        results = self._data["results"]

        # Categorize
        confirmed_correct = []
        dismissed_correct = []
        inconclusive_correct = []
        incorrect = []

        for r in results:
            sid = r["scenario_id"]
            scenario = self._corpus.get(sid)
            expected = scenario.metadata.expected_verdict.lower() if scenario else ""
            actual = r["verdict_outcome"]
            is_correct = actual == expected
            score = r["total_facts_available"] + r["verdict_confidence"]

            entry = (score, sid)
            if not is_correct:
                incorrect.append(entry)
            elif actual == "threat_confirmed":
                confirmed_correct.append(entry)
            elif actual == "threat_dismissed":
                dismissed_correct.append(entry)
            else:
                inconclusive_correct.append(entry)

        # Sort by score descending (more facts + higher confidence = better visuals)
        confirmed_correct.sort(reverse=True)
        dismissed_correct.sort(reverse=True)
        inconclusive_correct.sort(reverse=True)
        incorrect.sort(reverse=True)

        showcase = []
        # 2 best confirmed
        for _, sid in confirmed_correct[:2]:
            showcase.append(sid)
        # 1 best dismissed
        for _, sid in dismissed_correct[:1]:
            showcase.append(sid)
        # 1 best inconclusive
        for _, sid in inconclusive_correct[:1]:
            showcase.append(sid)
        # 1-2 incorrect (honesty)
        for _, sid in incorrect[:2]:
            showcase.append(sid)

        return showcase

    @staticmethod
    def _get_source_types(scenario) -> Tuple[str, ...]:
        """Extract sorted source types from a scenario's packet."""
        return tuple(sorted({
            f.provenance.source_type.value
            for f in scenario.packet.get_all_facts()
        }))

    def _load_default_corpus(self) -> Dict[str, Any]:
        """Load corpus_v2 as the default scenario metadata source."""
        try:
            from ares.dialectic.scripts.scenario_corpus_v2 import get_full_corpus_v2
            return {s.metadata.scenario_id: s for s in get_full_corpus_v2()}
        except ImportError:
            return {}

    def __repr__(self) -> str:
        n = len(self._data.get("results", []))
        return f"BenchmarkResultReplayer({self._results_path.name}, {n} scenarios)"
