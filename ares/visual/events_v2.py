"""Extended visual events — real benchmark data for content replay.

Session 035: Adds event types that carry actual LLM benchmark data
(real confidence values, real fact citations, real verdicts) for
replay through the visual pipeline.

Public API:
    ConfidenceUpdateEvent   — Real arch/skep confidence from LLM
    FactCitedEvent          — Which facts an agent actually cited
    DebateSummaryEvent      — Summary of the dialectical exchange
    AccuracyMilestoneEvent  — Running accuracy across replay
    v2_event_from_dict()    — Deserialize v2 events
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Tuple, Union


@dataclass(frozen=True)
class ConfidenceUpdateEvent:
    """Real architect/skeptic confidence from LLM benchmark."""

    event_type: str
    timestamp_ms: int
    scenario_id: str
    architect_confidence: float
    skeptic_confidence: float
    delta: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_type": self.event_type,
            "timestamp_ms": self.timestamp_ms,
            "scenario_id": self.scenario_id,
            "architect_confidence": self.architect_confidence,
            "skeptic_confidence": self.skeptic_confidence,
            "delta": self.delta,
        }


@dataclass(frozen=True)
class FactCitedEvent:
    """Which facts an agent actually cited in its reasoning."""

    event_type: str
    timestamp_ms: int
    scenario_id: str
    agent_role: str
    fact_ids: Tuple[str, ...]
    coverage_ratio: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_type": self.event_type,
            "timestamp_ms": self.timestamp_ms,
            "scenario_id": self.scenario_id,
            "agent_role": self.agent_role,
            "fact_ids": list(self.fact_ids),
            "coverage_ratio": self.coverage_ratio,
        }


@dataclass(frozen=True)
class DebateSummaryEvent:
    """Summary of the dialectical exchange for a scenario."""

    event_type: str
    timestamp_ms: int
    scenario_id: str
    architect_assertion_count: int
    skeptic_assertion_count: int
    verdict_outcome: str
    verdict_confidence: float
    expected_verdict: str
    is_correct: bool

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_type": self.event_type,
            "timestamp_ms": self.timestamp_ms,
            "scenario_id": self.scenario_id,
            "architect_assertion_count": self.architect_assertion_count,
            "skeptic_assertion_count": self.skeptic_assertion_count,
            "verdict_outcome": self.verdict_outcome,
            "verdict_confidence": self.verdict_confidence,
            "expected_verdict": self.expected_verdict,
            "is_correct": self.is_correct,
        }


@dataclass(frozen=True)
class AccuracyMilestoneEvent:
    """Running accuracy tracker across the replay."""

    event_type: str
    timestamp_ms: int
    scenarios_completed: int
    scenarios_correct: int
    running_accuracy: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_type": self.event_type,
            "timestamp_ms": self.timestamp_ms,
            "scenarios_completed": self.scenarios_completed,
            "scenarios_correct": self.scenarios_correct,
            "running_accuracy": self.running_accuracy,
        }


V2Event = Union[
    ConfidenceUpdateEvent,
    FactCitedEvent,
    DebateSummaryEvent,
    AccuracyMilestoneEvent,
]

_V2_EVENT_REGISTRY: Dict[str, type] = {
    "confidence_update": ConfidenceUpdateEvent,
    "fact_cited": FactCitedEvent,
    "debate_summary": DebateSummaryEvent,
    "accuracy_milestone": AccuracyMilestoneEvent,
}


def v2_event_from_dict(d: Dict[str, Any]) -> V2Event:
    """Deserialize a dict to the correct v2 event type.

    Args:
        d: Dictionary with an 'event_type' key.

    Returns:
        The appropriate frozen event dataclass instance.

    Raises:
        ValueError: If event_type is unknown.
    """
    event_type = d.get("event_type")
    if event_type not in _V2_EVENT_REGISTRY:
        raise ValueError(f"Unknown v2 event_type: {event_type!r}")

    cls = _V2_EVENT_REGISTRY[event_type]
    kwargs = dict(d)
    for key in ("fact_ids",):
        if key in kwargs and isinstance(kwargs[key], list):
            kwargs[key] = tuple(kwargs[key])

    return cls(**kwargs)
