"""Multi-turn visual events — per-round debate evolution.

Session 037: Event types for visualizing how confidence shifts
across debate rounds. Shows the Architect and Skeptic adjusting
positions in real-time.

Public API:
    RoundStartEvent         — New debate round begins
    RoundConfidenceEvent    — Per-round confidence snapshot
    DebateEvolutionEvent    — Summary of how debate evolved across all rounds
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Tuple, Union


@dataclass(frozen=True)
class RoundStartEvent:
    """Marks the beginning of a debate round."""

    event_type: str
    timestamp_ms: int
    scenario_id: str
    round_number: int
    max_rounds: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_type": self.event_type,
            "timestamp_ms": self.timestamp_ms,
            "scenario_id": self.scenario_id,
            "round_number": self.round_number,
            "max_rounds": self.max_rounds,
        }


@dataclass(frozen=True)
class RoundConfidenceEvent:
    """Confidence snapshot after a debate round completes."""

    event_type: str
    timestamp_ms: int
    scenario_id: str
    round_number: int
    architect_confidence: float
    skeptic_confidence: float
    architect_new_facts: int
    skeptic_new_facts: int
    architect_assertions: int
    skeptic_assertions: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_type": self.event_type,
            "timestamp_ms": self.timestamp_ms,
            "scenario_id": self.scenario_id,
            "round_number": self.round_number,
            "architect_confidence": self.architect_confidence,
            "skeptic_confidence": self.skeptic_confidence,
            "architect_new_facts": self.architect_new_facts,
            "skeptic_new_facts": self.skeptic_new_facts,
            "architect_assertions": self.architect_assertions,
            "skeptic_assertions": self.skeptic_assertions,
        }


@dataclass(frozen=True)
class DebateEvolutionEvent:
    """Summary of how the debate evolved across all rounds."""

    event_type: str
    timestamp_ms: int
    scenario_id: str
    total_rounds: int
    termination_reason: str
    confidence_trajectory: Tuple[Tuple[float, float], ...]  # ((arch_r1, skep_r1), (arch_r2, skep_r2), ...)
    verdict_outcome: str
    expected_verdict: str
    is_correct: bool

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_type": self.event_type,
            "timestamp_ms": self.timestamp_ms,
            "scenario_id": self.scenario_id,
            "total_rounds": self.total_rounds,
            "termination_reason": self.termination_reason,
            "confidence_trajectory": [list(pair) for pair in self.confidence_trajectory],
            "verdict_outcome": self.verdict_outcome,
            "expected_verdict": self.expected_verdict,
            "is_correct": self.is_correct,
        }


MultiTurnEvent = Union[RoundStartEvent, RoundConfidenceEvent, DebateEvolutionEvent]

_MT_EVENT_REGISTRY: Dict[str, type] = {
    "round_start": RoundStartEvent,
    "round_confidence": RoundConfidenceEvent,
    "debate_evolution": DebateEvolutionEvent,
}


def mt_event_from_dict(d: Dict[str, Any]) -> MultiTurnEvent:
    """Deserialize a dict to the correct multi-turn event type.

    Raises:
        ValueError: If event_type is unknown.
    """
    event_type = d.get("event_type")
    if event_type not in _MT_EVENT_REGISTRY:
        raise ValueError(f"Unknown multi-turn event_type: {event_type!r}")

    cls = _MT_EVENT_REGISTRY[event_type]
    kwargs = dict(d)
    if "confidence_trajectory" in kwargs and isinstance(kwargs["confidence_trajectory"], list):
        kwargs["confidence_trajectory"] = tuple(tuple(p) for p in kwargs["confidence_trajectory"])

    return cls(**kwargs)
