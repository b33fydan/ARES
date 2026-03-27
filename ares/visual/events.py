"""Visual event schema — typed JSON messages for the ARES visual emitter.

Session 029: Defines every event type that the VisualEmitter can produce.
Each event is a frozen dataclass that serializes to a JSON-compatible dict
via to_dict(). Events are the contract between the Python emitter and
the nw_wrld JavaScript modules.

Public API:
    Event dataclasses  — ScenarioStartEvent, FactIngestedEvent, etc.
    event_from_dict()  — Deserialize a dict back to the correct event type
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Tuple, Union


# ---------------------------------------------------------------------------
# Event types
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ScenarioStartEvent:
    """Emitted when a scenario begins processing."""

    event_type: str
    timestamp_ms: int
    scenario_id: str
    scenario_name: str
    expected_verdict: str
    fact_count: int
    source_types: Tuple[str, ...]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_type": self.event_type,
            "timestamp_ms": self.timestamp_ms,
            "scenario_id": self.scenario_id,
            "scenario_name": self.scenario_name,
            "expected_verdict": self.expected_verdict,
            "fact_count": self.fact_count,
            "source_types": list(self.source_types),
        }


@dataclass(frozen=True)
class FactIngestedEvent:
    """Emitted for each fact in the evidence packet."""

    event_type: str
    timestamp_ms: int
    scenario_id: str
    fact_id: str
    entity_type: str
    entity_id: str
    source_type: str
    field_name: str
    source_index: int
    fact_index: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_type": self.event_type,
            "timestamp_ms": self.timestamp_ms,
            "scenario_id": self.scenario_id,
            "fact_id": self.fact_id,
            "entity_type": self.entity_type,
            "entity_id": self.entity_id,
            "source_type": self.source_type,
            "field_name": self.field_name,
            "source_index": self.source_index,
            "fact_index": self.fact_index,
        }


@dataclass(frozen=True)
class AssertionFormedEvent:
    """Emitted for each assertion the Architect produces."""

    event_type: str
    timestamp_ms: int
    scenario_id: str
    assertion_id: str
    assertion_type: str
    content: str
    cited_fact_ids: Tuple[str, ...]
    confidence: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_type": self.event_type,
            "timestamp_ms": self.timestamp_ms,
            "scenario_id": self.scenario_id,
            "assertion_id": self.assertion_id,
            "assertion_type": self.assertion_type,
            "content": self.content,
            "cited_fact_ids": list(self.cited_fact_ids),
            "confidence": self.confidence,
        }


@dataclass(frozen=True)
class VerdictRenderedEvent:
    """Emitted when the final verdict is produced."""

    event_type: str
    timestamp_ms: int
    scenario_id: str
    outcome: str
    confidence: float
    correct: bool

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_type": self.event_type,
            "timestamp_ms": self.timestamp_ms,
            "scenario_id": self.scenario_id,
            "outcome": self.outcome,
            "confidence": self.confidence,
            "correct": self.correct,
        }


@dataclass(frozen=True)
class MiscalibrationCheckEvent:
    """Emitted after the MiscalibrationDetector runs."""

    event_type: str
    timestamp_ms: int
    scenario_id: str
    flagged: bool
    patterns_triggered: Tuple[str, ...]
    risk_score: float
    recommendation: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_type": self.event_type,
            "timestamp_ms": self.timestamp_ms,
            "scenario_id": self.scenario_id,
            "flagged": self.flagged,
            "patterns_triggered": list(self.patterns_triggered),
            "risk_score": self.risk_score,
            "recommendation": self.recommendation,
        }


@dataclass(frozen=True)
class ClaimAuditEvent:
    """Emitted after the ClaimAuditor runs (only if miscalibration flagged)."""

    event_type: str
    timestamp_ms: int
    scenario_id: str
    claims_total: int
    claims_supported: int
    claims_weak: int
    claims_unsupported: int
    audit_verdict: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_type": self.event_type,
            "timestamp_ms": self.timestamp_ms,
            "scenario_id": self.scenario_id,
            "claims_total": self.claims_total,
            "claims_supported": self.claims_supported,
            "claims_weak": self.claims_weak,
            "claims_unsupported": self.claims_unsupported,
            "audit_verdict": self.audit_verdict,
        }


@dataclass(frozen=True)
class ScenarioEndEvent:
    """Emitted when scenario processing is complete."""

    event_type: str
    timestamp_ms: int
    scenario_id: str
    duration_ms: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_type": self.event_type,
            "timestamp_ms": self.timestamp_ms,
            "scenario_id": self.scenario_id,
            "duration_ms": self.duration_ms,
        }


# Type alias for any visual event
VisualEvent = Union[
    ScenarioStartEvent,
    FactIngestedEvent,
    AssertionFormedEvent,
    VerdictRenderedEvent,
    MiscalibrationCheckEvent,
    ClaimAuditEvent,
    ScenarioEndEvent,
]

# Registry mapping event_type strings to constructors
_EVENT_REGISTRY: Dict[str, type] = {
    "scenario_start": ScenarioStartEvent,
    "fact_ingested": FactIngestedEvent,
    "assertion_formed": AssertionFormedEvent,
    "verdict_rendered": VerdictRenderedEvent,
    "miscalibration_check": MiscalibrationCheckEvent,
    "claim_audit": ClaimAuditEvent,
    "scenario_end": ScenarioEndEvent,
}


def event_from_dict(d: Dict[str, Any]) -> VisualEvent:
    """Deserialize a dict to the correct event type.

    Args:
        d: Dictionary with an 'event_type' key identifying the type.

    Returns:
        The appropriate frozen event dataclass instance.

    Raises:
        ValueError: If event_type is unknown.
        KeyError: If required fields are missing.
    """
    event_type = d.get("event_type")
    if event_type not in _EVENT_REGISTRY:
        raise ValueError(f"Unknown event_type: {event_type!r}")

    cls = _EVENT_REGISTRY[event_type]

    # Convert lists back to tuples for frozen dataclass fields
    kwargs = dict(d)
    for key in ("source_types", "cited_fact_ids", "patterns_triggered"):
        if key in kwargs and isinstance(kwargs[key], list):
            kwargs[key] = tuple(kwargs[key])

    return cls(**kwargs)
