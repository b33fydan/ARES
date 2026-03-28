"""Event sequence diagnostics — validates ARES visual event sequences.

Session 030: Validates that event sequences produced by ScenarioReplayer
conform to expected invariants. Detects structural anomalies (missing
bookends, ordering violations) and data anomalies (fact count mismatches,
duplicate facts, orphaned assertions).

Public API:
    validate_sequence()  — Validate an event sequence and return a DiagnosticResult
    AnomalyType          — Enum of detectable anomaly categories
    AnomalySeverity      — CRITICAL or WARNING
    SequenceAnomaly      — A single detected anomaly
    DiagnosticResult     — Aggregate validation result
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto
from typing import Sequence, Tuple, Union

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


# ---------------------------------------------------------------------------
# Anomaly taxonomy
# ---------------------------------------------------------------------------

class AnomalySeverity(Enum):
    """Severity of a detected anomaly."""

    CRITICAL = auto()  # Sequence is broken, rendering would fail
    WARNING = auto()   # Unexpected but renderable


class AnomalyType(Enum):
    """Categories of detectable anomalies in event sequences."""

    # CRITICAL
    MISSING_SCENARIO_START = auto()
    MISSING_SCENARIO_END = auto()
    MISSING_VERDICT = auto()
    FACT_COUNT_MISMATCH = auto()
    WRONG_EVENT_ORDER = auto()

    # WARNING
    ZERO_ASSERTIONS = auto()
    DUPLICATE_FACT_EVENT = auto()
    HIGH_EVENT_COUNT = auto()       # > 50 events for a single scenario
    ORPHANED_ASSERTION = auto()     # assertion references fact not yet ingested


_SEVERITY_MAP = {
    AnomalyType.MISSING_SCENARIO_START: AnomalySeverity.CRITICAL,
    AnomalyType.MISSING_SCENARIO_END: AnomalySeverity.CRITICAL,
    AnomalyType.MISSING_VERDICT: AnomalySeverity.CRITICAL,
    AnomalyType.FACT_COUNT_MISMATCH: AnomalySeverity.CRITICAL,
    AnomalyType.WRONG_EVENT_ORDER: AnomalySeverity.CRITICAL,
    AnomalyType.ZERO_ASSERTIONS: AnomalySeverity.WARNING,
    AnomalyType.DUPLICATE_FACT_EVENT: AnomalySeverity.WARNING,
    AnomalyType.HIGH_EVENT_COUNT: AnomalySeverity.WARNING,
    AnomalyType.ORPHANED_ASSERTION: AnomalySeverity.WARNING,
}


# ---------------------------------------------------------------------------
# Anomaly and result dataclasses
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SequenceAnomaly:
    """A single anomaly detected in an event sequence.

    Attributes:
        anomaly_type: Category of the anomaly.
        severity: CRITICAL or WARNING.
        description: Human-readable explanation.
        event_index: Index in the event list where the anomaly was detected,
                     or None if the anomaly is structural (e.g., missing event).
    """

    anomaly_type: AnomalyType
    severity: AnomalySeverity
    description: str
    event_index: int | None


@dataclass(frozen=True)
class DiagnosticResult:
    """Result of validating an event sequence.

    Attributes:
        scenario_id: Identifier of the scenario that produced these events.
        total_events: Number of events in the sequence.
        fact_events: Number of fact_ingested events.
        assertion_events: Number of assertion_formed events.
        anomalies: Tuple of detected anomalies.
    """

    scenario_id: str
    total_events: int
    fact_events: int
    assertion_events: int
    anomalies: Tuple[SequenceAnomaly, ...]

    @property
    def is_valid(self) -> bool:
        """True if zero CRITICAL anomalies."""
        return not any(
            a.severity == AnomalySeverity.CRITICAL for a in self.anomalies
        )

    @property
    def critical_count(self) -> int:
        """Number of CRITICAL anomalies."""
        return sum(
            1 for a in self.anomalies if a.severity == AnomalySeverity.CRITICAL
        )

    @property
    def warning_count(self) -> int:
        """Number of WARNING anomalies."""
        return sum(
            1 for a in self.anomalies if a.severity == AnomalySeverity.WARNING
        )


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

HIGH_EVENT_THRESHOLD = 50


def validate_sequence(
    events: Sequence[VisualEvent],
    packet,
    scenario_id: str = "unknown",
) -> DiagnosticResult:
    """Validate an event sequence against expected invariants.

    Checks:
        1. Starts with scenario_start
        2. Ends with scenario_end
        3. Contains exactly one verdict_rendered
        4. fact_ingested count matches packet.fact_count
        5. Events follow lifecycle ordering (no verdict before facts,
           no facts after verdict)
        6. No duplicate fact_ingested events for the same fact_id
        7. assertion_formed events reference previously ingested facts

    Args:
        events: The event sequence to validate.
        packet: The EvidencePacket that generated these events
                (for fact count comparison).
        scenario_id: Identifier for reporting.

    Returns:
        DiagnosticResult with any detected anomalies.
    """
    anomalies: list[SequenceAnomaly] = []
    fact_count = 0
    assertion_count = 0
    ingested_fact_ids: set[str] = set()
    verdict_seen = False
    verdict_index: int | None = None
    any_fact_seen = False

    # --- Bookend checks ---
    if not events:
        anomalies.append(_anomaly(
            AnomalyType.MISSING_SCENARIO_START,
            "Empty event sequence — no scenario_start",
            None,
        ))
        anomalies.append(_anomaly(
            AnomalyType.MISSING_SCENARIO_END,
            "Empty event sequence — no scenario_end",
            None,
        ))
        anomalies.append(_anomaly(
            AnomalyType.MISSING_VERDICT,
            "Empty event sequence — no verdict_rendered",
            None,
        ))
        anomalies.append(_anomaly(
            AnomalyType.FACT_COUNT_MISMATCH,
            f"Expected {packet.fact_count} facts, got 0",
            None,
        ))
        return DiagnosticResult(
            scenario_id=scenario_id,
            total_events=0,
            fact_events=0,
            assertion_events=0,
            anomalies=tuple(anomalies),
        )

    if not isinstance(events[0], ScenarioStartEvent):
        anomalies.append(_anomaly(
            AnomalyType.MISSING_SCENARIO_START,
            f"First event is {events[0].event_type}, expected scenario_start",
            0,
        ))

    if not isinstance(events[-1], ScenarioEndEvent):
        anomalies.append(_anomaly(
            AnomalyType.MISSING_SCENARIO_END,
            f"Last event is {events[-1].event_type}, expected scenario_end",
            len(events) - 1,
        ))

    # --- Walk the sequence ---
    for i, event in enumerate(events):
        if isinstance(event, FactIngestedEvent):
            fact_count += 1
            any_fact_seen = True

            # Ordering: no facts after verdict
            if verdict_seen:
                anomalies.append(_anomaly(
                    AnomalyType.WRONG_EVENT_ORDER,
                    f"fact_ingested at index {i} after verdict at index {verdict_index}",
                    i,
                ))

            # Duplicate fact check
            fid = event.fact_id
            if fid in ingested_fact_ids:
                anomalies.append(_anomaly(
                    AnomalyType.DUPLICATE_FACT_EVENT,
                    f"Duplicate fact_ingested for fact_id={fid!r}",
                    i,
                ))
            ingested_fact_ids.add(fid)

        elif isinstance(event, AssertionFormedEvent):
            assertion_count += 1

            # Ordering: assertion before any fact
            if not any_fact_seen:
                anomalies.append(_anomaly(
                    AnomalyType.WRONG_EVENT_ORDER,
                    f"assertion_formed at index {i} before any fact_ingested",
                    i,
                ))

            # Orphaned assertion: references facts not yet ingested
            for fid in event.cited_fact_ids:
                if fid not in ingested_fact_ids:
                    anomalies.append(_anomaly(
                        AnomalyType.ORPHANED_ASSERTION,
                        f"assertion {event.assertion_id!r} cites unknown fact {fid!r}",
                        i,
                    ))
                    break  # One anomaly per assertion is enough

        elif isinstance(event, VerdictRenderedEvent):
            if verdict_seen:
                anomalies.append(_anomaly(
                    AnomalyType.WRONG_EVENT_ORDER,
                    f"Multiple verdict_rendered events (first at {verdict_index}, second at {i})",
                    i,
                ))
            verdict_seen = True
            verdict_index = i

    # --- Post-walk checks ---

    if not verdict_seen:
        anomalies.append(_anomaly(
            AnomalyType.MISSING_VERDICT,
            "No verdict_rendered event in sequence",
            None,
        ))

    if fact_count != packet.fact_count:
        anomalies.append(_anomaly(
            AnomalyType.FACT_COUNT_MISMATCH,
            f"Expected {packet.fact_count} facts, got {fact_count}",
            None,
        ))

    if assertion_count == 0:
        anomalies.append(_anomaly(
            AnomalyType.ZERO_ASSERTIONS,
            "No assertion_formed events in sequence",
            None,
        ))

    if len(events) > HIGH_EVENT_THRESHOLD:
        anomalies.append(_anomaly(
            AnomalyType.HIGH_EVENT_COUNT,
            f"Sequence has {len(events)} events (threshold: {HIGH_EVENT_THRESHOLD})",
            None,
        ))

    return DiagnosticResult(
        scenario_id=scenario_id,
        total_events=len(events),
        fact_events=fact_count,
        assertion_events=assertion_count,
        anomalies=tuple(anomalies),
    )


def _anomaly(
    anomaly_type: AnomalyType,
    description: str,
    event_index: int | None,
) -> SequenceAnomaly:
    """Create a SequenceAnomaly with auto-resolved severity."""
    return SequenceAnomaly(
        anomaly_type=anomaly_type,
        severity=_SEVERITY_MAP[anomaly_type],
        description=description,
        event_index=event_index,
    )
