"""TurnContext: The packet-bound phase container for agent turns.

Every agent receives a TurnContext when asked to act. This context:
- Binds the agent to a specific EvidencePacket (by ID and snapshot)
- Specifies the current phase (THESIS, ANTITHESIS, SYNTHESIS)
- Tracks turn number within the cycle
- Provides read-only access to prior messages in this cycle

The TurnContext is the "closed world" for a single turn - agents cannot
reference anything outside it.
"""

from __future__ import annotations

from dataclasses import dataclass, field as dataclass_field
from datetime import datetime
from enum import Enum, auto
from typing import TYPE_CHECKING, FrozenSet, Optional

# Import Phase from existing messages module for consistency
from ares.dialectic.messages.protocol import Phase

if TYPE_CHECKING:
    from ares.dialectic.messages.protocol import DialecticalMessage


class AgentRole(Enum):
    """The three agent roles in the dialectical triad.

    Each role is bound to specific phases:
    - ARCHITECT: Acts only in THESIS phase
    - SKEPTIC: Acts only in ANTITHESIS phase
    - ORACLE: Acts only in SYNTHESIS phase
    """

    ARCHITECT = auto()
    SKEPTIC = auto()
    ORACLE = auto()


# Phase -> Allowed roles mapping (enforced by Coordinator)
# Note: Phase.RESOLUTION is not mapped - it's a terminal state with no agent action
PHASE_ROLE_MAP: dict[Phase, AgentRole] = {
    Phase.THESIS: AgentRole.ARCHITECT,
    Phase.ANTITHESIS: AgentRole.SKEPTIC,
    Phase.SYNTHESIS: AgentRole.ORACLE,
}


class RequestKind(Enum):
    """Types of data requests an agent can make.

    - MISSING_FACT: Agent needs a fact that should exist but isn't in the packet
    - CLARIFICATION: Agent needs disambiguation of existing facts
    - ADDITIONAL_CONTEXT: Agent needs related facts to complete analysis
    - TEMPORAL_EXTENSION: Agent needs facts from a different time window
    """

    MISSING_FACT = auto()
    CLARIFICATION = auto()
    ADDITIONAL_CONTEXT = auto()
    TEMPORAL_EXTENSION = auto()


class RequestPriority(Enum):
    """Priority levels for data requests."""

    LOW = auto()  # Nice to have, analysis can proceed without
    MEDIUM = auto()  # Would significantly improve analysis
    HIGH = auto()  # Cannot proceed without this data
    CRITICAL = auto()  # Blocking - refuse to produce verdict without


@dataclass(frozen=True)
class DataRequest:
    """Structured request for additional data.

    This is the machine-actionable sibling of the 'unknowns' field.
    When an agent can't proceed because data is missing, it should
    produce a DataRequest that the Coordinator can route or act on.

    Attributes:
        request_id: Unique identifier for this request
        kind: Type of data being requested
        description: Human-readable description of what's needed
        reason: Why this data is needed for the analysis
        priority: How important this data is
        entity_type: The type of entity the data relates to (if known)
        entity_id: Specific entity ID (if known)
        field: The field/attribute being requested (if known)
        suggested_sources: Hints about where this data might come from
    """

    request_id: str
    kind: RequestKind
    description: str
    reason: str
    priority: RequestPriority = RequestPriority.MEDIUM
    entity_type: Optional[str] = None
    entity_id: Optional[str] = None
    field: Optional[str] = None
    suggested_sources: tuple[str, ...] = dataclass_field(default_factory=tuple)

    def __post_init__(self) -> None:
        """Validate request fields."""
        if not self.request_id:
            raise ValueError("request_id cannot be empty")
        if not self.description:
            raise ValueError("description cannot be empty")
        if not self.reason:
            raise ValueError("reason cannot be empty")

    @property
    def is_blocking(self) -> bool:
        """True if this request blocks further analysis."""
        return self.priority in (RequestPriority.HIGH, RequestPriority.CRITICAL)


# Type alias for cleaner function signatures
DataRequests = tuple[DataRequest, ...]


@dataclass(frozen=True)
class TurnContext:
    """Immutable context for a single agent turn.

    This is what agents receive when asked to act. It provides:
    - Packet binding (packet_id, snapshot_id)
    - Phase information (what kind of message is expected)
    - Turn tracking (for multi-turn cycles)
    - Prior messages (read-only, for context)
    - Seen fact IDs (what's already been cited in this cycle)

    Invariants:
    - packet_id and snapshot_id MUST match the active EvidencePacket
    - phase determines what message types the agent can produce
    - prior_messages are validated, read-only copies
    - seen_fact_ids accumulates across the cycle (for "new evidence" rule)

    Attributes:
        cycle_id: Unique identifier for this dialectical cycle
        packet_id: ID of the bound EvidencePacket
        snapshot_id: Content hash of the EvidencePacket (for replay verification)
        phase: Current phase of the cycle
        turn_number: 1-indexed turn within this cycle
        max_turns: Maximum allowed turns before forced termination
        prior_messages: Read-only sequence of validated messages from earlier turns
        seen_fact_ids: All fact_ids cited so far in this cycle
        created_at: When this context was created
        deadline: Optional deadline for agent response
    """

    cycle_id: str
    packet_id: str
    snapshot_id: str
    phase: Phase
    turn_number: int
    max_turns: int
    prior_messages: tuple = dataclass_field(default_factory=tuple)  # tuple[DialecticalMessage, ...]
    seen_fact_ids: FrozenSet[str] = dataclass_field(default_factory=frozenset)
    created_at: datetime = dataclass_field(default_factory=datetime.utcnow)
    deadline: Optional[datetime] = None

    def __post_init__(self) -> None:
        """Validate context invariants."""
        if self.turn_number < 1:
            raise ValueError(f"turn_number must be >= 1, got {self.turn_number}")
        if self.max_turns < 1:
            raise ValueError(f"max_turns must be >= 1, got {self.max_turns}")
        if self.turn_number > self.max_turns:
            raise ValueError(
                f"turn_number ({self.turn_number}) cannot exceed max_turns ({self.max_turns})"
            )
        if not self.snapshot_id:
            raise ValueError("snapshot_id cannot be empty")
        if not self.packet_id:
            raise ValueError("packet_id cannot be empty")
        if not self.cycle_id:
            raise ValueError("cycle_id cannot be empty")

    @property
    def expected_role(self) -> AgentRole:
        """Return the agent role expected to act in this phase.

        Raises:
            KeyError: If phase has no mapped role (e.g., RESOLUTION)
        """
        if self.phase not in PHASE_ROLE_MAP:
            raise KeyError(f"No agent role mapped for phase {self.phase.name}")
        return PHASE_ROLE_MAP[self.phase]

    @property
    def is_first_turn(self) -> bool:
        """True if this is the first turn of the cycle."""
        return self.turn_number == 1

    @property
    def is_final_turn(self) -> bool:
        """True if this is the last allowed turn."""
        return self.turn_number == self.max_turns

    @property
    def turns_remaining(self) -> int:
        """Number of turns remaining in this cycle."""
        return self.max_turns - self.turn_number

    @property
    def is_past_deadline(self) -> bool:
        """True if the deadline has passed (if set)."""
        if self.deadline is None:
            return False
        return datetime.utcnow() > self.deadline

    def with_new_seen_facts(self, new_fact_ids: FrozenSet[str]) -> TurnContext:
        """Create a new context with additional seen fact IDs.

        Used by Coordinator when advancing to the next turn.

        Args:
            new_fact_ids: Additional fact IDs to add to seen_fact_ids

        Returns:
            New TurnContext with merged seen_fact_ids
        """
        return TurnContext(
            cycle_id=self.cycle_id,
            packet_id=self.packet_id,
            snapshot_id=self.snapshot_id,
            phase=self.phase,
            turn_number=self.turn_number,
            max_turns=self.max_turns,
            prior_messages=self.prior_messages,
            seen_fact_ids=self.seen_fact_ids | new_fact_ids,
            created_at=self.created_at,
            deadline=self.deadline,
        )

    def advance_turn(
        self,
        new_phase: Phase,
        new_message: "DialecticalMessage",
        new_fact_ids: FrozenSet[str],
    ) -> TurnContext:
        """Create a new context for the next turn.

        Used by Coordinator after validating and accepting a message.

        Args:
            new_phase: Phase for the next turn
            new_message: The validated message from the current turn
            new_fact_ids: Fact IDs cited in the new message

        Returns:
            New TurnContext for the next turn
        """
        return TurnContext(
            cycle_id=self.cycle_id,
            packet_id=self.packet_id,
            snapshot_id=self.snapshot_id,
            phase=new_phase,
            turn_number=self.turn_number + 1,
            max_turns=self.max_turns,
            prior_messages=self.prior_messages + (new_message,),
            seen_fact_ids=self.seen_fact_ids | new_fact_ids,
            created_at=datetime.utcnow(),
            deadline=self.deadline,
        )


@dataclass(frozen=True)
class TurnResult:
    """Result of an agent's turn.

    Wraps the agent's output with metadata for the Coordinator.

    Attributes:
        context: The TurnContext this result was produced for
        message: The DialecticalMessage produced (if any)
        requests: Structured data requests (if agent needs more info)
        processing_time_ms: How long the agent took to produce this result
        error: Error message if the agent failed to produce output
    """

    context: TurnContext
    message: Optional[object] = None  # DialecticalMessage
    requests: DataRequests = dataclass_field(default_factory=tuple)
    processing_time_ms: Optional[float] = None
    error: Optional[str] = None

    @property
    def has_output(self) -> bool:
        """True if the agent produced a message or requests."""
        return self.message is not None or len(self.requests) > 0

    @property
    def has_error(self) -> bool:
        """True if the agent encountered an error."""
        return self.error is not None

    @property
    def is_data_request(self) -> bool:
        """True if the agent is requesting additional data."""
        return len(self.requests) > 0 and self.message is None
