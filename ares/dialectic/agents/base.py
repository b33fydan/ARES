"""AgentBase: The shared DNA for all dialectical agents.

Every agent (Architect, Skeptic, Oracle) inherits from AgentBase.
This base class guarantees:

1. Packet Binding - Agents are locked to a specific EvidencePacket
2. Evidence Tracking - Agents track which facts they've seen/cited
3. Self-Validation - Agents validate their own work before submitting
4. Memory Management - Bounded working memory with consolidation hooks
5. Phase Awareness - Agents refuse to act outside their designated phase

The key invariant: NO AGENT CAN PRODUCE OUTPUT WITHOUT PROVING IT'S GROUNDED
IN THE CURRENT EVIDENCEPACKET. HALLUCINATIONS BECOME SCHEMA VIOLATIONS.
"""

from __future__ import annotations

import logging
import uuid
from abc import ABC, abstractmethod
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import TYPE_CHECKING, FrozenSet, Optional

from ares.dialectic.agents.context import (
    AgentRole,
    DataRequest,
    DataRequests,
    PHASE_ROLE_MAP,
    RequestKind,
    RequestPriority,
    TurnContext,
    TurnResult,
)
from ares.dialectic.messages.protocol import Phase

if TYPE_CHECKING:
    from ares.dialectic.evidence.packet import EvidencePacket
    from ares.dialectic.messages.protocol import DialecticalMessage


logger = logging.getLogger(__name__)


class AgentState(Enum):
    """Lifecycle states for an agent.

    - IDLE: Agent is not bound to any packet, waiting for observation
    - OBSERVING: Agent has received a packet, building internal state
    - READY: Agent is ready to receive turns and produce output
    - ACTING: Agent is currently processing a turn
    - CONSOLIDATING: Agent is compressing working memory
    - ERROR: Agent encountered an unrecoverable error
    """

    IDLE = auto()
    OBSERVING = auto()
    READY = auto()
    ACTING = auto()
    CONSOLIDATING = auto()
    ERROR = auto()


@dataclass
class AgentHealth:
    """Health metrics for an agent.

    Used by the Coordinator to monitor agent behavior and decide
    when consolidation or intervention is needed.
    """

    context_pressure: float  # 0.0-1.0, how full is working memory
    facts_seen: int  # Total facts observed
    facts_cited: int  # Facts actually used in messages
    messages_produced: int  # Total messages produced
    validation_failures: int  # Self-validation failures
    last_active: datetime  # Last time agent produced output

    @property
    def should_consolidate(self) -> bool:
        """True if agent should consolidate working memory."""
        return self.context_pressure > 0.8

    @property
    def citation_rate(self) -> float:
        """Ratio of cited facts to seen facts."""
        if self.facts_seen == 0:
            return 0.0
        return self.facts_cited / self.facts_seen


@dataclass
class SelfValidationResult:
    """Result of agent self-validation before submission."""

    is_valid: bool
    errors: tuple[str, ...] = field(default_factory=tuple)
    warnings: tuple[str, ...] = field(default_factory=tuple)
    missing_fact_ids: FrozenSet[str] = field(default_factory=frozenset)

    @classmethod
    def success(cls) -> SelfValidationResult:
        """Create a successful validation result."""
        return cls(is_valid=True)

    @classmethod
    def failure(cls, *errors: str) -> SelfValidationResult:
        """Create a failed validation result."""
        return cls(is_valid=False, errors=errors)


class PacketMismatchError(Exception):
    """Raised when an agent tries to act on the wrong packet."""

    def __init__(self, expected_packet_id: str, actual_packet_id: str) -> None:
        self.expected_packet_id = expected_packet_id
        self.actual_packet_id = actual_packet_id
        super().__init__(
            f"Packet mismatch: agent bound to {expected_packet_id}, "
            f"but turn context has {actual_packet_id}"
        )


class SnapshotMismatchError(Exception):
    """Raised when an agent's bound snapshot doesn't match the context."""

    def __init__(self, expected_snapshot_id: str, actual_snapshot_id: str) -> None:
        self.expected_snapshot_id = expected_snapshot_id
        self.actual_snapshot_id = actual_snapshot_id
        super().__init__(
            f"Snapshot mismatch: agent bound to {expected_snapshot_id}, "
            f"but turn context has {actual_snapshot_id}"
        )


class PhaseViolationError(Exception):
    """Raised when an agent tries to act outside its designated phase."""

    def __init__(self, agent_role: AgentRole, current_phase: Phase) -> None:
        self.agent_role = agent_role
        self.current_phase = current_phase
        expected_phases = [p for p, r in PHASE_ROLE_MAP.items() if r == agent_role]
        expected_phase = expected_phases[0] if expected_phases else None
        super().__init__(
            f"Phase violation: {agent_role.name} cannot act in {current_phase.name} phase "
            f"(expected {expected_phase.name if expected_phase else 'N/A'})"
        )


class AgentNotReadyError(Exception):
    """Raised when an agent is asked to act but isn't in READY state."""

    def __init__(self, agent_id: str, current_state: AgentState) -> None:
        self.agent_id = agent_id
        self.current_state = current_state
        super().__init__(
            f"Agent {agent_id} is not ready to act (current state: {current_state.name})"
        )


@dataclass
class WorkingMemoryEntry:
    """A single entry in the agent's working memory.

    Working memory holds recent messages and observations that the agent
    uses to inform its reasoning. Entries are timestamped and can be
    evicted when memory pressure is high.
    """

    content: object  # DialecticalMessage or other data
    timestamp: datetime
    relevance_score: float = 1.0  # Decays over time/turns

    def decay(self, factor: float = 0.9) -> None:
        """Reduce relevance score (called each turn)."""
        self.relevance_score *= factor


class AgentBase(ABC):
    """Abstract base class for all dialectical agents.

    Subclasses must implement:
    - role: The agent's role (ARCHITECT, SKEPTIC, or ORACLE)
    - _compose_impl: The actual message composition logic

    The base class handles:
    - Packet binding and validation
    - Evidence tracking (seen_fact_ids, cited_fact_ids)
    - Working memory management
    - Self-validation before submission
    - Phase enforcement
    """

    def __init__(
        self,
        agent_id: Optional[str] = None,
        max_memory_size: int = 100,
    ) -> None:
        """Initialize the agent.

        Args:
            agent_id: Unique identifier for this agent instance
            max_memory_size: Maximum entries in working memory
        """
        self._agent_id = agent_id or f"{self.role.name.lower()}-{uuid.uuid4().hex[:8]}"
        self._max_memory_size = max_memory_size

        # Packet binding
        self._evidence_packet: Optional[EvidencePacket] = None
        self._active_packet_id: Optional[str] = None
        self._active_snapshot_id: Optional[str] = None

        # Evidence tracking
        self._seen_fact_ids: set[str] = set()
        self._cited_fact_ids: set[str] = set()
        self._last_turn_fact_ids: set[str] = set()

        # Working memory
        self._working_memory: deque[WorkingMemoryEntry] = deque(maxlen=max_memory_size)

        # State
        self._state = AgentState.IDLE
        self._messages_produced = 0
        self._validation_failures = 0
        self._last_active: Optional[datetime] = None
        self._last_error: Optional[str] = None

    # =========================================================================
    # Abstract Properties/Methods (must be implemented by subclasses)
    # =========================================================================

    @property
    @abstractmethod
    def role(self) -> AgentRole:
        """The agent's role in the dialectical triad."""
        ...

    @abstractmethod
    def _compose_impl(
        self,
        context: TurnContext,
    ) -> tuple[Optional["DialecticalMessage"], DataRequests]:
        """Internal composition logic - implemented by subclasses.

        This is where the actual reasoning happens. The base class
        handles all the validation, binding, and bookkeeping.

        Args:
            context: The TurnContext for this turn

        Returns:
            Tuple of (message, data_requests). At least one must be non-empty.
        """
        ...

    # =========================================================================
    # Public Properties
    # =========================================================================

    @property
    def agent_id(self) -> str:
        """Unique identifier for this agent instance."""
        return self._agent_id

    @property
    def state(self) -> AgentState:
        """Current lifecycle state of the agent."""
        return self._state

    @property
    def is_ready(self) -> bool:
        """True if the agent is ready to receive turns."""
        return self._state == AgentState.READY

    @property
    def is_bound(self) -> bool:
        """True if the agent is bound to an EvidencePacket."""
        return self._active_packet_id is not None

    @property
    def active_packet_id(self) -> Optional[str]:
        """The packet ID this agent is currently bound to."""
        return self._active_packet_id

    @property
    def active_snapshot_id(self) -> Optional[str]:
        """The snapshot ID this agent is currently bound to."""
        return self._active_snapshot_id

    @property
    def seen_fact_ids(self) -> FrozenSet[str]:
        """All fact IDs this agent has observed (immutable view)."""
        return frozenset(self._seen_fact_ids)

    @property
    def cited_fact_ids(self) -> FrozenSet[str]:
        """All fact IDs this agent has cited in messages (immutable view)."""
        return frozenset(self._cited_fact_ids)

    @property
    def last_turn_fact_ids(self) -> FrozenSet[str]:
        """Fact IDs cited in the agent's last turn (for new-evidence rule)."""
        return frozenset(self._last_turn_fact_ids)

    @property
    def context_pressure(self) -> float:
        """How full is working memory (0.0 to 1.0)."""
        if self._max_memory_size == 0:
            return 1.0
        return len(self._working_memory) / self._max_memory_size

    @property
    def should_consolidate(self) -> bool:
        """True if the agent should consolidate working memory."""
        return self.context_pressure > 0.8

    @property
    def health(self) -> AgentHealth:
        """Current health metrics for this agent."""
        return AgentHealth(
            context_pressure=self.context_pressure,
            facts_seen=len(self._seen_fact_ids),
            facts_cited=len(self._cited_fact_ids),
            messages_produced=self._messages_produced,
            validation_failures=self._validation_failures,
            last_active=self._last_active or datetime.min,
        )

    @property
    def working_memory_size(self) -> int:
        """Current number of entries in working memory."""
        return len(self._working_memory)

    # =========================================================================
    # Core Methods
    # =========================================================================

    def observe(self, packet: "EvidencePacket") -> None:
        """Bind this agent to an EvidencePacket.

        This must be called before the agent can act. If the agent is
        already bound to a different packet, this triggers memory
        segmentation (previous context is cleared).

        Args:
            packet: The EvidencePacket to observe
        """
        self._state = AgentState.OBSERVING

        # Check if this is a new packet
        if self._active_packet_id is not None and self._active_packet_id != packet.packet_id:
            logger.info(
                f"Agent {self._agent_id} switching packets: "
                f"{self._active_packet_id} -> {packet.packet_id}"
            )
            self._on_packet_switch()

        # Bind to the new packet
        self._evidence_packet = packet
        self._active_packet_id = packet.packet_id
        self._active_snapshot_id = packet.snapshot_id

        # Track all available facts
        for fact_id in packet.fact_ids:
            self._seen_fact_ids.add(fact_id)

        self._state = AgentState.READY
        logger.debug(
            f"Agent {self._agent_id} bound to packet {packet.packet_id} "
            f"({len(packet.fact_ids)} facts)"
        )

    def act(self, context: TurnContext) -> TurnResult:
        """Produce output for the given turn context.

        This is the main entry point for agent action. It:
        1. Validates that the agent can act (state, packet, phase)
        2. Calls the subclass composition logic
        3. Self-validates the output
        4. Returns a TurnResult for the Coordinator

        Args:
            context: The TurnContext for this turn

        Returns:
            TurnResult containing the agent's output

        Raises:
            AgentNotReadyError: If agent is not in READY state
            PacketMismatchError: If context packet doesn't match bound packet
            SnapshotMismatchError: If context snapshot doesn't match bound snapshot
            PhaseViolationError: If this agent shouldn't act in this phase
        """
        start_time = datetime.utcnow()

        # State check
        if self._state != AgentState.READY:
            raise AgentNotReadyError(self._agent_id, self._state)

        # Packet binding check
        if self._active_packet_id != context.packet_id:
            raise PacketMismatchError(self._active_packet_id, context.packet_id)

        # Snapshot check (extra paranoia - catches data changes)
        if self._active_snapshot_id != context.snapshot_id:
            raise SnapshotMismatchError(self._active_snapshot_id, context.snapshot_id)

        # Phase check - THIS IS LAW
        if PHASE_ROLE_MAP.get(context.phase) != self.role:
            raise PhaseViolationError(self.role, context.phase)

        self._state = AgentState.ACTING

        try:
            # Call subclass implementation
            message, requests = self._compose_impl(context)

            # Self-validate if we have a message
            if message is not None:
                validation = self._self_validate(message, context)
                if not validation.is_valid:
                    self._validation_failures += 1
                    logger.warning(
                        f"Agent {self._agent_id} self-validation failed: {validation.errors}"
                    )
                    # Convert to data requests if we're missing facts
                    if validation.missing_fact_ids:
                        requests = self._convert_missing_facts_to_requests(
                            validation.missing_fact_ids,
                            requests,
                        )
                        message = None

            # Track cited facts
            if message is not None:
                self._last_turn_fact_ids = self._extract_fact_ids(message)
                self._cited_fact_ids.update(self._last_turn_fact_ids)
                self._messages_produced += 1

                # Record to working memory
                self._working_memory.append(
                    WorkingMemoryEntry(
                        content=message,
                        timestamp=datetime.utcnow(),
                    )
                )

            # Decay older memories
            for entry in self._working_memory:
                entry.decay()

            self._last_active = datetime.utcnow()
            self._state = AgentState.READY

            processing_time = (datetime.utcnow() - start_time).total_seconds() * 1000

            return TurnResult(
                context=context,
                message=message,
                requests=requests,
                processing_time_ms=processing_time,
            )

        except Exception as e:
            self._state = AgentState.ERROR
            self._last_error = str(e)
            logger.exception(f"Agent {self._agent_id} error during act()")
            return TurnResult(
                context=context,
                error=str(e),
            )

    def receive(self, message: "DialecticalMessage") -> None:
        """Receive a validated message from another agent.

        This is called by the Coordinator when routing messages.
        The message has already been validated.

        Args:
            message: A validated DialecticalMessage from another agent
        """
        if self._state not in (AgentState.READY, AgentState.IDLE):
            logger.warning(
                f"Agent {self._agent_id} received message while in {self._state.name} state"
            )
            return

        # Add to working memory
        self._working_memory.append(
            WorkingMemoryEntry(
                content=message,
                timestamp=datetime.utcnow(),
                relevance_score=0.8,  # Slightly lower than self-produced
            )
        )

        # Track seen facts from the message
        fact_ids = self._extract_fact_ids(message)
        self._seen_fact_ids.update(fact_ids)

    def consolidate(self) -> None:
        """Consolidate working memory.

        Called when context_pressure is high. Evicts low-relevance entries.
        """
        if self._state != AgentState.READY:
            logger.warning(
                f"Agent {self._agent_id} cannot consolidate in {self._state.name} state"
            )
            return

        self._state = AgentState.CONSOLIDATING

        # Sort by relevance and keep top entries
        entries = list(self._working_memory)
        entries.sort(key=lambda e: e.relevance_score, reverse=True)

        # Keep top 60% of max capacity
        keep_count = int(self._max_memory_size * 0.6)
        self._working_memory.clear()
        for entry in entries[:keep_count]:
            self._working_memory.append(entry)

        self._state = AgentState.READY
        logger.debug(
            f"Agent {self._agent_id} consolidated memory: "
            f"{len(entries)} -> {len(self._working_memory)} entries"
        )

    def reset(self) -> None:
        """Reset the agent to IDLE state.

        Clears all bindings and memory.
        """
        self._evidence_packet = None
        self._active_packet_id = None
        self._active_snapshot_id = None
        self._seen_fact_ids.clear()
        self._cited_fact_ids.clear()
        self._last_turn_fact_ids.clear()
        self._working_memory.clear()
        self._state = AgentState.IDLE
        self._last_error = None
        logger.debug(f"Agent {self._agent_id} reset to IDLE")

    # =========================================================================
    # Internal Methods
    # =========================================================================

    def _on_packet_switch(self) -> None:
        """Handle switching to a new EvidencePacket.

        This clears/segments working memory to prevent context bleed.
        """
        logger.info(f"Agent {self._agent_id} clearing memory for packet switch")
        self._seen_fact_ids.clear()
        self._cited_fact_ids.clear()
        self._last_turn_fact_ids.clear()
        self._working_memory.clear()

    def _self_validate(
        self,
        message: "DialecticalMessage",
        context: TurnContext,
    ) -> SelfValidationResult:
        """Validate a message before submission.

        Uses the same logic as the Coordinator's validator (as a preflight).
        """
        errors = []
        warnings = []
        missing_fact_ids: set[str] = set()

        # Check that all referenced fact_ids exist in the packet
        if self._evidence_packet is not None:
            for fact_id in self._extract_fact_ids(message):
                if fact_id not in self._evidence_packet.fact_ids:
                    missing_fact_ids.add(fact_id)
                    errors.append(f"Referenced fact_id not in packet: {fact_id}")

        # Check packet_id matches
        if hasattr(message, "packet_id") and message.packet_id != context.packet_id:
            errors.append(
                f"Message packet_id mismatch: {message.packet_id} != {context.packet_id}"
            )

        # Check for new evidence (if not first turn)
        if not context.is_first_turn:
            new_facts = self._extract_fact_ids(message) - context.seen_fact_ids
            if not new_facts and not hasattr(message, "requests"):
                warnings.append(
                    "Message introduces no new fact_ids - may trigger NO_NEW_EVIDENCE termination"
                )

        if errors:
            return SelfValidationResult(
                is_valid=False,
                errors=tuple(errors),
                warnings=tuple(warnings),
                missing_fact_ids=frozenset(missing_fact_ids),
            )

        return SelfValidationResult(
            is_valid=True,
            warnings=tuple(warnings),
        )

    def _extract_fact_ids(self, message: "DialecticalMessage") -> set[str]:
        """Extract all fact_ids referenced in a message."""
        fact_ids: set[str] = set()

        # Get fact_ids from assertions
        if hasattr(message, "assertions"):
            for assertion in message.assertions:
                if hasattr(assertion, "fact_ids"):
                    fact_ids.update(assertion.fact_ids)

        # Get fact_ids via get_all_fact_ids method (preferred)
        if hasattr(message, "get_all_fact_ids"):
            fact_ids.update(message.get_all_fact_ids())

        return fact_ids

    def _convert_missing_facts_to_requests(
        self,
        missing_fact_ids: FrozenSet[str],
        existing_requests: DataRequests,
    ) -> DataRequests:
        """Convert missing fact IDs to structured data requests."""
        new_requests = list(existing_requests)
        for fact_id in missing_fact_ids:
            new_requests.append(
                DataRequest(
                    request_id=f"missing-{fact_id[:8]}",
                    kind=RequestKind.MISSING_FACT,
                    description=f"Referenced fact_id not found: {fact_id}",
                    reason="Agent attempted to cite this fact but it's not in the EvidencePacket",
                    priority=RequestPriority.HIGH,
                )
            )
        return tuple(new_requests)

    # =========================================================================
    # Introspection
    # =========================================================================

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"id={self._agent_id!r}, "
            f"role={self.role.name}, "
            f"state={self._state.name}, "
            f"packet={self._active_packet_id})"
        )
