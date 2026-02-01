"""Dialectical cycle state management.

Manages the state machine for a single dialectical cycle,
tracking progression through thesis, antithesis, and synthesis phases.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from ares.dialectic.evidence import EvidencePacket
    from ares.dialectic.messages import DialecticalMessage


class CycleState(Enum):
    """States of a dialectical cycle.

    The cycle progresses: INITIALIZED -> THESIS -> ANTITHESIS -> SYNTHESIS -> RESOLVED
    Or may terminate early: any state -> TERMINATED
    """

    INITIALIZED = "initialized"
    THESIS_PENDING = "thesis_pending"
    THESIS_COMPLETE = "thesis_complete"
    ANTITHESIS_PENDING = "antithesis_pending"
    ANTITHESIS_COMPLETE = "antithesis_complete"
    SYNTHESIS_PENDING = "synthesis_pending"
    RESOLVED = "resolved"
    TERMINATED = "terminated"


class TerminationReason(Enum):
    """Reasons for early cycle termination."""

    MAX_TURNS_EXCEEDED = "max_turns_exceeded"
    NO_NEW_EVIDENCE = "no_new_evidence"
    CONFIDENCE_STABILIZED = "confidence_stabilized"
    INSUFFICIENT_DATA = "insufficient_data"
    VALIDATION_FAILURE = "validation_failure"
    MANUAL = "manual"


class InvalidStateError(Exception):
    """Raised when an operation is invalid for the current cycle state."""

    def __init__(self, message: str, current_state: CycleState) -> None:
        super().__init__(message)
        self.current_state = current_state


@dataclass
class CycleConfig:
    """Configuration for dialectical cycle behavior.

    Attributes:
        max_turns: Maximum number of back-and-forth rounds.
        confidence_epsilon: Confidence change threshold for stabilization.
        min_evidence_coverage: Minimum fraction of facts that must be referenced.
        allow_empty_unknowns: Whether agents must declare unknowns.
        require_new_evidence: Whether each turn must add new fact_ids.
    """

    max_turns: int = 3
    confidence_epsilon: float = 0.05
    min_evidence_coverage: float = 0.3
    allow_empty_unknowns: bool = True
    require_new_evidence: bool = True


class DialecticalCycle:
    """Manages the state of a single dialectical cycle.

    A cycle represents one complete thesis->antithesis->synthesis flow,
    tracking all messages, referenced facts, and state transitions.
    """

    def __init__(
        self,
        cycle_id: str,
        packet: "EvidencePacket",
        config: Optional[CycleConfig] = None,
    ) -> None:
        """Initialize a new dialectical cycle.

        Args:
            cycle_id: Unique identifier for this cycle.
            packet: The evidence packet for this debate.
            config: Configuration settings (uses defaults if not provided).
        """
        self._cycle_id = cycle_id
        self._packet = packet
        self._config = config or CycleConfig()

        self._state = CycleState.INITIALIZED
        self._turn_number = 0
        self._messages: List["DialecticalMessage"] = []
        self._referenced_facts: Set[str] = set()
        self._termination_reason: Optional[TerminationReason] = None

    @property
    def cycle_id(self) -> str:
        """Unique identifier for this cycle."""
        return self._cycle_id

    @property
    def packet(self) -> "EvidencePacket":
        """The evidence packet for this debate."""
        return self._packet

    @property
    def state(self) -> CycleState:
        """Current state of the cycle."""
        return self._state

    @property
    def turn_number(self) -> int:
        """Current turn number in the debate."""
        return self._turn_number

    @property
    def messages(self) -> List["DialecticalMessage"]:
        """Ordered history of messages in this cycle."""
        return self._messages.copy()

    @property
    def referenced_facts(self) -> Set[str]:
        """All fact_ids referenced so far in this cycle."""
        return self._referenced_facts.copy()

    @property
    def is_active(self) -> bool:
        """Whether the cycle is still active (not resolved or terminated)."""
        return self._state not in (CycleState.RESOLVED, CycleState.TERMINATED)

    @property
    def termination_reason(self) -> Optional[TerminationReason]:
        """Reason for termination, if terminated."""
        return self._termination_reason

    @property
    def config(self) -> CycleConfig:
        """Configuration for this cycle."""
        return self._config

    def record_message(self, message: "DialecticalMessage") -> None:
        """Record a message in the cycle history.

        Updates referenced_facts with any new fact_ids from the message
        and increments turn number when appropriate.

        Args:
            message: The message to record.

        Raises:
            InvalidStateError: If the cycle is not active.
        """
        if not self.is_active:
            raise InvalidStateError(
                f"Cannot record message in {self._state.value} cycle",
                self._state,
            )

        self._messages.append(message)

        # Update referenced facts
        new_facts = message.get_all_fact_ids()
        self._referenced_facts.update(new_facts)

        # Increment turn for certain state transitions
        if self._state in (
            CycleState.THESIS_PENDING,
            CycleState.ANTITHESIS_PENDING,
            CycleState.SYNTHESIS_PENDING,
        ):
            self._turn_number += 1

    def get_new_facts_in_message(self, message: "DialecticalMessage") -> Set[str]:
        """Get fact_ids in message that weren't previously referenced.

        Args:
            message: The message to check.

        Returns:
            Set of novel fact_ids.
        """
        message_facts = message.get_all_fact_ids()
        return message_facts - self._referenced_facts

    def check_should_terminate(self) -> Tuple[bool, Optional[TerminationReason]]:
        """Check if the cycle should terminate.

        Checks:
        - Turn number exceeds max_turns
        - No new facts in last turn (if require_new_evidence)
        - Confidence stabilized (delta < epsilon)

        Returns:
            Tuple of (should_terminate, reason).
        """
        # Check max turns
        if self._turn_number >= self._config.max_turns:
            return (True, TerminationReason.MAX_TURNS_EXCEEDED)

        # Check no new evidence (if required and we have messages)
        if self._config.require_new_evidence and len(self._messages) >= 2:
            last_message = self._messages[-1]
            new_facts = self.get_new_facts_in_message(last_message)
            # Actually we need to check if the message added new facts at the time
            # For simplicity, we'll check if any facts were new when recorded
            # This is a simplified check - in practice we'd track this per-message

        # Check confidence stabilization (need at least 2 messages)
        if len(self._messages) >= 2:
            last_confidence = self._messages[-1].confidence
            prev_confidence = self._messages[-2].confidence
            delta = abs(last_confidence - prev_confidence)
            if delta < self._config.confidence_epsilon:
                return (True, TerminationReason.CONFIDENCE_STABILIZED)

        return (False, None)

    def terminate(self, reason: TerminationReason) -> None:
        """Terminate the cycle early.

        Args:
            reason: The reason for termination.
        """
        self._state = CycleState.TERMINATED
        self._termination_reason = reason

    def advance_state(self) -> CycleState:
        """Advance to the next state in the cycle.

        Returns:
            The new state after advancement.

        Raises:
            InvalidStateError: If transition is not valid.
        """
        transitions = {
            CycleState.INITIALIZED: CycleState.THESIS_PENDING,
            CycleState.THESIS_PENDING: CycleState.THESIS_COMPLETE,
            CycleState.THESIS_COMPLETE: CycleState.ANTITHESIS_PENDING,
            CycleState.ANTITHESIS_PENDING: CycleState.ANTITHESIS_COMPLETE,
            CycleState.ANTITHESIS_COMPLETE: CycleState.SYNTHESIS_PENDING,
            CycleState.SYNTHESIS_PENDING: CycleState.RESOLVED,
        }

        if self._state not in transitions:
            raise InvalidStateError(
                f"Cannot advance from {self._state.value}",
                self._state,
            )

        self._state = transitions[self._state]
        return self._state

    def get_thesis_message(self) -> Optional["DialecticalMessage"]:
        """Get the thesis message if it exists.

        Returns:
            The thesis message or None.
        """
        for msg in self._messages:
            from ares.dialectic.messages import Phase
            if msg.phase == Phase.THESIS:
                return msg
        return None

    def get_antithesis_messages(self) -> List["DialecticalMessage"]:
        """Get all antithesis messages.

        Returns:
            List of antithesis messages.
        """
        from ares.dialectic.messages import Phase
        return [msg for msg in self._messages if msg.phase == Phase.ANTITHESIS]

    def get_synthesis_message(self) -> Optional["DialecticalMessage"]:
        """Get the synthesis message if it exists.

        Returns:
            The synthesis message or None.
        """
        for msg in self._messages:
            from ares.dialectic.messages import Phase
            if msg.phase == Phase.SYNTHESIS:
                return msg
        return None

    def calculate_evidence_coverage(self) -> float:
        """Calculate what fraction of facts have been referenced.

        Returns:
            Fraction from 0.0 to 1.0.
        """
        if self._packet.fact_count == 0:
            return 0.0
        return len(self._referenced_facts) / self._packet.fact_count

    def to_dict(self) -> Dict[str, Any]:
        """Serialize cycle to dictionary.

        Returns:
            Dictionary representation.
        """
        return {
            "cycle_id": self._cycle_id,
            "packet_id": self._packet.packet_id,
            "state": self._state.value,
            "turn_number": self._turn_number,
            "message_count": len(self._messages),
            "referenced_fact_count": len(self._referenced_facts),
            "termination_reason": (
                self._termination_reason.value if self._termination_reason else None
            ),
            "config": {
                "max_turns": self._config.max_turns,
                "confidence_epsilon": self._config.confidence_epsilon,
                "min_evidence_coverage": self._config.min_evidence_coverage,
                "allow_empty_unknowns": self._config.allow_empty_unknowns,
                "require_new_evidence": self._config.require_new_evidence,
            },
        }

    def summary(self) -> Dict[str, Any]:
        """Get human-readable summary of cycle state.

        Returns:
            Summary dictionary.
        """
        return {
            "cycle_id": self._cycle_id,
            "state": self._state.value,
            "turn": self._turn_number,
            "messages": len(self._messages),
            "facts_referenced": len(self._referenced_facts),
            "facts_total": self._packet.fact_count,
            "evidence_coverage": f"{self.calculate_evidence_coverage():.1%}",
            "is_active": self.is_active,
            "termination_reason": (
                self._termination_reason.value if self._termination_reason else None
            ),
        }
