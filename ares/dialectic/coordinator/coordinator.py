"""Coordinator - Central authority for dialectical debates.

The Coordinator manages dialectical cycles, validates all messages,
routes communication between agents, and enforces debate rules.
No message passes between agents without Coordinator approval.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple, TYPE_CHECKING

from .validator import MessageValidator, ValidationResult as ValidatorResult
from .cycle import (
    CycleState,
    CycleConfig,
    DialecticalCycle,
    TerminationReason,
)

if TYPE_CHECKING:
    from ares.dialectic.evidence import EvidencePacket
    from ares.dialectic.messages import DialecticalMessage


class CoordinatorError(Exception):
    """Base exception for coordinator errors."""

    pass


class DuplicateCycleError(CoordinatorError):
    """Raised when attempting to create a cycle with existing ID."""

    def __init__(self, cycle_id: str) -> None:
        self.cycle_id = cycle_id
        super().__init__(f"Cycle already exists: {cycle_id}")


class CycleNotFoundError(CoordinatorError):
    """Raised when a cycle is not found."""

    def __init__(self, cycle_id: str) -> None:
        self.cycle_id = cycle_id
        super().__init__(f"Cycle not found: {cycle_id}")


class MessageRejectedError(CoordinatorError):
    """Raised when a message is rejected during submission."""

    def __init__(self, message_id: str, reason: str) -> None:
        self.message_id = message_id
        self.reason = reason
        super().__init__(f"Message {message_id} rejected: {reason}")


@dataclass
class SubmissionResult:
    """Result of submitting a message to the coordinator.

    Attributes:
        accepted: Whether the message was accepted.
        message_id: ID of the submitted message.
        cycle_state: Current state of the cycle after submission.
        validation_result: Validation details if rejected.
        next_expected_agent: Who should send the next message.
        should_terminate: Whether the cycle should terminate.
        termination_reason: Reason for termination if applicable.
        warnings: Non-fatal issues to note.
    """

    accepted: bool
    message_id: str
    cycle_state: CycleState
    validation_result: Optional[ValidatorResult] = None
    next_expected_agent: Optional[str] = None
    should_terminate: bool = False
    termination_reason: Optional[TerminationReason] = None
    warnings: List[str] = field(default_factory=list)


class Coordinator:
    """Central authority for managing dialectical debates.

    The Coordinator is the ONLY path for agent communication.
    It validates all messages, manages cycle state, and enforces rules.
    """

    # Agent role mapping based on phase
    PHASE_AGENTS = {
        CycleState.THESIS_PENDING: "architect",
        CycleState.ANTITHESIS_PENDING: "skeptic",
        CycleState.SYNTHESIS_PENDING: "oracle",
    }

    def __init__(self, config: Optional[CycleConfig] = None) -> None:
        """Initialize the coordinator.

        Args:
            config: Default configuration for new cycles.
        """
        self._config = config or CycleConfig()
        self._active_cycles: Dict[str, DialecticalCycle] = {}
        self._completed_cycles: Dict[str, DialecticalCycle] = {}
        self._message_log: List[Tuple[datetime, str, "DialecticalMessage"]] = []

    @property
    def config(self) -> CycleConfig:
        """Default configuration for new cycles."""
        return self._config

    def start_cycle(
        self,
        cycle_id: str,
        packet: "EvidencePacket",
        config: Optional[CycleConfig] = None,
    ) -> DialecticalCycle:
        """Start a new dialectical cycle.

        Args:
            cycle_id: Unique identifier for the cycle.
            packet: The evidence packet for this debate.
            config: Optional custom config (uses coordinator default if not provided).

        Returns:
            The newly created DialecticalCycle.

        Raises:
            DuplicateCycleError: If cycle_id already exists.
        """
        if cycle_id in self._active_cycles or cycle_id in self._completed_cycles:
            raise DuplicateCycleError(cycle_id)

        cycle_config = config or self._config
        cycle = DialecticalCycle(cycle_id, packet, cycle_config)

        # Advance to THESIS_PENDING so we're ready to receive messages
        cycle.advance_state()

        self._active_cycles[cycle_id] = cycle
        return cycle

    def get_cycle(self, cycle_id: str) -> DialecticalCycle:
        """Get a cycle by ID.

        Args:
            cycle_id: The cycle identifier.

        Returns:
            The DialecticalCycle.

        Raises:
            CycleNotFoundError: If cycle doesn't exist.
        """
        if cycle_id in self._active_cycles:
            return self._active_cycles[cycle_id]
        if cycle_id in self._completed_cycles:
            return self._completed_cycles[cycle_id]
        raise CycleNotFoundError(cycle_id)

    def submit_message(self, message: "DialecticalMessage") -> SubmissionResult:
        """Submit a message from an agent.

        This is the main entry point for all agent communication.
        The message is validated, and if valid, the cycle state is updated.

        Args:
            message: The message to submit.

        Returns:
            SubmissionResult with acceptance status and details.
        """
        warnings: List[str] = []

        # Get the cycle
        try:
            cycle = self.get_cycle(message.cycle_id)
        except CycleNotFoundError:
            return SubmissionResult(
                accepted=False,
                message_id=message.message_id,
                cycle_state=CycleState.TERMINATED,
                validation_result=ValidatorResult(
                    is_valid=False,
                    errors=[],
                    warnings=[f"Cycle not found: {message.cycle_id}"],
                ),
            )

        # Check if cycle is active
        if not cycle.is_active:
            return SubmissionResult(
                accepted=False,
                message_id=message.message_id,
                cycle_state=cycle.state,
                validation_result=ValidatorResult(
                    is_valid=False,
                    errors=[],
                    warnings=[f"Cycle is not active: {cycle.state.value}"],
                ),
            )

        # Create validator and validate message
        validator = MessageValidator(cycle.packet)
        validation_result = validator.validate(message)

        if not validation_result.is_valid:
            # Log the rejection
            self._message_log.append((datetime.utcnow(), "rejected", message))

            return SubmissionResult(
                accepted=False,
                message_id=message.message_id,
                cycle_state=cycle.state,
                validation_result=validation_result,
            )

        # Check if new evidence is required
        if cycle.config.require_new_evidence and len(cycle.messages) > 0:
            new_facts = cycle.get_new_facts_in_message(message)
            if not new_facts:
                warnings.append("Message adds no new evidence")

        # Check evidence coverage
        # (preview what coverage would be after this message)
        preview_facts = cycle.referenced_facts | message.get_all_fact_ids()
        if cycle.packet.fact_count > 0:
            preview_coverage = len(preview_facts) / cycle.packet.fact_count
            if preview_coverage < cycle.config.min_evidence_coverage:
                warnings.append(
                    f"Evidence coverage ({preview_coverage:.1%}) below "
                    f"minimum ({cycle.config.min_evidence_coverage:.1%})"
                )

        # Message is valid - record it
        cycle.record_message(message)
        self._message_log.append((datetime.utcnow(), "accepted", message))

        # Advance cycle state
        cycle.advance_state()

        # Check termination conditions
        should_terminate, term_reason = cycle.check_should_terminate()

        if should_terminate and term_reason:
            cycle.terminate(term_reason)
            self._move_to_completed(cycle.cycle_id)
            return SubmissionResult(
                accepted=True,
                message_id=message.message_id,
                cycle_state=cycle.state,
                should_terminate=True,
                termination_reason=term_reason,
                warnings=warnings,
            )

        # Check if cycle is now resolved
        if cycle.state == CycleState.RESOLVED:
            self._move_to_completed(cycle.cycle_id)
            return SubmissionResult(
                accepted=True,
                message_id=message.message_id,
                cycle_state=cycle.state,
                warnings=warnings,
            )

        # Get next expected agent
        next_agent = self.get_next_expected_agent(cycle.cycle_id)

        return SubmissionResult(
            accepted=True,
            message_id=message.message_id,
            cycle_state=cycle.state,
            next_expected_agent=next_agent,
            warnings=warnings,
        )

    def get_next_expected_agent(self, cycle_id: str) -> Optional[str]:
        """Get the agent expected to send the next message.

        Args:
            cycle_id: The cycle identifier.

        Returns:
            Agent role name or None if cycle is not in a pending state.
        """
        cycle = self.get_cycle(cycle_id)

        # Need to look at the next pending state
        next_pending_map = {
            CycleState.THESIS_COMPLETE: CycleState.ANTITHESIS_PENDING,
            CycleState.ANTITHESIS_COMPLETE: CycleState.SYNTHESIS_PENDING,
        }

        # If currently in a pending state, return that agent
        if cycle.state in self.PHASE_AGENTS:
            return self.PHASE_AGENTS[cycle.state]

        # If in a complete state, return next pending state's agent
        if cycle.state in next_pending_map:
            next_state = next_pending_map[cycle.state]
            return self.PHASE_AGENTS.get(next_state)

        return None

    def terminate_cycle(self, cycle_id: str, reason: TerminationReason) -> None:
        """Manually terminate a cycle.

        Args:
            cycle_id: The cycle to terminate.
            reason: The reason for termination.

        Raises:
            CycleNotFoundError: If cycle doesn't exist.
        """
        cycle = self.get_cycle(cycle_id)
        cycle.terminate(reason)
        self._move_to_completed(cycle_id)

    def _move_to_completed(self, cycle_id: str) -> None:
        """Move a cycle from active to completed."""
        if cycle_id in self._active_cycles:
            cycle = self._active_cycles.pop(cycle_id)
            self._completed_cycles[cycle_id] = cycle

    def get_cycle_summary(self, cycle_id: str) -> Dict[str, Any]:
        """Get summary of a cycle.

        Args:
            cycle_id: The cycle identifier.

        Returns:
            Summary dictionary.
        """
        cycle = self.get_cycle(cycle_id)
        return cycle.summary()

    def get_all_active_cycles(self) -> List[str]:
        """Get list of all active cycle IDs.

        Returns:
            List of cycle IDs.
        """
        return list(self._active_cycles.keys())

    def get_all_completed_cycles(self) -> List[str]:
        """Get list of all completed cycle IDs.

        Returns:
            List of cycle IDs.
        """
        return list(self._completed_cycles.keys())

    def get_message_log(
        self, cycle_id: Optional[str] = None
    ) -> List[Tuple[datetime, str, "DialecticalMessage"]]:
        """Get the message log.

        Args:
            cycle_id: Optional filter by cycle ID.

        Returns:
            List of (timestamp, action, message) tuples.
        """
        if cycle_id is None:
            return self._message_log.copy()

        return [
            (ts, action, msg)
            for ts, action, msg in self._message_log
            if msg.cycle_id == cycle_id
        ]
