"""Dialectical message protocol for agent communication.

This module defines the structured message format that agents use
to communicate during dialectical debates. All claims must be
expressed through machine-checkable assertions grounded in evidence.
"""

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set, TYPE_CHECKING

from .assertions import Assertion

if TYPE_CHECKING:
    from ares.dialectic.evidence import EvidencePacket


class MessageType(Enum):
    """Types of messages in dialectical protocol.

    OBSERVATION: Initial notice of something suspicious
    HYPOTHESIS: Architect's threat claim
    REBUTTAL: Skeptic's counter-argument
    REQUEST: Request for more information
    VERDICT: Oracle's final decision
    """

    OBSERVATION = "observation"
    HYPOTHESIS = "hypothesis"
    REBUTTAL = "rebuttal"
    REQUEST = "request"
    VERDICT = "verdict"


class Phase(Enum):
    """Phases of dialectical reasoning.

    THESIS: Initial claim presentation
    ANTITHESIS: Counter-argument phase
    SYNTHESIS: Integration of perspectives
    RESOLUTION: Final determination
    """

    THESIS = "thesis"
    ANTITHESIS = "antithesis"
    SYNTHESIS = "synthesis"
    RESOLUTION = "resolution"


class Priority(Enum):
    """Message priority levels.

    LOW: Background information
    NORMAL: Standard priority
    HIGH: Urgent attention needed
    CRITICAL: Immediate action required
    """

    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ValidationResult:
    """Result of validating a message against an EvidencePacket.

    Attributes:
        is_valid: Whether all assertions reference valid facts.
        missing_fact_ids: Fact IDs that don't exist in the packet.
        invalid_assertions: Assertion IDs that failed validation.
        errors: Human-readable error messages.
    """

    is_valid: bool
    missing_fact_ids: List[str]
    invalid_assertions: List[str]
    errors: List[str]


@dataclass
class DialecticalMessage:
    """Structured message for agent communication.

    This is the hardened message format that prevents hallucination.
    All claims must be expressed through assertions that reference
    facts from an EvidencePacket.

    Envelope fields identify sender, receiver, and context.
    Dialectical context fields link to the debate state.
    Payload fields contain the actual reasoning content.
    Memory hook fields control persistence and prioritization.
    """

    # Envelope fields
    message_id: str
    timestamp: datetime
    source_agent: str
    target_agent: str
    schema_version: str = "1.0.0"
    reply_to: Optional[str] = None

    # Dialectical context fields
    packet_id: str = ""
    cycle_id: str = ""
    phase: Phase = Phase.THESIS
    turn_number: int = 0

    # Payload fields
    message_type: MessageType = MessageType.OBSERVATION
    assertions: List[Assertion] = field(default_factory=list)
    unknowns: List[str] = field(default_factory=list)
    confidence: float = 0.0
    narrative: Optional[str] = None  # LOW TRUST - never rely on this

    # Memory hook fields
    priority: Priority = Priority.NORMAL
    persist: bool = False
    tags: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        """Validate confidence is in valid range."""
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"Confidence must be between 0.0 and 1.0, got {self.confidence}")

    def add_assertion(self, assertion: Assertion) -> None:
        """Add an assertion to the message.

        Args:
            assertion: The assertion to add.
        """
        self.assertions.append(assertion)

    def has_substance(self) -> bool:
        """Check if message has substantive content.

        Returns:
            True if the message has at least one assertion.
        """
        return len(self.assertions) > 0

    def get_all_fact_ids(self) -> Set[str]:
        """Collect all fact IDs referenced by assertions.

        Returns:
            Set of all fact IDs from all assertions.
        """
        fact_ids: Set[str] = set()
        for assertion in self.assertions:
            fact_ids.update(assertion.fact_ids)
        return fact_ids

    def validate_against_packet(self, packet: "EvidencePacket") -> ValidationResult:
        """Validate all assertions against an EvidencePacket.

        Args:
            packet: The EvidencePacket to validate against.

        Returns:
            ValidationResult with validation details.
        """
        all_missing: Set[str] = set()
        invalid_assertions: List[str] = []
        errors: List[str] = []

        for assertion in self.assertions:
            is_valid, missing = assertion.validate_against_packet(packet)
            if not is_valid:
                all_missing.update(missing)
                invalid_assertions.append(assertion.assertion_id)
                errors.append(
                    f"Assertion '{assertion.assertion_id}' references "
                    f"missing facts: {missing}"
                )

        return ValidationResult(
            is_valid=len(invalid_assertions) == 0,
            missing_fact_ids=list(all_missing),
            invalid_assertions=invalid_assertions,
            errors=errors,
        )

    def to_dict(self) -> Dict[str, Any]:
        """Serialize message to dictionary.

        Returns:
            Dictionary representation suitable for JSON serialization.
        """
        return {
            "message_id": self.message_id,
            "timestamp": self.timestamp.isoformat(),
            "source_agent": self.source_agent,
            "target_agent": self.target_agent,
            "schema_version": self.schema_version,
            "reply_to": self.reply_to,
            "packet_id": self.packet_id,
            "cycle_id": self.cycle_id,
            "phase": self.phase.value,
            "turn_number": self.turn_number,
            "message_type": self.message_type.value,
            "assertions": [a.to_dict() for a in self.assertions],
            "unknowns": self.unknowns,
            "confidence": self.confidence,
            "narrative": self.narrative,
            "priority": self.priority.value,
            "persist": self.persist,
            "tags": self.tags,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DialecticalMessage":
        """Deserialize message from dictionary.

        Args:
            data: Dictionary containing message fields.

        Returns:
            DialecticalMessage instance.
        """
        return cls(
            message_id=data["message_id"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            source_agent=data["source_agent"],
            target_agent=data["target_agent"],
            schema_version=data.get("schema_version", "1.0.0"),
            reply_to=data.get("reply_to"),
            packet_id=data.get("packet_id", ""),
            cycle_id=data.get("cycle_id", ""),
            phase=Phase(data.get("phase", "thesis")),
            turn_number=data.get("turn_number", 0),
            message_type=MessageType(data.get("message_type", "observation")),
            assertions=[Assertion.from_dict(a) for a in data.get("assertions", [])],
            unknowns=data.get("unknowns", []),
            confidence=data.get("confidence", 0.0),
            narrative=data.get("narrative"),
            priority=Priority(data.get("priority", "normal")),
            persist=data.get("persist", False),
            tags=data.get("tags", []),
        )


class MessageBuilder:
    """Builder pattern for constructing DialecticalMessages.

    Provides a fluent interface for building messages step by step,
    automatically generating IDs and timestamps.
    """

    def __init__(self, source_agent: str, packet_id: str, cycle_id: str) -> None:
        """Initialize the builder with required fields.

        Args:
            source_agent: ID of the agent sending this message.
            packet_id: ID of the EvidencePacket this message references.
            cycle_id: ID of the current debate cycle.
        """
        self._source_agent = source_agent
        self._packet_id = packet_id
        self._cycle_id = cycle_id

        # Optional fields with defaults
        self._target_agent = "broadcast"
        self._phase = Phase.THESIS
        self._turn_number = 0
        self._message_type = MessageType.OBSERVATION
        self._assertions: List[Assertion] = []
        self._unknowns: List[str] = []
        self._confidence = 0.0
        self._narrative: Optional[str] = None
        self._priority = Priority.NORMAL
        self._persist = False
        self._tags: List[str] = []
        self._reply_to: Optional[str] = None

    def set_target(self, target: str) -> "MessageBuilder":
        """Set the target agent.

        Args:
            target: Target agent ID or "broadcast".

        Returns:
            Self for method chaining.
        """
        self._target_agent = target
        return self

    def set_phase(self, phase: Phase) -> "MessageBuilder":
        """Set the dialectical phase.

        Args:
            phase: The debate phase.

        Returns:
            Self for method chaining.
        """
        self._phase = phase
        return self

    def set_turn(self, turn_number: int) -> "MessageBuilder":
        """Set the turn number.

        Args:
            turn_number: Current turn in the debate.

        Returns:
            Self for method chaining.
        """
        self._turn_number = turn_number
        return self

    def set_type(self, message_type: MessageType) -> "MessageBuilder":
        """Set the message type.

        Args:
            message_type: Type of message.

        Returns:
            Self for method chaining.
        """
        self._message_type = message_type
        return self

    def add_assertion(self, assertion: Assertion) -> "MessageBuilder":
        """Add an assertion to the message.

        Args:
            assertion: The assertion to add.

        Returns:
            Self for method chaining.
        """
        self._assertions.append(assertion)
        return self

    def add_unknown(self, unknown: str) -> "MessageBuilder":
        """Add an explicit unknown to the message.

        Args:
            unknown: Description of something uncertain.

        Returns:
            Self for method chaining.
        """
        self._unknowns.append(unknown)
        return self

    def set_confidence(self, confidence: float) -> "MessageBuilder":
        """Set the confidence level.

        Args:
            confidence: Confidence from 0.0 to 1.0.

        Returns:
            Self for method chaining.

        Raises:
            ValueError: If confidence not in valid range.
        """
        if not 0.0 <= confidence <= 1.0:
            raise ValueError(f"Confidence must be between 0.0 and 1.0, got {confidence}")
        self._confidence = confidence
        return self

    def set_narrative(self, narrative: str) -> "MessageBuilder":
        """Set the optional narrative (LOW TRUST).

        Args:
            narrative: Human-readable explanation.

        Returns:
            Self for method chaining.
        """
        self._narrative = narrative
        return self

    def set_priority(self, priority: Priority) -> "MessageBuilder":
        """Set the message priority.

        Args:
            priority: Priority level.

        Returns:
            Self for method chaining.
        """
        self._priority = priority
        return self

    def set_persist(self, persist: bool) -> "MessageBuilder":
        """Set whether to persist this message.

        Args:
            persist: Whether to persist.

        Returns:
            Self for method chaining.
        """
        self._persist = persist
        return self

    def add_tag(self, tag: str) -> "MessageBuilder":
        """Add a tag to the message.

        Args:
            tag: Tag string.

        Returns:
            Self for method chaining.
        """
        self._tags.append(tag)
        return self

    def reply_to(self, message_id: str) -> "MessageBuilder":
        """Set this message as a reply to another.

        Args:
            message_id: ID of the message being replied to.

        Returns:
            Self for method chaining.
        """
        self._reply_to = message_id
        return self

    def build(self) -> DialecticalMessage:
        """Build the final DialecticalMessage.

        Automatically generates message_id (UUID) and timestamp.

        Returns:
            Constructed DialecticalMessage.
        """
        return DialecticalMessage(
            message_id=str(uuid.uuid4()),
            timestamp=datetime.utcnow(),
            source_agent=self._source_agent,
            target_agent=self._target_agent,
            packet_id=self._packet_id,
            cycle_id=self._cycle_id,
            phase=self._phase,
            turn_number=self._turn_number,
            message_type=self._message_type,
            assertions=self._assertions.copy(),
            unknowns=self._unknowns.copy(),
            confidence=self._confidence,
            narrative=self._narrative,
            priority=self._priority,
            persist=self._persist,
            tags=self._tags.copy(),
            reply_to=self._reply_to,
        )
