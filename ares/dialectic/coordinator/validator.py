"""Message validation against EvidencePacket.

The MessageValidator enforces closed-world semantics by ensuring
all message assertions reference facts that exist in the packet.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from ares.dialectic.evidence import EvidencePacket
    from ares.dialectic.messages import DialecticalMessage, Assertion


class ErrorCode(Enum):
    """Error codes for validation failures."""

    PACKET_MISMATCH = "packet_mismatch"
    MISSING_FACTS = "missing_facts"
    EMPTY_ASSERTIONS = "empty_assertions"
    INVALID_CONFIDENCE = "invalid_confidence"
    MISSING_REQUIRED_FIELD = "missing_required_field"
    INVALID_PHASE_TRANSITION = "invalid_phase_transition"


class ValidationError(Exception):
    """Exception raised for validation failures.

    Attributes:
        message: Human-readable error description.
        error_code: Machine-readable error code for programmatic handling.
        context: Additional context about the error.
    """

    def __init__(
        self,
        message: str,
        error_code: ErrorCode,
        context: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.context = context or {}

    def __str__(self) -> str:
        return f"[{self.error_code.value}] {self.message}"


@dataclass
class ValidationResult:
    """Result of message validation.

    Attributes:
        is_valid: Whether the message passed all validation checks.
        errors: List of ValidationError instances for failures.
        warnings: Non-fatal issues that should be noted.
    """

    is_valid: bool
    errors: List[ValidationError] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    @property
    def error_codes(self) -> List[ErrorCode]:
        """Get all error codes from validation errors."""
        return [e.error_code for e in self.errors]

    @property
    def error_messages(self) -> List[str]:
        """Get all error messages."""
        return [e.message for e in self.errors]


class MessageValidator:
    """Validates DialecticalMessages against an EvidencePacket.

    The validator ensures that all assertions in a message reference
    facts that exist in the associated packet, enforcing closed-world
    semantics for dialectical debates.
    """

    def __init__(self, packet: "EvidencePacket") -> None:
        """Initialize validator with an EvidencePacket.

        Args:
            packet: The evidence packet to validate against.
        """
        self._packet = packet

    @property
    def packet(self) -> "EvidencePacket":
        """The packet this validator checks against."""
        return self._packet

    @property
    def packet_id(self) -> str:
        """The ID of the packet this validator checks against."""
        return self._packet.packet_id

    def validate(self, message: "DialecticalMessage") -> ValidationResult:
        """Validate a message against the packet and rules.

        Checks:
        - packet_id matches validator's packet
        - All fact_ids in assertions exist in packet
        - Assertions list is not empty (has substance)
        - Confidence is between 0.0 and 1.0
        - Required fields are present

        Args:
            message: The message to validate.

        Returns:
            ValidationResult with all collected errors.
        """
        errors: List[ValidationError] = []
        warnings: List[str] = []

        # Check packet_id matches
        if message.packet_id != self._packet.packet_id:
            errors.append(
                ValidationError(
                    message=f"Packet ID mismatch: message references '{message.packet_id}' "
                    f"but validator has '{self._packet.packet_id}'",
                    error_code=ErrorCode.PACKET_MISMATCH,
                    context={
                        "message_packet_id": message.packet_id,
                        "validator_packet_id": self._packet.packet_id,
                    },
                )
            )

        # Check required fields
        if not message.source_agent:
            errors.append(
                ValidationError(
                    message="Missing required field: source_agent",
                    error_code=ErrorCode.MISSING_REQUIRED_FIELD,
                    context={"field": "source_agent"},
                )
            )

        if not message.target_agent:
            errors.append(
                ValidationError(
                    message="Missing required field: target_agent",
                    error_code=ErrorCode.MISSING_REQUIRED_FIELD,
                    context={"field": "target_agent"},
                )
            )

        if not message.cycle_id:
            errors.append(
                ValidationError(
                    message="Missing required field: cycle_id",
                    error_code=ErrorCode.MISSING_REQUIRED_FIELD,
                    context={"field": "cycle_id"},
                )
            )

        # Check confidence range (Note: DialecticalMessage already validates this,
        # but we double-check for defense in depth)
        if not 0.0 <= message.confidence <= 1.0:
            errors.append(
                ValidationError(
                    message=f"Invalid confidence: {message.confidence} "
                    "(must be between 0.0 and 1.0)",
                    error_code=ErrorCode.INVALID_CONFIDENCE,
                    context={"confidence": message.confidence},
                )
            )

        # Check assertions exist (has substance)
        if not message.has_substance():
            errors.append(
                ValidationError(
                    message="Message has no assertions (empty_assertions)",
                    error_code=ErrorCode.EMPTY_ASSERTIONS,
                    context={"assertion_count": 0},
                )
            )

        # Validate all fact references in assertions
        all_missing_facts: List[str] = []
        for assertion in message.assertions:
            is_valid, missing = self.validate_assertion(assertion)
            if not is_valid:
                all_missing_facts.extend(missing)

        if all_missing_facts:
            # Deduplicate
            unique_missing = list(set(all_missing_facts))
            errors.append(
                ValidationError(
                    message=f"Assertions reference {len(unique_missing)} "
                    f"fact(s) not in packet: {unique_missing}",
                    error_code=ErrorCode.MISSING_FACTS,
                    context={"missing_fact_ids": unique_missing},
                )
            )

        return ValidationResult(
            is_valid=len(errors) == 0,
            errors=errors,
            warnings=warnings,
        )

    def validate_assertion(
        self, assertion: "Assertion"
    ) -> Tuple[bool, List[str]]:
        """Validate a single assertion against the packet.

        Args:
            assertion: The assertion to validate.

        Returns:
            Tuple of (is_valid, list of missing fact_ids).
        """
        return assertion.validate_against_packet(self._packet)

    def validate_fact_references(
        self, fact_ids: List[str]
    ) -> Tuple[bool, List[str]]:
        """Bulk validate that fact_ids exist in the packet.

        Args:
            fact_ids: List of fact IDs to validate.

        Returns:
            Tuple of (all_valid, list of missing fact_ids).
        """
        return self._packet.validate_fact_ids(fact_ids)
