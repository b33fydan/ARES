"""Tests for MessageValidator class."""

import pytest
from datetime import datetime

from ares.dialectic.coordinator.validator import (
    MessageValidator,
    ValidationError,
    ValidationResult,
    ErrorCode,
)
from ares.dialectic.evidence import (
    EvidencePacket,
    Fact,
    Provenance,
    SourceType,
    EntityType,
    TimeWindow,
)
from ares.dialectic.messages import (
    DialecticalMessage,
    MessageBuilder,
    Assertion,
    Phase,
    MessageType,
)


def make_provenance() -> Provenance:
    """Create a test provenance instance."""
    return Provenance(
        source_type=SourceType.MANUAL,
        source_id="test",
        extracted_at=datetime(2024, 1, 15, 12, 0, 0),
    )


def make_fact(
    fact_id: str = "fact-001",
    entity_id: str = "node-001",
    field: str = "ip_address",
    value: any = "192.168.1.1",
) -> Fact:
    """Create a test fact instance."""
    return Fact(
        fact_id=fact_id,
        entity_id=entity_id,
        entity_type=EntityType.NODE,
        field=field,
        value=value,
        timestamp=datetime(2024, 1, 15, 12, 0, 0),
        provenance=make_provenance(),
    )


def make_packet_with_facts(*fact_ids: str) -> EvidencePacket:
    """Create a packet with facts having the given IDs."""
    packet = EvidencePacket(
        packet_id="test-packet",
        time_window=TimeWindow(
            start=datetime(2024, 1, 1),
            end=datetime(2024, 1, 31),
        ),
    )
    for fid in fact_ids:
        packet.add_fact(make_fact(fact_id=fid))
    return packet


def make_assertion(
    assertion_id: str = "a1",
    fact_ids: list = None,
) -> Assertion:
    """Create a test assertion."""
    if fact_ids is None:
        fact_ids = ["fact-001"]
    return Assertion.link_facts(
        assertion_id=assertion_id,
        fact_ids=fact_ids,
        interpretation="Test assertion",
    )


def make_valid_message(
    packet_id: str = "test-packet",
    cycle_id: str = "cycle-001",
    fact_ids: list = None,
) -> DialecticalMessage:
    """Create a valid message for testing."""
    if fact_ids is None:
        fact_ids = ["fact-001"]
    return (
        MessageBuilder("architect", packet_id, cycle_id)
        .set_target("skeptic")
        .set_phase(Phase.THESIS)
        .set_type(MessageType.HYPOTHESIS)
        .add_assertion(make_assertion(fact_ids=fact_ids))
        .set_confidence(0.8)
        .build()
    )


class TestValidatorCreation:
    """Tests for MessageValidator creation."""

    def test_creation_with_packet(self) -> None:
        """Validator is created with packet reference."""
        packet = make_packet_with_facts("f1")
        validator = MessageValidator(packet)

        assert validator.packet is packet

    def test_packet_id_property(self) -> None:
        """Validator exposes packet_id."""
        packet = make_packet_with_facts("f1")
        validator = MessageValidator(packet)

        assert validator.packet_id == "test-packet"


class TestValidateMethod:
    """Tests for validate() method."""

    def test_valid_message_passes(self) -> None:
        """Valid message passes validation."""
        packet = make_packet_with_facts("fact-001")
        validator = MessageValidator(packet)
        message = make_valid_message()

        result = validator.validate(message)

        assert result.is_valid is True
        assert result.errors == []

    def test_catches_packet_id_mismatch(self) -> None:
        """Detects when message references wrong packet."""
        packet = make_packet_with_facts("fact-001")
        validator = MessageValidator(packet)
        message = make_valid_message(packet_id="different-packet")

        result = validator.validate(message)

        assert result.is_valid is False
        assert ErrorCode.PACKET_MISMATCH in result.error_codes

    def test_catches_missing_fact_ids(self) -> None:
        """Detects when assertions reference non-existent facts."""
        packet = make_packet_with_facts("fact-001")
        validator = MessageValidator(packet)
        message = make_valid_message(fact_ids=["fact-001", "missing-fact"])

        result = validator.validate(message)

        assert result.is_valid is False
        assert ErrorCode.MISSING_FACTS in result.error_codes
        # Check context contains missing facts
        missing_error = next(e for e in result.errors if e.error_code == ErrorCode.MISSING_FACTS)
        assert "missing-fact" in missing_error.context["missing_fact_ids"]

    def test_catches_empty_assertions(self) -> None:
        """Detects when message has no assertions."""
        packet = make_packet_with_facts("fact-001")
        validator = MessageValidator(packet)
        message = DialecticalMessage(
            message_id="msg-001",
            timestamp=datetime(2024, 1, 15, 12, 0, 0),
            source_agent="architect",
            target_agent="skeptic",
            packet_id="test-packet",
            cycle_id="cycle-001",
            assertions=[],  # Empty!
            confidence=0.5,
        )

        result = validator.validate(message)

        assert result.is_valid is False
        assert ErrorCode.EMPTY_ASSERTIONS in result.error_codes

    def test_catches_missing_source_agent(self) -> None:
        """Detects when source_agent is missing."""
        packet = make_packet_with_facts("fact-001")
        validator = MessageValidator(packet)
        message = DialecticalMessage(
            message_id="msg-001",
            timestamp=datetime(2024, 1, 15, 12, 0, 0),
            source_agent="",  # Empty!
            target_agent="skeptic",
            packet_id="test-packet",
            cycle_id="cycle-001",
            assertions=[make_assertion()],
            confidence=0.5,
        )

        result = validator.validate(message)

        assert result.is_valid is False
        assert ErrorCode.MISSING_REQUIRED_FIELD in result.error_codes

    def test_catches_missing_target_agent(self) -> None:
        """Detects when target_agent is missing."""
        packet = make_packet_with_facts("fact-001")
        validator = MessageValidator(packet)
        message = DialecticalMessage(
            message_id="msg-001",
            timestamp=datetime(2024, 1, 15, 12, 0, 0),
            source_agent="architect",
            target_agent="",  # Empty!
            packet_id="test-packet",
            cycle_id="cycle-001",
            assertions=[make_assertion()],
            confidence=0.5,
        )

        result = validator.validate(message)

        assert result.is_valid is False
        assert ErrorCode.MISSING_REQUIRED_FIELD in result.error_codes

    def test_catches_missing_cycle_id(self) -> None:
        """Detects when cycle_id is missing."""
        packet = make_packet_with_facts("fact-001")
        validator = MessageValidator(packet)
        message = DialecticalMessage(
            message_id="msg-001",
            timestamp=datetime(2024, 1, 15, 12, 0, 0),
            source_agent="architect",
            target_agent="skeptic",
            packet_id="test-packet",
            cycle_id="",  # Empty!
            assertions=[make_assertion()],
            confidence=0.5,
        )

        result = validator.validate(message)

        assert result.is_valid is False
        assert ErrorCode.MISSING_REQUIRED_FIELD in result.error_codes

    def test_collects_multiple_errors(self) -> None:
        """Multiple validation errors are collected in single result."""
        packet = make_packet_with_facts("fact-001")
        validator = MessageValidator(packet)
        message = DialecticalMessage(
            message_id="msg-001",
            timestamp=datetime(2024, 1, 15, 12, 0, 0),
            source_agent="",  # Error 1
            target_agent="",  # Error 2
            packet_id="wrong-packet",  # Error 3
            cycle_id="",  # Error 4
            assertions=[],  # Error 5
            confidence=0.5,
        )

        result = validator.validate(message)

        assert result.is_valid is False
        # Should have multiple errors
        assert len(result.errors) >= 4


class TestValidateAssertion:
    """Tests for validate_assertion() method."""

    def test_valid_assertion_passes(self) -> None:
        """Valid assertion with existing facts passes."""
        packet = make_packet_with_facts("f1", "f2", "f3")
        validator = MessageValidator(packet)
        assertion = make_assertion(fact_ids=["f1", "f2"])

        is_valid, missing = validator.validate_assertion(assertion)

        assert is_valid is True
        assert missing == []

    def test_returns_missing_fact_ids(self) -> None:
        """Returns list of missing fact_ids."""
        packet = make_packet_with_facts("f1")
        validator = MessageValidator(packet)
        assertion = make_assertion(fact_ids=["f1", "f2", "f3"])

        is_valid, missing = validator.validate_assertion(assertion)

        assert is_valid is False
        assert set(missing) == {"f2", "f3"}


class TestValidateFactReferences:
    """Tests for validate_fact_references() method."""

    def test_all_valid_returns_true(self) -> None:
        """Returns (True, []) when all facts exist."""
        packet = make_packet_with_facts("f1", "f2", "f3")
        validator = MessageValidator(packet)

        is_valid, missing = validator.validate_fact_references(["f1", "f2"])

        assert is_valid is True
        assert missing == []

    def test_some_invalid_returns_missing(self) -> None:
        """Returns (False, missing) when some facts don't exist."""
        packet = make_packet_with_facts("f1")
        validator = MessageValidator(packet)

        is_valid, missing = validator.validate_fact_references(["f1", "f2", "f3"])

        assert is_valid is False
        assert set(missing) == {"f2", "f3"}

    def test_empty_list_returns_true(self) -> None:
        """Empty list validates as true."""
        packet = make_packet_with_facts("f1")
        validator = MessageValidator(packet)

        is_valid, missing = validator.validate_fact_references([])

        assert is_valid is True
        assert missing == []


class TestValidationError:
    """Tests for ValidationError exception class."""

    def test_contains_message(self) -> None:
        """ValidationError contains human-readable message."""
        error = ValidationError(
            message="Test error message",
            error_code=ErrorCode.MISSING_FACTS,
        )

        assert error.message == "Test error message"

    def test_contains_error_code(self) -> None:
        """ValidationError contains error code."""
        error = ValidationError(
            message="Test error",
            error_code=ErrorCode.PACKET_MISMATCH,
        )

        assert error.error_code == ErrorCode.PACKET_MISMATCH

    def test_contains_context(self) -> None:
        """ValidationError contains context dict."""
        error = ValidationError(
            message="Test error",
            error_code=ErrorCode.MISSING_FACTS,
            context={"missing_fact_ids": ["f1", "f2"]},
        )

        assert error.context["missing_fact_ids"] == ["f1", "f2"]

    def test_default_empty_context(self) -> None:
        """Context defaults to empty dict."""
        error = ValidationError(
            message="Test error",
            error_code=ErrorCode.EMPTY_ASSERTIONS,
        )

        assert error.context == {}

    def test_str_includes_error_code(self) -> None:
        """String representation includes error code."""
        error = ValidationError(
            message="Test error message",
            error_code=ErrorCode.INVALID_CONFIDENCE,
        )

        error_str = str(error)
        assert "invalid_confidence" in error_str
        assert "Test error message" in error_str


class TestErrorCode:
    """Tests for ErrorCode enum."""

    def test_all_error_codes_exist(self) -> None:
        """All expected error codes are defined."""
        expected = {
            "PACKET_MISMATCH",
            "MISSING_FACTS",
            "EMPTY_ASSERTIONS",
            "INVALID_CONFIDENCE",
            "MISSING_REQUIRED_FIELD",
            "INVALID_PHASE_TRANSITION",
        }
        actual = {member.name for member in ErrorCode}
        assert actual == expected


class TestValidationResult:
    """Tests for ValidationResult dataclass."""

    def test_error_codes_property(self) -> None:
        """error_codes property extracts codes from errors."""
        result = ValidationResult(
            is_valid=False,
            errors=[
                ValidationError("err1", ErrorCode.PACKET_MISMATCH),
                ValidationError("err2", ErrorCode.MISSING_FACTS),
            ],
        )

        assert ErrorCode.PACKET_MISMATCH in result.error_codes
        assert ErrorCode.MISSING_FACTS in result.error_codes

    def test_error_messages_property(self) -> None:
        """error_messages property extracts messages from errors."""
        result = ValidationResult(
            is_valid=False,
            errors=[
                ValidationError("First error", ErrorCode.PACKET_MISMATCH),
                ValidationError("Second error", ErrorCode.MISSING_FACTS),
            ],
        )

        assert "First error" in result.error_messages
        assert "Second error" in result.error_messages

    def test_valid_result_has_no_errors(self) -> None:
        """Valid result has empty errors list."""
        result = ValidationResult(is_valid=True)

        assert result.errors == []
        assert result.error_codes == []


class TestValidationIntegration:
    """Integration tests for validation flow."""

    def test_valid_message_with_multiple_assertions(self) -> None:
        """Valid message with multiple assertions passes."""
        packet = make_packet_with_facts("f1", "f2", "f3", "f4")
        validator = MessageValidator(packet)
        message = (
            MessageBuilder("architect", "test-packet", "cycle-001")
            .set_target("skeptic")
            .add_assertion(make_assertion(assertion_id="a1", fact_ids=["f1", "f2"]))
            .add_assertion(make_assertion(assertion_id="a2", fact_ids=["f3"]))
            .add_assertion(make_assertion(assertion_id="a3", fact_ids=["f4"]))
            .set_confidence(0.9)
            .build()
        )

        result = validator.validate(message)

        assert result.is_valid is True

    def test_invalid_message_reports_all_missing_facts(self) -> None:
        """Invalid message reports all missing facts from all assertions."""
        packet = make_packet_with_facts("f1")
        validator = MessageValidator(packet)
        message = (
            MessageBuilder("architect", "test-packet", "cycle-001")
            .set_target("skeptic")
            .add_assertion(make_assertion(assertion_id="a1", fact_ids=["f1", "missing1"]))
            .add_assertion(make_assertion(assertion_id="a2", fact_ids=["missing2", "missing3"]))
            .set_confidence(0.5)
            .build()
        )

        result = validator.validate(message)

        assert result.is_valid is False
        missing_error = next(e for e in result.errors if e.error_code == ErrorCode.MISSING_FACTS)
        missing_facts = set(missing_error.context["missing_fact_ids"])
        assert missing_facts == {"missing1", "missing2", "missing3"}
