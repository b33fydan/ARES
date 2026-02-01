"""Tests for protocol module."""

import pytest
from datetime import datetime
import uuid

from ares.dialectic.messages.protocol import (
    MessageType,
    Phase,
    Priority,
    ValidationResult,
    DialecticalMessage,
    MessageBuilder,
)
from ares.dialectic.messages.assertions import Assertion, AssertionType
from ares.dialectic.evidence import (
    EvidencePacket,
    Fact,
    Provenance,
    SourceType,
    EntityType,
    TimeWindow,
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


class TestMessageTypeEnum:
    """Tests for MessageType enum."""

    def test_observation_exists(self) -> None:
        """OBSERVATION type is defined."""
        assert MessageType.OBSERVATION.value == "observation"

    def test_hypothesis_exists(self) -> None:
        """HYPOTHESIS type is defined."""
        assert MessageType.HYPOTHESIS.value == "hypothesis"

    def test_rebuttal_exists(self) -> None:
        """REBUTTAL type is defined."""
        assert MessageType.REBUTTAL.value == "rebuttal"

    def test_request_exists(self) -> None:
        """REQUEST type is defined."""
        assert MessageType.REQUEST.value == "request"

    def test_verdict_exists(self) -> None:
        """VERDICT type is defined."""
        assert MessageType.VERDICT.value == "verdict"

    def test_all_message_types(self) -> None:
        """All expected message types are defined."""
        expected = {"OBSERVATION", "HYPOTHESIS", "REBUTTAL", "REQUEST", "VERDICT"}
        actual = {member.name for member in MessageType}
        assert actual == expected


class TestPhaseEnum:
    """Tests for Phase enum."""

    def test_thesis_exists(self) -> None:
        """THESIS phase is defined."""
        assert Phase.THESIS.value == "thesis"

    def test_antithesis_exists(self) -> None:
        """ANTITHESIS phase is defined."""
        assert Phase.ANTITHESIS.value == "antithesis"

    def test_synthesis_exists(self) -> None:
        """SYNTHESIS phase is defined."""
        assert Phase.SYNTHESIS.value == "synthesis"

    def test_resolution_exists(self) -> None:
        """RESOLUTION phase is defined."""
        assert Phase.RESOLUTION.value == "resolution"

    def test_all_phases(self) -> None:
        """All expected phases are defined."""
        expected = {"THESIS", "ANTITHESIS", "SYNTHESIS", "RESOLUTION"}
        actual = {member.name for member in Phase}
        assert actual == expected


class TestPriorityEnum:
    """Tests for Priority enum."""

    def test_low_exists(self) -> None:
        """LOW priority is defined."""
        assert Priority.LOW.value == "low"

    def test_normal_exists(self) -> None:
        """NORMAL priority is defined."""
        assert Priority.NORMAL.value == "normal"

    def test_high_exists(self) -> None:
        """HIGH priority is defined."""
        assert Priority.HIGH.value == "high"

    def test_critical_exists(self) -> None:
        """CRITICAL priority is defined."""
        assert Priority.CRITICAL.value == "critical"

    def test_all_priorities(self) -> None:
        """All expected priorities are defined."""
        expected = {"LOW", "NORMAL", "HIGH", "CRITICAL"}
        actual = {member.name for member in Priority}
        assert actual == expected


class TestDialecticalMessageCreation:
    """Tests for DialecticalMessage creation."""

    def test_creation_with_required_fields(self) -> None:
        """Message can be created with required fields."""
        msg = DialecticalMessage(
            message_id="msg-001",
            timestamp=datetime(2024, 1, 15, 12, 0, 0),
            source_agent="architect",
            target_agent="skeptic",
        )
        assert msg.message_id == "msg-001"
        assert msg.source_agent == "architect"
        assert msg.target_agent == "skeptic"

    def test_default_values(self) -> None:
        """Default values are set correctly."""
        msg = DialecticalMessage(
            message_id="msg-001",
            timestamp=datetime(2024, 1, 15, 12, 0, 0),
            source_agent="architect",
            target_agent="skeptic",
        )
        assert msg.schema_version == "1.0.0"
        assert msg.reply_to is None
        assert msg.phase == Phase.THESIS
        assert msg.turn_number == 0
        assert msg.message_type == MessageType.OBSERVATION
        assert msg.assertions == []
        assert msg.unknowns == []
        assert msg.confidence == 0.0
        assert msg.narrative is None
        assert msg.priority == Priority.NORMAL
        assert msg.persist is False
        assert msg.tags == []


class TestDialecticalMessageSerialization:
    """Tests for DialecticalMessage serialization."""

    def test_to_dict_contains_all_fields(self) -> None:
        """to_dict includes all message fields."""
        msg = DialecticalMessage(
            message_id="msg-001",
            timestamp=datetime(2024, 1, 15, 12, 0, 0),
            source_agent="architect",
            target_agent="skeptic",
            packet_id="packet-001",
            cycle_id="cycle-001",
            phase=Phase.ANTITHESIS,
            turn_number=3,
            message_type=MessageType.HYPOTHESIS,
            confidence=0.85,
            narrative="Test narrative",
            priority=Priority.HIGH,
            persist=True,
            tags=["urgent", "review"],
        )

        result = msg.to_dict()

        assert result["message_id"] == "msg-001"
        assert result["source_agent"] == "architect"
        assert result["target_agent"] == "skeptic"
        assert result["packet_id"] == "packet-001"
        assert result["cycle_id"] == "cycle-001"
        assert result["phase"] == "antithesis"
        assert result["turn_number"] == 3
        assert result["message_type"] == "hypothesis"
        assert result["confidence"] == 0.85
        assert result["narrative"] == "Test narrative"
        assert result["priority"] == "high"
        assert result["persist"] is True
        assert result["tags"] == ["urgent", "review"]

    def test_serialization_roundtrip(self) -> None:
        """Message survives serialization roundtrip."""
        original = DialecticalMessage(
            message_id="msg-001",
            timestamp=datetime(2024, 1, 15, 12, 0, 0),
            source_agent="architect",
            target_agent="skeptic",
            packet_id="packet-001",
            cycle_id="cycle-001",
            phase=Phase.SYNTHESIS,
            turn_number=5,
            message_type=MessageType.VERDICT,
            confidence=0.95,
            narrative="Final decision",
            priority=Priority.CRITICAL,
            persist=True,
            tags=["final"],
            reply_to="msg-000",
        )

        serialized = original.to_dict()
        restored = DialecticalMessage.from_dict(serialized)

        assert restored.message_id == original.message_id
        assert restored.source_agent == original.source_agent
        assert restored.target_agent == original.target_agent
        assert restored.phase == original.phase
        assert restored.message_type == original.message_type
        assert restored.confidence == original.confidence
        assert restored.reply_to == original.reply_to

    def test_roundtrip_with_assertions(self) -> None:
        """Assertions survive serialization roundtrip."""
        assertion = Assertion.assert_condition(
            assertion_id="a1",
            fact_id="f1",
            operator=">",
            threshold=100,
            interpretation="Value above threshold",
        )
        original = DialecticalMessage(
            message_id="msg-001",
            timestamp=datetime(2024, 1, 15, 12, 0, 0),
            source_agent="architect",
            target_agent="skeptic",
            assertions=[assertion],
        )

        serialized = original.to_dict()
        restored = DialecticalMessage.from_dict(serialized)

        assert len(restored.assertions) == 1
        assert restored.assertions[0].assertion_id == "a1"
        assert restored.assertions[0].operator == ">"
        assert restored.assertions[0].threshold == 100


class TestDialecticalMessageMethods:
    """Tests for DialecticalMessage methods."""

    def test_add_assertion(self) -> None:
        """add_assertion appends to list."""
        msg = DialecticalMessage(
            message_id="msg-001",
            timestamp=datetime(2024, 1, 15, 12, 0, 0),
            source_agent="architect",
            target_agent="skeptic",
        )

        assertion = make_assertion()
        msg.add_assertion(assertion)

        assert len(msg.assertions) == 1
        assert msg.assertions[0] == assertion

    def test_add_multiple_assertions(self) -> None:
        """Multiple assertions can be added."""
        msg = DialecticalMessage(
            message_id="msg-001",
            timestamp=datetime(2024, 1, 15, 12, 0, 0),
            source_agent="architect",
            target_agent="skeptic",
        )

        msg.add_assertion(make_assertion(assertion_id="a1"))
        msg.add_assertion(make_assertion(assertion_id="a2"))
        msg.add_assertion(make_assertion(assertion_id="a3"))

        assert len(msg.assertions) == 3

    def test_has_substance_false_when_no_assertions(self) -> None:
        """has_substance returns False with no assertions."""
        msg = DialecticalMessage(
            message_id="msg-001",
            timestamp=datetime(2024, 1, 15, 12, 0, 0),
            source_agent="architect",
            target_agent="skeptic",
        )
        assert msg.has_substance() is False

    def test_has_substance_true_with_assertions(self) -> None:
        """has_substance returns True with assertions."""
        msg = DialecticalMessage(
            message_id="msg-001",
            timestamp=datetime(2024, 1, 15, 12, 0, 0),
            source_agent="architect",
            target_agent="skeptic",
            assertions=[make_assertion()],
        )
        assert msg.has_substance() is True

    def test_get_all_fact_ids_empty(self) -> None:
        """get_all_fact_ids returns empty set with no assertions."""
        msg = DialecticalMessage(
            message_id="msg-001",
            timestamp=datetime(2024, 1, 15, 12, 0, 0),
            source_agent="architect",
            target_agent="skeptic",
        )
        assert msg.get_all_fact_ids() == set()

    def test_get_all_fact_ids_single_assertion(self) -> None:
        """get_all_fact_ids collects from single assertion."""
        msg = DialecticalMessage(
            message_id="msg-001",
            timestamp=datetime(2024, 1, 15, 12, 0, 0),
            source_agent="architect",
            target_agent="skeptic",
            assertions=[make_assertion(fact_ids=["f1", "f2"])],
        )
        assert msg.get_all_fact_ids() == {"f1", "f2"}

    def test_get_all_fact_ids_multiple_assertions(self) -> None:
        """get_all_fact_ids collects from all assertions."""
        msg = DialecticalMessage(
            message_id="msg-001",
            timestamp=datetime(2024, 1, 15, 12, 0, 0),
            source_agent="architect",
            target_agent="skeptic",
            assertions=[
                make_assertion(assertion_id="a1", fact_ids=["f1", "f2"]),
                make_assertion(assertion_id="a2", fact_ids=["f2", "f3"]),
                make_assertion(assertion_id="a3", fact_ids=["f4"]),
            ],
        )
        assert msg.get_all_fact_ids() == {"f1", "f2", "f3", "f4"}


class TestDialecticalMessageValidation:
    """Tests for validate_against_packet method."""

    def test_valid_when_all_facts_exist(self) -> None:
        """Returns valid when all referenced facts exist."""
        packet = make_packet_with_facts("f1", "f2", "f3")
        msg = DialecticalMessage(
            message_id="msg-001",
            timestamp=datetime(2024, 1, 15, 12, 0, 0),
            source_agent="architect",
            target_agent="skeptic",
            assertions=[
                make_assertion(assertion_id="a1", fact_ids=["f1", "f2"]),
            ],
        )

        result = msg.validate_against_packet(packet)

        assert result.is_valid is True
        assert result.missing_fact_ids == []
        assert result.invalid_assertions == []
        assert result.errors == []

    def test_invalid_when_facts_missing(self) -> None:
        """Returns invalid when facts are missing."""
        packet = make_packet_with_facts("f1")
        msg = DialecticalMessage(
            message_id="msg-001",
            timestamp=datetime(2024, 1, 15, 12, 0, 0),
            source_agent="architect",
            target_agent="skeptic",
            assertions=[
                make_assertion(assertion_id="a1", fact_ids=["f1", "f2", "f3"]),
            ],
        )

        result = msg.validate_against_packet(packet)

        assert result.is_valid is False
        assert set(result.missing_fact_ids) == {"f2", "f3"}
        assert result.invalid_assertions == ["a1"]
        assert len(result.errors) == 1

    def test_multiple_invalid_assertions(self) -> None:
        """Tracks multiple invalid assertions."""
        packet = make_packet_with_facts("f1")
        msg = DialecticalMessage(
            message_id="msg-001",
            timestamp=datetime(2024, 1, 15, 12, 0, 0),
            source_agent="architect",
            target_agent="skeptic",
            assertions=[
                make_assertion(assertion_id="a1", fact_ids=["f1"]),  # valid
                make_assertion(assertion_id="a2", fact_ids=["f2"]),  # invalid
                make_assertion(assertion_id="a3", fact_ids=["f3"]),  # invalid
            ],
        )

        result = msg.validate_against_packet(packet)

        assert result.is_valid is False
        assert set(result.invalid_assertions) == {"a2", "a3"}

    def test_valid_with_no_assertions(self) -> None:
        """Empty assertions list validates as true."""
        packet = make_packet_with_facts("f1")
        msg = DialecticalMessage(
            message_id="msg-001",
            timestamp=datetime(2024, 1, 15, 12, 0, 0),
            source_agent="architect",
            target_agent="skeptic",
        )

        result = msg.validate_against_packet(packet)

        assert result.is_valid is True


class TestValidationResult:
    """Tests for ValidationResult dataclass."""

    def test_validation_result_fields(self) -> None:
        """ValidationResult contains expected fields."""
        result = ValidationResult(
            is_valid=False,
            missing_fact_ids=["f1", "f2"],
            invalid_assertions=["a1"],
            errors=["Error message"],
        )

        assert result.is_valid is False
        assert result.missing_fact_ids == ["f1", "f2"]
        assert result.invalid_assertions == ["a1"]
        assert result.errors == ["Error message"]


class TestConfidenceBoundary:
    """Tests for confidence value validation."""

    def test_confidence_at_zero(self) -> None:
        """Confidence of 0.0 is valid."""
        msg = DialecticalMessage(
            message_id="msg-001",
            timestamp=datetime(2024, 1, 15, 12, 0, 0),
            source_agent="architect",
            target_agent="skeptic",
            confidence=0.0,
        )
        assert msg.confidence == 0.0

    def test_confidence_at_one(self) -> None:
        """Confidence of 1.0 is valid."""
        msg = DialecticalMessage(
            message_id="msg-001",
            timestamp=datetime(2024, 1, 15, 12, 0, 0),
            source_agent="architect",
            target_agent="skeptic",
            confidence=1.0,
        )
        assert msg.confidence == 1.0

    def test_confidence_in_middle(self) -> None:
        """Confidence of 0.5 is valid."""
        msg = DialecticalMessage(
            message_id="msg-001",
            timestamp=datetime(2024, 1, 15, 12, 0, 0),
            source_agent="architect",
            target_agent="skeptic",
            confidence=0.5,
        )
        assert msg.confidence == 0.5

    def test_confidence_below_zero_raises(self) -> None:
        """Confidence below 0.0 raises ValueError."""
        with pytest.raises(ValueError) as exc_info:
            DialecticalMessage(
                message_id="msg-001",
                timestamp=datetime(2024, 1, 15, 12, 0, 0),
                source_agent="architect",
                target_agent="skeptic",
                confidence=-0.1,
            )
        assert "Confidence must be between 0.0 and 1.0" in str(exc_info.value)

    def test_confidence_above_one_raises(self) -> None:
        """Confidence above 1.0 raises ValueError."""
        with pytest.raises(ValueError) as exc_info:
            DialecticalMessage(
                message_id="msg-001",
                timestamp=datetime(2024, 1, 15, 12, 0, 0),
                source_agent="architect",
                target_agent="skeptic",
                confidence=1.1,
            )
        assert "Confidence must be between 0.0 and 1.0" in str(exc_info.value)


class TestMessageWithNarrativeNoAssertions:
    """Tests for messages with narrative but no assertions."""

    def test_valid_but_no_substance(self) -> None:
        """Message with narrative but no assertions is valid but low substance."""
        msg = DialecticalMessage(
            message_id="msg-001",
            timestamp=datetime(2024, 1, 15, 12, 0, 0),
            source_agent="architect",
            target_agent="skeptic",
            narrative="This is just a narrative with no evidence",
        )

        # Valid to create
        assert msg.narrative is not None

        # But has no substance
        assert msg.has_substance() is False

        # And validates (nothing to check)
        packet = make_packet_with_facts("f1")
        result = msg.validate_against_packet(packet)
        assert result.is_valid is True


class TestMessageBuilder:
    """Tests for MessageBuilder class."""

    def test_builder_creates_message(self) -> None:
        """Builder creates a valid message."""
        builder = MessageBuilder(
            source_agent="architect",
            packet_id="packet-001",
            cycle_id="cycle-001",
        )
        msg = builder.build()

        assert msg.source_agent == "architect"
        assert msg.packet_id == "packet-001"
        assert msg.cycle_id == "cycle-001"

    def test_builder_generates_uuid(self) -> None:
        """Builder generates valid UUID for message_id."""
        builder = MessageBuilder(
            source_agent="architect",
            packet_id="packet-001",
            cycle_id="cycle-001",
        )
        msg = builder.build()

        # Should be a valid UUID
        parsed_uuid = uuid.UUID(msg.message_id)
        assert str(parsed_uuid) == msg.message_id

    def test_builder_sets_timestamp(self) -> None:
        """Builder sets timestamp to current time."""
        before = datetime.utcnow()
        builder = MessageBuilder(
            source_agent="architect",
            packet_id="packet-001",
            cycle_id="cycle-001",
        )
        msg = builder.build()
        after = datetime.utcnow()

        assert before <= msg.timestamp <= after

    def test_builder_chain_returns_self(self) -> None:
        """All builder methods return self for chaining."""
        builder = MessageBuilder(
            source_agent="architect",
            packet_id="packet-001",
            cycle_id="cycle-001",
        )

        # Each method should return the builder
        result = builder.set_target("skeptic")
        assert result is builder

        result = builder.set_phase(Phase.ANTITHESIS)
        assert result is builder

        result = builder.set_turn(5)
        assert result is builder

        result = builder.set_type(MessageType.HYPOTHESIS)
        assert result is builder

        result = builder.add_assertion(make_assertion())
        assert result is builder

        result = builder.add_unknown("Unknown factor")
        assert result is builder

        result = builder.set_confidence(0.75)
        assert result is builder

        result = builder.set_narrative("Narrative")
        assert result is builder

        result = builder.set_priority(Priority.HIGH)
        assert result is builder

        result = builder.set_persist(True)
        assert result is builder

        result = builder.add_tag("important")
        assert result is builder

        result = builder.reply_to("msg-000")
        assert result is builder

    def test_builder_full_chain(self) -> None:
        """Builder can chain all methods."""
        assertion = make_assertion()
        msg = (
            MessageBuilder("architect", "packet-001", "cycle-001")
            .set_target("skeptic")
            .set_phase(Phase.ANTITHESIS)
            .set_turn(3)
            .set_type(MessageType.REBUTTAL)
            .add_assertion(assertion)
            .add_unknown("Missing context")
            .set_confidence(0.7)
            .set_narrative("Counter argument")
            .set_priority(Priority.HIGH)
            .set_persist(True)
            .add_tag("debate")
            .reply_to("msg-000")
            .build()
        )

        assert msg.target_agent == "skeptic"
        assert msg.phase == Phase.ANTITHESIS
        assert msg.turn_number == 3
        assert msg.message_type == MessageType.REBUTTAL
        assert len(msg.assertions) == 1
        assert msg.unknowns == ["Missing context"]
        assert msg.confidence == 0.7
        assert msg.narrative == "Counter argument"
        assert msg.priority == Priority.HIGH
        assert msg.persist is True
        assert msg.tags == ["debate"]
        assert msg.reply_to == "msg-000"

    def test_builder_reply_to(self) -> None:
        """Builder sets reply_to correctly."""
        msg = (
            MessageBuilder("architect", "packet-001", "cycle-001")
            .reply_to("previous-msg-id")
            .build()
        )

        assert msg.reply_to == "previous-msg-id"

    def test_builder_default_target_is_broadcast(self) -> None:
        """Default target is broadcast."""
        msg = MessageBuilder("architect", "packet-001", "cycle-001").build()
        assert msg.target_agent == "broadcast"

    def test_builder_confidence_validation(self) -> None:
        """Builder validates confidence range."""
        builder = MessageBuilder("architect", "packet-001", "cycle-001")

        with pytest.raises(ValueError):
            builder.set_confidence(-0.1)

        with pytest.raises(ValueError):
            builder.set_confidence(1.5)

    def test_builder_multiple_assertions(self) -> None:
        """Builder can add multiple assertions."""
        msg = (
            MessageBuilder("architect", "packet-001", "cycle-001")
            .add_assertion(make_assertion(assertion_id="a1"))
            .add_assertion(make_assertion(assertion_id="a2"))
            .add_assertion(make_assertion(assertion_id="a3"))
            .build()
        )

        assert len(msg.assertions) == 3

    def test_builder_multiple_tags(self) -> None:
        """Builder can add multiple tags."""
        msg = (
            MessageBuilder("architect", "packet-001", "cycle-001")
            .add_tag("urgent")
            .add_tag("security")
            .add_tag("review")
            .build()
        )

        assert msg.tags == ["urgent", "security", "review"]

    def test_builder_multiple_unknowns(self) -> None:
        """Builder can add multiple unknowns."""
        msg = (
            MessageBuilder("architect", "packet-001", "cycle-001")
            .add_unknown("Missing log data")
            .add_unknown("Unknown user intent")
            .build()
        )

        assert msg.unknowns == ["Missing log data", "Unknown user intent"]


class TestIntegrationWithEvidencePacket:
    """Integration tests with EvidencePacket."""

    def test_full_workflow_valid(self) -> None:
        """Full workflow: create packet, freeze, create message, validate."""
        # 1. Create EvidencePacket with facts
        packet = EvidencePacket(
            packet_id="incident-001",
            time_window=TimeWindow(
                start=datetime(2024, 1, 1),
                end=datetime(2024, 1, 31),
            ),
        )
        packet.add_fact(make_fact(fact_id="login-event", field="event_type", value="login"))
        packet.add_fact(make_fact(fact_id="file-access", field="event_type", value="file_read"))
        packet.add_fact(make_fact(fact_id="network-conn", field="event_type", value="connection"))

        # 2. Freeze the packet
        snapshot_id = packet.freeze()
        assert snapshot_id is not None

        # 3. Create message with assertions referencing those facts
        msg = (
            MessageBuilder("architect", "incident-001", "cycle-001")
            .set_target("skeptic")
            .set_phase(Phase.THESIS)
            .set_type(MessageType.HYPOTHESIS)
            .add_assertion(
                Assertion.link_facts(
                    assertion_id="chain-001",
                    fact_ids=["login-event", "file-access", "network-conn"],
                    interpretation="Login followed by file access and network connection",
                )
            )
            .add_assertion(
                Assertion.assert_condition(
                    assertion_id="check-001",
                    fact_id="login-event",
                    operator="==",
                    threshold="login",
                    interpretation="Event was a login",
                )
            )
            .set_confidence(0.8)
            .build()
        )

        # 4. Validate message against packet
        result = msg.validate_against_packet(packet)

        # 5. Confirm validation passes
        assert result.is_valid is True
        assert result.missing_fact_ids == []
        assert result.invalid_assertions == []

    def test_full_workflow_invalid(self) -> None:
        """Workflow with invalid fact references."""
        # 1. Create packet with limited facts
        packet = EvidencePacket(
            packet_id="incident-001",
            time_window=TimeWindow(
                start=datetime(2024, 1, 1),
                end=datetime(2024, 1, 31),
            ),
        )
        packet.add_fact(make_fact(fact_id="login-event"))

        # 2. Create message referencing non-existent facts
        msg = (
            MessageBuilder("architect", "incident-001", "cycle-001")
            .add_assertion(
                Assertion.link_facts(
                    assertion_id="bad-chain",
                    fact_ids=["login-event", "nonexistent-fact", "also-missing"],
                    interpretation="Chain with missing facts",
                )
            )
            .build()
        )

        # 3. Validate against packet
        result = msg.validate_against_packet(packet)

        # 4. Confirm validation fails with correct missing IDs
        assert result.is_valid is False
        assert set(result.missing_fact_ids) == {"nonexistent-fact", "also-missing"}
        assert result.invalid_assertions == ["bad-chain"]
        assert len(result.errors) == 1
        assert "bad-chain" in result.errors[0]
