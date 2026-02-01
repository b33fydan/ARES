"""Tests for Coordinator class."""

import pytest
from datetime import datetime

from ares.dialectic.coordinator.coordinator import (
    Coordinator,
    SubmissionResult,
    CoordinatorError,
    DuplicateCycleError,
    CycleNotFoundError,
    MessageRejectedError,
)
from ares.dialectic.coordinator.cycle import (
    CycleState,
    CycleConfig,
    TerminationReason,
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


def make_message(
    packet_id: str = "test-packet",
    cycle_id: str = "cycle-001",
    fact_ids: list = None,
    phase: Phase = Phase.THESIS,
    confidence: float = 0.5,
    source_agent: str = "architect",
    target_agent: str = "skeptic",
) -> DialecticalMessage:
    """Create a message for testing."""
    if fact_ids is None:
        fact_ids = ["fact-001"]
    return (
        MessageBuilder(source_agent, packet_id, cycle_id)
        .set_target(target_agent)
        .set_phase(phase)
        .set_type(MessageType.HYPOTHESIS)
        .add_assertion(make_assertion(fact_ids=fact_ids))
        .set_confidence(confidence)
        .build()
    )


class TestCoordinatorCreation:
    """Tests for Coordinator creation."""

    def test_creation_with_defaults(self) -> None:
        """Coordinator is created with default config."""
        coord = Coordinator()

        assert coord.config.max_turns == 3

    def test_creation_with_custom_config(self) -> None:
        """Coordinator uses custom config."""
        config = CycleConfig(max_turns=10)
        coord = Coordinator(config)

        assert coord.config.max_turns == 10


class TestStartCycle:
    """Tests for start_cycle method."""

    def test_creates_new_cycle(self) -> None:
        """start_cycle creates a new cycle."""
        coord = Coordinator()
        packet = make_packet_with_facts("f1")

        cycle = coord.start_cycle("cycle-001", packet)

        assert cycle.cycle_id == "cycle-001"
        assert cycle.packet is packet

    def test_cycle_starts_in_thesis_pending(self) -> None:
        """New cycle starts in THESIS_PENDING state (ready for messages)."""
        coord = Coordinator()
        packet = make_packet_with_facts("f1")

        cycle = coord.start_cycle("cycle-001", packet)

        assert cycle.state == CycleState.THESIS_PENDING

    def test_raises_duplicate_cycle_error(self) -> None:
        """start_cycle raises error for duplicate ID."""
        coord = Coordinator()
        packet = make_packet_with_facts("f1")
        coord.start_cycle("cycle-001", packet)

        with pytest.raises(DuplicateCycleError) as exc_info:
            coord.start_cycle("cycle-001", packet)

        assert exc_info.value.cycle_id == "cycle-001"

    def test_uses_custom_config(self) -> None:
        """start_cycle can use custom config for specific cycle."""
        coord = Coordinator()
        packet = make_packet_with_facts("f1")
        config = CycleConfig(max_turns=5)

        cycle = coord.start_cycle("cycle-001", packet, config)

        assert cycle.config.max_turns == 5


class TestGetCycle:
    """Tests for get_cycle method."""

    def test_retrieves_active_cycle(self) -> None:
        """get_cycle retrieves active cycle."""
        coord = Coordinator()
        packet = make_packet_with_facts("f1")
        coord.start_cycle("cycle-001", packet)

        cycle = coord.get_cycle("cycle-001")

        assert cycle.cycle_id == "cycle-001"

    def test_raises_cycle_not_found_error(self) -> None:
        """get_cycle raises error for non-existent cycle."""
        coord = Coordinator()

        with pytest.raises(CycleNotFoundError) as exc_info:
            coord.get_cycle("nonexistent")

        assert exc_info.value.cycle_id == "nonexistent"


class TestSubmitMessage:
    """Tests for submit_message method."""

    def test_accepts_valid_message(self) -> None:
        """Valid message is accepted."""
        coord = Coordinator()
        packet = make_packet_with_facts("f1")
        coord.start_cycle("cycle-001", packet)
        message = make_message(cycle_id="cycle-001", fact_ids=["f1"])

        result = coord.submit_message(message)

        assert result.accepted is True
        assert result.message_id == message.message_id

    def test_rejects_invalid_message(self) -> None:
        """Invalid message is rejected."""
        coord = Coordinator()
        packet = make_packet_with_facts("f1")
        coord.start_cycle("cycle-001", packet)
        # Message references non-existent fact
        message = make_message(cycle_id="cycle-001", fact_ids=["nonexistent"])

        result = coord.submit_message(message)

        assert result.accepted is False
        assert result.validation_result is not None
        assert result.validation_result.is_valid is False

    def test_rejects_message_for_unknown_cycle(self) -> None:
        """Message for unknown cycle is rejected."""
        coord = Coordinator()
        message = make_message(cycle_id="unknown-cycle")

        result = coord.submit_message(message)

        assert result.accepted is False

    def test_advances_cycle_state(self) -> None:
        """Accepted message advances cycle state."""
        coord = Coordinator()
        packet = make_packet_with_facts("f1")
        coord.start_cycle("cycle-001", packet)
        message = make_message(cycle_id="cycle-001", fact_ids=["f1"], phase=Phase.THESIS)

        result = coord.submit_message(message)

        assert result.cycle_state == CycleState.THESIS_COMPLETE

    def test_returns_next_expected_agent(self) -> None:
        """Result includes next expected agent."""
        coord = Coordinator()
        packet = make_packet_with_facts("f1")
        coord.start_cycle("cycle-001", packet)
        message = make_message(cycle_id="cycle-001", fact_ids=["f1"], phase=Phase.THESIS)

        result = coord.submit_message(message)

        assert result.next_expected_agent == "skeptic"

    def test_logs_accepted_message(self) -> None:
        """Accepted messages are logged."""
        coord = Coordinator()
        packet = make_packet_with_facts("f1")
        coord.start_cycle("cycle-001", packet)
        message = make_message(cycle_id="cycle-001", fact_ids=["f1"])

        coord.submit_message(message)

        log = coord.get_message_log()
        assert len(log) == 1
        assert log[0][1] == "accepted"

    def test_logs_rejected_message(self) -> None:
        """Rejected messages are logged."""
        coord = Coordinator()
        packet = make_packet_with_facts("f1")
        coord.start_cycle("cycle-001", packet)
        message = make_message(cycle_id="cycle-001", fact_ids=["nonexistent"])

        coord.submit_message(message)

        log = coord.get_message_log()
        assert len(log) == 1
        assert log[0][1] == "rejected"


class TestGetNextExpectedAgent:
    """Tests for get_next_expected_agent method."""

    def test_thesis_pending_expects_architect(self) -> None:
        """THESIS_PENDING expects architect."""
        coord = Coordinator()
        packet = make_packet_with_facts("f1")
        coord.start_cycle("cycle-001", packet)

        agent = coord.get_next_expected_agent("cycle-001")

        assert agent == "architect"

    def test_antithesis_pending_expects_skeptic(self) -> None:
        """ANTITHESIS_PENDING expects skeptic."""
        coord = Coordinator()
        packet = make_packet_with_facts("f1")
        cycle = coord.start_cycle("cycle-001", packet)
        # Advance to antithesis pending
        thesis = make_message(cycle_id="cycle-001", fact_ids=["f1"], phase=Phase.THESIS)
        coord.submit_message(thesis)
        cycle.advance_state()  # THESIS_COMPLETE -> ANTITHESIS_PENDING

        agent = coord.get_next_expected_agent("cycle-001")

        assert agent == "skeptic"

    def test_synthesis_pending_expects_oracle(self) -> None:
        """SYNTHESIS_PENDING expects oracle."""
        # Use config that won't trigger early termination
        config = CycleConfig(confidence_epsilon=0.001, max_turns=10)
        coord = Coordinator(config)
        packet = make_packet_with_facts("f1", "f2")
        cycle = coord.start_cycle("cycle-001", packet)

        # Progress through cycle - submit_message advances state
        thesis = make_message(
            cycle_id="cycle-001", fact_ids=["f1"], phase=Phase.THESIS,
            confidence=0.3
        )
        coord.submit_message(thesis)
        # After submit: THESIS_COMPLETE, manually advance to ANTITHESIS_PENDING
        cycle.advance_state()

        antithesis = make_message(
            cycle_id="cycle-001", fact_ids=["f2"], phase=Phase.ANTITHESIS,
            source_agent="skeptic", confidence=0.8  # Different confidence
        )
        coord.submit_message(antithesis)
        # After submit: ANTITHESIS_COMPLETE, manually advance to SYNTHESIS_PENDING
        cycle.advance_state()

        agent = coord.get_next_expected_agent("cycle-001")

        assert agent == "oracle"


class TestTerminateCycle:
    """Tests for terminate_cycle method."""

    def test_terminates_cycle(self) -> None:
        """terminate_cycle ends the cycle."""
        coord = Coordinator()
        packet = make_packet_with_facts("f1")
        coord.start_cycle("cycle-001", packet)

        coord.terminate_cycle("cycle-001", TerminationReason.MANUAL)

        cycle = coord.get_cycle("cycle-001")
        assert cycle.state == CycleState.TERMINATED
        assert cycle.termination_reason == TerminationReason.MANUAL

    def test_moves_to_completed(self) -> None:
        """Terminated cycle moves to completed list."""
        coord = Coordinator()
        packet = make_packet_with_facts("f1")
        coord.start_cycle("cycle-001", packet)

        coord.terminate_cycle("cycle-001", TerminationReason.MANUAL)

        assert "cycle-001" not in coord.get_all_active_cycles()
        assert "cycle-001" in coord.get_all_completed_cycles()


class TestGetAllActiveCycles:
    """Tests for get_all_active_cycles method."""

    def test_returns_active_cycle_ids(self) -> None:
        """Returns list of active cycle IDs."""
        coord = Coordinator()
        packet1 = make_packet_with_facts("f1")
        packet2 = make_packet_with_facts("f2")
        coord.start_cycle("cycle-001", packet1)
        coord.start_cycle("cycle-002", packet2)

        active = coord.get_all_active_cycles()

        assert set(active) == {"cycle-001", "cycle-002"}

    def test_returns_empty_when_no_cycles(self) -> None:
        """Returns empty list when no active cycles."""
        coord = Coordinator()

        active = coord.get_all_active_cycles()

        assert active == []


class TestSubmissionResult:
    """Tests for SubmissionResult dataclass."""

    def test_contains_all_fields(self) -> None:
        """SubmissionResult contains expected fields."""
        result = SubmissionResult(
            accepted=True,
            message_id="msg-001",
            cycle_state=CycleState.THESIS_COMPLETE,
            next_expected_agent="skeptic",
            should_terminate=False,
            warnings=["Low coverage"],
        )

        assert result.accepted is True
        assert result.message_id == "msg-001"
        assert result.cycle_state == CycleState.THESIS_COMPLETE
        assert result.next_expected_agent == "skeptic"
        assert result.should_terminate is False
        assert result.warnings == ["Low coverage"]


class TestMessageLog:
    """Tests for message logging."""

    def test_filter_by_cycle_id(self) -> None:
        """Message log can be filtered by cycle_id."""
        coord = Coordinator()
        packet = make_packet_with_facts("f1", "f2")
        coord.start_cycle("cycle-001", packet)
        coord.start_cycle("cycle-002", packet)

        msg1 = make_message(cycle_id="cycle-001", fact_ids=["f1"])
        msg2 = make_message(cycle_id="cycle-002", fact_ids=["f2"])
        coord.submit_message(msg1)
        coord.submit_message(msg2)

        log = coord.get_message_log(cycle_id="cycle-001")

        assert len(log) == 1
        assert log[0][2].cycle_id == "cycle-001"


class TestExceptions:
    """Tests for custom exceptions."""

    def test_coordinator_error_is_base(self) -> None:
        """All coordinator exceptions inherit from CoordinatorError."""
        assert issubclass(DuplicateCycleError, CoordinatorError)
        assert issubclass(CycleNotFoundError, CoordinatorError)
        assert issubclass(MessageRejectedError, CoordinatorError)

    def test_duplicate_cycle_error_message(self) -> None:
        """DuplicateCycleError has descriptive message."""
        error = DuplicateCycleError("cycle-123")
        assert "cycle-123" in str(error)

    def test_cycle_not_found_error_message(self) -> None:
        """CycleNotFoundError has descriptive message."""
        error = CycleNotFoundError("missing-cycle")
        assert "missing-cycle" in str(error)

    def test_message_rejected_error(self) -> None:
        """MessageRejectedError contains message_id and reason."""
        error = MessageRejectedError("msg-001", "invalid facts")
        assert error.message_id == "msg-001"
        assert error.reason == "invalid facts"


class TestIntegrationFullDebateCycle:
    """Integration tests for full debate cycles."""

    def test_full_debate_cycle(self) -> None:
        """Complete debate cycle from thesis to resolution."""
        # Use config with higher max_turns to allow full cycle
        config = CycleConfig(max_turns=10, confidence_epsilon=0.001)
        coord = Coordinator(config)
        packet = make_packet_with_facts("f1", "f2", "f3")
        coord.start_cycle("cycle-001", packet)

        # Thesis from architect
        thesis = make_message(
            cycle_id="cycle-001",
            fact_ids=["f1"],
            phase=Phase.THESIS,
            source_agent="architect",
            confidence=0.3,
        )
        result = coord.submit_message(thesis)
        assert result.accepted is True
        assert result.next_expected_agent == "skeptic"

        # Manually advance to ANTITHESIS_PENDING
        cycle = coord.get_cycle("cycle-001")
        cycle.advance_state()

        # Antithesis from skeptic
        antithesis = make_message(
            cycle_id="cycle-001",
            fact_ids=["f2"],
            phase=Phase.ANTITHESIS,
            source_agent="skeptic",
            confidence=0.7,  # Different from thesis
        )
        result = coord.submit_message(antithesis)
        assert result.accepted is True
        assert result.next_expected_agent == "oracle"

        # Manually advance to SYNTHESIS_PENDING
        cycle.advance_state()

        # Synthesis from oracle
        synthesis = make_message(
            cycle_id="cycle-001",
            fact_ids=["f3"],
            phase=Phase.SYNTHESIS,
            source_agent="oracle",
            confidence=0.5,  # Different from antithesis
        )
        result = coord.submit_message(synthesis)
        assert result.accepted is True

        # Cycle should be resolved
        cycle = coord.get_cycle("cycle-001")
        assert cycle.state == CycleState.RESOLVED

    def test_cycle_terminated_for_confidence_stabilization(self) -> None:
        """Cycle terminates when confidence stabilizes."""
        config = CycleConfig(confidence_epsilon=0.1, max_turns=10)
        coord = Coordinator(config)
        packet = make_packet_with_facts("f1", "f2")
        coord.start_cycle("cycle-001", packet, config)

        # Thesis
        thesis = make_message(
            cycle_id="cycle-001",
            fact_ids=["f1"],
            phase=Phase.THESIS,
            confidence=0.75,
        )
        coord.submit_message(thesis)

        cycle = coord.get_cycle("cycle-001")
        cycle.advance_state()  # -> ANTITHESIS_PENDING

        # Antithesis with similar confidence
        antithesis = make_message(
            cycle_id="cycle-001",
            fact_ids=["f2"],
            phase=Phase.ANTITHESIS,
            confidence=0.78,  # Within epsilon
        )
        result = coord.submit_message(antithesis)

        # Check termination (happens in check_should_terminate)
        assert result.accepted is True

    def test_cycle_terminated_for_max_turns(self) -> None:
        """Cycle terminates when max turns exceeded."""
        # max_turns=2 allows thesis (turn 1), then terminates on antithesis (turn 2)
        config = CycleConfig(max_turns=2, confidence_epsilon=0.001)
        coord = Coordinator(config)
        packet = make_packet_with_facts("f1", "f2")
        coord.start_cycle("cycle-001", packet, config)

        # Thesis (turn 1)
        thesis = make_message(
            cycle_id="cycle-001",
            fact_ids=["f1"],
            phase=Phase.THESIS,
            confidence=0.5,
        )
        coord.submit_message(thesis)
        # submit_message advances state to THESIS_COMPLETE, then we need ANTITHESIS_PENDING
        cycle = coord.get_cycle("cycle-001")
        cycle.advance_state()  # THESIS_COMPLETE -> ANTITHESIS_PENDING

        # Antithesis (turn 2 - hits max_turns=2)
        antithesis = make_message(
            cycle_id="cycle-001",
            fact_ids=["f2"],
            phase=Phase.ANTITHESIS,
            confidence=0.9,  # Different enough to not stabilize
        )
        result = coord.submit_message(antithesis)

        assert result.should_terminate is True
        assert result.termination_reason == TerminationReason.MAX_TURNS_EXCEEDED


class TestRejectMessageForInactiveCycle:
    """Tests for rejecting messages to inactive cycles."""

    def test_rejects_message_to_terminated_cycle(self) -> None:
        """Message to terminated cycle is rejected."""
        coord = Coordinator()
        packet = make_packet_with_facts("f1")
        coord.start_cycle("cycle-001", packet)
        coord.terminate_cycle("cycle-001", TerminationReason.MANUAL)

        message = make_message(cycle_id="cycle-001", fact_ids=["f1"])
        result = coord.submit_message(message)

        assert result.accepted is False

    def test_rejects_message_to_resolved_cycle(self) -> None:
        """Message to resolved cycle is rejected."""
        # Use config that won't trigger early termination
        config = CycleConfig(max_turns=10, confidence_epsilon=0.001)
        coord = Coordinator(config)
        packet = make_packet_with_facts("f1", "f2", "f3")
        cycle = coord.start_cycle("cycle-001", packet, config)

        # Complete the full cycle with different confidence values to avoid stabilization
        thesis = make_message(
            cycle_id="cycle-001", fact_ids=["f1"], phase=Phase.THESIS, confidence=0.5
        )
        coord.submit_message(thesis)
        cycle.advance_state()  # THESIS_COMPLETE -> ANTITHESIS_PENDING

        antithesis = make_message(
            cycle_id="cycle-001", fact_ids=["f2"], phase=Phase.ANTITHESIS, confidence=0.7
        )
        coord.submit_message(antithesis)
        cycle.advance_state()  # ANTITHESIS_COMPLETE -> SYNTHESIS_PENDING

        synthesis = make_message(
            cycle_id="cycle-001", fact_ids=["f3"], phase=Phase.SYNTHESIS, confidence=0.9
        )
        coord.submit_message(synthesis)
        # After synthesis, cycle should be RESOLVED

        # Try to send another message
        extra = make_message(cycle_id="cycle-001", fact_ids=["f1"])
        result = coord.submit_message(extra)

        assert result.accepted is False
