"""Tests for DialecticalCycle class."""

import pytest
from datetime import datetime

from ares.dialectic.coordinator.cycle import (
    CycleState,
    TerminationReason,
    CycleConfig,
    DialecticalCycle,
    InvalidStateError,
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
) -> DialecticalMessage:
    """Create a message for testing."""
    if fact_ids is None:
        fact_ids = ["fact-001"]
    return (
        MessageBuilder("architect", packet_id, cycle_id)
        .set_target("skeptic")
        .set_phase(phase)
        .set_type(MessageType.HYPOTHESIS)
        .add_assertion(make_assertion(fact_ids=fact_ids))
        .set_confidence(confidence)
        .build()
    )


class TestCycleStateEnum:
    """Tests for CycleState enum."""

    def test_all_states_exist(self) -> None:
        """All expected states are defined."""
        expected = {
            "INITIALIZED",
            "THESIS_PENDING",
            "THESIS_COMPLETE",
            "ANTITHESIS_PENDING",
            "ANTITHESIS_COMPLETE",
            "SYNTHESIS_PENDING",
            "RESOLVED",
            "TERMINATED",
        }
        actual = {member.name for member in CycleState}
        assert actual == expected

    def test_state_values(self) -> None:
        """State values are lowercase."""
        assert CycleState.INITIALIZED.value == "initialized"
        assert CycleState.THESIS_PENDING.value == "thesis_pending"
        assert CycleState.RESOLVED.value == "resolved"


class TestTerminationReasonEnum:
    """Tests for TerminationReason enum."""

    def test_all_reasons_exist(self) -> None:
        """All expected termination reasons are defined."""
        expected = {
            "MAX_TURNS_EXCEEDED",
            "NO_NEW_EVIDENCE",
            "CONFIDENCE_STABILIZED",
            "INSUFFICIENT_DATA",
            "VALIDATION_FAILURE",
            "MANUAL",
        }
        actual = {member.name for member in TerminationReason}
        assert actual == expected


class TestCycleConfig:
    """Tests for CycleConfig dataclass."""

    def test_default_values(self) -> None:
        """Default configuration values are set."""
        config = CycleConfig()

        assert config.max_turns == 3
        assert config.confidence_epsilon == 0.05
        assert config.min_evidence_coverage == 0.3
        assert config.allow_empty_unknowns is True
        assert config.require_new_evidence is True

    def test_custom_values(self) -> None:
        """Custom configuration values can be set."""
        config = CycleConfig(
            max_turns=5,
            confidence_epsilon=0.1,
            min_evidence_coverage=0.5,
            allow_empty_unknowns=False,
            require_new_evidence=False,
        )

        assert config.max_turns == 5
        assert config.confidence_epsilon == 0.1
        assert config.min_evidence_coverage == 0.5
        assert config.allow_empty_unknowns is False
        assert config.require_new_evidence is False


class TestDialecticalCycleCreation:
    """Tests for DialecticalCycle creation."""

    def test_creation_with_required_args(self) -> None:
        """Cycle is created with required arguments."""
        packet = make_packet_with_facts("f1")
        cycle = DialecticalCycle("cycle-001", packet)

        assert cycle.cycle_id == "cycle-001"
        assert cycle.packet is packet

    def test_initial_state_is_initialized(self) -> None:
        """New cycle starts in INITIALIZED state."""
        packet = make_packet_with_facts("f1")
        cycle = DialecticalCycle("cycle-001", packet)

        assert cycle.state == CycleState.INITIALIZED

    def test_initial_turn_number_is_zero(self) -> None:
        """New cycle starts at turn 0."""
        packet = make_packet_with_facts("f1")
        cycle = DialecticalCycle("cycle-001", packet)

        assert cycle.turn_number == 0

    def test_initial_messages_empty(self) -> None:
        """New cycle has no messages."""
        packet = make_packet_with_facts("f1")
        cycle = DialecticalCycle("cycle-001", packet)

        assert cycle.messages == []

    def test_initial_referenced_facts_empty(self) -> None:
        """New cycle has no referenced facts."""
        packet = make_packet_with_facts("f1")
        cycle = DialecticalCycle("cycle-001", packet)

        assert cycle.referenced_facts == set()

    def test_initial_is_active(self) -> None:
        """New cycle is active."""
        packet = make_packet_with_facts("f1")
        cycle = DialecticalCycle("cycle-001", packet)

        assert cycle.is_active is True

    def test_initial_no_termination_reason(self) -> None:
        """New cycle has no termination reason."""
        packet = make_packet_with_facts("f1")
        cycle = DialecticalCycle("cycle-001", packet)

        assert cycle.termination_reason is None

    def test_custom_config(self) -> None:
        """Custom config is used when provided."""
        packet = make_packet_with_facts("f1")
        config = CycleConfig(max_turns=10)
        cycle = DialecticalCycle("cycle-001", packet, config)

        assert cycle.config.max_turns == 10


class TestRecordMessage:
    """Tests for record_message method."""

    def test_adds_to_history(self) -> None:
        """record_message adds message to history."""
        packet = make_packet_with_facts("f1")
        cycle = DialecticalCycle("cycle-001", packet)
        cycle.advance_state()  # INITIALIZED -> THESIS_PENDING
        message = make_message(cycle_id="cycle-001", fact_ids=["f1"])

        cycle.record_message(message)

        assert len(cycle.messages) == 1
        assert cycle.messages[0] is message

    def test_updates_referenced_facts(self) -> None:
        """record_message updates referenced_facts."""
        packet = make_packet_with_facts("f1", "f2", "f3")
        cycle = DialecticalCycle("cycle-001", packet)
        cycle.advance_state()  # INITIALIZED -> THESIS_PENDING
        message = make_message(cycle_id="cycle-001", fact_ids=["f1", "f2"])

        cycle.record_message(message)

        assert cycle.referenced_facts == {"f1", "f2"}

    def test_accumulates_referenced_facts(self) -> None:
        """Multiple messages accumulate referenced facts."""
        packet = make_packet_with_facts("f1", "f2", "f3")
        cycle = DialecticalCycle("cycle-001", packet)
        cycle.advance_state()  # THESIS_PENDING

        msg1 = make_message(cycle_id="cycle-001", fact_ids=["f1"])
        cycle.record_message(msg1)
        cycle.advance_state()  # THESIS_COMPLETE
        cycle.advance_state()  # ANTITHESIS_PENDING

        msg2 = make_message(cycle_id="cycle-001", fact_ids=["f2", "f3"], phase=Phase.ANTITHESIS)
        cycle.record_message(msg2)

        assert cycle.referenced_facts == {"f1", "f2", "f3"}

    def test_raises_when_not_active(self) -> None:
        """record_message raises InvalidStateError when cycle not active."""
        packet = make_packet_with_facts("f1")
        cycle = DialecticalCycle("cycle-001", packet)
        cycle.terminate(TerminationReason.MANUAL)
        message = make_message(cycle_id="cycle-001")

        with pytest.raises(InvalidStateError) as exc_info:
            cycle.record_message(message)

        assert exc_info.value.current_state == CycleState.TERMINATED


class TestGetNewFactsInMessage:
    """Tests for get_new_facts_in_message method."""

    def test_all_facts_are_new(self) -> None:
        """Returns all facts when none previously referenced."""
        packet = make_packet_with_facts("f1", "f2")
        cycle = DialecticalCycle("cycle-001", packet)
        message = make_message(cycle_id="cycle-001", fact_ids=["f1", "f2"])

        new_facts = cycle.get_new_facts_in_message(message)

        assert new_facts == {"f1", "f2"}

    def test_some_facts_are_new(self) -> None:
        """Returns only novel facts."""
        packet = make_packet_with_facts("f1", "f2", "f3")
        cycle = DialecticalCycle("cycle-001", packet)
        cycle.advance_state()  # THESIS_PENDING

        # Record first message with f1
        msg1 = make_message(cycle_id="cycle-001", fact_ids=["f1"])
        cycle.record_message(msg1)

        # Check new facts in second message
        msg2 = make_message(cycle_id="cycle-001", fact_ids=["f1", "f2", "f3"])
        new_facts = cycle.get_new_facts_in_message(msg2)

        assert new_facts == {"f2", "f3"}

    def test_no_new_facts(self) -> None:
        """Returns empty set when all facts already referenced."""
        packet = make_packet_with_facts("f1", "f2")
        cycle = DialecticalCycle("cycle-001", packet)
        cycle.advance_state()  # THESIS_PENDING

        msg1 = make_message(cycle_id="cycle-001", fact_ids=["f1", "f2"])
        cycle.record_message(msg1)

        msg2 = make_message(cycle_id="cycle-001", fact_ids=["f1"])
        new_facts = cycle.get_new_facts_in_message(msg2)

        assert new_facts == set()


class TestCheckShouldTerminate:
    """Tests for check_should_terminate method."""

    def test_max_turns_exceeded(self) -> None:
        """Returns termination for exceeding max turns."""
        packet = make_packet_with_facts("f1", "f2", "f3")
        config = CycleConfig(max_turns=2)
        cycle = DialecticalCycle("cycle-001", packet, config)

        # Simulate turns
        cycle._turn_number = 3

        should_term, reason = cycle.check_should_terminate()

        assert should_term is True
        assert reason == TerminationReason.MAX_TURNS_EXCEEDED

    def test_confidence_stabilized(self) -> None:
        """Returns termination when confidence stabilizes."""
        packet = make_packet_with_facts("f1")
        config = CycleConfig(confidence_epsilon=0.1)
        cycle = DialecticalCycle("cycle-001", packet, config)
        cycle.advance_state()  # THESIS_PENDING

        # Record two messages with similar confidence
        msg1 = make_message(cycle_id="cycle-001", confidence=0.75)
        cycle.record_message(msg1)
        cycle.advance_state()  # THESIS_COMPLETE
        cycle.advance_state()  # ANTITHESIS_PENDING

        msg2 = make_message(cycle_id="cycle-001", confidence=0.78, phase=Phase.ANTITHESIS)
        cycle.record_message(msg2)

        should_term, reason = cycle.check_should_terminate()

        assert should_term is True
        assert reason == TerminationReason.CONFIDENCE_STABILIZED

    def test_no_termination_needed(self) -> None:
        """Returns no termination when conditions not met."""
        packet = make_packet_with_facts("f1")
        config = CycleConfig(max_turns=10, confidence_epsilon=0.01)
        cycle = DialecticalCycle("cycle-001", packet, config)

        should_term, reason = cycle.check_should_terminate()

        assert should_term is False
        assert reason is None


class TestTerminate:
    """Tests for terminate method."""

    def test_sets_terminated_state(self) -> None:
        """terminate sets state to TERMINATED."""
        packet = make_packet_with_facts("f1")
        cycle = DialecticalCycle("cycle-001", packet)

        cycle.terminate(TerminationReason.MANUAL)

        assert cycle.state == CycleState.TERMINATED

    def test_sets_termination_reason(self) -> None:
        """terminate sets the termination reason."""
        packet = make_packet_with_facts("f1")
        cycle = DialecticalCycle("cycle-001", packet)

        cycle.terminate(TerminationReason.VALIDATION_FAILURE)

        assert cycle.termination_reason == TerminationReason.VALIDATION_FAILURE

    def test_is_active_false_after_terminate(self) -> None:
        """is_active returns False after termination."""
        packet = make_packet_with_facts("f1")
        cycle = DialecticalCycle("cycle-001", packet)

        cycle.terminate(TerminationReason.MANUAL)

        assert cycle.is_active is False


class TestAdvanceState:
    """Tests for advance_state method."""

    def test_initialized_to_thesis_pending(self) -> None:
        """INITIALIZED advances to THESIS_PENDING."""
        packet = make_packet_with_facts("f1")
        cycle = DialecticalCycle("cycle-001", packet)

        new_state = cycle.advance_state()

        assert new_state == CycleState.THESIS_PENDING
        assert cycle.state == CycleState.THESIS_PENDING

    def test_thesis_pending_to_thesis_complete(self) -> None:
        """THESIS_PENDING advances to THESIS_COMPLETE."""
        packet = make_packet_with_facts("f1")
        cycle = DialecticalCycle("cycle-001", packet)
        cycle._state = CycleState.THESIS_PENDING

        new_state = cycle.advance_state()

        assert new_state == CycleState.THESIS_COMPLETE

    def test_thesis_complete_to_antithesis_pending(self) -> None:
        """THESIS_COMPLETE advances to ANTITHESIS_PENDING."""
        packet = make_packet_with_facts("f1")
        cycle = DialecticalCycle("cycle-001", packet)
        cycle._state = CycleState.THESIS_COMPLETE

        new_state = cycle.advance_state()

        assert new_state == CycleState.ANTITHESIS_PENDING

    def test_antithesis_pending_to_antithesis_complete(self) -> None:
        """ANTITHESIS_PENDING advances to ANTITHESIS_COMPLETE."""
        packet = make_packet_with_facts("f1")
        cycle = DialecticalCycle("cycle-001", packet)
        cycle._state = CycleState.ANTITHESIS_PENDING

        new_state = cycle.advance_state()

        assert new_state == CycleState.ANTITHESIS_COMPLETE

    def test_antithesis_complete_to_synthesis_pending(self) -> None:
        """ANTITHESIS_COMPLETE advances to SYNTHESIS_PENDING."""
        packet = make_packet_with_facts("f1")
        cycle = DialecticalCycle("cycle-001", packet)
        cycle._state = CycleState.ANTITHESIS_COMPLETE

        new_state = cycle.advance_state()

        assert new_state == CycleState.SYNTHESIS_PENDING

    def test_synthesis_pending_to_resolved(self) -> None:
        """SYNTHESIS_PENDING advances to RESOLVED."""
        packet = make_packet_with_facts("f1")
        cycle = DialecticalCycle("cycle-001", packet)
        cycle._state = CycleState.SYNTHESIS_PENDING

        new_state = cycle.advance_state()

        assert new_state == CycleState.RESOLVED

    def test_cannot_advance_from_resolved(self) -> None:
        """Cannot advance from RESOLVED state."""
        packet = make_packet_with_facts("f1")
        cycle = DialecticalCycle("cycle-001", packet)
        cycle._state = CycleState.RESOLVED

        with pytest.raises(InvalidStateError) as exc_info:
            cycle.advance_state()

        assert exc_info.value.current_state == CycleState.RESOLVED

    def test_cannot_advance_from_terminated(self) -> None:
        """Cannot advance from TERMINATED state."""
        packet = make_packet_with_facts("f1")
        cycle = DialecticalCycle("cycle-001", packet)
        cycle._state = CycleState.TERMINATED

        with pytest.raises(InvalidStateError) as exc_info:
            cycle.advance_state()

        assert exc_info.value.current_state == CycleState.TERMINATED


class TestCalculateEvidenceCoverage:
    """Tests for calculate_evidence_coverage method."""

    def test_zero_coverage_initially(self) -> None:
        """New cycle has zero coverage."""
        packet = make_packet_with_facts("f1", "f2", "f3")
        cycle = DialecticalCycle("cycle-001", packet)

        coverage = cycle.calculate_evidence_coverage()

        assert coverage == 0.0

    def test_partial_coverage(self) -> None:
        """Coverage reflects referenced facts."""
        packet = make_packet_with_facts("f1", "f2", "f3", "f4")
        cycle = DialecticalCycle("cycle-001", packet)
        cycle.advance_state()  # THESIS_PENDING

        msg = make_message(cycle_id="cycle-001", fact_ids=["f1", "f2"])
        cycle.record_message(msg)

        coverage = cycle.calculate_evidence_coverage()

        assert coverage == 0.5  # 2 of 4 facts

    def test_full_coverage(self) -> None:
        """100% coverage when all facts referenced."""
        packet = make_packet_with_facts("f1", "f2")
        cycle = DialecticalCycle("cycle-001", packet)
        cycle.advance_state()  # THESIS_PENDING

        msg = make_message(cycle_id="cycle-001", fact_ids=["f1", "f2"])
        cycle.record_message(msg)

        coverage = cycle.calculate_evidence_coverage()

        assert coverage == 1.0

    def test_empty_packet_returns_zero(self) -> None:
        """Empty packet returns zero coverage."""
        packet = EvidencePacket(
            packet_id="empty-packet",
            time_window=TimeWindow(
                start=datetime(2024, 1, 1),
                end=datetime(2024, 1, 31),
            ),
        )
        cycle = DialecticalCycle("cycle-001", packet)

        coverage = cycle.calculate_evidence_coverage()

        assert coverage == 0.0


class TestCycleStateMachine:
    """Integration tests for full cycle state machine."""

    def test_full_cycle_to_resolution(self) -> None:
        """Complete cycle from INITIALIZED to RESOLVED."""
        packet = make_packet_with_facts("f1", "f2", "f3")
        cycle = DialecticalCycle("cycle-001", packet)

        # INITIALIZED -> THESIS_PENDING
        cycle.advance_state()
        assert cycle.state == CycleState.THESIS_PENDING

        # Record thesis
        thesis = make_message(cycle_id="cycle-001", fact_ids=["f1"], phase=Phase.THESIS)
        cycle.record_message(thesis)

        # THESIS_PENDING -> THESIS_COMPLETE
        cycle.advance_state()
        assert cycle.state == CycleState.THESIS_COMPLETE

        # THESIS_COMPLETE -> ANTITHESIS_PENDING
        cycle.advance_state()
        assert cycle.state == CycleState.ANTITHESIS_PENDING

        # Record antithesis
        antithesis = make_message(cycle_id="cycle-001", fact_ids=["f2"], phase=Phase.ANTITHESIS)
        cycle.record_message(antithesis)

        # ANTITHESIS_PENDING -> ANTITHESIS_COMPLETE
        cycle.advance_state()
        assert cycle.state == CycleState.ANTITHESIS_COMPLETE

        # ANTITHESIS_COMPLETE -> SYNTHESIS_PENDING
        cycle.advance_state()
        assert cycle.state == CycleState.SYNTHESIS_PENDING

        # Record synthesis
        synthesis = make_message(cycle_id="cycle-001", fact_ids=["f3"], phase=Phase.SYNTHESIS)
        cycle.record_message(synthesis)

        # SYNTHESIS_PENDING -> RESOLVED
        cycle.advance_state()
        assert cycle.state == CycleState.RESOLVED

        # Verify final state
        assert cycle.is_active is False
        assert len(cycle.messages) == 3
        assert cycle.referenced_facts == {"f1", "f2", "f3"}

    def test_early_termination(self) -> None:
        """Cycle can be terminated early."""
        packet = make_packet_with_facts("f1")
        cycle = DialecticalCycle("cycle-001", packet)

        cycle.advance_state()  # THESIS_PENDING
        cycle.terminate(TerminationReason.INSUFFICIENT_DATA)

        assert cycle.state == CycleState.TERMINATED
        assert cycle.is_active is False
        assert cycle.termination_reason == TerminationReason.INSUFFICIENT_DATA


class TestIsActive:
    """Tests for is_active property."""

    def test_active_in_initialized(self) -> None:
        """Cycle is active in INITIALIZED state."""
        packet = make_packet_with_facts("f1")
        cycle = DialecticalCycle("cycle-001", packet)

        assert cycle.is_active is True

    def test_active_in_thesis_pending(self) -> None:
        """Cycle is active in THESIS_PENDING state."""
        packet = make_packet_with_facts("f1")
        cycle = DialecticalCycle("cycle-001", packet)
        cycle._state = CycleState.THESIS_PENDING

        assert cycle.is_active is True

    def test_not_active_when_resolved(self) -> None:
        """Cycle is not active when RESOLVED."""
        packet = make_packet_with_facts("f1")
        cycle = DialecticalCycle("cycle-001", packet)
        cycle._state = CycleState.RESOLVED

        assert cycle.is_active is False

    def test_not_active_when_terminated(self) -> None:
        """Cycle is not active when TERMINATED."""
        packet = make_packet_with_facts("f1")
        cycle = DialecticalCycle("cycle-001", packet)
        cycle._state = CycleState.TERMINATED

        assert cycle.is_active is False


class TestCycleSerialization:
    """Tests for to_dict and summary methods."""

    def test_to_dict_contains_fields(self) -> None:
        """to_dict returns expected fields."""
        packet = make_packet_with_facts("f1", "f2")
        cycle = DialecticalCycle("cycle-001", packet)

        data = cycle.to_dict()

        assert data["cycle_id"] == "cycle-001"
        assert data["packet_id"] == "test-packet"
        assert data["state"] == "initialized"
        assert data["turn_number"] == 0
        assert data["message_count"] == 0
        assert "config" in data

    def test_summary_is_readable(self) -> None:
        """summary returns human-readable info."""
        packet = make_packet_with_facts("f1", "f2", "f3", "f4")
        cycle = DialecticalCycle("cycle-001", packet)
        cycle.advance_state()  # THESIS_PENDING

        msg = make_message(cycle_id="cycle-001", fact_ids=["f1", "f2"])
        cycle.record_message(msg)

        summary = cycle.summary()

        assert summary["cycle_id"] == "cycle-001"
        assert summary["state"] == "thesis_pending"
        assert summary["messages"] == 1
        assert summary["facts_referenced"] == 2
        assert summary["facts_total"] == 4
        assert "50" in summary["evidence_coverage"]  # 50%


class TestGetPhaseMessages:
    """Tests for get_thesis_message, get_antithesis_messages, get_synthesis_message."""

    def test_get_thesis_message(self) -> None:
        """get_thesis_message returns thesis message."""
        packet = make_packet_with_facts("f1")
        cycle = DialecticalCycle("cycle-001", packet)
        cycle.advance_state()

        thesis = make_message(cycle_id="cycle-001", phase=Phase.THESIS)
        cycle.record_message(thesis)

        result = cycle.get_thesis_message()

        assert result is thesis

    def test_get_thesis_message_none(self) -> None:
        """get_thesis_message returns None if no thesis."""
        packet = make_packet_with_facts("f1")
        cycle = DialecticalCycle("cycle-001", packet)

        result = cycle.get_thesis_message()

        assert result is None

    def test_get_antithesis_messages(self) -> None:
        """get_antithesis_messages returns list of antithesis messages."""
        packet = make_packet_with_facts("f1", "f2")
        cycle = DialecticalCycle("cycle-001", packet)
        cycle._state = CycleState.ANTITHESIS_PENDING

        anti1 = make_message(cycle_id="cycle-001", phase=Phase.ANTITHESIS, fact_ids=["f1"])
        anti2 = make_message(cycle_id="cycle-001", phase=Phase.ANTITHESIS, fact_ids=["f2"])
        cycle.record_message(anti1)
        cycle.record_message(anti2)

        result = cycle.get_antithesis_messages()

        assert len(result) == 2

    def test_get_synthesis_message(self) -> None:
        """get_synthesis_message returns synthesis message."""
        packet = make_packet_with_facts("f1")
        cycle = DialecticalCycle("cycle-001", packet)
        cycle._state = CycleState.SYNTHESIS_PENDING

        synthesis = make_message(cycle_id="cycle-001", phase=Phase.SYNTHESIS)
        cycle.record_message(synthesis)

        result = cycle.get_synthesis_message()

        assert result is synthesis
