"""Tests for agents context module."""

import pytest
from datetime import datetime, timedelta
from typing import FrozenSet

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


# =============================================================================
# Helper Functions
# =============================================================================


def make_turn_context(
    cycle_id: str = "cycle-001",
    packet_id: str = "packet-001",
    snapshot_id: str = "abc123def456",
    phase: Phase = Phase.THESIS,
    turn_number: int = 1,
    max_turns: int = 10,
    prior_messages: tuple = (),
    seen_fact_ids: FrozenSet[str] = frozenset(),
    deadline: datetime = None,
) -> TurnContext:
    """Create a test TurnContext instance."""
    return TurnContext(
        cycle_id=cycle_id,
        packet_id=packet_id,
        snapshot_id=snapshot_id,
        phase=phase,
        turn_number=turn_number,
        max_turns=max_turns,
        prior_messages=prior_messages,
        seen_fact_ids=seen_fact_ids,
        deadline=deadline,
    )


def make_data_request(
    request_id: str = "req-001",
    kind: RequestKind = RequestKind.MISSING_FACT,
    description: str = "Need more data",
    reason: str = "Analysis incomplete",
    priority: RequestPriority = RequestPriority.MEDIUM,
) -> DataRequest:
    """Create a test DataRequest instance."""
    return DataRequest(
        request_id=request_id,
        kind=kind,
        description=description,
        reason=reason,
        priority=priority,
    )


# =============================================================================
# Tests for AgentRole
# =============================================================================


class TestAgentRole:
    """Tests for AgentRole enum."""

    def test_architect_role_exists(self) -> None:
        """ARCHITECT role is defined."""
        assert AgentRole.ARCHITECT is not None

    def test_skeptic_role_exists(self) -> None:
        """SKEPTIC role is defined."""
        assert AgentRole.SKEPTIC is not None

    def test_oracle_role_exists(self) -> None:
        """ORACLE role is defined."""
        assert AgentRole.ORACLE is not None

    def test_role_names(self) -> None:
        """Role names are correct."""
        assert AgentRole.ARCHITECT.name == "ARCHITECT"
        assert AgentRole.SKEPTIC.name == "SKEPTIC"
        assert AgentRole.ORACLE.name == "ORACLE"


# =============================================================================
# Tests for PHASE_ROLE_MAP
# =============================================================================


class TestPhaseRoleMap:
    """Tests for phase-to-role mapping."""

    def test_thesis_maps_to_architect(self) -> None:
        """THESIS phase maps to ARCHITECT role."""
        assert PHASE_ROLE_MAP[Phase.THESIS] == AgentRole.ARCHITECT

    def test_antithesis_maps_to_skeptic(self) -> None:
        """ANTITHESIS phase maps to SKEPTIC role."""
        assert PHASE_ROLE_MAP[Phase.ANTITHESIS] == AgentRole.SKEPTIC

    def test_synthesis_maps_to_oracle(self) -> None:
        """SYNTHESIS phase maps to ORACLE role."""
        assert PHASE_ROLE_MAP[Phase.SYNTHESIS] == AgentRole.ORACLE

    def test_resolution_not_mapped(self) -> None:
        """RESOLUTION phase has no role mapping."""
        assert Phase.RESOLUTION not in PHASE_ROLE_MAP


# =============================================================================
# Tests for RequestKind
# =============================================================================


class TestRequestKind:
    """Tests for RequestKind enum."""

    def test_missing_fact_exists(self) -> None:
        """MISSING_FACT kind is defined."""
        assert RequestKind.MISSING_FACT is not None

    def test_clarification_exists(self) -> None:
        """CLARIFICATION kind is defined."""
        assert RequestKind.CLARIFICATION is not None

    def test_additional_context_exists(self) -> None:
        """ADDITIONAL_CONTEXT kind is defined."""
        assert RequestKind.ADDITIONAL_CONTEXT is not None

    def test_temporal_extension_exists(self) -> None:
        """TEMPORAL_EXTENSION kind is defined."""
        assert RequestKind.TEMPORAL_EXTENSION is not None


# =============================================================================
# Tests for RequestPriority
# =============================================================================


class TestRequestPriority:
    """Tests for RequestPriority enum."""

    def test_all_priorities_exist(self) -> None:
        """All priority levels are defined."""
        assert RequestPriority.LOW is not None
        assert RequestPriority.MEDIUM is not None
        assert RequestPriority.HIGH is not None
        assert RequestPriority.CRITICAL is not None


# =============================================================================
# Tests for DataRequest
# =============================================================================


class TestDataRequestCreation:
    """Tests for DataRequest creation and validation."""

    def test_create_basic_request(self) -> None:
        """DataRequest can be created with required fields."""
        req = DataRequest(
            request_id="req-001",
            kind=RequestKind.MISSING_FACT,
            description="Need IP address data",
            reason="Cannot verify network connection",
        )
        assert req.request_id == "req-001"
        assert req.kind == RequestKind.MISSING_FACT
        assert req.description == "Need IP address data"
        assert req.reason == "Cannot verify network connection"

    def test_default_priority_is_medium(self) -> None:
        """Default priority is MEDIUM."""
        req = make_data_request()
        assert req.priority == RequestPriority.MEDIUM

    def test_empty_request_id_raises(self) -> None:
        """Empty request_id raises ValueError."""
        with pytest.raises(ValueError, match="request_id cannot be empty"):
            DataRequest(
                request_id="",
                kind=RequestKind.MISSING_FACT,
                description="Need data",
                reason="Analysis incomplete",
            )

    def test_empty_description_raises(self) -> None:
        """Empty description raises ValueError."""
        with pytest.raises(ValueError, match="description cannot be empty"):
            DataRequest(
                request_id="req-001",
                kind=RequestKind.MISSING_FACT,
                description="",
                reason="Analysis incomplete",
            )

    def test_empty_reason_raises(self) -> None:
        """Empty reason raises ValueError."""
        with pytest.raises(ValueError, match="reason cannot be empty"):
            DataRequest(
                request_id="req-001",
                kind=RequestKind.MISSING_FACT,
                description="Need data",
                reason="",
            )

    def test_optional_fields_default_none(self) -> None:
        """Optional fields default to None."""
        req = make_data_request()
        assert req.entity_type is None
        assert req.entity_id is None
        assert req.field is None

    def test_optional_fields_can_be_set(self) -> None:
        """Optional fields can be set."""
        req = DataRequest(
            request_id="req-001",
            kind=RequestKind.MISSING_FACT,
            description="Need IP data",
            reason="Cannot verify",
            entity_type="node",
            entity_id="node-001",
            field="ip_address",
        )
        assert req.entity_type == "node"
        assert req.entity_id == "node-001"
        assert req.field == "ip_address"

    def test_suggested_sources_default_empty(self) -> None:
        """Suggested sources defaults to empty tuple."""
        req = make_data_request()
        assert req.suggested_sources == ()

    def test_suggested_sources_can_be_set(self) -> None:
        """Suggested sources can be provided."""
        req = DataRequest(
            request_id="req-001",
            kind=RequestKind.MISSING_FACT,
            description="Need data",
            reason="Analysis incomplete",
            suggested_sources=("dns_logs", "firewall_logs"),
        )
        assert req.suggested_sources == ("dns_logs", "firewall_logs")


class TestDataRequestIsBlocking:
    """Tests for DataRequest.is_blocking property."""

    def test_low_priority_not_blocking(self) -> None:
        """LOW priority is not blocking."""
        req = make_data_request(priority=RequestPriority.LOW)
        assert req.is_blocking is False

    def test_medium_priority_not_blocking(self) -> None:
        """MEDIUM priority is not blocking."""
        req = make_data_request(priority=RequestPriority.MEDIUM)
        assert req.is_blocking is False

    def test_high_priority_is_blocking(self) -> None:
        """HIGH priority is blocking."""
        req = make_data_request(priority=RequestPriority.HIGH)
        assert req.is_blocking is True

    def test_critical_priority_is_blocking(self) -> None:
        """CRITICAL priority is blocking."""
        req = make_data_request(priority=RequestPriority.CRITICAL)
        assert req.is_blocking is True


class TestDataRequestImmutability:
    """Tests for DataRequest immutability (frozen dataclass)."""

    def test_request_is_frozen(self) -> None:
        """DataRequest attributes cannot be changed."""
        req = make_data_request()
        with pytest.raises(AttributeError):
            req.request_id = "new-id"


# =============================================================================
# Tests for TurnContext Creation
# =============================================================================


class TestTurnContextCreation:
    """Tests for TurnContext creation and validation."""

    def test_create_basic_context(self) -> None:
        """TurnContext can be created with required fields."""
        ctx = make_turn_context()
        assert ctx.cycle_id == "cycle-001"
        assert ctx.packet_id == "packet-001"
        assert ctx.snapshot_id == "abc123def456"
        assert ctx.phase == Phase.THESIS
        assert ctx.turn_number == 1
        assert ctx.max_turns == 10

    def test_turn_number_zero_raises(self) -> None:
        """turn_number must be >= 1."""
        with pytest.raises(ValueError, match="turn_number must be >= 1"):
            make_turn_context(turn_number=0)

    def test_turn_number_negative_raises(self) -> None:
        """Negative turn_number raises ValueError."""
        with pytest.raises(ValueError, match="turn_number must be >= 1"):
            make_turn_context(turn_number=-1)

    def test_max_turns_zero_raises(self) -> None:
        """max_turns must be >= 1."""
        with pytest.raises(ValueError, match="max_turns must be >= 1"):
            make_turn_context(max_turns=0)

    def test_turn_exceeds_max_raises(self) -> None:
        """turn_number cannot exceed max_turns."""
        with pytest.raises(ValueError, match="turn_number.*cannot exceed max_turns"):
            make_turn_context(turn_number=5, max_turns=3)

    def test_empty_snapshot_id_raises(self) -> None:
        """Empty snapshot_id raises ValueError."""
        with pytest.raises(ValueError, match="snapshot_id cannot be empty"):
            make_turn_context(snapshot_id="")

    def test_empty_packet_id_raises(self) -> None:
        """Empty packet_id raises ValueError."""
        with pytest.raises(ValueError, match="packet_id cannot be empty"):
            make_turn_context(packet_id="")

    def test_empty_cycle_id_raises(self) -> None:
        """Empty cycle_id raises ValueError."""
        with pytest.raises(ValueError, match="cycle_id cannot be empty"):
            make_turn_context(cycle_id="")

    def test_default_prior_messages_empty(self) -> None:
        """Default prior_messages is empty tuple."""
        ctx = make_turn_context()
        assert ctx.prior_messages == ()

    def test_default_seen_fact_ids_empty(self) -> None:
        """Default seen_fact_ids is empty frozenset."""
        ctx = make_turn_context()
        assert ctx.seen_fact_ids == frozenset()

    def test_default_deadline_none(self) -> None:
        """Default deadline is None."""
        ctx = make_turn_context()
        assert ctx.deadline is None


# =============================================================================
# Tests for TurnContext Properties
# =============================================================================


class TestTurnContextExpectedRole:
    """Tests for TurnContext.expected_role property."""

    def test_thesis_expects_architect(self) -> None:
        """THESIS phase expects ARCHITECT role."""
        ctx = make_turn_context(phase=Phase.THESIS)
        assert ctx.expected_role == AgentRole.ARCHITECT

    def test_antithesis_expects_skeptic(self) -> None:
        """ANTITHESIS phase expects SKEPTIC role."""
        ctx = make_turn_context(phase=Phase.ANTITHESIS)
        assert ctx.expected_role == AgentRole.SKEPTIC

    def test_synthesis_expects_oracle(self) -> None:
        """SYNTHESIS phase expects ORACLE role."""
        ctx = make_turn_context(phase=Phase.SYNTHESIS)
        assert ctx.expected_role == AgentRole.ORACLE

    def test_resolution_raises_key_error(self) -> None:
        """RESOLUTION phase raises KeyError (no mapped role)."""
        ctx = make_turn_context(phase=Phase.RESOLUTION)
        with pytest.raises(KeyError, match="No agent role mapped"):
            _ = ctx.expected_role


class TestTurnContextTurnProperties:
    """Tests for TurnContext turn-related properties."""

    def test_is_first_turn_true_when_turn_1(self) -> None:
        """is_first_turn is True when turn_number is 1."""
        ctx = make_turn_context(turn_number=1)
        assert ctx.is_first_turn is True

    def test_is_first_turn_false_when_not_1(self) -> None:
        """is_first_turn is False when turn_number > 1."""
        ctx = make_turn_context(turn_number=2)
        assert ctx.is_first_turn is False

    def test_is_final_turn_true_when_at_max(self) -> None:
        """is_final_turn is True when at max_turns."""
        ctx = make_turn_context(turn_number=10, max_turns=10)
        assert ctx.is_final_turn is True

    def test_is_final_turn_false_when_not_at_max(self) -> None:
        """is_final_turn is False when before max_turns."""
        ctx = make_turn_context(turn_number=5, max_turns=10)
        assert ctx.is_final_turn is False

    def test_turns_remaining_calculation(self) -> None:
        """turns_remaining is correctly calculated."""
        ctx = make_turn_context(turn_number=3, max_turns=10)
        assert ctx.turns_remaining == 7

    def test_turns_remaining_zero_at_final(self) -> None:
        """turns_remaining is 0 at final turn."""
        ctx = make_turn_context(turn_number=10, max_turns=10)
        assert ctx.turns_remaining == 0


class TestTurnContextDeadline:
    """Tests for TurnContext deadline handling."""

    def test_is_past_deadline_false_when_none(self) -> None:
        """is_past_deadline is False when deadline is None."""
        ctx = make_turn_context(deadline=None)
        assert ctx.is_past_deadline is False

    def test_is_past_deadline_false_when_future(self) -> None:
        """is_past_deadline is False when deadline is in future."""
        future = datetime.utcnow() + timedelta(hours=1)
        ctx = make_turn_context(deadline=future)
        assert ctx.is_past_deadline is False

    def test_is_past_deadline_true_when_past(self) -> None:
        """is_past_deadline is True when deadline has passed."""
        past = datetime.utcnow() - timedelta(hours=1)
        ctx = make_turn_context(deadline=past)
        assert ctx.is_past_deadline is True


# =============================================================================
# Tests for TurnContext Methods
# =============================================================================


class TestTurnContextWithNewSeenFacts:
    """Tests for TurnContext.with_new_seen_facts method."""

    def test_adds_new_fact_ids(self) -> None:
        """New fact IDs are added to seen_fact_ids."""
        ctx = make_turn_context(seen_fact_ids=frozenset({"fact-1", "fact-2"}))
        new_ctx = ctx.with_new_seen_facts(frozenset({"fact-3", "fact-4"}))
        assert new_ctx.seen_fact_ids == frozenset({"fact-1", "fact-2", "fact-3", "fact-4"})

    def test_preserves_existing_fact_ids(self) -> None:
        """Existing fact IDs are preserved."""
        ctx = make_turn_context(seen_fact_ids=frozenset({"fact-1"}))
        new_ctx = ctx.with_new_seen_facts(frozenset({"fact-1", "fact-2"}))
        assert "fact-1" in new_ctx.seen_fact_ids
        assert "fact-2" in new_ctx.seen_fact_ids

    def test_preserves_other_fields(self) -> None:
        """Other fields are preserved."""
        ctx = make_turn_context(
            cycle_id="cycle-test",
            packet_id="packet-test",
            turn_number=5,
        )
        new_ctx = ctx.with_new_seen_facts(frozenset({"new-fact"}))
        assert new_ctx.cycle_id == "cycle-test"
        assert new_ctx.packet_id == "packet-test"
        assert new_ctx.turn_number == 5

    def test_original_unchanged(self) -> None:
        """Original context is unchanged (immutability)."""
        ctx = make_turn_context(seen_fact_ids=frozenset({"fact-1"}))
        _ = ctx.with_new_seen_facts(frozenset({"fact-2"}))
        assert ctx.seen_fact_ids == frozenset({"fact-1"})


class TestTurnContextAdvanceTurn:
    """Tests for TurnContext.advance_turn method."""

    def test_increments_turn_number(self) -> None:
        """Turn number is incremented by 1."""
        ctx = make_turn_context(turn_number=1, max_turns=10)
        new_ctx = ctx.advance_turn(Phase.ANTITHESIS, "mock_message", frozenset())
        assert new_ctx.turn_number == 2

    def test_updates_phase(self) -> None:
        """Phase is updated to new phase."""
        ctx = make_turn_context(phase=Phase.THESIS)
        new_ctx = ctx.advance_turn(Phase.ANTITHESIS, "mock_message", frozenset())
        assert new_ctx.phase == Phase.ANTITHESIS

    def test_appends_message_to_prior(self) -> None:
        """New message is appended to prior_messages."""
        ctx = make_turn_context(prior_messages=("msg1",))
        new_ctx = ctx.advance_turn(Phase.ANTITHESIS, "msg2", frozenset())
        assert new_ctx.prior_messages == ("msg1", "msg2")

    def test_merges_fact_ids(self) -> None:
        """New fact IDs are merged into seen_fact_ids."""
        ctx = make_turn_context(seen_fact_ids=frozenset({"fact-1"}))
        new_ctx = ctx.advance_turn(Phase.ANTITHESIS, "msg", frozenset({"fact-2"}))
        assert new_ctx.seen_fact_ids == frozenset({"fact-1", "fact-2"})

    def test_preserves_packet_binding(self) -> None:
        """Packet ID and snapshot ID are preserved."""
        ctx = make_turn_context(packet_id="p-123", snapshot_id="snap-456")
        new_ctx = ctx.advance_turn(Phase.ANTITHESIS, "msg", frozenset())
        assert new_ctx.packet_id == "p-123"
        assert new_ctx.snapshot_id == "snap-456"

    def test_preserves_deadline(self) -> None:
        """Deadline is preserved."""
        deadline = datetime.utcnow() + timedelta(hours=1)
        ctx = make_turn_context(deadline=deadline)
        new_ctx = ctx.advance_turn(Phase.ANTITHESIS, "msg", frozenset())
        assert new_ctx.deadline == deadline


class TestTurnContextImmutability:
    """Tests for TurnContext immutability (frozen dataclass)."""

    def test_context_is_frozen(self) -> None:
        """TurnContext attributes cannot be changed."""
        ctx = make_turn_context()
        with pytest.raises(AttributeError):
            ctx.turn_number = 5


# =============================================================================
# Tests for TurnResult
# =============================================================================


class TestTurnResultCreation:
    """Tests for TurnResult creation."""

    def test_create_with_message(self) -> None:
        """TurnResult can be created with a message."""
        ctx = make_turn_context()
        result = TurnResult(context=ctx, message="test_message")
        assert result.message == "test_message"

    def test_create_with_requests(self) -> None:
        """TurnResult can be created with data requests."""
        ctx = make_turn_context()
        req = make_data_request()
        result = TurnResult(context=ctx, requests=(req,))
        assert len(result.requests) == 1

    def test_create_with_error(self) -> None:
        """TurnResult can be created with an error."""
        ctx = make_turn_context()
        result = TurnResult(context=ctx, error="Something went wrong")
        assert result.error == "Something went wrong"

    def test_default_message_none(self) -> None:
        """Default message is None."""
        ctx = make_turn_context()
        result = TurnResult(context=ctx)
        assert result.message is None

    def test_default_requests_empty(self) -> None:
        """Default requests is empty tuple."""
        ctx = make_turn_context()
        result = TurnResult(context=ctx)
        assert result.requests == ()


class TestTurnResultProperties:
    """Tests for TurnResult properties."""

    def test_has_output_true_with_message(self) -> None:
        """has_output is True when message is present."""
        ctx = make_turn_context()
        result = TurnResult(context=ctx, message="test")
        assert result.has_output is True

    def test_has_output_true_with_requests(self) -> None:
        """has_output is True when requests are present."""
        ctx = make_turn_context()
        req = make_data_request()
        result = TurnResult(context=ctx, requests=(req,))
        assert result.has_output is True

    def test_has_output_false_when_empty(self) -> None:
        """has_output is False when no message or requests."""
        ctx = make_turn_context()
        result = TurnResult(context=ctx)
        assert result.has_output is False

    def test_has_error_true_with_error(self) -> None:
        """has_error is True when error is present."""
        ctx = make_turn_context()
        result = TurnResult(context=ctx, error="Error!")
        assert result.has_error is True

    def test_has_error_false_without_error(self) -> None:
        """has_error is False when no error."""
        ctx = make_turn_context()
        result = TurnResult(context=ctx)
        assert result.has_error is False

    def test_is_data_request_true(self) -> None:
        """is_data_request is True when only requests present."""
        ctx = make_turn_context()
        req = make_data_request()
        result = TurnResult(context=ctx, requests=(req,))
        assert result.is_data_request is True

    def test_is_data_request_false_with_message(self) -> None:
        """is_data_request is False when message is present."""
        ctx = make_turn_context()
        req = make_data_request()
        result = TurnResult(context=ctx, message="msg", requests=(req,))
        assert result.is_data_request is False

    def test_is_data_request_false_when_empty(self) -> None:
        """is_data_request is False when no requests."""
        ctx = make_turn_context()
        result = TurnResult(context=ctx)
        assert result.is_data_request is False


class TestTurnResultImmutability:
    """Tests for TurnResult immutability (frozen dataclass)."""

    def test_result_is_frozen(self) -> None:
        """TurnResult attributes cannot be changed."""
        ctx = make_turn_context()
        result = TurnResult(context=ctx)
        with pytest.raises(AttributeError):
            result.message = "new"
