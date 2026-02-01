"""Tests for agents base module."""

import pytest
from datetime import datetime, timedelta
from typing import FrozenSet, Optional

from ares.dialectic.agents.base import (
    AgentBase,
    AgentHealth,
    AgentNotReadyError,
    AgentState,
    PacketMismatchError,
    PhaseViolationError,
    SelfValidationResult,
    SnapshotMismatchError,
    WorkingMemoryEntry,
)
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
from ares.dialectic.evidence.packet import EvidencePacket, TimeWindow
from ares.dialectic.evidence.fact import Fact, EntityType
from ares.dialectic.evidence.provenance import Provenance, SourceType
from ares.dialectic.messages.assertions import Assertion, AssertionType


# =============================================================================
# Concrete Agent Implementations for Testing
# =============================================================================


class MockArchitect(AgentBase):
    """Concrete Architect agent for testing."""

    def __init__(
        self,
        agent_id: Optional[str] = None,
        max_memory_size: int = 100,
        compose_result: Optional[tuple] = None,
    ) -> None:
        # Store compose_result before super().__init__ since it accesses self.role
        self._compose_result = compose_result or (None, ())
        super().__init__(agent_id=agent_id, max_memory_size=max_memory_size)

    @property
    def role(self) -> AgentRole:
        return AgentRole.ARCHITECT

    def _compose_impl(
        self,
        context: TurnContext,
    ) -> tuple[Optional[object], DataRequests]:
        return self._compose_result

    def set_compose_result(self, message: object, requests: DataRequests = ()) -> None:
        """Set what _compose_impl should return."""
        self._compose_result = (message, requests)


class MockSkeptic(AgentBase):
    """Concrete Skeptic agent for testing."""

    def __init__(
        self,
        agent_id: Optional[str] = None,
        max_memory_size: int = 100,
        compose_result: Optional[tuple] = None,
    ) -> None:
        self._compose_result = compose_result or (None, ())
        super().__init__(agent_id=agent_id, max_memory_size=max_memory_size)

    @property
    def role(self) -> AgentRole:
        return AgentRole.SKEPTIC

    def _compose_impl(
        self,
        context: TurnContext,
    ) -> tuple[Optional[object], DataRequests]:
        return self._compose_result


class MockOracle(AgentBase):
    """Concrete Oracle agent for testing."""

    def __init__(
        self,
        agent_id: Optional[str] = None,
        max_memory_size: int = 100,
        compose_result: Optional[tuple] = None,
    ) -> None:
        self._compose_result = compose_result or (None, ())
        super().__init__(agent_id=agent_id, max_memory_size=max_memory_size)

    @property
    def role(self) -> AgentRole:
        return AgentRole.ORACLE

    def _compose_impl(
        self,
        context: TurnContext,
    ) -> tuple[Optional[object], DataRequests]:
        return self._compose_result


# =============================================================================
# Mock Message for Testing
# =============================================================================


class MockMessage:
    """Mock message with assertions and fact_ids."""

    def __init__(
        self,
        packet_id: str = "packet-001",
        assertions: list = None,
    ) -> None:
        self.packet_id = packet_id
        self.assertions = assertions or []

    def get_all_fact_ids(self) -> set[str]:
        """Collect all fact IDs from assertions."""
        fact_ids = set()
        for assertion in self.assertions:
            if hasattr(assertion, "fact_ids"):
                fact_ids.update(assertion.fact_ids)
        return fact_ids


class MockAssertion:
    """Mock assertion with fact_ids."""

    def __init__(self, fact_ids: tuple[str, ...] = ()) -> None:
        self.fact_ids = fact_ids


# =============================================================================
# Helper Functions
# =============================================================================


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
    timestamp: datetime = None,
) -> Fact:
    """Create a test fact instance."""
    if timestamp is None:
        timestamp = datetime(2024, 1, 15, 12, 0, 0)
    return Fact(
        fact_id=fact_id,
        entity_id=entity_id,
        entity_type=EntityType.NODE,
        field=field,
        value=value,
        timestamp=timestamp,
        provenance=make_provenance(),
    )


def make_time_window() -> TimeWindow:
    """Create a test time window."""
    return TimeWindow(
        start=datetime(2024, 1, 1, 0, 0, 0),
        end=datetime(2024, 1, 31, 23, 59, 59),
    )


def make_packet(packet_id: str = "packet-001", frozen: bool = True) -> EvidencePacket:
    """Create a test evidence packet."""
    packet = EvidencePacket(packet_id=packet_id, time_window=make_time_window())
    packet.add_fact(make_fact("fact-001"))
    packet.add_fact(make_fact("fact-002", entity_id="node-002"))
    packet.add_fact(make_fact("fact-003", entity_id="node-003"))
    if frozen:
        packet.freeze()
    return packet


def make_turn_context(
    cycle_id: str = "cycle-001",
    packet_id: str = "packet-001",
    snapshot_id: str = "abc123def456",
    phase: Phase = Phase.THESIS,
    turn_number: int = 1,
    max_turns: int = 10,
    prior_messages: tuple = (),
    seen_fact_ids: FrozenSet[str] = frozenset(),
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
    )


# =============================================================================
# Tests for AgentState
# =============================================================================


class TestAgentState:
    """Tests for AgentState enum."""

    def test_all_states_exist(self) -> None:
        """All expected states are defined."""
        assert AgentState.IDLE is not None
        assert AgentState.OBSERVING is not None
        assert AgentState.READY is not None
        assert AgentState.ACTING is not None
        assert AgentState.CONSOLIDATING is not None
        assert AgentState.ERROR is not None


# =============================================================================
# Tests for AgentHealth
# =============================================================================


class TestAgentHealth:
    """Tests for AgentHealth dataclass."""

    def test_should_consolidate_above_threshold(self) -> None:
        """should_consolidate is True when pressure > 0.8."""
        health = AgentHealth(
            context_pressure=0.85,
            facts_seen=10,
            facts_cited=5,
            messages_produced=3,
            validation_failures=0,
            last_active=datetime.utcnow(),
        )
        assert health.should_consolidate is True

    def test_should_consolidate_below_threshold(self) -> None:
        """should_consolidate is False when pressure <= 0.8."""
        health = AgentHealth(
            context_pressure=0.5,
            facts_seen=10,
            facts_cited=5,
            messages_produced=3,
            validation_failures=0,
            last_active=datetime.utcnow(),
        )
        assert health.should_consolidate is False

    def test_citation_rate_calculation(self) -> None:
        """citation_rate is facts_cited / facts_seen."""
        health = AgentHealth(
            context_pressure=0.5,
            facts_seen=10,
            facts_cited=5,
            messages_produced=3,
            validation_failures=0,
            last_active=datetime.utcnow(),
        )
        assert health.citation_rate == 0.5

    def test_citation_rate_zero_when_no_facts_seen(self) -> None:
        """citation_rate is 0 when facts_seen is 0."""
        health = AgentHealth(
            context_pressure=0.0,
            facts_seen=0,
            facts_cited=0,
            messages_produced=0,
            validation_failures=0,
            last_active=datetime.utcnow(),
        )
        assert health.citation_rate == 0.0


# =============================================================================
# Tests for SelfValidationResult
# =============================================================================


class TestSelfValidationResult:
    """Tests for SelfValidationResult dataclass."""

    def test_success_factory(self) -> None:
        """success() creates a valid result."""
        result = SelfValidationResult.success()
        assert result.is_valid is True
        assert result.errors == ()

    def test_failure_factory(self) -> None:
        """failure() creates an invalid result with errors."""
        result = SelfValidationResult.failure("Error 1", "Error 2")
        assert result.is_valid is False
        assert result.errors == ("Error 1", "Error 2")


# =============================================================================
# Tests for WorkingMemoryEntry
# =============================================================================


class TestWorkingMemoryEntry:
    """Tests for WorkingMemoryEntry dataclass."""

    def test_default_relevance_score(self) -> None:
        """Default relevance_score is 1.0."""
        entry = WorkingMemoryEntry(content="test", timestamp=datetime.utcnow())
        assert entry.relevance_score == 1.0

    def test_decay_reduces_relevance(self) -> None:
        """decay() reduces relevance_score."""
        entry = WorkingMemoryEntry(content="test", timestamp=datetime.utcnow())
        entry.decay(factor=0.9)
        assert entry.relevance_score == 0.9

    def test_decay_accumulates(self) -> None:
        """Multiple decay() calls accumulate."""
        entry = WorkingMemoryEntry(content="test", timestamp=datetime.utcnow())
        entry.decay(factor=0.9)
        entry.decay(factor=0.9)
        assert abs(entry.relevance_score - 0.81) < 0.001


# =============================================================================
# Tests for Exceptions
# =============================================================================


class TestPacketMismatchError:
    """Tests for PacketMismatchError."""

    def test_error_message(self) -> None:
        """Error message contains packet IDs."""
        err = PacketMismatchError("packet-a", "packet-b")
        assert "packet-a" in str(err)
        assert "packet-b" in str(err)

    def test_error_attributes(self) -> None:
        """Error has expected and actual packet IDs."""
        err = PacketMismatchError("packet-a", "packet-b")
        assert err.expected_packet_id == "packet-a"
        assert err.actual_packet_id == "packet-b"


class TestSnapshotMismatchError:
    """Tests for SnapshotMismatchError."""

    def test_error_message(self) -> None:
        """Error message contains snapshot IDs."""
        err = SnapshotMismatchError("snap-a", "snap-b")
        assert "snap-a" in str(err)
        assert "snap-b" in str(err)


class TestPhaseViolationError:
    """Tests for PhaseViolationError."""

    def test_error_message(self) -> None:
        """Error message contains role and phase."""
        err = PhaseViolationError(AgentRole.ARCHITECT, Phase.ANTITHESIS)
        assert "ARCHITECT" in str(err)
        assert "ANTITHESIS" in str(err)

    def test_error_attributes(self) -> None:
        """Error has role and phase."""
        err = PhaseViolationError(AgentRole.ARCHITECT, Phase.ANTITHESIS)
        assert err.agent_role == AgentRole.ARCHITECT
        assert err.current_phase == Phase.ANTITHESIS


class TestAgentNotReadyError:
    """Tests for AgentNotReadyError."""

    def test_error_message(self) -> None:
        """Error message contains agent ID and state."""
        err = AgentNotReadyError("agent-001", AgentState.IDLE)
        assert "agent-001" in str(err)
        assert "IDLE" in str(err)


# =============================================================================
# Critical Test Group 1: Packet Binding
# =============================================================================


class TestPacketBinding:
    """Critical tests for packet binding - Context bleed is a schema violation."""

    def test_observe_binds_packet(self) -> None:
        """observe() binds agent to packet."""
        agent = MockArchitect()
        packet = make_packet()
        agent.observe(packet)
        assert agent.active_packet_id == packet.packet_id
        assert agent.active_snapshot_id == packet.snapshot_id

    def test_observe_tracks_fact_ids(self) -> None:
        """observe() adds all packet fact_ids to seen_fact_ids."""
        agent = MockArchitect()
        packet = make_packet()
        agent.observe(packet)
        assert packet.fact_ids == agent.seen_fact_ids

    def test_observe_sets_ready_state(self) -> None:
        """observe() transitions agent to READY state."""
        agent = MockArchitect()
        packet = make_packet()
        agent.observe(packet)
        assert agent.state == AgentState.READY
        assert agent.is_ready is True

    def test_packet_switch_clears_memory(self) -> None:
        """Switching packets clears working memory."""
        agent = MockArchitect()
        packet1 = make_packet("packet-001")
        packet2 = make_packet("packet-002")

        agent.observe(packet1)
        # Simulate adding to memory
        agent._working_memory.append(
            WorkingMemoryEntry(content="test", timestamp=datetime.utcnow())
        )

        agent.observe(packet2)
        assert agent.working_memory_size == 0

    def test_packet_switch_clears_seen_facts(self) -> None:
        """Switching packets clears seen_fact_ids."""
        agent = MockArchitect()
        packet1 = make_packet("packet-001")
        packet2 = make_packet("packet-002")

        agent.observe(packet1)
        old_facts = agent.seen_fact_ids

        agent.observe(packet2)
        # seen_fact_ids should now be only from packet2
        assert agent.seen_fact_ids == packet2.fact_ids

    def test_packet_switch_clears_cited_facts(self) -> None:
        """Switching packets clears cited_fact_ids."""
        agent = MockArchitect()
        packet1 = make_packet("packet-001")
        packet2 = make_packet("packet-002")

        agent.observe(packet1)
        agent._cited_fact_ids.add("fact-001")

        agent.observe(packet2)
        assert len(agent.cited_fact_ids) == 0

    def test_act_rejects_mismatched_packet_id(self) -> None:
        """act() raises PacketMismatchError for wrong packet_id."""
        agent = MockArchitect()
        packet = make_packet("packet-001")
        agent.observe(packet)

        context = make_turn_context(
            packet_id="packet-002",  # WRONG!
            snapshot_id=packet.snapshot_id,
        )

        with pytest.raises(PacketMismatchError) as exc_info:
            agent.act(context)
        assert exc_info.value.expected_packet_id == "packet-001"
        assert exc_info.value.actual_packet_id == "packet-002"

    def test_act_rejects_mismatched_snapshot_id(self) -> None:
        """act() raises SnapshotMismatchError for wrong snapshot_id."""
        agent = MockArchitect()
        packet = make_packet("packet-001")
        agent.observe(packet)

        context = make_turn_context(
            packet_id="packet-001",
            snapshot_id="wrong-snapshot",  # WRONG!
        )

        with pytest.raises(SnapshotMismatchError):
            agent.act(context)

    def test_same_packet_observation_no_clear(self) -> None:
        """Re-observing same packet does not clear memory."""
        agent = MockArchitect()
        packet = make_packet("packet-001")

        agent.observe(packet)
        agent._working_memory.append(
            WorkingMemoryEntry(content="test", timestamp=datetime.utcnow())
        )
        original_size = agent.working_memory_size

        agent.observe(packet)  # Same packet
        assert agent.working_memory_size == original_size


# =============================================================================
# Critical Test Group 2: Phase Enforcement
# =============================================================================


class TestPhaseEnforcement:
    """Critical tests for phase enforcement - Role boundaries as law."""

    def test_architect_can_act_in_thesis(self) -> None:
        """Architect can act in THESIS phase."""
        agent = MockArchitect()
        packet = make_packet()
        agent.observe(packet)

        context = make_turn_context(
            packet_id=packet.packet_id,
            snapshot_id=packet.snapshot_id,
            phase=Phase.THESIS,
        )

        result = agent.act(context)
        assert result.has_error is False

    def test_architect_cannot_act_in_antithesis(self) -> None:
        """Architect raises PhaseViolationError in ANTITHESIS phase."""
        agent = MockArchitect()
        packet = make_packet()
        agent.observe(packet)

        context = make_turn_context(
            packet_id=packet.packet_id,
            snapshot_id=packet.snapshot_id,
            phase=Phase.ANTITHESIS,
        )

        with pytest.raises(PhaseViolationError) as exc_info:
            agent.act(context)
        assert exc_info.value.agent_role == AgentRole.ARCHITECT
        assert exc_info.value.current_phase == Phase.ANTITHESIS

    def test_architect_cannot_act_in_synthesis(self) -> None:
        """Architect raises PhaseViolationError in SYNTHESIS phase."""
        agent = MockArchitect()
        packet = make_packet()
        agent.observe(packet)

        context = make_turn_context(
            packet_id=packet.packet_id,
            snapshot_id=packet.snapshot_id,
            phase=Phase.SYNTHESIS,
        )

        with pytest.raises(PhaseViolationError):
            agent.act(context)

    def test_skeptic_can_act_in_antithesis(self) -> None:
        """Skeptic can act in ANTITHESIS phase."""
        agent = MockSkeptic()
        packet = make_packet()
        agent.observe(packet)

        context = make_turn_context(
            packet_id=packet.packet_id,
            snapshot_id=packet.snapshot_id,
            phase=Phase.ANTITHESIS,
        )

        result = agent.act(context)
        assert result.has_error is False

    def test_skeptic_cannot_act_in_thesis(self) -> None:
        """Skeptic raises PhaseViolationError in THESIS phase."""
        agent = MockSkeptic()
        packet = make_packet()
        agent.observe(packet)

        context = make_turn_context(
            packet_id=packet.packet_id,
            snapshot_id=packet.snapshot_id,
            phase=Phase.THESIS,
        )

        with pytest.raises(PhaseViolationError) as exc_info:
            agent.act(context)
        assert exc_info.value.agent_role == AgentRole.SKEPTIC

    def test_oracle_can_act_in_synthesis(self) -> None:
        """Oracle can act in SYNTHESIS phase."""
        agent = MockOracle()
        packet = make_packet()
        agent.observe(packet)

        context = make_turn_context(
            packet_id=packet.packet_id,
            snapshot_id=packet.snapshot_id,
            phase=Phase.SYNTHESIS,
        )

        result = agent.act(context)
        assert result.has_error is False

    def test_oracle_cannot_act_in_thesis(self) -> None:
        """Oracle raises PhaseViolationError in THESIS phase."""
        agent = MockOracle()
        packet = make_packet()
        agent.observe(packet)

        context = make_turn_context(
            packet_id=packet.packet_id,
            snapshot_id=packet.snapshot_id,
            phase=Phase.THESIS,
        )

        with pytest.raises(PhaseViolationError):
            agent.act(context)


# =============================================================================
# Critical Test Group 3: Evidence Tracking
# =============================================================================


class TestEvidenceTracking:
    """Critical tests for evidence tracking - New evidence rule compliance."""

    def test_cited_fact_ids_tracked(self) -> None:
        """cited_fact_ids updated when message contains facts."""
        agent = MockArchitect()
        packet = make_packet()
        agent.observe(packet)

        # Create message with assertions referencing facts
        msg = MockMessage(
            packet_id=packet.packet_id,
            assertions=[MockAssertion(fact_ids=("fact-001", "fact-002"))],
        )
        agent.set_compose_result(msg)

        context = make_turn_context(
            packet_id=packet.packet_id,
            snapshot_id=packet.snapshot_id,
        )

        agent.act(context)
        assert "fact-001" in agent.cited_fact_ids
        assert "fact-002" in agent.cited_fact_ids

    def test_last_turn_fact_ids_updated(self) -> None:
        """last_turn_fact_ids reflects only current turn's facts."""
        agent = MockArchitect()
        packet = make_packet()
        agent.observe(packet)

        # First turn with fact-001
        msg1 = MockMessage(
            packet_id=packet.packet_id,
            assertions=[MockAssertion(fact_ids=("fact-001",))],
        )
        agent.set_compose_result(msg1)

        context1 = make_turn_context(
            packet_id=packet.packet_id,
            snapshot_id=packet.snapshot_id,
            turn_number=1,
        )
        agent.act(context1)
        assert "fact-001" in agent.last_turn_fact_ids

        # Second turn with fact-002
        msg2 = MockMessage(
            packet_id=packet.packet_id,
            assertions=[MockAssertion(fact_ids=("fact-002",))],
        )
        agent.set_compose_result(msg2)

        context2 = make_turn_context(
            packet_id=packet.packet_id,
            snapshot_id=packet.snapshot_id,
            turn_number=2,
        )
        agent.act(context2)
        assert "fact-002" in agent.last_turn_fact_ids
        assert "fact-001" not in agent.last_turn_fact_ids

    def test_seen_fact_ids_accumulates_from_packet(self) -> None:
        """seen_fact_ids includes all facts from observed packet."""
        agent = MockArchitect()
        packet = make_packet()
        agent.observe(packet)

        assert "fact-001" in agent.seen_fact_ids
        assert "fact-002" in agent.seen_fact_ids
        assert "fact-003" in agent.seen_fact_ids

    def test_receive_adds_to_seen_facts(self) -> None:
        """receive() adds message fact_ids to seen_fact_ids."""
        agent = MockArchitect()
        packet = make_packet()
        agent.observe(packet)

        msg = MockMessage(
            packet_id=packet.packet_id,
            assertions=[MockAssertion(fact_ids=("new-fact",))],
        )
        agent.receive(msg)

        assert "new-fact" in agent.seen_fact_ids


# =============================================================================
# Tests for Agent State Machine
# =============================================================================


class TestAgentStateMachine:
    """Tests for agent state transitions."""

    def test_initial_state_is_idle(self) -> None:
        """Agent starts in IDLE state."""
        agent = MockArchitect()
        assert agent.state == AgentState.IDLE

    def test_observe_transitions_to_ready(self) -> None:
        """observe() transitions from IDLE to READY."""
        agent = MockArchitect()
        packet = make_packet()
        agent.observe(packet)
        assert agent.state == AgentState.READY

    def test_act_returns_to_ready(self) -> None:
        """Successful act() returns to READY state."""
        agent = MockArchitect()
        packet = make_packet()
        agent.observe(packet)

        context = make_turn_context(
            packet_id=packet.packet_id,
            snapshot_id=packet.snapshot_id,
        )

        agent.act(context)
        assert agent.state == AgentState.READY

    def test_act_requires_ready_state(self) -> None:
        """act() raises AgentNotReadyError if not READY."""
        agent = MockArchitect()

        context = make_turn_context()

        with pytest.raises(AgentNotReadyError) as exc_info:
            agent.act(context)
        assert exc_info.value.current_state == AgentState.IDLE

    def test_reset_returns_to_idle(self) -> None:
        """reset() returns agent to IDLE state."""
        agent = MockArchitect()
        packet = make_packet()
        agent.observe(packet)
        agent.reset()
        assert agent.state == AgentState.IDLE

    def test_reset_clears_binding(self) -> None:
        """reset() clears packet binding."""
        agent = MockArchitect()
        packet = make_packet()
        agent.observe(packet)
        agent.reset()
        assert agent.active_packet_id is None
        assert agent.active_snapshot_id is None
        assert agent.is_bound is False


# =============================================================================
# Tests for Working Memory
# =============================================================================


class TestWorkingMemory:
    """Tests for working memory management."""

    def test_working_memory_bounded(self) -> None:
        """Working memory respects max_memory_size."""
        agent = MockArchitect(max_memory_size=5)
        packet = make_packet()
        agent.observe(packet)

        for i in range(10):
            agent._working_memory.append(
                WorkingMemoryEntry(content=f"msg-{i}", timestamp=datetime.utcnow())
            )

        assert agent.working_memory_size == 5

    def test_context_pressure_calculation(self) -> None:
        """context_pressure correctly reflects memory usage."""
        agent = MockArchitect(max_memory_size=10)
        packet = make_packet()
        agent.observe(packet)

        for i in range(5):
            agent._working_memory.append(
                WorkingMemoryEntry(content=f"msg-{i}", timestamp=datetime.utcnow())
            )

        assert agent.context_pressure == 0.5

    def test_context_pressure_full(self) -> None:
        """context_pressure is 1.0 when memory is full."""
        agent = MockArchitect(max_memory_size=5)
        packet = make_packet()
        agent.observe(packet)

        for i in range(5):
            agent._working_memory.append(
                WorkingMemoryEntry(content=f"msg-{i}", timestamp=datetime.utcnow())
            )

        assert agent.context_pressure == 1.0

    def test_context_pressure_zero_when_empty(self) -> None:
        """context_pressure is 0.0 when memory is empty."""
        agent = MockArchitect(max_memory_size=10)
        assert agent.context_pressure == 0.0

    def test_context_pressure_handles_zero_max(self) -> None:
        """context_pressure is 1.0 when max_memory_size is 0."""
        agent = MockArchitect(max_memory_size=0)
        assert agent.context_pressure == 1.0


# =============================================================================
# Tests for Consolidation
# =============================================================================


class TestConsolidation:
    """Tests for memory consolidation."""

    def test_should_consolidate_above_threshold(self) -> None:
        """should_consolidate is True when pressure > 0.8."""
        agent = MockArchitect(max_memory_size=10)
        packet = make_packet()
        agent.observe(packet)

        for i in range(9):
            agent._working_memory.append(
                WorkingMemoryEntry(content=f"msg-{i}", timestamp=datetime.utcnow())
            )

        assert agent.should_consolidate is True

    def test_consolidate_reduces_memory(self) -> None:
        """consolidate() reduces working memory size."""
        agent = MockArchitect(max_memory_size=10)
        packet = make_packet()
        agent.observe(packet)

        for i in range(10):
            agent._working_memory.append(
                WorkingMemoryEntry(
                    content=f"msg-{i}",
                    timestamp=datetime.utcnow(),
                    relevance_score=float(i) / 10,  # Varying relevance
                )
            )

        original_size = agent.working_memory_size
        agent.consolidate()
        assert agent.working_memory_size < original_size

    def test_consolidate_keeps_high_relevance(self) -> None:
        """consolidate() keeps high-relevance entries."""
        agent = MockArchitect(max_memory_size=10)
        packet = make_packet()
        agent.observe(packet)

        # Add entries with varying relevance
        for i in range(10):
            agent._working_memory.append(
                WorkingMemoryEntry(
                    content=f"msg-{i}",
                    timestamp=datetime.utcnow(),
                    relevance_score=float(i) / 10,
                )
            )

        agent.consolidate()

        # Check that remaining entries have higher relevance scores
        for entry in agent._working_memory:
            assert entry.relevance_score >= 0.3  # Bottom ~40% removed

    def test_consolidate_returns_to_ready(self) -> None:
        """consolidate() returns to READY state."""
        agent = MockArchitect()
        packet = make_packet()
        agent.observe(packet)
        agent.consolidate()
        assert agent.state == AgentState.READY


# =============================================================================
# Tests for Health Metrics
# =============================================================================


class TestHealthMetrics:
    """Tests for agent health reporting."""

    def test_health_reports_context_pressure(self) -> None:
        """health.context_pressure reflects working memory."""
        agent = MockArchitect(max_memory_size=10)
        packet = make_packet()
        agent.observe(packet)

        for i in range(5):
            agent._working_memory.append(
                WorkingMemoryEntry(content=f"msg-{i}", timestamp=datetime.utcnow())
            )

        health = agent.health
        assert health.context_pressure == 0.5

    def test_health_reports_facts_seen(self) -> None:
        """health.facts_seen reports correct count."""
        agent = MockArchitect()
        packet = make_packet()  # Has 3 facts
        agent.observe(packet)

        health = agent.health
        assert health.facts_seen == 3

    def test_health_reports_facts_cited(self) -> None:
        """health.facts_cited reports correct count."""
        agent = MockArchitect()
        packet = make_packet()
        agent.observe(packet)

        agent._cited_fact_ids.add("fact-001")
        agent._cited_fact_ids.add("fact-002")

        health = agent.health
        assert health.facts_cited == 2

    def test_health_reports_messages_produced(self) -> None:
        """health.messages_produced reports correct count."""
        agent = MockArchitect()
        packet = make_packet()
        agent.observe(packet)

        msg = MockMessage(packet_id=packet.packet_id)
        agent.set_compose_result(msg)

        context = make_turn_context(
            packet_id=packet.packet_id,
            snapshot_id=packet.snapshot_id,
        )

        agent.act(context)
        agent.act(context)

        health = agent.health
        assert health.messages_produced == 2


# =============================================================================
# Tests for Agent Identity
# =============================================================================


class TestAgentIdentity:
    """Tests for agent identity and role."""

    def test_architect_role(self) -> None:
        """MockArchitect has ARCHITECT role."""
        agent = MockArchitect()
        assert agent.role == AgentRole.ARCHITECT

    def test_skeptic_role(self) -> None:
        """MockSkeptic has SKEPTIC role."""
        agent = MockSkeptic()
        assert agent.role == AgentRole.SKEPTIC

    def test_oracle_role(self) -> None:
        """MockOracle has ORACLE role."""
        agent = MockOracle()
        assert agent.role == AgentRole.ORACLE

    def test_custom_agent_id(self) -> None:
        """Agent uses provided agent_id."""
        agent = MockArchitect(agent_id="my-agent")
        assert agent.agent_id == "my-agent"

    def test_generated_agent_id(self) -> None:
        """Agent generates ID if not provided."""
        agent = MockArchitect()
        assert agent.agent_id.startswith("architect-")

    def test_repr_contains_info(self) -> None:
        """__repr__ contains agent info."""
        agent = MockArchitect(agent_id="test-agent")
        repr_str = repr(agent)
        assert "test-agent" in repr_str
        assert "ARCHITECT" in repr_str


# =============================================================================
# Tests for Message Handling
# =============================================================================


class TestMessageHandling:
    """Tests for receiving and processing messages."""

    def test_receive_adds_to_memory(self) -> None:
        """receive() adds message to working memory."""
        agent = MockArchitect()
        packet = make_packet()
        agent.observe(packet)

        msg = MockMessage(packet_id=packet.packet_id)
        agent.receive(msg)

        assert agent.working_memory_size == 1

    def test_received_message_lower_relevance(self) -> None:
        """Received messages have lower initial relevance."""
        agent = MockArchitect()
        packet = make_packet()
        agent.observe(packet)

        msg = MockMessage(packet_id=packet.packet_id)
        agent.receive(msg)

        entry = agent._working_memory[0]
        assert entry.relevance_score == 0.8  # Lower than default 1.0


# =============================================================================
# Tests for Self-Validation
# =============================================================================


class TestSelfValidation:
    """Tests for message self-validation."""

    def test_validation_detects_missing_facts(self) -> None:
        """Self-validation detects references to non-existent facts."""
        agent = MockArchitect()
        packet = make_packet()
        agent.observe(packet)

        # Message references a fact not in packet
        msg = MockMessage(
            packet_id=packet.packet_id,
            assertions=[MockAssertion(fact_ids=("non-existent-fact",))],
        )
        agent.set_compose_result(msg)

        context = make_turn_context(
            packet_id=packet.packet_id,
            snapshot_id=packet.snapshot_id,
        )

        result = agent.act(context)
        # Should convert to data request
        assert result.message is None
        assert len(result.requests) > 0

    def test_validation_allows_valid_facts(self) -> None:
        """Self-validation passes for valid fact references."""
        agent = MockArchitect()
        packet = make_packet()
        agent.observe(packet)

        msg = MockMessage(
            packet_id=packet.packet_id,
            assertions=[MockAssertion(fact_ids=("fact-001",))],
        )
        agent.set_compose_result(msg)

        context = make_turn_context(
            packet_id=packet.packet_id,
            snapshot_id=packet.snapshot_id,
        )

        result = agent.act(context)
        assert result.message is not None


# =============================================================================
# Tests for TurnResult Production
# =============================================================================


class TestTurnResultProduction:
    """Tests for TurnResult production from act()."""

    def test_act_returns_turn_result(self) -> None:
        """act() returns a TurnResult."""
        agent = MockArchitect()
        packet = make_packet()
        agent.observe(packet)

        context = make_turn_context(
            packet_id=packet.packet_id,
            snapshot_id=packet.snapshot_id,
        )

        result = agent.act(context)
        assert isinstance(result, TurnResult)

    def test_turn_result_has_context(self) -> None:
        """TurnResult contains the original context."""
        agent = MockArchitect()
        packet = make_packet()
        agent.observe(packet)

        context = make_turn_context(
            packet_id=packet.packet_id,
            snapshot_id=packet.snapshot_id,
        )

        result = agent.act(context)
        assert result.context == context

    def test_turn_result_has_processing_time(self) -> None:
        """TurnResult includes processing_time_ms."""
        agent = MockArchitect()
        packet = make_packet()
        agent.observe(packet)

        context = make_turn_context(
            packet_id=packet.packet_id,
            snapshot_id=packet.snapshot_id,
        )

        result = agent.act(context)
        assert result.processing_time_ms is not None
        assert result.processing_time_ms >= 0
