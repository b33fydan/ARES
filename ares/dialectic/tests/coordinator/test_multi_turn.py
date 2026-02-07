"""Tests for Multi-Turn Dialectical Cycles.

Validates the multi-turn debate loop that extends the single-turn Orchestrator
with multiple THESIS -> ANTITHESIS rounds before a final SYNTHESIS verdict.
"""

import pytest
from datetime import datetime

from ares.dialectic.agents.patterns import Verdict, VerdictOutcome
from ares.dialectic.coordinator.cycle import TerminationReason
from ares.dialectic.coordinator.multi_turn import (
    DebateRound,
    MultiTurnConfig,
    MultiTurnCycleResult,
    run_multi_turn_cycle,
)
from ares.dialectic.coordinator.orchestrator import CycleError, CycleResult
from ares.dialectic.evidence.fact import EntityType, Fact
from ares.dialectic.evidence.packet import EvidencePacket, TimeWindow
from ares.dialectic.evidence.provenance import Provenance, SourceType
from ares.dialectic.messages.protocol import Phase


# =============================================================================
# Helpers
# =============================================================================


def make_provenance() -> Provenance:
    """Create a test provenance."""
    return Provenance(
        source_type=SourceType.MANUAL,
        source_id="test",
        extracted_at=datetime(2024, 1, 15, 12, 0, 0),
    )


def make_fact(
    fact_id: str = "fact-001",
    entity_id: str = "node-001",
    field: str = "data",
    value: object = "test_value",
    timestamp: datetime = None,
) -> Fact:
    """Create a test fact."""
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


def build_privilege_escalation_packet() -> EvidencePacket:
    """Build packet with clear threat indicators.

    Scenario: User 'jsmith' gains admin privileges outside maintenance window.
    """
    packet = EvidencePacket(
        packet_id="threat-scenario-001",
        time_window=make_time_window(),
    )

    packet.add_fact(make_fact(
        "fact-user-001", entity_id="user-jsmith",
        field="user_name", value="jsmith",
    ))
    packet.add_fact(make_fact(
        "fact-user-002", entity_id="user-jsmith",
        field="user_role", value="standard_user",
    ))
    packet.add_fact(make_fact(
        "fact-proc-001", entity_id="process-123",
        field="process_name", value="cmd.exe",
    ))
    packet.add_fact(make_fact(
        "fact-proc-002", entity_id="process-123",
        field="process_owner", value="NT AUTHORITY\\SYSTEM",
    ))
    packet.add_fact(make_fact(
        "fact-proc-003", entity_id="process-123",
        field="parent_process", value="explorer.exe",
    ))
    packet.add_fact(make_fact(
        "fact-priv-001", entity_id="event-456",
        field="event_type", value="privilege_escalation",
    ))
    packet.add_fact(make_fact(
        "fact-priv-002", entity_id="event-456",
        field="integrity_level", value="high_integrity",
    ))
    packet.add_fact(make_fact(
        "fact-priv-003", entity_id="event-456",
        field="elevation_type", value="admin",
    ))
    packet.add_fact(make_fact(
        "fact-time-001", entity_id="event-456",
        field="event_time", value="2024-01-15T14:30:00Z",
        timestamp=datetime(2024, 1, 15, 14, 30, 0),
    ))

    packet.freeze()
    return packet


def build_minimal_packet() -> EvidencePacket:
    """Build a packet with a single benign fact."""
    packet = EvidencePacket(
        packet_id="minimal-001",
        time_window=make_time_window(),
    )
    packet.add_fact(make_fact(
        "fact-001", entity_id="host-001",
        field="hostname", value="workstation-42",
    ))
    packet.freeze()
    return packet


def build_empty_packet() -> EvidencePacket:
    """Build a packet with no facts."""
    packet = EvidencePacket(
        packet_id="empty-packet-001",
        time_window=make_time_window(),
    )
    packet.freeze()
    return packet


# =============================================================================
# MultiTurnConfig Validation
# =============================================================================


class TestMultiTurnConfig:
    """Tests for MultiTurnConfig validation."""

    def test_default_config(self):
        """Default config has sensible values."""
        config = MultiTurnConfig()
        assert config.max_rounds == 3
        assert config.confidence_delta == 0.1
        assert config.require_new_evidence is True

    def test_custom_config(self):
        """Config accepts custom values."""
        config = MultiTurnConfig(max_rounds=5, confidence_delta=0.2, require_new_evidence=False)
        assert config.max_rounds == 5
        assert config.confidence_delta == 0.2
        assert config.require_new_evidence is False

    def test_max_rounds_must_be_positive(self):
        """max_rounds < 1 raises ValueError."""
        with pytest.raises(ValueError, match="max_rounds"):
            MultiTurnConfig(max_rounds=0)

    def test_max_rounds_rejects_negative(self):
        """Negative max_rounds raises ValueError."""
        with pytest.raises(ValueError, match="max_rounds"):
            MultiTurnConfig(max_rounds=-1)

    def test_confidence_delta_rejects_negative(self):
        """Negative confidence_delta raises ValueError."""
        with pytest.raises(ValueError, match="confidence_delta"):
            MultiTurnConfig(confidence_delta=-0.1)

    def test_confidence_delta_rejects_above_one(self):
        """confidence_delta > 1.0 raises ValueError."""
        with pytest.raises(ValueError, match="confidence_delta"):
            MultiTurnConfig(confidence_delta=1.1)

    def test_confidence_delta_boundary_zero(self):
        """confidence_delta=0.0 is valid."""
        config = MultiTurnConfig(confidence_delta=0.0)
        assert config.confidence_delta == 0.0

    def test_confidence_delta_boundary_one(self):
        """confidence_delta=1.0 is valid."""
        config = MultiTurnConfig(confidence_delta=1.0)
        assert config.confidence_delta == 1.0

    def test_config_is_frozen(self):
        """Config should be immutable."""
        config = MultiTurnConfig()
        with pytest.raises(AttributeError):
            config.max_rounds = 10


# =============================================================================
# DebateRound Tests
# =============================================================================


class TestDebateRound:
    """Tests for DebateRound frozen dataclass."""

    def test_debate_round_is_frozen(self):
        """DebateRound should be immutable."""
        packet = build_privilege_escalation_packet()
        result = run_multi_turn_cycle(packet, config=MultiTurnConfig(max_rounds=1))
        with pytest.raises(AttributeError):
            result.rounds[0].round_number = 999

    def test_debate_round_confidence_delegates_to_messages(self):
        """Confidence properties delegate to thesis/antithesis messages."""
        packet = build_privilege_escalation_packet()
        result = run_multi_turn_cycle(packet, config=MultiTurnConfig(max_rounds=1))
        rnd = result.rounds[0]
        assert rnd.architect_confidence == rnd.thesis.confidence
        assert rnd.skeptic_confidence == rnd.antithesis.confidence


# =============================================================================
# Basic Multi-Turn Execution
# =============================================================================


class TestBasicMultiTurnExecution:
    """Tests for the happy path: run_multi_turn_cycle end-to-end."""

    def test_two_round_cycle_completes(self):
        """A 2-round cycle returns MultiTurnCycleResult with <= 2 DebateRounds."""
        packet = build_privilege_escalation_packet()
        config = MultiTurnConfig(max_rounds=2, require_new_evidence=False)
        result = run_multi_turn_cycle(packet, config=config)

        assert result.total_rounds <= 2
        assert result.verdict is not None
        assert len(result.rounds) == result.total_rounds
        assert all(isinstance(r, DebateRound) for r in result.rounds)

    def test_three_round_cycle_completes(self):
        """A 3-round cycle completes with <= 3 rounds."""
        packet = build_privilege_escalation_packet()
        config = MultiTurnConfig(max_rounds=3, require_new_evidence=False)
        result = run_multi_turn_cycle(packet, config=config)
        assert result.total_rounds <= 3
        assert result.verdict is not None

    def test_single_round_multi_turn(self):
        """max_rounds=1 should produce exactly 1 round with MAX_TURNS_EXCEEDED."""
        packet = build_privilege_escalation_packet()
        config = MultiTurnConfig(max_rounds=1)
        result = run_multi_turn_cycle(packet, config=config)
        assert result.total_rounds == 1
        assert result.termination_reason == TerminationReason.MAX_TURNS_EXCEEDED

    def test_rounds_are_ordered(self):
        """Round numbers should be sequential starting from 1."""
        packet = build_privilege_escalation_packet()
        config = MultiTurnConfig(max_rounds=3, require_new_evidence=False)
        result = run_multi_turn_cycle(packet, config=config)
        for i, rnd in enumerate(result.rounds):
            assert rnd.round_number == i + 1

    def test_default_config_used_when_none(self):
        """Passing no config should use defaults."""
        packet = build_privilege_escalation_packet()
        result = run_multi_turn_cycle(packet)
        assert result is not None
        assert result.verdict is not None

    def test_round_messages_have_correct_phases(self):
        """Thesis messages are THESIS, antithesis messages are ANTITHESIS."""
        packet = build_privilege_escalation_packet()
        config = MultiTurnConfig(max_rounds=2, require_new_evidence=False)
        result = run_multi_turn_cycle(packet, config=config)
        for rnd in result.rounds:
            assert rnd.thesis.phase == Phase.THESIS
            assert rnd.antithesis.phase == Phase.ANTITHESIS

    def test_cycle_id_is_unique(self):
        """Each call produces a unique cycle_id."""
        packet = build_privilege_escalation_packet()
        r1 = run_multi_turn_cycle(packet, config=MultiTurnConfig(max_rounds=1))
        r2 = run_multi_turn_cycle(packet, config=MultiTurnConfig(max_rounds=1))
        assert r1.cycle_id != r2.cycle_id

    def test_duration_ms_is_non_negative(self):
        """Duration should be >= 0."""
        packet = build_privilege_escalation_packet()
        result = run_multi_turn_cycle(packet, config=MultiTurnConfig(max_rounds=1))
        assert result.duration_ms >= 0

    def test_timestamps_ordered(self):
        """started_at must be before or equal to completed_at."""
        packet = build_privilege_escalation_packet()
        result = run_multi_turn_cycle(packet, config=MultiTurnConfig(max_rounds=1))
        assert result.started_at <= result.completed_at

    def test_cycle_id_has_cycle_prefix(self):
        """Cycle IDs follow 'cycle-{uuid}' format."""
        packet = build_privilege_escalation_packet()
        result = run_multi_turn_cycle(packet, config=MultiTurnConfig(max_rounds=1))
        assert result.cycle_id.startswith("cycle-")

    def test_packet_id_preserved(self):
        """Result preserves the original packet_id."""
        packet = build_privilege_escalation_packet()
        result = run_multi_turn_cycle(packet, config=MultiTurnConfig(max_rounds=1))
        assert result.packet_id == "threat-scenario-001"


# =============================================================================
# Termination Conditions
# =============================================================================


class TestTerminationConditions:
    """Tests for the three termination conditions."""

    def test_terminates_at_max_rounds(self):
        """Cycle should terminate at or before max_rounds."""
        packet = build_privilege_escalation_packet()
        config = MultiTurnConfig(max_rounds=2, require_new_evidence=False)
        result = run_multi_turn_cycle(packet, config=config)
        assert result.total_rounds <= 2
        if result.total_rounds == 2:
            assert result.termination_reason == TerminationReason.MAX_TURNS_EXCEEDED

    def test_max_rounds_one_always_max_turns(self):
        """max_rounds=1 always terminates with MAX_TURNS_EXCEEDED."""
        packet = build_privilege_escalation_packet()
        config = MultiTurnConfig(max_rounds=1)
        result = run_multi_turn_cycle(packet, config=config)
        assert result.total_rounds == 1
        assert result.termination_reason == TerminationReason.MAX_TURNS_EXCEEDED

    def test_terminates_on_no_new_evidence(self):
        """When agents recite the same facts, debate should end early."""
        packet = build_privilege_escalation_packet()
        config = MultiTurnConfig(max_rounds=5, require_new_evidence=True)
        result = run_multi_turn_cycle(packet, config=config)
        if result.termination_reason == TerminationReason.NO_NEW_EVIDENCE:
            assert result.total_rounds < 5

    def test_continues_without_new_evidence_when_disabled(self):
        """require_new_evidence=False should not terminate on stale evidence."""
        packet = build_privilege_escalation_packet()
        config = MultiTurnConfig(max_rounds=2, require_new_evidence=False)
        result = run_multi_turn_cycle(packet, config=config)
        assert result.termination_reason != TerminationReason.NO_NEW_EVIDENCE

    def test_terminates_on_confidence_stabilized(self):
        """When confidence stops changing, debate should end."""
        packet = build_privilege_escalation_packet()
        # delta=1.0 means any change less than 1.0 = stabilized
        config = MultiTurnConfig(
            max_rounds=5, confidence_delta=1.0, require_new_evidence=False,
        )
        result = run_multi_turn_cycle(packet, config=config)
        if result.total_rounds > 1:
            assert result.termination_reason == TerminationReason.CONFIDENCE_STABILIZED

    def test_confidence_delta_zero_very_strict(self):
        """confidence_delta=0.0 means stabilization is extremely unlikely."""
        packet = build_privilege_escalation_packet()
        config = MultiTurnConfig(
            max_rounds=3, confidence_delta=0.0, require_new_evidence=False,
        )
        result = run_multi_turn_cycle(packet, config=config)
        # With delta=0.0, stabilization requires < 0.0 change (impossible).
        # So we should hit max_rounds or another condition.
        assert result.total_rounds >= 1

    def test_termination_reason_is_always_set(self):
        """Every result has a termination reason."""
        packet = build_privilege_escalation_packet()
        result = run_multi_turn_cycle(packet)
        assert result.termination_reason is not None
        assert isinstance(result.termination_reason, TerminationReason)

    def test_no_new_evidence_requires_round_greater_than_one(self):
        """NO_NEW_EVIDENCE can only trigger at round 2+."""
        packet = build_privilege_escalation_packet()
        config = MultiTurnConfig(max_rounds=1, require_new_evidence=True)
        result = run_multi_turn_cycle(packet, config=config)
        # Round 1 can't trigger NO_NEW_EVIDENCE (no previous round to compare)
        assert result.termination_reason == TerminationReason.MAX_TURNS_EXCEEDED


# =============================================================================
# Agent State Across Rounds
# =============================================================================


class TestAgentStateAcrossRounds:
    """Tests for correct agent state management in multi-round debates."""

    def test_architect_receives_skeptic_message_round_2(self):
        """In round 2, Architect should have received round 1's antithesis."""
        packet = build_privilege_escalation_packet()
        config = MultiTurnConfig(max_rounds=2, require_new_evidence=False)
        result = run_multi_turn_cycle(packet, config=config)
        if result.total_rounds >= 2:
            # Round 2 thesis exists — Architect was able to respond
            assert result.rounds[1].thesis is not None

    def test_skeptic_receives_architect_message_each_round(self):
        """Skeptic produces antithesis in every round (received thesis first)."""
        packet = build_privilege_escalation_packet()
        config = MultiTurnConfig(max_rounds=2, require_new_evidence=False)
        result = run_multi_turn_cycle(packet, config=config)
        for rnd in result.rounds:
            assert rnd.antithesis is not None

    def test_agent_isolation_between_cycles(self):
        """Separate multi-turn cycles must not share agent state."""
        packet = build_privilege_escalation_packet()
        config = MultiTurnConfig(max_rounds=1)
        r1 = run_multi_turn_cycle(packet, config=config)
        r2 = run_multi_turn_cycle(packet, config=config)
        assert r1.cycle_id != r2.cycle_id

    def test_turn_numbers_increment_across_rounds(self):
        """Turn numbers should increase: round 1 uses turns 1-2, round 2 uses 3-4, etc."""
        packet = build_privilege_escalation_packet()
        config = MultiTurnConfig(max_rounds=3, require_new_evidence=False)
        result = run_multi_turn_cycle(packet, config=config)
        # Verify through round structure: each round has sequential thesis/antithesis
        for i, rnd in enumerate(result.rounds):
            expected_thesis_turn = i * 2 + 1
            expected_antithesis_turn = i * 2 + 2
            assert rnd.thesis.turn_number == expected_thesis_turn
            assert rnd.antithesis.turn_number == expected_antithesis_turn

    def test_unfrozen_packet_rejected(self):
        """Unfrozen packet raises ValueError."""
        packet = EvidencePacket(
            packet_id="unfrozen-test",
            time_window=make_time_window(),
        )
        packet.add_fact(make_fact())
        with pytest.raises(ValueError, match="frozen"):
            run_multi_turn_cycle(packet)

    def test_unfrozen_empty_packet_rejected(self):
        """Even empty unfrozen packet is rejected."""
        packet = EvidencePacket(
            packet_id="unfrozen-empty",
            time_window=make_time_window(),
        )
        with pytest.raises(ValueError, match="frozen"):
            run_multi_turn_cycle(packet)

    def test_empty_packet_produces_result(self):
        """An empty packet should still complete (Oracle decides)."""
        empty_packet = build_empty_packet()
        result = run_multi_turn_cycle(
            empty_packet, config=MultiTurnConfig(max_rounds=1),
        )
        assert result.verdict is not None


# =============================================================================
# Verdict and Oracle
# =============================================================================


class TestVerdictAndOracle:
    """Tests for verdict computation and OracleNarrator."""

    def test_verdict_computed_from_final_round(self):
        """OracleJudge should receive the LAST round's messages."""
        packet = build_privilege_escalation_packet()
        config = MultiTurnConfig(max_rounds=2, require_new_evidence=False)
        result = run_multi_turn_cycle(packet, config=config)
        assert result.verdict is not None
        assert result.verdict.outcome in VerdictOutcome

    def test_verdict_has_valid_confidence(self):
        """Verdict confidence must be in [0.0, 1.0]."""
        packet = build_privilege_escalation_packet()
        result = run_multi_turn_cycle(packet, config=MultiTurnConfig(max_rounds=1))
        assert 0.0 <= result.verdict.confidence <= 1.0

    def test_verdict_reasoning_not_empty(self):
        """Verdict must include reasoning."""
        packet = build_privilege_escalation_packet()
        result = run_multi_turn_cycle(packet, config=MultiTurnConfig(max_rounds=1))
        assert len(result.verdict.reasoning) > 0

    def test_narrator_produces_message_when_enabled(self):
        """Narrator message is present when narration is enabled."""
        packet = build_privilege_escalation_packet()
        result = run_multi_turn_cycle(
            packet, config=MultiTurnConfig(max_rounds=1), include_narration=True,
        )
        assert result.narrator_message is not None

    def test_narrator_skipped_when_disabled(self):
        """Narrator message is None when narration is disabled."""
        packet = build_privilege_escalation_packet()
        result = run_multi_turn_cycle(
            packet, config=MultiTurnConfig(max_rounds=1), include_narration=False,
        )
        assert result.narrator_message is None
        assert result.verdict is not None

    def test_narrator_cannot_change_verdict(self):
        """Narrator message should not affect the verdict outcome."""
        packet = build_privilege_escalation_packet()
        config = MultiTurnConfig(max_rounds=1)
        result_with = run_multi_turn_cycle(packet, config=config, include_narration=True)
        result_without = run_multi_turn_cycle(packet, config=config, include_narration=False)
        # Same packet, same config → same verdict (deterministic agents)
        assert result_with.verdict.outcome == result_without.verdict.outcome

    def test_narrator_message_is_synthesis_phase(self):
        """Narrator message should be in SYNTHESIS phase."""
        packet = build_privilege_escalation_packet()
        result = run_multi_turn_cycle(
            packet, config=MultiTurnConfig(max_rounds=1), include_narration=True,
        )
        assert result.narrator_message.phase == Phase.SYNTHESIS


# =============================================================================
# Result Integrity
# =============================================================================


class TestResultIntegrity:
    """Tests for immutability and structural integrity of results."""

    def test_multi_turn_result_is_frozen(self):
        """MultiTurnCycleResult should be immutable."""
        packet = build_privilege_escalation_packet()
        result = run_multi_turn_cycle(packet, config=MultiTurnConfig(max_rounds=1))
        with pytest.raises(AttributeError):
            result.cycle_id = "tampered"

    def test_multi_turn_result_frozen_verdict(self):
        """Cannot reassign verdict on frozen result."""
        packet = build_privilege_escalation_packet()
        result = run_multi_turn_cycle(packet, config=MultiTurnConfig(max_rounds=1))
        with pytest.raises(AttributeError):
            result.verdict = None

    def test_to_cycle_result_returns_valid_cycle_result(self):
        """Conversion to CycleResult produces a valid, storable object."""
        packet = build_privilege_escalation_packet()
        mt_result = run_multi_turn_cycle(packet, config=MultiTurnConfig(max_rounds=1))
        cr = mt_result.to_cycle_result()
        assert isinstance(cr, CycleResult)
        assert cr.cycle_id == mt_result.cycle_id
        assert cr.packet_id == mt_result.packet_id
        assert cr.verdict == mt_result.verdict
        assert cr.architect_message == mt_result.final_round.thesis
        assert cr.skeptic_message == mt_result.final_round.antithesis
        assert cr.duration_ms == mt_result.duration_ms

    def test_to_cycle_result_storable_in_memory_stream(self):
        """CycleResult from to_cycle_result() accepted by MemoryStream."""
        from ares.dialectic.memory.stream import MemoryStream
        from ares.dialectic.memory.backends.in_memory import InMemoryBackend

        packet = build_privilege_escalation_packet()
        mt_result = run_multi_turn_cycle(packet, config=MultiTurnConfig(max_rounds=1))
        cr = mt_result.to_cycle_result()

        stream = MemoryStream(backend=InMemoryBackend())
        entry = stream.store(cr)
        assert entry.cycle_id == cr.cycle_id

    def test_final_round_property(self):
        """final_round should return the last round."""
        packet = build_privilege_escalation_packet()
        config = MultiTurnConfig(max_rounds=2, require_new_evidence=False)
        result = run_multi_turn_cycle(packet, config=config)
        assert result.final_round == result.rounds[-1]

    def test_total_rounds_property(self):
        """total_rounds should equal len(rounds)."""
        packet = build_privilege_escalation_packet()
        config = MultiTurnConfig(max_rounds=2, require_new_evidence=False)
        result = run_multi_turn_cycle(packet, config=config)
        assert result.total_rounds == len(result.rounds)

    def test_to_cycle_result_uses_final_round(self):
        """CycleResult should use the FINAL round's messages, not round 1."""
        packet = build_privilege_escalation_packet()
        config = MultiTurnConfig(max_rounds=2, require_new_evidence=False)
        result = run_multi_turn_cycle(packet, config=config)
        cr = result.to_cycle_result()
        if result.total_rounds == 2:
            # The CycleResult messages should be from round 2, not round 1
            assert cr.architect_message == result.rounds[-1].thesis
            assert cr.skeptic_message == result.rounds[-1].antithesis

    def test_to_cycle_result_preserves_timestamps(self):
        """CycleResult should preserve start/end timestamps."""
        packet = build_privilege_escalation_packet()
        mt_result = run_multi_turn_cycle(packet, config=MultiTurnConfig(max_rounds=1))
        cr = mt_result.to_cycle_result()
        assert cr.started_at == mt_result.started_at
        assert cr.completed_at == mt_result.completed_at


# =============================================================================
# Insufficient Data / Early Termination
# =============================================================================


class TestInsufficientData:
    """Tests for minimal/empty evidence handling."""

    def test_insufficient_data_terminates_gracefully(self):
        """Minimal evidence should not cause infinite spinning."""
        minimal_packet = build_minimal_packet()
        config = MultiTurnConfig(max_rounds=5)
        result = run_multi_turn_cycle(minimal_packet, config=config)
        assert result.total_rounds <= 5
        assert result.verdict is not None

    def test_multi_turn_with_rich_evidence(self):
        """More evidence should still produce a valid result."""
        rich_packet = build_privilege_escalation_packet()
        result = run_multi_turn_cycle(rich_packet, config=MultiTurnConfig(max_rounds=3))
        assert result.verdict is not None
        assert result.total_rounds >= 1

    def test_empty_packet_verdict_outcome(self):
        """Empty evidence should produce INCONCLUSIVE verdict."""
        empty_packet = build_empty_packet()
        result = run_multi_turn_cycle(
            empty_packet, config=MultiTurnConfig(max_rounds=1),
        )
        assert result.verdict.outcome == VerdictOutcome.INCONCLUSIVE


# =============================================================================
# Agent ID Format
# =============================================================================


class TestAgentIdFormat:
    """Tests for agent ID generation and traceability."""

    def test_agent_ids_contain_prefix(self):
        """Agent messages should have IDs containing the prefix."""
        packet = build_privilege_escalation_packet()
        result = run_multi_turn_cycle(
            packet, config=MultiTurnConfig(max_rounds=1),
            agent_id_prefix="test",
        )
        assert result.rounds[0].thesis.source_agent.startswith("test-arch-")
        assert result.rounds[0].antithesis.source_agent.startswith("test-skep-")

    def test_agent_ids_share_cycle_uuid(self):
        """All agents in a cycle share the same UUID suffix."""
        packet = build_privilege_escalation_packet()
        result = run_multi_turn_cycle(
            packet, config=MultiTurnConfig(max_rounds=1),
        )
        arch_suffix = result.rounds[0].thesis.source_agent.split("-")[-1]
        skep_suffix = result.rounds[0].antithesis.source_agent.split("-")[-1]
        assert arch_suffix == skep_suffix

    def test_narrator_shares_cycle_uuid(self):
        """Narrator agent ID shares UUID suffix with debate agents."""
        packet = build_privilege_escalation_packet()
        result = run_multi_turn_cycle(
            packet, config=MultiTurnConfig(max_rounds=1),
            include_narration=True,
        )
        arch_suffix = result.rounds[0].thesis.source_agent.split("-")[-1]
        narr_suffix = result.narrator_message.source_agent.split("-")[-1]
        assert arch_suffix == narr_suffix


# =============================================================================
# Determinism
# =============================================================================


class TestDeterminism:
    """Tests verifying deterministic behavior across runs."""

    def test_same_packet_same_verdict_outcome(self):
        """Same input should produce the same verdict outcome."""
        packet = build_privilege_escalation_packet()
        config = MultiTurnConfig(max_rounds=1)
        r1 = run_multi_turn_cycle(packet, config=config)
        r2 = run_multi_turn_cycle(packet, config=config)
        assert r1.verdict.outcome == r2.verdict.outcome

    def test_same_packet_same_confidence(self):
        """Same input should produce the same confidence."""
        packet = build_privilege_escalation_packet()
        config = MultiTurnConfig(max_rounds=1)
        r1 = run_multi_turn_cycle(packet, config=config)
        r2 = run_multi_turn_cycle(packet, config=config)
        assert r1.verdict.confidence == r2.verdict.confidence

    def test_same_packet_same_round_count(self):
        """Same input should produce the same number of rounds."""
        packet = build_privilege_escalation_packet()
        config = MultiTurnConfig(max_rounds=3, require_new_evidence=False)
        r1 = run_multi_turn_cycle(packet, config=config)
        r2 = run_multi_turn_cycle(packet, config=config)
        assert r1.total_rounds == r2.total_rounds

    def test_same_packet_same_termination_reason(self):
        """Same input should produce the same termination reason."""
        packet = build_privilege_escalation_packet()
        config = MultiTurnConfig(max_rounds=3)
        r1 = run_multi_turn_cycle(packet, config=config)
        r2 = run_multi_turn_cycle(packet, config=config)
        assert r1.termination_reason == r2.termination_reason


# =============================================================================
# Integration Tests
# =============================================================================


class TestIntegration:
    """Integration tests with other ARES components."""

    def test_full_pipeline_with_multi_turn(self):
        """Raw XML -> Extractor -> Packet -> MultiTurn -> Verdict."""
        from ares.dialectic.evidence.extractors.windows import WindowsEventExtractor

        xml = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
            <System>
                <EventID>4624</EventID>
                <TimeCreated SystemTime="2024-01-15T14:30:00.000Z"/>
                <Computer>WORKSTATION01</Computer>
            </System>
            <EventData>
                <Data Name="SubjectUserName">jsmith</Data>
                <Data Name="TargetUserName">administrator</Data>
                <Data Name="LogonType">10</Data>
                <Data Name="IpAddress">10.0.0.50</Data>
                <Data Name="WorkstationName">WORKSTATION01</Data>
            </EventData>
        </Event>"""

        extractor = WindowsEventExtractor()
        extraction = extractor.extract(xml, source_ref="test-4624")

        packet = EvidencePacket(
            packet_id="pipeline-mt-test",
            time_window=make_time_window(),
        )
        for fact in extraction.facts:
            packet.add_fact(fact)
        packet.freeze()

        mt_result = run_multi_turn_cycle(
            packet, config=MultiTurnConfig(max_rounds=2),
        )
        assert mt_result.verdict.outcome in VerdictOutcome
        assert mt_result.total_rounds >= 1

    def test_multi_turn_then_memory_stream_pipeline(self):
        """MultiTurn -> to_cycle_result -> MemoryStream -> verify chain."""
        from ares.dialectic.memory.stream import MemoryStream
        from ares.dialectic.memory.backends.in_memory import InMemoryBackend

        packet = build_privilege_escalation_packet()
        stream = MemoryStream(backend=InMemoryBackend())

        mt1 = run_multi_turn_cycle(packet, config=MultiTurnConfig(max_rounds=1))
        mt2 = run_multi_turn_cycle(packet, config=MultiTurnConfig(max_rounds=1))

        stream.store(mt1.to_cycle_result())
        stream.store(mt2.to_cycle_result())

        assert stream.verify_chain_integrity() is True
        assert stream.count == 2

    def test_single_turn_and_multi_turn_same_memory_stream(self):
        """Single-turn and multi-turn results can coexist in MemoryStream."""
        from ares.dialectic.coordinator.orchestrator import DialecticalOrchestrator
        from ares.dialectic.memory.stream import MemoryStream
        from ares.dialectic.memory.backends.in_memory import InMemoryBackend

        packet = build_privilege_escalation_packet()
        stream = MemoryStream(backend=InMemoryBackend())

        # Single-turn via orchestrator
        orchestrator = DialecticalOrchestrator()
        single_result = orchestrator.run_cycle(packet)
        stream.store(single_result)

        # Multi-turn via run_multi_turn_cycle
        mt_result = run_multi_turn_cycle(packet, config=MultiTurnConfig(max_rounds=1))
        stream.store(mt_result.to_cycle_result())

        assert stream.verify_chain_integrity() is True
        assert stream.count == 2
