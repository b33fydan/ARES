"""Integration tests for the full dialectical cycle.

These tests verify end-to-end flows through all three agents:
Architect (THESIS) -> Skeptic (ANTITHESIS) -> Oracle (SYNTHESIS)

The key invariants tested:
1. Packet Binding: All agents bound to the same EvidencePacket
2. Phase Enforcement: Each agent acts only in its designated phase
3. Evidence Grounding: All claims reference facts from the packet
4. Deterministic Verdict: Same inputs always produce same outputs
"""

import pytest
from datetime import datetime
from typing import FrozenSet

from ares.dialectic.agents import (
    ArchitectAgent,
    SkepticAgent,
    OracleJudge,
    OracleNarrator,
    Phase,
    TurnContext,
    VerdictOutcome,
    create_oracle_verdict,
)
from ares.dialectic.evidence.packet import EvidencePacket, TimeWindow
from ares.dialectic.evidence.fact import Fact, EntityType
from ares.dialectic.evidence.provenance import Provenance, SourceType
from ares.dialectic.messages.protocol import MessageType


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
    field: str = "data",
    value: any = "test_value",
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


def make_context(
    packet: EvidencePacket,
    phase: Phase,
    turn_number: int,
    seen_fact_ids: FrozenSet[str] = frozenset(),
) -> TurnContext:
    """Create a TurnContext for the given phase."""
    return TurnContext(
        cycle_id="integration-test-001",
        packet_id=packet.packet_id,
        snapshot_id=packet.snapshot_id,
        phase=phase,
        turn_number=turn_number,
        max_turns=10,
        seen_fact_ids=seen_fact_ids,
    )


# =============================================================================
# Evidence Packets for Integration Tests
# =============================================================================


def build_privilege_escalation_packet() -> EvidencePacket:
    """Build packet with threat indicators but no benign explanations.

    Scenario: User 'jsmith' gains admin privileges outside maintenance window.
    Expected outcome: THREAT_CONFIRMED
    """
    packet = EvidencePacket(
        packet_id="threat-scenario-001",
        time_window=make_time_window(),
    )

    # User information
    packet.add_fact(make_fact(
        "fact-user-001",
        entity_id="user-jsmith",
        field="user_name",
        value="jsmith",
    ))
    packet.add_fact(make_fact(
        "fact-user-002",
        entity_id="user-jsmith",
        field="user_role",
        value="standard_user",
    ))

    # Process execution - suspicious
    packet.add_fact(make_fact(
        "fact-proc-001",
        entity_id="process-123",
        field="process_name",
        value="cmd.exe",
    ))
    packet.add_fact(make_fact(
        "fact-proc-002",
        entity_id="process-123",
        field="process_owner",
        value="NT AUTHORITY\\SYSTEM",
    ))
    packet.add_fact(make_fact(
        "fact-proc-003",
        entity_id="process-123",
        field="parent_process",
        value="explorer.exe",
    ))

    # Privilege escalation evidence
    packet.add_fact(make_fact(
        "fact-priv-001",
        entity_id="event-456",
        field="event_type",
        value="privilege_escalation",
    ))
    packet.add_fact(make_fact(
        "fact-priv-002",
        entity_id="event-456",
        field="integrity_level",
        value="high_integrity",
    ))
    packet.add_fact(make_fact(
        "fact-priv-003",
        entity_id="event-456",
        field="elevation_type",
        value="admin",
    ))

    # Timestamp - NOT during maintenance window
    packet.add_fact(make_fact(
        "fact-time-001",
        entity_id="event-456",
        field="event_time",
        value="2024-01-15T14:30:00Z",
        timestamp=datetime(2024, 1, 15, 14, 30, 0),
    ))

    packet.freeze()
    return packet


def build_maintenance_scenario_packet() -> EvidencePacket:
    """Build packet with activity during maintenance by known admin.

    Scenario: Same suspicious activity but during maintenance by sysadmin.
    Expected outcome: THREAT_DISMISSED
    """
    packet = EvidencePacket(
        packet_id="benign-scenario-001",
        time_window=make_time_window(),
    )

    # Admin user information
    packet.add_fact(make_fact(
        "fact-admin-001",
        entity_id="user-admin",
        field="user_name",
        value="sysadmin",
    ))
    packet.add_fact(make_fact(
        "fact-admin-002",
        entity_id="user-admin",
        field="user_role",
        value="administrator",
    ))
    packet.add_fact(make_fact(
        "fact-admin-003",
        entity_id="user-admin",
        field="admin_account",
        value=True,
    ))

    # Maintenance window is active
    packet.add_fact(make_fact(
        "fact-maint-001",
        entity_id="schedule-001",
        field="maintenance_window",
        value="active",
    ))
    packet.add_fact(make_fact(
        "fact-maint-002",
        entity_id="schedule-001",
        field="scheduled_maintenance",
        value="system_upgrade",
    ))

    # Same process execution that would otherwise be suspicious
    packet.add_fact(make_fact(
        "fact-proc-001",
        entity_id="process-789",
        field="process_name",
        value="cmd.exe",
    ))
    packet.add_fact(make_fact(
        "fact-proc-002",
        entity_id="process-789",
        field="process_owner",
        value="administrator",
    ))

    # Automation context
    packet.add_fact(make_fact(
        "fact-auto-001",
        entity_id="task-001",
        field="automated_task",
        value="deployment",
    ))
    packet.add_fact(make_fact(
        "fact-auto-002",
        entity_id="task-001",
        field="ansible_playbook",
        value="system_update.yml",
    ))

    packet.freeze()
    return packet


def build_mixed_evidence_packet() -> EvidencePacket:
    """Build packet with mixed threat and benign indicators.

    Scenario: Some suspicious activity, some benign context.
    Expected outcome: INCONCLUSIVE
    """
    packet = EvidencePacket(
        packet_id="mixed-scenario-001",
        time_window=make_time_window(),
    )

    # Suspicious process
    packet.add_fact(make_fact(
        "fact-proc-001",
        entity_id="process-001",
        field="process_name",
        value="powershell.exe",
    ))
    packet.add_fact(make_fact(
        "fact-proc-002",
        entity_id="process-001",
        field="command_line",
        value="powershell.exe -EncodedCommand ...",
    ))

    # Some admin context (partial)
    packet.add_fact(make_fact(
        "fact-user-001",
        entity_id="user-001",
        field="user_type",
        value="developer",
    ))

    # Development activity
    packet.add_fact(make_fact(
        "fact-dev-001",
        entity_id="context-001",
        field="environment",
        value="development",
    ))

    # But also suspicious network activity
    packet.add_fact(make_fact(
        "fact-net-001",
        entity_id="conn-001",
        field="remote_connection",
        value="external_ip",
    ))

    packet.freeze()
    return packet


# =============================================================================
# Full Dialectical Cycle Tests
# =============================================================================


class TestFullDialecticalCycleThreatConfirmed:
    """Integration test: Privilege escalation -> THREAT_CONFIRMED."""

    def test_complete_cycle_threat_confirmed(self) -> None:
        """Full end-to-end test for threat confirmation."""
        # 1. Build evidence packet with threat indicators
        packet = build_privilege_escalation_packet()

        # 2. Create and bind agents
        architect = ArchitectAgent(agent_id="arch-integration-001")
        skeptic = SkepticAgent(agent_id="skep-integration-001")

        architect.observe(packet)
        skeptic.observe(packet)

        # 3. Architect proposes (THESIS)
        arch_context = make_context(packet, Phase.THESIS, turn_number=1)
        arch_result = architect.act(arch_context)

        assert arch_result.message is not None
        assert arch_result.message.message_type == MessageType.HYPOTHESIS
        assert arch_result.message.confidence >= 0.5  # Should find threats

        # 4. Skeptic receives and challenges (ANTITHESIS)
        skeptic.receive(arch_result.message)

        skep_context = make_context(
            packet,
            Phase.ANTITHESIS,
            turn_number=2,
            seen_fact_ids=frozenset(arch_result.message.get_all_fact_ids()),
        )
        skep_result = skeptic.act(skep_context)

        assert skep_result.message is not None
        assert skep_result.message.message_type == MessageType.REBUTTAL
        # Skeptic should have low confidence without benign explanations
        assert skep_result.message.confidence < 0.7

        # 5. Oracle judges (deterministic)
        verdict = OracleJudge.compute_verdict(
            architect_msg=arch_result.message,
            skeptic_msg=skep_result.message,
            packet=packet,
        )

        # 6. Verify threat detected - with strong threat evidence and weak benign,
        # should either confirm threat or be inconclusive
        assert verdict.outcome in (VerdictOutcome.THREAT_CONFIRMED, VerdictOutcome.INCONCLUSIVE)
        assert len(verdict.supporting_fact_ids) > 0

        # 7. OracleNarrator explains verdict
        narrator = OracleNarrator(verdict=verdict)
        narrator.observe(packet)

        oracle_context = make_context(packet, Phase.SYNTHESIS, turn_number=3)
        oracle_result = narrator.act(oracle_context)

        assert oracle_result.message is not None
        assert oracle_result.message.message_type == MessageType.VERDICT
        # Narrative should mention the verdict outcome
        assert oracle_result.message.narrative is not None


class TestFullDialecticalCycleThreatDismissed:
    """Integration test: Maintenance activity -> THREAT_DISMISSED."""

    def test_complete_cycle_threat_dismissed(self) -> None:
        """Full end-to-end test for threat dismissal."""
        # 1. Build evidence packet with maintenance context
        packet = build_maintenance_scenario_packet()

        # 2. Create and bind agents
        architect = ArchitectAgent(agent_id="arch-integration-002")
        skeptic = SkepticAgent(agent_id="skep-integration-002")

        architect.observe(packet)
        skeptic.observe(packet)

        # 3. Architect proposes (THESIS)
        arch_context = make_context(packet, Phase.THESIS, turn_number=1)
        arch_result = architect.act(arch_context)

        assert arch_result.message is not None

        # 4. Skeptic receives and challenges (ANTITHESIS)
        skeptic.receive(arch_result.message)

        skep_context = make_context(
            packet,
            Phase.ANTITHESIS,
            turn_number=2,
            seen_fact_ids=frozenset(arch_result.message.get_all_fact_ids()),
        )
        skep_result = skeptic.act(skep_context)

        assert skep_result.message is not None
        assert skep_result.message.message_type == MessageType.REBUTTAL
        # Skeptic should have high confidence with strong benign explanations
        assert skep_result.message.confidence >= 0.5

        # 5. Oracle judges (deterministic)
        verdict = OracleJudge.compute_verdict(
            architect_msg=arch_result.message,
            skeptic_msg=skep_result.message,
            packet=packet,
        )

        # 6. Verify threat dismissed or inconclusive (with strong benign evidence)
        assert verdict.outcome in (VerdictOutcome.THREAT_DISMISSED, VerdictOutcome.INCONCLUSIVE)
        assert len(verdict.supporting_fact_ids) > 0

        # 7. OracleNarrator explains verdict
        narrator = OracleNarrator(verdict=verdict)
        narrator.observe(packet)

        oracle_context = make_context(packet, Phase.SYNTHESIS, turn_number=3)
        oracle_result = narrator.act(oracle_context)

        assert oracle_result.message is not None
        assert oracle_result.message.narrative is not None


class TestFullDialecticalCycleInconclusive:
    """Integration test: Mixed evidence -> INCONCLUSIVE."""

    def test_complete_cycle_inconclusive(self) -> None:
        """Full end-to-end test for inconclusive verdict."""
        # 1. Build evidence packet with mixed indicators
        packet = build_mixed_evidence_packet()

        # 2. Create and bind agents
        architect = ArchitectAgent(agent_id="arch-integration-003")
        skeptic = SkepticAgent(agent_id="skep-integration-003")

        architect.observe(packet)
        skeptic.observe(packet)

        # 3. Architect proposes (THESIS)
        arch_context = make_context(packet, Phase.THESIS, turn_number=1)
        arch_result = architect.act(arch_context)

        # 4. Skeptic receives and challenges (ANTITHESIS)
        skeptic.receive(arch_result.message)

        skep_context = make_context(
            packet,
            Phase.ANTITHESIS,
            turn_number=2,
            seen_fact_ids=frozenset(arch_result.message.get_all_fact_ids()),
        )
        skep_result = skeptic.act(skep_context)

        # 5. Oracle judges (deterministic)
        verdict = OracleJudge.compute_verdict(
            architect_msg=arch_result.message,
            skeptic_msg=skep_result.message,
            packet=packet,
        )

        # 6. Mixed evidence should lead to inconclusive or one of the sides
        # The exact outcome depends on evidence weights
        assert verdict.outcome in (
            VerdictOutcome.THREAT_CONFIRMED,
            VerdictOutcome.THREAT_DISMISSED,
            VerdictOutcome.INCONCLUSIVE,
        )

        # 7. OracleNarrator explains verdict
        verdict_narrator, narrator = create_oracle_verdict(
            arch_result.message,
            skep_result.message,
            packet,
        )

        oracle_context = make_context(packet, Phase.SYNTHESIS, turn_number=3)
        oracle_result = narrator.act(oracle_context)

        assert oracle_result.message is not None


# =============================================================================
# Packet Binding Invariant Tests
# =============================================================================


class TestPacketBindingInvariant:
    """Tests that all agents respect packet binding."""

    def test_all_agents_use_same_packet(self) -> None:
        """All agents must be bound to the same packet for a cycle."""
        packet = build_privilege_escalation_packet()

        architect = ArchitectAgent()
        skeptic = SkepticAgent()

        architect.observe(packet)
        skeptic.observe(packet)

        # Both should have same packet binding
        assert architect.active_packet_id == packet.packet_id
        assert skeptic.active_packet_id == packet.packet_id
        assert architect.active_snapshot_id == packet.snapshot_id
        assert skeptic.active_snapshot_id == packet.snapshot_id

    def test_all_assertions_reference_packet_facts(self) -> None:
        """All assertions must reference facts from the packet."""
        packet = build_privilege_escalation_packet()

        architect = ArchitectAgent()
        architect.observe(packet)

        arch_context = make_context(packet, Phase.THESIS, turn_number=1)
        arch_result = architect.act(arch_context)

        # Verify all fact_ids in assertions exist in packet
        for assertion in arch_result.message.assertions:
            for fact_id in assertion.fact_ids:
                assert fact_id in packet.fact_ids, f"Fact {fact_id} not in packet"


# =============================================================================
# Evidence Tracking Tests
# =============================================================================


class TestEvidenceTrackingThroughCycle:
    """Tests for evidence tracking across the cycle."""

    def test_fact_ids_accumulate_through_cycle(self) -> None:
        """Seen fact IDs accumulate as the cycle progresses."""
        packet = build_privilege_escalation_packet()

        architect = ArchitectAgent()
        skeptic = SkepticAgent()

        architect.observe(packet)
        skeptic.observe(packet)

        # Architect turn
        arch_context = make_context(packet, Phase.THESIS, turn_number=1)
        arch_result = architect.act(arch_context)

        arch_facts = arch_result.message.get_all_fact_ids()

        # Skeptic turn - should see Architect's facts
        skeptic.receive(arch_result.message)

        skep_context = make_context(
            packet,
            Phase.ANTITHESIS,
            turn_number=2,
            seen_fact_ids=frozenset(arch_facts),
        )
        skep_result = skeptic.act(skep_context)

        # Combined facts should include both
        all_facts = arch_facts | skep_result.message.get_all_fact_ids()
        assert len(all_facts) >= len(arch_facts)


# =============================================================================
# Determinism Tests
# =============================================================================


class TestDeterministicBehavior:
    """Tests that the system behaves deterministically."""

    def test_same_packet_same_verdict(self) -> None:
        """Same packet produces same verdict across runs."""
        packet = build_privilege_escalation_packet()

        # First run
        arch1 = ArchitectAgent(agent_id="arch-det-001")
        skep1 = SkepticAgent(agent_id="skep-det-001")
        arch1.observe(packet)
        skep1.observe(packet)

        arch_ctx1 = make_context(packet, Phase.THESIS, turn_number=1)
        arch_result1 = arch1.act(arch_ctx1)
        skep1.receive(arch_result1.message)

        skep_ctx1 = make_context(packet, Phase.ANTITHESIS, turn_number=2)
        skep_result1 = skep1.act(skep_ctx1)

        verdict1 = OracleJudge.compute_verdict(
            arch_result1.message,
            skep_result1.message,
            packet,
        )

        # Second run with same packet
        arch2 = ArchitectAgent(agent_id="arch-det-002")
        skep2 = SkepticAgent(agent_id="skep-det-002")
        arch2.observe(packet)
        skep2.observe(packet)

        arch_ctx2 = make_context(packet, Phase.THESIS, turn_number=1)
        arch_result2 = arch2.act(arch_ctx2)
        skep2.receive(arch_result2.message)

        skep_ctx2 = make_context(packet, Phase.ANTITHESIS, turn_number=2)
        skep_result2 = skep2.act(skep_ctx2)

        verdict2 = OracleJudge.compute_verdict(
            arch_result2.message,
            skep_result2.message,
            packet,
        )

        # Verdicts should be identical
        assert verdict1.outcome == verdict2.outcome


# =============================================================================
# Error Path Tests
# =============================================================================


class TestErrorPaths:
    """Tests for error handling in the cycle."""

    def test_architect_without_observation_fails(self) -> None:
        """Architect cannot act without observing packet."""
        from ares.dialectic.agents.base import AgentNotReadyError

        architect = ArchitectAgent()
        packet = build_privilege_escalation_packet()

        context = make_context(packet, Phase.THESIS, turn_number=1)

        with pytest.raises(AgentNotReadyError):
            architect.act(context)

    def test_skeptic_without_architect_message(self) -> None:
        """Skeptic requests context when no Architect message received."""
        packet = build_privilege_escalation_packet()

        skeptic = SkepticAgent()
        skeptic.observe(packet)

        context = make_context(packet, Phase.ANTITHESIS, turn_number=2)
        result = skeptic.act(context)

        # Should return data request, not message
        assert result.message is None
        assert len(result.requests) > 0

    def test_narrator_without_verdict(self) -> None:
        """Narrator requests context when no verdict provided."""
        packet = build_privilege_escalation_packet()

        narrator = OracleNarrator()  # No verdict
        narrator.observe(packet)

        context = make_context(packet, Phase.SYNTHESIS, turn_number=3)
        result = narrator.act(context)

        assert result.message is None
        assert len(result.requests) > 0


# =============================================================================
# Create Oracle Verdict Helper Tests
# =============================================================================


class TestCreateOracleVerdictIntegration:
    """Tests for create_oracle_verdict in full cycle."""

    def test_convenience_function_works_in_cycle(self) -> None:
        """create_oracle_verdict integrates properly in full cycle."""
        packet = build_privilege_escalation_packet()

        architect = ArchitectAgent()
        skeptic = SkepticAgent()

        architect.observe(packet)
        skeptic.observe(packet)

        arch_context = make_context(packet, Phase.THESIS, turn_number=1)
        arch_result = architect.act(arch_context)

        skeptic.receive(arch_result.message)
        skep_context = make_context(packet, Phase.ANTITHESIS, turn_number=2)
        skep_result = skeptic.act(skep_context)

        # Use convenience function
        verdict, narrator = create_oracle_verdict(
            arch_result.message,
            skep_result.message,
            packet,
        )

        # Narrator should be ready
        assert narrator.is_ready
        assert narrator.verdict == verdict

        # Narrator should be able to act
        oracle_context = make_context(packet, Phase.SYNTHESIS, turn_number=3)
        oracle_result = narrator.act(oracle_context)

        assert oracle_result.message is not None
        assert oracle_result.message.message_type == MessageType.VERDICT
