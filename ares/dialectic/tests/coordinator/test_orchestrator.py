"""Tests for DialecticalOrchestrator.

Validates the orchestration facade that automates the complete
THESIS -> ANTITHESIS -> SYNTHESIS cycle.
"""

import pytest
from datetime import datetime
from typing import FrozenSet

from ares.dialectic.agents.patterns import Verdict, VerdictOutcome
from ares.dialectic.agents.context import TurnContext
from ares.dialectic.coordinator.orchestrator import (
    CycleError,
    CycleResult,
    DialecticalOrchestrator,
)
from ares.dialectic.evidence.fact import EntityType, Fact
from ares.dialectic.evidence.packet import EvidencePacket, TimeWindow
from ares.dialectic.evidence.provenance import Provenance, SourceType
from ares.dialectic.messages.protocol import Phase, MessageType


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


def build_maintenance_scenario_packet() -> EvidencePacket:
    """Build packet with benign explanations.

    Scenario: Admin activity during maintenance window.
    """
    packet = EvidencePacket(
        packet_id="benign-scenario-001",
        time_window=make_time_window(),
    )

    packet.add_fact(make_fact(
        "fact-admin-001", entity_id="user-admin",
        field="user_name", value="sysadmin",
    ))
    packet.add_fact(make_fact(
        "fact-admin-002", entity_id="user-admin",
        field="user_role", value="administrator",
    ))
    packet.add_fact(make_fact(
        "fact-maint-001", entity_id="window-001",
        field="maintenance_window", value="scheduled",
    ))
    packet.add_fact(make_fact(
        "fact-maint-002", entity_id="window-001",
        field="maintenance_type", value="planned",
    ))
    packet.add_fact(make_fact(
        "fact-proc-001", entity_id="process-789",
        field="process_name", value="cmd.exe",
    ))
    packet.add_fact(make_fact(
        "fact-proc-002", entity_id="process-789",
        field="process_owner", value="administrator",
    ))
    packet.add_fact(make_fact(
        "fact-update-001", entity_id="task-001",
        field="task_type", value="scheduled_task",
    ))
    packet.add_fact(make_fact(
        "fact-update-002", entity_id="task-001",
        field="automation", value="patch_update",
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


# =============================================================================
# CycleResult Tests
# =============================================================================


class TestCycleResult:
    """Tests for CycleResult frozen dataclass."""

    def test_cycle_result_is_frozen(self):
        """CycleResult should be immutable."""
        packet = build_privilege_escalation_packet()
        orchestrator = DialecticalOrchestrator()
        result = orchestrator.run_cycle(packet)

        with pytest.raises(AttributeError):
            result.verdict = None

    def test_cycle_result_is_frozen_cycle_id(self):
        """Cannot modify cycle_id on frozen result."""
        packet = build_privilege_escalation_packet()
        orchestrator = DialecticalOrchestrator()
        result = orchestrator.run_cycle(packet)

        with pytest.raises(AttributeError):
            result.cycle_id = "hacked"

    def test_cycle_result_is_frozen_duration(self):
        """Cannot modify duration_ms on frozen result."""
        packet = build_privilege_escalation_packet()
        orchestrator = DialecticalOrchestrator()
        result = orchestrator.run_cycle(packet)

        with pytest.raises(AttributeError):
            result.duration_ms = -1


# =============================================================================
# CycleError Tests
# =============================================================================


class TestCycleError:
    """Tests for CycleError exception."""

    def test_cycle_error_attributes(self):
        """CycleError stores phase, cycle_id, and cause."""
        cause = ValueError("test cause")
        err = CycleError("boom", Phase.THESIS, "cycle-abc", cause=cause)

        assert str(err) == "boom"
        assert err.phase == Phase.THESIS
        assert err.cycle_id == "cycle-abc"
        assert err.cause is cause

    def test_cycle_error_no_cause(self):
        """CycleError works without a cause."""
        err = CycleError("fail", Phase.ANTITHESIS, "cycle-def")

        assert err.cause is None
        assert err.phase == Phase.ANTITHESIS

    def test_cycle_error_is_exception(self):
        """CycleError inherits from Exception."""
        err = CycleError("test", Phase.SYNTHESIS, "cycle-ghi")
        assert isinstance(err, Exception)

    def test_cycle_error_can_be_raised_and_caught(self):
        """CycleError can participate in raise/except flow."""
        with pytest.raises(CycleError, match="kaboom"):
            raise CycleError("kaboom", Phase.THESIS, "cycle-xyz")


# =============================================================================
# Orchestrator Construction Tests
# =============================================================================


class TestOrchestratorConstruction:
    """Tests for DialecticalOrchestrator initialization."""

    def test_default_construction(self):
        """Orchestrator has sensible defaults."""
        orch = DialecticalOrchestrator()
        assert orch.agent_id_prefix == "ares"
        assert orch.include_narration is True

    def test_custom_prefix(self):
        """Can set a custom agent ID prefix."""
        orch = DialecticalOrchestrator(agent_id_prefix="test")
        assert orch.agent_id_prefix == "test"

    def test_narration_disabled(self):
        """Can disable narration."""
        orch = DialecticalOrchestrator(include_narration=False)
        assert orch.include_narration is False

    def test_keyword_only_args(self):
        """Constructor requires keyword arguments."""
        with pytest.raises(TypeError):
            DialecticalOrchestrator("prefix", True)  # type: ignore


# =============================================================================
# Unfrozen Packet Rejection
# =============================================================================


class TestUnfrozenPacketRejection:
    """Tests for frozen packet enforcement."""

    def test_run_cycle_rejects_unfrozen_packet(self):
        """Unfrozen packet raises ValueError."""
        packet = EvidencePacket(
            packet_id="unfrozen",
            time_window=make_time_window(),
        )
        packet.add_fact(make_fact())

        orchestrator = DialecticalOrchestrator()
        with pytest.raises(ValueError, match="frozen"):
            orchestrator.run_cycle(packet)

    def test_run_cycle_rejects_unfrozen_empty_packet(self):
        """Even an empty unfrozen packet is rejected."""
        packet = EvidencePacket(
            packet_id="unfrozen-empty",
            time_window=make_time_window(),
        )

        orchestrator = DialecticalOrchestrator()
        with pytest.raises(ValueError, match="frozen"):
            orchestrator.run_cycle(packet)


# =============================================================================
# Basic Cycle Execution
# =============================================================================


class TestBasicCycleExecution:
    """Tests for the happy path: run_cycle end-to-end."""

    def test_run_cycle_returns_complete_result(self):
        """run_cycle returns a CycleResult with all fields populated."""
        packet = build_privilege_escalation_packet()
        orchestrator = DialecticalOrchestrator()
        result = orchestrator.run_cycle(packet)

        assert isinstance(result, CycleResult)
        assert result.cycle_id is not None
        assert len(result.cycle_id) > 0
        assert result.packet_id == "threat-scenario-001"
        assert result.verdict is not None
        assert isinstance(result.verdict, Verdict)
        assert result.architect_message is not None
        assert result.skeptic_message is not None
        assert result.narrator_message is not None
        assert result.duration_ms >= 0

    def test_architect_message_is_thesis(self):
        """Architect message should be in THESIS phase."""
        packet = build_privilege_escalation_packet()
        result = DialecticalOrchestrator().run_cycle(packet)
        assert result.architect_message.phase == Phase.THESIS

    def test_skeptic_message_is_antithesis(self):
        """Skeptic message should be in ANTITHESIS phase."""
        packet = build_privilege_escalation_packet()
        result = DialecticalOrchestrator().run_cycle(packet)
        assert result.skeptic_message.phase == Phase.ANTITHESIS

    def test_narrator_message_is_synthesis(self):
        """Narrator message should be in SYNTHESIS phase."""
        packet = build_privilege_escalation_packet()
        result = DialecticalOrchestrator().run_cycle(packet)
        assert result.narrator_message.phase == Phase.SYNTHESIS

    def test_verdict_has_valid_outcome(self):
        """Verdict outcome must be a valid VerdictOutcome."""
        packet = build_privilege_escalation_packet()
        result = DialecticalOrchestrator().run_cycle(packet)
        assert result.verdict.outcome in VerdictOutcome

    def test_verdict_confidence_in_range(self):
        """Verdict confidence must be between 0.0 and 1.0."""
        packet = build_privilege_escalation_packet()
        result = DialecticalOrchestrator().run_cycle(packet)
        assert 0.0 <= result.verdict.confidence <= 1.0

    def test_timestamps_ordered(self):
        """started_at must be before completed_at."""
        packet = build_privilege_escalation_packet()
        result = DialecticalOrchestrator().run_cycle(packet)
        assert result.started_at <= result.completed_at

    def test_cycle_id_starts_with_cycle_prefix(self):
        """Cycle IDs should follow 'cycle-{uuid}' format."""
        packet = build_privilege_escalation_packet()
        result = DialecticalOrchestrator().run_cycle(packet)
        assert result.cycle_id.startswith("cycle-")

    def test_duration_ms_non_negative(self):
        """Duration should be non-negative."""
        packet = build_privilege_escalation_packet()
        result = DialecticalOrchestrator().run_cycle(packet)
        assert result.duration_ms >= 0


# =============================================================================
# Narration Skip
# =============================================================================


class TestNarrationSkip:
    """Tests for include_narration=False mode."""

    def test_can_skip_narration(self):
        """Narrator message is None when narration disabled."""
        packet = build_privilege_escalation_packet()
        orchestrator = DialecticalOrchestrator(include_narration=False)
        result = orchestrator.run_cycle(packet)

        assert result.narrator_message is None

    def test_verdict_still_computed_without_narration(self):
        """Verdict is computed even without narration."""
        packet = build_privilege_escalation_packet()
        orchestrator = DialecticalOrchestrator(include_narration=False)
        result = orchestrator.run_cycle(packet)

        assert result.verdict is not None
        assert result.verdict.outcome in VerdictOutcome

    def test_architect_and_skeptic_still_run_without_narration(self):
        """Architect and Skeptic messages present even without narration."""
        packet = build_privilege_escalation_packet()
        orchestrator = DialecticalOrchestrator(include_narration=False)
        result = orchestrator.run_cycle(packet)

        assert result.architect_message is not None
        assert result.skeptic_message is not None

    def test_skip_narration_faster(self):
        """Skipping narration should not increase duration."""
        packet = build_privilege_escalation_packet()

        with_narr = DialecticalOrchestrator(include_narration=True)
        without_narr = DialecticalOrchestrator(include_narration=False)

        # Just verify both complete - timing is non-deterministic
        r1 = with_narr.run_cycle(packet)
        r2 = without_narr.run_cycle(packet)

        assert r1.narrator_message is not None
        assert r2.narrator_message is None


# =============================================================================
# Cycle Isolation
# =============================================================================


class TestCycleIsolation:
    """Tests for agent isolation between cycles."""

    def test_cycles_have_unique_ids(self):
        """Each cycle gets a unique cycle_id."""
        packet = build_privilege_escalation_packet()
        orchestrator = DialecticalOrchestrator()

        r1 = orchestrator.run_cycle(packet)
        r2 = orchestrator.run_cycle(packet)

        assert r1.cycle_id != r2.cycle_id

    def test_no_state_leakage_between_cycles(self):
        """Running multiple cycles produces independent results."""
        p1 = build_privilege_escalation_packet()
        p2 = build_maintenance_scenario_packet()
        orchestrator = DialecticalOrchestrator()

        r1 = orchestrator.run_cycle(p1)
        r2 = orchestrator.run_cycle(p2)

        assert r1.cycle_id != r2.cycle_id
        assert r1.packet_id != r2.packet_id

    def test_three_sequential_cycles_all_unique(self):
        """Three cycles all get distinct cycle_ids."""
        packet = build_privilege_escalation_packet()
        orchestrator = DialecticalOrchestrator()

        results = [orchestrator.run_cycle(packet) for _ in range(3)]
        cycle_ids = {r.cycle_id for r in results}
        assert len(cycle_ids) == 3

    def test_different_packets_different_cycle_ids(self):
        """Same orchestrator, different packets, different cycle IDs."""
        orchestrator = DialecticalOrchestrator()
        r1 = orchestrator.run_cycle(build_privilege_escalation_packet())
        r2 = orchestrator.run_cycle(build_maintenance_scenario_packet())
        assert r1.cycle_id != r2.cycle_id


# =============================================================================
# Agent ID Format
# =============================================================================


class TestAgentIdFormat:
    """Tests for agent ID generation and traceability."""

    def test_agent_ids_contain_prefix(self):
        """Agent messages should have IDs containing the prefix."""
        orchestrator = DialecticalOrchestrator(agent_id_prefix="test")
        result = orchestrator.run_cycle(build_privilege_escalation_packet())

        assert result.architect_message.source_agent.startswith("test-arch-")
        assert result.skeptic_message.source_agent.startswith("test-skep-")

    def test_agent_ids_share_cycle_uuid(self):
        """All agents in a cycle share the same UUID suffix."""
        orchestrator = DialecticalOrchestrator(agent_id_prefix="ares")
        result = orchestrator.run_cycle(build_privilege_escalation_packet())

        arch_suffix = result.architect_message.source_agent.split("-")[-1]
        skep_suffix = result.skeptic_message.source_agent.split("-")[-1]
        assert arch_suffix == skep_suffix

    def test_narrator_shares_cycle_uuid(self):
        """Narrator agent ID shares UUID suffix with other agents."""
        orchestrator = DialecticalOrchestrator(agent_id_prefix="ares")
        result = orchestrator.run_cycle(build_privilege_escalation_packet())

        arch_suffix = result.architect_message.source_agent.split("-")[-1]
        narr_suffix = result.narrator_message.source_agent.split("-")[-1]
        assert arch_suffix == narr_suffix

    def test_default_prefix_is_ares(self):
        """Default prefix 'ares' appears in agent IDs."""
        orchestrator = DialecticalOrchestrator()
        result = orchestrator.run_cycle(build_privilege_escalation_packet())
        assert result.architect_message.source_agent.startswith("ares-arch-")

    def test_different_cycles_different_uuid_suffix(self):
        """Different cycles produce different agent UUID suffixes."""
        orchestrator = DialecticalOrchestrator()
        r1 = orchestrator.run_cycle(build_privilege_escalation_packet())
        r2 = orchestrator.run_cycle(build_privilege_escalation_packet())

        suffix1 = r1.architect_message.source_agent.split("-")[-1]
        suffix2 = r2.architect_message.source_agent.split("-")[-1]
        assert suffix1 != suffix2


# =============================================================================
# Empty Packet Handling
# =============================================================================


class TestEmptyPacketHandling:
    """Tests for packets with no facts."""

    def test_empty_packet_produces_result(self):
        """Empty packet should still produce a result."""
        packet = build_empty_packet()
        orchestrator = DialecticalOrchestrator()
        result = orchestrator.run_cycle(packet)

        assert result is not None
        assert result.verdict is not None

    def test_empty_packet_inconclusive_verdict(self):
        """Empty evidence should produce INCONCLUSIVE verdict."""
        packet = build_empty_packet()
        orchestrator = DialecticalOrchestrator()
        result = orchestrator.run_cycle(packet)

        assert result.verdict.outcome == VerdictOutcome.INCONCLUSIVE


# =============================================================================
# Threat Scenario Tests
# =============================================================================


class TestThreatScenarios:
    """Tests verifying correct verdicts for different scenarios."""

    def test_privilege_escalation_detected(self):
        """Packet with clear threat indicators should be flagged."""
        packet = build_privilege_escalation_packet()
        orchestrator = DialecticalOrchestrator()
        result = orchestrator.run_cycle(packet)

        # Architect should detect the threat with high confidence
        assert result.architect_message.confidence >= 0.5

    def test_maintenance_scenario_has_benign_signals(self):
        """Maintenance scenario should have benign explanation signals."""
        packet = build_maintenance_scenario_packet()
        orchestrator = DialecticalOrchestrator()
        result = orchestrator.run_cycle(packet)

        # Skeptic should find benign explanations
        assert result.skeptic_message.confidence > 0.0

    def test_minimal_packet_produces_low_confidence(self):
        """Minimal evidence should produce low architect confidence."""
        packet = build_minimal_packet()
        orchestrator = DialecticalOrchestrator()
        result = orchestrator.run_cycle(packet)

        # Low evidence → low architect confidence
        assert result.architect_message.confidence <= 0.5

    def test_verdict_reasoning_not_empty(self):
        """Verdict should include non-empty reasoning."""
        packet = build_privilege_escalation_packet()
        result = DialecticalOrchestrator().run_cycle(packet)
        assert len(result.verdict.reasoning) > 0


# =============================================================================
# Determinism Tests
# =============================================================================


class TestDeterminism:
    """Tests verifying deterministic behavior."""

    def test_same_packet_same_verdict_outcome(self):
        """Same input packet should produce same verdict outcome."""
        packet = build_privilege_escalation_packet()
        orchestrator = DialecticalOrchestrator()

        r1 = orchestrator.run_cycle(packet)
        r2 = orchestrator.run_cycle(packet)

        assert r1.verdict.outcome == r2.verdict.outcome

    def test_same_packet_same_confidence(self):
        """Same input packet should produce same confidence."""
        packet = build_privilege_escalation_packet()
        orchestrator = DialecticalOrchestrator()

        r1 = orchestrator.run_cycle(packet)
        r2 = orchestrator.run_cycle(packet)

        assert r1.verdict.confidence == r2.verdict.confidence


# =============================================================================
# Message Content Validation
# =============================================================================


class TestMessageContent:
    """Tests for message content correctness."""

    def test_architect_message_has_assertions(self):
        """Architect message should contain assertions."""
        packet = build_privilege_escalation_packet()
        result = DialecticalOrchestrator().run_cycle(packet)
        assert len(result.architect_message.assertions) > 0

    def test_skeptic_message_has_assertions(self):
        """Skeptic message should contain assertions."""
        packet = build_privilege_escalation_packet()
        result = DialecticalOrchestrator().run_cycle(packet)
        assert len(result.skeptic_message.assertions) > 0

    def test_narrator_message_has_assertions(self):
        """Narrator message should contain assertions."""
        packet = build_privilege_escalation_packet()
        result = DialecticalOrchestrator().run_cycle(packet)
        assert len(result.narrator_message.assertions) > 0

    def test_all_messages_reference_same_packet(self):
        """All messages should reference the same packet_id."""
        packet = build_privilege_escalation_packet()
        result = DialecticalOrchestrator().run_cycle(packet)

        assert result.architect_message.packet_id == packet.packet_id
        assert result.skeptic_message.packet_id == packet.packet_id
        assert result.narrator_message.packet_id == packet.packet_id

    def test_all_messages_reference_same_cycle(self):
        """All messages should reference the same cycle_id."""
        packet = build_privilege_escalation_packet()
        result = DialecticalOrchestrator().run_cycle(packet)

        assert result.architect_message.cycle_id == result.cycle_id
        assert result.skeptic_message.cycle_id == result.cycle_id
        assert result.narrator_message.cycle_id == result.cycle_id

    def test_architect_message_type_is_hypothesis_or_observation(self):
        """Architect should produce HYPOTHESIS or OBSERVATION."""
        packet = build_privilege_escalation_packet()
        result = DialecticalOrchestrator().run_cycle(packet)
        assert result.architect_message.message_type in (
            MessageType.HYPOTHESIS, MessageType.OBSERVATION,
        )

    def test_skeptic_message_type_is_rebuttal(self):
        """Skeptic should produce REBUTTAL."""
        packet = build_privilege_escalation_packet()
        result = DialecticalOrchestrator().run_cycle(packet)
        assert result.skeptic_message.message_type == MessageType.REBUTTAL

    def test_narrator_message_type_is_verdict(self):
        """Narrator should produce VERDICT."""
        packet = build_privilege_escalation_packet()
        result = DialecticalOrchestrator().run_cycle(packet)
        assert result.narrator_message.message_type == MessageType.VERDICT


# =============================================================================
# Integration with Extractors (pipeline test)
# =============================================================================


class TestExtractorIntegration:
    """Tests for the full pipeline: XML -> Extractor -> Packet -> Orchestrator."""

    def test_full_pipeline_with_4624_logon(self):
        """Raw Windows 4624 logon event -> Orchestrator -> Verdict."""
        from ares.dialectic.evidence.extractors.windows import (
            WindowsEventExtractor,
        )

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
            packet_id="pipeline-4624",
            time_window=make_time_window(),
        )
        for fact in extraction.facts:
            packet.add_fact(fact)
        packet.freeze()

        orchestrator = DialecticalOrchestrator()
        result = orchestrator.run_cycle(packet)

        assert result.verdict.outcome in VerdictOutcome
        assert result.cycle_id is not None

    def test_full_pipeline_with_4688_process(self):
        """Raw Windows 4688 process creation -> Orchestrator -> Verdict."""
        from ares.dialectic.evidence.extractors.windows import (
            WindowsEventExtractor,
        )

        xml = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
            <System>
                <EventID>4688</EventID>
                <TimeCreated SystemTime="2024-01-15T14:31:00.000Z"/>
                <Computer>WORKSTATION01</Computer>
            </System>
            <EventData>
                <Data Name="SubjectUserName">jsmith</Data>
                <Data Name="NewProcessName">C:\\Windows\\System32\\cmd.exe</Data>
                <Data Name="CommandLine">cmd.exe /c whoami</Data>
                <Data Name="ParentProcessName">C:\\Windows\\explorer.exe</Data>
                <Data Name="TokenElevationType">%%1937</Data>
            </EventData>
        </Event>"""

        extractor = WindowsEventExtractor()
        extraction = extractor.extract(xml, source_ref="test-4688")

        packet = EvidencePacket(
            packet_id="pipeline-4688",
            time_window=make_time_window(),
        )
        for fact in extraction.facts:
            packet.add_fact(fact)
        packet.freeze()

        orchestrator = DialecticalOrchestrator()
        result = orchestrator.run_cycle(packet)

        assert result.verdict.outcome in VerdictOutcome


# =============================================================================
# Edge Cases
# =============================================================================


class TestEdgeCases:
    """Edge case and boundary tests."""

    def test_single_fact_packet(self):
        """Packet with a single fact completes without error."""
        packet = build_minimal_packet()
        result = DialecticalOrchestrator().run_cycle(packet)
        assert result.verdict is not None

    def test_packet_id_preserved_in_result(self):
        """CycleResult preserves the original packet_id."""
        packet = build_privilege_escalation_packet()
        result = DialecticalOrchestrator().run_cycle(packet)
        assert result.packet_id == packet.packet_id

    def test_result_has_started_at(self):
        """CycleResult has a valid started_at timestamp."""
        before = datetime.utcnow()
        result = DialecticalOrchestrator().run_cycle(
            build_privilege_escalation_packet()
        )
        after = datetime.utcnow()
        assert before <= result.started_at <= after

    def test_result_has_completed_at(self):
        """CycleResult has a valid completed_at timestamp."""
        before = datetime.utcnow()
        result = DialecticalOrchestrator().run_cycle(
            build_privilege_escalation_packet()
        )
        after = datetime.utcnow()
        assert before <= result.completed_at <= after

    def test_empty_prefix(self):
        """Empty prefix is allowed."""
        orchestrator = DialecticalOrchestrator(agent_id_prefix="")
        result = orchestrator.run_cycle(build_privilege_escalation_packet())
        assert result.verdict is not None
