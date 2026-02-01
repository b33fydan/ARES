"""Tests for SkepticAgent - ANTITHESIS phase counter-argument generator."""

import pytest
from datetime import datetime
from typing import FrozenSet

from ares.dialectic.agents import (
    SkepticAgent,
    ArchitectAgent,
    AgentRole,
    AgentState,
    Phase,
    TurnContext,
    ExplanationType,
    PhaseViolationError,
)
from ares.dialectic.evidence.packet import EvidencePacket, TimeWindow
from ares.dialectic.evidence.fact import Fact, EntityType
from ares.dialectic.evidence.provenance import Provenance, SourceType
from ares.dialectic.messages.protocol import MessageType, DialecticalMessage, MessageBuilder
from ares.dialectic.messages.assertions import Assertion, AssertionType


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


def make_packet(packet_id: str = "packet-001", frozen: bool = True) -> EvidencePacket:
    """Create a basic test evidence packet."""
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
    phase: Phase = Phase.ANTITHESIS,
    turn_number: int = 2,
    max_turns: int = 10,
    prior_messages: tuple = (),
    seen_fact_ids: FrozenSet[str] = frozenset(),
) -> TurnContext:
    """Create a test TurnContext instance for ANTITHESIS phase."""
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


def make_architect_message(
    packet_id: str = "packet-001",
    cycle_id: str = "cycle-001",
    fact_ids: tuple = ("fact-001",),
    confidence: float = 0.7,
) -> DialecticalMessage:
    """Create a mock Architect HYPOTHESIS message."""
    builder = MessageBuilder(
        source_agent="architect-001",
        packet_id=packet_id,
        cycle_id=cycle_id,
    )
    builder.set_phase(Phase.THESIS)
    builder.set_turn(1)
    builder.set_type(MessageType.HYPOTHESIS)
    builder.set_confidence(confidence)

    assertion = Assertion(
        assertion_id="hyp-001",
        assertion_type=AssertionType.ASSERT,
        fact_ids=fact_ids,
        interpretation="Threat detected",
        operator="detected",
        threshold="threat",
    )
    builder.add_assertion(assertion)
    builder.set_narrative("Suspicious activity detected.")

    return builder.build()


# =============================================================================
# Tests for SkepticAgent Basic Properties
# =============================================================================


class TestSkepticAgentBasics:
    """Tests for basic SkepticAgent properties."""

    def test_role_is_skeptic(self) -> None:
        """SkepticAgent has SKEPTIC role."""
        agent = SkepticAgent()
        assert agent.role == AgentRole.SKEPTIC

    def test_default_agent_id(self) -> None:
        """Default agent ID starts with 'skeptic-'."""
        agent = SkepticAgent()
        assert agent.agent_id.startswith("skeptic-")

    def test_custom_agent_id(self) -> None:
        """Custom agent ID is used when provided."""
        agent = SkepticAgent(agent_id="my-skeptic")
        assert agent.agent_id == "my-skeptic"

    def test_initial_state_is_idle(self) -> None:
        """Agent starts in IDLE state."""
        agent = SkepticAgent()
        assert agent.state == AgentState.IDLE

    def test_observe_transitions_to_ready(self) -> None:
        """observe() transitions agent to READY state."""
        agent = SkepticAgent()
        packet = make_packet()
        agent.observe(packet)
        assert agent.state == AgentState.READY


# =============================================================================
# Tests for Phase Enforcement
# =============================================================================


class TestSkepticPhaseEnforcement:
    """Tests that Skeptic can only act in ANTITHESIS phase."""

    def test_can_act_in_antithesis(self) -> None:
        """Skeptic can act in ANTITHESIS phase."""
        agent = SkepticAgent()
        packet = make_packet()
        agent.observe(packet)

        # Give the Skeptic an Architect message to respond to
        arch_msg = make_architect_message(packet_id=packet.packet_id)
        agent.receive(arch_msg)

        context = make_turn_context(
            packet_id=packet.packet_id,
            snapshot_id=packet.snapshot_id,
            phase=Phase.ANTITHESIS,
        )

        result = agent.act(context)
        assert result.has_error is False

    def test_cannot_act_in_thesis(self) -> None:
        """Skeptic raises PhaseViolationError in THESIS phase."""
        agent = SkepticAgent()
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
        assert exc_info.value.current_phase == Phase.THESIS

    def test_cannot_act_in_synthesis(self) -> None:
        """Skeptic raises PhaseViolationError in SYNTHESIS phase."""
        agent = SkepticAgent()
        packet = make_packet()
        agent.observe(packet)

        context = make_turn_context(
            packet_id=packet.packet_id,
            snapshot_id=packet.snapshot_id,
            phase=Phase.SYNTHESIS,
        )

        with pytest.raises(PhaseViolationError):
            agent.act(context)


# =============================================================================
# Tests for Maintenance Window Detection
# =============================================================================


class TestMaintenanceWindowDetection:
    """Tests for maintenance window benign explanation detection."""

    def test_detects_maintenance_in_field(self) -> None:
        """Detects maintenance window when 'maintenance' in field name."""
        packet = EvidencePacket(packet_id="maint-001", time_window=make_time_window())
        packet.add_fact(make_fact("fact-001", field="maintenance_window", value="active"))
        packet.add_fact(make_fact("fact-002", field="process", value="cmd.exe"))
        packet.freeze()

        agent = SkepticAgent()
        agent.observe(packet)

        facts_by_field = {}
        for fact in packet.get_all_facts():
            field = fact.field.lower()
            if field not in facts_by_field:
                facts_by_field[field] = []
            facts_by_field[field].append(fact)

        result = agent._check_maintenance_window(packet, facts_by_field)
        assert result is not None
        assert result.explanation_type == ExplanationType.MAINTENANCE_WINDOW

    def test_detects_scheduled_in_value(self) -> None:
        """Detects maintenance window when 'scheduled' in value."""
        packet = EvidencePacket(packet_id="maint-002", time_window=make_time_window())
        packet.add_fact(make_fact("fact-001", field="event_type", value="scheduled_maintenance"))
        packet.freeze()

        agent = SkepticAgent()
        agent.observe(packet)

        facts_by_field = {"event_type": [packet.get_fact("fact-001")]}
        result = agent._check_maintenance_window(packet, facts_by_field)
        assert result is not None


# =============================================================================
# Tests for Known Admin Detection
# =============================================================================


class TestKnownAdminDetection:
    """Tests for known admin benign explanation detection."""

    def test_detects_admin_user(self) -> None:
        """Detects known admin activity."""
        packet = EvidencePacket(packet_id="admin-001", time_window=make_time_window())
        packet.add_fact(make_fact("fact-001", field="user_type", value="administrator"))
        packet.add_fact(make_fact("fact-002", field="admin_account", value=True))
        packet.freeze()

        agent = SkepticAgent()
        agent.observe(packet)

        facts_by_field = {}
        for fact in packet.get_all_facts():
            field = fact.field.lower()
            if field not in facts_by_field:
                facts_by_field[field] = []
            facts_by_field[field].append(fact)

        result = agent._check_known_admin(packet, facts_by_field)
        assert result is not None
        assert result.explanation_type == ExplanationType.KNOWN_ADMIN

    def test_detects_service_account(self) -> None:
        """Detects service account as known admin."""
        packet = EvidencePacket(packet_id="admin-002", time_window=make_time_window())
        packet.add_fact(make_fact("fact-001", field="account", value="service_account_deployment"))
        packet.freeze()

        agent = SkepticAgent()
        agent.observe(packet)

        facts_by_field = {"account": [packet.get_fact("fact-001")]}
        result = agent._check_known_admin(packet, facts_by_field)
        assert result is not None


# =============================================================================
# Tests for Scheduled Task Detection
# =============================================================================


class TestScheduledTaskDetection:
    """Tests for scheduled task benign explanation detection."""

    def test_detects_cron_job(self) -> None:
        """Detects cron job as scheduled task."""
        packet = EvidencePacket(packet_id="sched-001", time_window=make_time_window())
        packet.add_fact(make_fact("fact-001", field="cron_job", value="backup_script"))
        packet.freeze()

        agent = SkepticAgent()
        agent.observe(packet)

        facts_by_field = {"cron_job": [packet.get_fact("fact-001")]}
        result = agent._check_scheduled_task(packet, facts_by_field)
        assert result is not None
        assert result.explanation_type == ExplanationType.SCHEDULED_TASK

    def test_detects_automated_task(self) -> None:
        """Detects automated task."""
        packet = EvidencePacket(packet_id="sched-002", time_window=make_time_window())
        packet.add_fact(make_fact("fact-001", field="task_type", value="automated"))
        packet.add_fact(make_fact("fact-002", field="job_scheduler", value="task_scheduler"))
        packet.freeze()

        agent = SkepticAgent()
        agent.observe(packet)

        facts_by_field = {}
        for fact in packet.get_all_facts():
            field = fact.field.lower()
            if field not in facts_by_field:
                facts_by_field[field] = []
            facts_by_field[field].append(fact)

        result = agent._check_scheduled_task(packet, facts_by_field)
        assert result is not None


# =============================================================================
# Tests for Software Update Detection
# =============================================================================


class TestSoftwareUpdateDetection:
    """Tests for software update benign explanation detection."""

    def test_detects_windows_update(self) -> None:
        """Detects Windows Update."""
        packet = EvidencePacket(packet_id="upd-001", time_window=make_time_window())
        packet.add_fact(make_fact("fact-001", field="service", value="windows_update"))
        packet.freeze()

        agent = SkepticAgent()
        agent.observe(packet)

        facts_by_field = {"service": [packet.get_fact("fact-001")]}
        result = agent._check_software_update(packet, facts_by_field)
        assert result is not None
        assert result.explanation_type == ExplanationType.SOFTWARE_UPDATE

    def test_detects_patch_activity(self) -> None:
        """Detects patching activity."""
        packet = EvidencePacket(packet_id="upd-002", time_window=make_time_window())
        packet.add_fact(make_fact("fact-001", field="activity", value="security_patch"))
        packet.add_fact(make_fact("fact-002", field="hotfix", value="KB12345"))
        packet.freeze()

        agent = SkepticAgent()
        agent.observe(packet)

        facts_by_field = {}
        for fact in packet.get_all_facts():
            field = fact.field.lower()
            if field not in facts_by_field:
                facts_by_field[field] = []
            facts_by_field[field].append(fact)

        result = agent._check_software_update(packet, facts_by_field)
        assert result is not None


# =============================================================================
# Tests for Legitimate Remote Access Detection
# =============================================================================


class TestLegitimateRemoteDetection:
    """Tests for legitimate remote access benign explanation detection."""

    def test_detects_vpn_access(self) -> None:
        """Detects VPN access as legitimate."""
        packet = EvidencePacket(packet_id="remote-001", time_window=make_time_window())
        packet.add_fact(make_fact("fact-001", field="vpn_connection", value="active"))
        packet.add_fact(make_fact("fact-002", field="authorized_access", value=True))
        packet.freeze()

        agent = SkepticAgent()
        agent.observe(packet)

        facts_by_field = {}
        for fact in packet.get_all_facts():
            field = fact.field.lower()
            if field not in facts_by_field:
                facts_by_field[field] = []
            facts_by_field[field].append(fact)

        result = agent._check_legitimate_remote(packet, facts_by_field)
        assert result is not None
        assert result.explanation_type == ExplanationType.LEGITIMATE_REMOTE_ACCESS

    def test_detects_authorized_access(self) -> None:
        """Detects authorized remote access."""
        packet = EvidencePacket(packet_id="remote-002", time_window=make_time_window())
        packet.add_fact(make_fact("fact-001", field="authorization", value="approved"))
        packet.add_fact(make_fact("fact-002", field="change_request", value="CHG12345"))
        packet.freeze()

        agent = SkepticAgent()
        agent.observe(packet)

        facts_by_field = {}
        for fact in packet.get_all_facts():
            field = fact.field.lower()
            if field not in facts_by_field:
                facts_by_field[field] = []
            facts_by_field[field].append(fact)

        result = agent._check_legitimate_remote(packet, facts_by_field)
        assert result is not None


# =============================================================================
# Tests for Security Tool Detection
# =============================================================================


class TestSecurityToolDetection:
    """Tests for security tool benign explanation detection."""

    def test_detects_antivirus(self) -> None:
        """Detects antivirus as security tool."""
        packet = EvidencePacket(packet_id="sec-001", time_window=make_time_window())
        packet.add_fact(make_fact("fact-001", field="process", value="antivirus_scanner"))
        packet.freeze()

        agent = SkepticAgent()
        agent.observe(packet)

        facts_by_field = {"process": [packet.get_fact("fact-001")]}
        result = agent._check_security_tool(packet, facts_by_field)
        assert result is not None
        assert result.explanation_type == ExplanationType.SECURITY_TOOL

    def test_detects_edr(self) -> None:
        """Detects EDR as security tool."""
        packet = EvidencePacket(packet_id="sec-002", time_window=make_time_window())
        packet.add_fact(make_fact("fact-001", field="edr_tool", value="crowdstrike"))
        packet.add_fact(make_fact("fact-002", field="security_scan", value="active"))
        packet.freeze()

        agent = SkepticAgent()
        agent.observe(packet)

        facts_by_field = {}
        for fact in packet.get_all_facts():
            field = fact.field.lower()
            if field not in facts_by_field:
                facts_by_field[field] = []
            facts_by_field[field].append(fact)

        result = agent._check_security_tool(packet, facts_by_field)
        assert result is not None


# =============================================================================
# Tests for Development Activity Detection
# =============================================================================


class TestDevelopmentActivityDetection:
    """Tests for development activity benign explanation detection."""

    def test_detects_development_environment(self) -> None:
        """Detects development environment."""
        packet = EvidencePacket(packet_id="dev-001", time_window=make_time_window())
        packet.add_fact(make_fact("fact-001", field="environment", value="development"))
        packet.freeze()

        agent = SkepticAgent()
        agent.observe(packet)

        facts_by_field = {"environment": [packet.get_fact("fact-001")]}
        result = agent._check_development_activity(packet, facts_by_field)
        assert result is not None
        assert result.explanation_type == ExplanationType.DEVELOPMENT_ACTIVITY

    def test_detects_ide_activity(self) -> None:
        """Detects IDE as development activity."""
        packet = EvidencePacket(packet_id="dev-002", time_window=make_time_window())
        packet.add_fact(make_fact("fact-001", field="developer_tool", value="vscode"))
        packet.add_fact(make_fact("fact-002", field="development_activity", value=True))
        packet.freeze()

        agent = SkepticAgent()
        agent.observe(packet)

        facts_by_field = {}
        for fact in packet.get_all_facts():
            field = fact.field.lower()
            if field not in facts_by_field:
                facts_by_field[field] = []
            facts_by_field[field].append(fact)

        result = agent._check_development_activity(packet, facts_by_field)
        assert result is not None


# =============================================================================
# Tests for Backup Activity Detection
# =============================================================================


class TestBackupActivityDetection:
    """Tests for backup activity benign explanation detection."""

    def test_detects_backup_operation(self) -> None:
        """Detects backup operation."""
        packet = EvidencePacket(packet_id="backup-001", time_window=make_time_window())
        packet.add_fact(make_fact("fact-001", field="backup_operation", value="scheduled"))
        packet.add_fact(make_fact("fact-002", field="backup_job", value="nightly"))
        packet.freeze()

        agent = SkepticAgent()
        agent.observe(packet)

        facts_by_field = {}
        for fact in packet.get_all_facts():
            field = fact.field.lower()
            if field not in facts_by_field:
                facts_by_field[field] = []
            facts_by_field[field].append(fact)

        result = agent._check_backup_activity(packet, facts_by_field)
        assert result is not None
        assert result.explanation_type == ExplanationType.AUTOMATED_BACKUP

    def test_detects_veeam(self) -> None:
        """Detects Veeam as backup tool."""
        packet = EvidencePacket(packet_id="backup-002", time_window=make_time_window())
        packet.add_fact(make_fact("fact-001", field="backup_tool", value="veeam"))
        packet.add_fact(make_fact("fact-002", field="restore_point", value="created"))
        packet.freeze()

        agent = SkepticAgent()
        agent.observe(packet)

        facts_by_field = {}
        for fact in packet.get_all_facts():
            field = fact.field.lower()
            if field not in facts_by_field:
                facts_by_field[field] = []
            facts_by_field[field].append(fact)

        result = agent._check_backup_activity(packet, facts_by_field)
        assert result is not None


# =============================================================================
# Tests for Message Composition
# =============================================================================


class TestSkepticMessageComposition:
    """Tests for REBUTTAL message composition."""

    def test_produces_rebuttal_message(self) -> None:
        """Skeptic produces REBUTTAL message."""
        packet = EvidencePacket(packet_id="msg-001", time_window=make_time_window())
        packet.add_fact(make_fact("fact-001", field="maintenance", value="active"))
        packet.add_fact(make_fact("fact-002", field="process", value="cmd.exe"))
        packet.freeze()

        agent = SkepticAgent()
        agent.observe(packet)

        # Receive Architect's message
        arch_msg = make_architect_message(
            packet_id=packet.packet_id,
            fact_ids=("fact-002",),
        )
        agent.receive(arch_msg)

        context = make_turn_context(
            packet_id=packet.packet_id,
            snapshot_id=packet.snapshot_id,
        )

        result = agent.act(context)
        assert result.message is not None
        assert result.message.message_type == MessageType.REBUTTAL

    def test_message_has_assertions(self) -> None:
        """Rebuttal message contains assertions."""
        packet = EvidencePacket(packet_id="msg-002", time_window=make_time_window())
        packet.add_fact(make_fact("fact-001", field="admin", value="sysadmin"))
        packet.freeze()

        agent = SkepticAgent()
        agent.observe(packet)

        arch_msg = make_architect_message(
            packet_id=packet.packet_id,
            fact_ids=("fact-001",),
        )
        agent.receive(arch_msg)

        context = make_turn_context(
            packet_id=packet.packet_id,
            snapshot_id=packet.snapshot_id,
        )

        result = agent.act(context)
        assert len(result.message.assertions) > 0

    def test_message_phase_is_antithesis(self) -> None:
        """Message phase is set to ANTITHESIS."""
        packet = EvidencePacket(packet_id="msg-003", time_window=make_time_window())
        packet.add_fact(make_fact("fact-001", field="data", value="test"))
        packet.freeze()

        agent = SkepticAgent()
        agent.observe(packet)

        arch_msg = make_architect_message(
            packet_id=packet.packet_id,
            fact_ids=("fact-001",),
        )
        agent.receive(arch_msg)

        context = make_turn_context(
            packet_id=packet.packet_id,
            snapshot_id=packet.snapshot_id,
        )

        result = agent.act(context)
        assert result.message.phase == Phase.ANTITHESIS

    def test_message_references_architect(self) -> None:
        """Rebuttal message references Architect's message."""
        packet = EvidencePacket(packet_id="msg-004", time_window=make_time_window())
        packet.add_fact(make_fact("fact-001", field="data", value="test"))
        packet.freeze()

        agent = SkepticAgent()
        agent.observe(packet)

        arch_msg = make_architect_message(
            packet_id=packet.packet_id,
            fact_ids=("fact-001",),
        )
        agent.receive(arch_msg)

        context = make_turn_context(
            packet_id=packet.packet_id,
            snapshot_id=packet.snapshot_id,
        )

        result = agent.act(context)
        assert result.message.reply_to == arch_msg.message_id

    def test_alt_assertions_for_benign_explanations(self) -> None:
        """Creates ALT assertions for benign explanations."""
        packet = EvidencePacket(packet_id="msg-005", time_window=make_time_window())
        packet.add_fact(make_fact("fact-001", field="maintenance_window", value="active"))
        packet.freeze()

        agent = SkepticAgent()
        agent.observe(packet)

        arch_msg = make_architect_message(
            packet_id=packet.packet_id,
            fact_ids=("fact-001",),
        )
        agent.receive(arch_msg)

        context = make_turn_context(
            packet_id=packet.packet_id,
            snapshot_id=packet.snapshot_id,
        )

        result = agent.act(context)

        alt_assertions = [a for a in result.message.assertions if a.assertion_type == AssertionType.ALT]
        assert len(alt_assertions) >= 1


# =============================================================================
# Tests for Missing Architect Message
# =============================================================================


class TestMissingArchitectMessage:
    """Tests for behavior when Architect message is missing."""

    def test_requests_context_without_architect_message(self) -> None:
        """Requests additional context when no Architect message received."""
        packet = EvidencePacket(packet_id="miss-001", time_window=make_time_window())
        packet.add_fact(make_fact("fact-001", field="data", value="test"))
        packet.freeze()

        agent = SkepticAgent()
        agent.observe(packet)
        # Note: NOT receiving an Architect message

        context = make_turn_context(
            packet_id=packet.packet_id,
            snapshot_id=packet.snapshot_id,
        )

        result = agent.act(context)
        # Should return data request, not a message
        assert result.message is None
        assert len(result.requests) > 0


# =============================================================================
# Tests for Evidence Tracking
# =============================================================================


class TestSkepticEvidenceTracking:
    """Tests for evidence tracking."""

    def test_cited_facts_tracked(self) -> None:
        """Cited facts are tracked."""
        packet = EvidencePacket(packet_id="track-001", time_window=make_time_window())
        packet.add_fact(make_fact("fact-001", field="admin", value="true"))
        packet.freeze()

        agent = SkepticAgent()
        agent.observe(packet)

        arch_msg = make_architect_message(
            packet_id=packet.packet_id,
            fact_ids=("fact-001",),
        )
        agent.receive(arch_msg)

        context = make_turn_context(
            packet_id=packet.packet_id,
            snapshot_id=packet.snapshot_id,
        )

        agent.act(context)
        assert len(agent.cited_fact_ids) > 0


# =============================================================================
# Tests for BenignExplanation Dataclass
# =============================================================================


class TestBenignExplanationValidation:
    """Tests for BenignExplanation dataclass validation."""

    def test_valid_benign_explanation(self) -> None:
        """Valid BenignExplanation creates successfully."""
        from ares.dialectic.agents.patterns import BenignExplanation

        explanation = BenignExplanation(
            explanation_type=ExplanationType.MAINTENANCE_WINDOW,
            fact_ids=frozenset({"fact-001"}),
            confidence=0.7,
            description="Test explanation",
        )
        assert explanation.confidence == 0.7

    def test_confidence_must_be_valid(self) -> None:
        """Confidence must be between 0.0 and 1.0."""
        from ares.dialectic.agents.patterns import BenignExplanation

        with pytest.raises(ValueError):
            BenignExplanation(
                explanation_type=ExplanationType.MAINTENANCE_WINDOW,
                fact_ids=frozenset({"fact-001"}),
                confidence=-0.5,  # Invalid
                description="Test",
            )

    def test_must_have_fact_ids(self) -> None:
        """BenignExplanation must reference at least one fact."""
        from ares.dialectic.agents.patterns import BenignExplanation

        with pytest.raises(ValueError):
            BenignExplanation(
                explanation_type=ExplanationType.MAINTENANCE_WINDOW,
                fact_ids=frozenset(),  # Empty
                confidence=0.7,
                description="Test",
            )

    def test_must_have_description(self) -> None:
        """BenignExplanation must have a description."""
        from ares.dialectic.agents.patterns import BenignExplanation

        with pytest.raises(ValueError):
            BenignExplanation(
                explanation_type=ExplanationType.MAINTENANCE_WINDOW,
                fact_ids=frozenset({"fact-001"}),
                confidence=0.7,
                description="",  # Empty
            )


# =============================================================================
# Tests for Edge Cases
# =============================================================================


class TestSkepticEdgeCases:
    """Tests for edge cases."""

    def test_case_insensitive_detection(self) -> None:
        """Detection is case-insensitive."""
        packet = EvidencePacket(packet_id="edge-001", time_window=make_time_window())
        packet.add_fact(make_fact("fact-001", field="MAINTENANCE_WINDOW", value="ACTIVE"))
        packet.freeze()

        agent = SkepticAgent()
        agent.observe(packet)

        facts_by_field = {}
        for fact in packet.get_all_facts():
            field = fact.field.lower()
            if field not in facts_by_field:
                facts_by_field[field] = []
            facts_by_field[field].append(fact)

        result = agent._check_maintenance_window(packet, facts_by_field)
        assert result is not None

    def test_reset_clears_state(self) -> None:
        """reset() clears agent state."""
        packet = EvidencePacket(packet_id="edge-002", time_window=make_time_window())
        packet.add_fact(make_fact("fact-001", field="data", value="test"))
        packet.freeze()

        agent = SkepticAgent()
        agent.observe(packet)
        agent.reset()

        assert agent.state == AgentState.IDLE
        assert not agent.is_bound

    def test_confidence_inversely_weighted(self) -> None:
        """Skeptic confidence increases when Architect has gaps."""
        # Strong benign evidence
        packet = EvidencePacket(packet_id="edge-003", time_window=make_time_window())
        packet.add_fact(make_fact("fact-001", field="maintenance_window", value="active"))
        packet.add_fact(make_fact("fact-002", field="scheduled_task", value="backup"))
        packet.add_fact(make_fact("fact-003", field="admin_account", value="sysadmin"))
        packet.freeze()

        agent = SkepticAgent()
        agent.observe(packet)

        # Architect with minimal evidence
        arch_msg = make_architect_message(
            packet_id=packet.packet_id,
            fact_ids=("fact-001",),  # Minimal evidence
            confidence=0.3,  # Low confidence
        )
        agent.receive(arch_msg)

        context = make_turn_context(
            packet_id=packet.packet_id,
            snapshot_id=packet.snapshot_id,
        )

        result = agent.act(context)
        # Skeptic should have reasonable confidence with strong benign evidence
        assert result.message.confidence >= 0.3
