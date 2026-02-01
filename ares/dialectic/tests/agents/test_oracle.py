"""Tests for Oracle components - OracleJudge and OracleNarrator."""

import pytest
from datetime import datetime
from typing import FrozenSet

from ares.dialectic.agents import (
    OracleJudge,
    OracleNarrator,
    AgentRole,
    AgentState,
    Phase,
    TurnContext,
    Verdict,
    VerdictOutcome,
    PhaseViolationError,
    create_oracle_verdict,
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
    phase: Phase = Phase.SYNTHESIS,
    turn_number: int = 3,
    max_turns: int = 10,
    prior_messages: tuple = (),
    seen_fact_ids: FrozenSet[str] = frozenset(),
) -> TurnContext:
    """Create a test TurnContext instance for SYNTHESIS phase."""
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

    return builder.build()


def make_skeptic_message(
    packet_id: str = "packet-001",
    cycle_id: str = "cycle-001",
    fact_ids: tuple = ("fact-002",),
    confidence: float = 0.3,
) -> DialecticalMessage:
    """Create a mock Skeptic REBUTTAL message."""
    builder = MessageBuilder(
        source_agent="skeptic-001",
        packet_id=packet_id,
        cycle_id=cycle_id,
    )
    builder.set_phase(Phase.ANTITHESIS)
    builder.set_turn(2)
    builder.set_type(MessageType.REBUTTAL)
    builder.set_confidence(confidence)

    assertion = Assertion.alternative(
        assertion_id="alt-001",
        fact_ids=list(fact_ids),
        interpretation="Benign explanation",
    )
    builder.add_assertion(assertion)

    return builder.build()


# =============================================================================
# Tests for OracleJudge - Decision Table
# =============================================================================


class TestOracleJudgeDecisionTable:
    """Tests for OracleJudge decision table logic."""

    def test_threat_confirmed_high_arch_low_skep(self) -> None:
        """THREAT_CONFIRMED when Architect >= 0.7 and Skeptic < 0.5."""
        packet = make_packet()

        arch_msg = make_architect_message(
            packet_id=packet.packet_id,
            confidence=0.8,
            fact_ids=("fact-001", "fact-002"),
        )
        skep_msg = make_skeptic_message(
            packet_id=packet.packet_id,
            confidence=0.3,
            fact_ids=("fact-003",),
        )

        verdict = OracleJudge.compute_verdict(arch_msg, skep_msg, packet)

        assert verdict.outcome == VerdictOutcome.THREAT_CONFIRMED
        assert verdict.confidence >= 0.7

    def test_threat_dismissed_high_skep_low_arch(self) -> None:
        """THREAT_DISMISSED when Skeptic >= 0.7 and Architect < 0.5."""
        packet = make_packet()

        arch_msg = make_architect_message(
            packet_id=packet.packet_id,
            confidence=0.3,
            fact_ids=("fact-001",),
        )
        skep_msg = make_skeptic_message(
            packet_id=packet.packet_id,
            confidence=0.8,
            fact_ids=("fact-002", "fact-003"),
        )

        verdict = OracleJudge.compute_verdict(arch_msg, skep_msg, packet)

        assert verdict.outcome == VerdictOutcome.THREAT_DISMISSED
        assert verdict.confidence >= 0.7

    def test_inconclusive_both_high(self) -> None:
        """INCONCLUSIVE when both Architect and Skeptic are high."""
        packet = make_packet()

        arch_msg = make_architect_message(
            packet_id=packet.packet_id,
            confidence=0.8,
            fact_ids=("fact-001",),
        )
        skep_msg = make_skeptic_message(
            packet_id=packet.packet_id,
            confidence=0.75,
            fact_ids=("fact-002",),
        )

        verdict = OracleJudge.compute_verdict(arch_msg, skep_msg, packet)

        assert verdict.outcome == VerdictOutcome.INCONCLUSIVE

    def test_inconclusive_both_moderate(self) -> None:
        """INCONCLUSIVE when both Architect and Skeptic are moderate."""
        packet = make_packet()

        arch_msg = make_architect_message(
            packet_id=packet.packet_id,
            confidence=0.5,
            fact_ids=("fact-001",),
        )
        skep_msg = make_skeptic_message(
            packet_id=packet.packet_id,
            confidence=0.5,
            fact_ids=("fact-002",),
        )

        verdict = OracleJudge.compute_verdict(arch_msg, skep_msg, packet)

        assert verdict.outcome == VerdictOutcome.INCONCLUSIVE

    def test_inconclusive_both_low(self) -> None:
        """INCONCLUSIVE when both Architect and Skeptic are low."""
        packet = make_packet()

        arch_msg = make_architect_message(
            packet_id=packet.packet_id,
            confidence=0.2,
            fact_ids=("fact-001",),
        )
        skep_msg = make_skeptic_message(
            packet_id=packet.packet_id,
            confidence=0.2,
            fact_ids=("fact-002",),
        )

        verdict = OracleJudge.compute_verdict(arch_msg, skep_msg, packet)

        assert verdict.outcome == VerdictOutcome.INCONCLUSIVE

    def test_threat_confirmed_at_threshold(self) -> None:
        """THREAT_CONFIRMED at exact threshold values."""
        packet = make_packet()

        arch_msg = make_architect_message(
            packet_id=packet.packet_id,
            confidence=0.7,  # Exactly at threshold
            fact_ids=("fact-001",),
        )
        skep_msg = make_skeptic_message(
            packet_id=packet.packet_id,
            confidence=0.49,  # Just below weak threshold
            fact_ids=("fact-002",),
        )

        verdict = OracleJudge.compute_verdict(arch_msg, skep_msg, packet)

        assert verdict.outcome == VerdictOutcome.THREAT_CONFIRMED

    def test_threat_dismissed_at_threshold(self) -> None:
        """THREAT_DISMISSED at exact threshold values."""
        packet = make_packet()

        arch_msg = make_architect_message(
            packet_id=packet.packet_id,
            confidence=0.49,  # Just below weak threshold
            fact_ids=("fact-001",),
        )
        skep_msg = make_skeptic_message(
            packet_id=packet.packet_id,
            confidence=0.7,  # Exactly at threshold
            fact_ids=("fact-002",),
        )

        verdict = OracleJudge.compute_verdict(arch_msg, skep_msg, packet)

        assert verdict.outcome == VerdictOutcome.THREAT_DISMISSED


# =============================================================================
# Tests for OracleJudge - Evidence-Based Decisions
# =============================================================================


class TestOracleJudgeEvidenceBased:
    """Tests for evidence-based verdict decisions."""

    def test_threat_confirmed_with_more_evidence(self) -> None:
        """THREAT_CONFIRMED when Architect has significantly more evidence."""
        packet = EvidencePacket(packet_id="evi-001", time_window=make_time_window())
        for i in range(10):
            packet.add_fact(make_fact(f"fact-{i:03d}", entity_id=f"node-{i}"))
        packet.freeze()

        # Architect cites many facts
        arch_facts = tuple(f"fact-{i:03d}" for i in range(8))
        arch_msg = make_architect_message(
            packet_id=packet.packet_id,
            confidence=0.75,
            fact_ids=arch_facts,
        )

        # Skeptic cites few facts
        skep_msg = make_skeptic_message(
            packet_id=packet.packet_id,
            confidence=0.55,
            fact_ids=("fact-008", "fact-009"),
        )

        verdict = OracleJudge.compute_verdict(arch_msg, skep_msg, packet)

        # High confidence Architect with more evidence should win
        assert verdict.outcome == VerdictOutcome.THREAT_CONFIRMED

    def test_threat_dismissed_with_more_evidence(self) -> None:
        """THREAT_DISMISSED when Skeptic has significantly more evidence."""
        packet = EvidencePacket(packet_id="evi-002", time_window=make_time_window())
        for i in range(10):
            packet.add_fact(make_fact(f"fact-{i:03d}", entity_id=f"node-{i}"))
        packet.freeze()

        # Architect cites few facts
        arch_msg = make_architect_message(
            packet_id=packet.packet_id,
            confidence=0.55,
            fact_ids=("fact-000", "fact-001"),
        )

        # Skeptic cites many facts
        skep_facts = tuple(f"fact-{i:03d}" for i in range(2, 10))
        skep_msg = make_skeptic_message(
            packet_id=packet.packet_id,
            confidence=0.75,
            fact_ids=skep_facts,
        )

        verdict = OracleJudge.compute_verdict(arch_msg, skep_msg, packet)

        assert verdict.outcome == VerdictOutcome.THREAT_DISMISSED


# =============================================================================
# Tests for OracleJudge - Verdict Attributes
# =============================================================================


class TestOracleJudgeVerdictAttributes:
    """Tests for verdict attribute correctness."""

    def test_verdict_has_reasoning(self) -> None:
        """Verdict includes reasoning string."""
        packet = make_packet()

        arch_msg = make_architect_message(
            packet_id=packet.packet_id,
            confidence=0.8,
            fact_ids=("fact-001",),
        )
        skep_msg = make_skeptic_message(
            packet_id=packet.packet_id,
            confidence=0.3,
            fact_ids=("fact-002",),
        )

        verdict = OracleJudge.compute_verdict(arch_msg, skep_msg, packet)

        assert verdict.reasoning
        assert len(verdict.reasoning) > 0

    def test_verdict_preserves_confidences(self) -> None:
        """Verdict preserves both agent confidences."""
        packet = make_packet()

        arch_msg = make_architect_message(
            packet_id=packet.packet_id,
            confidence=0.75,
            fact_ids=("fact-001",),
        )
        skep_msg = make_skeptic_message(
            packet_id=packet.packet_id,
            confidence=0.35,
            fact_ids=("fact-002",),
        )

        verdict = OracleJudge.compute_verdict(arch_msg, skep_msg, packet)

        assert verdict.architect_confidence == 0.75
        assert verdict.skeptic_confidence == 0.35

    def test_verdict_includes_supporting_facts_threat(self) -> None:
        """THREAT_CONFIRMED verdict includes Architect's facts."""
        packet = make_packet()

        arch_msg = make_architect_message(
            packet_id=packet.packet_id,
            confidence=0.85,
            fact_ids=("fact-001", "fact-002"),
        )
        skep_msg = make_skeptic_message(
            packet_id=packet.packet_id,
            confidence=0.3,
            fact_ids=("fact-003",),
        )

        verdict = OracleJudge.compute_verdict(arch_msg, skep_msg, packet)

        assert verdict.outcome == VerdictOutcome.THREAT_CONFIRMED
        assert "fact-001" in verdict.supporting_fact_ids
        assert "fact-002" in verdict.supporting_fact_ids

    def test_verdict_includes_supporting_facts_dismissed(self) -> None:
        """THREAT_DISMISSED verdict includes Skeptic's facts."""
        packet = make_packet()

        arch_msg = make_architect_message(
            packet_id=packet.packet_id,
            confidence=0.3,
            fact_ids=("fact-001",),
        )
        skep_msg = make_skeptic_message(
            packet_id=packet.packet_id,
            confidence=0.85,
            fact_ids=("fact-002", "fact-003"),
        )

        verdict = OracleJudge.compute_verdict(arch_msg, skep_msg, packet)

        assert verdict.outcome == VerdictOutcome.THREAT_DISMISSED
        assert "fact-002" in verdict.supporting_fact_ids
        assert "fact-003" in verdict.supporting_fact_ids

    def test_verdict_includes_all_facts_inconclusive(self) -> None:
        """INCONCLUSIVE verdict includes facts from both sides."""
        packet = make_packet()

        arch_msg = make_architect_message(
            packet_id=packet.packet_id,
            confidence=0.5,
            fact_ids=("fact-001",),
        )
        skep_msg = make_skeptic_message(
            packet_id=packet.packet_id,
            confidence=0.5,
            fact_ids=("fact-002",),
        )

        verdict = OracleJudge.compute_verdict(arch_msg, skep_msg, packet)

        assert verdict.outcome == VerdictOutcome.INCONCLUSIVE
        assert "fact-001" in verdict.supporting_fact_ids
        assert "fact-002" in verdict.supporting_fact_ids


# =============================================================================
# Tests for Verdict Dataclass
# =============================================================================


class TestVerdictDataclass:
    """Tests for Verdict dataclass."""

    def test_is_conclusive_threat(self) -> None:
        """is_conclusive returns True for THREAT_CONFIRMED."""
        verdict = Verdict(
            outcome=VerdictOutcome.THREAT_CONFIRMED,
            confidence=0.8,
            supporting_fact_ids=frozenset({"fact-001"}),
            architect_confidence=0.8,
            skeptic_confidence=0.3,
            reasoning="Test reasoning",
        )
        assert verdict.is_conclusive is True

    def test_is_conclusive_dismissed(self) -> None:
        """is_conclusive returns True for THREAT_DISMISSED."""
        verdict = Verdict(
            outcome=VerdictOutcome.THREAT_DISMISSED,
            confidence=0.8,
            supporting_fact_ids=frozenset({"fact-001"}),
            architect_confidence=0.3,
            skeptic_confidence=0.8,
            reasoning="Test reasoning",
        )
        assert verdict.is_conclusive is True

    def test_is_conclusive_inconclusive(self) -> None:
        """is_conclusive returns False for INCONCLUSIVE."""
        verdict = Verdict(
            outcome=VerdictOutcome.INCONCLUSIVE,
            confidence=0.5,
            supporting_fact_ids=frozenset({"fact-001"}),
            architect_confidence=0.5,
            skeptic_confidence=0.5,
            reasoning="Test reasoning",
        )
        assert verdict.is_conclusive is False

    def test_threat_detected_true(self) -> None:
        """threat_detected returns True for THREAT_CONFIRMED."""
        verdict = Verdict(
            outcome=VerdictOutcome.THREAT_CONFIRMED,
            confidence=0.8,
            supporting_fact_ids=frozenset({"fact-001"}),
            architect_confidence=0.8,
            skeptic_confidence=0.3,
            reasoning="Test reasoning",
        )
        assert verdict.threat_detected is True

    def test_threat_detected_false_dismissed(self) -> None:
        """threat_detected returns False for THREAT_DISMISSED."""
        verdict = Verdict(
            outcome=VerdictOutcome.THREAT_DISMISSED,
            confidence=0.8,
            supporting_fact_ids=frozenset({"fact-001"}),
            architect_confidence=0.3,
            skeptic_confidence=0.8,
            reasoning="Test reasoning",
        )
        assert verdict.threat_detected is False

    def test_threat_detected_false_inconclusive(self) -> None:
        """threat_detected returns False for INCONCLUSIVE."""
        verdict = Verdict(
            outcome=VerdictOutcome.INCONCLUSIVE,
            confidence=0.5,
            supporting_fact_ids=frozenset({"fact-001"}),
            architect_confidence=0.5,
            skeptic_confidence=0.5,
            reasoning="Test reasoning",
        )
        assert verdict.threat_detected is False

    def test_verdict_validation_confidence(self) -> None:
        """Verdict validates confidence range."""
        with pytest.raises(ValueError):
            Verdict(
                outcome=VerdictOutcome.THREAT_CONFIRMED,
                confidence=1.5,  # Invalid
                supporting_fact_ids=frozenset({"fact-001"}),
                architect_confidence=0.8,
                skeptic_confidence=0.3,
                reasoning="Test",
            )

    def test_verdict_validation_reasoning(self) -> None:
        """Verdict requires non-empty reasoning."""
        with pytest.raises(ValueError):
            Verdict(
                outcome=VerdictOutcome.THREAT_CONFIRMED,
                confidence=0.8,
                supporting_fact_ids=frozenset({"fact-001"}),
                architect_confidence=0.8,
                skeptic_confidence=0.3,
                reasoning="",  # Empty
            )


# =============================================================================
# Tests for OracleNarrator - Basic Properties
# =============================================================================


class TestOracleNarratorBasics:
    """Tests for basic OracleNarrator properties."""

    def test_role_is_oracle(self) -> None:
        """OracleNarrator has ORACLE role."""
        agent = OracleNarrator()
        assert agent.role == AgentRole.ORACLE

    def test_default_agent_id(self) -> None:
        """Default agent ID starts with 'oracle-'."""
        agent = OracleNarrator()
        assert agent.agent_id.startswith("oracle-")

    def test_custom_agent_id(self) -> None:
        """Custom agent ID is used when provided."""
        agent = OracleNarrator(agent_id="my-oracle")
        assert agent.agent_id == "my-oracle"

    def test_initial_state_is_idle(self) -> None:
        """Agent starts in IDLE state."""
        agent = OracleNarrator()
        assert agent.state == AgentState.IDLE

    def test_verdict_property(self) -> None:
        """Verdict property returns the locked verdict."""
        verdict = Verdict(
            outcome=VerdictOutcome.THREAT_CONFIRMED,
            confidence=0.8,
            supporting_fact_ids=frozenset({"fact-001"}),
            architect_confidence=0.8,
            skeptic_confidence=0.3,
            reasoning="Test reasoning",
        )
        agent = OracleNarrator(verdict=verdict)
        assert agent.verdict == verdict


# =============================================================================
# Tests for OracleNarrator - Phase Enforcement
# =============================================================================


class TestOracleNarratorPhaseEnforcement:
    """Tests that OracleNarrator can only act in SYNTHESIS phase."""

    def test_can_act_in_synthesis(self) -> None:
        """OracleNarrator can act in SYNTHESIS phase."""
        packet = make_packet()
        verdict = Verdict(
            outcome=VerdictOutcome.THREAT_CONFIRMED,
            confidence=0.8,
            supporting_fact_ids=frozenset({"fact-001"}),
            architect_confidence=0.8,
            skeptic_confidence=0.3,
            reasoning="Test reasoning",
        )

        agent = OracleNarrator(verdict=verdict)
        agent.observe(packet)

        context = make_turn_context(
            packet_id=packet.packet_id,
            snapshot_id=packet.snapshot_id,
            phase=Phase.SYNTHESIS,
        )

        result = agent.act(context)
        assert result.has_error is False

    def test_cannot_act_in_thesis(self) -> None:
        """OracleNarrator raises PhaseViolationError in THESIS phase."""
        packet = make_packet()
        verdict = Verdict(
            outcome=VerdictOutcome.THREAT_CONFIRMED,
            confidence=0.8,
            supporting_fact_ids=frozenset({"fact-001"}),
            architect_confidence=0.8,
            skeptic_confidence=0.3,
            reasoning="Test reasoning",
        )

        agent = OracleNarrator(verdict=verdict)
        agent.observe(packet)

        context = make_turn_context(
            packet_id=packet.packet_id,
            snapshot_id=packet.snapshot_id,
            phase=Phase.THESIS,
        )

        with pytest.raises(PhaseViolationError):
            agent.act(context)

    def test_cannot_act_in_antithesis(self) -> None:
        """OracleNarrator raises PhaseViolationError in ANTITHESIS phase."""
        packet = make_packet()
        verdict = Verdict(
            outcome=VerdictOutcome.THREAT_CONFIRMED,
            confidence=0.8,
            supporting_fact_ids=frozenset({"fact-001"}),
            architect_confidence=0.8,
            skeptic_confidence=0.3,
            reasoning="Test reasoning",
        )

        agent = OracleNarrator(verdict=verdict)
        agent.observe(packet)

        context = make_turn_context(
            packet_id=packet.packet_id,
            snapshot_id=packet.snapshot_id,
            phase=Phase.ANTITHESIS,
        )

        with pytest.raises(PhaseViolationError):
            agent.act(context)


# =============================================================================
# Tests for OracleNarrator - Message Composition
# =============================================================================


class TestOracleNarratorMessageComposition:
    """Tests for VERDICT message composition."""

    def test_produces_verdict_message(self) -> None:
        """OracleNarrator produces VERDICT message."""
        packet = make_packet()
        verdict = Verdict(
            outcome=VerdictOutcome.THREAT_CONFIRMED,
            confidence=0.8,
            supporting_fact_ids=frozenset({"fact-001"}),
            architect_confidence=0.8,
            skeptic_confidence=0.3,
            reasoning="Test reasoning",
        )

        agent = OracleNarrator(verdict=verdict)
        agent.observe(packet)

        context = make_turn_context(
            packet_id=packet.packet_id,
            snapshot_id=packet.snapshot_id,
        )

        result = agent.act(context)
        assert result.message is not None
        assert result.message.message_type == MessageType.VERDICT

    def test_message_has_assertions(self) -> None:
        """Verdict message contains assertions."""
        packet = make_packet()
        verdict = Verdict(
            outcome=VerdictOutcome.THREAT_CONFIRMED,
            confidence=0.8,
            supporting_fact_ids=frozenset({"fact-001", "fact-002"}),
            architect_confidence=0.8,
            skeptic_confidence=0.3,
            reasoning="Test reasoning",
        )

        agent = OracleNarrator(verdict=verdict)
        agent.observe(packet)

        context = make_turn_context(
            packet_id=packet.packet_id,
            snapshot_id=packet.snapshot_id,
        )

        result = agent.act(context)
        assert len(result.message.assertions) > 0

    def test_message_phase_is_synthesis(self) -> None:
        """Message phase is set to SYNTHESIS."""
        packet = make_packet()
        verdict = Verdict(
            outcome=VerdictOutcome.THREAT_DISMISSED,
            confidence=0.8,
            supporting_fact_ids=frozenset({"fact-001"}),
            architect_confidence=0.3,
            skeptic_confidence=0.8,
            reasoning="Test reasoning",
        )

        agent = OracleNarrator(verdict=verdict)
        agent.observe(packet)

        context = make_turn_context(
            packet_id=packet.packet_id,
            snapshot_id=packet.snapshot_id,
        )

        result = agent.act(context)
        assert result.message.phase == Phase.SYNTHESIS

    def test_message_has_narrative(self) -> None:
        """Message includes a narrative."""
        packet = make_packet()
        verdict = Verdict(
            outcome=VerdictOutcome.INCONCLUSIVE,
            confidence=0.5,
            supporting_fact_ids=frozenset({"fact-001"}),
            architect_confidence=0.5,
            skeptic_confidence=0.5,
            reasoning="Test reasoning",
        )

        agent = OracleNarrator(verdict=verdict)
        agent.observe(packet)

        context = make_turn_context(
            packet_id=packet.packet_id,
            snapshot_id=packet.snapshot_id,
        )

        result = agent.act(context)
        assert result.message.narrative is not None
        assert len(result.message.narrative) > 0

    def test_narrative_includes_verdict_outcome(self) -> None:
        """Narrative mentions the verdict outcome."""
        packet = make_packet()
        verdict = Verdict(
            outcome=VerdictOutcome.THREAT_CONFIRMED,
            confidence=0.8,
            supporting_fact_ids=frozenset({"fact-001"}),
            architect_confidence=0.8,
            skeptic_confidence=0.3,
            reasoning="Test reasoning",
        )

        agent = OracleNarrator(verdict=verdict)
        agent.observe(packet)

        context = make_turn_context(
            packet_id=packet.packet_id,
            snapshot_id=packet.snapshot_id,
        )

        result = agent.act(context)
        assert "THREAT CONFIRMED" in result.message.narrative

    def test_message_confidence_matches_verdict(self) -> None:
        """Message confidence matches verdict confidence."""
        packet = make_packet()
        verdict = Verdict(
            outcome=VerdictOutcome.THREAT_CONFIRMED,
            confidence=0.85,
            supporting_fact_ids=frozenset({"fact-001"}),
            architect_confidence=0.85,
            skeptic_confidence=0.3,
            reasoning="Test reasoning",
        )

        agent = OracleNarrator(verdict=verdict)
        agent.observe(packet)

        context = make_turn_context(
            packet_id=packet.packet_id,
            snapshot_id=packet.snapshot_id,
        )

        result = agent.act(context)
        assert result.message.confidence == verdict.confidence


# =============================================================================
# Tests for OracleNarrator - Verdict Locking
# =============================================================================


class TestOracleNarratorVerdictLocking:
    """Tests for verdict locking behavior."""

    def test_verdict_can_be_set_before_acting(self) -> None:
        """Verdict can be set via set_verdict() before acting."""
        packet = make_packet()
        verdict = Verdict(
            outcome=VerdictOutcome.THREAT_CONFIRMED,
            confidence=0.8,
            supporting_fact_ids=frozenset({"fact-001"}),
            architect_confidence=0.8,
            skeptic_confidence=0.3,
            reasoning="Test reasoning",
        )

        agent = OracleNarrator()
        agent.set_verdict(verdict)
        agent.observe(packet)

        assert agent.verdict == verdict

    def test_cannot_change_verdict_after_acting(self) -> None:
        """Cannot change verdict after OracleNarrator has produced output."""
        packet = make_packet()
        verdict1 = Verdict(
            outcome=VerdictOutcome.THREAT_CONFIRMED,
            confidence=0.8,
            supporting_fact_ids=frozenset({"fact-001"}),
            architect_confidence=0.8,
            skeptic_confidence=0.3,
            reasoning="Test reasoning",
        )
        verdict2 = Verdict(
            outcome=VerdictOutcome.THREAT_DISMISSED,
            confidence=0.8,
            supporting_fact_ids=frozenset({"fact-002"}),
            architect_confidence=0.3,
            skeptic_confidence=0.8,
            reasoning="Different reasoning",
        )

        agent = OracleNarrator(verdict=verdict1)
        agent.observe(packet)

        context = make_turn_context(
            packet_id=packet.packet_id,
            snapshot_id=packet.snapshot_id,
        )

        agent.act(context)

        with pytest.raises(RuntimeError):
            agent.set_verdict(verdict2)

    def test_requests_context_without_verdict(self) -> None:
        """Requests context when no verdict is set."""
        packet = make_packet()

        agent = OracleNarrator()  # No verdict
        agent.observe(packet)

        context = make_turn_context(
            packet_id=packet.packet_id,
            snapshot_id=packet.snapshot_id,
        )

        result = agent.act(context)
        assert result.message is None
        assert len(result.requests) > 0


# =============================================================================
# Tests for create_oracle_verdict Helper
# =============================================================================


class TestCreateOracleVerdict:
    """Tests for create_oracle_verdict convenience function."""

    def test_creates_verdict_and_narrator(self) -> None:
        """create_oracle_verdict returns both verdict and narrator."""
        packet = make_packet()
        arch_msg = make_architect_message(
            packet_id=packet.packet_id,
            confidence=0.8,
        )
        skep_msg = make_skeptic_message(
            packet_id=packet.packet_id,
            confidence=0.3,
        )

        verdict, narrator = create_oracle_verdict(arch_msg, skep_msg, packet)

        assert isinstance(verdict, Verdict)
        assert isinstance(narrator, OracleNarrator)
        assert narrator.verdict == verdict

    def test_narrator_is_ready_to_act(self) -> None:
        """Narrator from create_oracle_verdict is ready to act."""
        packet = make_packet()
        arch_msg = make_architect_message(
            packet_id=packet.packet_id,
            confidence=0.8,
        )
        skep_msg = make_skeptic_message(
            packet_id=packet.packet_id,
            confidence=0.3,
        )

        verdict, narrator = create_oracle_verdict(arch_msg, skep_msg, packet)

        assert narrator.is_ready
        assert narrator.is_bound


# =============================================================================
# Tests for Edge Cases
# =============================================================================


class TestOracleEdgeCases:
    """Tests for edge cases."""

    def test_deterministic_verdict(self) -> None:
        """Same inputs produce same verdict (deterministic)."""
        packet = make_packet()
        arch_msg = make_architect_message(
            packet_id=packet.packet_id,
            confidence=0.75,
            fact_ids=("fact-001", "fact-002"),
        )
        skep_msg = make_skeptic_message(
            packet_id=packet.packet_id,
            confidence=0.35,
            fact_ids=("fact-003",),
        )

        verdict1 = OracleJudge.compute_verdict(arch_msg, skep_msg, packet)
        verdict2 = OracleJudge.compute_verdict(arch_msg, skep_msg, packet)

        assert verdict1.outcome == verdict2.outcome
        assert verdict1.confidence == verdict2.confidence

    def test_reset_clears_state(self) -> None:
        """reset() clears narrator state."""
        packet = make_packet()
        verdict = Verdict(
            outcome=VerdictOutcome.THREAT_CONFIRMED,
            confidence=0.8,
            supporting_fact_ids=frozenset({"fact-001"}),
            architect_confidence=0.8,
            skeptic_confidence=0.3,
            reasoning="Test",
        )

        agent = OracleNarrator(verdict=verdict)
        agent.observe(packet)
        agent.reset()

        assert agent.state == AgentState.IDLE
        assert not agent.is_bound
