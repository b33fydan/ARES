"""Integration tests for strategies with full agent lifecycle.

Verifies that agents with pluggable strategies produce valid output
through the complete observe → receive → act lifecycle.
"""

from __future__ import annotations

from datetime import datetime
from typing import List
from unittest.mock import MagicMock

import pytest

from ares.dialectic.agents.architect import ArchitectAgent
from ares.dialectic.agents.context import AgentRole, TurnContext
from ares.dialectic.agents.oracle import OracleJudge, OracleNarrator
from ares.dialectic.agents.patterns import (
    AnomalyPattern,
    BenignExplanation,
    ExplanationType,
    PatternType,
    Verdict,
    VerdictOutcome,
)
from ares.dialectic.agents.skeptic import SkepticAgent
from ares.dialectic.agents.strategies.rule_based import (
    RuleBasedExplanationFinder,
    RuleBasedNarrativeGenerator,
    RuleBasedThreatAnalyzer,
)
from ares.dialectic.coordinator.orchestrator import CycleResult, DialecticalOrchestrator
from ares.dialectic.evidence.fact import EntityType, Fact
from ares.dialectic.evidence.packet import EvidencePacket, TimeWindow
from ares.dialectic.evidence.provenance import Provenance, SourceType
from ares.dialectic.messages.protocol import Phase

from .conftest import make_provenance, make_time_window


def _build_threat_packet() -> EvidencePacket:
    """Build a frozen packet with clear threat indicators."""
    packet = EvidencePacket(packet_id="integ-packet", time_window=make_time_window())
    prov = make_provenance()
    packet.add_fact(Fact(
        fact_id="fact-priv-001", entity_id="user-admin", entity_type=EntityType.NODE,
        field="privilege", value="SeDebugPrivilege",
        timestamp=datetime(2024, 1, 15, 2, 30, 0), provenance=prov,
    ))
    packet.add_fact(Fact(
        fact_id="fact-proc-001", entity_id="proc-cmd", entity_type=EntityType.NODE,
        field="process_name", value="cmd.exe",
        timestamp=datetime(2024, 1, 15, 2, 31, 0), provenance=prov,
    ))
    packet.add_fact(Fact(
        fact_id="fact-admin-001", entity_id="user-admin", entity_type=EntityType.NODE,
        field="account_type", value="administrator",
        timestamp=datetime(2024, 1, 15, 2, 30, 0), provenance=prov,
    ))
    packet.freeze()
    return packet


class TestArchitectIntegration:
    """ArchitectAgent with strategies through full lifecycle."""

    def test_with_rule_based_same_as_default(self):
        """Explicit RuleBasedThreatAnalyzer == default behavior."""
        packet = _build_threat_packet()
        # Default
        agent1 = ArchitectAgent(agent_id="arch-default")
        agent1.observe(packet)
        ctx1 = TurnContext(
            cycle_id="c1", packet_id=packet.packet_id,
            snapshot_id=packet.snapshot_id, phase=Phase.THESIS,
            turn_number=1, max_turns=3,
        )
        result1 = agent1.act(ctx1)

        # Explicit rule-based
        agent2 = ArchitectAgent(
            agent_id="arch-explicit",
            threat_analyzer=RuleBasedThreatAnalyzer(),
        )
        agent2.observe(packet)
        ctx2 = TurnContext(
            cycle_id="c2", packet_id=packet.packet_id,
            snapshot_id=packet.snapshot_id, phase=Phase.THESIS,
            turn_number=1, max_turns=3,
        )
        result2 = agent2.act(ctx2)

        assert result1.message is not None
        assert result2.message is not None
        # Both should produce messages of the same type
        assert result1.message.message_type == result2.message.message_type

    def test_with_mock_llm_strategy(self):
        """ArchitectAgent with mock strategy uses mock result."""
        packet = _build_threat_packet()
        mock_strategy = MagicMock()
        mock_strategy.analyze_threats.return_value = [
            AnomalyPattern(
                pattern_type=PatternType.PRIVILEGE_ESCALATION,
                fact_ids=frozenset({"fact-priv-001"}),
                confidence=0.95,
                description="Mock LLM detection",
            )
        ]

        agent = ArchitectAgent(agent_id="arch-mock", threat_analyzer=mock_strategy)
        agent.observe(packet)
        ctx = TurnContext(
            cycle_id="c1", packet_id=packet.packet_id,
            snapshot_id=packet.snapshot_id, phase=Phase.THESIS,
            turn_number=1, max_turns=3,
        )
        result = agent.act(ctx)
        assert result.message is not None
        mock_strategy.analyze_threats.assert_called_once_with(packet)


class TestSkepticIntegration:
    """SkepticAgent with strategies through full lifecycle."""

    def test_with_rule_based_same_as_default(self):
        """Explicit RuleBasedExplanationFinder == default behavior."""
        packet = _build_threat_packet()

        # First need an architect message
        architect = ArchitectAgent(agent_id="arch")
        architect.observe(packet)
        arch_ctx = TurnContext(
            cycle_id="c1", packet_id=packet.packet_id,
            snapshot_id=packet.snapshot_id, phase=Phase.THESIS,
            turn_number=1, max_turns=3,
        )
        arch_result = architect.act(arch_ctx)
        assert arch_result.message is not None

        # Default skeptic
        skep1 = SkepticAgent(agent_id="skep-default")
        skep1.observe(packet)
        skep1.receive(arch_result.message)
        skep_ctx1 = TurnContext(
            cycle_id="c1", packet_id=packet.packet_id,
            snapshot_id=packet.snapshot_id, phase=Phase.ANTITHESIS,
            turn_number=2, max_turns=3,
            seen_fact_ids=frozenset(arch_result.message.get_all_fact_ids()),
        )
        result1 = skep1.act(skep_ctx1)

        # Explicit rule-based skeptic
        skep2 = SkepticAgent(
            agent_id="skep-explicit",
            explanation_finder=RuleBasedExplanationFinder(),
        )
        skep2.observe(packet)
        skep2.receive(arch_result.message)
        skep_ctx2 = TurnContext(
            cycle_id="c2", packet_id=packet.packet_id,
            snapshot_id=packet.snapshot_id, phase=Phase.ANTITHESIS,
            turn_number=2, max_turns=3,
            seen_fact_ids=frozenset(arch_result.message.get_all_fact_ids()),
        )
        result2 = skep2.act(skep_ctx2)

        assert result1.message is not None
        assert result2.message is not None

    def test_with_mock_llm_strategy(self):
        """SkepticAgent with mock strategy uses mock result."""
        packet = _build_threat_packet()
        architect = ArchitectAgent(agent_id="arch")
        architect.observe(packet)
        arch_ctx = TurnContext(
            cycle_id="c1", packet_id=packet.packet_id,
            snapshot_id=packet.snapshot_id, phase=Phase.THESIS,
            turn_number=1, max_turns=3,
        )
        arch_result = architect.act(arch_ctx)

        mock_strategy = MagicMock()
        mock_strategy.find_explanations.return_value = []

        skep = SkepticAgent(agent_id="skep-mock", explanation_finder=mock_strategy)
        skep.observe(packet)
        skep.receive(arch_result.message)
        skep_ctx = TurnContext(
            cycle_id="c1", packet_id=packet.packet_id,
            snapshot_id=packet.snapshot_id, phase=Phase.ANTITHESIS,
            turn_number=2, max_turns=3,
            seen_fact_ids=frozenset(arch_result.message.get_all_fact_ids()),
        )
        result = skep.act(skep_ctx)
        assert result.message is not None
        mock_strategy.find_explanations.assert_called_once()


class TestNarratorIntegration:
    """OracleNarrator with strategies through full lifecycle."""

    def test_with_rule_based_same_as_default(self):
        """Explicit RuleBasedNarrativeGenerator == default behavior."""
        packet = _build_threat_packet()
        verdict = Verdict(
            outcome=VerdictOutcome.THREAT_CONFIRMED,
            confidence=0.85,
            supporting_fact_ids=frozenset({"fact-priv-001"}),
            architect_confidence=0.9,
            skeptic_confidence=0.3,
            reasoning="test",
        )

        # Default
        n1 = OracleNarrator(agent_id="oracle-default", verdict=verdict)
        n1.observe(packet)
        ctx1 = TurnContext(
            cycle_id="c1", packet_id=packet.packet_id,
            snapshot_id=packet.snapshot_id, phase=Phase.SYNTHESIS,
            turn_number=3, max_turns=3,
        )
        result1 = n1.act(ctx1)

        # Explicit
        n2 = OracleNarrator(
            agent_id="oracle-explicit", verdict=verdict,
            narrative_generator=RuleBasedNarrativeGenerator(),
        )
        n2.observe(packet)
        ctx2 = TurnContext(
            cycle_id="c2", packet_id=packet.packet_id,
            snapshot_id=packet.snapshot_id, phase=Phase.SYNTHESIS,
            turn_number=3, max_turns=3,
        )
        result2 = n2.act(ctx2)

        assert result1.message is not None
        assert result2.message is not None
        # Same narrative content
        assert result1.message.narrative == result2.message.narrative


class TestOrchestratorIntegration:
    """Orchestrator still works with default strategies."""

    def test_orchestrator_unchanged(self):
        """DialecticalOrchestrator works identically (agents use defaults)."""
        packet = _build_threat_packet()
        orchestrator = DialecticalOrchestrator()
        result = orchestrator.run_cycle(packet)
        assert isinstance(result, CycleResult)
        assert result.verdict is not None
        assert result.architect_message is not None
        assert result.skeptic_message is not None

    def test_multi_turn_still_works(self):
        """run_multi_turn_cycle still works (agents created internally)."""
        from ares.dialectic.coordinator.multi_turn import run_multi_turn_cycle

        packet = _build_threat_packet()
        mt_result = run_multi_turn_cycle(packet)
        assert mt_result.total_rounds >= 1
        cr = mt_result.to_cycle_result()
        assert cr.verdict is not None

    def test_memory_stream_stores_strategy_results(self):
        """MemoryStream stores results from strategy-powered cycles."""
        from ares.dialectic.memory.backends.in_memory import InMemoryBackend
        from ares.dialectic.memory.stream import MemoryStream

        packet = _build_threat_packet()
        orchestrator = DialecticalOrchestrator()
        result = orchestrator.run_cycle(packet)

        stream = MemoryStream(backend=InMemoryBackend())
        entry = stream.store(result)
        assert entry is not None
        assert stream.verify_chain_integrity()
