"""Tests for strategy protocol compliance.

Verifies that all implementations satisfy their respective protocols,
and that agents correctly accept and use strategy objects.
"""

from __future__ import annotations

from typing import List, Optional
from unittest.mock import MagicMock

import pytest

from ares.dialectic.agents.architect import ArchitectAgent
from ares.dialectic.agents.oracle import OracleNarrator
from ares.dialectic.agents.patterns import AnomalyPattern, BenignExplanation, Verdict
from ares.dialectic.agents.skeptic import SkepticAgent
from ares.dialectic.agents.strategies.llm_strategy import (
    LLMExplanationFinder,
    LLMNarrativeGenerator,
    LLMThreatAnalyzer,
)
from ares.dialectic.agents.strategies.protocol import (
    ExplanationFinder,
    NarrativeGenerator,
    ThreatAnalyzer,
)
from ares.dialectic.agents.strategies.rule_based import (
    RuleBasedExplanationFinder,
    RuleBasedNarrativeGenerator,
    RuleBasedThreatAnalyzer,
)
from ares.dialectic.evidence.packet import EvidencePacket
from ares.dialectic.messages.protocol import DialecticalMessage


# =============================================================================
# Protocol Compliance — Rule-Based
# =============================================================================


class TestRuleBasedProtocolCompliance:
    """Rule-based implementations satisfy their respective protocols."""

    def test_rule_based_threat_analyzer_satisfies_protocol(self):
        """RuleBasedThreatAnalyzer has analyze_threats method."""
        analyzer = RuleBasedThreatAnalyzer()
        assert hasattr(analyzer, "analyze_threats")
        assert callable(analyzer.analyze_threats)

    def test_rule_based_explanation_finder_satisfies_protocol(self):
        """RuleBasedExplanationFinder has find_explanations method."""
        finder = RuleBasedExplanationFinder()
        assert hasattr(finder, "find_explanations")
        assert callable(finder.find_explanations)

    def test_rule_based_narrative_generator_satisfies_protocol(self):
        """RuleBasedNarrativeGenerator has generate_narrative method."""
        generator = RuleBasedNarrativeGenerator()
        assert hasattr(generator, "generate_narrative")
        assert callable(generator.generate_narrative)

    def test_rule_based_threat_analyzer_is_structural_subtype(self):
        """RuleBasedThreatAnalyzer is a structural subtype of ThreatAnalyzer."""
        analyzer = RuleBasedThreatAnalyzer()
        # Protocol uses structural subtyping — duck typing check
        assert isinstance(analyzer.analyze_threats, type(analyzer.analyze_threats))

    def test_rule_based_explanation_finder_is_structural_subtype(self):
        """RuleBasedExplanationFinder is a structural subtype of ExplanationFinder."""
        finder = RuleBasedExplanationFinder()
        assert isinstance(finder.find_explanations, type(finder.find_explanations))

    def test_rule_based_narrative_generator_is_structural_subtype(self):
        """RuleBasedNarrativeGenerator is a structural subtype of NarrativeGenerator."""
        gen = RuleBasedNarrativeGenerator()
        assert isinstance(gen.generate_narrative, type(gen.generate_narrative))


# =============================================================================
# Protocol Compliance — LLM
# =============================================================================


class TestLLMProtocolCompliance:
    """LLM implementations satisfy their respective protocols."""

    def test_llm_threat_analyzer_satisfies_protocol(self, mock_client):
        """LLMThreatAnalyzer has analyze_threats method."""
        analyzer = LLMThreatAnalyzer(mock_client)
        assert hasattr(analyzer, "analyze_threats")
        assert callable(analyzer.analyze_threats)

    def test_llm_explanation_finder_satisfies_protocol(self, mock_client):
        """LLMExplanationFinder has find_explanations method."""
        finder = LLMExplanationFinder(mock_client)
        assert hasattr(finder, "find_explanations")
        assert callable(finder.find_explanations)

    def test_llm_narrative_generator_satisfies_protocol(self, mock_client):
        """LLMNarrativeGenerator has generate_narrative method."""
        gen = LLMNarrativeGenerator(mock_client)
        assert hasattr(gen, "generate_narrative")
        assert callable(gen.generate_narrative)


# =============================================================================
# Agent Construction with Strategies
# =============================================================================


class TestAgentStrategyAcceptance:
    """Agents accept strategy objects at construction."""

    def test_architect_accepts_threat_analyzer(self):
        """ArchitectAgent accepts ThreatAnalyzer at construction."""
        custom = RuleBasedThreatAnalyzer()
        agent = ArchitectAgent(agent_id="test-arch", threat_analyzer=custom)
        assert agent._threat_analyzer is custom

    def test_skeptic_accepts_explanation_finder(self):
        """SkepticAgent accepts ExplanationFinder at construction."""
        custom = RuleBasedExplanationFinder()
        agent = SkepticAgent(agent_id="test-skep", explanation_finder=custom)
        assert agent._explanation_finder is custom

    def test_narrator_accepts_narrative_generator(self):
        """OracleNarrator accepts NarrativeGenerator at construction."""
        custom = RuleBasedNarrativeGenerator()
        narrator = OracleNarrator(agent_id="test-oracle", narrative_generator=custom)
        assert narrator._narrative_generator is custom

    def test_architect_defaults_to_rule_based(self):
        """ArchitectAgent defaults to RuleBasedThreatAnalyzer."""
        agent = ArchitectAgent(agent_id="test-arch")
        assert isinstance(agent._threat_analyzer, RuleBasedThreatAnalyzer)

    def test_skeptic_defaults_to_rule_based(self):
        """SkepticAgent defaults to RuleBasedExplanationFinder."""
        agent = SkepticAgent(agent_id="test-skep")
        assert isinstance(agent._explanation_finder, RuleBasedExplanationFinder)

    def test_narrator_defaults_to_rule_based(self):
        """OracleNarrator defaults to RuleBasedNarrativeGenerator."""
        narrator = OracleNarrator(agent_id="test-oracle")
        assert isinstance(narrator._narrative_generator, RuleBasedNarrativeGenerator)

    def test_custom_strategy_implementing_protocol_works(self, sample_packet):
        """A custom class implementing the protocol works with agents."""

        class CustomAnalyzer:
            def analyze_threats(self, packet):
                return []

        agent = ArchitectAgent(agent_id="test", threat_analyzer=CustomAnalyzer())
        result = agent._detect_anomalies(sample_packet)
        assert result == []

    def test_architect_preserves_positional_args(self):
        """ArchitectAgent still accepts agent_id and max_memory_size positionally."""
        agent = ArchitectAgent("my-arch", 50)
        assert agent.agent_id == "my-arch"
        assert agent._max_memory_size == 50

    def test_skeptic_preserves_positional_args(self):
        """SkepticAgent still accepts agent_id and max_memory_size positionally."""
        agent = SkepticAgent("my-skep", 50)
        assert agent.agent_id == "my-skep"
        assert agent._max_memory_size == 50

    def test_narrator_preserves_existing_constructor(self):
        """OracleNarrator still accepts verdict as positional arg."""
        from ares.dialectic.agents.patterns import Verdict, VerdictOutcome

        verdict = Verdict(
            outcome=VerdictOutcome.INCONCLUSIVE,
            confidence=0.5,
            supporting_fact_ids=frozenset({"f1"}),
            architect_confidence=0.5,
            skeptic_confidence=0.5,
            reasoning="test",
        )
        narrator = OracleNarrator("my-oracle", verdict, 50)
        assert narrator.agent_id == "my-oracle"
        assert narrator._locked_verdict is verdict
        assert narrator._max_memory_size == 50
