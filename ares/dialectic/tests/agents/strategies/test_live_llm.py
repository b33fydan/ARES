"""Tests that make real Anthropic API calls.

ALL tests in this file are marked @pytest.mark.live_llm and are
SKIPPED by default. Run with:

    pytest -m live_llm --run-live-llm -v

Requires: ANTHROPIC_API_KEY environment variable.

IMPORTANT: These tests assert output SHAPE and CONSTRAINTS only.
They do NOT assert exact LLM content — LLM output is non-deterministic.
"""

from __future__ import annotations

import os

import pytest

from ares.dialectic.agents.patterns import AnomalyPattern, BenignExplanation
from ares.dialectic.agents.strategies.client import AnthropicClient
from ares.dialectic.agents.strategies.live_cycle import (
    run_cycle_with_strategies,
    run_multi_turn_with_strategies,
)
from ares.dialectic.agents.strategies.llm_strategy import (
    LLMExplanationFinder,
    LLMNarrativeGenerator,
    LLMThreatAnalyzer,
)
from ares.dialectic.agents.strategies.observability import LLMCallLogger
from ares.dialectic.coordinator.orchestrator import CycleResult
from ares.dialectic.memory.backends.in_memory import InMemoryBackend
from ares.dialectic.memory.stream import MemoryStream
from ares.dialectic.scripts.sample_packets import build_privilege_escalation_packet


@pytest.fixture(scope="module")
def live_client():
    """Create a real AnthropicClient (requires ANTHROPIC_API_KEY)."""
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        pytest.skip("ANTHROPIC_API_KEY not set")
    return AnthropicClient(api_key=api_key)


@pytest.fixture(scope="module")
def priv_esc_packet():
    """Build the privilege escalation sample packet once per module."""
    return build_privilege_escalation_packet()


@pytest.mark.live_llm
class TestLiveLLMIntegration:
    """Tests that make real Anthropic API calls.

    Run with: pytest -m live_llm --run-live-llm -v
    Requires: ANTHROPIC_API_KEY environment variable
    """

    def test_architect_live_threat_analysis(self, live_client, priv_esc_packet):
        """Architect analyzes a privilege escalation packet via live LLM."""
        analyzer = LLMThreatAnalyzer(live_client)
        result = analyzer.analyze_threats(priv_esc_packet)

        assert isinstance(result, list)
        for pattern in result:
            assert isinstance(pattern, AnomalyPattern)
            # Closed-world: all fact_ids must exist in packet
            assert pattern.fact_ids <= priv_esc_packet.fact_ids
            # Confidence must be valid
            assert 0.0 <= pattern.confidence <= 1.0

    def test_skeptic_live_explanation(self, live_client, priv_esc_packet):
        """Skeptic finds benign explanations via live LLM."""
        # First run architect to get a message for the skeptic
        analyzer = LLMThreatAnalyzer(live_client)
        patterns = analyzer.analyze_threats(priv_esc_packet)

        # Run a quick rule-based cycle to get an architect message
        baseline = run_cycle_with_strategies(priv_esc_packet)
        architect_msg = baseline.architect_message

        finder = LLMExplanationFinder(live_client)
        result = finder.find_explanations(architect_msg, priv_esc_packet)

        assert isinstance(result, list)
        for explanation in result:
            assert isinstance(explanation, BenignExplanation)
            assert explanation.fact_ids <= priv_esc_packet.fact_ids
            assert 0.0 <= explanation.confidence <= 1.0

    def test_narrator_live_narrative(self, live_client, priv_esc_packet):
        """Narrator generates explanation via live LLM."""
        baseline = run_cycle_with_strategies(priv_esc_packet)
        gen = LLMNarrativeGenerator(live_client)
        result = gen.generate_narrative(baseline.verdict, priv_esc_packet)
        assert isinstance(result, str)
        assert len(result) > 0

    def test_full_cycle_live(self, live_client, priv_esc_packet):
        """Full single-turn cycle with live LLM agents."""
        result = run_cycle_with_strategies(
            priv_esc_packet,
            threat_analyzer=LLMThreatAnalyzer(live_client),
            explanation_finder=LLMExplanationFinder(live_client),
            narrative_generator=LLMNarrativeGenerator(live_client),
        )

        assert isinstance(result, CycleResult)
        assert result.verdict is not None
        assert result.architect_message is not None
        assert result.skeptic_message is not None
        # Verdict outcome must be a valid enum value
        assert result.verdict.outcome.value in (
            "threat_confirmed", "threat_dismissed", "inconclusive",
        )

        # Store in Memory Stream
        stream = MemoryStream(backend=InMemoryBackend())
        entry = stream.store(result)
        assert entry is not None
        assert stream.verify_chain_integrity()

    def test_full_cycle_live_with_observability(self, live_client, priv_esc_packet):
        """Full cycle with LLMCallLogger capturing all calls."""
        call_logger = LLMCallLogger()
        result = run_cycle_with_strategies(
            priv_esc_packet,
            threat_analyzer=LLMThreatAnalyzer(
                live_client, call_logger=call_logger,
            ),
            explanation_finder=LLMExplanationFinder(
                live_client, call_logger=call_logger,
            ),
            narrative_generator=LLMNarrativeGenerator(
                live_client, call_logger=call_logger,
            ),
        )

        assert isinstance(result, CycleResult)
        # Should have 3 records (architect + skeptic + narrator)
        assert len(call_logger.records) == 3
        for record in call_logger.records:
            assert record.input_tokens > 0
            assert record.output_tokens > 0
            assert record.latency_ms > 0
            assert record.model != ""

    def test_live_cost_tracking(self, live_client, priv_esc_packet):
        """Verify token counts and cost estimate from real API."""
        call_logger = LLMCallLogger()
        run_cycle_with_strategies(
            priv_esc_packet,
            threat_analyzer=LLMThreatAnalyzer(
                live_client, call_logger=call_logger,
            ),
            explanation_finder=LLMExplanationFinder(
                live_client, call_logger=call_logger,
            ),
            narrative_generator=LLMNarrativeGenerator(
                live_client, call_logger=call_logger,
            ),
        )

        summary = call_logger.summary()
        assert summary["total_calls"] > 0
        assert summary["total_input_tokens"] > 0
        assert summary["total_output_tokens"] > 0
        assert summary["estimated_cost_usd"] > 0

    def test_live_fallback_on_bad_response(self, live_client, priv_esc_packet):
        """Verify fallback works even in live mode (empty packet)."""
        # Use a packet with a single benign fact — LLM might return nothing valid
        from ares.dialectic.evidence.fact import EntityType, Fact
        from ares.dialectic.evidence.packet import EvidencePacket, TimeWindow
        from ares.dialectic.evidence.provenance import Provenance, SourceType
        from datetime import datetime

        packet = EvidencePacket(
            packet_id="minimal-live-test",
            time_window=TimeWindow(
                start=datetime(2024, 1, 1),
                end=datetime(2024, 1, 31),
            ),
        )
        packet.add_fact(Fact(
            fact_id="fact-only",
            entity_id="node-001",
            entity_type=EntityType.NODE,
            field="status",
            value="normal",
            timestamp=datetime(2024, 1, 15),
            provenance=Provenance(
                source_type=SourceType.MANUAL,
                source_id="test",
            ),
        ))
        packet.freeze()

        call_logger = LLMCallLogger()
        result = run_cycle_with_strategies(
            packet,
            threat_analyzer=LLMThreatAnalyzer(
                live_client, call_logger=call_logger,
            ),
        )
        # Should still produce valid result (fallback or LLM)
        assert isinstance(result, CycleResult)
        assert result.verdict is not None

    def test_live_multi_turn(self, live_client, priv_esc_packet):
        """Multi-turn cycle with live LLM agents."""
        result = run_multi_turn_with_strategies(
            priv_esc_packet,
            threat_analyzer=LLMThreatAnalyzer(live_client),
            explanation_finder=LLMExplanationFinder(live_client),
            narrative_generator=LLMNarrativeGenerator(live_client),
            max_rounds=2,
        )

        assert isinstance(result, CycleResult)
        assert result.verdict is not None
        # Store in Memory Stream
        stream = MemoryStream(backend=InMemoryBackend())
        entry = stream.store(result)
        assert entry is not None
        assert stream.verify_chain_integrity()
