"""Tests for round-aware multi-turn LLM strategy implementations.

All tests are deterministic — NO live LLM calls. The AnthropicClient
is mocked throughout.

Tests cover:
- Round state management (set_round_context, reset)
- Protocol compliance (drop-in replacement for single-turn strategies)
- Round-aware behavior (prompt selection based on round number)
- Edge cases (empty messages, missing context, etc.)
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

from ares.dialectic.agents.patterns import (
    AnomalyPattern,
    BenignExplanation,
    ExplanationType,
    PatternType,
    VerdictOutcome,
)
from ares.dialectic.agents.strategies.client import LLMResponse
from ares.dialectic.agents.strategies.multi_turn_strategies import (
    MultiTurnLLMExplanationFinder,
    MultiTurnLLMNarrativeGenerator,
    MultiTurnLLMThreatAnalyzer,
)
from ares.dialectic.agents.strategies.observability import LLMCallLogger
from ares.dialectic.agents.strategies.prompts import (
    ARCHITECT_SYSTEM_PROMPT,
    SKEPTIC_SYSTEM_PROMPT,
)
from ares.dialectic.messages.protocol import Phase

from .conftest import make_assertion, make_message, make_verdict


# =============================================================================
# Round State Management Tests
# =============================================================================


class TestRoundStateManagement:
    """Tests for set_round_context() and reset() on all strategy classes."""

    def test_initial_round_number_is_one(self, mock_client):
        """Strategies start at round 1."""
        analyzer = MultiTurnLLMThreatAnalyzer(mock_client)
        assert analyzer._round_number == 1

    def test_set_round_context_updates_round_number(self, mock_client):
        """set_round_context updates the internal round number."""
        analyzer = MultiTurnLLMThreatAnalyzer(mock_client)
        analyzer.set_round_context(3)
        assert analyzer._round_number == 3

    def test_set_round_context_stores_previous_messages(self, mock_client):
        """set_round_context stores thesis and antithesis messages."""
        analyzer = MultiTurnLLMThreatAnalyzer(mock_client)
        thesis = make_message(phase=Phase.THESIS)
        antithesis = make_message(phase=Phase.ANTITHESIS)
        analyzer.set_round_context(2, previous_thesis=thesis, previous_antithesis=antithesis)
        assert analyzer._previous_thesis is thesis
        assert analyzer._previous_antithesis is antithesis

    def test_reset_clears_round_state(self, mock_client):
        """reset() returns state to initial."""
        analyzer = MultiTurnLLMThreatAnalyzer(mock_client)
        analyzer.set_round_context(
            3,
            previous_thesis=make_message(),
            previous_antithesis=make_message(phase=Phase.ANTITHESIS),
        )
        analyzer.reset()
        assert analyzer._round_number == 1
        assert analyzer._previous_thesis is None
        assert analyzer._previous_antithesis is None

    def test_reset_after_set_round_context_returns_to_round_one(self, mock_client):
        """After set_round_context then reset, round is 1 again."""
        finder = MultiTurnLLMExplanationFinder(mock_client)
        finder.set_round_context(5)
        finder.reset()
        assert finder._round_number == 1

    def test_set_round_context_accepts_none_messages(self, mock_client):
        """set_round_context accepts None for optional message params."""
        analyzer = MultiTurnLLMThreatAnalyzer(mock_client)
        analyzer.set_round_context(2, previous_thesis=None, previous_antithesis=None)
        assert analyzer._round_number == 2
        assert analyzer._previous_thesis is None
        assert analyzer._previous_antithesis is None


# =============================================================================
# Protocol Compliance Tests
# =============================================================================


class TestProtocolCompliance:
    """Tests that multi-turn strategies implement the correct protocols."""

    def test_multi_turn_threat_analyzer_implements_protocol(self, mock_client, sample_packet):
        """MultiTurnLLMThreatAnalyzer has analyze_threats(packet) -> List[AnomalyPattern]."""
        content = json.dumps([{
            "pattern_type": "privilege_escalation",
            "fact_ids": ["fact-001"],
            "confidence": 0.8,
            "description": "test",
        }])
        mock_client.complete.return_value = LLMResponse(
            content=content, model="m", usage_input_tokens=1, usage_output_tokens=1,
        )
        analyzer = MultiTurnLLMThreatAnalyzer(mock_client)
        result = analyzer.analyze_threats(sample_packet)
        assert isinstance(result, list)
        assert all(isinstance(p, AnomalyPattern) for p in result)

    def test_multi_turn_explanation_finder_implements_protocol(
        self, mock_client, sample_packet, architect_msg
    ):
        """MultiTurnLLMExplanationFinder has find_explanations(msg, packet) -> List[BenignExplanation]."""
        content = json.dumps([{
            "explanation_type": "known_admin",
            "fact_ids": ["fact-003"],
            "confidence": 0.7,
            "description": "admin",
        }])
        mock_client.complete.return_value = LLMResponse(
            content=content, model="m", usage_input_tokens=1, usage_output_tokens=1,
        )
        finder = MultiTurnLLMExplanationFinder(mock_client)
        result = finder.find_explanations(architect_msg, sample_packet)
        assert isinstance(result, list)
        assert all(isinstance(e, BenignExplanation) for e in result)

    def test_multi_turn_narrative_generator_implements_protocol(
        self, mock_client, sample_packet, threat_verdict
    ):
        """MultiTurnLLMNarrativeGenerator has generate_narrative(...) -> str."""
        mock_client.complete.return_value = LLMResponse(
            content="Threat confirmed based on evidence.",
            model="m", usage_input_tokens=1, usage_output_tokens=1,
        )
        gen = MultiTurnLLMNarrativeGenerator(mock_client)
        result = gen.generate_narrative(threat_verdict, sample_packet)
        assert isinstance(result, str)
        assert len(result) > 0

    def test_multi_turn_strategies_work_as_drop_in_replacement(
        self, mock_client, sample_packet, architect_msg, threat_verdict
    ):
        """All three strategies work with the same call signatures as single-turn."""
        # ThreatAnalyzer
        content_threats = json.dumps([{
            "pattern_type": "suspicious_process",
            "fact_ids": ["fact-002"],
            "confidence": 0.7,
            "description": "test",
        }])
        mock_client.complete.return_value = LLMResponse(
            content=content_threats, model="m", usage_input_tokens=1, usage_output_tokens=1,
        )
        analyzer = MultiTurnLLMThreatAnalyzer(mock_client)
        threats = analyzer.analyze_threats(sample_packet)
        assert len(threats) >= 1

        # ExplanationFinder
        content_expls = json.dumps([{
            "explanation_type": "scheduled_task",
            "fact_ids": ["fact-004"],
            "confidence": 0.6,
            "description": "test",
        }])
        mock_client.complete.return_value = LLMResponse(
            content=content_expls, model="m", usage_input_tokens=1, usage_output_tokens=1,
        )
        finder = MultiTurnLLMExplanationFinder(mock_client)
        expls = finder.find_explanations(architect_msg, sample_packet)
        assert len(expls) >= 1

        # NarrativeGenerator
        mock_client.complete.return_value = LLMResponse(
            content="The analysis concluded threat.",
            model="m", usage_input_tokens=1, usage_output_tokens=1,
        )
        gen = MultiTurnLLMNarrativeGenerator(mock_client)
        narrative = gen.generate_narrative(threat_verdict, sample_packet)
        assert len(narrative) > 0


# =============================================================================
# Round-Aware Behavior Tests
# =============================================================================


class TestRoundAwareBehavior:
    """Tests that strategies select prompts based on round number."""

    def test_round_one_uses_standard_prompt(self, mock_client, sample_packet):
        """Round 1 (default) uses the standard ARCHITECT_SYSTEM_PROMPT."""
        content = json.dumps([{
            "pattern_type": "privilege_escalation",
            "fact_ids": ["fact-001"],
            "confidence": 0.8,
            "description": "test",
        }])
        mock_client.complete.return_value = LLMResponse(
            content=content, model="m", usage_input_tokens=1, usage_output_tokens=1,
        )
        analyzer = MultiTurnLLMThreatAnalyzer(mock_client)
        analyzer.analyze_threats(sample_packet)

        call_args = mock_client.complete.call_args
        system_prompt = call_args.kwargs.get("system") or call_args[1].get("system")
        assert system_prompt == ARCHITECT_SYSTEM_PROMPT

    def test_round_two_uses_refinement_prompt(self, mock_client, sample_packet):
        """Round 2 with antithesis context uses refinement prompt."""
        content = json.dumps([{
            "pattern_type": "privilege_escalation",
            "fact_ids": ["fact-001"],
            "confidence": 0.8,
            "description": "test",
        }])
        mock_client.complete.return_value = LLMResponse(
            content=content, model="m", usage_input_tokens=1, usage_output_tokens=1,
        )
        antithesis = make_message(
            source_agent="skeptic",
            phase=Phase.ANTITHESIS,
            confidence=0.6,
        )

        analyzer = MultiTurnLLMThreatAnalyzer(mock_client)
        analyzer.set_round_context(2, previous_antithesis=antithesis)
        analyzer.analyze_threats(sample_packet)

        call_args = mock_client.complete.call_args
        system_prompt = call_args.kwargs.get("system") or call_args[1].get("system")
        assert "ROUND 2 REFINEMENT" in system_prompt
        assert ARCHITECT_SYSTEM_PROMPT in system_prompt

    def test_round_two_prompt_includes_skeptic_summary(self, mock_client, sample_packet):
        """Architect's round 2 prompt includes the Skeptic's arguments."""
        content = json.dumps([{
            "pattern_type": "privilege_escalation",
            "fact_ids": ["fact-001"],
            "confidence": 0.8,
            "description": "test",
        }])
        mock_client.complete.return_value = LLMResponse(
            content=content, model="m", usage_input_tokens=1, usage_output_tokens=1,
        )
        skeptic_assertion = make_assertion(
            assertion_id="skep-1",
            fact_ids=("fact-003",),
            interpretation="Known administrator account",
        )
        antithesis = make_message(
            source_agent="skeptic",
            phase=Phase.ANTITHESIS,
            confidence=0.6,
            assertions=[skeptic_assertion],
        )

        analyzer = MultiTurnLLMThreatAnalyzer(mock_client)
        analyzer.set_round_context(2, previous_antithesis=antithesis)
        analyzer.analyze_threats(sample_packet)

        call_args = mock_client.complete.call_args
        system_prompt = call_args.kwargs.get("system") or call_args[1].get("system")
        assert "Known administrator account" in system_prompt
        assert "fact-003" in system_prompt

    def test_round_two_prompt_includes_architect_summary(
        self, mock_client, sample_packet, architect_msg
    ):
        """Skeptic's round 2 prompt includes the Architect's arguments."""
        content = json.dumps([{
            "explanation_type": "known_admin",
            "fact_ids": ["fact-003"],
            "confidence": 0.6,
            "description": "admin activity",
        }])
        mock_client.complete.return_value = LLMResponse(
            content=content, model="m", usage_input_tokens=1, usage_output_tokens=1,
        )
        arch_assertion = make_assertion(
            assertion_id="arch-1",
            fact_ids=("fact-001", "fact-002"),
            interpretation="Privilege escalation attack chain",
        )
        thesis = make_message(
            confidence=0.9,
            assertions=[arch_assertion],
        )

        finder = MultiTurnLLMExplanationFinder(mock_client)
        finder.set_round_context(2, previous_thesis=thesis)
        finder.find_explanations(architect_msg, sample_packet)

        call_args = mock_client.complete.call_args
        system_prompt = call_args.kwargs.get("system") or call_args[1].get("system")
        assert "Privilege escalation attack chain" in system_prompt

    def test_round_one_after_reset_uses_standard_prompt(self, mock_client, sample_packet):
        """After reset(), round 1 uses standard prompt again."""
        content = json.dumps([{
            "pattern_type": "privilege_escalation",
            "fact_ids": ["fact-001"],
            "confidence": 0.8,
            "description": "test",
        }])
        mock_client.complete.return_value = LLMResponse(
            content=content, model="m", usage_input_tokens=1, usage_output_tokens=1,
        )
        analyzer = MultiTurnLLMThreatAnalyzer(mock_client)
        analyzer.set_round_context(2, previous_antithesis=make_message(phase=Phase.ANTITHESIS))
        analyzer.reset()
        analyzer.analyze_threats(sample_packet)

        call_args = mock_client.complete.call_args
        system_prompt = call_args.kwargs.get("system") or call_args[1].get("system")
        assert system_prompt == ARCHITECT_SYSTEM_PROMPT

    def test_fact_id_validation_still_enforced(self, mock_client, sample_packet):
        """Closed-world fact_id validation survives round-aware prompting."""
        content = json.dumps([{
            "pattern_type": "privilege_escalation",
            "fact_ids": ["HALLUCINATED-999"],
            "confidence": 0.9,
            "description": "fake pattern",
        }])
        mock_client.complete.return_value = LLMResponse(
            content=content, model="m", usage_input_tokens=1, usage_output_tokens=1,
        )
        analyzer = MultiTurnLLMThreatAnalyzer(mock_client)
        analyzer.set_round_context(2, previous_antithesis=make_message(phase=Phase.ANTITHESIS))
        result = analyzer.analyze_threats(sample_packet)
        # Hallucinated fact_id should be rejected → fallback
        assert isinstance(result, list)
        # None of the results should cite the hallucinated ID
        for pattern in result:
            assert "HALLUCINATED-999" not in pattern.fact_ids

    def test_fallback_still_works(self, mock_client, sample_packet):
        """Rule-based fallback triggers on API error in round 2."""
        mock_client.complete.side_effect = RuntimeError("network error")
        analyzer = MultiTurnLLMThreatAnalyzer(mock_client)
        analyzer.set_round_context(2, previous_antithesis=make_message(phase=Phase.ANTITHESIS))
        result = analyzer.analyze_threats(sample_packet)
        assert isinstance(result, list)

    def test_call_logger_records_round_aware_calls(self, mock_client, sample_packet):
        """Observability still works — calls are logged with strategy type."""
        content = json.dumps([{
            "pattern_type": "privilege_escalation",
            "fact_ids": ["fact-001"],
            "confidence": 0.8,
            "description": "test",
        }])
        mock_client.complete.return_value = LLMResponse(
            content=content, model="m", usage_input_tokens=10, usage_output_tokens=5,
        )
        logger = LLMCallLogger()
        analyzer = MultiTurnLLMThreatAnalyzer(mock_client, call_logger=logger)
        analyzer.analyze_threats(sample_packet)

        assert len(logger.records) == 1
        assert logger.records[0].strategy_type == "MultiTurnThreatAnalyzer"


# =============================================================================
# Edge Case Tests
# =============================================================================


class TestEdgeCases:
    """Edge cases for multi-turn strategies."""

    def test_set_round_context_with_empty_message(self, mock_client, sample_packet):
        """set_round_context works with a message that has no assertions."""
        content = json.dumps([{
            "pattern_type": "privilege_escalation",
            "fact_ids": ["fact-001"],
            "confidence": 0.8,
            "description": "test",
        }])
        mock_client.complete.return_value = LLMResponse(
            content=content, model="m", usage_input_tokens=1, usage_output_tokens=1,
        )
        empty_msg = make_message(phase=Phase.ANTITHESIS, assertions=[], confidence=0.0)
        analyzer = MultiTurnLLMThreatAnalyzer(mock_client)
        analyzer.set_round_context(2, previous_antithesis=empty_msg)
        # Should not crash
        result = analyzer.analyze_threats(sample_packet)
        assert isinstance(result, list)

    def test_multiple_rounds_accumulate_correctly(self, mock_client, sample_packet):
        """Setting round context multiple times uses the latest."""
        content = json.dumps([{
            "pattern_type": "privilege_escalation",
            "fact_ids": ["fact-001"],
            "confidence": 0.8,
            "description": "test",
        }])
        mock_client.complete.return_value = LLMResponse(
            content=content, model="m", usage_input_tokens=1, usage_output_tokens=1,
        )
        analyzer = MultiTurnLLMThreatAnalyzer(mock_client)
        analyzer.set_round_context(2, previous_antithesis=make_message(phase=Phase.ANTITHESIS))
        analyzer.set_round_context(3, previous_antithesis=make_message(phase=Phase.ANTITHESIS))
        assert analyzer._round_number == 3

        analyzer.analyze_threats(sample_packet)
        call_args = mock_client.complete.call_args
        system_prompt = call_args.kwargs.get("system") or call_args[1].get("system")
        assert "ROUND 3" in system_prompt

    def test_strategy_works_without_set_round_context(self, mock_client, sample_packet):
        """Strategy works fine if set_round_context is never called (round 1)."""
        content = json.dumps([{
            "pattern_type": "privilege_escalation",
            "fact_ids": ["fact-001"],
            "confidence": 0.8,
            "description": "test",
        }])
        mock_client.complete.return_value = LLMResponse(
            content=content, model="m", usage_input_tokens=1, usage_output_tokens=1,
        )
        analyzer = MultiTurnLLMThreatAnalyzer(mock_client)
        result = analyzer.analyze_threats(sample_packet)
        assert isinstance(result, list)
        assert len(result) == 1

    def test_narrator_round_aware_includes_round_count(self, mock_client, sample_packet, threat_verdict):
        """Narrator prompt includes round count when termination context is set."""
        mock_client.complete.return_value = LLMResponse(
            content="Multi-round analysis concluded threat.",
            model="m", usage_input_tokens=1, usage_output_tokens=1,
        )
        gen = MultiTurnLLMNarrativeGenerator(mock_client)
        gen.set_termination_context(total_rounds=3, termination_reason="NO_NEW_EVIDENCE")
        gen.generate_narrative(threat_verdict, sample_packet)

        call_args = mock_client.complete.call_args
        system_prompt = call_args.kwargs.get("system") or call_args[1].get("system")
        assert "3-round" in system_prompt or "3 round" in system_prompt
        assert "NO_NEW_EVIDENCE" in system_prompt

    def test_narrator_reset_clears_termination_context(self, mock_client):
        """Narrator reset() clears termination context."""
        gen = MultiTurnLLMNarrativeGenerator(mock_client)
        gen.set_termination_context(total_rounds=3, termination_reason="DONE")
        gen.reset()
        assert gen._total_rounds == 1
        assert gen._termination_reason is None

    def test_explanation_finder_fallback_on_api_error(
        self, mock_client, sample_packet, architect_msg
    ):
        """ExplanationFinder falls back on API error in round 2."""
        mock_client.complete.side_effect = RuntimeError("connection refused")
        finder = MultiTurnLLMExplanationFinder(mock_client)
        finder.set_round_context(2, previous_thesis=make_message())
        result = finder.find_explanations(architect_msg, sample_packet)
        assert isinstance(result, list)
