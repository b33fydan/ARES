"""Tests for anchored prompts and strategies — Session 020.

Verifies conviction anchoring language, obligation-to-move language,
structured rebuttal format, round-aware behavior, and protocol compliance.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

from ares.dialectic.agents.strategies.anchored_prompts import (
    get_anchored_architect_system_prompt,
    get_anchored_skeptic_system_prompt,
)
from ares.dialectic.agents.strategies.anchored_strategies import (
    AnchoredMultiTurnExplanationFinder,
    AnchoredMultiTurnNarrativeGenerator,
    AnchoredMultiTurnThreatAnalyzer,
)
from ares.dialectic.messages.assertions import Assertion, AssertionType
from ares.dialectic.messages.protocol import (
    DialecticalMessage,
    MessageType,
    Phase,
)


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------


def _make_message(
    source_agent: str = "test-agent",
    phase: Phase = Phase.ANTITHESIS,
    confidence: float = 0.6,
) -> DialecticalMessage:
    """Build a test DialecticalMessage for prompt injection."""
    return DialecticalMessage(
        message_id=str(uuid.uuid4()),
        timestamp=datetime(2024, 1, 15, 12, 0, 0),
        source_agent=source_agent,
        target_agent="broadcast",
        packet_id="test-packet-001",
        cycle_id="cycle-test001",
        phase=phase,
        turn_number=2,
        message_type=MessageType.REBUTTAL,
        assertions=[
            Assertion(
                assertion_id="assert-001",
                assertion_type=AssertionType.ALT,
                fact_ids=("fact-001",),
                interpretation="This could be a scheduled maintenance task",
                operator=">",
                threshold=0,
            )
        ],
        confidence=confidence,
    )


# ------------------------------------------------------------------
# Architect Conviction Anchoring
# ------------------------------------------------------------------


class TestArchitectConvictionAnchoring:
    """Architect prompts include conviction anchoring language."""

    def test_anchored_architect_prompt_contains_conviction_language_round1(self):
        prompt = get_anchored_architect_system_prompt(
            round_number=1, previous_messages=[]
        )
        assert "Do NOT lower your confidence" in prompt
        assert "capitulation" in prompt
        assert "SPECIFIC" in prompt

    def test_anchored_architect_prompt_round1_vs_round2(self):
        """Round 1 has anchoring but no rebuttal format. Round 2 has both."""
        r1 = get_anchored_architect_system_prompt(
            round_number=1, previous_messages=[]
        )
        msg = _make_message(phase=Phase.ANTITHESIS)
        r2 = get_anchored_architect_system_prompt(
            round_number=2, previous_messages=[msg]
        )

        # Round 1 has anchoring
        assert "CONVICTION ANCHORING" in r1
        # Round 1 does NOT have round refinement
        assert "ROUND 2 REFINEMENT" not in r1

        # Round 2 has both anchoring AND refinement
        assert "CONVICTION ANCHORING" in r2
        assert "ROUND 2 REFINEMENT" in r2
        assert "DISPUTED_CLAIMS" in r2

    def test_anchored_architect_prompt_round2_includes_opponent_summary(self):
        msg = _make_message(
            source_agent="test-skeptic",
            phase=Phase.ANTITHESIS,
            confidence=0.7,
        )
        prompt = get_anchored_architect_system_prompt(
            round_number=2, previous_messages=[msg]
        )
        assert "test-skeptic" in prompt
        assert "scheduled maintenance" in prompt


# ------------------------------------------------------------------
# Skeptic Obligation to Move
# ------------------------------------------------------------------


class TestSkepticObligationToMove:
    """Skeptic prompts include obligation-to-move language."""

    def test_anchored_skeptic_prompt_contains_obligation_language_round1(self):
        prompt = get_anchored_skeptic_system_prompt(
            round_number=1, previous_messages=[]
        )
        assert "MUST acknowledge" in prompt
        assert "obstinacy" in prompt
        assert "stress-test, not to win" in prompt

    def test_anchored_skeptic_prompt_round1_vs_round2(self):
        """Round 1 has obligation but no rebuttal format. Round 2 has both."""
        r1 = get_anchored_skeptic_system_prompt(
            round_number=1, previous_messages=[]
        )
        msg = _make_message(phase=Phase.THESIS)
        r2 = get_anchored_skeptic_system_prompt(
            round_number=2, previous_messages=[msg]
        )

        assert "OBLIGATION TO MOVE" in r1
        assert "ROUND 2 REFINEMENT" not in r1

        assert "OBLIGATION TO MOVE" in r2
        assert "ROUND 2 REFINEMENT" in r2
        assert "DISPUTED_CLAIMS" in r2

    def test_anchored_skeptic_prompt_round2_includes_opponent_summary(self):
        msg = _make_message(
            source_agent="test-architect",
            phase=Phase.THESIS,
            confidence=0.85,
        )
        prompt = get_anchored_skeptic_system_prompt(
            round_number=2, previous_messages=[msg]
        )
        assert "test-architect" in prompt


# ------------------------------------------------------------------
# Structured Rebuttal Format
# ------------------------------------------------------------------


class TestStructuredRebuttalFormat:
    """Round 2+ prompts include the DISPUTED_CLAIMS format."""

    def test_structured_rebuttal_format_in_round2_architect(self):
        msg = _make_message(phase=Phase.ANTITHESIS)
        prompt = get_anchored_architect_system_prompt(
            round_number=2, previous_messages=[msg]
        )
        assert "DISPUTED_CLAIMS" in prompt
        assert "OVERALL_CONFIDENCE" in prompt
        assert "CONFIDENCE_DELTA" in prompt
        assert "DELTA_JUSTIFICATION" in prompt

    def test_structured_rebuttal_format_in_round2_skeptic(self):
        msg = _make_message(phase=Phase.THESIS)
        prompt = get_anchored_skeptic_system_prompt(
            round_number=2, previous_messages=[msg]
        )
        assert "DISPUTED_CLAIMS" in prompt
        assert "OVERALL_CONFIDENCE" in prompt
        assert "CONFIDENCE_DELTA" in prompt
        assert "DELTA_JUSTIFICATION" in prompt

    def test_structured_rebuttal_format_not_in_round1(self):
        r1_arch = get_anchored_architect_system_prompt(
            round_number=1, previous_messages=[]
        )
        r1_skep = get_anchored_skeptic_system_prompt(
            round_number=1, previous_messages=[]
        )
        assert "DISPUTED_CLAIMS" not in r1_arch
        assert "DISPUTED_CLAIMS" not in r1_skep


# ------------------------------------------------------------------
# Protocol Compliance
# ------------------------------------------------------------------


class TestProtocolCompliance:
    """Anchored strategies implement the correct protocols."""

    def test_anchored_threat_analyzer_implements_protocol(self):
        """AnchoredMultiTurnThreatAnalyzer has analyze_threats method."""
        from ares.dialectic.agents.strategies.protocol import ThreatAnalyzer

        mock_client = MagicMock()
        mock_client.complete.return_value = MagicMock(
            content="[]", usage_input_tokens=0, usage_output_tokens=0, model="test"
        )
        analyzer = AnchoredMultiTurnThreatAnalyzer(mock_client)
        assert hasattr(analyzer, "analyze_threats")
        assert callable(analyzer.analyze_threats)

    def test_anchored_explanation_finder_implements_protocol(self):
        """AnchoredMultiTurnExplanationFinder has find_explanations method."""
        from ares.dialectic.agents.strategies.protocol import ExplanationFinder

        mock_client = MagicMock()
        finder = AnchoredMultiTurnExplanationFinder(mock_client)
        assert hasattr(finder, "find_explanations")
        assert callable(finder.find_explanations)

    def test_anchored_narrative_generator_implements_protocol(self):
        """AnchoredMultiTurnNarrativeGenerator has generate_narrative method."""
        mock_client = MagicMock()
        gen = AnchoredMultiTurnNarrativeGenerator(mock_client)
        assert hasattr(gen, "generate_narrative")
        assert callable(gen.generate_narrative)


# ------------------------------------------------------------------
# Round and Message Interface
# ------------------------------------------------------------------


class TestRoundAndMessageInterface:
    """Anchored strategies accept round_number and previous_messages."""

    def test_anchored_strategies_accept_round_and_messages(self):
        """All three strategies have set_round_context and reset methods."""
        mock_client = MagicMock()
        analyzer = AnchoredMultiTurnThreatAnalyzer(mock_client)
        finder = AnchoredMultiTurnExplanationFinder(mock_client)
        narrator = AnchoredMultiTurnNarrativeGenerator(mock_client)

        msg = _make_message()

        # All accept set_round_context
        analyzer.set_round_context(2, previous_thesis=msg, previous_antithesis=msg)
        finder.set_round_context(2, previous_thesis=msg, previous_antithesis=msg)
        narrator.set_round_context(2, previous_thesis=msg, previous_antithesis=msg)

        # All accept reset
        analyzer.reset()
        finder.reset()
        narrator.reset()

    def test_anchored_threat_analyzer_initial_round_is_one(self):
        mock_client = MagicMock()
        analyzer = AnchoredMultiTurnThreatAnalyzer(mock_client)
        assert analyzer._round_number == 1

    def test_anchored_explanation_finder_initial_round_is_one(self):
        mock_client = MagicMock()
        finder = AnchoredMultiTurnExplanationFinder(mock_client)
        assert finder._round_number == 1

    def test_anchored_narrator_has_termination_context(self):
        """Narrator accepts set_termination_context for multi-turn metadata."""
        mock_client = MagicMock()
        narrator = AnchoredMultiTurnNarrativeGenerator(mock_client)
        narrator.set_termination_context(
            total_rounds=3, termination_reason="MAX_TURNS_EXCEEDED"
        )
        assert narrator._total_rounds == 3
        assert narrator._termination_reason == "MAX_TURNS_EXCEEDED"


# ------------------------------------------------------------------
# JSON Extraction with Structured Rebuttal
# ------------------------------------------------------------------


class TestJsonExtractionWithRebuttal:
    """The anchored strategies can parse JSON from mixed analysis+JSON output."""

    def test_extract_json_from_pure_array(self):
        from ares.dialectic.agents.strategies.anchored_strategies import (
            _parse_json_array,
        )
        result = _parse_json_array('[{"a": 1}]')
        assert result == [{"a": 1}]

    def test_extract_json_from_analysis_then_array(self):
        from ares.dialectic.agents.strategies.anchored_strategies import (
            _parse_json_array,
        )
        content = (
            "DISPUTED_CLAIMS:\n"
            "1. Privilege escalation\n\n"
            "OVERALL_CONFIDENCE: 0.85\n"
            "CONFIDENCE_DELTA: -0.05\n\n"
            '[{"pattern_type": "privilege_escalation", '
            '"fact_ids": ["f1"], "confidence": 0.85, '
            '"description": "test"}]'
        )
        result = _parse_json_array(content)
        assert len(result) == 1
        assert result[0]["pattern_type"] == "privilege_escalation"

    def test_extract_json_from_code_fenced_after_analysis(self):
        from ares.dialectic.agents.strategies.anchored_strategies import (
            _parse_json_array,
        )
        content = (
            "DISPUTED_CLAIMS:\n1. Test\n\n"
            "```json\n"
            '[{"pattern_type": "lateral_movement", '
            '"fact_ids": ["f1"], "confidence": 0.7, '
            '"description": "test"}]\n'
            "```"
        )
        result = _parse_json_array(content)
        assert len(result) == 1
        assert result[0]["pattern_type"] == "lateral_movement"
