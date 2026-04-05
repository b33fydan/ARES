"""Tests for v5 LLM strategy prompts — kill chain awareness.

Session 042: Validates that v5 prompts contain the kill chain framework,
preserve closed-world constraints from v4, and differ from v4 where expected.
All tests are prompt content validation — no live LLM calls.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

from ares.dialectic.agents.strategies.client import LLMResponse
from ares.dialectic.agents.strategies.prompts_v4 import (
    ARCHITECT_SYSTEM_PROMPT_V4,
    NARRATOR_SYSTEM_PROMPT_V4,
    SKEPTIC_SYSTEM_PROMPT_V4,
)
from ares.dialectic.agents.strategies.prompts_v5 import (
    ARCHITECT_SYSTEM_PROMPT_V5,
    NARRATOR_SYSTEM_PROMPT_V5,
    SKEPTIC_SYSTEM_PROMPT_V5,
)
from ares.dialectic.agents.strategies.llm_strategy_v5 import (
    LLMThreatAnalyzerV5,
    LLMExplanationFinderV5,
    LLMNarrativeGeneratorV5,
)

from .conftest import make_message, make_verdict


# =============================================================================
# V5 Class Instantiation
# =============================================================================


class TestV5ClassInstantiation:
    """V5 strategy classes instantiate with the same interface as v4."""

    def test_threat_analyzer_v5_instantiates(self, mock_client):
        analyzer = LLMThreatAnalyzerV5(mock_client)
        assert analyzer is not None

    def test_explanation_finder_v5_instantiates(self, mock_client):
        finder = LLMExplanationFinderV5(mock_client)
        assert finder is not None

    def test_narrative_generator_v5_instantiates(self, mock_client):
        generator = LLMNarrativeGeneratorV5(mock_client)
        assert generator is not None


# =============================================================================
# V5 Architect Prompt — Kill Chain Content
# =============================================================================


class TestV5ArchitectKillChain:
    """V5 Architect prompt contains the kill chain assessment framework."""

    def test_contains_kill_chain_header(self):
        assert "KILL CHAIN ASSESSMENT" in ARCHITECT_SYSTEM_PROMPT_V5

    def test_contains_stage_1_reconnaissance(self):
        assert "STAGE 1" in ARCHITECT_SYSTEM_PROMPT_V5
        assert "RECONNAISSANCE" in ARCHITECT_SYSTEM_PROMPT_V5

    def test_contains_stage_2_vulnerability(self):
        assert "STAGE 2" in ARCHITECT_SYSTEM_PROMPT_V5
        assert "VULNERABILITY IDENTIFIED" in ARCHITECT_SYSTEM_PROMPT_V5

    def test_contains_stage_3_exploitation(self):
        assert "STAGE 3" in ARCHITECT_SYSTEM_PROMPT_V5
        assert "EXPLOITATION CONFIRMED" in ARCHITECT_SYSTEM_PROMPT_V5

    def test_contains_stage_4_post_exploitation(self):
        assert "STAGE 4" in ARCHITECT_SYSTEM_PROMPT_V5
        assert "POST-EXPLOITATION" in ARCHITECT_SYSTEM_PROMPT_V5

    def test_contains_failed_attack_case(self):
        assert "FAILED ATTACK" in ARCHITECT_SYSTEM_PROMPT_V5

    def test_stage_1_confidence_range(self):
        assert "0.30-0.45" in ARCHITECT_SYSTEM_PROMPT_V5

    def test_stage_2_confidence_range(self):
        assert "0.45-0.60" in ARCHITECT_SYSTEM_PROMPT_V5

    def test_stage_3_confidence_range(self):
        assert "0.75-0.90" in ARCHITECT_SYSTEM_PROMPT_V5

    def test_stage_4_confidence_range(self):
        assert "0.90-0.95" in ARCHITECT_SYSTEM_PROMPT_V5

    def test_failed_attack_confidence_range(self):
        assert "0.25-0.40" in ARCHITECT_SYSTEM_PROMPT_V5

    def test_contains_pentest_tool_conditional(self):
        prompt = ARCHITECT_SYSTEM_PROMPT_V5
        assert "pentest" in prompt.lower()
        assert "offensive" in prompt.lower()
        # Conditional: telemetry-only should use standard assessment
        assert "security telemetry" in prompt.lower()

    def test_contains_highest_stage_instruction(self):
        assert "highest stage reached" in ARCHITECT_SYSTEM_PROMPT_V5.lower()


# =============================================================================
# V5 Architect Prompt — Preserved V4 Constraints
# =============================================================================


class TestV5ArchitectPreservesV4:
    """V5 Architect retains all critical v4 constraints."""

    def test_preserves_closed_world_rule(self):
        assert "CLOSED WORLD" in ARCHITECT_SYSTEM_PROMPT_V5

    def test_preserves_fact_citation_requirement(self):
        assert "EVIDENCE EXHAUSTIVENESS REQUIREMENT" in ARCHITECT_SYSTEM_PROMPT_V5

    def test_preserves_mixed_signal_calibration(self):
        assert "MIXED-SIGNAL CALIBRATION" in ARCHITECT_SYSTEM_PROMPT_V5

    def test_preserves_pattern_types(self):
        assert "PATTERN TYPES" in ARCHITECT_SYSTEM_PROMPT_V5
        assert "PRIVILEGE_ESCALATION" in ARCHITECT_SYSTEM_PROMPT_V5

    def test_preserves_json_array_instruction(self):
        assert "JSON array" in ARCHITECT_SYSTEM_PROMPT_V5

    def test_preserves_no_markdown_instruction(self):
        assert "No explanation, no markdown, no preamble" in ARCHITECT_SYSTEM_PROMPT_V5


# =============================================================================
# V5 Architect Prompt — Different from V4
# =============================================================================


class TestV5ArchitectDiffersFromV4:
    """V5 Architect prompt is NOT identical to v4."""

    def test_v5_architect_differs_from_v4(self):
        assert ARCHITECT_SYSTEM_PROMPT_V5 != ARCHITECT_SYSTEM_PROMPT_V4

    def test_v5_architect_is_longer_than_v4(self):
        # Kill chain framework adds significant content
        assert len(ARCHITECT_SYSTEM_PROMPT_V5) > len(ARCHITECT_SYSTEM_PROMPT_V4)

    def test_v5_has_kill_chain_v4_does_not(self):
        assert "KILL CHAIN" in ARCHITECT_SYSTEM_PROMPT_V5
        assert "KILL CHAIN" not in ARCHITECT_SYSTEM_PROMPT_V4


# =============================================================================
# V5 Skeptic Prompt — Kill Chain Defense
# =============================================================================


class TestV5SkepticKillChain:
    """V5 Skeptic prompt contains kill chain defense arguments."""

    def test_contains_kill_chain_defense_section(self):
        assert "KILL CHAIN DEFENSE" in SKEPTIC_SYSTEM_PROMPT_V5

    def test_contains_exploitation_challenge(self):
        prompt = SKEPTIC_SYSTEM_PROMPT_V5.lower()
        assert "did the attack actually succeed" in prompt

    def test_contains_failure_indicator_guidance(self):
        prompt = SKEPTIC_SYSTEM_PROMPT_V5
        assert "exploited: false" in prompt or "vulnerable: false" in prompt

    def test_contains_recon_not_threat_argument(self):
        prompt = SKEPTIC_SYSTEM_PROMPT_V5.lower()
        assert "reconnaissance" in prompt

    def test_skeptic_differs_from_v4(self):
        assert SKEPTIC_SYSTEM_PROMPT_V5 != SKEPTIC_SYSTEM_PROMPT_V4

    def test_skeptic_preserves_closed_world(self):
        assert "CLOSED WORLD" in SKEPTIC_SYSTEM_PROMPT_V5

    def test_skeptic_preserves_explanation_types(self):
        assert "EXPLANATION TYPES" in SKEPTIC_SYSTEM_PROMPT_V5


# =============================================================================
# V5 Narrator — Unchanged from V4
# =============================================================================


class TestV5Narrator:
    """V5 Narrator is identical to v4."""

    def test_narrator_unchanged_from_v4(self):
        assert NARRATOR_SYSTEM_PROMPT_V5 == NARRATOR_SYSTEM_PROMPT_V4


# =============================================================================
# V5 Strategy Protocol Compliance
# =============================================================================


class TestV5ProtocolCompliance:
    """V5 classes follow the same protocol as base classes."""

    def test_threat_analyzer_has_analyze_threats(self):
        assert hasattr(LLMThreatAnalyzerV5, "analyze_threats")

    def test_explanation_finder_has_find_explanations(self):
        assert hasattr(LLMExplanationFinderV5, "find_explanations")

    def test_narrative_generator_has_generate_narrative(self):
        assert hasattr(LLMNarrativeGeneratorV5, "generate_narrative")

    def test_threat_analyzer_calls_v5_prompt(self, mock_client, sample_packet):
        """V5 Architect sends v5 system prompt to the client."""
        mock_client.complete.return_value = LLMResponse(
            content='[{"pattern_type": "suspicious_process", "fact_ids": ["fact-001"], "confidence": 0.5, "description": "test"}]',
            model="claude-sonnet-4-20250514",
            usage_input_tokens=10,
            usage_output_tokens=5,
        )
        analyzer = LLMThreatAnalyzerV5(mock_client)
        analyzer.analyze_threats(sample_packet)
        call_args = mock_client.complete.call_args
        assert "KILL CHAIN" in call_args.kwargs.get("system", call_args[1].get("system", ""))

    def test_explanation_finder_calls_v5_prompt(self, mock_client, sample_packet, architect_msg):
        """V5 Skeptic sends v5 system prompt to the client."""
        mock_client.complete.return_value = LLMResponse(
            content='[{"explanation_type": "known_admin", "fact_ids": ["fact-001"], "confidence": 0.5, "description": "test"}]',
            model="claude-sonnet-4-20250514",
            usage_input_tokens=10,
            usage_output_tokens=5,
        )
        finder = LLMExplanationFinderV5(mock_client)
        finder.find_explanations(architect_msg, sample_packet)
        call_args = mock_client.complete.call_args
        assert "KILL CHAIN DEFENSE" in call_args.kwargs.get("system", call_args[1].get("system", ""))
