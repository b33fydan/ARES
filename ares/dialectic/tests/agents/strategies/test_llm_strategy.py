"""Tests for LLM strategy implementations with mocked API calls.

All tests use mocked AnthropicClient — no real API calls are made.
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
)
from ares.dialectic.agents.strategies.client import LLMResponse
from ares.dialectic.agents.strategies.llm_strategy import (
    LLMExplanationFinder,
    LLMNarrativeGenerator,
    LLMThreatAnalyzer,
    _parse_json_array,
    _serialize_facts,
    _strip_code_fences,
)

from .conftest import make_message, make_verdict


# =============================================================================
# LLMThreatAnalyzer Tests
# =============================================================================


class TestLLMThreatAnalyzer:
    """Tests for LLM-powered threat analysis."""

    def test_valid_json_response(self, mock_client, sample_packet, mock_llm_response_valid):
        """Valid JSON response produces correct AnomalyPattern list."""
        mock_client.complete.return_value = mock_llm_response_valid
        analyzer = LLMThreatAnalyzer(mock_client)
        result = analyzer.analyze_threats(sample_packet)
        assert len(result) == 1
        assert result[0].pattern_type == PatternType.PRIVILEGE_ESCALATION
        assert result[0].fact_ids == frozenset({"fact-001", "fact-002"})
        assert result[0].confidence == 0.85

    def test_json_in_markdown_code_fences(self, mock_client, sample_packet):
        """JSON wrapped in ```json ... ``` is parsed correctly."""
        response = LLMResponse(
            content='```json\n[{"pattern_type": "privilege_escalation", "fact_ids": ["fact-001"], "confidence": 0.8, "description": "test"}]\n```',
            model="claude-sonnet-4-20250514",
            usage_input_tokens=10,
            usage_output_tokens=5,
        )
        mock_client.complete.return_value = response
        analyzer = LLMThreatAnalyzer(mock_client)
        result = analyzer.analyze_threats(sample_packet)
        assert len(result) == 1
        assert result[0].pattern_type == PatternType.PRIVILEGE_ESCALATION

    def test_empty_array_falls_back(self, mock_client, sample_packet):
        """Empty JSON array triggers fallback to rule-based."""
        response = LLMResponse(content="[]", model="m", usage_input_tokens=1, usage_output_tokens=1)
        mock_client.complete.return_value = response
        analyzer = LLMThreatAnalyzer(mock_client)
        result = analyzer.analyze_threats(sample_packet)
        # Fallback produces rule-based results (sample_packet has anomalies)
        assert isinstance(result, list)

    def test_null_fields_handled_gracefully(self, mock_client, sample_packet):
        """Items with null/missing fields are skipped."""
        response = LLMResponse(
            content='[{"pattern_type": null, "fact_ids": null}]',
            model="m", usage_input_tokens=1, usage_output_tokens=1,
        )
        mock_client.complete.return_value = response
        analyzer = LLMThreatAnalyzer(mock_client)
        # Should not crash — falls back to rule-based
        result = analyzer.analyze_threats(sample_packet)
        assert isinstance(result, list)

    def test_multiple_valid_patterns(self, mock_client, sample_packet):
        """Multiple valid patterns in response are all returned."""
        content = json.dumps([
            {"pattern_type": "privilege_escalation", "fact_ids": ["fact-001"], "confidence": 0.8, "description": "priv esc"},
            {"pattern_type": "suspicious_process", "fact_ids": ["fact-002"], "confidence": 0.6, "description": "proc"},
        ])
        mock_client.complete.return_value = LLMResponse(content=content, model="m", usage_input_tokens=1, usage_output_tokens=1)
        analyzer = LLMThreatAnalyzer(mock_client)
        result = analyzer.analyze_threats(sample_packet)
        assert len(result) == 2
        types = {p.pattern_type for p in result}
        assert PatternType.PRIVILEGE_ESCALATION in types
        assert PatternType.SUSPICIOUS_PROCESS in types


# =============================================================================
# LLMExplanationFinder Tests
# =============================================================================


class TestLLMExplanationFinder:
    """Tests for LLM-powered explanation finding."""

    def test_valid_response(self, mock_client, sample_packet, mock_llm_response_explanations, architect_msg):
        """Valid JSON response produces correct BenignExplanation list."""
        mock_client.complete.return_value = mock_llm_response_explanations
        finder = LLMExplanationFinder(mock_client)
        result = finder.find_explanations(architect_msg, sample_packet)
        assert len(result) == 1
        assert result[0].explanation_type == ExplanationType.KNOWN_ADMIN
        assert result[0].confidence == 0.7

    def test_empty_response_falls_back(self, mock_client, sample_packet, architect_msg):
        """Empty response triggers fallback."""
        response = LLMResponse(content="[]", model="m", usage_input_tokens=1, usage_output_tokens=1)
        mock_client.complete.return_value = response
        finder = LLMExplanationFinder(mock_client)
        result = finder.find_explanations(architect_msg, sample_packet)
        assert isinstance(result, list)

    def test_api_error_falls_back(self, mock_client, sample_packet, architect_msg):
        """API error triggers fallback."""
        mock_client.complete.side_effect = Exception("API error")
        finder = LLMExplanationFinder(mock_client)
        result = finder.find_explanations(architect_msg, sample_packet)
        assert isinstance(result, list)


# =============================================================================
# LLMNarrativeGenerator Tests
# =============================================================================


class TestLLMNarrativeGenerator:
    """Tests for LLM-powered narrative generation."""

    def test_valid_response(self, mock_client, sample_packet, mock_llm_response_narrative, threat_verdict):
        """Valid response returns string directly."""
        mock_client.complete.return_value = mock_llm_response_narrative
        gen = LLMNarrativeGenerator(mock_client)
        result = gen.generate_narrative(threat_verdict, sample_packet)
        assert "evidence strongly suggests" in result

    def test_empty_response_falls_back(self, mock_client, sample_packet, threat_verdict):
        """Empty response triggers template fallback."""
        response = LLMResponse(content="", model="m", usage_input_tokens=1, usage_output_tokens=1)
        mock_client.complete.return_value = response
        gen = LLMNarrativeGenerator(mock_client)
        result = gen.generate_narrative(threat_verdict, sample_packet)
        assert "VERDICT: THREAT CONFIRMED" in result

    def test_api_error_falls_back(self, mock_client, sample_packet, threat_verdict):
        """API error triggers template fallback."""
        mock_client.complete.side_effect = RuntimeError("network error")
        gen = LLMNarrativeGenerator(mock_client)
        result = gen.generate_narrative(threat_verdict, sample_packet)
        assert "VERDICT: THREAT CONFIRMED" in result


# =============================================================================
# Prompt Builder Tests
# =============================================================================


class TestPromptBuilders:
    """Tests for prompt construction helpers."""

    def test_serialize_facts_includes_all_facts(self, sample_packet):
        """Fact serialization includes all facts from packet."""
        text = _serialize_facts(sample_packet)
        assert "fact-001" in text
        assert "fact-002" in text
        assert "fact-003" in text

    def test_serialize_facts_includes_packet_id(self, sample_packet):
        """Fact serialization includes the packet ID."""
        text = _serialize_facts(sample_packet)
        assert sample_packet.packet_id in text

    def test_serialize_empty_packet(self, empty_packet):
        """Serialization handles packet with minimal facts."""
        text = _serialize_facts(empty_packet)
        assert "fact-benign-001" in text

    def test_strip_code_fences_json(self):
        """Strips ```json ... ``` fences."""
        text = '```json\n[1, 2, 3]\n```'
        assert _strip_code_fences(text) == "[1, 2, 3]"

    def test_strip_code_fences_bare(self):
        """Strips bare ``` ... ``` fences."""
        text = '```\n{"key": "value"}\n```'
        assert _strip_code_fences(text) == '{"key": "value"}'

    def test_strip_code_fences_none(self):
        """No fences → text returned unchanged."""
        text = '[1, 2, 3]'
        assert _strip_code_fences(text) == "[1, 2, 3]"

    def test_parse_json_array_valid(self):
        """Parses valid JSON array."""
        result = _parse_json_array('[{"a": 1}, {"b": 2}]')
        assert len(result) == 2

    def test_parse_json_array_with_bom(self):
        """Handles BOM character."""
        result = _parse_json_array('\ufeff[{"a": 1}]')
        assert len(result) == 1

    def test_parse_json_array_rejects_object(self):
        """JSON object (not array) raises ValueError."""
        with pytest.raises(ValueError, match="Expected JSON array"):
            _parse_json_array('{"key": "value"}')

    def test_parse_json_array_with_whitespace(self):
        """Extra whitespace is handled."""
        result = _parse_json_array('  \n  [{"a": 1}]  \n  ')
        assert len(result) == 1

    def test_system_prompts_are_nonempty(self):
        """All system prompts are non-empty strings."""
        from ares.dialectic.agents.strategies.prompts import (
            ARCHITECT_SYSTEM_PROMPT,
            NARRATOR_SYSTEM_PROMPT,
            SKEPTIC_SYSTEM_PROMPT,
        )
        assert len(ARCHITECT_SYSTEM_PROMPT) > 0
        assert len(SKEPTIC_SYSTEM_PROMPT) > 0
        assert len(NARRATOR_SYSTEM_PROMPT) > 0
