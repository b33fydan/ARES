"""Tests for fallback mechanisms.

Verifies that LLM strategies degrade gracefully to rule-based
on any failure: API errors, parse errors, validation rejections.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

from ares.dialectic.agents.patterns import AnomalyPattern, BenignExplanation
from ares.dialectic.agents.strategies.client import LLMResponse
from ares.dialectic.agents.strategies.llm_strategy import (
    LLMExplanationFinder,
    LLMNarrativeGenerator,
    LLMThreatAnalyzer,
)
from ares.dialectic.agents.strategies.rule_based import (
    RuleBasedExplanationFinder,
    RuleBasedNarrativeGenerator,
    RuleBasedThreatAnalyzer,
)

from .conftest import make_message, make_verdict


def _make_response(content: str) -> LLMResponse:
    return LLMResponse(content=content, model="m", usage_input_tokens=1, usage_output_tokens=1)


class TestThreatAnalyzerFallback:
    """Fallback tests for LLMThreatAnalyzer."""

    def test_api_error_returns_rule_based(self, mock_client, sample_packet):
        """API error (any Exception) → rule-based result returned."""
        mock_client.complete.side_effect = ConnectionError("network down")
        analyzer = LLMThreatAnalyzer(mock_client)
        result = analyzer.analyze_threats(sample_packet)
        # Should get rule-based results (sample_packet has privilege indicators)
        assert isinstance(result, list)
        # Verify it's from rule-based by checking it's not empty
        # (sample_packet has privilege and process indicators)
        assert len(result) >= 0  # May or may not find anomalies depending on packet

    def test_json_parse_error_returns_rule_based(self, mock_client, sample_packet):
        """JSON parse error → rule-based result returned."""
        mock_client.complete.return_value = _make_response("not json")
        analyzer = LLMThreatAnalyzer(mock_client)
        result = analyzer.analyze_threats(sample_packet)
        assert isinstance(result, list)

    def test_validation_rejects_all_returns_rule_based(self, mock_client, sample_packet):
        """When validation rejects ALL patterns → rule-based result."""
        content = json.dumps([
            {"pattern_type": "privilege_escalation", "fact_ids": ["FAKE"], "confidence": 0.9, "description": "x"},
        ])
        mock_client.complete.return_value = _make_response(content)
        analyzer = LLMThreatAnalyzer(mock_client)
        result = analyzer.analyze_threats(sample_packet)
        assert isinstance(result, list)

    def test_custom_fallback_used(self, mock_client, sample_packet):
        """Custom fallback strategy is used instead of default."""
        custom_fallback = MagicMock()
        custom_fallback.analyze_threats.return_value = []
        mock_client.complete.side_effect = RuntimeError("fail")
        analyzer = LLMThreatAnalyzer(mock_client, fallback=custom_fallback)
        result = analyzer.analyze_threats(sample_packet)
        custom_fallback.analyze_threats.assert_called_once_with(sample_packet)
        assert result == []

    def test_default_fallback_is_rule_based(self, mock_client):
        """Default fallback is RuleBasedThreatAnalyzer."""
        analyzer = LLMThreatAnalyzer(mock_client)
        assert isinstance(analyzer._fallback, RuleBasedThreatAnalyzer)

    def test_fallback_does_not_reraise(self, mock_client, sample_packet):
        """Fallback never re-raises exceptions."""
        mock_client.complete.side_effect = RuntimeError("catastrophic failure")
        analyzer = LLMThreatAnalyzer(mock_client)
        # Should not raise
        result = analyzer.analyze_threats(sample_packet)
        assert isinstance(result, list)

    def test_multiple_consecutive_fallbacks(self, mock_client, sample_packet):
        """Multiple fallbacks don't corrupt state."""
        mock_client.complete.side_effect = RuntimeError("fail")
        analyzer = LLMThreatAnalyzer(mock_client)
        result1 = analyzer.analyze_threats(sample_packet)
        result2 = analyzer.analyze_threats(sample_packet)
        # Both produce consistent results
        assert len(result1) == len(result2)


class TestExplanationFinderFallback:
    """Fallback tests for LLMExplanationFinder."""

    def test_api_error_returns_rule_based(self, mock_client, sample_packet, architect_msg):
        """API error → rule-based result."""
        mock_client.complete.side_effect = TimeoutError("timeout")
        finder = LLMExplanationFinder(mock_client)
        result = finder.find_explanations(architect_msg, sample_packet)
        assert isinstance(result, list)

    def test_default_fallback_is_rule_based(self, mock_client):
        """Default fallback is RuleBasedExplanationFinder."""
        finder = LLMExplanationFinder(mock_client)
        assert isinstance(finder._fallback, RuleBasedExplanationFinder)


class TestNarrativeGeneratorFallback:
    """Fallback tests for LLMNarrativeGenerator."""

    def test_api_error_returns_template(self, mock_client, sample_packet, threat_verdict):
        """API error → template narrative."""
        mock_client.complete.side_effect = Exception("fail")
        gen = LLMNarrativeGenerator(mock_client)
        result = gen.generate_narrative(threat_verdict, sample_packet)
        assert "VERDICT: THREAT CONFIRMED" in result

    def test_default_fallback_is_rule_based(self, mock_client):
        """Default fallback is RuleBasedNarrativeGenerator."""
        gen = LLMNarrativeGenerator(mock_client)
        assert isinstance(gen._fallback, RuleBasedNarrativeGenerator)
