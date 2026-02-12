"""Tests for LLM output validation edge cases.

The validation layer enforces the closed-world constraint:
fact_ids referenced by the LLM MUST exist in the packet.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

from ares.dialectic.agents.patterns import AnomalyPattern, PatternType
from ares.dialectic.agents.strategies.client import LLMResponse
from ares.dialectic.agents.strategies.llm_strategy import (
    LLMExplanationFinder,
    LLMThreatAnalyzer,
    LLMNarrativeGenerator,
)

from .conftest import make_message, make_verdict


def _make_response(content: str) -> LLMResponse:
    """Helper to build LLMResponse from content string."""
    return LLMResponse(content=content, model="m", usage_input_tokens=1, usage_output_tokens=1)


# =============================================================================
# Threat Analyzer Validation Tests
# =============================================================================


class TestThreatAnalyzerValidation:
    """Closed-world validation for LLMThreatAnalyzer."""

    def test_valid_fact_ids_accepted(self, mock_client, sample_packet):
        """Pattern with valid fact_ids is accepted."""
        content = json.dumps([{
            "pattern_type": "privilege_escalation",
            "fact_ids": ["fact-001", "fact-002"],
            "confidence": 0.85,
            "description": "test",
        }])
        mock_client.complete.return_value = _make_response(content)
        analyzer = LLMThreatAnalyzer(mock_client)
        result = analyzer.analyze_threats(sample_packet)
        assert len(result) == 1

    def test_hallucinated_fact_ids_rejected(self, mock_client, sample_packet):
        """Pattern with fact_ids NOT in packet is REJECTED."""
        content = json.dumps([{
            "pattern_type": "privilege_escalation",
            "fact_ids": ["fact-HALLUCINATED"],
            "confidence": 0.9,
            "description": "fake",
        }])
        mock_client.complete.return_value = _make_response(content)
        analyzer = LLMThreatAnalyzer(mock_client)
        result = analyzer.analyze_threats(sample_packet)
        # Should fall back to rule-based (hallucinated pattern rejected)
        priv = [p for p in result if p.description == "fake"]
        assert len(priv) == 0

    def test_mixed_valid_invalid_fact_ids_rejected(self, mock_client, sample_packet):
        """Pattern with mix of valid and invalid fact_ids is REJECTED entirely."""
        content = json.dumps([{
            "pattern_type": "privilege_escalation",
            "fact_ids": ["fact-001", "fact-DOESNOTEXIST"],
            "confidence": 0.8,
            "description": "mixed",
        }])
        mock_client.complete.return_value = _make_response(content)
        analyzer = LLMThreatAnalyzer(mock_client)
        result = analyzer.analyze_threats(sample_packet)
        mixed = [p for p in result if p.description == "mixed"]
        assert len(mixed) == 0

    def test_all_invalid_triggers_fallback(self, mock_client, sample_packet):
        """When ALL patterns have invalid fact_ids, fallback is triggered."""
        content = json.dumps([
            {"pattern_type": "privilege_escalation", "fact_ids": ["FAKE-1"], "confidence": 0.9, "description": "a"},
            {"pattern_type": "suspicious_process", "fact_ids": ["FAKE-2"], "confidence": 0.8, "description": "b"},
        ])
        mock_client.complete.return_value = _make_response(content)
        analyzer = LLMThreatAnalyzer(mock_client)
        result = analyzer.analyze_threats(sample_packet)
        # Result is from fallback, not from LLM
        assert isinstance(result, list)

    def test_confidence_above_1_clamped(self, mock_client, sample_packet):
        """Confidence > 1.0 is clamped to 1.0."""
        content = json.dumps([{
            "pattern_type": "privilege_escalation",
            "fact_ids": ["fact-001"],
            "confidence": 1.5,
            "description": "over-confident",
        }])
        mock_client.complete.return_value = _make_response(content)
        analyzer = LLMThreatAnalyzer(mock_client)
        result = analyzer.analyze_threats(sample_packet)
        assert len(result) == 1
        assert result[0].confidence == 1.0

    def test_confidence_below_0_clamped(self, mock_client, sample_packet):
        """Confidence < 0.0 is clamped to 0.0."""
        content = json.dumps([{
            "pattern_type": "privilege_escalation",
            "fact_ids": ["fact-001"],
            "confidence": -0.5,
            "description": "negative confidence",
        }])
        mock_client.complete.return_value = _make_response(content)
        analyzer = LLMThreatAnalyzer(mock_client)
        result = analyzer.analyze_threats(sample_packet)
        # AnomalyPattern requires confidence 0-1, so 0.0 is valid
        assert len(result) == 1
        assert result[0].confidence == 0.0

    def test_confidence_string_parsed(self, mock_client, sample_packet):
        """Confidence as string "0.8" is parsed to float."""
        content = json.dumps([{
            "pattern_type": "privilege_escalation",
            "fact_ids": ["fact-001"],
            "confidence": "0.8",
            "description": "string confidence",
        }])
        mock_client.complete.return_value = _make_response(content)
        analyzer = LLMThreatAnalyzer(mock_client)
        result = analyzer.analyze_threats(sample_packet)
        assert len(result) == 1
        assert result[0].confidence == 0.8

    def test_confidence_missing_defaults_zero(self, mock_client, sample_packet):
        """Missing confidence defaults to 0.0."""
        content = json.dumps([{
            "pattern_type": "privilege_escalation",
            "fact_ids": ["fact-001"],
            "description": "no confidence field",
        }])
        mock_client.complete.return_value = _make_response(content)
        analyzer = LLMThreatAnalyzer(mock_client)
        result = analyzer.analyze_threats(sample_packet)
        assert len(result) == 1
        assert result[0].confidence == 0.0

    def test_novel_pattern_type_rejected(self, mock_client, sample_packet):
        """Unknown pattern type is skipped (not in PatternType enum)."""
        content = json.dumps([{
            "pattern_type": "ZERO_DAY_EXPLOIT",
            "fact_ids": ["fact-001"],
            "confidence": 0.9,
            "description": "novel type",
        }])
        mock_client.complete.return_value = _make_response(content)
        analyzer = LLMThreatAnalyzer(mock_client)
        result = analyzer.analyze_threats(sample_packet)
        novel = [p for p in result if p.description == "novel type"]
        assert len(novel) == 0

    def test_fact_ids_not_a_list_rejected(self, mock_client, sample_packet):
        """fact_ids that is not a list causes pattern to be rejected."""
        content = json.dumps([{
            "pattern_type": "privilege_escalation",
            "fact_ids": "fact-001",
            "confidence": 0.8,
            "description": "string fact_ids",
        }])
        mock_client.complete.return_value = _make_response(content)
        analyzer = LLMThreatAnalyzer(mock_client)
        result = analyzer.analyze_threats(sample_packet)
        bad = [p for p in result if p.description == "string fact_ids"]
        assert len(bad) == 0

    def test_fact_ids_with_non_string_rejected(self, mock_client, sample_packet):
        """fact_ids containing non-string elements causes rejection."""
        content = json.dumps([{
            "pattern_type": "privilege_escalation",
            "fact_ids": [123, "fact-001"],
            "confidence": 0.8,
            "description": "numeric fact_id",
        }])
        mock_client.complete.return_value = _make_response(content)
        analyzer = LLMThreatAnalyzer(mock_client)
        result = analyzer.analyze_threats(sample_packet)
        bad = [p for p in result if p.description == "numeric fact_id"]
        assert len(bad) == 0

    def test_duplicate_fact_ids_deduplicated(self, mock_client, sample_packet):
        """Duplicate fact_ids are deduplicated via frozenset."""
        content = json.dumps([{
            "pattern_type": "privilege_escalation",
            "fact_ids": ["fact-001", "fact-001", "fact-001"],
            "confidence": 0.8,
            "description": "dup fact_ids",
        }])
        mock_client.complete.return_value = _make_response(content)
        analyzer = LLMThreatAnalyzer(mock_client)
        result = analyzer.analyze_threats(sample_packet)
        assert len(result) == 1
        assert result[0].fact_ids == frozenset({"fact-001"})

    def test_description_missing_uses_default(self, mock_client, sample_packet):
        """Missing description uses default."""
        content = json.dumps([{
            "pattern_type": "privilege_escalation",
            "fact_ids": ["fact-001"],
            "confidence": 0.8,
        }])
        mock_client.complete.return_value = _make_response(content)
        analyzer = LLMThreatAnalyzer(mock_client)
        result = analyzer.analyze_threats(sample_packet)
        assert len(result) == 1
        assert result[0].description == "LLM-detected pattern"

    def test_invalid_json_triggers_fallback(self, mock_client, sample_packet):
        """Completely invalid JSON triggers fallback."""
        mock_client.complete.return_value = _make_response("this is not json at all")
        analyzer = LLMThreatAnalyzer(mock_client)
        result = analyzer.analyze_threats(sample_packet)
        assert isinstance(result, list)

    def test_json_object_instead_of_array_triggers_fallback(self, mock_client, sample_packet):
        """JSON object (not array) triggers fallback."""
        mock_client.complete.return_value = _make_response('{"pattern": "not an array"}')
        analyzer = LLMThreatAnalyzer(mock_client)
        result = analyzer.analyze_threats(sample_packet)
        assert isinstance(result, list)

    def test_array_of_non_objects_items_skipped(self, mock_client, sample_packet):
        """JSON array of non-objects — individual items skipped."""
        mock_client.complete.return_value = _make_response('["string1", 42, null]')
        analyzer = LLMThreatAnalyzer(mock_client)
        result = analyzer.analyze_threats(sample_packet)
        assert isinstance(result, list)


# =============================================================================
# Explanation Finder Validation Tests
# =============================================================================


class TestExplanationFinderValidation:
    """Closed-world validation for LLMExplanationFinder."""

    def test_valid_explanation_accepted(self, mock_client, sample_packet, architect_msg):
        """Explanation with valid fact_ids is accepted."""
        content = json.dumps([{
            "explanation_type": "known_admin",
            "fact_ids": ["fact-003"],
            "confidence": 0.7,
            "description": "admin account",
        }])
        mock_client.complete.return_value = _make_response(content)
        finder = LLMExplanationFinder(mock_client)
        result = finder.find_explanations(architect_msg, sample_packet)
        assert len(result) == 1

    def test_hallucinated_fact_ids_rejected(self, mock_client, sample_packet, architect_msg):
        """Explanation with hallucinated fact_ids is rejected."""
        content = json.dumps([{
            "explanation_type": "known_admin",
            "fact_ids": ["fact-GHOST"],
            "confidence": 0.7,
            "description": "ghost",
        }])
        mock_client.complete.return_value = _make_response(content)
        finder = LLMExplanationFinder(mock_client)
        result = finder.find_explanations(architect_msg, sample_packet)
        ghost = [e for e in result if e.description == "ghost"]
        assert len(ghost) == 0


# =============================================================================
# Narrative Generator Validation Tests
# =============================================================================


class TestNarrativeValidation:
    """Validation for LLMNarrativeGenerator."""

    def test_empty_narrative_triggers_fallback(self, mock_client, sample_packet, threat_verdict):
        """Empty string narrative triggers template fallback."""
        mock_client.complete.return_value = _make_response("")
        gen = LLMNarrativeGenerator(mock_client)
        result = gen.generate_narrative(threat_verdict, sample_packet)
        assert "VERDICT: THREAT CONFIRMED" in result

    def test_long_narrative_accepted(self, mock_client, sample_packet, threat_verdict):
        """Very long response is accepted (no length limit)."""
        long_text = "Analysis: " + "detailed explanation. " * 500
        long_text = long_text.strip()  # Generator strips response
        mock_client.complete.return_value = _make_response(long_text)
        gen = LLMNarrativeGenerator(mock_client)
        result = gen.generate_narrative(threat_verdict, sample_packet)
        assert result == long_text
