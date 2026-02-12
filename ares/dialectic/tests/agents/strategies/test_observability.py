"""Tests for LLMCallRecord and LLMCallLogger observability infrastructure.

All tests use mocked AnthropicClient — no real API calls are made.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

from ares.dialectic.agents.strategies.client import LLMResponse
from ares.dialectic.agents.strategies.llm_strategy import (
    LLMExplanationFinder,
    LLMNarrativeGenerator,
    LLMThreatAnalyzer,
)
from ares.dialectic.agents.strategies.observability import (
    LLMCallLogger,
    LLMCallRecord,
)

from .conftest import make_message, make_verdict


# =============================================================================
# Helper
# =============================================================================

def _make_record(
    *,
    strategy_type: str = "ThreatAnalyzer",
    input_tokens: int = 100,
    output_tokens: int = 50,
    fallback_used: bool = False,
    fallback_reason: str | None = None,
    error: str | None = None,
    validation_errors: tuple = (),
    latency_ms: float = 250.0,
) -> LLMCallRecord:
    return LLMCallRecord(
        timestamp="2024-03-15T12:00:00+00:00",
        strategy_type=strategy_type,
        model="claude-sonnet-4-20250514",
        system_prompt="test system",
        user_prompt="test user",
        raw_response='[{"pattern_type": "privilege_escalation"}]',
        parsed_result=[{"pattern_type": "privilege_escalation"}],
        validated_result=None,
        validation_errors=validation_errors,
        fallback_used=fallback_used,
        fallback_reason=fallback_reason,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        latency_ms=latency_ms,
        error=error,
    )


# =============================================================================
# LLMCallRecord Tests
# =============================================================================


class TestLLMCallRecord:
    """Tests for the LLMCallRecord frozen dataclass."""

    def test_is_frozen(self):
        """LLMCallRecord is immutable."""
        record = _make_record()
        with pytest.raises(AttributeError):
            record.strategy_type = "modified"

    def test_stores_all_fields(self):
        """LLMCallRecord stores all fields correctly."""
        record = _make_record(
            strategy_type="ExplanationFinder",
            input_tokens=200,
            output_tokens=100,
            fallback_used=True,
            fallback_reason="test reason",
            error="test error",
            validation_errors=("error1", "error2"),
            latency_ms=500.0,
        )
        assert record.strategy_type == "ExplanationFinder"
        assert record.input_tokens == 200
        assert record.output_tokens == 100
        assert record.fallback_used is True
        assert record.fallback_reason == "test reason"
        assert record.error == "test error"
        assert record.validation_errors == ("error1", "error2")
        assert record.latency_ms == 500.0

    def test_validation_errors_is_tuple(self):
        """validation_errors is stored as a tuple."""
        record = _make_record(validation_errors=("a", "b"))
        assert isinstance(record.validation_errors, tuple)
        assert len(record.validation_errors) == 2

    def test_fallback_fields(self):
        """Captures fallback_used and fallback_reason."""
        record = _make_record(fallback_used=True, fallback_reason="No valid patterns")
        assert record.fallback_used is True
        assert record.fallback_reason == "No valid patterns"

    def test_error_field(self):
        """Captures error on exception."""
        record = _make_record(error="RuntimeError: connection failed")
        assert record.error == "RuntimeError: connection failed"

    def test_latency_non_negative(self):
        """latency_ms is non-negative."""
        record = _make_record(latency_ms=123.45)
        assert record.latency_ms >= 0.0

    def test_no_error_when_successful(self):
        """Successful call has error=None."""
        record = _make_record(error=None)
        assert record.error is None

    def test_equality(self):
        """Records with same data are equal."""
        r1 = _make_record(input_tokens=50, output_tokens=25)
        r2 = _make_record(input_tokens=50, output_tokens=25)
        assert r1 == r2


# =============================================================================
# LLMCallLogger Tests
# =============================================================================


class TestLLMCallLogger:
    """Tests for the LLMCallLogger collector."""

    def test_starts_empty(self):
        """Logger starts with no records."""
        logger = LLMCallLogger()
        assert len(logger.records) == 0

    def test_record_appends(self):
        """record() appends a record."""
        logger = LLMCallLogger()
        logger.record(_make_record())
        assert len(logger.records) == 1

    def test_records_returns_immutable_tuple(self):
        """records property returns an immutable tuple."""
        logger = LLMCallLogger()
        logger.record(_make_record())
        records = logger.records
        assert isinstance(records, tuple)

    def test_total_input_tokens_sums_correctly(self):
        """total_input_tokens sums across all records."""
        logger = LLMCallLogger()
        logger.record(_make_record(input_tokens=100))
        logger.record(_make_record(input_tokens=200))
        assert logger.total_input_tokens == 300

    def test_total_output_tokens_sums_correctly(self):
        """total_output_tokens sums across all records."""
        logger = LLMCallLogger()
        logger.record(_make_record(output_tokens=50))
        logger.record(_make_record(output_tokens=75))
        assert logger.total_output_tokens == 125

    def test_cost_estimate_calculates_correctly(self):
        """total_cost_estimate_usd uses Sonnet 4 pricing."""
        logger = LLMCallLogger()
        # 1M input tokens * $3/MTok = $3.00
        # 1M output tokens * $15/MTok = $15.00
        logger.record(_make_record(input_tokens=1_000_000, output_tokens=1_000_000))
        assert logger.total_cost_estimate_usd == pytest.approx(18.0)

    def test_summary_returns_correct_shape(self):
        """summary() returns dict with expected keys."""
        logger = LLMCallLogger()
        logger.record(_make_record(fallback_used=True, error="test"))
        summary = logger.summary()
        assert "total_calls" in summary
        assert "total_input_tokens" in summary
        assert "total_output_tokens" in summary
        assert "estimated_cost_usd" in summary
        assert "fallback_count" in summary
        assert "error_count" in summary
        assert summary["total_calls"] == 1
        assert summary["fallback_count"] == 1
        assert summary["error_count"] == 1

    def test_clear_empties_records(self):
        """clear() empties all records."""
        logger = LLMCallLogger()
        logger.record(_make_record())
        logger.record(_make_record())
        logger.clear()
        assert len(logger.records) == 0

    def test_zero_records_returns_zero_totals(self):
        """Empty logger returns zero for all totals."""
        logger = LLMCallLogger()
        assert logger.total_input_tokens == 0
        assert logger.total_output_tokens == 0
        assert logger.total_cost_estimate_usd == 0.0

    def test_multiple_records_sum_correctly(self):
        """Multiple records from different strategies sum correctly."""
        logger = LLMCallLogger()
        logger.record(_make_record(
            strategy_type="ThreatAnalyzer", input_tokens=100, output_tokens=50,
        ))
        logger.record(_make_record(
            strategy_type="ExplanationFinder", input_tokens=150, output_tokens=75,
        ))
        logger.record(_make_record(
            strategy_type="NarrativeGenerator", input_tokens=80, output_tokens=40,
        ))
        assert logger.total_input_tokens == 330
        assert logger.total_output_tokens == 165
        assert len(logger.records) == 3


# =============================================================================
# Strategy + Logger Integration Tests
# =============================================================================


class TestStrategyLoggerIntegration:
    """Tests that LLM strategies produce LLMCallRecords when call_logger is set."""

    def test_threat_analyzer_with_logger(self, mock_client, sample_packet):
        """LLMThreatAnalyzer with call_logger produces LLMCallRecord."""
        content = json.dumps([{
            "pattern_type": "privilege_escalation",
            "fact_ids": ["fact-001"],
            "confidence": 0.8,
            "description": "test",
        }])
        mock_client.complete.return_value = LLMResponse(
            content=content, model="m", usage_input_tokens=50, usage_output_tokens=25,
        )
        logger = LLMCallLogger()
        analyzer = LLMThreatAnalyzer(mock_client, call_logger=logger)
        analyzer.analyze_threats(sample_packet)
        assert len(logger.records) == 1
        assert logger.records[0].strategy_type == "ThreatAnalyzer"
        assert logger.records[0].input_tokens == 50
        assert logger.records[0].output_tokens == 25

    def test_strategy_without_logger_works_normally(self, mock_client, sample_packet):
        """LLMThreatAnalyzer without call_logger works with no error."""
        content = json.dumps([{
            "pattern_type": "privilege_escalation",
            "fact_ids": ["fact-001"],
            "confidence": 0.8,
            "description": "test",
        }])
        mock_client.complete.return_value = LLMResponse(
            content=content, model="m", usage_input_tokens=50, usage_output_tokens=25,
        )
        analyzer = LLMThreatAnalyzer(mock_client)
        result = analyzer.analyze_threats(sample_packet)
        assert len(result) == 1

    def test_records_raw_response_on_parse_failure(self, mock_client, sample_packet):
        """Logger records raw_response even when JSON parsing fails."""
        mock_client.complete.return_value = LLMResponse(
            content="not valid json at all",
            model="m", usage_input_tokens=10, usage_output_tokens=5,
        )
        logger = LLMCallLogger()
        analyzer = LLMThreatAnalyzer(mock_client, call_logger=logger)
        analyzer.analyze_threats(sample_packet)
        assert len(logger.records) == 1
        assert logger.records[0].raw_response == "not valid json at all"
        assert logger.records[0].fallback_used is True
        assert logger.records[0].error is not None

    def test_records_empty_response_on_api_exception(self, mock_client, sample_packet):
        """Logger records empty raw_response on API exception."""
        mock_client.complete.side_effect = RuntimeError("API down")
        logger = LLMCallLogger()
        analyzer = LLMThreatAnalyzer(mock_client, call_logger=logger)
        analyzer.analyze_threats(sample_packet)
        assert len(logger.records) == 1
        assert logger.records[0].raw_response == ""
        assert logger.records[0].error is not None
        assert "RuntimeError" in logger.records[0].error

    def test_records_validation_errors(self, mock_client, sample_packet):
        """Logger captures validation errors for rejected patterns."""
        content = json.dumps([{
            "pattern_type": "privilege_escalation",
            "fact_ids": ["fake-999"],
            "confidence": 0.8,
            "description": "hallucinated",
        }])
        mock_client.complete.return_value = LLMResponse(
            content=content, model="m", usage_input_tokens=10, usage_output_tokens=5,
        )
        logger = LLMCallLogger()
        analyzer = LLMThreatAnalyzer(mock_client, call_logger=logger)
        analyzer.analyze_threats(sample_packet)
        assert len(logger.records) == 1
        assert len(logger.records[0].validation_errors) > 0
        assert "hallucinated" in logger.records[0].validation_errors[0]

    def test_explanation_finder_with_logger(self, mock_client, sample_packet, architect_msg):
        """LLMExplanationFinder with call_logger produces record."""
        content = json.dumps([{
            "explanation_type": "known_admin",
            "fact_ids": ["fact-003"],
            "confidence": 0.7,
            "description": "admin",
        }])
        mock_client.complete.return_value = LLMResponse(
            content=content, model="m", usage_input_tokens=60, usage_output_tokens=30,
        )
        logger = LLMCallLogger()
        finder = LLMExplanationFinder(mock_client, call_logger=logger)
        finder.find_explanations(architect_msg, sample_packet)
        assert len(logger.records) == 1
        assert logger.records[0].strategy_type == "ExplanationFinder"

    def test_narrative_generator_with_logger(self, mock_client, sample_packet, threat_verdict):
        """LLMNarrativeGenerator with call_logger produces record."""
        mock_client.complete.return_value = LLMResponse(
            content="The evidence suggests...",
            model="m", usage_input_tokens=80, usage_output_tokens=20,
        )
        logger = LLMCallLogger()
        gen = LLMNarrativeGenerator(mock_client, call_logger=logger)
        gen.generate_narrative(threat_verdict, sample_packet)
        assert len(logger.records) == 1
        assert logger.records[0].strategy_type == "NarrativeGenerator"

    def test_latency_is_positive(self, mock_client, sample_packet):
        """Recorded latency is positive."""
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
        analyzer = LLMThreatAnalyzer(mock_client, call_logger=logger)
        analyzer.analyze_threats(sample_packet)
        assert logger.records[0].latency_ms >= 0.0
