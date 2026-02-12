"""Observability infrastructure for LLM strategy calls.

Captures complete diagnostic records for every LLM API interaction:
raw output, parsed result, validation outcome, token usage, and timing.

LLMCallRecord is frozen (immutable audit trail, same principle as MemoryEntry).
LLMCallLogger collects records for inspection — NOT a singleton, each
cycle/runner creates its own logger for isolation.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, List, Optional

logger = logging.getLogger("ares.llm")


@dataclass(frozen=True)
class LLMCallRecord:
    """Complete record of a single LLM API call for diagnostics.

    Attributes:
        timestamp: ISO format UTC timestamp.
        strategy_type: Which strategy made the call (ThreatAnalyzer, etc.).
        model: Model ID that generated the response.
        system_prompt: System prompt sent to the LLM.
        user_prompt: User prompt sent to the LLM.
        raw_response: Raw text content from the LLM.
        parsed_result: Parsed JSON (before validation), or None if parse failed.
        validated_result: After validation (the final output), or None.
        validation_errors: Tuple of string descriptions of rejected items.
        fallback_used: Whether rule-based fallback was triggered.
        fallback_reason: Why fallback was triggered (if applicable).
        input_tokens: Number of input tokens consumed.
        output_tokens: Number of output tokens generated.
        latency_ms: Round-trip time in milliseconds.
        error: Exception message if call failed.
    """

    timestamp: str
    strategy_type: str
    model: str
    system_prompt: str
    user_prompt: str
    raw_response: str
    parsed_result: Optional[Any]
    validated_result: Optional[Any]
    validation_errors: tuple
    fallback_used: bool
    fallback_reason: Optional[str]
    input_tokens: int
    output_tokens: int
    latency_ms: float
    error: Optional[str]


class LLMCallLogger:
    """Collects LLMCallRecords for inspection.

    Thread-safe via append-only list. Each cycle/runner creates its own
    logger instance for isolation.
    """

    def __init__(self) -> None:
        self._records: List[LLMCallRecord] = []

    def record(self, call_record: LLMCallRecord) -> None:
        """Store a call record and log a summary."""
        self._records.append(call_record)
        self._log_summary(call_record)

    @property
    def records(self) -> tuple:
        """Return all records as immutable tuple."""
        return tuple(self._records)

    @property
    def total_input_tokens(self) -> int:
        """Sum of input tokens across all recorded calls."""
        return sum(r.input_tokens for r in self._records)

    @property
    def total_output_tokens(self) -> int:
        """Sum of output tokens across all recorded calls."""
        return sum(r.output_tokens for r in self._records)

    @property
    def total_cost_estimate_usd(self) -> float:
        """Rough cost estimate. Sonnet 4 pricing: $3/MTok input, $15/MTok output."""
        input_cost = (self.total_input_tokens / 1_000_000) * 3.0
        output_cost = (self.total_output_tokens / 1_000_000) * 15.0
        return input_cost + output_cost

    def summary(self) -> dict:
        """Return a summary dict for display."""
        return {
            "total_calls": len(self._records),
            "total_input_tokens": self.total_input_tokens,
            "total_output_tokens": self.total_output_tokens,
            "estimated_cost_usd": round(self.total_cost_estimate_usd, 6),
            "fallback_count": sum(1 for r in self._records if r.fallback_used),
            "error_count": sum(1 for r in self._records if r.error is not None),
        }

    def clear(self) -> None:
        """Clear all records."""
        self._records.clear()

    def _log_summary(self, record: LLMCallRecord) -> None:
        """Log a one-line summary of the call."""
        status = "FALLBACK" if record.fallback_used else "OK"
        if record.error:
            status = f"ERROR: {record.error}"
        logger.info(
            f"[{record.strategy_type}] {status} | "
            f"tokens: {record.input_tokens}in/{record.output_tokens}out | "
            f"latency: {record.latency_ms:.0f}ms | "
            f"validation_errors: {len(record.validation_errors)}"
        )
