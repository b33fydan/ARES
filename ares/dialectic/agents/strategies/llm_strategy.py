"""LLM-powered strategy implementations using Anthropic API.

Each strategy:
1. Builds a structured prompt from evidence
2. Calls the Anthropic API via AnthropicClient
3. Parses the JSON response
4. Validates output against the EvidencePacket (closed-world enforcement)
5. Falls back to rule-based on any failure

The closed-world constraint is the architectural firewall:
fact_ids referenced by the LLM MUST exist in the packet.
Hallucinated fact_ids cause the entire pattern to be rejected.
"""

from __future__ import annotations

import json
import re
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple, TYPE_CHECKING

from ares.dialectic.agents.patterns import (
    AnomalyPattern,
    BenignExplanation,
    ExplanationType,
    PatternType,
    Verdict,
    VerdictOutcome,
)
from ares.dialectic.agents.strategies.client import AnthropicClient, LLMResponse
from ares.dialectic.agents.strategies.prompts import (
    ARCHITECT_SYSTEM_PROMPT,
    NARRATOR_SYSTEM_PROMPT,
    SKEPTIC_SYSTEM_PROMPT,
)
from ares.dialectic.agents.strategies.rule_based import (
    RuleBasedExplanationFinder,
    RuleBasedNarrativeGenerator,
    RuleBasedThreatAnalyzer,
)

if TYPE_CHECKING:
    from ares.dialectic.agents.strategies.observability import (
        LLMCallLogger,
        LLMCallRecord,
    )
    from ares.dialectic.evidence.packet import EvidencePacket
    from ares.dialectic.messages.protocol import DialecticalMessage


def _strip_code_fences(text: str) -> str:
    """Strip markdown code fences from LLM response.

    Handles ```json ... ```, ``` ... ```, and bare text.

    Args:
        text: Raw LLM response text.

    Returns:
        Cleaned text with code fences removed.
    """
    text = text.strip()
    # Remove ```json ... ``` or ``` ... ```
    pattern = r"^```(?:json)?\s*\n?(.*?)\n?\s*```$"
    match = re.match(pattern, text, re.DOTALL)
    if match:
        return match.group(1).strip()
    return text


def _parse_json_array(content: str) -> List[Dict]:
    """Parse LLM response as a JSON array.

    Handles code fences, BOM characters, and whitespace.

    Args:
        content: Raw LLM response text.

    Returns:
        List of dictionaries parsed from JSON.

    Raises:
        ValueError: If content is not a valid JSON array.
    """
    # Strip BOM and whitespace
    cleaned = content.lstrip("\ufeff").strip()
    cleaned = _strip_code_fences(cleaned)

    parsed = json.loads(cleaned)
    if not isinstance(parsed, list):
        raise ValueError(f"Expected JSON array, got {type(parsed).__name__}")
    return parsed


def _serialize_facts(packet: "EvidencePacket") -> str:
    """Serialize packet facts into a structured prompt section.

    Args:
        packet: The EvidencePacket to serialize.

    Returns:
        Formatted string listing all facts with their IDs.
    """
    lines = [f"Evidence Packet: {packet.packet_id}", ""]
    facts = packet.get_all_facts()
    if not facts:
        lines.append("No facts in packet.")
        return "\n".join(lines)

    lines.append(f"Facts ({len(facts)} total):")
    for fact in facts:
        lines.append(
            f"  - fact_id: {fact.fact_id}"
            f"  | entity: {fact.entity_id}"
            f"  | field: {fact.field}"
            f"  | value: {fact.value}"
        )

    lines.append("")
    lines.append(f"Valid fact_ids: {sorted(packet.fact_ids)}")
    return "\n".join(lines)


class LLMThreatAnalyzer:
    """Uses Anthropic API to detect anomaly patterns.

    Falls back to rule-based on any failure (API error, parse error,
    validation rejection).
    """

    def __init__(
        self,
        client: AnthropicClient,
        *,
        fallback: Optional[RuleBasedThreatAnalyzer] = None,
        call_logger: Optional["LLMCallLogger"] = None,
    ) -> None:
        self._client = client
        self._fallback = fallback or RuleBasedThreatAnalyzer()
        self._call_logger = call_logger

    def analyze_threats(self, packet: "EvidencePacket") -> List[AnomalyPattern]:
        """Detect anomaly patterns using LLM reasoning.

        Args:
            packet: The EvidencePacket to analyze.

        Returns:
            List of validated AnomalyPattern instances.
        """
        start = time.monotonic()
        system_prompt = ARCHITECT_SYSTEM_PROMPT
        user_prompt = self._build_user_prompt(packet)

        raw_response = ""
        parsed = None
        validated = None
        validation_errors: List[str] = []
        fallback_used = False
        fallback_reason = None
        error_msg = None
        input_tokens = 0
        output_tokens = 0
        model = ""

        try:
            response = self._client.complete(
                system=system_prompt,
                user=user_prompt,
            )
            raw_response = response.content
            input_tokens = response.usage_input_tokens
            output_tokens = response.usage_output_tokens
            model = response.model

            parsed = _parse_json_array(raw_response)
            validated, validation_errors = self._validate_patterns_with_errors(
                parsed, packet
            )

            if validated:
                result = validated
            else:
                fallback_used = True
                fallback_reason = "No valid patterns after validation"
                result = self._fallback.analyze_threats(packet)

        except Exception as e:
            error_msg = f"{type(e).__name__}: {e}"
            fallback_used = True
            fallback_reason = f"Exception: {error_msg}"
            result = self._fallback.analyze_threats(packet)

        elapsed_ms = (time.monotonic() - start) * 1000

        if self._call_logger is not None:
            from ares.dialectic.agents.strategies.observability import LLMCallRecord

            record = LLMCallRecord(
                timestamp=datetime.now(timezone.utc).isoformat(),
                strategy_type="ThreatAnalyzer",
                model=model,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                raw_response=raw_response,
                parsed_result=parsed,
                validated_result=validated,
                validation_errors=tuple(validation_errors),
                fallback_used=fallback_used,
                fallback_reason=fallback_reason,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                latency_ms=elapsed_ms,
                error=error_msg,
            )
            self._call_logger.record(record)

        return result

    def _build_user_prompt(self, packet: "EvidencePacket") -> str:
        """Build user prompt from packet facts."""
        return (
            "Analyze the following security telemetry for threat patterns:\n\n"
            + _serialize_facts(packet)
        )

    def _validate_patterns(
        self, raw: List[Dict], packet: "EvidencePacket"
    ) -> List[AnomalyPattern]:
        """Validate LLM output against packet. Reject hallucinated fact_ids.

        Preserved for backward compatibility with Session 009 tests.
        """
        validated, _ = self._validate_patterns_with_errors(raw, packet)
        return validated

    def _validate_patterns_with_errors(
        self, raw: List[Dict], packet: "EvidencePacket"
    ) -> Tuple[List[AnomalyPattern], List[str]]:
        """Validate LLM output against packet. Returns validated items and errors.

        Args:
            raw: Parsed JSON array from LLM response.
            packet: The EvidencePacket for closed-world validation.

        Returns:
            Tuple of (validated patterns, list of error descriptions).
        """
        valid_fact_ids = packet.fact_ids
        validated: List[AnomalyPattern] = []
        errors: List[str] = []

        for i, item in enumerate(raw):
            if not isinstance(item, dict):
                errors.append(f"Item {i}: not a dict")
                continue

            # Validate fact_ids
            raw_fact_ids = item.get("fact_ids", [])
            if not isinstance(raw_fact_ids, list):
                errors.append(f"Item {i}: fact_ids is not a list")
                continue
            if not all(isinstance(fid, str) for fid in raw_fact_ids):
                errors.append(f"Item {i}: fact_ids contains non-string values")
                continue

            cited = frozenset(raw_fact_ids)
            if not cited:
                errors.append(f"Item {i}: empty fact_ids")
                continue
            hallucinated = cited - valid_fact_ids
            if hallucinated:
                errors.append(
                    f"Item {i}: hallucinated fact_ids {hallucinated}"
                )
                continue

            # Clamp confidence
            try:
                confidence = max(0.0, min(1.0, float(item.get("confidence", 0.0))))
            except (TypeError, ValueError):
                confidence = 0.0

            # Resolve pattern type
            raw_type = str(item.get("pattern_type", "")).upper()
            try:
                pattern_type = PatternType(raw_type.lower())
            except ValueError:
                errors.append(f"Item {i}: unknown pattern_type '{raw_type}'")
                continue

            description = str(item.get("description", "")) or "LLM-detected pattern"

            try:
                validated.append(
                    AnomalyPattern(
                        pattern_type=pattern_type,
                        fact_ids=cited,
                        confidence=confidence,
                        description=description,
                    )
                )
            except (ValueError, TypeError) as e:
                errors.append(f"Item {i}: AnomalyPattern creation failed: {e}")
                continue

        return validated, errors


class LLMExplanationFinder:
    """Uses Anthropic API to find benign explanations.

    Falls back to rule-based on any failure.
    """

    def __init__(
        self,
        client: AnthropicClient,
        *,
        fallback: Optional[RuleBasedExplanationFinder] = None,
        call_logger: Optional["LLMCallLogger"] = None,
    ) -> None:
        self._client = client
        self._fallback = fallback or RuleBasedExplanationFinder()
        self._call_logger = call_logger

    def find_explanations(
        self,
        architect_msg: "DialecticalMessage",
        packet: "EvidencePacket",
    ) -> List[BenignExplanation]:
        """Find benign explanations using LLM reasoning.

        Args:
            architect_msg: The Architect's hypothesis message.
            packet: The EvidencePacket to analyze.

        Returns:
            List of validated BenignExplanation instances.
        """
        start = time.monotonic()
        system_prompt = SKEPTIC_SYSTEM_PROMPT
        user_prompt = self._build_user_prompt(architect_msg, packet)

        raw_response = ""
        parsed = None
        validated = None
        validation_errors: List[str] = []
        fallback_used = False
        fallback_reason = None
        error_msg = None
        input_tokens = 0
        output_tokens = 0
        model = ""

        try:
            response = self._client.complete(
                system=system_prompt,
                user=user_prompt,
            )
            raw_response = response.content
            input_tokens = response.usage_input_tokens
            output_tokens = response.usage_output_tokens
            model = response.model

            parsed = _parse_json_array(raw_response)
            validated, validation_errors = self._validate_explanations_with_errors(
                parsed, packet
            )

            if validated:
                result = validated
            else:
                fallback_used = True
                fallback_reason = "No valid explanations after validation"
                result = self._fallback.find_explanations(architect_msg, packet)

        except Exception as e:
            error_msg = f"{type(e).__name__}: {e}"
            fallback_used = True
            fallback_reason = f"Exception: {error_msg}"
            result = self._fallback.find_explanations(architect_msg, packet)

        elapsed_ms = (time.monotonic() - start) * 1000

        if self._call_logger is not None:
            from ares.dialectic.agents.strategies.observability import LLMCallRecord

            record = LLMCallRecord(
                timestamp=datetime.now(timezone.utc).isoformat(),
                strategy_type="ExplanationFinder",
                model=model,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                raw_response=raw_response,
                parsed_result=parsed,
                validated_result=validated,
                validation_errors=tuple(validation_errors),
                fallback_used=fallback_used,
                fallback_reason=fallback_reason,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                latency_ms=elapsed_ms,
                error=error_msg,
            )
            self._call_logger.record(record)

        return result

    def _build_user_prompt(
        self, architect_msg: "DialecticalMessage", packet: "EvidencePacket"
    ) -> str:
        """Build user prompt from architect message and packet facts."""
        parts = [
            "The Architect has proposed the following threat hypothesis:\n",
        ]

        # Include architect's assertions
        for assertion in architect_msg.assertions:
            parts.append(
                f"  - {assertion.interpretation} "
                f"(fact_ids: {list(assertion.fact_ids)}, "
                f"confidence context: {assertion.operator} {assertion.threshold})"
            )

        parts.append("\nAnalyze the evidence for benign explanations:\n")
        parts.append(_serialize_facts(packet))
        return "\n".join(parts)

    def _validate_explanations(
        self, raw: List[Dict], packet: "EvidencePacket"
    ) -> List[BenignExplanation]:
        """Validate LLM output against packet. Reject hallucinated fact_ids.

        Preserved for backward compatibility with Session 009 tests.
        """
        validated, _ = self._validate_explanations_with_errors(raw, packet)
        return validated

    def _validate_explanations_with_errors(
        self, raw: List[Dict], packet: "EvidencePacket"
    ) -> Tuple[List[BenignExplanation], List[str]]:
        """Validate LLM output against packet. Returns validated items and errors.

        Args:
            raw: Parsed JSON array from LLM response.
            packet: The EvidencePacket for closed-world validation.

        Returns:
            Tuple of (validated explanations, list of error descriptions).
        """
        valid_fact_ids = packet.fact_ids
        validated: List[BenignExplanation] = []
        errors: List[str] = []

        for i, item in enumerate(raw):
            if not isinstance(item, dict):
                errors.append(f"Item {i}: not a dict")
                continue

            raw_fact_ids = item.get("fact_ids", [])
            if not isinstance(raw_fact_ids, list):
                errors.append(f"Item {i}: fact_ids is not a list")
                continue
            if not all(isinstance(fid, str) for fid in raw_fact_ids):
                errors.append(f"Item {i}: fact_ids contains non-string values")
                continue

            cited = frozenset(raw_fact_ids)
            if not cited:
                errors.append(f"Item {i}: empty fact_ids")
                continue
            hallucinated = cited - valid_fact_ids
            if hallucinated:
                errors.append(
                    f"Item {i}: hallucinated fact_ids {hallucinated}"
                )
                continue

            try:
                confidence = max(0.0, min(1.0, float(item.get("confidence", 0.0))))
            except (TypeError, ValueError):
                confidence = 0.0

            raw_type = str(item.get("explanation_type", "")).lower()
            try:
                explanation_type = ExplanationType(raw_type)
            except ValueError:
                errors.append(f"Item {i}: unknown explanation_type '{raw_type}'")
                continue

            description = str(item.get("description", "")) or "LLM-proposed explanation"

            try:
                validated.append(
                    BenignExplanation(
                        explanation_type=explanation_type,
                        fact_ids=cited,
                        confidence=confidence,
                        description=description,
                    )
                )
            except (ValueError, TypeError) as e:
                errors.append(f"Item {i}: BenignExplanation creation failed: {e}")
                continue

        return validated, errors


class LLMNarrativeGenerator:
    """Uses Anthropic API to generate verdict explanations.

    Falls back to rule-based template on any failure.
    """

    def __init__(
        self,
        client: AnthropicClient,
        *,
        fallback: Optional[RuleBasedNarrativeGenerator] = None,
        call_logger: Optional["LLMCallLogger"] = None,
    ) -> None:
        self._client = client
        self._fallback = fallback or RuleBasedNarrativeGenerator()
        self._call_logger = call_logger

    def generate_narrative(
        self,
        verdict: Verdict,
        packet: "EvidencePacket",
        architect_msg: Optional["DialecticalMessage"] = None,
        skeptic_msg: Optional["DialecticalMessage"] = None,
    ) -> str:
        """Generate verdict explanation using LLM reasoning.

        Args:
            verdict: The locked verdict to explain.
            packet: The EvidencePacket for context.
            architect_msg: The Architect's message (if available).
            skeptic_msg: The Skeptic's message (if available).

        Returns:
            Narrative explanation string.
        """
        start = time.monotonic()
        system_prompt = NARRATOR_SYSTEM_PROMPT
        user_prompt = self._build_user_prompt(
            verdict, packet, architect_msg, skeptic_msg
        )

        raw_response = ""
        fallback_used = False
        fallback_reason = None
        error_msg = None
        input_tokens = 0
        output_tokens = 0
        model = ""

        try:
            response = self._client.complete(
                system=system_prompt,
                user=user_prompt,
            )
            raw_response = response.content
            input_tokens = response.usage_input_tokens
            output_tokens = response.usage_output_tokens
            model = response.model

            narrative = response.content.strip()
            if not narrative:
                fallback_used = True
                fallback_reason = "Empty response from LLM"
                result = self._fallback.generate_narrative(
                    verdict, packet, architect_msg, skeptic_msg
                )
            else:
                result = narrative

        except Exception as e:
            error_msg = f"{type(e).__name__}: {e}"
            fallback_used = True
            fallback_reason = f"Exception: {error_msg}"
            result = self._fallback.generate_narrative(
                verdict, packet, architect_msg, skeptic_msg
            )

        elapsed_ms = (time.monotonic() - start) * 1000

        if self._call_logger is not None:
            from ares.dialectic.agents.strategies.observability import LLMCallRecord

            record = LLMCallRecord(
                timestamp=datetime.now(timezone.utc).isoformat(),
                strategy_type="NarrativeGenerator",
                model=model,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                raw_response=raw_response,
                parsed_result=None,
                validated_result=result if not fallback_used else None,
                validation_errors=(),
                fallback_used=fallback_used,
                fallback_reason=fallback_reason,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                latency_ms=elapsed_ms,
                error=error_msg,
            )
            self._call_logger.record(record)

        return result

    def _build_user_prompt(
        self,
        verdict: Verdict,
        packet: "EvidencePacket",
        architect_msg: Optional["DialecticalMessage"],
        skeptic_msg: Optional["DialecticalMessage"],
    ) -> str:
        """Build user prompt from verdict, messages, and evidence."""
        parts = [
            f"Verdict: {verdict.outcome.value}",
            f"Confidence: {verdict.confidence:.0%}",
            f"Reasoning: {verdict.reasoning}",
            f"Architect confidence: {verdict.architect_confidence:.0%}",
            f"Skeptic confidence: {verdict.skeptic_confidence:.0%}",
            "",
        ]

        if architect_msg:
            parts.append("Architect's hypothesis:")
            for a in architect_msg.assertions:
                parts.append(f"  - {a.interpretation}")
            parts.append("")

        if skeptic_msg:
            parts.append("Skeptic's challenge:")
            for a in skeptic_msg.assertions:
                parts.append(f"  - {a.interpretation}")
            parts.append("")

        parts.append(_serialize_facts(packet))
        return "\n".join(parts)
