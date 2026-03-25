"""Conviction-anchored multi-turn LLM strategy implementations.

Session 020: Strategy classes that use the anchored prompts from
anchored_prompts.py. Identical structure to multi_turn_strategies.py —
same protocol compliance, same round state management, same validation,
same fallback. The ONLY difference is the prompt source.

These are independent implementations — NOT subclasses — to avoid coupling.
"""

from __future__ import annotations

import json
import re
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple, TYPE_CHECKING

from ares.dialectic.agents.patterns import (
    AnomalyPattern,
    BenignExplanation,
    ExplanationType,
    PatternType,
    Verdict,
    VerdictOutcome,
)
from ares.dialectic.agents.strategies.anchored_prompts import (
    get_anchored_architect_system_prompt,
    get_anchored_skeptic_system_prompt,
)
from ares.dialectic.agents.strategies.client import AnthropicClient, LLMResponse
from ares.dialectic.agents.strategies.multi_turn_prompts import (
    build_narrator_multi_turn_prompt,
)
from ares.dialectic.agents.strategies.prompts import NARRATOR_SYSTEM_PROMPT
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


# =============================================================================
# Shared helpers (replicated from multi_turn_strategies.py — no coupling)
# =============================================================================


def _strip_code_fences(text: str) -> str:
    """Strip markdown code fences from LLM response."""
    text = text.strip()
    pattern = r"^```(?:json)?\s*\n?(.*?)\n?\s*```$"
    match = re.match(pattern, text, re.DOTALL)
    if match:
        return match.group(1).strip()
    return text


def _extract_json_array(content: str) -> str:
    """Extract the JSON array portion from a response that may contain
    structured analysis before the JSON.

    Handles:
    1. Pure JSON array responses
    2. Structured rebuttal format followed by JSON array
    3. Code-fenced JSON after analysis

    Args:
        content: Raw LLM response text.

    Returns:
        The JSON array string.
    """
    cleaned = content.lstrip("\ufeff").strip()
    cleaned = _strip_code_fences(cleaned)

    # Try parsing directly first — handles pure JSON responses
    try:
        parsed = json.loads(cleaned)
        if isinstance(parsed, list):
            return cleaned
    except (json.JSONDecodeError, ValueError):
        pass

    # Look for the last JSON array in the response (after analysis block)
    # Find all [ ... ] blocks and try parsing from the last one
    bracket_positions = []
    depth = 0
    start_pos = None
    for i, ch in enumerate(cleaned):
        if ch == "[":
            if depth == 0:
                start_pos = i
            depth += 1
        elif ch == "]":
            depth -= 1
            if depth == 0 and start_pos is not None:
                bracket_positions.append((start_pos, i + 1))
                start_pos = None

    # Try from the last array bracket position
    for start, end in reversed(bracket_positions):
        candidate = cleaned[start:end]
        try:
            parsed = json.loads(candidate)
            if isinstance(parsed, list):
                return candidate
        except (json.JSONDecodeError, ValueError):
            continue

    # Fallback: return as-is and let json.loads raise the error downstream
    return cleaned


def _parse_json_array(content: str) -> List[Dict]:
    """Parse LLM response as a JSON array, handling structured rebuttal format."""
    json_str = _extract_json_array(content)
    parsed = json.loads(json_str)
    if not isinstance(parsed, list):
        raise ValueError(f"Expected JSON array, got {type(parsed).__name__}")
    return parsed


def _serialize_facts(packet: "EvidencePacket") -> str:
    """Serialize packet facts into a structured prompt section."""
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


# =============================================================================
# AnchoredMultiTurnThreatAnalyzer
# =============================================================================


class AnchoredMultiTurnThreatAnalyzer:
    """Round-aware Architect with conviction anchoring.

    Implements ThreatAnalyzer protocol. Uses anchored prompts that
    instruct the Architect to only retreat when the Skeptic cites
    specific counter-evidence.

    Same interface as MultiTurnLLMThreatAnalyzer — drop-in replacement.
    """

    def __init__(
        self,
        client: AnthropicClient,
        *,
        call_logger: Optional["LLMCallLogger"] = None,
        fallback: Optional[RuleBasedThreatAnalyzer] = None,
    ) -> None:
        self._client = client
        self._call_logger = call_logger
        self._fallback = fallback or RuleBasedThreatAnalyzer()
        self._round_number: int = 1
        self._previous_thesis: Optional["DialecticalMessage"] = None
        self._previous_antithesis: Optional["DialecticalMessage"] = None

    def set_round_context(
        self,
        round_number: int,
        previous_thesis: Optional["DialecticalMessage"] = None,
        previous_antithesis: Optional["DialecticalMessage"] = None,
    ) -> None:
        """Update debate context. Called by benchmark loop between rounds."""
        self._round_number = round_number
        self._previous_thesis = previous_thesis
        self._previous_antithesis = previous_antithesis

    def reset(self) -> None:
        """Reset for a new scenario."""
        self._round_number = 1
        self._previous_thesis = None
        self._previous_antithesis = None

    def analyze_threats(self, packet: "EvidencePacket") -> List[AnomalyPattern]:
        """Detect anomaly patterns using LLM with conviction anchoring."""
        start = time.monotonic()

        # Build previous_messages list for the prompt function
        previous_messages: list = []
        if self._previous_antithesis is not None:
            previous_messages.append(self._previous_antithesis)

        system_prompt = get_anchored_architect_system_prompt(
            round_number=self._round_number,
            previous_messages=previous_messages,
        )
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
                strategy_type="AnchoredThreatAnalyzer",
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

    def _validate_patterns_with_errors(
        self, raw: List[Dict], packet: "EvidencePacket"
    ) -> Tuple[List[AnomalyPattern], List[str]]:
        """Validate LLM output against packet."""
        valid_fact_ids = packet.fact_ids
        validated: List[AnomalyPattern] = []
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
                errors.append(f"Item {i}: hallucinated fact_ids {hallucinated}")
                continue

            try:
                confidence = max(0.0, min(1.0, float(item.get("confidence", 0.0))))
            except (TypeError, ValueError):
                confidence = 0.0

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


# =============================================================================
# AnchoredMultiTurnExplanationFinder
# =============================================================================


class AnchoredMultiTurnExplanationFinder:
    """Round-aware Skeptic with obligation to move.

    Implements ExplanationFinder protocol. Uses anchored prompts that
    instruct the Skeptic to acknowledge when the Architect successfully
    rebuts a point.

    Same interface as MultiTurnLLMExplanationFinder — drop-in replacement.
    """

    def __init__(
        self,
        client: AnthropicClient,
        *,
        call_logger: Optional["LLMCallLogger"] = None,
        fallback: Optional[RuleBasedExplanationFinder] = None,
    ) -> None:
        self._client = client
        self._call_logger = call_logger
        self._fallback = fallback or RuleBasedExplanationFinder()
        self._round_number: int = 1
        self._previous_thesis: Optional["DialecticalMessage"] = None
        self._previous_antithesis: Optional["DialecticalMessage"] = None

    def set_round_context(
        self,
        round_number: int,
        previous_thesis: Optional["DialecticalMessage"] = None,
        previous_antithesis: Optional["DialecticalMessage"] = None,
    ) -> None:
        """Update debate context. Called by benchmark loop between rounds."""
        self._round_number = round_number
        self._previous_thesis = previous_thesis
        self._previous_antithesis = previous_antithesis

    def reset(self) -> None:
        """Reset for a new scenario."""
        self._round_number = 1
        self._previous_thesis = None
        self._previous_antithesis = None

    def find_explanations(
        self,
        architect_msg: "DialecticalMessage",
        packet: "EvidencePacket",
    ) -> List[BenignExplanation]:
        """Find benign explanations using LLM with obligation to move."""
        start = time.monotonic()

        # Build previous_messages list for the prompt function
        previous_messages: list = []
        if self._previous_thesis is not None:
            previous_messages.append(self._previous_thesis)

        system_prompt = get_anchored_skeptic_system_prompt(
            round_number=self._round_number,
            previous_messages=previous_messages,
        )
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
                strategy_type="AnchoredExplanationFinder",
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

        for assertion in architect_msg.assertions:
            parts.append(
                f"  - {assertion.interpretation} "
                f"(fact_ids: {list(assertion.fact_ids)}, "
                f"confidence context: {assertion.operator} {assertion.threshold})"
            )

        parts.append("\nAnalyze the evidence for benign explanations:\n")
        parts.append(_serialize_facts(packet))
        return "\n".join(parts)

    def _validate_explanations_with_errors(
        self, raw: List[Dict], packet: "EvidencePacket"
    ) -> Tuple[List[BenignExplanation], List[str]]:
        """Validate LLM output against packet."""
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
                errors.append(f"Item {i}: hallucinated fact_ids {hallucinated}")
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


# =============================================================================
# AnchoredMultiTurnNarrativeGenerator
# =============================================================================


class AnchoredMultiTurnNarrativeGenerator:
    """Round-aware LLM narrative generator for anchored debate.

    Reuses the narrator prompt from multi_turn_prompts.py — the narrator
    doesn't need anchoring changes (it runs once at end). Included for
    completeness and to match the strategy factory triple.

    Same interface as MultiTurnLLMNarrativeGenerator.
    """

    def __init__(
        self,
        client: AnthropicClient,
        *,
        call_logger: Optional["LLMCallLogger"] = None,
        fallback: Optional[RuleBasedNarrativeGenerator] = None,
    ) -> None:
        self._client = client
        self._call_logger = call_logger
        self._fallback = fallback or RuleBasedNarrativeGenerator()
        self._round_number: int = 1
        self._total_rounds: int = 1
        self._termination_reason: Optional[str] = None

    def set_round_context(
        self,
        round_number: int,
        previous_thesis: Optional["DialecticalMessage"] = None,
        previous_antithesis: Optional["DialecticalMessage"] = None,
    ) -> None:
        """Update debate context."""
        self._round_number = round_number
        if round_number > self._total_rounds:
            self._total_rounds = round_number

    def set_termination_context(
        self,
        total_rounds: int,
        termination_reason: str,
    ) -> None:
        """Set termination context for narrative generation."""
        self._total_rounds = total_rounds
        self._termination_reason = termination_reason

    def reset(self) -> None:
        """Reset for a new scenario."""
        self._round_number = 1
        self._total_rounds = 1
        self._termination_reason = None

    def generate_narrative(
        self,
        verdict: Verdict,
        packet: "EvidencePacket",
        architect_msg: Optional["DialecticalMessage"] = None,
        skeptic_msg: Optional["DialecticalMessage"] = None,
    ) -> str:
        """Generate verdict explanation using LLM reasoning."""
        start = time.monotonic()

        if self._total_rounds > 1 and self._termination_reason is not None:
            system_prompt = build_narrator_multi_turn_prompt(
                total_rounds=self._total_rounds,
                termination_reason=self._termination_reason,
                base_system_prompt=NARRATOR_SYSTEM_PROMPT,
            )
        else:
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
                strategy_type="AnchoredNarrativeGenerator",
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
