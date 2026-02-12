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
from typing import Dict, List, Optional, Set, TYPE_CHECKING

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
    ) -> None:
        self._client = client
        self._fallback = fallback or RuleBasedThreatAnalyzer()

    def analyze_threats(self, packet: "EvidencePacket") -> List[AnomalyPattern]:
        """Detect anomaly patterns using LLM reasoning.

        Args:
            packet: The EvidencePacket to analyze.

        Returns:
            List of validated AnomalyPattern instances.
        """
        try:
            response = self._client.complete(
                system=ARCHITECT_SYSTEM_PROMPT,
                user=self._build_user_prompt(packet),
            )
            raw_patterns = _parse_json_array(response.content)
            validated = self._validate_patterns(raw_patterns, packet)
            if validated:
                return validated
            # LLM returned nothing usable -> fallback
            return self._fallback.analyze_threats(packet)
        except Exception:
            return self._fallback.analyze_threats(packet)

    def _build_user_prompt(self, packet: "EvidencePacket") -> str:
        """Build user prompt from packet facts."""
        return (
            "Analyze the following security telemetry for threat patterns:\n\n"
            + _serialize_facts(packet)
        )

    def _validate_patterns(
        self, raw: List[Dict], packet: "EvidencePacket"
    ) -> List[AnomalyPattern]:
        """Validate LLM output against packet. Reject hallucinated fact_ids."""
        valid_fact_ids = packet.fact_ids
        validated: List[AnomalyPattern] = []

        for item in raw:
            if not isinstance(item, dict):
                continue

            # Validate fact_ids
            raw_fact_ids = item.get("fact_ids", [])
            if not isinstance(raw_fact_ids, list):
                continue
            if not all(isinstance(fid, str) for fid in raw_fact_ids):
                continue

            cited = frozenset(raw_fact_ids)
            if not cited or (cited - valid_fact_ids):
                continue  # Reject — references facts not in packet

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
                continue  # Unknown pattern type — skip

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
            except (ValueError, TypeError):
                continue  # AnomalyPattern validation failed

        return validated


class LLMExplanationFinder:
    """Uses Anthropic API to find benign explanations.

    Falls back to rule-based on any failure.
    """

    def __init__(
        self,
        client: AnthropicClient,
        *,
        fallback: Optional[RuleBasedExplanationFinder] = None,
    ) -> None:
        self._client = client
        self._fallback = fallback or RuleBasedExplanationFinder()

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
        try:
            response = self._client.complete(
                system=SKEPTIC_SYSTEM_PROMPT,
                user=self._build_user_prompt(architect_msg, packet),
            )
            raw_explanations = _parse_json_array(response.content)
            validated = self._validate_explanations(raw_explanations, packet)
            if validated:
                return validated
            return self._fallback.find_explanations(architect_msg, packet)
        except Exception:
            return self._fallback.find_explanations(architect_msg, packet)

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
        """Validate LLM output against packet. Reject hallucinated fact_ids."""
        valid_fact_ids = packet.fact_ids
        validated: List[BenignExplanation] = []

        for item in raw:
            if not isinstance(item, dict):
                continue

            raw_fact_ids = item.get("fact_ids", [])
            if not isinstance(raw_fact_ids, list):
                continue
            if not all(isinstance(fid, str) for fid in raw_fact_ids):
                continue

            cited = frozenset(raw_fact_ids)
            if not cited or (cited - valid_fact_ids):
                continue

            try:
                confidence = max(0.0, min(1.0, float(item.get("confidence", 0.0))))
            except (TypeError, ValueError):
                confidence = 0.0

            raw_type = str(item.get("explanation_type", "")).lower()
            try:
                explanation_type = ExplanationType(raw_type)
            except ValueError:
                continue  # Unknown explanation type

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
            except (ValueError, TypeError):
                continue

        return validated


class LLMNarrativeGenerator:
    """Uses Anthropic API to generate verdict explanations.

    Falls back to rule-based template on any failure.
    """

    def __init__(
        self,
        client: AnthropicClient,
        *,
        fallback: Optional[RuleBasedNarrativeGenerator] = None,
    ) -> None:
        self._client = client
        self._fallback = fallback or RuleBasedNarrativeGenerator()

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
        try:
            response = self._client.complete(
                system=NARRATOR_SYSTEM_PROMPT,
                user=self._build_user_prompt(
                    verdict, packet, architect_msg, skeptic_msg
                ),
            )
            narrative = response.content.strip()
            if not narrative:
                return self._fallback.generate_narrative(
                    verdict, packet, architect_msg, skeptic_msg
                )
            return narrative
        except Exception:
            return self._fallback.generate_narrative(
                verdict, packet, architect_msg, skeptic_msg
            )

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
