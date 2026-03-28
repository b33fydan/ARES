"""LLM strategy wrappers using v3 prompts.

Session 032: Thin wrappers around the existing LLM strategy classes
that substitute v3 prompts for improved fact citation and confidence
calibration. The core logic (JSON parsing, validation, fallback)
is inherited unchanged.

Public API:
    LLMThreatAnalyzerV3       — Uses ARCHITECT_SYSTEM_PROMPT_V3
    LLMExplanationFinderV3    — Uses SKEPTIC_SYSTEM_PROMPT_V3
    LLMNarrativeGeneratorV3   — Uses NARRATOR_SYSTEM_PROMPT_V3
"""

from __future__ import annotations

from ares.dialectic.agents.strategies.llm_strategy import (
    LLMExplanationFinder,
    LLMNarrativeGenerator,
    LLMThreatAnalyzer,
)
from ares.dialectic.agents.strategies.prompts_v3 import (
    ARCHITECT_SYSTEM_PROMPT_V3,
    NARRATOR_SYSTEM_PROMPT_V3,
    SKEPTIC_SYSTEM_PROMPT_V3,
)


class LLMThreatAnalyzerV3(LLMThreatAnalyzer):
    """LLMThreatAnalyzer with v3 prompts (exhaustive fact citation)."""

    def analyze_threats(self, packet):
        """Override to inject v3 prompt."""
        import time
        start = time.monotonic()
        user_prompt = self._build_user_prompt(packet)

        response = self._client.complete(
            system=ARCHITECT_SYSTEM_PROMPT_V3,
            user=user_prompt,
        )
        raw_response = response.content

        from ares.dialectic.agents.strategies.llm_strategy import _parse_json_array
        parsed = _parse_json_array(raw_response)
        validated, validation_errors = self._validate_patterns_with_errors(
            parsed, packet
        )

        latency_ms = (time.monotonic() - start) * 1000.0
        fallback_used = False

        if validated:
            result = validated
        else:
            fallback_used = True
            result = self._fallback.analyze_threats(packet)

        if self._call_logger is not None:
            from ares.dialectic.agents.strategies.observability import LLMCallRecord
            self._call_logger.record(LLMCallRecord(
                timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                strategy_type="LLMThreatAnalyzerV3",
                model=self._client.model,
                system_prompt=ARCHITECT_SYSTEM_PROMPT_V3[:200],
                user_prompt=user_prompt[:200],
                raw_response=raw_response[:500],
                parsed_result=parsed if parsed else None,
                validated_result=result if not fallback_used else None,
                validation_errors=tuple(validation_errors),
                fallback_used=fallback_used,
                fallback_reason="No valid patterns after validation" if fallback_used else None,
                input_tokens=response.usage_input_tokens,
                output_tokens=response.usage_output_tokens,
                latency_ms=latency_ms,
                error=None,
            ))

        return result


class LLMExplanationFinderV3(LLMExplanationFinder):
    """LLMExplanationFinder with v3 prompts (confidence calibration)."""

    def find_explanations(self, architect_msg, packet):
        """Override to inject v3 prompt."""
        import time
        start = time.monotonic()
        user_prompt = self._build_user_prompt(architect_msg, packet)

        response = self._client.complete(
            system=SKEPTIC_SYSTEM_PROMPT_V3,
            user=user_prompt,
        )
        raw_response = response.content

        from ares.dialectic.agents.strategies.llm_strategy import _parse_json_array
        parsed = _parse_json_array(raw_response)
        validated, validation_errors = self._validate_explanations_with_errors(
            parsed, packet
        )

        latency_ms = (time.monotonic() - start) * 1000.0
        fallback_used = False

        if validated:
            result = validated
        else:
            fallback_used = True
            result = self._fallback.find_explanations(architect_msg, packet)

        if self._call_logger is not None:
            from ares.dialectic.agents.strategies.observability import LLMCallRecord
            self._call_logger.record(LLMCallRecord(
                timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                strategy_type="LLMExplanationFinderV3",
                model=self._client.model,
                system_prompt=SKEPTIC_SYSTEM_PROMPT_V3[:200],
                user_prompt=user_prompt[:200],
                raw_response=raw_response[:500],
                parsed_result=parsed if parsed else None,
                validated_result=result if not fallback_used else None,
                validation_errors=tuple(validation_errors),
                fallback_used=fallback_used,
                fallback_reason="No valid explanations after validation" if fallback_used else None,
                input_tokens=response.usage_input_tokens,
                output_tokens=response.usage_output_tokens,
                latency_ms=latency_ms,
                error=None,
            ))

        return result


class LLMNarrativeGeneratorV3(LLMNarrativeGenerator):
    """LLMNarrativeGenerator with v3 prompts."""

    def generate_narrative(self, verdict, packet, architect_msg=None, skeptic_msg=None):
        """Override to inject v3 prompt."""
        import time
        start = time.monotonic()
        user_prompt = self._build_user_prompt(
            verdict, packet, architect_msg, skeptic_msg
        )

        try:
            response = self._client.complete(
                system=NARRATOR_SYSTEM_PROMPT_V3,
                user=user_prompt,
            )
            narrative = response.content.strip()
            fallback_used = not narrative

            if fallback_used:
                result = self._fallback.generate_narrative(
                    verdict, packet, architect_msg, skeptic_msg
                )
            else:
                result = narrative

        except Exception:
            fallback_used = True
            result = self._fallback.generate_narrative(
                verdict, packet, architect_msg, skeptic_msg
            )

        return result
