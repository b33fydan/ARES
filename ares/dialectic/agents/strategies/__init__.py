"""Pluggable reasoning strategies for ARES dialectical agents.

Strategy Pattern: agents accept optional strategy objects at construction.
The default is always rule-based (deterministic, zero behavior change).
LLM strategies wrap the Anthropic API with closed-world validation.

Protocols:
    ThreatAnalyzer      - Architect's anomaly detection
    ExplanationFinder   - Skeptic's benign explanation finding
    NarrativeGenerator  - OracleNarrator's verdict explanation

Rule-based (default):
    RuleBasedThreatAnalyzer
    RuleBasedExplanationFinder
    RuleBasedNarrativeGenerator

LLM-powered:
    LLMThreatAnalyzer
    LLMExplanationFinder
    LLMNarrativeGenerator

Client:
    AnthropicClient  - Thin API wrapper
    LLMResponse      - Frozen response container
"""

from ares.dialectic.agents.strategies.protocol import (
    ExplanationFinder,
    NarrativeGenerator,
    ThreatAnalyzer,
)

from ares.dialectic.agents.strategies.rule_based import (
    RuleBasedExplanationFinder,
    RuleBasedNarrativeGenerator,
    RuleBasedThreatAnalyzer,
)

from ares.dialectic.agents.strategies.llm_strategy import (
    LLMExplanationFinder,
    LLMNarrativeGenerator,
    LLMThreatAnalyzer,
)

from ares.dialectic.agents.strategies.client import (
    AnthropicClient,
    LLMResponse,
)

__all__ = [
    # Protocols
    "ThreatAnalyzer",
    "ExplanationFinder",
    "NarrativeGenerator",
    # Rule-based implementations
    "RuleBasedThreatAnalyzer",
    "RuleBasedExplanationFinder",
    "RuleBasedNarrativeGenerator",
    # LLM implementations
    "LLMThreatAnalyzer",
    "LLMExplanationFinder",
    "LLMNarrativeGenerator",
    # Client
    "AnthropicClient",
    "LLMResponse",
]
