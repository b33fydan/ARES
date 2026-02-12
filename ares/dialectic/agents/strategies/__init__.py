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

Observability:
    LLMCallRecord    - Frozen diagnostic record per LLM call
    LLMCallLogger    - Collects LLMCallRecords for inspection

Cycle Helpers:
    run_cycle_with_strategies       - Single-turn with strategy injection
    run_multi_turn_with_strategies  - Multi-turn with strategy injection
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

from ares.dialectic.agents.strategies.observability import (
    LLMCallLogger,
    LLMCallRecord,
)

from ares.dialectic.agents.strategies.live_cycle import (
    run_cycle_with_strategies,
    run_multi_turn_with_strategies,
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
    # Observability
    "LLMCallRecord",
    "LLMCallLogger",
    # Cycle helpers
    "run_cycle_with_strategies",
    "run_multi_turn_with_strategies",
]
