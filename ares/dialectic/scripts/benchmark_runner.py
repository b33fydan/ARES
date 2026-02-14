"""Benchmark runner — execute scenarios and collect metrics.

Runs BenchmarkScenarios through rule-based or LLM strategy paths
and collects structured results for comparison.

Public API:
    run_benchmark() -> BenchmarkRun
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Sequence, Union

from ares.dialectic.agents.strategies.live_cycle import run_cycle_with_strategies
from ares.dialectic.agents.strategies.rule_based import (
    RuleBasedExplanationFinder,
    RuleBasedNarrativeGenerator,
    RuleBasedThreatAnalyzer,
)
from ares.dialectic.coordinator.orchestrator import CycleResult
from ares.dialectic.scripts.scenario_corpus import BenchmarkScenario


# =============================================================================
# Result types
# =============================================================================

@dataclass(frozen=True)
class ScenarioResult:
    """Result of running a single scenario through a strategy path.

    Attributes:
        scenario_id: Scenario identifier (e.g., "SC-001").
        strategy_type: "rule_based" or "llm".
        verdict_outcome: VerdictOutcome value as string.
        verdict_confidence: Overall verdict confidence.
        architect_confidence: Architect's claim confidence.
        skeptic_confidence: Skeptic's rebuttal confidence.
        architect_assertion_count: Number of assertions in the THESIS message.
        skeptic_assertion_count: Number of assertions in the ANTITHESIS message.
        architect_fact_ids_cited: Fact IDs cited by the Architect.
        skeptic_fact_ids_cited: Fact IDs cited by the Skeptic.
        total_facts_available: Total facts in the packet.
        fact_coverage_ratio: Fraction of facts cited by either agent.
        validation_errors: Number of validation errors (0 for rule-based).
        fallback_triggers: Number of fallback triggers (0 for rule-based).
        duration_ms: Elapsed time in milliseconds.
        token_usage: Token usage dict (None for rule-based).
        cost_usd: Cost in USD (None for rule-based).
        narrator_output: Narrator narrative text (None if narration excluded).
    """

    scenario_id: str
    strategy_type: str
    verdict_outcome: str
    verdict_confidence: float
    architect_confidence: float
    skeptic_confidence: float
    architect_assertion_count: int
    skeptic_assertion_count: int
    architect_fact_ids_cited: frozenset[str]
    skeptic_fact_ids_cited: frozenset[str]
    total_facts_available: int
    fact_coverage_ratio: float
    validation_errors: int
    fallback_triggers: int
    duration_ms: int
    token_usage: Optional[dict]
    cost_usd: Optional[float]
    narrator_output: Optional[str]


@dataclass(frozen=True)
class BenchmarkRun:
    """Complete benchmark run across all scenarios.

    Attributes:
        run_id: UUID string identifying this run.
        timestamp: When the run started.
        strategy_type: "rule_based" or "llm".
        scenario_count: Number of scenarios in the run.
        results: Tuple of ScenarioResult for each scenario.
        total_duration_ms: Total elapsed time for the entire run.
        total_cost_usd: Total cost in USD (None for rule-based).
    """

    run_id: str
    timestamp: datetime
    strategy_type: str
    scenario_count: int
    results: tuple[ScenarioResult, ...]
    total_duration_ms: int
    total_cost_usd: Optional[float]


# =============================================================================
# Internal helpers
# =============================================================================

def _extract_scenario_result(
    scenario: BenchmarkScenario,
    cycle_result: CycleResult,
    strategy_type: str,
    duration_ms: int,
    include_narration: bool,
) -> ScenarioResult:
    """Extract metrics from a CycleResult into a ScenarioResult."""
    architect_fact_ids = frozenset(
        cycle_result.architect_message.get_all_fact_ids()
    )
    skeptic_fact_ids = frozenset(
        cycle_result.skeptic_message.get_all_fact_ids()
    )
    total_facts = scenario.packet.fact_count
    all_cited = architect_fact_ids | skeptic_fact_ids
    coverage = len(all_cited) / total_facts if total_facts > 0 else 0.0

    narrator_text: Optional[str] = None
    if include_narration and cycle_result.narrator_message is not None:
        narrator_text = cycle_result.narrator_message.narrative

    return ScenarioResult(
        scenario_id=scenario.metadata.scenario_id,
        strategy_type=strategy_type,
        verdict_outcome=cycle_result.verdict.outcome.value,
        verdict_confidence=cycle_result.verdict.confidence,
        architect_confidence=cycle_result.verdict.architect_confidence,
        skeptic_confidence=cycle_result.verdict.skeptic_confidence,
        architect_assertion_count=len(cycle_result.architect_message.assertions),
        skeptic_assertion_count=len(cycle_result.skeptic_message.assertions),
        architect_fact_ids_cited=architect_fact_ids,
        skeptic_fact_ids_cited=skeptic_fact_ids,
        total_facts_available=total_facts,
        fact_coverage_ratio=coverage,
        validation_errors=0,
        fallback_triggers=0,
        duration_ms=duration_ms,
        token_usage=None,
        cost_usd=None,
        narrator_output=narrator_text,
    )


# =============================================================================
# Public API
# =============================================================================

def run_benchmark(
    scenarios: Union[list[BenchmarkScenario], tuple[BenchmarkScenario, ...]],
    strategy_type: str = "rule_based",
    include_narration: bool = True,
    client: object = None,
    call_logger: object = None,
) -> BenchmarkRun:
    """Run all scenarios through the specified strategy path and collect metrics.

    Args:
        scenarios: List of BenchmarkScenarios to run.
        strategy_type: "rule_based" or "llm".
        include_narration: Whether to include OracleNarrator output.
        client: Required if strategy_type is "llm". AnthropicClient instance.
        call_logger: Optional LLMCallLogger for LLM runs.

    Returns:
        BenchmarkRun with results for all scenarios.

    Raises:
        ValueError: If strategy_type is not "rule_based" or "llm".
        ValueError: If strategy_type is "llm" and client is None.
        ValueError: If scenarios is empty.
    """
    if strategy_type not in ("rule_based", "llm"):
        raise ValueError(
            f"strategy_type must be 'rule_based' or 'llm', got '{strategy_type}'"
        )
    if not scenarios:
        raise ValueError("scenarios must not be empty")
    if strategy_type == "llm" and client is None:
        raise ValueError("client is required when strategy_type is 'llm'")

    run_id = str(uuid.uuid4())
    run_timestamp = datetime.utcnow()
    run_start = time.perf_counter()
    results: list[ScenarioResult] = []

    for scenario in scenarios:
        # Build strategies
        if strategy_type == "rule_based":
            threat_analyzer = RuleBasedThreatAnalyzer()
            explanation_finder = RuleBasedExplanationFinder()
            narrative_generator = RuleBasedNarrativeGenerator()
        else:
            # LLM path — import lazily to avoid hard dependency
            from ares.dialectic.agents.strategies.llm_strategy import (
                LLMExplanationFinder,
                LLMNarrativeGenerator,
                LLMThreatAnalyzer,
            )
            threat_analyzer = LLMThreatAnalyzer(client)
            explanation_finder = LLMExplanationFinder(client)
            narrative_generator = LLMNarrativeGenerator(client)

        # Run the cycle with timing
        cycle_start = time.perf_counter()
        cycle_result = run_cycle_with_strategies(
            packet=scenario.packet,
            threat_analyzer=threat_analyzer,
            explanation_finder=explanation_finder,
            narrative_generator=narrative_generator,
            include_narration=include_narration,
        )
        cycle_end = time.perf_counter()
        duration_ms = int((cycle_end - cycle_start) * 1000)

        result = _extract_scenario_result(
            scenario=scenario,
            cycle_result=cycle_result,
            strategy_type=strategy_type,
            duration_ms=duration_ms,
            include_narration=include_narration,
        )
        results.append(result)

    run_end = time.perf_counter()
    total_duration_ms = int((run_end - run_start) * 1000)

    return BenchmarkRun(
        run_id=run_id,
        timestamp=run_timestamp,
        strategy_type=strategy_type,
        scenario_count=len(results),
        results=tuple(results),
        total_duration_ms=total_duration_ms,
        total_cost_usd=None if strategy_type == "rule_based" else 0.0,
    )
