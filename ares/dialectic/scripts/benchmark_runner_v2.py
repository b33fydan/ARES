"""Injectable benchmark runner — accepts custom strategies and judge.

Session 033: Solves the blocker where run_benchmark() creates strategies
internally. This module provides run_benchmark_custom() which accepts
pre-constructed strategy instances and an optional custom judge function.

Reuses ScenarioResult and BenchmarkRun from benchmark_runner.py.

Public API:
    run_benchmark_custom()  — Run benchmark with injected strategies + judge
"""

from __future__ import annotations

import time
import traceback
import uuid
from datetime import datetime, timezone
from typing import Callable, Optional, Sequence, Tuple, Union

from ares.dialectic.agents.strategies.live_cycle import run_cycle_with_strategies
from ares.dialectic.scripts.benchmark_runner import BenchmarkRun, ScenarioResult


def run_benchmark_custom(
    scenarios: Union[list, tuple],
    threat_analyzer,
    explanation_finder,
    narrative_generator=None,
    judge_fn: Optional[Callable] = None,
    call_logger=None,
    include_narration: bool = True,
    strategy_label: str = "custom",
) -> BenchmarkRun:
    """Run benchmark with pre-constructed strategy instances and optional custom judge.

    Args:
        scenarios: Sequence of BenchmarkScenario instances.
        threat_analyzer: ThreatAnalyzer implementation (e.g., LLMThreatAnalyzerV3).
        explanation_finder: ExplanationFinder implementation (e.g., LLMExplanationFinderV3).
        narrative_generator: Optional NarrativeGenerator (e.g., LLMNarrativeGeneratorV3).
        judge_fn: Optional callable (architect_msg, skeptic_msg, packet) -> Verdict.
                  If None, uses default OracleJudge (V1) from the cycle.
        call_logger: Optional LLMCallLogger for token/cost tracking.
        include_narration: Whether to include narrator output.
        strategy_label: Label for BenchmarkRun.strategy_type field.

    Returns:
        BenchmarkRun with ScenarioResult for each scenario.

    Raises:
        ValueError: If scenarios is empty.
    """
    if not scenarios:
        raise ValueError("scenarios must not be empty")

    run_id = uuid.uuid4().hex[:12]
    run_timestamp = datetime.now(timezone.utc)
    start_perf = time.perf_counter()
    results: list[ScenarioResult] = []

    for scenario in scenarios:
        sid = scenario.metadata.scenario_id
        scenario_start = time.perf_counter()
        record_start = len(call_logger.records) if call_logger else 0

        try:
            cycle_result = run_cycle_with_strategies(
                packet=scenario.packet,
                threat_analyzer=threat_analyzer,
                explanation_finder=explanation_finder,
                narrative_generator=narrative_generator,
                include_narration=include_narration,
            )

            # Optionally replace verdict with custom judge
            if judge_fn is not None:
                verdict = judge_fn(
                    cycle_result.architect_message,
                    cycle_result.skeptic_message,
                    scenario.packet,
                )
            else:
                verdict = cycle_result.verdict

            # Extract metrics
            arch_msg = cycle_result.architect_message
            skep_msg = cycle_result.skeptic_message

            arch_facts = arch_msg.get_all_fact_ids()
            skep_facts = skep_msg.get_all_fact_ids()
            all_cited = arch_facts | skep_facts
            total_facts = scenario.packet.fact_count
            coverage = len(all_cited) / total_facts if total_facts > 0 else 0.0

            # LLM metrics from call_logger
            validation_errors = 0
            fallback_triggers = 0
            token_usage = None
            cost_usd = None

            if call_logger is not None:
                records_slice = call_logger.records[record_start:]
                for rec in records_slice:
                    validation_errors += len(rec.validation_errors)
                    if rec.fallback_used:
                        fallback_triggers += 1
                if records_slice:
                    total_in = sum(r.input_tokens for r in records_slice)
                    total_out = sum(r.output_tokens for r in records_slice)
                    token_usage = {
                        "input_tokens": total_in,
                        "output_tokens": total_out,
                    }
                    cost_usd = (total_in / 1_000_000) * 3.0 + (total_out / 1_000_000) * 15.0

            # Narrator output
            narrator_output = None
            if include_narration and cycle_result.narrator_message is not None:
                narrator_output = cycle_result.narrator_message.narrative

            scenario_ms = int((time.perf_counter() - scenario_start) * 1000)

            result = ScenarioResult(
                scenario_id=sid,
                strategy_type=strategy_label,
                verdict_outcome=verdict.outcome.value,
                verdict_confidence=verdict.confidence,
                architect_confidence=verdict.architect_confidence,
                skeptic_confidence=verdict.skeptic_confidence,
                architect_assertion_count=len(arch_msg.assertions),
                skeptic_assertion_count=len(skep_msg.assertions),
                architect_fact_ids_cited=frozenset(arch_facts),
                skeptic_fact_ids_cited=frozenset(skep_facts),
                total_facts_available=total_facts,
                fact_coverage_ratio=coverage,
                validation_errors=validation_errors,
                fallback_triggers=fallback_triggers,
                duration_ms=scenario_ms,
                token_usage=token_usage,
                cost_usd=cost_usd,
                narrator_output=narrator_output,
            )

        except Exception as exc:
            scenario_ms = int((time.perf_counter() - scenario_start) * 1000)
            tb = traceback.format_exc()[:500]
            result = ScenarioResult(
                scenario_id=sid,
                strategy_type=strategy_label,
                verdict_outcome="ERROR",
                verdict_confidence=0.0,
                architect_confidence=0.0,
                skeptic_confidence=0.0,
                architect_assertion_count=0,
                skeptic_assertion_count=0,
                architect_fact_ids_cited=frozenset(),
                skeptic_fact_ids_cited=frozenset(),
                total_facts_available=scenario.packet.fact_count,
                fact_coverage_ratio=0.0,
                validation_errors=0,
                fallback_triggers=0,
                duration_ms=scenario_ms,
                token_usage=None,
                cost_usd=None,
                narrator_output=f"ERROR: {tb}",
            )

        results.append(result)

    total_ms = int((time.perf_counter() - start_perf) * 1000)
    total_cost = sum(r.cost_usd for r in results if r.cost_usd is not None) or None

    return BenchmarkRun(
        run_id=run_id,
        timestamp=run_timestamp,
        strategy_type=strategy_label,
        scenario_count=len(results),
        results=tuple(results),
        total_duration_ms=total_ms,
        total_cost_usd=total_cost,
    )
