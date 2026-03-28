"""Selective escalation pipeline — the core Phase 3 deliverable.

Session 024: Routes scenarios through the two-gate architecture:
  1. Run single-turn verdict
  2. Check EscalationGate (uncertainty detection)
  3. Check MiscalibrationDetector (overconfidence detection)
  4. If EITHER gate triggers -> run multi-turn debate, use that verdict
  5. If NEITHER triggers -> accept single-turn verdict

This is the measurement that answers: does selective escalation beat
pure single-turn accuracy?

Public API:
    SelectiveResult    — frozen dataclass per-scenario outcome
    SelectiveSummary   — frozen dataclass aggregate metrics
    run_selective_escalation — run the pipeline
    format_selective_report  — formatted text report
"""

from __future__ import annotations

import logging
import time
import traceback
from dataclasses import dataclass
from typing import Optional, Sequence, Tuple, Union

from ares.dialectic.agents.patterns import VerdictOutcome
from ares.dialectic.coordinator.escalation import (
    EscalationDecision,
    EscalationGate,
)
from ares.dialectic.coordinator.miscalibration import (
    MiscalibrationDetector,
    MiscalibrationRecommendation,
)
from ares.dialectic.scripts.scenario_corpus import BenchmarkScenario

logger = logging.getLogger("ares.selective_escalation")


@dataclass(frozen=True)
class SelectiveResult:
    """Per-scenario outcome from the selective escalation pipeline.

    Attributes:
        scenario_id: Scenario identifier.
        scenario_name: Human-readable name.
        expected_verdict: Expected VerdictOutcome value.
        single_turn_verdict: Verdict from single-turn run.
        single_turn_confidence: Confidence from single-turn run.
        escalated: Whether this scenario was escalated.
        escalation_reason: "uncertainty", "miscalibration", "both", or "none".
        final_verdict: The verdict used as the answer.
        final_correct: Whether the final verdict matches expected.
        cost: Total LLM cost for this scenario.
    """

    scenario_id: str
    scenario_name: str
    expected_verdict: VerdictOutcome
    single_turn_verdict: VerdictOutcome
    single_turn_confidence: float
    escalated: bool
    escalation_reason: str
    final_verdict: VerdictOutcome
    final_correct: bool
    cost: float


@dataclass(frozen=True)
class SelectiveSummary:
    """Aggregate metrics from the selective escalation pipeline.

    Attributes:
        total_scenarios: Number of scenarios processed.
        escalated_count: Number escalated to multi-turn.
        escalation_rate: Fraction escalated.
        single_turn_accuracy: Baseline single-turn accuracy.
        selective_accuracy: Selective escalation accuracy.
        accuracy_delta: selective - single_turn (positive = improvement).
        total_cost: Total LLM cost across all scenarios.
        single_turn_cost: Cost of just the single-turn passes.
        cost_ratio: total_cost / single_turn_cost.
        results: Per-scenario details.
    """

    total_scenarios: int
    escalated_count: int
    escalation_rate: float
    single_turn_accuracy: float
    selective_accuracy: float
    accuracy_delta: float
    total_cost: float
    single_turn_cost: float
    cost_ratio: float
    results: Tuple[SelectiveResult, ...]


def _classify_escalation_reason(
    esc_triggered: bool,
    misc_triggered: bool,
) -> str:
    """Classify why a scenario was escalated."""
    if esc_triggered and misc_triggered:
        return "both"
    elif esc_triggered:
        return "uncertainty"
    elif misc_triggered:
        return "miscalibration"
    return "none"


def run_selective_escalation(
    scenarios: Union[list[BenchmarkScenario], tuple[BenchmarkScenario, ...]],
    *,
    escalation_gate: EscalationGate | None = None,
    miscalibration_detector: MiscalibrationDetector | None = None,
    client: object = None,
    call_logger: object = None,
    max_rounds: int = 3,
    use_anchored: bool = True,
) -> SelectiveSummary:
    """Run the selective escalation pipeline on all scenarios.

    For each scenario:
    1. Run single-turn with LLM strategies
    2. Check both gates
    3. If flagged, run multi-turn debate
    4. Record final verdict and cost

    Args:
        scenarios: Benchmark scenarios to evaluate.
        escalation_gate: Custom gate (defaults to [0.35, 0.65]).
        miscalibration_detector: Custom detector (defaults to standard).
        client: AnthropicClient for LLM calls. Required.
        call_logger: LLMCallLogger for cost tracking.
        max_rounds: Max debate rounds for multi-turn.
        use_anchored: Use anchored strategies for multi-turn (default True).

    Returns:
        SelectiveSummary with aggregate and per-scenario results.
    """
    if client is None:
        raise ValueError("client is required for selective escalation")
    if not scenarios:
        raise ValueError("scenarios must not be empty")

    gate = escalation_gate or EscalationGate()
    detector = miscalibration_detector or MiscalibrationDetector()

    # Lazy imports for LLM strategies
    from ares.dialectic.scripts.benchmark_runner import run_benchmark
    from ares.dialectic.scripts.multi_turn_benchmark import run_multi_turn_benchmark

    results: list[SelectiveResult] = []
    total_cost = 0.0
    single_turn_cost = 0.0

    total = len(scenarios)
    for i, scenario in enumerate(scenarios):
        sid = scenario.metadata.scenario_id
        sname = scenario.metadata.name
        expected = VerdictOutcome(scenario.metadata.expected_verdict.lower())

        print(f"  [{i+1}/{total}] {sid}: {sname}")

        # Step 1: Single-turn LLM
        record_start = len(call_logger.records) if call_logger else 0
        st_start = time.perf_counter()

        try:
            st_run = run_benchmark(
                scenarios=[scenario],
                strategy_type="llm",
                include_narration=True,
                client=client,
                call_logger=call_logger,
            )
            st_result = st_run.results[0]
            st_verdict_outcome = VerdictOutcome(st_result.verdict_outcome.lower())
            st_confidence = st_result.verdict_confidence
            st_cost = st_result.cost_usd or 0.0
        except Exception as exc:
            logger.warning("Single-turn failed for %s: %s", sid, exc)
            st_verdict_outcome = VerdictOutcome.INCONCLUSIVE
            st_confidence = 0.0
            st_cost = 0.0

        single_turn_cost += st_cost
        scenario_cost = st_cost

        # Step 2: Gate check — need the CycleResult for miscalibration detector
        # Re-run single-turn to get the full CycleResult (or extract from benchmark)
        # We use the benchmark result fields to reconstruct what we need
        try:
            from ares.dialectic.agents.strategies.live_cycle import run_cycle_with_strategies
            from ares.dialectic.agents.strategies.llm_strategy import (
                LLMThreatAnalyzer,
                LLMExplanationFinder,
                LLMNarrativeGenerator,
            )
            from ares.dialectic.agents.patterns import Verdict

            # Build a Verdict from the benchmark result for gate evaluation
            st_verdict = Verdict(
                outcome=st_verdict_outcome,
                confidence=st_confidence,
                supporting_fact_ids=frozenset(),
                architect_confidence=st_result.architect_confidence,
                skeptic_confidence=st_result.skeptic_confidence,
                reasoning="Reconstructed from benchmark result",
            )

            # EscalationGate check
            esc_result = gate.evaluate(st_verdict)
            esc_triggered = esc_result.decision == EscalationDecision.ESCALATED

            # MiscalibrationDetector needs architect/skeptic messages
            # We can only do a partial check using the verdict's confidence
            # since we don't have the full messages from run_benchmark.
            # Use a simplified check: confidence + assertion counts
            from ares.dialectic.messages.protocol import DialecticalMessage, Phase, MessageType
            from ares.dialectic.messages.assertions import Assertion, AssertionType
            from datetime import datetime

            # Build minimal messages from benchmark data for detector
            arch_assertions = [
                Assertion(
                    assertion_id=f"a{k}",
                    assertion_type=AssertionType.ASSERT,
                    fact_ids=tuple(st_result.architect_fact_ids_cited),
                    interpretation="benchmark assertion",
                )
                for k in range(st_result.architect_assertion_count)
            ] if st_result.architect_assertion_count > 0 else []

            arch_msg = DialecticalMessage(
                message_id="arch-bench",
                timestamp=datetime.utcnow(),
                source_agent="architect",
                target_agent="oracle",
                confidence=st_result.architect_confidence,
                assertions=arch_assertions,
                phase=Phase.THESIS,
                message_type=MessageType.HYPOTHESIS,
            )

            skep_msg = DialecticalMessage(
                message_id="skep-bench",
                timestamp=datetime.utcnow(),
                source_agent="skeptic",
                target_agent="oracle",
                confidence=st_result.skeptic_confidence,
                assertions=[],
                phase=Phase.ANTITHESIS,
                message_type=MessageType.REBUTTAL,
            )

            misc_result = detector.detect(st_verdict, arch_msg, skep_msg, scenario.packet)
            misc_triggered = misc_result.recommendation == MiscalibrationRecommendation.INSPECT

        except Exception as exc:
            logger.warning("Gate check failed for %s: %s", sid, exc)
            esc_triggered = False
            misc_triggered = False

        escalated = esc_triggered or misc_triggered
        reason = _classify_escalation_reason(esc_triggered, misc_triggered)

        # Step 3: Multi-turn if escalated
        final_verdict = st_verdict_outcome
        if escalated:
            print(f"    -> ESCALATED ({reason})")
            try:
                if use_anchored:
                    from ares.dialectic.agents.strategies.anchored_strategies import (
                        AnchoredMultiTurnThreatAnalyzer,
                        AnchoredMultiTurnExplanationFinder,
                        AnchoredMultiTurnNarrativeGenerator,
                    )
                    mt_run = run_multi_turn_benchmark(
                        scenarios=[scenario],
                        client=client,
                        call_logger=call_logger,
                        max_rounds=max_rounds,
                        threat_analyzer_factory=lambda: AnchoredMultiTurnThreatAnalyzer(
                            client, call_logger=call_logger
                        ),
                        explanation_finder_factory=lambda: AnchoredMultiTurnExplanationFinder(
                            client, call_logger=call_logger
                        ),
                        narrative_generator_factory=lambda: AnchoredMultiTurnNarrativeGenerator(
                            client, call_logger=call_logger
                        ),
                    )
                else:
                    from ares.dialectic.agents.strategies.multi_turn_strategies import (
                        MultiTurnLLMThreatAnalyzer,
                        MultiTurnLLMExplanationFinder,
                        MultiTurnLLMNarrativeGenerator,
                    )
                    mt_run = run_multi_turn_benchmark(
                        scenarios=[scenario],
                        client=client,
                        call_logger=call_logger,
                        max_rounds=max_rounds,
                        threat_analyzer_factory=lambda: MultiTurnLLMThreatAnalyzer(
                            client, call_logger=call_logger
                        ),
                        explanation_finder_factory=lambda: MultiTurnLLMExplanationFinder(
                            client, call_logger=call_logger
                        ),
                        narrative_generator_factory=lambda: MultiTurnLLMNarrativeGenerator(
                            client, call_logger=call_logger
                        ),
                    )

                mt_result = mt_run.results[0]
                final_verdict = VerdictOutcome(mt_result.verdict_outcome.lower())
                scenario_cost += mt_result.cost_usd
            except Exception as exc:
                logger.warning("Multi-turn failed for %s: %s", sid, exc)
                # Keep single-turn verdict on multi-turn failure
        else:
            print(f"    -> RESOLVED (accepted single-turn)")

        total_cost += scenario_cost
        final_correct = final_verdict == expected

        results.append(SelectiveResult(
            scenario_id=sid,
            scenario_name=sname,
            expected_verdict=expected,
            single_turn_verdict=st_verdict_outcome,
            single_turn_confidence=st_confidence,
            escalated=escalated,
            escalation_reason=reason,
            final_verdict=final_verdict,
            final_correct=final_correct,
            cost=scenario_cost,
        ))

    # Compute summaries
    n = len(results)
    escalated_count = sum(1 for r in results if r.escalated)
    st_correct = sum(1 for r in results if r.single_turn_verdict == r.expected_verdict)
    sel_correct = sum(1 for r in results if r.final_correct)

    st_accuracy = st_correct / n if n > 0 else 0.0
    sel_accuracy = sel_correct / n if n > 0 else 0.0

    return SelectiveSummary(
        total_scenarios=n,
        escalated_count=escalated_count,
        escalation_rate=escalated_count / n if n > 0 else 0.0,
        single_turn_accuracy=st_accuracy,
        selective_accuracy=sel_accuracy,
        accuracy_delta=sel_accuracy - st_accuracy,
        total_cost=total_cost,
        single_turn_cost=single_turn_cost,
        cost_ratio=total_cost / single_turn_cost if single_turn_cost > 0 else 1.0,
        results=tuple(results),
    )


def format_selective_report(summary: SelectiveSummary) -> str:
    """Produce a formatted text report from selective escalation results.

    Args:
        summary: The SelectiveSummary to format.

    Returns:
        Multi-line string report.
    """
    lines: list[str] = []
    lines.append("=" * 70)
    lines.append("SELECTIVE ESCALATION REPORT")
    lines.append("=" * 70)
    lines.append("")
    lines.append(f"Total scenarios:    {summary.total_scenarios}")
    lines.append(f"Escalated:          {summary.escalated_count} ({summary.escalation_rate:.0%})")
    lines.append("")
    lines.append("--- Accuracy Comparison ---")
    lines.append(f"  Single-turn:      {summary.single_turn_accuracy:.1%}")
    lines.append(f"  Selective:        {summary.selective_accuracy:.1%}")
    delta_sign = "+" if summary.accuracy_delta >= 0 else ""
    lines.append(f"  Delta:            {delta_sign}{summary.accuracy_delta:.1%}")
    lines.append("")
    lines.append("--- Cost Comparison ---")
    lines.append(f"  Single-turn:      ${summary.single_turn_cost:.4f}")
    lines.append(f"  Selective total:  ${summary.total_cost:.4f}")
    lines.append(f"  Cost ratio:       {summary.cost_ratio:.2f}x")
    lines.append("")
    lines.append("--- Per-Scenario Breakdown ---")
    lines.append(
        f"{'ID':<8} {'Name':<30} {'Expected':<18} {'ST':<8} "
        f"{'Final':<8} {'Esc?':<6} {'Reason':<16} {'Cost':>8}"
    )
    lines.append("-" * 120)

    for r in summary.results:
        st_mark = "Y" if r.single_turn_verdict == r.expected_verdict else "X"
        fin_mark = "Y" if r.final_correct else "X"
        esc_mark = "ESC" if r.escalated else "---"
        lines.append(
            f"{r.scenario_id:<8} {r.scenario_name[:29]:<30} "
            f"{r.expected_verdict.value:<18} {st_mark:<8} "
            f"{fin_mark:<8} {esc_mark:<6} {r.escalation_reason:<16} "
            f"${r.cost:>7.4f}"
        )

    lines.append("")

    # Highlight flips
    flips_good = [r for r in summary.results if r.escalated and r.final_correct and r.single_turn_verdict != r.expected_verdict]
    flips_bad = [r for r in summary.results if r.escalated and not r.final_correct and r.single_turn_verdict == r.expected_verdict]

    if flips_good:
        lines.append(f"GOOD FLIPS (escalation fixed error): {len(flips_good)}")
        for r in flips_good:
            lines.append(f"  {r.scenario_id}: {r.single_turn_verdict.value} -> {r.final_verdict.value}")
    if flips_bad:
        lines.append(f"BAD FLIPS (escalation introduced error): {len(flips_bad)}")
        for r in flips_bad:
            lines.append(f"  {r.scenario_id}: {r.single_turn_verdict.value} -> {r.final_verdict.value}")

    if not flips_good and not flips_bad:
        lines.append("No verdict flips from escalation.")

    lines.append("")
    lines.append("=" * 70)
    return "\n".join(lines)
