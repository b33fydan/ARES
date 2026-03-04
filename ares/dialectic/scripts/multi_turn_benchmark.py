"""Multi-turn benchmark runner — execute scenarios with iterative debate.

Runs BenchmarkScenarios through multi-turn LLM-powered dialectical debate
and collects structured results including per-round snapshots for analysis
of how debate evolves across rounds.

Public API:
    run_multi_turn_benchmark() -> MultiTurnBenchmarkRun
"""

from __future__ import annotations

import logging
import time
import traceback
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Sequence, Union

from ares.dialectic.agents.architect import ArchitectAgent
from ares.dialectic.agents.context import TurnContext
from ares.dialectic.agents.oracle import OracleJudge, OracleNarrator
from ares.dialectic.agents.skeptic import SkepticAgent
from ares.dialectic.coordinator.cycle import TerminationReason
from ares.dialectic.coordinator.multi_turn import DebateRound, MultiTurnConfig
from ares.dialectic.coordinator.orchestrator import CycleError
from ares.dialectic.evidence.packet import EvidencePacket
from ares.dialectic.messages.protocol import Phase
from ares.dialectic.scripts.scenario_corpus import BenchmarkScenario

logger = logging.getLogger("ares.multi_turn_benchmark")


# =============================================================================
# Result types
# =============================================================================


@dataclass(frozen=True)
class RoundSnapshot:
    """Captured state from one debate round.

    Immutable record of agent positions at a specific round,
    enabling analysis of how debate evolves across rounds.

    Attributes:
        round_number: 1-indexed round number within the cycle.
        architect_confidence: Architect's confidence in this round.
        skeptic_confidence: Skeptic's confidence in this round.
        architect_new_fact_count: Facts cited this round not seen in previous rounds.
        skeptic_new_fact_count: Facts cited this round not seen in previous rounds.
        architect_assertion_count: Number of assertions in the THESIS message.
        skeptic_assertion_count: Number of assertions in the ANTITHESIS message.
    """

    round_number: int
    architect_confidence: float
    skeptic_confidence: float
    architect_new_fact_count: int
    skeptic_new_fact_count: int
    architect_assertion_count: int
    skeptic_assertion_count: int


@dataclass(frozen=True)
class MultiTurnScenarioResult:
    """Result of running one scenario through multi-turn dialectical debate.

    Extends the measurement model from ScenarioResult with debate-specific
    metrics: round count, termination reason, and per-round snapshots.

    Attributes:
        scenario_id: Scenario identifier (e.g., "SC-001").
        scenario_name: Human-readable scenario name.
        expected_verdict: Expected verdict from scenario metadata.
        verdict_outcome: VerdictOutcome.value or "ERROR".
        verdict_confidence: Overall verdict confidence.
        architect_confidence: Final architect confidence.
        skeptic_confidence: Final skeptic confidence.
        coverage: Fraction of facts cited by either agent.
        narrator_output: Narrator narrative text or error message.
        duration_ms: Elapsed time in milliseconds.
        rounds_used: Number of debate rounds completed.
        max_rounds_configured: Maximum rounds allowed.
        termination_reason: TerminationReason.value or "ERROR".
        round_snapshots: Per-round state snapshots (tuple for frozen safety).
        validation_errors: Count of LLM validation errors.
        fallback_triggers: Count of fallback triggers.
        token_usage: Token usage dict.
        cost_usd: Cost in USD.
    """

    scenario_id: str
    scenario_name: str
    expected_verdict: str
    verdict_outcome: str
    verdict_confidence: float
    architect_confidence: float
    skeptic_confidence: float
    coverage: float
    narrator_output: str
    duration_ms: int
    rounds_used: int
    max_rounds_configured: int
    termination_reason: str
    round_snapshots: tuple
    validation_errors: int
    fallback_triggers: int
    token_usage: dict
    cost_usd: float

    @property
    def verdict_matches(self) -> bool:
        """Whether the actual verdict matches the expected verdict."""
        return self.verdict_outcome.lower() == self.expected_verdict.lower()


@dataclass(frozen=True)
class MultiTurnBenchmarkRun:
    """Complete multi-turn benchmark execution across all scenarios.

    Parallel to BenchmarkRun but with multi-turn metadata.

    Attributes:
        run_id: UUID string identifying this run.
        timestamp: When the run started (ISO format).
        strategy_type: Always "multi_turn_llm" for this runner.
        max_rounds: Maximum rounds configured.
        confidence_delta: Confidence delta for stabilization detection.
        require_new_evidence: Whether no-new-evidence termination is enabled.
        scenario_count: Number of scenarios in the run.
        results: Tuple of MultiTurnScenarioResult for each scenario.
        total_cost_usd: Total cost in USD across all scenarios.
        total_duration_ms: Total elapsed time for the entire run.
    """

    run_id: str
    timestamp: str
    strategy_type: str
    max_rounds: int
    confidence_delta: float
    require_new_evidence: bool
    scenario_count: int
    results: tuple
    total_cost_usd: float
    total_duration_ms: int

    @property
    def match_rate(self) -> float:
        """Fraction of scenarios where verdict matches expected."""
        matches = sum(1 for r in self.results if r.verdict_matches)
        return matches / len(self.results) if self.results else 0.0

    @property
    def avg_rounds_used(self) -> float:
        """Average number of debate rounds used across all scenarios."""
        return (
            sum(r.rounds_used for r in self.results) / len(self.results)
            if self.results
            else 0.0
        )

    @property
    def matches(self) -> int:
        """Number of scenarios where verdict matches expected."""
        return sum(1 for r in self.results if r.verdict_matches)


# =============================================================================
# Internal helpers
# =============================================================================


def _extract_llm_metrics(
    call_logger: object,
    start_index: int,
) -> tuple:
    """Extract LLM metrics from call_logger records added since start_index.

    Args:
        call_logger: LLMCallLogger instance with recorded calls.
        start_index: Index into call_logger.records marking the start of
            this scenario's records.

    Returns:
        Tuple of (validation_errors, fallback_triggers, token_usage, cost_usd).
    """
    records = call_logger.records[start_index:]
    validation_errors = sum(len(r.validation_errors) for r in records)
    fallback_triggers = sum(1 for r in records if r.fallback_used)
    input_tokens = sum(r.input_tokens for r in records)
    output_tokens = sum(r.output_tokens for r in records)
    token_usage = {"input_tokens": input_tokens, "output_tokens": output_tokens}
    cost_usd = (input_tokens / 1_000_000) * 3.0 + (output_tokens / 1_000_000) * 15.0
    return validation_errors, fallback_triggers, token_usage, cost_usd


def _build_round_snapshot(
    round_number: int,
    thesis_message: object,
    antithesis_message: object,
    facts_before_round: frozenset,
) -> RoundSnapshot:
    """Build a RoundSnapshot from a completed debate round.

    Args:
        round_number: 1-indexed round number.
        thesis_message: The Architect's DialecticalMessage.
        antithesis_message: The Skeptic's DialecticalMessage.
        facts_before_round: Fact IDs seen before this round.

    Returns:
        RoundSnapshot capturing the state of this round.
    """
    thesis_fact_ids = thesis_message.get_all_fact_ids()
    antithesis_fact_ids = antithesis_message.get_all_fact_ids()

    architect_new = len(thesis_fact_ids - facts_before_round)
    skeptic_new = len(antithesis_fact_ids - facts_before_round)

    return RoundSnapshot(
        round_number=round_number,
        architect_confidence=thesis_message.confidence,
        skeptic_confidence=antithesis_message.confidence,
        architect_new_fact_count=architect_new,
        skeptic_new_fact_count=skeptic_new,
        architect_assertion_count=len(thesis_message.assertions),
        skeptic_assertion_count=len(antithesis_message.assertions),
    )


def _run_single_scenario(
    scenario: BenchmarkScenario,
    *,
    threat_analyzer: object,
    explanation_finder: object,
    narrative_generator: object,
    max_rounds: int,
    confidence_delta: float,
    require_new_evidence: bool,
) -> tuple:
    """Run a single scenario through multi-turn debate.

    Replicates the multi-turn loop from coordinator/multi_turn.py with
    strategy injection from live_cycle.py. Fresh agents per scenario.

    Args:
        scenario: The benchmark scenario to run.
        threat_analyzer: ThreatAnalyzer strategy instance.
        explanation_finder: ExplanationFinder strategy instance.
        narrative_generator: NarrativeGenerator strategy instance.
        max_rounds: Maximum debate rounds.
        confidence_delta: Stabilization threshold.
        require_new_evidence: Whether to terminate on no new evidence.

    Returns:
        Tuple of (verdict, rounds_list, termination_reason, narrator_text,
                  all_cited_fact_ids, round_snapshots).

    Raises:
        CycleError: If any phase fails.
        ValueError: If packet is not frozen.
    """
    packet = scenario.packet
    if not packet.is_frozen:
        raise ValueError("Packet must be frozen before running a cycle")

    config = MultiTurnConfig(
        max_rounds=max_rounds,
        confidence_delta=confidence_delta,
        require_new_evidence=require_new_evidence,
    )

    cycle_uuid = uuid.uuid4().hex[:8]
    cycle_id = f"cycle-{cycle_uuid}"

    # Fresh agents per scenario with injected strategies
    architect = ArchitectAgent(
        agent_id=f"bench-arch-{cycle_uuid}",
        threat_analyzer=threat_analyzer,
    )
    skeptic = SkepticAgent(
        agent_id=f"bench-skep-{cycle_uuid}",
        explanation_finder=explanation_finder,
    )

    # Both agents observe the packet
    try:
        architect.observe(packet)
        skeptic.observe(packet)
    except Exception as e:
        raise CycleError(
            f"Agent observation failed: {e}",
            phase=Phase.THESIS,
            cycle_id=cycle_id,
            cause=e,
        ) from e

    # Multi-turn debate loop
    max_turns = 2 * config.max_rounds + 1
    all_cited_fact_ids: set = set()
    rounds: list = []
    round_snapshots: list = []
    termination_reason: Optional[TerminationReason] = None

    for round_number in range(1, config.max_rounds + 1):
        facts_before_round = frozenset(all_cited_fact_ids)

        # THESIS phase
        if round_number > 1:
            architect.receive(rounds[-1].antithesis)

        thesis_turn = (round_number - 1) * 2 + 1
        thesis_context = TurnContext(
            cycle_id=cycle_id,
            packet_id=packet.packet_id,
            snapshot_id=packet.snapshot_id,
            phase=Phase.THESIS,
            turn_number=thesis_turn,
            max_turns=max_turns,
            seen_fact_ids=facts_before_round,
        )

        try:
            architect_result = architect.act(thesis_context)
        except Exception as e:
            raise CycleError(
                f"THESIS phase failed in round {round_number}: {e}",
                phase=Phase.THESIS,
                cycle_id=cycle_id,
                cause=e,
            ) from e

        if architect_result.message is None:
            raise CycleError(
                f"Architect produced no message in round {round_number}",
                phase=Phase.THESIS,
                cycle_id=cycle_id,
            )

        thesis_message = architect_result.message
        thesis_fact_ids = thesis_message.get_all_fact_ids()
        all_cited_fact_ids.update(thesis_fact_ids)

        # ANTITHESIS phase
        skeptic.receive(thesis_message)

        antithesis_turn = (round_number - 1) * 2 + 2
        antithesis_context = TurnContext(
            cycle_id=cycle_id,
            packet_id=packet.packet_id,
            snapshot_id=packet.snapshot_id,
            phase=Phase.ANTITHESIS,
            turn_number=antithesis_turn,
            max_turns=max_turns,
            seen_fact_ids=frozenset(all_cited_fact_ids),
        )

        try:
            skeptic_result = skeptic.act(antithesis_context)
        except Exception as e:
            raise CycleError(
                f"ANTITHESIS phase failed in round {round_number}: {e}",
                phase=Phase.ANTITHESIS,
                cycle_id=cycle_id,
                cause=e,
            ) from e

        if skeptic_result.message is None:
            raise CycleError(
                f"Skeptic produced no message in round {round_number}",
                phase=Phase.ANTITHESIS,
                cycle_id=cycle_id,
            )

        antithesis_message = skeptic_result.message
        antithesis_fact_ids = antithesis_message.get_all_fact_ids()
        all_cited_fact_ids.update(antithesis_fact_ids)

        # Pass round context to strategies for next round (duck-typed)
        for strategy in [threat_analyzer, explanation_finder, narrative_generator]:
            if hasattr(strategy, 'set_round_context'):
                strategy.set_round_context(
                    round_number=round_number + 1,
                    previous_thesis=thesis_message,
                    previous_antithesis=antithesis_message,
                )

        # Record round
        debate_round = DebateRound(
            round_number=round_number,
            thesis=thesis_message,
            antithesis=antithesis_message,
        )
        rounds.append(debate_round)

        # Build snapshot for this round
        snapshot = _build_round_snapshot(
            round_number=round_number,
            thesis_message=thesis_message,
            antithesis_message=antithesis_message,
            facts_before_round=facts_before_round,
        )
        round_snapshots.append(snapshot)

        # TERMINATION CHECKS
        if round_number == config.max_rounds:
            termination_reason = TerminationReason.MAX_TURNS_EXCEEDED
            break

        if config.require_new_evidence and round_number > 1:
            round_fact_ids = thesis_fact_ids | antithesis_fact_ids
            new_facts = round_fact_ids - facts_before_round
            if not new_facts:
                termination_reason = TerminationReason.NO_NEW_EVIDENCE
                break

        if round_number > 1:
            prev_round = rounds[-2]
            curr_round = rounds[-1]
            arch_delta = abs(
                curr_round.architect_confidence - prev_round.architect_confidence
            )
            skep_delta = abs(
                curr_round.skeptic_confidence - prev_round.skeptic_confidence
            )
            if (
                arch_delta < config.confidence_delta
                and skep_delta < config.confidence_delta
            ):
                termination_reason = TerminationReason.CONFIDENCE_STABILIZED
                break

    assert termination_reason is not None, (
        "Bug: termination_reason not set after debate loop"
    )

    # Set termination context on narrator strategy (duck-typed)
    if hasattr(narrative_generator, 'set_termination_context'):
        narrative_generator.set_termination_context(
            total_rounds=len(rounds),
            termination_reason=termination_reason.value,
        )

    # Verdict computation (deterministic)
    final_round = rounds[-1]
    try:
        verdict = OracleJudge.compute_verdict(
            final_round.thesis,
            final_round.antithesis,
            packet,
        )
    except Exception as e:
        raise CycleError(
            f"Verdict computation failed: {e}",
            phase=Phase.SYNTHESIS,
            cycle_id=cycle_id,
            cause=e,
        ) from e

    # SYNTHESIS phase (narration)
    narrator_text: Optional[str] = None
    narrator = OracleNarrator(
        agent_id=f"bench-oracle-{cycle_uuid}",
        verdict=verdict,
        narrative_generator=narrative_generator,
    )
    try:
        narrator.observe(packet)
        synthesis_turn = len(rounds) * 2 + 1
        synthesis_context = TurnContext(
            cycle_id=cycle_id,
            packet_id=packet.packet_id,
            snapshot_id=packet.snapshot_id,
            phase=Phase.SYNTHESIS,
            turn_number=synthesis_turn,
            max_turns=max_turns,
            seen_fact_ids=frozenset(all_cited_fact_ids),
        )
        narrator_result = narrator.act(synthesis_context)
        if narrator_result.message is not None:
            narrator_text = narrator_result.message.narrative
    except Exception as e:
        raise CycleError(
            f"SYNTHESIS phase failed: {e}",
            phase=Phase.SYNTHESIS,
            cycle_id=cycle_id,
            cause=e,
        ) from e

    return (
        verdict,
        rounds,
        termination_reason,
        narrator_text,
        all_cited_fact_ids,
        tuple(round_snapshots),
    )


# =============================================================================
# Public API
# =============================================================================


def run_multi_turn_benchmark(
    scenarios: Union[list, tuple],
    *,
    client: object,
    call_logger: object = None,
    max_rounds: int = 3,
    confidence_delta: float = 0.05,
    require_new_evidence: bool = True,
    threat_analyzer_factory: object = None,
    explanation_finder_factory: object = None,
    narrative_generator_factory: object = None,
) -> MultiTurnBenchmarkRun:
    """Run all scenarios through multi-turn LLM-powered dialectical debate.

    For each scenario:
    1. Create fresh agents with LLM strategies (agent isolation)
    2. Run multi-turn debate loop (replicating multi_turn/cycle.py flow)
    3. Capture RoundSnapshot after each round
    4. Run OracleJudge on final round (deterministic)
    5. Record termination reason and round count
    6. Per-scenario error handling (Session 012 pattern)

    Args:
        scenarios: List of BenchmarkScenario from scenario_corpus.
        client: AnthropicClient for LLM calls.
        call_logger: Optional LLMCallLogger for cost tracking.
        max_rounds: Maximum debate rounds per scenario (default 3).
        confidence_delta: Terminate if confidence shifts < this between rounds.
        require_new_evidence: Terminate if no new fact_ids introduced.
        threat_analyzer_factory: Optional callable() -> ThreatAnalyzer.
            If None, uses LLMThreatAnalyzer.
        explanation_finder_factory: Optional callable() -> ExplanationFinder.
            If None, uses LLMExplanationFinder.
        narrative_generator_factory: Optional callable() -> NarrativeGenerator.
            If None, uses LLMNarrativeGenerator.

    Returns:
        MultiTurnBenchmarkRun with full results.

    Raises:
        ValueError: If scenarios is empty.
    """
    if not scenarios:
        raise ValueError("scenarios must not be empty")

    run_id = str(uuid.uuid4())
    run_timestamp = datetime.utcnow().isoformat()
    run_start = time.perf_counter()
    results: list = []

    for scenario in scenarios:
        # Create strategies — use factories if provided, else default LLM strategies
        if threat_analyzer_factory is not None:
            threat_analyzer = threat_analyzer_factory()
        else:
            from ares.dialectic.agents.strategies.llm_strategy import LLMThreatAnalyzer
            threat_analyzer = LLMThreatAnalyzer(client, call_logger=call_logger)

        if explanation_finder_factory is not None:
            explanation_finder = explanation_finder_factory()
        else:
            from ares.dialectic.agents.strategies.llm_strategy import LLMExplanationFinder
            explanation_finder = LLMExplanationFinder(client, call_logger=call_logger)

        if narrative_generator_factory is not None:
            narrative_generator = narrative_generator_factory()
        else:
            from ares.dialectic.agents.strategies.llm_strategy import LLMNarrativeGenerator
            narrative_generator = LLMNarrativeGenerator(client, call_logger=call_logger)

        # Snapshot logger state before cycle for per-scenario metric extraction
        record_start = (
            len(call_logger.records) if call_logger is not None else 0
        )

        cycle_start = time.perf_counter()
        try:
            (
                verdict,
                rounds,
                termination_reason,
                narrator_text,
                all_cited_fact_ids,
                round_snapshots,
            ) = _run_single_scenario(
                scenario,
                threat_analyzer=threat_analyzer,
                explanation_finder=explanation_finder,
                narrative_generator=narrative_generator,
                max_rounds=max_rounds,
                confidence_delta=confidence_delta,
                require_new_evidence=require_new_evidence,
            )
            cycle_end = time.perf_counter()
            duration_ms = int((cycle_end - cycle_start) * 1000)

            # Extract LLM metrics
            llm_validation_errors = 0
            llm_fallback_triggers = 0
            llm_token_usage: dict = {"input_tokens": 0, "output_tokens": 0}
            llm_cost_usd: float = 0.0
            if call_logger is not None:
                (
                    llm_validation_errors,
                    llm_fallback_triggers,
                    llm_token_usage,
                    llm_cost_usd,
                ) = _extract_llm_metrics(call_logger, record_start)

            # Compute coverage
            total_facts = scenario.packet.fact_count
            coverage = (
                len(all_cited_fact_ids) / total_facts if total_facts > 0 else 0.0
            )

            result = MultiTurnScenarioResult(
                scenario_id=scenario.metadata.scenario_id,
                scenario_name=scenario.metadata.name,
                expected_verdict=scenario.metadata.expected_verdict,
                verdict_outcome=verdict.outcome.value,
                verdict_confidence=verdict.confidence,
                architect_confidence=verdict.architect_confidence,
                skeptic_confidence=verdict.skeptic_confidence,
                coverage=coverage,
                narrator_output=narrator_text or "",
                duration_ms=duration_ms,
                rounds_used=len(rounds),
                max_rounds_configured=max_rounds,
                termination_reason=termination_reason.value,
                round_snapshots=round_snapshots,
                validation_errors=llm_validation_errors,
                fallback_triggers=llm_fallback_triggers,
                token_usage=llm_token_usage,
                cost_usd=llm_cost_usd,
            )

        except Exception as exc:
            cycle_end = time.perf_counter()
            duration_ms = int((cycle_end - cycle_start) * 1000)
            tb = traceback.format_exc()
            error_msg = f"{type(exc).__name__}: {exc}\n{tb}"
            logger.warning(
                "Scenario %s failed: %s",
                scenario.metadata.scenario_id,
                exc,
            )
            result = MultiTurnScenarioResult(
                scenario_id=scenario.metadata.scenario_id,
                scenario_name=scenario.metadata.name,
                expected_verdict=scenario.metadata.expected_verdict,
                verdict_outcome="ERROR",
                verdict_confidence=0.0,
                architect_confidence=0.0,
                skeptic_confidence=0.0,
                coverage=0.0,
                narrator_output=error_msg[:500],
                duration_ms=duration_ms,
                rounds_used=0,
                max_rounds_configured=max_rounds,
                termination_reason="ERROR",
                round_snapshots=(),
                validation_errors=0,
                fallback_triggers=0,
                token_usage={"input_tokens": 0, "output_tokens": 0},
                cost_usd=0.0,
            )

        results.append(result)

    run_end = time.perf_counter()
    total_duration_ms = int((run_end - run_start) * 1000)
    total_cost = sum(r.cost_usd for r in results)

    return MultiTurnBenchmarkRun(
        run_id=run_id,
        timestamp=run_timestamp,
        strategy_type="multi_turn_llm",
        max_rounds=max_rounds,
        confidence_delta=confidence_delta,
        require_new_evidence=require_new_evidence,
        scenario_count=len(results),
        results=tuple(results),
        total_cost_usd=total_cost,
        total_duration_ms=total_duration_ms,
    )
