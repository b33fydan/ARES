"""Helper functions for running dialectical cycles with custom strategies.

These replicate the flow of DialecticalOrchestrator.run_cycle() but allow
strategy injection for LLM-powered agents. The production Orchestrator
remains untouched.

Architecture note: These are PEER functions to the Orchestrator, not wrappers.
They compose the same building blocks (agents, TurnContext, OracleJudge)
to implement cycles with pluggable strategies.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional, TYPE_CHECKING

from ares.dialectic.agents.architect import ArchitectAgent
from ares.dialectic.agents.context import TurnContext
from ares.dialectic.agents.oracle import OracleJudge, OracleNarrator
from ares.dialectic.agents.skeptic import SkepticAgent
from ares.dialectic.coordinator.cycle import TerminationReason
from ares.dialectic.coordinator.orchestrator import CycleError, CycleResult
from ares.dialectic.coordinator.multi_turn import (
    DebateRound,
    MultiTurnConfig,
    MultiTurnCycleResult,
)
from ares.dialectic.evidence.packet import EvidencePacket
from ares.dialectic.messages.protocol import DialecticalMessage, Phase

if TYPE_CHECKING:
    from ares.dialectic.agents.strategies.protocol import (
        ExplanationFinder,
        NarrativeGenerator,
        ThreatAnalyzer,
    )


def run_cycle_with_strategies(
    packet: EvidencePacket,
    *,
    threat_analyzer: Optional["ThreatAnalyzer"] = None,
    explanation_finder: Optional["ExplanationFinder"] = None,
    narrative_generator: Optional["NarrativeGenerator"] = None,
    agent_id_prefix: str = "ares",
    include_narration: bool = True,
) -> CycleResult:
    """Run a single-turn dialectical cycle with injected strategies.

    Replicates DialecticalOrchestrator.run_cycle() flow but accepts
    pluggable reasoning strategies for each agent role.

    Default strategies are RuleBasedXxx (identical to production behavior).

    Args:
        packet: Frozen EvidencePacket containing facts to analyze.
        threat_analyzer: Strategy for Architect's anomaly detection.
        explanation_finder: Strategy for Skeptic's benign explanations.
        narrative_generator: Strategy for OracleNarrator's explanation.
        agent_id_prefix: Prefix for generated agent IDs.
        include_narration: If True, run OracleNarrator for human explanation.

    Returns:
        CycleResult with verdict and all messages.

    Raises:
        ValueError: If packet is not frozen.
        CycleError: If any phase fails.
    """
    if not packet.is_frozen:
        raise ValueError("Packet must be frozen before running a cycle")

    started_at = datetime.utcnow()

    cycle_uuid = uuid.uuid4().hex[:8]
    cycle_id = f"cycle-{cycle_uuid}"
    prefix = agent_id_prefix

    # --- Create agents with injected strategies ---
    architect = ArchitectAgent(
        agent_id=f"{prefix}-arch-{cycle_uuid}",
        threat_analyzer=threat_analyzer,
    )
    skeptic = SkepticAgent(
        agent_id=f"{prefix}-skep-{cycle_uuid}",
        explanation_finder=explanation_finder,
    )

    # --- THESIS phase ---
    try:
        architect.observe(packet)
        thesis_context = TurnContext(
            cycle_id=cycle_id,
            packet_id=packet.packet_id,
            snapshot_id=packet.snapshot_id,
            phase=Phase.THESIS,
            turn_number=1,
            max_turns=3,
            seen_fact_ids=frozenset(),
        )
        architect_result = architect.act(thesis_context)
    except Exception as e:
        raise CycleError(
            f"THESIS phase failed: {e}",
            phase=Phase.THESIS,
            cycle_id=cycle_id,
            cause=e,
        ) from e

    if architect_result.message is None:
        raise CycleError(
            "Architect produced no message",
            phase=Phase.THESIS,
            cycle_id=cycle_id,
        )
    architect_message = architect_result.message

    # --- ANTITHESIS phase ---
    try:
        skeptic.observe(packet)
        skeptic.receive(architect_message)
        arch_fact_ids = frozenset(architect_message.get_all_fact_ids())
        antithesis_context = TurnContext(
            cycle_id=cycle_id,
            packet_id=packet.packet_id,
            snapshot_id=packet.snapshot_id,
            phase=Phase.ANTITHESIS,
            turn_number=2,
            max_turns=3,
            seen_fact_ids=arch_fact_ids,
        )
        skeptic_result = skeptic.act(antithesis_context)
    except Exception as e:
        raise CycleError(
            f"ANTITHESIS phase failed: {e}",
            phase=Phase.ANTITHESIS,
            cycle_id=cycle_id,
            cause=e,
        ) from e

    if skeptic_result.message is None:
        raise CycleError(
            "Skeptic produced no message",
            phase=Phase.ANTITHESIS,
            cycle_id=cycle_id,
        )
    skeptic_message = skeptic_result.message

    # --- Verdict computation (deterministic, not an agent) ---
    try:
        verdict = OracleJudge.compute_verdict(
            architect_message, skeptic_message, packet,
        )
    except Exception as e:
        raise CycleError(
            f"Verdict computation failed: {e}",
            phase=Phase.SYNTHESIS,
            cycle_id=cycle_id,
            cause=e,
        ) from e

    # --- SYNTHESIS phase (optional narration) ---
    narrator_message: Optional[DialecticalMessage] = None
    if include_narration:
        narrator = OracleNarrator(
            agent_id=f"{prefix}-oracle-{cycle_uuid}",
            verdict=verdict,
            narrative_generator=narrative_generator,
        )
        try:
            narrator.observe(packet)
            all_fact_ids = frozenset(verdict.supporting_fact_ids)
            synthesis_context = TurnContext(
                cycle_id=cycle_id,
                packet_id=packet.packet_id,
                snapshot_id=packet.snapshot_id,
                phase=Phase.SYNTHESIS,
                turn_number=3,
                max_turns=3,
                seen_fact_ids=all_fact_ids,
            )
            narrator_result = narrator.act(synthesis_context)
        except Exception as e:
            raise CycleError(
                f"SYNTHESIS phase failed: {e}",
                phase=Phase.SYNTHESIS,
                cycle_id=cycle_id,
                cause=e,
            ) from e

        if narrator_result.message is None:
            raise CycleError(
                "OracleNarrator produced no message",
                phase=Phase.SYNTHESIS,
                cycle_id=cycle_id,
            )
        narrator_message = narrator_result.message

    completed_at = datetime.utcnow()
    duration_ms = int((completed_at - started_at).total_seconds() * 1000)

    return CycleResult(
        cycle_id=cycle_id,
        packet_id=packet.packet_id,
        verdict=verdict,
        architect_message=architect_message,
        skeptic_message=skeptic_message,
        narrator_message=narrator_message,
        started_at=started_at,
        completed_at=completed_at,
        duration_ms=duration_ms,
    )


def run_multi_turn_with_strategies(
    packet: EvidencePacket,
    *,
    threat_analyzer: Optional["ThreatAnalyzer"] = None,
    explanation_finder: Optional["ExplanationFinder"] = None,
    narrative_generator: Optional["NarrativeGenerator"] = None,
    agent_id_prefix: str = "ares",
    max_rounds: int = 3,
    include_narration: bool = True,
) -> CycleResult:
    """Run a multi-turn dialectical cycle with injected strategies.

    Replicates run_multi_turn_cycle() flow with strategy injection.
    Returns CycleResult (not MultiTurnCycleResult) for Memory Stream
    compatibility via to_cycle_result() bridge.

    Args:
        packet: Frozen EvidencePacket containing facts to analyze.
        threat_analyzer: Strategy for Architect's anomaly detection.
        explanation_finder: Strategy for Skeptic's benign explanations.
        narrative_generator: Strategy for OracleNarrator's explanation.
        agent_id_prefix: Prefix for generated agent IDs.
        max_rounds: Maximum THESIS/ANTITHESIS pairs before forced verdict.
        include_narration: If True, run OracleNarrator after verdict.

    Returns:
        CycleResult with verdict and final round messages.

    Raises:
        ValueError: If packet is not frozen.
        CycleError: If any phase fails.
    """
    if not packet.is_frozen:
        raise ValueError("Packet must be frozen before running a cycle")

    config = MultiTurnConfig(max_rounds=max_rounds)
    started_at = datetime.utcnow()

    cycle_uuid = uuid.uuid4().hex[:8]
    cycle_id = f"cycle-{cycle_uuid}"

    # --- Create agents with injected strategies ---
    architect = ArchitectAgent(
        agent_id=f"{agent_id_prefix}-arch-{cycle_uuid}",
        threat_analyzer=threat_analyzer,
    )
    skeptic = SkepticAgent(
        agent_id=f"{agent_id_prefix}-skep-{cycle_uuid}",
        explanation_finder=explanation_finder,
    )

    # --- Both agents observe the packet ---
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

    # --- Multi-turn debate loop ---
    max_turns = 2 * config.max_rounds + 1
    all_cited_fact_ids: set[str] = set()
    rounds: list[DebateRound] = []
    termination_reason: Optional[TerminationReason] = None

    for round_number in range(1, config.max_rounds + 1):
        facts_before_round = frozenset(all_cited_fact_ids)

        # --- THESIS phase ---
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

        # --- ANTITHESIS phase ---
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

        # --- Record round ---
        debate_round = DebateRound(
            round_number=round_number,
            thesis=thesis_message,
            antithesis=antithesis_message,
        )
        rounds.append(debate_round)

        # --- TERMINATION CHECKS ---
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

    assert termination_reason is not None

    # --- Verdict computation ---
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

    # --- SYNTHESIS phase (optional narration) ---
    narrator_message: Optional[DialecticalMessage] = None
    if include_narration:
        narrator = OracleNarrator(
            agent_id=f"{agent_id_prefix}-oracle-{cycle_uuid}",
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
        except Exception as e:
            raise CycleError(
                f"SYNTHESIS phase failed: {e}",
                phase=Phase.SYNTHESIS,
                cycle_id=cycle_id,
                cause=e,
            ) from e

        if narrator_result.message is None:
            raise CycleError(
                "OracleNarrator produced no message",
                phase=Phase.SYNTHESIS,
                cycle_id=cycle_id,
            )
        narrator_message = narrator_result.message

    completed_at = datetime.utcnow()
    duration_ms = int((completed_at - started_at).total_seconds() * 1000)

    # Build MultiTurnCycleResult and convert to CycleResult for Memory Stream
    mt_result = MultiTurnCycleResult(
        cycle_id=cycle_id,
        packet_id=packet.packet_id,
        verdict=verdict,
        rounds=tuple(rounds),
        termination_reason=termination_reason,
        narrator_message=narrator_message,
        started_at=started_at,
        completed_at=completed_at,
        duration_ms=duration_ms,
    )

    return mt_result.to_cycle_result()
