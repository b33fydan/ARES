"""Multi-Turn Dialectical Cycles.

Extends the single-turn Orchestrator pattern to support multiple rounds
of THESIS -> ANTITHESIS debate before a final SYNTHESIS verdict.

This is a PEER module to the existing Orchestrator — not a replacement,
not a wrapper. It composes the same building blocks (agents, TurnContext,
OracleJudge) to implement a multi-round debate loop.

Architecture:
    EvidencePacket (frozen)
        |
        +---> orchestrator.run_cycle(packet) -> CycleResult          (existing, 1 round)
        |
        +---> run_multi_turn_cycle(packet) -> MultiTurnCycleResult   (new, N rounds)
                                                |
                                                +---> .to_cycle_result() -> CycleResult
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from ares.dialectic.agents.architect import ArchitectAgent
from ares.dialectic.agents.context import TurnContext
from ares.dialectic.agents.oracle import OracleJudge, OracleNarrator
from ares.dialectic.agents.patterns import Verdict
from ares.dialectic.agents.skeptic import SkepticAgent
from ares.dialectic.coordinator.cycle import TerminationReason
from ares.dialectic.coordinator.orchestrator import CycleError, CycleResult
from ares.dialectic.evidence.packet import EvidencePacket
from ares.dialectic.messages.protocol import DialecticalMessage, Phase


@dataclass(frozen=True)
class DebateRound:
    """A single THESIS -> ANTITHESIS exchange within a multi-turn cycle.

    Attributes:
        round_number: 1-indexed round number within the cycle.
        thesis: The Architect's message (Phase.THESIS).
        antithesis: The Skeptic's message (Phase.ANTITHESIS).
    """

    round_number: int
    thesis: DialecticalMessage
    antithesis: DialecticalMessage

    @property
    def architect_confidence(self) -> float:
        """Convenience: thesis.confidence"""
        return self.thesis.confidence

    @property
    def skeptic_confidence(self) -> float:
        """Convenience: antithesis.confidence"""
        return self.antithesis.confidence


@dataclass(frozen=True)
class MultiTurnConfig:
    """Configuration for multi-turn dialectical cycles.

    IMPORTANT: This delegates termination semantics to CycleConfig from cycle.py.
    It adds only multi-turn-specific configuration (max_rounds).

    Attributes:
        max_rounds: Maximum THESIS/ANTITHESIS pairs before forced verdict.
        confidence_delta: Confidence change below this triggers stabilization.
        require_new_evidence: If True, terminate when no new fact_ids.
    """

    max_rounds: int = 3
    confidence_delta: float = 0.1
    require_new_evidence: bool = True

    def __post_init__(self) -> None:
        if self.max_rounds < 1:
            raise ValueError("max_rounds must be >= 1")
        if not (0.0 <= self.confidence_delta <= 1.0):
            raise ValueError("confidence_delta must be between 0.0 and 1.0")


@dataclass(frozen=True)
class MultiTurnCycleResult:
    """Complete output of a multi-turn dialectical cycle.

    Attributes:
        cycle_id: UUID string, unique per multi-turn cycle.
        packet_id: Source packet identifier.
        verdict: Final verdict from OracleJudge.
        rounds: Complete debate history, ordered.
        termination_reason: Why the debate ended.
        narrator_message: SYNTHESIS explanation (None if skipped).
        started_at: Cycle start timestamp.
        completed_at: Cycle end timestamp.
        duration_ms: Full execution duration in milliseconds.
    """

    cycle_id: str
    packet_id: str
    verdict: Verdict
    rounds: tuple[DebateRound, ...]
    termination_reason: TerminationReason
    narrator_message: Optional[DialecticalMessage]
    started_at: datetime
    completed_at: datetime
    duration_ms: int

    @property
    def total_rounds(self) -> int:
        """Number of completed debate rounds."""
        return len(self.rounds)

    @property
    def final_round(self) -> DebateRound:
        """The last completed debate round."""
        return self.rounds[-1]

    def to_cycle_result(self) -> CycleResult:
        """Convert to a standard CycleResult using the final round's messages.

        This enables Memory Stream integration without modifying the Memory Stream.
        The CycleResult represents the FINAL state of the debate — the refined
        positions after all rounds of deliberation.
        """
        return CycleResult(
            cycle_id=self.cycle_id,
            packet_id=self.packet_id,
            verdict=self.verdict,
            architect_message=self.final_round.thesis,
            skeptic_message=self.final_round.antithesis,
            narrator_message=self.narrator_message,
            started_at=self.started_at,
            completed_at=self.completed_at,
            duration_ms=self.duration_ms,
        )


def run_multi_turn_cycle(
    packet: EvidencePacket,
    *,
    config: Optional[MultiTurnConfig] = None,
    agent_id_prefix: str = "ares",
    include_narration: bool = True,
) -> MultiTurnCycleResult:
    """Execute a multi-turn dialectical cycle.

    The debate alternates THESIS/ANTITHESIS rounds until a termination
    condition is met, then OracleJudge computes the final verdict.

    Termination conditions (checked after each complete round):
    1. max_rounds reached
    2. No new evidence introduced (if config.require_new_evidence is True):
       Neither agent cited any fact_ids in this round that weren't already
       cited in previous rounds.
    3. Confidence stabilized: Both architect and skeptic confidence changed
       by less than config.confidence_delta compared to the previous round.

    Args:
        packet: Frozen EvidencePacket containing facts to analyze.
        config: Multi-turn configuration. Defaults to MultiTurnConfig() if None.
        agent_id_prefix: Prefix for generated agent IDs.
        include_narration: If True, run OracleNarrator after verdict.

    Returns:
        MultiTurnCycleResult with verdict, full debate history, and termination reason.

    Raises:
        ValueError: If packet is not frozen.
        CycleError: If any phase fails.
    """
    # --- Pre-flight: packet must be frozen ---
    if not packet.is_frozen:
        raise ValueError("Packet must be frozen before running a cycle")

    config = config or MultiTurnConfig()
    started_at = datetime.utcnow()

    # --- Generate cycle and agent IDs ---
    cycle_uuid = uuid.uuid4().hex[:8]
    cycle_id = f"cycle-{cycle_uuid}"

    architect = ArchitectAgent(agent_id=f"{agent_id_prefix}-arch-{cycle_uuid}")
    skeptic = SkepticAgent(agent_id=f"{agent_id_prefix}-skep-{cycle_uuid}")

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
    max_turns = 2 * config.max_rounds + 1  # Enough for all debate + synthesis turns
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

        # --- TERMINATION CHECKS (after each complete round) ---

        # 1. Max rounds reached
        if round_number == config.max_rounds:
            termination_reason = TerminationReason.MAX_TURNS_EXCEEDED
            break

        # 2. No new evidence (only meaningful after round 1)
        if config.require_new_evidence and round_number > 1:
            round_fact_ids = thesis_fact_ids | antithesis_fact_ids
            new_facts = round_fact_ids - facts_before_round
            if not new_facts:
                termination_reason = TerminationReason.NO_NEW_EVIDENCE
                break

        # 3. Confidence stabilized (only meaningful after round 1)
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

    # Safety check — the max_rounds check guarantees this
    assert termination_reason is not None, (
        "Bug: termination_reason not set after debate loop"
    )

    # --- Verdict computation (deterministic, not an agent) ---
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

    return MultiTurnCycleResult(
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
