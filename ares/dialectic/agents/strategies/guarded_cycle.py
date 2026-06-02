"""Firewall-guarded dialectical cycle with hot-swap quarantine.

Session 046: Wraps run_cycle_with_strategies with Oracle Firewall validation
at the Architect->Skeptic junction. When taint is detected, the hot-swap
protocol spawns a fresh Architect instance on raw evidence only.

Public API:
    run_guarded_cycle()     -- Firewall-guarded single-turn cycle
    GuardedCycleResult      -- Frozen result with firewall metadata
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Callable, Optional, TYPE_CHECKING

from ares.dialectic.agents.architect import ArchitectAgent
from ares.dialectic.agents.context import TurnContext
from ares.dialectic.agents.oracle import OracleJudge, OracleNarrator
from ares.dialectic.agents.skeptic import SkepticAgent
from ares.dialectic.coordinator.cycle import TerminationReason
from ares.dialectic.coordinator.firewall import FirewallVerdict, OracleFirewall
from ares.dialectic.coordinator.orchestrator import CycleError, CycleResult
from ares.dialectic.evidence.packet import EvidencePacket
from ares.dialectic.messages.assertions import Assertion
from ares.dialectic.messages.protocol import DialecticalMessage, Phase

if TYPE_CHECKING:
    from ares.dialectic.agents.strategies.protocol import (
        ExplanationFinder,
        NarrativeGenerator,
        ThreatAnalyzer,
    )


@dataclass(frozen=True)
class GuardedCycleResult:
    """Result of a firewall-guarded analysis cycle.

    Attributes:
        cycle_result: The underlying analysis result.
        firewall_verdict: Firewall validation of the Architect's output.
        hot_swap_triggered: Whether the hot-swap protocol was activated.
        hot_swap_firewall_verdict: Firewall result for the hot-swap Architect, if triggered.
        quarantined_output: The tainted interpretation text that was quarantined.
        used_sanitized: Whether sanitized output was used instead of original.
    """

    cycle_result: CycleResult
    firewall_verdict: FirewallVerdict
    hot_swap_triggered: bool
    hot_swap_firewall_verdict: Optional[FirewallVerdict]
    quarantined_output: Optional[tuple[str, ...]]
    used_sanitized: bool


def _build_sanitized_message(
    original: DialecticalMessage,
    sanitized_interpretations: tuple[str, ...],
) -> DialecticalMessage:
    """Build a new DialecticalMessage with sanitized assertion interpretations.

    Creates a new message preserving all envelope and context fields from the
    original, but replacing each assertion's interpretation text with the
    corresponding sanitized version.

    Args:
        original: The tainted Architect message.
        sanitized_interpretations: Cleaned interpretation texts, one per assertion.

    Returns:
        A new DialecticalMessage with sanitized assertions.
    """
    sanitized_assertions = []
    for i, assertion in enumerate(original.assertions):
        sanitized_assertions.append(Assertion(
            assertion_id=assertion.assertion_id,
            assertion_type=assertion.assertion_type,
            fact_ids=assertion.fact_ids,
            interpretation=sanitized_interpretations[i],
            operator=assertion.operator,
            threshold=assertion.threshold,
        ))

    return DialecticalMessage(
        message_id=original.message_id,
        timestamp=original.timestamp,
        source_agent=original.source_agent,
        target_agent=original.target_agent,
        schema_version=original.schema_version,
        reply_to=original.reply_to,
        packet_id=original.packet_id,
        cycle_id=original.cycle_id,
        phase=original.phase,
        turn_number=original.turn_number,
        message_type=original.message_type,
        assertions=sanitized_assertions,
        unknowns=list(original.unknowns),
        confidence=original.confidence,
        narrative=original.narrative,
        priority=original.priority,
        persist=original.persist,
        tags=list(original.tags),
    )


def _make_clean_firewall_verdict() -> FirewallVerdict:
    """Create a pass-through FirewallVerdict for when no firewall is supplied."""
    return FirewallVerdict(
        passed=True,
        violations=(),
        taint_score=0.0,
        sanitized_output=None,
        timestamp=datetime.utcnow(),
    )


def run_guarded_cycle(
    packet: EvidencePacket,
    *,
    threat_analyzer: Optional["ThreatAnalyzer"] = None,
    explanation_finder: Optional["ExplanationFinder"] = None,
    narrative_generator: Optional["NarrativeGenerator"] = None,
    firewall: Optional[OracleFirewall] = None,
    enable_hot_swap: bool = True,
    hot_swap_factory: Optional[Callable[[], "ThreatAnalyzer"]] = None,
    agent_id_prefix: str = "ares",
    include_narration: bool = True,
    sanitize_supporting_facts: bool = False,
) -> GuardedCycleResult:
    """Run a firewall-guarded single-turn dialectical cycle.

    Follows the same THESIS -> ANTITHESIS -> SYNTHESIS flow as
    run_cycle_with_strategies, but inserts an Oracle Firewall checkpoint
    between THESIS and ANTITHESIS. When taint is detected:

    - If enable_hot_swap is True, a fresh Architect is spawned via
      hot_swap_factory on raw evidence only. If the hot-swap also fails,
      sanitized output is used.
    - If enable_hot_swap is False, sanitized output replaces the tainted
      interpretation text.

    Args:
        packet: Frozen EvidencePacket containing facts to analyze.
        threat_analyzer: Strategy for Architect's anomaly detection.
        explanation_finder: Strategy for Skeptic's benign explanations.
        narrative_generator: Strategy for OracleNarrator's explanation.
        firewall: OracleFirewall instance. None disables firewall validation.
        enable_hot_swap: Whether to attempt hot-swap on firewall failure.
        hot_swap_factory: Callable returning a fresh ThreatAnalyzer for hot-swap.
            Required when enable_hot_swap is True.
        agent_id_prefix: Prefix for generated agent IDs.
        include_narration: If True, run OracleNarrator for human explanation.
        sanitize_supporting_facts: If True, re-derive Verdict.supporting_fact_ids
            from the packet (framing-invariant). Default False = legacy passthrough.

    Returns:
        GuardedCycleResult with cycle output and firewall metadata.

    Raises:
        ValueError: If packet is not frozen, or enable_hot_swap is True
            but hot_swap_factory is None.
        CycleError: If any phase fails.
    """
    if not packet.is_frozen:
        raise ValueError("Packet must be frozen before running a cycle")

    if enable_hot_swap and hot_swap_factory is None:
        raise ValueError(
            "hot_swap_factory is required when enable_hot_swap is True"
        )

    started_at = datetime.utcnow()

    cycle_uuid = uuid.uuid4().hex[:8]
    cycle_id = f"cycle-{cycle_uuid}"
    prefix = agent_id_prefix

    # --- Create Architect with injected strategy ---
    architect = ArchitectAgent(
        agent_id=f"{prefix}-arch-{cycle_uuid}",
        threat_analyzer=threat_analyzer,
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

    # --- FIREWALL CHECKPOINT ---
    hot_swap_triggered = False
    hot_swap_firewall_verdict: Optional[FirewallVerdict] = None
    quarantined_output: Optional[tuple[str, ...]] = None
    used_sanitized = False

    if firewall is not None:
        firewall_verdict = firewall.validate(architect_message, packet)
    else:
        firewall_verdict = _make_clean_firewall_verdict()

    if not firewall_verdict.passed:
        # --- Firewall FAILED ---
        if enable_hot_swap:
            # Quarantine the original tainted output
            quarantined_output = tuple(
                a.interpretation for a in architect_message.assertions
            )
            hot_swap_triggered = True

            # Spawn a fresh Architect via factory
            assert hot_swap_factory is not None  # guaranteed by validation above
            swap_strategy = hot_swap_factory()
            swap_uuid = uuid.uuid4().hex[:8]
            swap_architect = ArchitectAgent(
                agent_id=f"{prefix}-arch-swap-{swap_uuid}",
                threat_analyzer=swap_strategy,
            )

            # Run THESIS again with fresh agent on raw evidence only
            try:
                swap_architect.observe(packet)
                swap_context = TurnContext(
                    cycle_id=cycle_id,
                    packet_id=packet.packet_id,
                    snapshot_id=packet.snapshot_id,
                    phase=Phase.THESIS,
                    turn_number=1,
                    max_turns=3,
                    seen_fact_ids=frozenset(),
                )
                swap_result = swap_architect.act(swap_context)
            except Exception as e:
                raise CycleError(
                    f"Hot-swap THESIS phase failed: {e}",
                    phase=Phase.THESIS,
                    cycle_id=cycle_id,
                    cause=e,
                ) from e

            if swap_result.message is None:
                raise CycleError(
                    "Hot-swap Architect produced no message",
                    phase=Phase.THESIS,
                    cycle_id=cycle_id,
                )
            swap_message = swap_result.message

            # Validate hot-swap output through firewall
            assert firewall is not None  # we only get here if firewall was set
            hot_swap_firewall_verdict = firewall.validate(swap_message, packet)

            if hot_swap_firewall_verdict.passed:
                # Hot-swap passed -- use its output
                architect_message = swap_message
            else:
                # Hot-swap also failed. Require sanitized output to fall back
                # to; otherwise fail closed rather than propagate the original
                # tainted message to the Skeptic. The FirewallVerdict invariant
                # makes this branch unreachable in practice, but enforcing it
                # at the use site keeps the contract local and survives any
                # future producer change.
                sanitized = hot_swap_firewall_verdict.sanitized_output
                if sanitized is None:
                    raise CycleError(
                        "Firewall failed-closed: hot-swap output rejected "
                        "and no sanitized fallback available",
                        phase=Phase.THESIS,
                        cycle_id=cycle_id,
                    )
                architect_message = _build_sanitized_message(
                    swap_message, sanitized,
                )
                used_sanitized = True
        else:
            # No hot-swap -- require sanitized output to use directly.
            # Fail closed if absent (same contract as the hot-swap branch).
            sanitized = firewall_verdict.sanitized_output
            if sanitized is None:
                raise CycleError(
                    "Firewall failed-closed: output rejected "
                    "and no sanitized fallback available",
                    phase=Phase.THESIS,
                    cycle_id=cycle_id,
                )
            architect_message = _build_sanitized_message(
                architect_message, sanitized,
            )
            used_sanitized = True

    # --- Create Skeptic with injected strategy ---
    skeptic = SkepticAgent(
        agent_id=f"{prefix}-skep-{cycle_uuid}",
        explanation_finder=explanation_finder,
    )

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

    # --- Optional supporting_fact_ids sanitization (opt-in, default off) ---
    if sanitize_supporting_facts:
        from ares.dialectic.agents.verdict_sanitizer import sanitize_verdict
        verdict = sanitize_verdict(verdict, packet)

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

    cycle_result = CycleResult(
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

    return GuardedCycleResult(
        cycle_result=cycle_result,
        firewall_verdict=firewall_verdict,
        hot_swap_triggered=hot_swap_triggered,
        hot_swap_firewall_verdict=hot_swap_firewall_verdict,
        quarantined_output=quarantined_output,
        used_sanitized=used_sanitized,
    )
