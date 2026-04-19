"""Session 050 light-guarded dialectical cycle.

Parallel to :mod:`guarded_cycle` and :mod:`ablated_cycle` but with the
Skeptic replaced by the deterministic :mod:`light_skeptic` rule engine.
Flow:

    Architect (LLM) -> OracleFirewall -> Light Skeptic (deterministic) -> OracleJudge

The Architect still runs through the full LLM strategy; the firewall
still validates its output; only the Skeptic ANTITHESIS step is
replaced by a pure-Python rule evaluation. The resulting
:class:`LightSkepticJudgment` is serialised into a valid
:class:`DialecticalMessage` so the existing OracleJudge contract
is unchanged.

Public API:
    LightGuardedCycleResult    Frozen record with firewall + variant + judgment
    run_light_guarded_cycle    Main entry point
    build_skeptic_message_from_judgment   Helper (exposed for tests)
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, TYPE_CHECKING

from ares.dialectic.agents.architect import ArchitectAgent
from ares.dialectic.agents.context import TurnContext
from ares.dialectic.agents.light_skeptic import evaluate as light_evaluate
from ares.dialectic.agents.oracle import OracleJudge, OracleNarrator
from ares.dialectic.coordinator.firewall import FirewallVerdict, OracleFirewall
from ares.dialectic.coordinator.orchestrator import CycleError, CycleResult
from ares.dialectic.evidence.packet import EvidencePacket
from ares.dialectic.messages.assertions import Assertion
from ares.dialectic.messages.protocol import (
    DialecticalMessage,
    MessageBuilder,
    MessageType,
    Phase,
    Priority,
)
from ares.dialectic.schemas.light_skeptic_judgment import LightSkepticJudgment

if TYPE_CHECKING:
    from ares.dialectic.agents.strategies.protocol import (
        NarrativeGenerator,
        ThreatAnalyzer,
    )


# Session 050 pipeline variant label.
PIPELINE_VARIANT_LABEL: str = "light"


@dataclass(frozen=True)
class LightGuardedCycleResult:
    """Result of a Light-Skeptic-guarded analysis cycle.

    Attributes:
        cycle_result: The underlying CycleResult. ``skeptic_message`` is
            a DialecticalMessage synthesised from the Light Skeptic
            judgment (confidence + narrative).
        firewall_verdict: Firewall validation of the Architect's output.
        light_judgment: The frozen :class:`LightSkepticJudgment` that
            drove the synthesised Skeptic message.
        used_sanitized: Whether sanitized firewall output replaced the
            Architect's tainted interpretation before the verdict.
        pipeline_variant: Always ``"light"``.
    """

    cycle_result: CycleResult
    firewall_verdict: FirewallVerdict
    light_judgment: LightSkepticJudgment
    used_sanitized: bool
    pipeline_variant: str = PIPELINE_VARIANT_LABEL


# =============================================================================
# Synthesising a valid DialecticalMessage from a LightSkepticJudgment
# =============================================================================


def build_skeptic_message_from_judgment(
    judgment: LightSkepticJudgment,
    *,
    cycle_id: str,
    packet_id: str,
    turn_number: int = 2,
) -> DialecticalMessage:
    """Turn a Light Skeptic judgment into a valid ANTITHESIS REBUTTAL.

    Confidence is taken directly from the judgment. The rationale list
    is joined into the narrative so downstream narrators can render the
    explanation without re-running any rules. No assertions are added —
    the OracleJudge uses confidence and cited fact counts, and the
    Light Skeptic has no cited facts by design.

    Args:
        judgment: Frozen :class:`LightSkepticJudgment`.
        cycle_id: Cycle identifier shared with the Architect message.
        packet_id: Evidence packet identifier.
        turn_number: Turn number for the synthetic message (default 2).

    Returns:
        A DialecticalMessage of type REBUTTAL carrying the judgment's
        confidence and a narrative that explains which rules fired.
    """
    builder = MessageBuilder(
        source_agent="ares-skep-light",
        packet_id=packet_id,
        cycle_id=cycle_id,
    )
    builder.set_target("broadcast")
    builder.set_phase(Phase.ANTITHESIS)
    builder.set_turn(turn_number)
    builder.set_type(MessageType.REBUTTAL)
    builder.set_priority(Priority.NORMAL)
    builder.set_confidence(judgment.confidence)

    narrative_lines = [
        "Light Skeptic (deterministic; zero LLM calls).",
        f"Triggered rules: {', '.join(judgment.triggered_rules)}",
        f"benign_score={judgment.benign_score:.2f}, "
        f"malign_score={judgment.malign_score:.2f}",
    ]
    narrative_lines.extend(f"- {line}" for line in judgment.rationale)
    builder.set_narrative("\n".join(narrative_lines))

    return builder.build()


# =============================================================================
# Sanitization (duplicated from guarded_cycle on purpose — new-files-only)
# =============================================================================


def _build_sanitized_message(
    original: DialecticalMessage,
    sanitized_interpretations: tuple[str, ...],
) -> DialecticalMessage:
    """Rebuild an Architect message with sanitized assertion interpretations."""
    sanitized_assertions = [
        Assertion(
            assertion_id=assertion.assertion_id,
            assertion_type=assertion.assertion_type,
            fact_ids=assertion.fact_ids,
            interpretation=sanitized_interpretations[i],
            operator=assertion.operator,
            threshold=assertion.threshold,
        )
        for i, assertion in enumerate(original.assertions)
    ]
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
    return FirewallVerdict(
        passed=True,
        violations=(),
        taint_score=0.0,
        sanitized_output=None,
        timestamp=datetime.utcnow(),
    )


# =============================================================================
# Public API
# =============================================================================


def run_light_guarded_cycle(
    packet: EvidencePacket,
    *,
    threat_analyzer: Optional["ThreatAnalyzer"] = None,
    narrative_generator: Optional["NarrativeGenerator"] = None,
    firewall: Optional[OracleFirewall] = None,
    agent_id_prefix: str = "ares",
    include_narration: bool = True,
) -> LightGuardedCycleResult:
    """Run a Light-Skeptic-guarded single-turn dialectical cycle.

    Steps:
        1. Architect runs THESIS via its injected strategy.
        2. Firewall validates the Architect's output. If the firewall
           flags the message, the sanitized output replaces the
           interpretation text in-place (no hot-swap — this variant is
           about measuring the cheap deterministic Skeptic, not about
           resilience).
        3. The Light Skeptic evaluates the packet + Architect message
           and emits a frozen LightSkepticJudgment.
        4. A synthetic Skeptic REBUTTAL is built from the judgment's
           confidence + narrative and passed to OracleJudge.
        5. OracleNarrator optionally explains the verdict.

    Args:
        packet: Frozen EvidencePacket.
        threat_analyzer: Strategy for the Architect.
        narrative_generator: Strategy for the OracleNarrator.
        firewall: OracleFirewall instance. ``None`` disables validation.
        agent_id_prefix: Prefix for generated agent IDs.
        include_narration: If True, run OracleNarrator.

    Returns:
        A frozen :class:`LightGuardedCycleResult`.

    Raises:
        ValueError: If packet is not frozen.
        CycleError: If any phase fails.
    """
    if not packet.is_frozen:
        raise ValueError("Packet must be frozen before running a cycle")

    started_at = datetime.utcnow()
    cycle_uuid = uuid.uuid4().hex[:8]
    cycle_id = f"cycle-light-{cycle_uuid}"
    prefix = agent_id_prefix

    # --- Architect ---
    architect = ArchitectAgent(
        agent_id=f"{prefix}-arch-{cycle_uuid}",
        threat_analyzer=threat_analyzer,
    )
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
    except Exception as exc:
        raise CycleError(
            f"THESIS phase failed: {exc}",
            phase=Phase.THESIS,
            cycle_id=cycle_id,
            cause=exc,
        ) from exc

    if architect_result.message is None:
        raise CycleError(
            "Architect produced no message",
            phase=Phase.THESIS,
            cycle_id=cycle_id,
        )
    architect_message = architect_result.message

    # --- Firewall ---
    if firewall is not None:
        firewall_verdict = firewall.validate(architect_message, packet)
    else:
        firewall_verdict = _make_clean_firewall_verdict()

    used_sanitized = False
    if not firewall_verdict.passed and firewall_verdict.sanitized_output is not None:
        architect_message = _build_sanitized_message(
            architect_message, firewall_verdict.sanitized_output,
        )
        used_sanitized = True

    # --- Light Skeptic (deterministic) ---
    judgment = light_evaluate(packet, architect_message)
    light_skeptic_msg = build_skeptic_message_from_judgment(
        judgment,
        cycle_id=cycle_id,
        packet_id=packet.packet_id,
    )

    # --- Verdict ---
    try:
        verdict = OracleJudge.compute_verdict(
            architect_message, light_skeptic_msg, packet,
        )
    except Exception as exc:
        raise CycleError(
            f"Verdict computation failed: {exc}",
            phase=Phase.SYNTHESIS,
            cycle_id=cycle_id,
            cause=exc,
        ) from exc

    # --- Optional narration ---
    narrator_message: Optional[DialecticalMessage] = None
    if include_narration:
        narrator = OracleNarrator(
            agent_id=f"{prefix}-oracle-{cycle_uuid}",
            verdict=verdict,
            narrative_generator=narrative_generator,
        )
        try:
            narrator.observe(packet)
            synthesis_context = TurnContext(
                cycle_id=cycle_id,
                packet_id=packet.packet_id,
                snapshot_id=packet.snapshot_id,
                phase=Phase.SYNTHESIS,
                turn_number=3,
                max_turns=3,
                seen_fact_ids=frozenset(verdict.supporting_fact_ids),
            )
            narrator_result = narrator.act(synthesis_context)
        except Exception as exc:
            raise CycleError(
                f"SYNTHESIS phase failed: {exc}",
                phase=Phase.SYNTHESIS,
                cycle_id=cycle_id,
                cause=exc,
            ) from exc
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
        skeptic_message=light_skeptic_msg,
        narrator_message=narrator_message,
        started_at=started_at,
        completed_at=completed_at,
        duration_ms=duration_ms,
    )

    return LightGuardedCycleResult(
        cycle_result=cycle_result,
        firewall_verdict=firewall_verdict,
        light_judgment=judgment,
        used_sanitized=used_sanitized,
    )
