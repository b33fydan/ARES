"""DialecticalOrchestrator - Single entry point for dialectical cycles.

The Orchestrator is a FACADE that composes existing components to automate
the complete THESIS -> ANTITHESIS -> SYNTHESIS cycle. It does NOT replace
the existing Coordinator (bouncer) or any existing validation.

Handles:
- Agent instantiation and lifecycle (fresh agents per cycle)
- Turn context creation (with proper packet_id, snapshot_id, cycle_id)
- Phase transitions (THESIS -> ANTITHESIS -> SYNTHESIS)
- Message passing between agents
- Verdict computation via OracleJudge
- Optional narration via OracleNarrator
- Cycle timing and unique identification
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
from ares.dialectic.evidence.packet import EvidencePacket
from ares.dialectic.messages.protocol import DialecticalMessage, Phase


class CycleError(Exception):
    """Raised when a dialectical cycle fails.

    Use 'raise CycleError(...) from original_exception' to preserve
    the exception chain for debugging.

    Attributes:
        phase: The phase where the failure occurred.
        cycle_id: The cycle that failed.
        cause: The original exception, if any.
    """

    def __init__(
        self,
        message: str,
        phase: Phase,
        cycle_id: str,
        cause: Optional[Exception] = None,
    ) -> None:
        super().__init__(message)
        self.phase = phase
        self.cycle_id = cycle_id
        self.cause = cause


@dataclass(frozen=True)
class CycleResult:
    """Complete output of a dialectical cycle.

    Immutable record containing the verdict and all messages produced
    during the THESIS -> ANTITHESIS -> SYNTHESIS flow.

    Attributes:
        cycle_id: Unique identifier for this cycle.
        packet_id: ID of the evidence packet analyzed.
        verdict: The OracleJudge's deterministic verdict.
        architect_message: The THESIS message from the Architect.
        skeptic_message: The ANTITHESIS message from the Skeptic.
        narrator_message: The SYNTHESIS explanation (None if narration skipped).
        started_at: When the cycle began.
        completed_at: When the cycle finished.
        duration_ms: Total elapsed time in milliseconds.
    """

    cycle_id: str
    packet_id: str
    verdict: Verdict
    architect_message: DialecticalMessage
    skeptic_message: DialecticalMessage
    narrator_message: Optional[DialecticalMessage]
    started_at: datetime
    completed_at: datetime
    duration_ms: int


class DialecticalOrchestrator:
    """Manages the complete THESIS -> ANTITHESIS -> SYNTHESIS cycle.

    Single entry point for dialectical reasoning. Handles:
    - Agent instantiation and lifecycle
    - Turn context creation (with proper packet_id, snapshot_id, cycle_id)
    - Phase transitions
    - Message passing between agents
    - Verdict computation
    - Cycle timing and identification

    This is a FACADE over existing components. It does NOT replace the
    Coordinator (bouncer) or any existing validation.
    """

    def __init__(
        self,
        *,
        agent_id_prefix: str = "ares",
        include_narration: bool = True,
    ) -> None:
        """Initialize the orchestrator.

        Args:
            agent_id_prefix: Prefix for generated agent IDs.
            include_narration: If True, run OracleNarrator for human explanation.
        """
        self._agent_id_prefix = agent_id_prefix
        self._include_narration = include_narration

    @property
    def agent_id_prefix(self) -> str:
        """Prefix used for agent IDs."""
        return self._agent_id_prefix

    @property
    def include_narration(self) -> bool:
        """Whether narration is enabled."""
        return self._include_narration

    def run_cycle(self, packet: EvidencePacket) -> CycleResult:
        """Execute a complete dialectical cycle on the given evidence.

        Args:
            packet: Frozen EvidencePacket containing facts to analyze.

        Returns:
            CycleResult with verdict and all messages.

        Raises:
            ValueError: If packet is not frozen.
            CycleError: If any phase fails.
        """
        # --- Pre-flight: packet must be frozen ---
        if not packet.is_frozen:
            raise ValueError("Packet must be frozen before running a cycle")

        started_at = datetime.utcnow()

        # --- Generate cycle and agent IDs ---
        cycle_uuid = uuid.uuid4().hex[:8]
        cycle_id = f"cycle-{cycle_uuid}"
        prefix = self._agent_id_prefix

        architect = ArchitectAgent(agent_id=f"{prefix}-arch-{cycle_uuid}")
        skeptic = SkepticAgent(agent_id=f"{prefix}-skep-{cycle_uuid}")

        # --- THESIS phase ---
        architect_message = self._run_thesis(
            architect, packet, cycle_id, cycle_uuid,
        )

        # --- ANTITHESIS phase ---
        skeptic_message = self._run_antithesis(
            skeptic, packet, architect_message, cycle_id, cycle_uuid,
        )

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
        if self._include_narration:
            narrator_message = self._run_synthesis(
                packet, verdict, cycle_id, cycle_uuid,
            )

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

    # ------------------------------------------------------------------
    # Private phase runners
    # ------------------------------------------------------------------

    def _make_context(
        self,
        packet: EvidencePacket,
        cycle_id: str,
        phase: Phase,
        turn_number: int,
        seen_fact_ids: frozenset[str] = frozenset(),
    ) -> TurnContext:
        """Build a fully-populated TurnContext."""
        return TurnContext(
            cycle_id=cycle_id,
            packet_id=packet.packet_id,
            snapshot_id=packet.snapshot_id,
            phase=phase,
            turn_number=turn_number,
            max_turns=3,
            seen_fact_ids=seen_fact_ids,
        )

    def _run_thesis(
        self,
        architect: ArchitectAgent,
        packet: EvidencePacket,
        cycle_id: str,
        cycle_uuid: str,
    ) -> DialecticalMessage:
        """Execute the THESIS phase."""
        try:
            architect.observe(packet)
            context = self._make_context(packet, cycle_id, Phase.THESIS, 1)
            result = architect.act(context)
        except Exception as e:
            raise CycleError(
                f"THESIS phase failed: {e}",
                phase=Phase.THESIS,
                cycle_id=cycle_id,
                cause=e,
            ) from e

        if result.message is None:
            raise CycleError(
                "Architect produced no message",
                phase=Phase.THESIS,
                cycle_id=cycle_id,
            )

        return result.message

    def _run_antithesis(
        self,
        skeptic: SkepticAgent,
        packet: EvidencePacket,
        architect_message: DialecticalMessage,
        cycle_id: str,
        cycle_uuid: str,
    ) -> DialecticalMessage:
        """Execute the ANTITHESIS phase."""
        try:
            skeptic.observe(packet)
            skeptic.receive(architect_message)
            arch_fact_ids = frozenset(architect_message.get_all_fact_ids())
            context = self._make_context(
                packet, cycle_id, Phase.ANTITHESIS, 2,
                seen_fact_ids=arch_fact_ids,
            )
            result = skeptic.act(context)
        except Exception as e:
            raise CycleError(
                f"ANTITHESIS phase failed: {e}",
                phase=Phase.ANTITHESIS,
                cycle_id=cycle_id,
                cause=e,
            ) from e

        if result.message is None:
            raise CycleError(
                "Skeptic produced no message",
                phase=Phase.ANTITHESIS,
                cycle_id=cycle_id,
            )

        return result.message

    def _run_synthesis(
        self,
        packet: EvidencePacket,
        verdict: Verdict,
        cycle_id: str,
        cycle_uuid: str,
    ) -> DialecticalMessage:
        """Execute the SYNTHESIS narration phase."""
        prefix = self._agent_id_prefix
        narrator = OracleNarrator(
            agent_id=f"{prefix}-oracle-{cycle_uuid}",
            verdict=verdict,
        )
        try:
            narrator.observe(packet)
            all_fact_ids = frozenset(verdict.supporting_fact_ids)
            context = self._make_context(
                packet, cycle_id, Phase.SYNTHESIS, 3,
                seen_fact_ids=all_fact_ids,
            )
            result = narrator.act(context)
        except Exception as e:
            raise CycleError(
                f"SYNTHESIS phase failed: {e}",
                phase=Phase.SYNTHESIS,
                cycle_id=cycle_id,
                cause=e,
            ) from e

        if result.message is None:
            raise CycleError(
                "OracleNarrator produced no message",
                phase=Phase.SYNTHESIS,
                cycle_id=cycle_id,
            )

        return result.message
