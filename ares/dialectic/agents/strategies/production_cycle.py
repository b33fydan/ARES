"""Production single-turn cycle: the leak-closed live path.

run_production_cycle is a thin peer of run_cycle_with_strategies with the
Oracle supporting_fact_ids sanitizer turned ON by default. It is the one
blessed entrypoint that emits framing-invariant Verdict.supporting_fact_ids.
The measurement/Paper-3 harness keeps the default (leaky) path and is
unaffected, because it calls the underlying cycles directly without the flag.
"""
from __future__ import annotations

from typing import Optional, TYPE_CHECKING

from ares.dialectic.agents.strategies.live_cycle import run_cycle_with_strategies

if TYPE_CHECKING:
    from ares.dialectic.coordinator.orchestrator import CycleResult
    from ares.dialectic.evidence.packet import EvidencePacket
    from ares.dialectic.agents.strategies.protocol import (
        ExplanationFinder,
        NarrativeGenerator,
        ThreatAnalyzer,
    )


def run_production_cycle(
    packet: "EvidencePacket",
    *,
    threat_analyzer: "Optional[ThreatAnalyzer]" = None,
    explanation_finder: "Optional[ExplanationFinder]" = None,
    narrative_generator: "Optional[NarrativeGenerator]" = None,
    agent_id_prefix: str = "ares",
    include_narration: bool = True,
) -> "CycleResult":
    """Single-turn production cycle with sanitized supporting_fact_ids.

    Thin wrapper over run_cycle_with_strategies with
    sanitize_supporting_facts=True. Argument semantics are identical to that
    function; this entrypoint exists so production callers get the leak-closed
    behavior by default while the measurement path stays on the leaky default.
    """
    return run_cycle_with_strategies(
        packet,
        threat_analyzer=threat_analyzer,
        explanation_finder=explanation_finder,
        narrative_generator=narrative_generator,
        agent_id_prefix=agent_id_prefix,
        include_narration=include_narration,
        sanitize_supporting_facts=True,
    )
