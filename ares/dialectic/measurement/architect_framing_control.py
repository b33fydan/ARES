"""Positive control: drop the highest kill-chain-stage fact from a scenario's
packet — a structured change that SHOULD move the Architect's cited-fact set.
Used to prove the measurement pipeline can register a real change (closes the
'can the alarm even ring?' gap)."""
from __future__ import annotations

from ares.dialectic.agents.light_skeptic import _STAGE_MAP, _DEFAULT_STAGE
from ares.dialectic.evidence.packet import EvidencePacket
from ares.dialectic.scripts.scenario_corpus import BenchmarkScenario


def highest_stage_fact_id(packet) -> str:
    """fact_id of the highest-stage fact; deterministic tie-break by fact_id."""
    facts = packet.get_all_facts()
    if not facts:
        raise ValueError("packet has no facts")
    return max(
        facts,
        key=lambda f: (_STAGE_MAP.get(f.field, _DEFAULT_STAGE), f.fact_id),
    ).fact_id


def build_positive_control_scenario(baseline: BenchmarkScenario) -> BenchmarkScenario:
    facts = baseline.packet.get_all_facts()
    if len(facts) < 2:
        raise ValueError("positive control requires a packet with at least 2 facts")
    drop = highest_stage_fact_id(baseline.packet)
    ctrl = EvidencePacket(
        packet_id=f"{baseline.packet.packet_id}-ctrl",
        time_window=baseline.packet.time_window,
    )
    for f in facts:
        if f.fact_id != drop:
            ctrl.add_fact(f)
    ctrl.freeze()
    return BenchmarkScenario(metadata=baseline.metadata, packet=ctrl)
