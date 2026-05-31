"""Positive control: drop a fact the baseline Architect actually CITES — a
structured change guaranteed to move the Architect's cited-fact set. Proves the
measurement pipeline can register a real change (closes the 'can the alarm even
ring?' gap).

The S077 pilot showed that dropping the highest kill-chain-STAGE fact (per the
Light Skeptic's stage map) is not sufficient: on INJ-009 that fact was never
cited by the Architect, so its removal changed nothing. The control must target
a fact the *Architect* relies on, chosen from the observed baseline citations.
"""
from __future__ import annotations

from collections import Counter
from typing import Sequence

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


def choose_control_drop_fact(
    packet, baseline_cited_sets: Sequence[frozenset[str]]
) -> str | None:
    """Pick the fact to drop for the positive control: the packet fact most
    frequently cited across the baseline resamples, tie-broken by highest stage
    then fact_id. Returns None if the baseline cited no packet fact (caller
    falls back to highest_stage_fact_id)."""
    packet_ids = {f.fact_id for f in packet.get_all_facts()}
    stage = {f.fact_id: _STAGE_MAP.get(f.field, _DEFAULT_STAGE)
             for f in packet.get_all_facts()}
    freq: Counter[str] = Counter()
    for cited in baseline_cited_sets:
        for fid in cited:
            if fid in packet_ids:
                freq[fid] += 1
    if not freq:
        return None
    return max(freq, key=lambda fid: (freq[fid], stage[fid], fid))


def build_positive_control_scenario(
    baseline: BenchmarkScenario, drop_fact_id: str | None = None
) -> BenchmarkScenario:
    facts = baseline.packet.get_all_facts()
    if len(facts) < 2:
        raise ValueError("positive control requires a packet with at least 2 facts")
    fact_ids = {f.fact_id for f in facts}
    if drop_fact_id is None:
        drop = highest_stage_fact_id(baseline.packet)
    elif drop_fact_id in fact_ids:
        drop = drop_fact_id
    else:
        raise ValueError(f"drop_fact_id {drop_fact_id!r} not present in packet")
    ctrl = EvidencePacket(
        packet_id=f"{baseline.packet.packet_id}-ctrl",
        time_window=baseline.packet.time_window,
    )
    for f in facts:
        if f.fact_id != drop:
            ctrl.add_fact(f)
    ctrl.freeze()
    return BenchmarkScenario(metadata=baseline.metadata, packet=ctrl)
