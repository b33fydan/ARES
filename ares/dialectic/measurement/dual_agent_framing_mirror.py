"""Pure mirror-pattern logic for the dual-agent framing measurement (Session 084).

Stdlib only. No LLM, no I/O. Quantifies the S083 dual-agent mirror: the Architect
collapses its cited-fact set toward the contested fact while the Skeptic expands
toward it (mirror_class == "opposed").
"""
from __future__ import annotations

from collections import Counter
from typing import Sequence

from ares.dialectic.measurement.architect_framing_metrics import jaccard_distance
from ares.dialectic.measurement.dual_agent_framing_schema import MirrorRecord

DIR_NONE = "none"
DIR_COLLAPSE = "collapse"
DIR_EXPAND = "expand"
DIR_SWAP = "swap"

MIRROR_NONE = "none"
MIRROR_SINGLE = "single"
MIRROR_ALIGNED = "aligned"
MIRROR_OPPOSED = "opposed"
MIRROR_MIXED = "mixed"


def direction(baseline: frozenset[str], framed: frozenset[str]) -> str:
    drop = baseline - framed
    add = framed - baseline
    if not drop and not add:
        return DIR_NONE
    if drop and not add:
        return DIR_COLLAPSE
    if add and not drop:
        return DIR_EXPAND
    return DIR_SWAP


def modal_set(sets: Sequence[frozenset[str]]) -> frozenset[str]:
    if not sets:
        return frozenset()
    counts = Counter(sets)
    top = max(counts.values())
    tied = [s for s, c in counts.items() if c == top]
    return min(tied, key=lambda s: tuple(sorted(s)))


def classify_mirror(arch_dir: str, skep_dir: str) -> str:
    if arch_dir == DIR_NONE and skep_dir == DIR_NONE:
        return MIRROR_NONE
    if arch_dir == DIR_NONE or skep_dir == DIR_NONE:
        return MIRROR_SINGLE
    if arch_dir == skep_dir:
        return MIRROR_ALIGNED
    if {arch_dir, skep_dir} == {DIR_COLLAPSE, DIR_EXPAND}:
        return MIRROR_OPPOSED
    return MIRROR_MIXED


def build_mirror_record(
    *,
    scenario_id: str,
    operator_name: str,
    arch_base_sets: Sequence[frozenset[str]],
    arch_framed_sets: Sequence[frozenset[str]],
    skep_base_sets: Sequence[frozenset[str]],
    skep_framed_sets: Sequence[frozenset[str]],
) -> MirrorRecord:
    a_b, a_f = modal_set(arch_base_sets), modal_set(arch_framed_sets)
    s_b, s_f = modal_set(skep_base_sets), modal_set(skep_framed_sets)
    a_dir, s_dir = direction(a_b, a_f), direction(s_b, s_f)
    return MirrorRecord(
        scenario_id=scenario_id,
        operator_name=operator_name,
        architect_jaccard=jaccard_distance(a_b, a_f),
        architect_direction=a_dir,
        skeptic_jaccard=jaccard_distance(s_b, s_f),
        skeptic_direction=s_dir,
        mirror_class=classify_mirror(a_dir, s_dir),
    )
