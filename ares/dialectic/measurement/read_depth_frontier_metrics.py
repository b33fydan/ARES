# ares/dialectic/measurement/read_depth_frontier_metrics.py
"""Exact frontier metrics for the deterministic tiers (Phase B).

The deterministic tiers need no inferential statistics — X is an exact
flip-rate and Y an exact TPR-FPR. (The permutation/bootstrap machinery in
``architect_framing_metrics`` is reserved for the Phase-C LLM anchor.)
"""
from __future__ import annotations

from typing import Sequence, Tuple

from ares.dialectic.schemas.light_skeptic_judgment import LightSkepticJudgment

DEFAULT_OPERATING_POINT = 0.0


def is_malign_verdict(
    judgment: LightSkepticJudgment,
    operating_point: float = DEFAULT_OPERATING_POINT,
) -> bool:
    """A tier calls a packet malign iff its malign_score exceeds the point."""
    return judgment.malign_score > operating_point


def cumulative_verdict(prefix_verdicts: Sequence[bool]) -> bool:
    """Cumulative (depth-N) verdict = OR of all standalone verdicts up to N."""
    return any(prefix_verdicts)


def flip_rate(n_mutations: int, n_flips: int) -> float:
    """Fraction of *actually-mutating* perturbations that changed the verdict.

    Returns 0.0 when nothing mutated (no-op perturbations are excluded from
    the denominator by the caller, so a 0 denominator means "no probe landed").
    """
    if n_mutations <= 0:
        return 0.0
    return n_flips / n_mutations


def tpr_fpr(
    malign_verdicts: Sequence[bool],
    benign_verdicts: Sequence[bool],
) -> Tuple[float, float]:
    """(TPR, FPR) at the current operating point."""
    tpr = (
        sum(1 for v in malign_verdicts if v) / len(malign_verdicts)
        if malign_verdicts
        else 0.0
    )
    fpr = (
        sum(1 for v in benign_verdicts if v) / len(benign_verdicts)
        if benign_verdicts
        else 0.0
    )
    return tpr, fpr


def youden_j(tpr: float, fpr: float) -> float:
    """Youden's J = detection power = TPR - FPR."""
    return tpr - fpr
