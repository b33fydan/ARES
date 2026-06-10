# ares/dialectic/measurement/read_depth_tier4_metrics.py
"""Noise-controlled metrics for the tier-4 LLM anchor (Phase C).

The LLM is the only stochastic tier, so a framing "flip" must clear sampling
noise. We reuse architect_framing_metrics.permutation_pvalue (two-sided test on
the difference of malign-rates) as the gate. A flip counts iff the majority
verdict changes AND the rate change is significant.
"""
from __future__ import annotations

import random
from typing import List, Sequence, Tuple

from ares.dialectic.measurement.architect_framing_metrics import (
    permutation_pvalue,
)

_P_THRESHOLD = 0.05


def malign_rate(verdicts: Sequence[bool]) -> float:
    return sum(1 for v in verdicts if v) / len(verdicts) if verdicts else 0.0


def majority_malign(verdicts: Sequence[bool]) -> bool:
    """Tie (exactly 0.5) resolves to malign — conservative for detection."""
    return malign_rate(verdicts) >= 0.5


def flip_decision(
    baseline: Sequence[bool], perturbed: Sequence[bool], *, seed: int = 0
) -> Tuple[bool, float]:
    """(flipped, p). Flip = majority changed AND rate-shift clears noise."""
    p = permutation_pvalue([1.0 if v else 0.0 for v in perturbed],
                           [1.0 if v else 0.0 for v in baseline], seed=seed)
    majority_changed = majority_malign(baseline) != majority_malign(perturbed)
    return (majority_changed and p < _P_THRESHOLD), p


def bootstrap_flip_rate_ci(
    flip_indicators: Sequence[bool], *, n_boot: int = 2000, seed: int = 0,
    alpha: float = 0.05,
) -> Tuple[float, float]:
    """Percentile bootstrap CI for the mean of per-cell flip indicators."""
    if not flip_indicators:
        return (0.0, 0.0)
    rng = random.Random(seed)
    xs: List[float] = [1.0 if f else 0.0 for f in flip_indicators]
    means: List[float] = []
    for _ in range(n_boot):
        sample = [rng.choice(xs) for _ in xs]
        means.append(sum(sample) / len(sample))
    means.sort()
    lo_i = int((alpha / 2) * n_boot)
    hi_i = min(n_boot - 1, int((1 - alpha / 2) * n_boot))
    return (means[lo_i], means[hi_i])
