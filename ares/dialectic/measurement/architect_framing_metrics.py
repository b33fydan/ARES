"""Pure metric + stats functions for the Architect-path framing measurement.

Stdlib only. No LLM. No I/O. Fully deterministic given inputs (+ seed for bootstrap/perm).
"""
from __future__ import annotations

import random
from statistics import median
from typing import Sequence

from ares.dialectic.measurement.architect_framing_schema import (
    OperatorFramingResult, VERDICT_REAL, VERDICT_NOISE, VERDICT_INCONCLUSIVE,
)

_P_THRESHOLD = 0.05


# ---------------------------------------------------------------------------
# Distances
# ---------------------------------------------------------------------------


def jaccard_distance(a: frozenset[str], b: frozenset[str]) -> float:
    union = a | b
    if not union:
        return 0.0
    return 1.0 - len(a & b) / len(union)


def within_distances(sets: Sequence[frozenset[str]]) -> list[float]:
    """All pairwise Jaccard distances among the resample sets (the noise floor)."""
    n = len(sets)
    return [
        jaccard_distance(sets[i], sets[j])
        for i in range(n) for j in range(i + 1, n)
    ]


def cross_distances(
    baseline_sets: Sequence[frozenset[str]],
    mutated_sets: Sequence[frozenset[str]],
) -> list[float]:
    """All baseline x mutated Jaccard distances."""
    return [jaccard_distance(b, m) for b in baseline_sets for m in mutated_sets]


# ---------------------------------------------------------------------------
# Statistics (dependency-free)
# ---------------------------------------------------------------------------


def _mean(xs: Sequence[float]) -> float:
    return sum(xs) / len(xs)


def permutation_pvalue(
    cross: Sequence[float], within: Sequence[float], *, n_perm: int = 2000, seed: int = 0
) -> float:
    """Two-sided permutation test on the difference of MEANS (cross - within).

    Mean, not median: Jaccard distances cluster on {0, 1}, and the median gap is
    degenerate under permutation (random shuffles hit the max gap often), so a
    median statistic fails to register genuine separation. The mean shift is the
    sensitive, correct statistic for "are cross distances systematically larger".
    """
    if not cross or not within:
        return 1.0
    observed = abs(_mean(cross) - _mean(within))
    pool = list(cross) + list(within)
    n_cross = len(cross)
    rng = random.Random(seed)
    hits = 0
    for _ in range(n_perm):
        rng.shuffle(pool)
        diff = abs(_mean(pool[:n_cross]) - _mean(pool[n_cross:]))
        if diff >= observed - 1e-12:
            hits += 1
    return hits / n_perm


def bootstrap_ci_median_diff(
    cross: Sequence[float], within: Sequence[float],
    *, n_boot: int = 2000, seed: int = 0, alpha: float = 0.05,
) -> tuple[float, float]:
    """Percentile bootstrap CI for median(cross) - median(within)."""
    if not cross or not within:
        return (0.0, 0.0)
    rng = random.Random(seed)
    cross = list(cross)
    within = list(within)
    diffs = []
    for _ in range(n_boot):
        bc = [rng.choice(cross) for _ in cross]
        bw = [rng.choice(within) for _ in within]
        diffs.append(median(bc) - median(bw))
    diffs.sort()
    lo_i = int((alpha / 2) * n_boot)
    hi_i = min(n_boot - 1, int((1 - alpha / 2) * n_boot))
    return (diffs[lo_i], diffs[hi_i])


def classify_operator(
    cross: Sequence[float], within: Sequence[float],
    *, n_perm: int = 2000, n_boot: int = 2000, seed: int = 0,
    operator_name: str = "",
) -> OperatorFramingResult:
    """Decide whether framing exceeds the noise floor for one operator."""
    cm = median(cross) if cross else 0.0
    wm = median(within) if within else 0.0
    effect = cm - wm
    p = permutation_pvalue(cross, within, n_perm=n_perm, seed=seed)
    lo, hi = bootstrap_ci_median_diff(cross, within, n_boot=n_boot, seed=seed)
    if p < _P_THRESHOLD and effect > 0.0 and lo > 0.0:
        verdict = VERDICT_REAL
    elif p >= _P_THRESHOLD and hi <= 0.0:
        verdict = VERDICT_NOISE
    elif p >= _P_THRESHOLD and effect <= 0.0:
        verdict = VERDICT_NOISE
    else:
        verdict = VERDICT_INCONCLUSIVE
    return OperatorFramingResult(
        operator_name=operator_name, n_cross=len(cross),
        cross_median=cm, within_median=wm, effect_size=effect,
        p_value=p, ci_low=lo, ci_high=hi, verdict=verdict,
    )
