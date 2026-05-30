"""Pure metric + stats functions for the Architect-path framing measurement.

Stdlib only. No LLM. No I/O. Fully deterministic given inputs (+ seed for bootstrap/perm).
"""
from __future__ import annotations

import random
from statistics import median
from typing import Sequence


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
