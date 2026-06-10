# ares/dialectic/measurement/read_depth_verdict.py
"""The pre-registered read-depth frontier decision rule (Phase C).

Single source of truth for the bands. The pre-registration doc cites these exact
constants; tests/paper_4/test_prereg_bands_match_code.py guards against drift.
Pure, deterministic, offline.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence, Tuple

FRAMING_ROBUST_MAX_X = 0.10   # X_semantic <= this  => framing-robust
HIGH_DETECTION_MIN_J = 0.50   # cumulative Youden J >= this  => high detection

VERDICT_SUPPORTED = "SUPPORTED"
VERDICT_FALSIFIED = "FALSIFIED"


@dataclass(frozen=True)
class CornerPoint:
    """One tier's coordinate on the verdict plane (cumulative view)."""

    tier_id: str
    x_semantic: float
    cumulative_youden_j: float

    def in_good_corner(self) -> bool:
        return (self.x_semantic <= FRAMING_ROBUST_MAX_X
                and self.cumulative_youden_j >= HIGH_DETECTION_MIN_J)


@dataclass(frozen=True)
class FrontierVerdict:
    verdict: str
    occupants: Tuple[str, ...]


def classify_frontier(points: Sequence[CornerPoint]) -> FrontierVerdict:
    """Trilemma SUPPORTED iff the good corner is empty; else FALSIFIED."""
    occupants = tuple(p.tier_id for p in points if p.in_good_corner())
    verdict = VERDICT_FALSIFIED if occupants else VERDICT_SUPPORTED
    return FrontierVerdict(verdict=verdict, occupants=occupants)
