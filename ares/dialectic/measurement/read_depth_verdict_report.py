# ares/dialectic/measurement/read_depth_verdict_report.py
"""Combine the 4 deterministic coordinates (Phase B) + the tier-4 coordinate,
apply the pre-registered rule, render the verdict (Phase C).
"""
from __future__ import annotations

from typing import List, Sequence

from ares.dialectic.measurement.read_depth_frontier_schema import TierCoordinate
from ares.dialectic.measurement.read_depth_tier4_schema import Tier4Coordinate
from ares.dialectic.measurement.read_depth_verdict import (
    FRAMING_ROBUST_MAX_X, HIGH_DETECTION_MIN_J, CornerPoint, classify_frontier,
)

_NON_FALSIFIER_NOTE = (
    "> Named non-falsifier: standalone `v2_canonical` may sit in the *standalone* "
    "good corner, but its `X_lexical=0` is by construction (Phase B evasion "
    "operators are in-vocabulary). The verdict is read on the cumulative view; "
    "the adversarial out-of-vocabulary evasion axis is future work."
)


def build_corner_points(
    deterministic: Sequence[TierCoordinate],
    tier4: Sequence[Tier4Coordinate],
) -> List[CornerPoint]:
    """One CornerPoint per tier, using the CUMULATIVE view only."""
    pts: List[CornerPoint] = []
    for c in deterministic:
        if c.view == "cumulative":
            pts.append(CornerPoint(c.tier_id, c.x_semantic, c.youden_j))
    for c in tier4:
        if c.view == "cumulative":
            pts.append(CornerPoint(c.tier_id, c.x_semantic, c.youden_j))
    return pts


def _rows(det, t4, view: str) -> List[str]:
    out = ["| tier | X_semantic | TPR | FPR | Youden J |",
           "|------|-----------:|----:|----:|---------:|"]
    for c in det:
        if c.view == view:
            out.append(f"| {c.tier_id} | {c.x_semantic:.3f} | {c.tpr:.3f} "
                       f"| {c.fpr:.3f} | {c.youden_j:.3f} |")
    for c in t4:
        if c.view == view:
            out.append(f"| {c.tier_id} | {c.x_semantic:.3f} "
                       f"[{c.x_semantic_ci_low:.2f}, {c.x_semantic_ci_high:.2f}] "
                       f"| {c.tpr:.3f} | {c.fpr:.3f} | {c.youden_j:.3f} |")
    out.append("")
    return out


def render_verdict_report(
    deterministic: Sequence[TierCoordinate],
    tier4: Sequence[Tier4Coordinate],
) -> str:
    points = build_corner_points(deterministic, tier4)
    verdict = classify_frontier(points)
    lines = [
        "# Read-Depth Robustness Frontier — Phase C verdict",
        "",
        f"Bands: framing-robust `X_semantic <= {FRAMING_ROBUST_MAX_X:.2f}`, "
        f"high detection `cumulative Youden J >= {HIGH_DETECTION_MIN_J:.2f}`.",
        "",
        f"## Verdict: {verdict.verdict}",
        "",
        (f"Good corner occupied by: {', '.join(verdict.occupants)}."
         if verdict.occupants else "Good corner is empty (trilemma holds)."),
        "",
        "## View: cumulative (verdict-bearing)",
        "",
    ]
    lines += _rows(deterministic, tier4, "cumulative")
    lines += ["## View: standalone (contrast)", ""]
    lines += _rows(deterministic, tier4, "standalone")
    lines += [_NON_FALSIFIER_NOTE, ""]
    return "\n".join(lines)
