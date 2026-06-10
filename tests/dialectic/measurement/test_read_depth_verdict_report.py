# tests/dialectic/measurement/test_read_depth_verdict_report.py
from ares.dialectic.measurement.read_depth_frontier_schema import TierCoordinate
from ares.dialectic.measurement.read_depth_tier4_schema import Tier4Coordinate
from ares.dialectic.measurement.read_depth_verdict_report import (
    build_corner_points, render_verdict_report,
)


def _det(tier, view, j):
    return TierCoordinate(tier_id=tier, view=view, x_semantic=0.0, x_lexical=0.0,
                          tpr=1.0, fpr=1.0 - j, youden_j=j, n_malign=4, n_benign=4)


def _t4(view, x, j):
    return Tier4Coordinate(tier_id="llm_semantic", view=view, x_semantic=x,
                           x_semantic_ci_low=x, x_semantic_ci_high=x, tpr=1.0,
                           fpr=1.0 - j, youden_j=j, n_malign=4, n_benign=4,
                           k_resamples=20, model="m", provider="anthropic")


def test_build_corner_points_uses_cumulative_only():
    det = [_det("v2_canonical", "cumulative", 0.25), _det("v2_canonical", "standalone", 0.75)]
    pts = build_corner_points(det, [_t4("cumulative", 0.4, 0.75), _t4("standalone", 0.4, 0.75)])
    assert {p.tier_id for p in pts} == {"v2_canonical", "llm_semantic"}
    assert all(p.cumulative_youden_j in (0.25, 0.75) for p in pts)
    # the v2_canonical point used is the CUMULATIVE one (0.25), not standalone (0.75)
    v2 = next(p for p in pts if p.tier_id == "v2_canonical")
    assert v2.cumulative_youden_j == 0.25


def test_supported_render_contains_verdict_and_both_views():
    det = [_det("v2_structured", "cumulative", 0.25), _det("v2_structured", "standalone", 0.25)]
    t4 = [_t4("cumulative", 0.4, 0.75), _t4("standalone", 0.4, 0.75)]
    md = render_verdict_report(det, t4)
    assert "SUPPORTED" in md
    assert "standalone" in md and "cumulative" in md


def test_falsified_when_deterministic_tier_in_cumulative_corner():
    det = [_det("v2_canonical", "cumulative", 0.75), _det("v2_canonical", "standalone", 0.75)]
    md = render_verdict_report(det, [_t4("cumulative", 0.4, 0.25), _t4("standalone", 0.4, 0.25)])
    assert "FALSIFIED" in md
