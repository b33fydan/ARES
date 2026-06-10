# tests/dialectic/measurement/test_read_depth_verdict.py
import pytest
from ares.dialectic.measurement.read_depth_verdict import (
    FRAMING_ROBUST_MAX_X, HIGH_DETECTION_MIN_J,
    CornerPoint, classify_frontier, VERDICT_SUPPORTED, VERDICT_FALSIFIED,
)


def _p(tier, x, j):
    return CornerPoint(tier_id=tier, x_semantic=x, cumulative_youden_j=j)


def test_bands_are_frozen_constants():
    assert FRAMING_ROBUST_MAX_X == 0.10
    assert HIGH_DETECTION_MIN_J == 0.50


def test_empty_corner_is_supported():
    # deterministic tiers: robust but low detection; tier-4: high detection but susceptible
    pts = [
        _p("v1_field", 0.0, 0.0),
        _p("v2_structured", 0.0, 0.25),
        _p("v2_lexical", 0.0, 0.25),
        _p("v2_canonical", 0.0, 0.25),
        _p("llm_semantic", 0.40, 0.75),
    ]
    result = classify_frontier(pts)
    assert result.verdict == VERDICT_SUPPORTED
    assert result.occupants == ()


def test_deterministic_tier_in_corner_falsifies():
    pts = [_p("v2_canonical", 0.0, 0.75), _p("llm_semantic", 0.40, 0.75)]
    result = classify_frontier(pts)
    assert result.verdict == VERDICT_FALSIFIED
    assert "v2_canonical" in result.occupants


def test_tier4_in_corner_falsifies():
    pts = [_p("v2_structured", 0.0, 0.25), _p("llm_semantic", 0.05, 0.75)]
    result = classify_frontier(pts)
    assert result.verdict == VERDICT_FALSIFIED
    assert "llm_semantic" in result.occupants


def test_boundary_is_inclusive():
    # exactly on both bands counts as IN the corner
    pts = [_p("edge", 0.10, 0.50)]
    assert classify_frontier(pts).verdict == VERDICT_FALSIFIED


def test_just_outside_each_band_is_empty():
    pts = [_p("a", 0.11, 0.75), _p("b", 0.0, 0.49)]
    assert classify_frontier(pts).verdict == VERDICT_SUPPORTED
