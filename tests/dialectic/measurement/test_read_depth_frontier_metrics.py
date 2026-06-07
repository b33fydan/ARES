# tests/dialectic/measurement/test_read_depth_frontier_metrics.py
"""Tests for the exact read-depth frontier metrics."""
from __future__ import annotations

from ares.dialectic.measurement.read_depth_frontier_metrics import (
    cumulative_verdict,
    flip_rate,
    is_malign_verdict,
    tpr_fpr,
    youden_j,
)
from ares.dialectic.schemas.light_skeptic_judgment import LightSkepticJudgment


def _judg(malign_score):
    # confidence kept in-range; only malign_score matters to the binarizer.
    return LightSkepticJudgment(
        confidence=max(0.0, 0.5 - malign_score),
        rationale=("r",), triggered_rules=("t",),
        benign_score=0.0, malign_score=malign_score,
    )


def test_is_malign_verdict_operating_point():
    assert is_malign_verdict(_judg(0.4)) is True
    assert is_malign_verdict(_judg(0.0)) is False
    # operating point is exclusive: malign_score must exceed it.
    assert is_malign_verdict(_judg(0.3), operating_point=0.3) is False
    assert is_malign_verdict(_judg(0.4), operating_point=0.3) is True


def test_cumulative_verdict_is_or():
    assert cumulative_verdict([False, False]) is False
    assert cumulative_verdict([False, True]) is True
    assert cumulative_verdict([]) is False


def test_flip_rate_excludes_zero_denominator():
    assert flip_rate(n_mutations=0, n_flips=0) == 0.0
    assert flip_rate(n_mutations=5, n_flips=2) == 0.4


def test_tpr_fpr_and_youden():
    tpr, fpr = tpr_fpr([True, True, True, False], [True, False, False, False])
    assert tpr == 0.75
    assert fpr == 0.25
    assert youden_j(tpr, fpr) == 0.5


def test_tpr_fpr_empty_sets():
    tpr, fpr = tpr_fpr([], [])
    assert tpr == 0.0
    assert fpr == 0.0
