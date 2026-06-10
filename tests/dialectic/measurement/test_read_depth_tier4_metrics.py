# tests/dialectic/measurement/test_read_depth_tier4_metrics.py
from ares.dialectic.measurement.read_depth_tier4_metrics import (
    malign_rate, majority_malign, flip_decision, bootstrap_flip_rate_ci,
)


def test_malign_rate_and_majority():
    assert malign_rate([True, True, False, False, True]) == 0.6
    assert majority_malign([True, True, False]) is True
    assert majority_malign([True, False, False]) is False
    assert majority_malign([True, False]) is True   # tie -> malign (>= 0.5)


def test_flip_decision_requires_majority_change_and_significance():
    # baseline all-benign, perturbed all-malign: clear flip, p tiny -> flipped
    flipped, p = flip_decision([False] * 20, [True] * 20, seed=0)
    assert flipped is True
    assert p < 0.05


def test_flip_decision_no_majority_change_is_not_flip():
    # both majorities malign even if rates differ a little
    flipped, _ = flip_decision([True] * 18 + [False] * 2,
                               [True] * 14 + [False] * 6, seed=0)
    assert flipped is False


def test_flip_decision_majority_change_but_noise_is_not_flip():
    # 11/20 vs 9/20: majority flips but within sampling noise -> p large -> not flipped
    flipped, p = flip_decision([True] * 11 + [False] * 9,
                               [True] * 9 + [False] * 11, seed=0)
    assert p >= 0.05
    assert flipped is False


def test_bootstrap_flip_rate_ci_bounds():
    lo, hi = bootstrap_flip_rate_ci([True, True, False, False], seed=0)
    assert 0.0 <= lo <= hi <= 1.0
