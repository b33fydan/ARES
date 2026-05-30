from ares.dialectic.measurement.architect_framing_metrics import (
    jaccard_distance, within_distances, cross_distances,
    permutation_pvalue, bootstrap_ci_median_diff, classify_operator,
)
from ares.dialectic.measurement.architect_framing_schema import (
    VERDICT_REAL, VERDICT_NOISE, VERDICT_INCONCLUSIVE,
)


def test_jaccard_identical_is_zero():
    assert jaccard_distance(frozenset({"a", "b"}), frozenset({"a", "b"})) == 0.0


def test_jaccard_disjoint_is_one():
    assert jaccard_distance(frozenset({"a"}), frozenset({"b"})) == 1.0


def test_jaccard_both_empty_is_zero():
    assert jaccard_distance(frozenset(), frozenset()) == 0.0


def test_jaccard_half():
    # {a,b} vs {a,c}: intersection 1, union 3 -> 1 - 1/3
    assert abs(jaccard_distance(frozenset({"a", "b"}), frozenset({"a", "c"})) - (2 / 3)) < 1e-9


def test_within_distances_count():
    sets = [frozenset({"a"}), frozenset({"a"}), frozenset({"b"})]
    d = within_distances(sets)
    assert len(d) == 3            # C(3,2)
    assert sorted(d) == [0.0, 1.0, 1.0]


def test_cross_distances_count():
    base = [frozenset({"a"}), frozenset({"a"})]
    mut = [frozenset({"b"}), frozenset({"b"}), frozenset({"b"})]
    d = cross_distances(base, mut)
    assert len(d) == 6            # 2 x 3
    assert all(x == 1.0 for x in d)


def test_permutation_pvalue_clear_separation_is_small():
    within = [0.0] * 10
    cross = [1.0] * 10
    p = permutation_pvalue(cross, within, n_perm=500, seed=0)
    assert p < 0.05


def test_permutation_pvalue_identical_is_large():
    within = [0.2, 0.3, 0.25, 0.2]
    cross = [0.2, 0.3, 0.25, 0.2]
    p = permutation_pvalue(cross, within, n_perm=500, seed=0)
    assert p > 0.2


def test_bootstrap_ci_brackets_positive_effect():
    within = [0.0] * 8
    cross = [1.0] * 8
    lo, hi = bootstrap_ci_median_diff(cross, within, n_boot=500, seed=0)
    assert lo > 0.0 and hi > 0.0


def test_classify_real_when_significant_and_positive():
    within = [0.0] * 10
    cross = [1.0] * 10
    v = classify_operator(cross, within, n_perm=300, n_boot=300, seed=0)
    assert v.verdict == VERDICT_REAL
    assert v.effect_size > 0.0


def test_classify_noise_when_no_separation():
    within = [0.3, 0.3, 0.3, 0.3]
    cross = [0.3, 0.3, 0.3, 0.3]
    v = classify_operator(cross, within, n_perm=300, n_boot=300, seed=0)
    assert v.verdict in (VERDICT_NOISE, VERDICT_INCONCLUSIVE)
