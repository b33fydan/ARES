from ares.dialectic.measurement.architect_framing_metrics import (
    jaccard_distance, within_distances, cross_distances,
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
