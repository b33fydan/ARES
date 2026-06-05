from ares.dialectic.measurement.dual_agent_framing_mirror import (
    build_mirror_record, classify_mirror, direction, modal_set,
)


def test_direction_cases():
    assert direction(frozenset("abc"), frozenset("abc")) == "none"
    assert direction(frozenset("abc"), frozenset("c")) == "collapse"
    assert direction(frozenset("c"), frozenset("abc")) == "expand"
    assert direction(frozenset("ab"), frozenset("bc")) == "swap"


def test_modal_set_picks_most_common_with_deterministic_tiebreak():
    a, b = frozenset({"x"}), frozenset({"y"})
    # 2x a, 2x b -> tie -> lexicographically smallest sorted tuple wins ("x" < "y")
    assert modal_set([a, b, a, b]) == a
    # clear majority
    assert modal_set([a, a, b]) == a
    assert modal_set([]) == frozenset()


def test_classify_mirror_truth_table():
    assert classify_mirror("none", "none") == "none"
    assert classify_mirror("collapse", "none") == "single"
    assert classify_mirror("none", "expand") == "single"
    assert classify_mirror("collapse", "collapse") == "aligned"
    assert classify_mirror("collapse", "expand") == "opposed"
    assert classify_mirror("expand", "collapse") == "opposed"
    assert classify_mirror("collapse", "swap") == "mixed"
    assert classify_mirror("swap", "expand") == "mixed"


def test_build_mirror_record_opposed():
    rec = build_mirror_record(
        scenario_id="INJ-020", operator_name="framing_prefix_v1",
        arch_base_sets=[frozenset({"f1", "f2", "f3"})] * 3,
        arch_framed_sets=[frozenset({"f3"})] * 3,
        skep_base_sets=[frozenset({"f1", "f2", "f3"})] * 3,
        skep_framed_sets=[frozenset({"f1", "f2", "f3", "f4"})] * 3,
    )
    assert rec.architect_direction == "collapse"
    assert rec.skeptic_direction == "expand"
    assert rec.mirror_class == "opposed"
    assert abs(rec.architect_jaccard - (1 - 1 / 3)) < 1e-9
    assert abs(rec.skeptic_jaccard - (1 - 3 / 4)) < 1e-9
