import dataclasses
import json

import pytest
from ares.dialectic.visualization.cycle_trace import (
    CycleSnapshot,
    CycleTimelineV2,
    PairTrace,
    cycle_timeline_to_json,
)


def _valid_snapshot(**overrides):
    base = dict(
        architect_confidence=0.95,
        architect_cited_facts=("inj001-fact-001",),
        architect_message_type="hypothesis",
        skeptic_confidence=0.3,
        skeptic_cited_facts=("inj001-fact-001",),
        skeptic_message_type="rebuttal",
        skeptic_triggered_rules=(),
        oracle_outcome="threat_confirmed",
        oracle_confidence=0.95,
        oracle_supporting_facts=("inj001-fact-001",),
        final_outcome="threat_confirmed",
        final_confidence=0.95,
        pipeline="llm",
    )
    base.update(overrides)
    return CycleSnapshot(**base)


def test_cycle_snapshot_constructs_with_valid_values():
    snap = _valid_snapshot()
    assert snap.architect_confidence == 0.95
    assert snap.pipeline == "llm"


def test_cycle_snapshot_is_frozen():
    snap = _valid_snapshot()
    with pytest.raises(dataclasses.FrozenInstanceError):
        snap.architect_confidence = 0.5  # type: ignore[misc]


def test_cycle_snapshot_rejects_confidence_below_zero():
    with pytest.raises(ValueError, match="architect_confidence"):
        _valid_snapshot(architect_confidence=-0.1)


def test_cycle_snapshot_rejects_confidence_above_one():
    with pytest.raises(ValueError, match="oracle_confidence"):
        _valid_snapshot(oracle_confidence=1.1)


def test_cycle_snapshot_rejects_invalid_pipeline():
    with pytest.raises(ValueError, match="pipeline"):
        _valid_snapshot(pipeline="bogus")


def test_cycle_snapshot_accepts_light_pipeline():
    snap = _valid_snapshot(pipeline="light")
    assert snap.pipeline == "light"


def test_cycle_snapshot_rejects_skeptic_confidence_below_zero():
    with pytest.raises(ValueError, match="skeptic_confidence"):
        _valid_snapshot(skeptic_confidence=-0.01)


def test_cycle_snapshot_rejects_final_confidence_above_one():
    with pytest.raises(ValueError, match="final_confidence"):
        _valid_snapshot(final_confidence=1.5)


def test_cycle_snapshot_accepts_empty_citation_tuples():
    snap = _valid_snapshot(
        architect_cited_facts=(),
        skeptic_cited_facts=(),
        oracle_supporting_facts=(),
        skeptic_triggered_rules=(),
    )
    assert snap.architect_cited_facts == ()
    assert snap.skeptic_cited_facts == ()
    assert snap.oracle_supporting_facts == ()
    assert snap.skeptic_triggered_rules == ()


def _valid_pair_trace(**overrides):
    snap_llm_b = _valid_snapshot(pipeline="llm")
    snap_llm_m = _valid_snapshot(pipeline="llm")
    snap_light_b = _valid_snapshot(pipeline="light")
    snap_light_m = _valid_snapshot(pipeline="light")
    base = dict(
        pair_index=0,
        scenario_id="INJ-001",
        operator="framing_prefix_v1",
        baseline_llm=snap_llm_b,
        mutated_llm=snap_llm_m,
        baseline_light=snap_light_b,
        mutated_light=snap_light_m,
        narrow_leakage=False,
        broad_leakage=False,
        first_diverging_layer="None",
        llm_architect_bits=(False, False, False, False),
        llm_skeptic_bits=(False, False, False, False),
        llm_oracle_bits=(False, False, False, False),
        llm_final_bits=(False, False, False, False),
    )
    base.update(overrides)
    return PairTrace(**base)


def test_pair_trace_constructs_with_valid_values():
    pair = _valid_pair_trace()
    assert pair.scenario_id == "INJ-001"
    assert pair.operator == "framing_prefix_v1"


def test_pair_trace_is_frozen():
    pair = _valid_pair_trace()
    with pytest.raises(dataclasses.FrozenInstanceError):
        pair.pair_index = 99  # type: ignore[misc]


def test_pair_trace_rejects_negative_pair_index():
    with pytest.raises(ValueError, match="pair_index"):
        _valid_pair_trace(pair_index=-1)


def test_pair_trace_rejects_empty_scenario_id():
    with pytest.raises(ValueError, match="scenario_id"):
        _valid_pair_trace(scenario_id="")


def test_pair_trace_rejects_empty_operator():
    with pytest.raises(ValueError, match="operator"):
        _valid_pair_trace(operator="")


def test_pair_trace_rejects_invalid_diverging_layer():
    with pytest.raises(ValueError, match="first_diverging_layer"):
        _valid_pair_trace(first_diverging_layer="bogus")


def test_pair_trace_accepts_all_valid_diverging_layers():
    for layer in ("Architect", "Skeptic", "Oracle", "Final", "None"):
        pair = _valid_pair_trace(first_diverging_layer=layer)
        assert pair.first_diverging_layer == layer


def test_pair_trace_rejects_leakage_bits_wrong_arity():
    with pytest.raises(ValueError, match="llm_architect_bits"):
        _valid_pair_trace(llm_architect_bits=(False, False, False))  # 3 bits


def test_pair_trace_rejects_non_bool_in_leakage_bits():
    with pytest.raises(TypeError, match="llm_oracle_bits"):
        _valid_pair_trace(llm_oracle_bits=(False, False, 1, False))  # int 1, not bool


def test_pair_trace_allows_missing_light_pipeline():
    pair = _valid_pair_trace(baseline_light=None, mutated_light=None)
    assert pair.baseline_light is None
    assert pair.mutated_light is None


def test_pair_trace_requires_at_least_one_complete_pipeline():
    with pytest.raises(ValueError, match="at least one"):
        _valid_pair_trace(
            baseline_llm=None,
            mutated_llm=None,
            baseline_light=None,
            mutated_light=None,
        )


def test_pair_trace_rejects_half_pipeline():
    with pytest.raises(ValueError, match="at least one"):
        _valid_pair_trace(
            baseline_llm=None,
            baseline_light=None,
            mutated_light=None,
        )


def test_cycle_timeline_v2_constructs():
    pair = _valid_pair_trace()
    timeline = CycleTimelineV2(
        schema_version="v2",
        run_id="20260510-193950-f401a8",
        operators=("framing_prefix_v1",),
        pairs=(pair,),
    )
    assert timeline.schema_version == "v2"
    assert len(timeline.pairs) == 1


def test_cycle_timeline_v2_rejects_wrong_schema_version():
    pair = _valid_pair_trace()
    with pytest.raises(ValueError, match="schema_version"):
        CycleTimelineV2(
            schema_version="v1",
            run_id="run-id",
            operators=("op",),
            pairs=(pair,),
        )


def test_cycle_timeline_v2_rejects_empty_pairs():
    with pytest.raises(ValueError, match="pairs"):
        CycleTimelineV2(
            schema_version="v2",
            run_id="run-id",
            operators=("op",),
            pairs=(),
        )


def test_cycle_timeline_v2_rejects_empty_run_id():
    pair = _valid_pair_trace()
    with pytest.raises(ValueError, match="run_id"):
        CycleTimelineV2(
            schema_version="v2",
            run_id="",
            operators=("op",),
            pairs=(pair,),
        )


def test_cycle_timeline_v2_rejects_empty_operators():
    pair = _valid_pair_trace()
    with pytest.raises(ValueError, match="operators"):
        CycleTimelineV2(
            schema_version="v2",
            run_id="run-id",
            operators=(),
            pairs=(pair,),
        )


def test_cycle_timeline_to_json_round_trip():
    pair = _valid_pair_trace()
    timeline = CycleTimelineV2(
        schema_version="v2",
        run_id="run-id",
        operators=("framing_prefix_v1",),
        pairs=(pair,),
    )
    payload = json.loads(cycle_timeline_to_json(timeline))
    assert payload["schema_version"] == "v2"
    assert payload["run_id"] == "run-id"
    assert payload["operators"] == ["framing_prefix_v1"]
    assert len(payload["pairs"]) == 1
    assert payload["pairs"][0]["scenario_id"] == "INJ-001"
    assert payload["pairs"][0]["baseline_llm"]["architect_confidence"] == 0.95
    assert payload["pairs"][0]["llm_skeptic_bits"] == [False, False, False, False]

    expected_pair_keys = {
        "pair_index", "scenario_id", "operator",
        "baseline_llm", "mutated_llm", "baseline_light", "mutated_light",
        "narrow_leakage", "broad_leakage", "first_diverging_layer",
        "llm_architect_bits", "llm_skeptic_bits", "llm_oracle_bits", "llm_final_bits",
    }
    assert set(payload["pairs"][0].keys()) == expected_pair_keys

    expected_snapshot_keys = {
        "architect_confidence", "architect_cited_facts", "architect_message_type",
        "skeptic_confidence", "skeptic_cited_facts", "skeptic_message_type",
        "skeptic_triggered_rules",
        "oracle_outcome", "oracle_confidence", "oracle_supporting_facts",
        "final_outcome", "final_confidence", "pipeline",
    }
    assert set(payload["pairs"][0]["baseline_llm"].keys()) == expected_snapshot_keys


def test_cycle_timeline_to_json_is_deterministic():
    """Same process, same object: two serializations must produce identical bytes.

    Note: cross-process byte stability (e.g., the JSON file would be
    git-stable across regenerations) is a stronger property not covered
    here -- it's verified indirectly when Task A7 commits the generated
    prism-timeline.json against Session 059 traces.
    """
    pair = _valid_pair_trace()
    timeline = CycleTimelineV2(
        schema_version="v2",
        run_id="run-id",
        operators=("op-a", "op-b"),
        pairs=(pair,),
    )
    a = cycle_timeline_to_json(timeline)
    b = cycle_timeline_to_json(timeline)
    assert a == b


def test_cycle_timeline_to_json_serializes_null_pipelines():
    pair = _valid_pair_trace(baseline_light=None, mutated_light=None)
    timeline = CycleTimelineV2(
        schema_version="v2",
        run_id="run-id",
        operators=("op",),
        pairs=(pair,),
    )
    payload = json.loads(cycle_timeline_to_json(timeline))
    assert payload["pairs"][0]["baseline_light"] is None
    assert payload["pairs"][0]["mutated_light"] is None
