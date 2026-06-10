# tests/dialectic/measurement/test_read_depth_tier4_schema.py
from ares.dialectic.measurement.read_depth_tier4_schema import (
    READ_DEPTH_TIER4_HARD_CEILING_USD,
    Tier4OperatorRecord, Tier4ScenarioRecord, Tier4Coordinate, Tier4Summary,
)


def test_hard_ceiling_is_15():
    assert READ_DEPTH_TIER4_HARD_CEILING_USD == 15.0


def test_coordinate_roundtrips():
    c = Tier4Coordinate(
        tier_id="llm_semantic", view="cumulative", x_semantic=0.4,
        x_semantic_ci_low=0.2, x_semantic_ci_high=0.6, tpr=1.0, fpr=0.5,
        youden_j=0.5, n_malign=4, n_benign=4, k_resamples=20,
        model="claude-sonnet-4-20250514", provider="anthropic",
    )
    assert Tier4Coordinate.from_dict(c.to_dict()) == c


def test_summary_roundtrips():
    op = Tier4OperatorRecord(operator_name="framing_prefix_v1",
                             perturbed_malign_rate=0.5, flipped=True,
                             p_value=0.01, n_resamples=20)
    rec = Tier4ScenarioRecord(
        scenario_id="RDF-M-LEX-001", is_malign=True, stratum="M-lex",
        baseline_malign_rate=0.9, baseline_majority_malign=True,
        operator_records=(op,))
    coord = Tier4Coordinate(
        tier_id="llm_semantic", view="standalone", x_semantic=0.5,
        x_semantic_ci_low=0.0, x_semantic_ci_high=1.0, tpr=1.0, fpr=0.25,
        youden_j=0.75, n_malign=4, n_benign=4, k_resamples=20,
        model="m", provider="anthropic")
    s = Tier4Summary(coordinates=(coord,), records=(rec,),
                     corpus_digest="9401b7188ba790a5", total_cost_usd=4.6,
                     model="m", provider="anthropic", k_resamples=20)
    assert Tier4Summary.from_dict(s.to_dict()) == s
