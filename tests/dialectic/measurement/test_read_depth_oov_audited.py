# tests/dialectic/measurement/test_read_depth_oov_audited.py
import pytest
from ares.dialectic.measurement.read_depth_corpus import MALIGN_ENTRIES
from ares.dialectic.measurement.read_depth_oov_schema import (
    ARM_BLACK, OOVCandidate, OOVFrontierSummary,
)
from ares.dialectic.measurement.read_depth_oov_audit import OOVDisguiseRecord
from ares.dialectic.measurement.read_depth_oov_validator import CostCeilingExceeded
from ares.dialectic.measurement.read_depth_oov_runner import (
    OOVConfig, run_oov_experiment, run_oov_experiment_audited,
)

# strips the threat tokens on LEX-002 -> canonical flips; others left intact
_EVADE = {
    "RDF-M-LEX-002": {"rdf-m-lex-002-fact-001": "C:/Temp/refresh-tool",
                      "rdf-m-lex-002-fact-003": "C:/Temp/refresh-tool 1.2MB"},
}


def _gen(scenario, arm, k):
    sid = scenario.metadata.scenario_id
    rewrites = _EVADE.get(sid, {})
    if not rewrites:
        return [], 0.0
    return [OOVCandidate(sid, arm, tuple(rewrites.items()))], 0.01


def _judge_yes(orig, evaded):
    return True, 0.002


def test_audited_returns_summary_and_disguise_records():
    summ, disguises = run_oov_experiment_audited(
        OOVConfig(k=1, arms=(ARM_BLACK,)), generate_fn=_gen, judge_fn=_judge_yes)
    assert isinstance(summ, OOVFrontierSummary)
    assert all(isinstance(d, OOVDisguiseRecord) for d in disguises)
    # one candidate generated only for LEX-002 in this fake
    assert len(disguises) == 1
    d = disguises[0]
    assert d.scenario_id == "RDF-M-LEX-002" and d.accepted is True
    assert d.canonical_flipped is True            # threat tokens stripped
    # original_values captured from the pre-rewrite packet
    ov = dict(d.original_values)
    assert ov["rdf-m-lex-002-fact-001"] == "C:\\Temp\\update.exe"


def test_wrapper_returns_only_summary():
    summ = run_oov_experiment(
        OOVConfig(k=1, arms=(ARM_BLACK,)), generate_fn=_gen, judge_fn=_judge_yes)
    assert isinstance(summ, OOVFrontierSummary)


def test_rejected_candidates_are_recorded_too():
    def gen_bad(scenario, arm, k):
        sid = scenario.metadata.scenario_id
        if sid != "RDF-M-LEX-002":
            return [], 0.0
        return [OOVCandidate(sid, arm, (("no-such-fact", "x"),))], 0.01
    summ, disguises = run_oov_experiment_audited(
        OOVConfig(k=1, arms=(ARM_BLACK,)), generate_fn=gen_bad, judge_fn=_judge_yes)
    assert len(disguises) == 1
    assert disguises[0].accepted is False
    assert disguises[0].skeleton_ok is False
    assert "unknown_fact_id" in disguises[0].reject_reason


def test_cost_ceiling_aborts_midrun():
    def gen_expensive(scenario, arm, k):
        return [], 50.0  # generation cost alone blows the ceiling
    with pytest.raises(CostCeilingExceeded):
        run_oov_experiment_audited(
            OOVConfig(k=1, arms=(ARM_BLACK,), cost_ceiling_usd=10.0),
            generate_fn=gen_expensive, judge_fn=_judge_yes)
