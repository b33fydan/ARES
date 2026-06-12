# tests/dialectic/measurement/test_read_depth_oov_runner.py
from ares.dialectic.measurement.read_depth_corpus import MALIGN_ENTRIES
from ares.dialectic.measurement.read_depth_oov_schema import (
    ARM_BLACK, ARM_WHITE, OOVCandidate,
    VERDICT_SUPPORTED_STRONG, VERDICT_FALSIFIED, VERDICT_INSTRUMENT_FAILURE,
)
from ares.dialectic.measurement.read_depth_oov_runner import (
    OOVConfig, estimate_cost_usd, run_oov_experiment, run_preflight,
)

# A disguise that strips every threat token -> canonical can no longer match.
_EVADE = {
    "RDF-M-LEX-001": {"rdf-m-lex-001-fact-002": "C:/Users/Public/pd-utility",
                      "rdf-m-lex-001-fact-003": "pd-utility reads auth memory"},
    "RDF-M-LEX-002": {"rdf-m-lex-002-fact-001": "C:/Users/Public/refresh-tool",
                      "rdf-m-lex-002-fact-003": "C:/Users/Public/refresh-tool 1.2MB"},
    "RDF-M-SYN-001": {"rdf-m-syn-001-fact-001": "payload placed in public area"},
    "RDF-M-PATCH-001": {"rdf-m-patch-001-fact-002": "pd-utility reads auth memory",
                        "rdf-m-patch-001-fact-003": "C:/Users/Public/pd-utility"},
}


def _gen_evade(scenario, arm, k):
    sid = scenario.metadata.scenario_id
    rewrites = _EVADE.get(sid, {})
    return [OOVCandidate(sid, arm, tuple(rewrites.items()))], 0.01


def _gen_weak(scenario, arm, k):
    # introduces an OOV token but keeps the threat literally present
    sid = scenario.metadata.scenario_id
    f = next(x for x in scenario.packet.get_all_facts()
             if isinstance(x.value, str))
    return [OOVCandidate(sid, arm, ((f.fact_id, f.value + " (oov-marker-xyz)"),))], 0.01


def _gen_empty(scenario, arm, k):
    return [], 0.0


def _judge_yes(orig, evaded):
    return True, 0.002


def test_preflight_is_free_and_reports_estimate():
    pf = run_preflight(OOVConfig(k=8))
    assert pf["estimate_usd"] > 0.0
    assert pf["corpus_digest"] == "9401b7188ba790a5"
    assert pf["n_malign"] == len(MALIGN_ENTRIES)


def test_estimate_scales_with_arms_and_k():
    one = estimate_cost_usd(OOVConfig(k=8, arms=(ARM_BLACK,)), per_call_usd=0.02)
    two = estimate_cost_usd(OOVConfig(k=8, arms=(ARM_BLACK, ARM_WHITE)),
                            per_call_usd=0.02)
    assert two > one


def test_canonical_evaded_in_black_box_is_supported_strong():
    summ = run_oov_experiment(OOVConfig(k=2), generate_fn=_gen_evade,
                              judge_fn=_judge_yes)
    assert summ.verdict == VERDICT_SUPPORTED_STRONG
    black = next(a for a in summ.arm_summaries if a.arm == ARM_BLACK)
    assert black.adversarial_x_scenario == 1.0          # all 4 evaded
    assert set(black.scenarios_evaded) == {e.scenario_id for e in MALIGN_ENTRIES}
    assert summ.total_cost_usd > 0.0
    assert len(summ.oov_corpus_digest) == 16


def test_canonical_holds_is_falsified():
    summ = run_oov_experiment(OOVConfig(k=2), generate_fn=_gen_weak,
                              judge_fn=_judge_yes)
    assert summ.verdict == VERDICT_FALSIFIED
    for a in summ.arm_summaries:
        assert a.adversarial_x_scenario == 0.0
        assert a.n_accepted > 0


def test_empty_generation_is_instrument_failure():
    summ = run_oov_experiment(OOVConfig(k=2), generate_fn=_gen_empty,
                              judge_fn=_judge_yes)
    assert summ.verdict == VERDICT_INSTRUMENT_FAILURE
