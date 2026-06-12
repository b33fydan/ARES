# tests/dialectic/measurement/test_read_depth_oov_audit_verdict.py
from ares.dialectic.measurement.read_depth_oov_audit import (
    AUDIT_ROBUST, AUDIT_PARTIAL, AUDIT_REFUTED, AUDIT_INCONCLUSIVE,
    INDEP_CONFIRMED, INDEP_SPLIT, INDEP_REFUTED,
    EvadingJudgement, ControlJudgement, OOVAuditSummary,
    classify_evading, scenario_confirmed, controls_pass, classify_audit_verdict,
)


def test_classify_evading_requires_both_independents():
    assert classify_evading((True, True)) == INDEP_CONFIRMED
    assert classify_evading((True, False)) == INDEP_SPLIT
    assert classify_evading((False, False)) == INDEP_REFUTED
    assert classify_evading(()) == INDEP_REFUTED


def _ej(sid, cls):
    return EvadingJudgement(sid, "black", (), (), True, (("openai", True),), cls)


def test_scenario_confirmed_needs_one_confirmed_disguise():
    js = (_ej("RDF-M-LEX-002", INDEP_SPLIT), _ej("RDF-M-LEX-002", INDEP_CONFIRMED))
    assert scenario_confirmed(js, "RDF-M-LEX-002") is True
    assert scenario_confirmed(js, "RDF-M-SYN-001") is False


def _cj(passed):
    return ControlJudgement("RDF-B-CLEAN-001", "negative", False,
                            (("openai", False),), passed)


def test_controls_pass_is_all():
    assert controls_pass((_cj(True), _cj(True))) is True
    assert controls_pass((_cj(True), _cj(False))) is False


def test_audit_verdict_matrix():
    evaded = ("A", "B")
    assert classify_audit_verdict(evaded, {"A": True, "B": True}, True) == AUDIT_ROBUST
    assert classify_audit_verdict(evaded, {"A": True, "B": False}, True) == AUDIT_PARTIAL
    assert classify_audit_verdict(evaded, {"A": False, "B": False}, True) == AUDIT_REFUTED
    assert classify_audit_verdict(evaded, {"A": True, "B": True}, False) == AUDIT_INCONCLUSIVE
    assert classify_audit_verdict((), {}, True) == AUDIT_INCONCLUSIVE


def test_summary_roundtrip():
    summ = OOVAuditSummary(
        evading=(_ej("RDF-M-LEX-002", INDEP_CONFIRMED),),
        controls=(_cj(True),),
        per_scenario_confirmed=(("RDF-M-LEX-002", True),),
        judge_labels=("openai", "gemini"), controls_passed=True,
        audit_verdict=AUDIT_ROBUST, total_cost_usd=1.5,
        base_oov_corpus_digest="deadbeefdeadbeef")
    assert OOVAuditSummary.from_dict(summ.to_dict()) == summ
