# tests/dialectic/measurement/test_read_depth_oov_audit_runner.py
import pytest
from ares.dialectic.measurement.read_depth_oov_audit import (
    AUDIT_ROBUST, AUDIT_REFUTED, AUDIT_INCONCLUSIVE,
    OOVDisguiseRecord, run_audit, estimate_audit_cost, run_audit_preflight,
)
from ares.dialectic.measurement.read_depth_oov_validator import CostCeilingExceeded

_SENTINEL = "zzthreatzz"


def _token_judge(sc):
    blob = " ".join(f.value.lower() for f in sc.packet.get_all_facts()
                    if isinstance(f.value, str))
    malign = ("procdump" in blob) or ("lsass" in blob) or (_SENTINEL in blob)
    return malign, 0.001


def _rec(rewrites):
    orig = tuple((fid, "ORIG") for fid, _ in rewrites)
    return OOVDisguiseRecord("RDF-M-LEX-001", "black", tuple(rewrites), orig,
                             True, True, True, True, "", True, False)


# Evaded scenario is LEX-001 only: its original carries procdump/lsass (positive
# control passes) and its benign twin RDF-B-TWIN-001 (svchost) + the clean
# baseline carry neither (negative controls pass).
_ROBUST_RECS = (_rec([("rdf-m-lex-001-fact-002", f"C:/Users/Public/{_SENTINEL}")]),)
_REFUTED_RECS = (_rec([("rdf-m-lex-001-fact-002", "C:/Users/Public/pd-utility"),
                       ("rdf-m-lex-001-fact-003", "pd-utility reads auth memory")]),)
_JUDGES = (("openai", _token_judge), ("gemini", _token_judge))


def test_robust_when_independents_confirm_and_controls_pass():
    summ = run_audit(_ROBUST_RECS, _JUDGES, cost_ceiling_usd=10.0)
    assert summ.audit_verdict == AUDIT_ROBUST
    assert summ.controls_passed is True
    assert len(summ.evading) == 1 and summ.evading[0].classification == "independent_confirmed"
    assert summ.total_cost_usd > 0.0


def test_refuted_when_disguise_reads_benign_but_controls_still_pass():
    summ = run_audit(_REFUTED_RECS, _JUDGES, cost_ceiling_usd=10.0)
    assert summ.audit_verdict == AUDIT_REFUTED
    assert summ.controls_passed is True


def test_always_malign_judge_fails_negative_control_inconclusive():
    yes = (("openai", lambda sc: (True, 0.001)),
           ("gemini", lambda sc: (True, 0.001)))
    summ = run_audit(_ROBUST_RECS, yes, cost_ceiling_usd=10.0)
    assert summ.controls_passed is False
    assert summ.audit_verdict == AUDIT_INCONCLUSIVE


def test_cost_ceiling_aborts_audit():
    pricey = (("openai", lambda sc: (True, 9.0)),)
    with pytest.raises(CostCeilingExceeded):
        run_audit(_ROBUST_RECS, pricey, cost_ceiling_usd=1.0)


def test_preflight_is_free_and_counts_items():
    pf = run_audit_preflight(_ROBUST_RECS, ("openai", "gemini"))
    assert pf["n_evading"] == 1
    assert pf["n_pos_controls"] == 1
    assert pf["n_neg_controls"] == 2          # B-TWIN-001 + B-CLEAN-001
    assert pf["estimate_usd"] == estimate_audit_cost(_ROBUST_RECS, 2)
