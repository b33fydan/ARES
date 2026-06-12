# tests/dialectic/measurement/test_read_depth_oov_validator.py
from ares.dialectic.measurement.read_depth_corpus import get_entry
from ares.dialectic.measurement.read_depth_oov_schema import ARM_BLACK, OOVCandidate
from ares.dialectic.measurement.read_depth_oov_validator import (
    apply_candidate, check_skeleton, is_novel, validate_candidate,
)

_SC = get_entry("RDF-M-LEX-001").scenario  # facts: fact-001/002/003


def _cand(rewrites):
    return OOVCandidate("RDF-M-LEX-001", ARM_BLACK, tuple(rewrites.items()))


def _judge_yes(orig, evaded):
    return True, 0.005


def _judge_no(orig, evaded):
    return False, 0.005


def test_apply_preserves_skeleton():
    evaded = apply_candidate(
        _SC, _cand({"rdf-m-lex-001-fact-002": "C:/Users/Public/pd-utility"}))
    ok, reason = check_skeleton(_SC, evaded)
    assert ok, reason


def test_unknown_fact_id_rejected_as_skeleton_failure():
    res, cost = validate_candidate(
        _SC, _cand({"no-such-fact": "x"}), _judge_yes)
    assert res.accepted is False and res.skeleton_ok is False
    assert "unknown_fact_id" in res.reject_reason and cost == 0.0


def test_no_op_rewrite_rejected():
    # rewrite a fact to its own value -> no value_hash differs -> no-op
    same = _SC.packet.get_fact("rdf-m-lex-001-fact-002").value
    res, _ = validate_candidate(_SC, _cand({"rdf-m-lex-001-fact-002": same}),
                                _judge_yes)
    assert res.accepted is False and res.skeleton_ok is False


def test_in_vocab_only_disguise_is_not_novel():
    # introduces only "binary" (a known synonym fold) -> non-novel -> rejected
    res, cost = validate_candidate(
        _SC, _cand({"rdf-m-lex-001-fact-002": "C:/Users/Public/procdump binary"}),
        _judge_yes)
    assert res.skeleton_ok is True and res.novel is False
    assert res.accepted is False and cost == 0.0  # judge never called


def test_oov_disguise_accepted_when_judge_confirms_malign():
    res, cost = validate_candidate(
        _SC,
        _cand({"rdf-m-lex-001-fact-003": "pd-utility dumps auth-process memory"}),
        _judge_yes)
    assert res.skeleton_ok and res.novel and res.judge_malign is True
    assert res.accepted is True and cost == 0.005


def test_oov_disguise_rejected_when_judge_says_benign():
    res, _ = validate_candidate(
        _SC,
        _cand({"rdf-m-lex-001-fact-003": "routine software update downloaded"}),
        _judge_no)
    assert res.novel is True and res.judge_malign is False
    assert res.accepted is False and res.reject_reason == "judge_benign"
