# tests/dialectic/measurement/test_read_depth_oov_schema.py
from ares.dialectic.measurement.read_depth_oov_schema import (
    ARM_BLACK, ARM_WHITE, ARMS,
    READ_DEPTH_OOV_HARD_CEILING_USD, FALSIFIED_REQUIRES_ZERO_EVASIONS,
    VERDICT_SUPPORTED_STRONG, VERDICT_SUPPORTED_MODERATE,
    VERDICT_FALSIFIED, VERDICT_INSTRUMENT_FAILURE,
    OOVCandidate, OOVArmSummary, OOVEvasionRecord, OOVFrontierSummary,
    classify_oov_verdict, oov_corpus_digest,
)


def _arm(arm, *, n_accepted, evaded):
    return OOVArmSummary(
        arm=arm, n_candidates=n_accepted, n_accepted=n_accepted,
        n_rejected_skeleton=0, n_rejected_novelty=0, n_rejected_judge=0,
        scenarios_evaded=tuple(evaded),
        adversarial_x_scenario=len(evaded) / 4.0,
        per_candidate_flip_rate=0.0, n_malign_scenarios=4,
    )


def test_constants():
    assert READ_DEPTH_OOV_HARD_CEILING_USD == 10.0
    assert FALSIFIED_REQUIRES_ZERO_EVASIONS is True
    assert ARMS == (ARM_BLACK, ARM_WHITE)


def test_black_hole_is_supported_strong():
    arms = (_arm(ARM_BLACK, n_accepted=5, evaded=["RDF-M-LEX-001"]),
            _arm(ARM_WHITE, n_accepted=5, evaded=[]))
    assert classify_oov_verdict(arms) == VERDICT_SUPPORTED_STRONG


def test_white_only_hole_is_supported_moderate():
    arms = (_arm(ARM_BLACK, n_accepted=5, evaded=[]),
            _arm(ARM_WHITE, n_accepted=5, evaded=["RDF-M-LEX-002"]))
    assert classify_oov_verdict(arms) == VERDICT_SUPPORTED_MODERATE


def test_survives_both_is_falsified():
    arms = (_arm(ARM_BLACK, n_accepted=5, evaded=[]),
            _arm(ARM_WHITE, n_accepted=5, evaded=[]))
    assert classify_oov_verdict(arms) == VERDICT_FALSIFIED


def test_empty_accepted_arm_is_instrument_failure():
    arms = (_arm(ARM_BLACK, n_accepted=0, evaded=[]),
            _arm(ARM_WHITE, n_accepted=5, evaded=[]))
    assert classify_oov_verdict(arms) == VERDICT_INSTRUMENT_FAILURE


def test_corpus_digest_is_order_independent_and_stable():
    c1 = OOVCandidate("RDF-M-LEX-001", ARM_BLACK, (("f1", "a"), ("f2", "b")))
    c2 = OOVCandidate("RDF-M-LEX-002", ARM_WHITE, (("f3", "c"),))
    assert oov_corpus_digest((c1, c2)) == oov_corpus_digest((c2, c1))
    assert len(oov_corpus_digest((c1, c2))) == 16


def test_summary_json_roundtrip():
    arm = _arm(ARM_BLACK, n_accepted=1, evaded=["RDF-M-LEX-001"])
    rec = OOVEvasionRecord("RDF-M-LEX-001", ARM_BLACK, True, False)
    summ = OOVFrontierSummary(
        arm_summaries=(arm,), records=(rec,), verdict=VERDICT_SUPPORTED_STRONG,
        corpus_digest="9401b7188ba790a5", oov_corpus_digest="deadbeefdeadbeef",
        total_cost_usd=1.23, model="claude-sonnet-4-20250514",
        provider="anthropic", k=8,
    )
    back = OOVFrontierSummary.from_dict(summ.to_dict())
    assert back == summ
