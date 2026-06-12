# tests/dialectic/measurement/test_read_depth_oov_audit_schema.py
from ares.dialectic.measurement.read_depth_oov_audit import (
    AUDIT_ROBUST, AUDIT_PARTIAL, AUDIT_REFUTED, AUDIT_INCONCLUSIVE,
    CONFIRM_REQUIRES_BOTH_INDEPENDENTS,
    OOVDisguiseRecord, dump_disguises, load_disguises,
)


def _rec(**kw):
    base = dict(
        scenario_id="RDF-M-LEX-002", arm="black",
        value_rewrites=(("rdf-m-lex-002-fact-001", "C:/Temp/x"),),
        original_values=(("rdf-m-lex-002-fact-001", "C:\\Temp\\update.exe"),),
        skeleton_ok=True, novel=True, judge_malign=True, accepted=True,
        reject_reason="", canonical_flipped=True, lexical_flipped=True)
    base.update(kw)
    return OOVDisguiseRecord(**base)


def test_record_roundtrip_including_none_judge():
    r1 = _rec()
    r2 = _rec(judge_malign=None, accepted=False, reject_reason="skeleton: bad",
              canonical_flipped=False, lexical_flipped=False)
    for r in (r1, r2):
        assert OOVDisguiseRecord.from_dict(r.to_dict()) == r


def test_is_evading_requires_accepted_and_canonical_flip():
    assert _rec().is_evading() is True
    assert _rec(canonical_flipped=False).is_evading() is False
    assert _rec(accepted=False).is_evading() is False
    assert _rec(accepted=False, canonical_flipped=True).is_evading() is False


def test_sidecar_dump_load_roundtrip():
    header = {"corpus_digest": "9401b7188ba790a5",
              "oov_corpus_digest": "deadbeefdeadbeef",
              "model": "claude-sonnet-4-20250514", "provider": "anthropic",
              "k": 8, "verdict": "SUPPORTED_STRONG"}
    recs = (_rec(), _rec(arm="white"))
    h2, r2 = load_disguises(dump_disguises(header, recs))
    assert h2 == header
    assert r2 == recs


def test_audit_constants():
    assert CONFIRM_REQUIRES_BOTH_INDEPENDENTS is True
    assert {AUDIT_ROBUST, AUDIT_PARTIAL, AUDIT_REFUTED, AUDIT_INCONCLUSIVE} == {
        "ROBUST", "PARTIAL", "REFUTED", "INCONCLUSIVE"}
