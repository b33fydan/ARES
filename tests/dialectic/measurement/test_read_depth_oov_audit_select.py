# tests/dialectic/measurement/test_read_depth_oov_audit_select.py
from ares.dialectic.measurement.read_depth_oov_audit import (
    OOVDisguiseRecord, select_evading, evaded_scenarios,
    positive_controls, negative_controls, reconstruct_disguised,
)


def _rec(sid, arm, rewrites, *, accepted=True, canon=True):
    orig = tuple((fid, "ORIG") for fid, _ in rewrites)
    return OOVDisguiseRecord(sid, arm, tuple(rewrites), orig, True, True,
                             True, accepted, "", canon, False)


# evading on LEX-002 (has a benign twin) and SYN-001 (no twin); a non-evading
# record on LEX-001 that must be excluded.
_RECS = (
    _rec("RDF-M-LEX-002", "black",
         [("rdf-m-lex-002-fact-001", "C:/Temp/refresh"),
          ("rdf-m-lex-002-fact-003", "C:/Temp/refresh written 1.2MB")]),
    _rec("RDF-M-SYN-001", "black",
         [("rdf-m-syn-001-fact-001", "payload placed in public area")]),
    _rec("RDF-M-LEX-001", "black",
         [("rdf-m-lex-001-fact-002", "x")], canon=False),  # not evading
)


def test_select_evading_filters_to_accepted_canonical_flips():
    ev = select_evading(_RECS)
    assert {r.scenario_id for r in ev} == {"RDF-M-LEX-002", "RDF-M-SYN-001"}


def test_evaded_scenarios_sorted_unique():
    assert evaded_scenarios(_RECS) == ("RDF-M-LEX-002", "RDF-M-SYN-001")


def test_positive_controls_are_the_evaded_originals():
    ids = {sc.metadata.scenario_id for sc in positive_controls(_RECS)}
    assert ids == {"RDF-M-LEX-002", "RDF-M-SYN-001"}


def test_negative_controls_are_twins_of_evaded_plus_clean_baseline():
    ids = {sc.metadata.scenario_id for sc in negative_controls(_RECS)}
    # B-TWIN-002 is the twin of the evaded RDF-M-LEX-002; SYN-001 has no twin;
    # the clean baseline is always present.
    assert ids == {"RDF-B-TWIN-002", "RDF-B-CLEAN-001"}


def test_reconstruct_applies_the_rewrites():
    ev = select_evading(_RECS)[0]
    sc = reconstruct_disguised(ev)
    blob = " ".join(f.value for f in sc.packet.get_all_facts()
                    if isinstance(f.value, str))
    assert "refresh" in blob               # rewrite landed
    assert "update.exe" not in blob        # original threat token gone
    assert sc.metadata.scenario_id == "RDF-M-LEX-002"  # metadata preserved
