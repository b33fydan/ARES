# tests/dialectic/measurement/test_read_depth_oov_generator.py
from ares.dialectic.measurement.read_depth_corpus import get_entry
from ares.dialectic.measurement.read_depth_oov_schema import ARM_BLACK, ARM_WHITE
from ares.dialectic.measurement.read_depth_oov_generator import (
    build_prompt, parse_candidates,
)

_SC = get_entry("RDF-M-LEX-001").scenario


def test_black_box_prompt_omits_matcher_internals():
    system, user = build_prompt(_SC, ARM_BLACK)
    assert "_SYNONYMS" not in user and "_SYNONYMS" not in system
    # the malign values are shown
    assert "procdump.exe" in user
    # each fact is keyed by fact_id so the model can return rewrites
    assert "rdf-m-lex-001-fact-002" in user
    # negative discrimination: matcher-block-exclusive strings must be absent
    assert "canonicalize" not in user
    assert "credential tooling" not in user


def test_white_box_prompt_includes_matcher_internals():
    system, user = build_prompt(_SC, ARM_WHITE)
    blob = system + user
    # white-box exposes the canonicalizer + named matcher patterns; these
    # strings appear ONLY in the matcher block, never in black-box.
    assert "canonicalize" in blob
    assert "credential tooling" in blob


def test_parse_candidates_builds_skeleton_keyed_rewrites():
    raw = '''Here are disguises:
    [
      {"rdf-m-lex-001-fact-2": "C:/Users/Public/pd-utility"},
      {"rdf-m-lex-001-fact-3": "pd-utility dumps the auth process memory"}
    ]
    Done.'''
    cands = parse_candidates(_SC, ARM_BLACK, raw)
    assert len(cands) == 2
    assert cands[0].arm == ARM_BLACK
    assert cands[0].scenario_id == "RDF-M-LEX-001"
    assert cands[0].value_rewrites == (("rdf-m-lex-001-fact-2",
                                        "C:/Users/Public/pd-utility"),)


def test_parse_candidates_tolerates_garbage():
    assert parse_candidates(_SC, ARM_BLACK, "no json here") == []
    assert parse_candidates(_SC, ARM_BLACK, "[not, valid, json}") == []
    assert parse_candidates(_SC, ARM_BLACK, '{"not": "a list"}') == []
