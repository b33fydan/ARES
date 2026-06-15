"""Tests for demo.battle_script_compiler (Glass Box Half A)."""
import json as _json

import pytest

from demo.battle_script_compiler import (
    load_inj020_scenario,
    resolve_facts,
    load_inj020_traces,
    modal_fact_set,
    median_confidence,
    round_caption,
    claim_label,
    round_leakage_vector,
    compile_battle_script,
    validate_provenance,
    emit_battle_script,
)

BASELINE = "baseline"
PREFIX = "framing:framing_prefix_v1"

# ---------------------------------------------------------------------------
# Task 1: scenario loader
# ---------------------------------------------------------------------------


def test_load_inj020_scenario_has_five_facts():
    scenario = load_inj020_scenario()
    assert scenario.metadata.scenario_id == "INJ-020"
    fact_ids = [f.fact_id for f in scenario.packet.get_all_facts()]
    assert fact_ids == [
        "inj020-fact-001", "inj020-fact-002", "inj020-fact-003",
        "inj020-fact-004", "inj020-fact-005",
    ]


# ---------------------------------------------------------------------------
# Task 2: fact resolution
# ---------------------------------------------------------------------------


def test_resolve_facts_shapes_and_threat_fact():
    facts = resolve_facts()
    assert [f["fact_id"] for f in facts] == [
        "inj020-fact-001", "inj020-fact-002", "inj020-fact-003",
        "inj020-fact-004", "inj020-fact-005",
    ]
    by_id = {f["fact_id"]: f for f in facts}
    # threat-dominant is derived from the framed architect collapse
    assert by_id["inj020-fact-003"]["is_threat_dominant"] is True
    assert by_id["inj020-fact-001"]["is_threat_dominant"] is False
    # labels and source types are non-empty strings
    for f in facts:
        assert isinstance(f["display_label"], str) and f["display_label"]
        assert isinstance(f["source_type"], str) and f["source_type"]


# ---------------------------------------------------------------------------
# Task 3: trace loading, modal cited-fact set, median confidence
# ---------------------------------------------------------------------------


def test_load_inj020_traces_counts():
    records = load_inj020_traces()
    assert len(records) == 100
    assert all(r["scenario_id"] == "INJ-020" for r in records)
    conditions = {r["condition"] for r in records}
    assert {BASELINE, PREFIX, "framing:synonym_substitution_conservative_v2"} <= conditions


def test_modal_sets_match_committed_artifact():
    records = load_inj020_traces()
    base = [r for r in records if r["condition"] == BASELINE]
    pref = [r for r in records if r["condition"] == PREFIX]
    assert modal_fact_set(base, "architect_cited_facts") == (
        "inj020-fact-001", "inj020-fact-002", "inj020-fact-003",
        "inj020-fact-004", "inj020-fact-005",
    )
    assert modal_fact_set(base, "skeptic_cited_facts") == (
        "inj020-fact-001", "inj020-fact-002", "inj020-fact-004",
    )
    assert modal_fact_set(pref, "architect_cited_facts") == ("inj020-fact-003",)
    assert modal_fact_set(pref, "skeptic_cited_facts") == (
        "inj020-fact-001", "inj020-fact-002", "inj020-fact-003",
        "inj020-fact-004", "inj020-fact-005",
    )


def test_median_confidence_is_float_in_range():
    base = [r for r in load_inj020_traces() if r["condition"] == BASELINE]
    m = median_confidence(base, "architect_confidence")
    assert 0.0 <= m <= 1.0


# ---------------------------------------------------------------------------
# Task 4: captions + claim labels
# ---------------------------------------------------------------------------


def test_claim_label_architect_collapse():
    label = claim_label("architect", ("inj020-fact-003",), 5)
    assert label == "Architect cites 1 of 5 facts — threat."


def test_claim_label_skeptic_spread():
    label = claim_label(
        "skeptic",
        ("inj020-fact-001", "inj020-fact-002", "inj020-fact-004"),
        5,
    )
    assert label == "Skeptic cites 3 of 5 facts — benign."


def test_round_caption_baseline_and_framing():
    assert round_caption("baseline") == (
        "Baseline: both agents weigh the evidence; the verdict is dismissed."
    )
    assert round_caption("framing:framing_prefix_v1") == (
        "Reframed wording — the explanations dissociate. The verdict does not move."
    )
    assert round_caption(
        "framing:synonym_substitution_conservative_v2"
    ) == (
        "Reworded facts — same dissociation. The verdict still does not move."
    )


# ---------------------------------------------------------------------------
# Task 5: round-level leakage vector
# ---------------------------------------------------------------------------


def test_leakage_vector_baseline_vs_self_all_zero():
    records = load_inj020_traces()
    base = [r for r in records if r["condition"] == BASELINE]
    lv = round_leakage_vector(base, base)
    assert lv == {
        "verdict_changed": 0, "action_changed": 0,
        "cited_facts_changed": 0, "confidence_drift_exceeded": 0,
    }


def test_leakage_vector_framing_flips_cited_facts_only():
    records = load_inj020_traces()
    base = [r for r in records if r["condition"] == BASELINE]
    pref = [r for r in records if r["condition"] == PREFIX]
    lv = round_leakage_vector(base, pref)
    assert lv["verdict_changed"] == 0          # threat_dismissed both
    assert lv["action_changed"] == 0           # stance derived from outcome
    assert lv["cited_facts_changed"] == 1      # architect collapse + skeptic fan
    assert lv["confidence_drift_exceeded"] in (0, 1)
    for v in lv.values():
        assert v in (0, 1)


# ---------------------------------------------------------------------------
# Task 6: compile_battle_script structure
# ---------------------------------------------------------------------------


def test_compile_battle_script_structure():
    script = compile_battle_script(compiled_at="2026-06-14T00:00:00Z")
    assert script["scenario_id"] == "INJ-020"
    assert [r["variant"] for r in script["rounds"]] == [
        "baseline",
        "framing:framing_prefix_v1",
        "framing:synonym_substitution_conservative_v2",
    ]
    assert len(script["evidence_packet"]["facts"]) == 5
    # every round has architect/skeptic/oracle beats, all dismissed
    for rnd in script["rounds"]:
        actors = [b["actor"] for b in rnd["beats"]]
        assert actors == ["architect", "skeptic", "oracle"]
        oracle = rnd["beats"][2]
        assert oracle["outcome"] == "threat_dismissed"
        assert "confidence" not in oracle           # stone = outcome only
    # R2 architect collapses to the lone threat fact
    r2_arch = script["rounds"][1]["beats"][0]
    assert r2_arch["cited_fact_ids"] == ["inj020-fact-003"]
    # provenance
    prov = script["provenance"]
    assert prov["source_run"] == "20260605-194137-713674"
    assert prov["git_sha"] == "40f1751"
    assert len(prov["trace_sha256"]) == 64
    assert prov["compiler_version"] == "1.0"
    assert prov["compiled_at"] == "2026-06-14T00:00:00Z"


# ---------------------------------------------------------------------------
# Task 7: verdict pixel-stability invariant
# ---------------------------------------------------------------------------


def test_verdict_invariant_across_rounds():
    script = compile_battle_script(compiled_at="2026-06-14T00:00:00Z")
    outcomes = {r["beats"][2]["outcome"] for r in script["rounds"]}
    assert outcomes == {"threat_dismissed"}   # one value => pixel-stable stone


# ---------------------------------------------------------------------------
# Task 8: provenance gate + emitter
# ---------------------------------------------------------------------------


def test_validate_provenance_rejects_missing_fields():
    with pytest.raises(ValueError):
        validate_provenance({"provenance": {"source_run": "", "trace_sha256": ""}})
    with pytest.raises(ValueError):
        validate_provenance({"provenance": {}})
    with pytest.raises(ValueError):
        validate_provenance({})


def test_emit_writes_loadable_json(tmp_path):
    out = tmp_path / "inj020.battle.json"
    path = emit_battle_script(str(out), compiled_at="2026-06-14T00:00:00Z")
    assert path == str(out)
    loaded = _json.loads(out.read_text(encoding="utf-8"))
    validate_provenance(loaded)   # does not raise
    assert loaded["scenario_id"] == "INJ-020"


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


def test_deterministic_same_input_same_json():
    import json as _json
    a = compile_battle_script(compiled_at="2026-06-14T00:00:00Z")
    b = compile_battle_script(compiled_at="2026-06-14T00:00:00Z")
    assert a == b
    assert _json.dumps(a, sort_keys=True) == _json.dumps(b, sort_keys=True)
