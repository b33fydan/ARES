from demo.tactics_script_compiler import (
    DEFAULT_TRACES_PATH, load_scenario_traces, scenarios_in_run,
)


def test_scenarios_in_run_returns_the_17_s084_scenarios():
    ids = scenarios_in_run(DEFAULT_TRACES_PATH)
    assert "INJ-020" in ids and "INJ-001" in ids
    assert len(ids) >= 15  # S084 ran 17 scenarios


def test_load_scenario_traces_filters_by_id():
    recs = load_scenario_traces("INJ-020", DEFAULT_TRACES_PATH)
    assert recs, "no INJ-020 records found"
    assert all(r["scenario_id"] == "INJ-020" for r in recs)
    # dual-agent schema present
    r = recs[0]
    for key in ("condition", "architect_cited_facts", "skeptic_cited_facts",
                "architect_confidence", "skeptic_confidence",
                "oracle_supporting_facts", "final_outcome"):
        assert key in r


from demo.tactics_script_compiler import (
    conditions_in, condition_summary,
)


def test_conditions_in_includes_baseline_and_framing():
    recs = load_scenario_traces("INJ-020")
    conds = conditions_in(recs)
    assert "baseline" in conds
    assert any(c.startswith("framing:") for c in conds)


def test_condition_summary_shape_for_baseline():
    recs = load_scenario_traces("INJ-020")
    summ = condition_summary(recs, "baseline")
    assert isinstance(summ["architect"]["cited_fact_ids"], list)
    assert 0.0 <= summ["architect"]["confidence"] <= 1.0
    assert isinstance(summ["skeptic"]["cited_fact_ids"], list)
    assert summ["oracle"]["verdict"] in {
        "threat_confirmed", "threat_dismissed", "inconclusive"}
    assert isinstance(summ["oracle"]["supporting_fact_ids"], list)


from demo.tactics_script_compiler import resolve_facts


def test_resolve_facts_returns_display_fields():
    facts = resolve_facts("INJ-020")
    assert facts, "no facts resolved"
    f = facts[0]
    assert set(f) >= {"fact_id", "field", "display_label", "source_type", "is_threat_dominant"}
    assert any(x["is_threat_dominant"] for x in facts)  # at least one threat-dominant fact


import json as _json
from demo.tactics_script_compiler import (
    SOURCE_RUN,
    synthesize_claim, compile_tactics_script, validate_provenance, emit_tactics_script,
)


def test_synthesize_claim_states_counts_and_stance():
    c = synthesize_claim("architect", ["a", "b"], total=5)
    assert "2" in c and "5" in c and "threat" in c.lower()
    c2 = synthesize_claim("skeptic", ["a"], total=5)
    assert "benign" in c2.lower()


def test_compile_tactics_script_full_shape():
    s = compile_tactics_script("INJ-020")
    assert s["scenario_id"] == "INJ-020"
    assert s["facts"]
    assert s["conditions"] and s["conditions"][0]["name"] == "baseline"
    cond = s["conditions"][0]
    assert "claim" in cond["architect"] and "claim" in cond["skeptic"]
    assert cond["oracle"]["verdict"] in {"threat_confirmed", "threat_dismissed", "inconclusive"}
    validate_provenance(s)  # must not raise
    assert s["provenance"]["source_run"] == SOURCE_RUN
    assert s["provenance"]["trace_sha256"]


def test_emit_writes_valid_json(tmp_path):
    out = emit_tactics_script("INJ-020", out_dir=str(tmp_path))
    data = _json.loads(open(out, encoding="utf-8").read())
    assert data["scenario_id"] == "INJ-020"
