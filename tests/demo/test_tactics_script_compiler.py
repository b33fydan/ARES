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
