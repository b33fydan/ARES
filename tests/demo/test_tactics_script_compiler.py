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
