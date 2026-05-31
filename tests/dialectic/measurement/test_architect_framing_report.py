from ares.dialectic.measurement.architect_framing_report import render_report
from ares.dialectic.measurement.architect_framing_schema import (
    ArchitectFramingSummary, ScenarioFramingResult, OperatorFramingResult, VERDICT_REAL,
)


def _op(verdict=VERDICT_REAL):
    return OperatorFramingResult(
        operator_name="framing_prefix_v1", n_cross=64, cross_median=0.5,
        within_median=0.1, effect_size=0.4, p_value=0.01, ci_low=0.2, ci_high=0.6,
        verdict=verdict,
    )


def _scn(sid, control_exceeds=True):
    return ScenarioFramingResult(
        scenario_id=sid, within_distances=(0.1,), control_distances=(0.9,),
        control_exceeds_noise=control_exceeds, operator_results=(_op(),), skipped_operators=(),
    )


def _summary(scenarios, control_valid=True):
    return ArchitectFramingSummary(
        run_id="r1", timestamp_iso="t", git_sha="abc", provider="anthropic",
        model="claude-sonnet-4-20250514", k_resamples=8,
        operator_names=("framing_prefix_v1",), scenario_results=tuple(scenarios),
        deferred_scenario_ids=(), control_valid=control_valid, total_cost_usd=4.2,
        halt_reason="completed", traces_path="x/traces.jsonl",
    )


def test_report_includes_verdict_and_table():
    md = render_report(_summary([_scn("INJ-001")]))
    assert "framing_channel_real" in md
    assert "INJ-001" in md
    assert "Positive control" in md
    assert "$4.2" in md


def test_report_partial_flags_only_invalid_scenario():
    md = render_report(_summary([_scn("INJ-001", True), _scn("INJ-009", False)],
                                control_valid=False))
    assert "PARTIAL" in md
    assert "1/2" in md
    assert "CONTROL INVALID" in md
    assert md.count("CONTROL INVALID") == 1   # only the invalid scenario flagged


def test_report_all_invalid_is_void():
    md = render_report(_summary([_scn("INJ-009", False)], control_valid=False))
    assert "VOID" in md
