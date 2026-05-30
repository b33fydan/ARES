from ares.dialectic.measurement.architect_framing_report import render_report
from ares.dialectic.measurement.architect_framing_schema import (
    ArchitectFramingSummary, ScenarioFramingResult, OperatorFramingResult,
    VERDICT_REAL,
)


def _summary(control_valid=True, verdict=VERDICT_REAL):
    op = OperatorFramingResult(
        operator_name="framing_prefix_v1", n_cross=64, cross_median=0.5,
        within_median=0.1, effect_size=0.4, p_value=0.01, ci_low=0.2, ci_high=0.6,
        verdict=verdict,
    )
    sr = ScenarioFramingResult(
        scenario_id="INJ-001", within_distances=(0.1,), control_distances=(0.9,),
        control_exceeds_noise=True, operator_results=(op,), skipped_operators=(),
    )
    return ArchitectFramingSummary(
        run_id="r1", timestamp_iso="t", git_sha="abc", provider="anthropic",
        model="claude-sonnet-4-20250514", k_resamples=8,
        operator_names=("framing_prefix_v1",), scenario_results=(sr,),
        deferred_scenario_ids=(), control_valid=control_valid, total_cost_usd=4.2,
        halt_reason="completed", traces_path="x/traces.jsonl",
    )


def test_report_includes_verdict_and_control_banner():
    md = render_report(_summary())
    assert "framing_channel_real" in md
    assert "INJ-001" in md
    assert "Positive control" in md
    assert "$4.2" in md


def test_report_warns_when_control_invalid():
    md = render_report(_summary(control_valid=False))
    assert "VOID" in md or "void" in md
