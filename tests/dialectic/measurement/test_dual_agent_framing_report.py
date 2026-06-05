from ares.dialectic.measurement.architect_framing_schema import (
    OperatorFramingResult, VERDICT_REAL,
)
from ares.dialectic.measurement.dual_agent_framing_report import (
    render_report, write_report,
)
from ares.dialectic.measurement.dual_agent_framing_schema import (
    AGENT_ARCHITECT, AGENT_SKEPTIC, AgentFramingResult, DualAgentFramingSummary,
    MirrorRecord, ScenarioDualFramingResult,
)


def _op(name, verdict=VERDICT_REAL):
    return OperatorFramingResult(
        operator_name=name, n_cross=16, cross_median=0.5, within_median=0.0,
        effect_size=0.5, p_value=0.001, ci_low=0.3, ci_high=0.7, verdict=verdict,
    )


def _summary(*, skep_control_ok=True, traces_path="t/traces.jsonl"):
    sr = ScenarioDualFramingResult(
        scenario_id="INJ-020",
        architect=AgentFramingResult(
            agent=AGENT_ARCHITECT, within_distances=(0.0,), control_distances=(1.0,),
            control_exceeds_noise=True, operator_results=(_op("framing_prefix_v1"),)),
        skeptic=AgentFramingResult(
            agent=AGENT_SKEPTIC, within_distances=(0.0,), control_distances=(1.0,),
            control_exceeds_noise=skep_control_ok, operator_results=(_op("framing_prefix_v1"),)),
        mirror=(MirrorRecord(
            scenario_id="INJ-020", operator_name="framing_prefix_v1",
            architect_jaccard=0.8, architect_direction="collapse",
            skeptic_jaccard=0.4, skeptic_direction="expand", mirror_class="opposed"),),
        skipped_operators=(),
    )
    return DualAgentFramingSummary(
        run_id="20260605-000000-abcdef", timestamp_iso="2026-06-05T00:00:00Z",
        git_sha="deadbee", provider="anthropic", model="claude-sonnet-4-20250514",
        k_resamples=20, operator_names=("framing_prefix_v1",), scenario_results=(sr,),
        deferred_scenario_ids=(), control_valid_architect=True,
        control_valid_skeptic=skep_control_ok, total_cost_usd=24.8,
        halt_reason="completed", traces_path=traces_path,
    )


def test_render_contains_both_agent_tables_and_mirror():
    text = render_report(_summary())
    assert "Architect path" in text
    assert "Skeptic path" in text
    assert "mirror" in text.lower()
    assert "opposed" in text
    assert "INJ-020" in text


def test_render_flags_control_unvalidated_agent():
    text = render_report(_summary(skep_control_ok=False))
    assert "control-unvalidated" in text
    assert "INJ-020 (skeptic)" in text


def test_write_report_writes_md_next_to_traces(tmp_path):
    traces = tmp_path / "traces.jsonl"
    traces.write_text("", encoding="utf-8")
    summary = _summary(traces_path=str(traces))
    out = write_report(summary)
    assert out.endswith(".md")
    assert "DUAL_AGENT_FRAMING_" in out
    from pathlib import Path
    assert Path(out).exists()
