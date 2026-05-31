from ares.dialectic.measurement.architect_framing_schema import (
    ArchitectFramingConfig, VERDICT_REAL,
)
from ares.dialectic.measurement.architect_framing_runner import (
    run_preflight, total_cycles_for, run_measurement,
)
from ares.dialectic.measurement.leakage_runner import CycleTrace
from ares.dialectic.scripts.injection_registry_v3 import build_registry_v3


def _trace(cost=0.02, cited=("f1",)):
    return CycleTrace(
        cycle_id="c", scenario_id="INJ-001", operator_name=None, pair_index=0,
        is_baseline=True, pipeline="llm", architect_message_type="hypothesis",
        architect_confidence=0.9, architect_cited_facts=tuple(cited),
        skeptic_message_type="rebuttal", skeptic_confidence=0.3,
        skeptic_cited_facts=(), skeptic_triggered_rules=(),
        oracle_outcome="threat_confirmed", oracle_confidence=0.9,
        oracle_supporting_facts=tuple(cited), final_outcome="threat_confirmed",
        final_confidence=0.9, cost_usd=cost, tokens_in=10, tokens_out=10, elapsed_ms=100.0,
    )


def _stub_cycle_fn(**kwargs):
    return _trace(cost=0.02), 0.02


def test_total_cycles_formula():
    assert total_cycles_for(n_scenarios=3, k=8, n_ops=3) == 3 * 8 * 5


def test_preflight_estimates_and_flags_over_ceiling():
    cfg = ArchitectFramingConfig(
        s059_traces_path="x", scenario_ids=("INJ-001", "INJ-002", "INJ-003"),
        k_resamples=8, max_scenarios=6, cost_ceiling_usd=1.0,
    )
    res = run_preflight(config=cfg, client=object(), cycle_fn=_stub_cycle_fn, n_samples=3)
    assert res["exceeds_ceiling"] is True
    assert res["estimated_total_cost_usd"] > 1.0
    assert res["avg_cost_per_cycle_usd"] == 0.02


def test_preflight_under_ceiling():
    cfg = ArchitectFramingConfig(
        s059_traces_path="x", scenario_ids=("INJ-001",),
        k_resamples=2, max_scenarios=6, cost_ceiling_usd=6.0,
    )
    res = run_preflight(config=cfg, client=object(), cycle_fn=_stub_cycle_fn, n_samples=2)
    assert res["exceeds_ceiling"] is False


def _make_condition_aware_cycle_fn():
    """Stub: baseline/framing return a stable cited set; control returns a
    very different set -> control must exceed noise, framing within noise."""
    def fn(*, scenario, pipeline, client, cycle_id, pair_index, is_baseline, operator_name):
        if operator_name == "__control__":
            cited = ("zzz",)
        else:
            cited = ("f1", "f2", "f3")
        return _trace(cost=0.001, cited=cited), 0.001
    return fn


def test_run_measurement_offline_control_fires_framing_quiet(tmp_path):
    sid = next(s.metadata.scenario_id for s in build_registry_v3().all_scenarios()
               if len(s.packet.get_all_facts()) >= 2)
    cfg = ArchitectFramingConfig(
        s059_traces_path="x", scenario_ids=(sid,), k_resamples=4,
        max_scenarios=6, cost_ceiling_usd=6.0, traces_root=tmp_path,
    )
    summary = run_measurement(config=cfg, client=object(),
                              cycle_fn=_make_condition_aware_cycle_fn())
    assert summary.control_valid is True
    sr = summary.scenario_results[0]
    assert sr.control_exceeds_noise is True
    assert all(op.verdict != VERDICT_REAL for op in sr.operator_results)
    assert summary.halt_reason == "completed"
    assert (tmp_path / summary.run_id / "traces.jsonl").exists()
