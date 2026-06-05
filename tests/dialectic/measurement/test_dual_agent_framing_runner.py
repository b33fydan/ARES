import json

from ares.dialectic.measurement.architect_framing_schema import VERDICT_REAL
from ares.dialectic.measurement.dual_agent_framing_runner import (
    run_measurement, run_preflight, total_cycles_for,
)
from ares.dialectic.measurement.dual_agent_framing_schema import DualAgentFramingConfig
from ares.dialectic.measurement.leakage_runner import CycleTrace
from ares.dialectic.scripts.injection_registry_v3 import build_registry_v3


def _dual_trace(*, cost, arch, skep, outcome="threat_dismissed"):
    return CycleTrace(
        cycle_id="c", scenario_id="INJ-XXX", operator_name=None, pair_index=0,
        is_baseline=True, pipeline="llm", architect_message_type="hypothesis",
        architect_confidence=0.9, architect_cited_facts=tuple(arch),
        skeptic_message_type="rebuttal", skeptic_confidence=0.3,
        skeptic_cited_facts=tuple(skep), skeptic_triggered_rules=(),
        oracle_outcome=outcome, oracle_confidence=0.9,
        oracle_supporting_facts=tuple(skep), final_outcome=outcome,
        final_confidence=0.9, cost_usd=cost, tokens_in=10, tokens_out=10, elapsed_ms=100.0,
    )


def _stub_cycle_fn(**kwargs):
    return _dual_trace(cost=0.02, arch=("a1",), skep=("s1",)), 0.02


def test_total_cycles_formula():
    assert total_cycles_for(n_scenarios=17, k=20, n_ops=3) == 17 * 20 * 5


def test_preflight_flags_over_ceiling():
    cfg = DualAgentFramingConfig(
        s059_traces_path="x", scenario_ids=("INJ-001", "INJ-002", "INJ-003"),
        k_resamples=20, max_scenarios=17, cost_ceiling_usd=1.0,
    )
    res = run_preflight(config=cfg, client=object(), cycle_fn=_stub_cycle_fn, n_samples=3)
    assert res["exceeds_ceiling"] is True
    assert res["avg_cost_per_cycle_usd"] == 0.02
    assert res["n_cycles"] == total_cycles_for(n_scenarios=3, k=20, n_ops=3)


def test_preflight_under_ceiling():
    cfg = DualAgentFramingConfig(
        s059_traces_path="x", scenario_ids=("INJ-001",),
        k_resamples=2, max_scenarios=17, cost_ceiling_usd=32.0,
    )
    res = run_preflight(config=cfg, client=object(), cycle_fn=_stub_cycle_fn, n_samples=1)
    assert res["exceeds_ceiling"] is False


def _two_valid_sids(n=2):
    return [s.metadata.scenario_id for s in build_registry_v3().all_scenarios()
            if len(s.packet.get_all_facts()) >= 2][:n]


def _mirror_cycle_fn():
    """baseline: both cite {f1,f2,f3}; framing: architect collapses to {f3},
    skeptic expands to {f1,f2,f3,f4}; control: both cite {zzz} (far from baseline)."""
    def fn(*, scenario, pipeline, client, cycle_id, pair_index, is_baseline, operator_name):
        if operator_name == "__control__":
            return _dual_trace(cost=0.001, arch=("zzz",), skep=("zzz",)), 0.001
        if operator_name is None:
            return _dual_trace(cost=0.001, arch=("f1", "f2", "f3"), skep=("f1", "f2", "f3")), 0.001
        return _dual_trace(cost=0.001, arch=("f3",), skep=("f1", "f2", "f3", "f4")), 0.001
    return fn


def test_dual_measurement_mirror_opposed_and_both_columns_persisted(tmp_path):
    sid = _two_valid_sids(1)[0]
    cfg = DualAgentFramingConfig(
        s059_traces_path="x", scenario_ids=(sid,), k_resamples=4,
        max_scenarios=17, cost_ceiling_usd=32.0, traces_root=tmp_path,
    )
    summary = run_measurement(config=cfg, client=object(), cycle_fn=_mirror_cycle_fn())
    sr = summary.scenario_results[0]
    assert summary.control_valid_architect is True
    assert summary.control_valid_skeptic is True
    assert all(op.verdict == VERDICT_REAL for op in sr.architect.operator_results)
    assert all(op.verdict == VERDICT_REAL for op in sr.skeptic.operator_results)
    assert sr.mirror[0].architect_direction == "collapse"
    assert sr.mirror[0].skeptic_direction == "expand"
    assert sr.mirror[0].mirror_class == "opposed"
    assert summary.halt_reason == "completed"

    traces = (tmp_path / summary.run_id / "traces.jsonl")
    rows = [json.loads(l) for l in traces.read_text(encoding="utf-8").splitlines()]
    assert rows and all("architect_cited_facts" in r and "skeptic_cited_facts" in r for r in rows)
    assert (tmp_path / summary.run_id / "summary.json").exists()


def test_dual_measurement_defers_when_capped(tmp_path):
    sids = _two_valid_sids(2)
    assert len(sids) == 2
    cfg = DualAgentFramingConfig(
        s059_traces_path="x", scenario_ids=tuple(sids), k_resamples=2,
        max_scenarios=1, cost_ceiling_usd=32.0, traces_root=tmp_path,
    )
    summary = run_measurement(config=cfg, client=object(), cycle_fn=_mirror_cycle_fn())
    assert len(summary.scenario_results) == 1
    assert summary.deferred_scenario_ids == (sids[1],)
