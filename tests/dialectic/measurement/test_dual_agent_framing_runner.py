import json

from ares.dialectic.measurement.architect_framing_schema import VERDICT_REAL
from ares.dialectic.measurement.dual_agent_framing_runner import (
    run_preflight, total_cycles_for,
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
