from ares.dialectic.measurement.architect_framing_schema import ArchitectFramingConfig
from ares.dialectic.measurement.architect_framing_runner import (
    run_preflight, total_cycles_for,
)
from ares.dialectic.measurement.leakage_runner import CycleTrace


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
    # K*(2 + n_ops) per scenario: baseline K + control K + n_ops*K
    assert total_cycles_for(n_scenarios=3, k=8, n_ops=3) == 3 * 8 * 5


def test_preflight_estimates_and_flags_over_ceiling():
    cfg = ArchitectFramingConfig(
        s059_traces_path="x", scenario_ids=("INJ-001", "INJ-002", "INJ-003"),
        k_resamples=8, max_scenarios=6, cost_ceiling_usd=1.0,  # tiny ceiling
    )
    res = run_preflight(config=cfg, client=object(), cycle_fn=_stub_cycle_fn, n_samples=3)
    # 3 scenarios * 8 * 5 = 120 cycles * $0.02 = $2.4 > $1.0 ceiling
    assert res["exceeds_ceiling"] is True
    assert res["estimated_total_cost_usd"] > 1.0
    assert res["avg_cost_per_cycle_usd"] == 0.02


def test_preflight_under_ceiling():
    cfg = ArchitectFramingConfig(
        s059_traces_path="x", scenario_ids=("INJ-001",),
        k_resamples=2, max_scenarios=6, cost_ceiling_usd=6.0,
    )
    res = run_preflight(config=cfg, client=object(), cycle_fn=_stub_cycle_fn, n_samples=2)
    # 1 scenario * 2 * 5 = 10 cycles * 0.02 = 0.20 < 6.0
    assert res["exceeds_ceiling"] is False
