"""Runner for the Architect-path framing-sensitivity measurement (Session 077).

Reuses leakage_runner._run_one_cycle (pipeline='llm') as the resample primitive,
so the noise floor is measured on the SAME cycle that produced the 60-78% figure.
The orchestration accepts an injectable cycle_fn for offline testing.
"""
from __future__ import annotations

import logging
from typing import Any, Callable

from ares.dialectic.measurement.architect_framing_schema import ArchitectFramingConfig
from ares.dialectic.measurement.leakage_runner import _run_one_cycle

logger = logging.getLogger("ares.measurement.architect_framing")

CycleFn = Callable[..., tuple[Any, float]]   # mirrors _run_one_cycle


def total_cycles_for(*, n_scenarios: int, k: int, n_ops: int) -> int:
    """K baseline + K control + n_ops*K framing, per scenario."""
    return n_scenarios * k * (2 + n_ops)


def run_preflight(
    *,
    config: ArchitectFramingConfig,
    client: Any,
    cycle_fn: CycleFn = _run_one_cycle,
    n_samples: int = 3,
) -> dict[str, Any]:
    """Sample a few llm cycles, estimate per-cycle cost, extrapolate the full run."""
    from ares.dialectic.scripts.injection_registry_v3 import build_registry_v3

    registry = build_registry_v3()
    by_id = {s.metadata.scenario_id: s for s in registry.all_scenarios()}
    sample_ids = [sid for sid in config.scenario_ids if sid in by_id][:n_samples]

    sample_costs: list[float] = []
    for i, sid in enumerate(sample_ids):
        try:
            _, cost = cycle_fn(
                scenario=by_id[sid], pipeline="llm", client=client,
                cycle_id=f"preflight-{i:02d}", pair_index=i,
                is_baseline=True, operator_name=None,
            )
            sample_costs.append(cost)
        except Exception as exc:  # noqa: BLE001
            logger.warning("preflight sample %s failed: %s", sid, exc)

    n_scenarios = min(len(config.scenario_ids), config.max_scenarios)
    n_cycles = total_cycles_for(
        n_scenarios=n_scenarios, k=config.k_resamples, n_ops=len(config.operator_names)
    )
    if not sample_costs:
        return {"status": "no_samples", "estimated_total_cost_usd": None,
                "exceeds_ceiling": True, "n_cycles": n_cycles,
                "cost_ceiling_usd": config.cost_ceiling_usd, "avg_cost_per_cycle_usd": None}

    avg = sum(sample_costs) / len(sample_costs)
    est = avg * n_cycles
    return {
        "status": "ok",
        "avg_cost_per_cycle_usd": avg,
        "n_cycles": n_cycles,
        "n_scenarios": n_scenarios,
        "estimated_total_cost_usd": est,
        "cost_ceiling_usd": config.cost_ceiling_usd,
        "exceeds_ceiling": est > config.cost_ceiling_usd,
    }
