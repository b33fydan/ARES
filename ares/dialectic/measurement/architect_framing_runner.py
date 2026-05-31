"""Runner for the Architect-path framing-sensitivity measurement (Session 077).

Reuses leakage_runner._run_one_cycle (pipeline='llm') as the resample primitive,
so the noise floor is measured on the SAME cycle that produced the 60-78% figure.
The orchestration accepts an injectable cycle_fn for offline testing.
"""
from __future__ import annotations

import json
import logging
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from ares.dialectic.agents.strategies.client_factory import make_client
from ares.dialectic.measurement.architect_framing_control import (
    build_positive_control_scenario, choose_control_drop_fact,
)
from ares.dialectic.measurement.architect_framing_metrics import (
    classify_operator, cross_distances, within_distances,
)
from ares.dialectic.measurement.architect_framing_schema import (
    ArchitectFramingConfig, ArchitectFramingSummary, CONDITION_BASELINE, CONDITION_CONTROL,
    ResampleRecord, ScenarioFramingResult, framing_condition,
)
from ares.dialectic.measurement.architect_framing_selection import select_diverging_scenarios
from ares.dialectic.measurement.leakage_runner import _resolve_operator, _run_one_cycle
from ares.dialectic.scripts.injection_registry_v3 import build_registry_v3
from ares.dialectic.scripts.non_interference.paired_scenario_mutator import (
    PairedScenarioMutator, SkeletonInvariantError,
)

logger = logging.getLogger("ares.measurement.architect_framing")

CycleFn = Callable[..., tuple[Any, float]]   # mirrors _run_one_cycle
_CONTROL_SENTINEL = "__control__"


def total_cycles_for(*, n_scenarios: int, k: int, n_ops: int) -> int:
    """K baseline + K control + n_ops*K framing, per scenario."""
    return n_scenarios * k * (2 + n_ops)


def _git_sha() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"], text=True
        ).strip()
    except Exception:  # noqa: BLE001
        return "unknown"


def run_preflight(
    *,
    config: ArchitectFramingConfig,
    client: Any,
    cycle_fn: CycleFn = _run_one_cycle,
    n_samples: int = 3,
) -> dict[str, Any]:
    """Sample a few llm cycles, estimate per-cycle cost, extrapolate the full run."""
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


def _resample(scenario, *, client, cycle_fn, condition, operator_name, k, sink):
    """Run k llm cycles on `scenario`; return list[frozenset] of cited facts."""
    sets: list[frozenset[str]] = []
    for j in range(k):
        trace, cost = cycle_fn(
            scenario=scenario, pipeline="llm", client=client,
            cycle_id=f"{scenario.metadata.scenario_id}-{condition}-{j}-{uuid.uuid4().hex[:4]}",
            pair_index=j, is_baseline=(condition == CONDITION_BASELINE),
            operator_name=operator_name,
        )
        cited = frozenset(trace.architect_cited_facts)
        sets.append(cited)
        sink.append(ResampleRecord(
            scenario_id=scenario.metadata.scenario_id, condition=condition,
            resample_index=j, architect_cited_facts=tuple(sorted(cited)),
            architect_confidence=trace.architect_confidence,
            final_outcome=trace.final_outcome,
            oracle_supporting_facts=tuple(sorted(trace.oracle_supporting_facts)),
            cost_usd=cost, elapsed_ms=trace.elapsed_ms,
        ))
    return sets


def run_measurement(
    *, config: ArchitectFramingConfig, client=None, cycle_fn: CycleFn = _run_one_cycle,
) -> ArchitectFramingSummary:
    if client is None:
        client = make_client(config.provider, model=config.model)

    run_id = f"{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"
    registry = build_registry_v3()
    by_id = {s.metadata.scenario_id: s for s in registry.all_scenarios()}

    selected = list(config.scenario_ids) or select_diverging_scenarios(config.s059_traces_path)
    selected = [sid for sid in selected if sid in by_id]
    to_run = selected[: config.max_scenarios]
    deferred = tuple(selected[config.max_scenarios:])

    mutator = PairedScenarioMutator(
        operators=tuple(_resolve_operator(n) for n in config.operator_names)
    )

    records: list[ResampleRecord] = []
    scenario_results: list[ScenarioFramingResult] = []
    total_cost = 0.0
    halt_reason = "completed"

    for sid in to_run:
        if total_cost >= config.cost_ceiling_usd:
            halt_reason = "cost_ceiling"
            deferred = deferred + (sid,)
            continue
        base = by_id[sid]
        base_sets = _resample(base, client=client, cycle_fn=cycle_fn,
                              condition=CONDITION_BASELINE, operator_name=None,
                              k=config.k_resamples, sink=records)
        within = within_distances(base_sets)

        op_results = []
        skipped = []
        for op_name in config.operator_names:
            try:
                pair = mutator.mutate(base, op_name)
            except SkeletonInvariantError:
                skipped.append(op_name)        # no-op mutation on this scenario
                continue
            mut_sets = _resample(pair.mutated_scenario, client=client, cycle_fn=cycle_fn,
                                 condition=framing_condition(op_name), operator_name=op_name,
                                 k=config.k_resamples, sink=records)
            cross = cross_distances(base_sets, mut_sets)
            op_results.append(classify_operator(cross, within, seed=config.seed,
                                                 operator_name=op_name))

        # positive control: drop a fact the baseline Architect actually cites,
        # then require its divergence to significantly exceed the noise floor.
        try:
            drop_fid = choose_control_drop_fact(base.packet, base_sets)
            ctrl = build_positive_control_scenario(base, drop_fact_id=drop_fid)
            ctrl_sets = _resample(ctrl, client=client, cycle_fn=cycle_fn,
                                  condition=CONDITION_CONTROL, operator_name=_CONTROL_SENTINEL,
                                  k=config.k_resamples, sink=records)
            ctrl_cross = cross_distances(base_sets, ctrl_sets)
            cv = classify_operator(ctrl_cross, within, seed=config.seed,
                                   operator_name=_CONTROL_SENTINEL)
            control_exceeds = cv.effect_size > 0.0 and cv.p_value < 0.05
        except ValueError:
            ctrl_cross, control_exceeds = [], False

        scenario_results.append(ScenarioFramingResult(
            scenario_id=sid, within_distances=tuple(within),
            control_distances=tuple(ctrl_cross), control_exceeds_noise=control_exceeds,
            operator_results=tuple(op_results), skipped_operators=tuple(skipped),
        ))
        total_cost = sum(r.cost_usd for r in records)

    # persist traces
    traces_dir = Path(config.traces_root) / run_id
    traces_dir.mkdir(parents=True, exist_ok=True)
    traces_path = traces_dir / "traces.jsonl"
    with traces_path.open("w", encoding="utf-8") as fh:
        for r in records:
            fh.write(json.dumps(r.to_dict(), sort_keys=True) + "\n")

    control_valid = bool(scenario_results) and all(
        s.control_exceeds_noise for s in scenario_results
    )
    return ArchitectFramingSummary(
        run_id=run_id, timestamp_iso=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        git_sha=_git_sha(), provider=config.provider, model=config.model,
        k_resamples=config.k_resamples, operator_names=config.operator_names,
        scenario_results=tuple(scenario_results), deferred_scenario_ids=deferred,
        control_valid=control_valid, total_cost_usd=total_cost,
        halt_reason=halt_reason, traces_path=str(traces_path),
    )
