"""Runner for the dual-agent framing-sensitivity measurement (Session 084).

Reuses leakage_runner._run_one_cycle (pipeline='llm') as the resample primitive,
recording BOTH architect_cited_facts and skeptic_cited_facts per cycle, so one run
yields the Architect-path verdict, the Skeptic-path verdict, and the paired mirror.
Accepts an injectable cycle_fn for offline testing.
"""
from __future__ import annotations

import dataclasses
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
    CONDITION_BASELINE, CONDITION_CONTROL, framing_condition,
)
from ares.dialectic.measurement.architect_framing_selection import select_diverging_scenarios
from ares.dialectic.measurement.dual_agent_framing_mirror import build_mirror_record
from ares.dialectic.measurement.dual_agent_framing_schema import (
    AGENT_ARCHITECT, AGENT_SKEPTIC, AgentFramingResult, DualAgentFramingConfig,
    DualAgentFramingSummary, DualAgentResampleRecord, ScenarioDualFramingResult,
)
from ares.dialectic.measurement.leakage_runner import _resolve_operator, _run_one_cycle
from ares.dialectic.scripts.injection_registry_v3 import build_registry_v3
from ares.dialectic.scripts.non_interference.paired_scenario_mutator import (
    PairedScenarioMutator, SkeletonInvariantError,
)

logger = logging.getLogger("ares.measurement.dual_agent_framing")

CycleFn = Callable[..., tuple[Any, float]]
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


def _selected_ids(config: DualAgentFramingConfig, by_id: dict) -> list[str]:
    selected = list(config.scenario_ids) or select_diverging_scenarios(config.s059_traces_path)
    return [sid for sid in selected if sid in by_id]


def _resample_dual(scenario, *, client, cycle_fn, condition, operator_name, k, sink):
    """Run k llm cycles; return (arch_sets, skep_sets) as list[frozenset]; append records."""
    arch_sets: list[frozenset[str]] = []
    skep_sets: list[frozenset[str]] = []
    for j in range(k):
        trace, cost = cycle_fn(
            scenario=scenario, pipeline="llm", client=client,
            cycle_id=f"{scenario.metadata.scenario_id}-{condition}-{j}-{uuid.uuid4().hex[:4]}",
            pair_index=j, is_baseline=(condition == CONDITION_BASELINE),
            operator_name=operator_name,
        )
        a = frozenset(trace.architect_cited_facts)
        s = frozenset(trace.skeptic_cited_facts)
        arch_sets.append(a)
        skep_sets.append(s)
        sink.append(DualAgentResampleRecord(
            scenario_id=scenario.metadata.scenario_id, condition=condition,
            resample_index=j,
            architect_cited_facts=tuple(sorted(a)),
            skeptic_cited_facts=tuple(sorted(s)),
            architect_confidence=trace.architect_confidence,
            skeptic_confidence=trace.skeptic_confidence,
            final_outcome=trace.final_outcome,
            oracle_supporting_facts=tuple(sorted(trace.oracle_supporting_facts)),
            cost_usd=cost, elapsed_ms=trace.elapsed_ms,
        ))
    return arch_sets, skep_sets


def run_preflight(
    *, config: DualAgentFramingConfig, client: Any,
    cycle_fn: CycleFn = _run_one_cycle, n_samples: int = 3,
) -> dict[str, Any]:
    registry = build_registry_v3()
    by_id = {s.metadata.scenario_id: s for s in registry.all_scenarios()}
    selected = _selected_ids(config, by_id)
    sample_ids = selected[:n_samples]

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

    n_scenarios = min(len(selected), config.max_scenarios)
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
        "status": "ok", "avg_cost_per_cycle_usd": avg, "n_cycles": n_cycles,
        "n_scenarios": n_scenarios, "estimated_total_cost_usd": est,
        "cost_ceiling_usd": config.cost_ceiling_usd,
        "exceeds_ceiling": est > config.cost_ceiling_usd,
    }


def run_measurement(
    *, config: DualAgentFramingConfig, client=None, cycle_fn: CycleFn = _run_one_cycle,
) -> DualAgentFramingSummary:
    if client is None:
        client = make_client(config.provider, model=config.model)

    run_id = f"{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"
    registry = build_registry_v3()
    by_id = {s.metadata.scenario_id: s for s in registry.all_scenarios()}

    selected = _selected_ids(config, by_id)
    to_run = selected[: config.max_scenarios]
    deferred = tuple(selected[config.max_scenarios:])

    mutator = PairedScenarioMutator(
        operators=tuple(_resolve_operator(n) for n in config.operator_names)
    )

    records: list[DualAgentResampleRecord] = []
    scenario_results: list[ScenarioDualFramingResult] = []
    total_cost = 0.0
    halt_reason = "completed"

    for sid in to_run:
        if total_cost >= config.cost_ceiling_usd:
            halt_reason = "cost_ceiling"
            deferred = deferred + (sid,)
            continue
        base = by_id[sid]
        arch_base, skep_base = _resample_dual(
            base, client=client, cycle_fn=cycle_fn, condition=CONDITION_BASELINE,
            operator_name=None, k=config.k_resamples, sink=records)
        arch_within = within_distances(arch_base)
        skep_within = within_distances(skep_base)

        arch_ops, skep_ops, mirror_records, skipped = [], [], [], []
        for op_name in config.operator_names:
            try:
                pair = mutator.mutate(base, op_name)
            except SkeletonInvariantError:
                skipped.append(op_name)
                continue
            arch_framed, skep_framed = _resample_dual(
                pair.mutated_scenario, client=client, cycle_fn=cycle_fn,
                condition=framing_condition(op_name), operator_name=op_name,
                k=config.k_resamples, sink=records)
            arch_ops.append(classify_operator(
                cross_distances(arch_base, arch_framed), arch_within,
                seed=config.seed, operator_name=op_name))
            skep_ops.append(classify_operator(
                cross_distances(skep_base, skep_framed), skep_within,
                seed=config.seed, operator_name=op_name))
            mirror_records.append(build_mirror_record(
                scenario_id=sid, operator_name=op_name,
                arch_base_sets=arch_base, arch_framed_sets=arch_framed,
                skep_base_sets=skep_base, skep_framed_sets=skep_framed))

        # single joint positive control: drop the most-jointly-cited fact.
        arch_ctrl_cross: list[float] = []
        skep_ctrl_cross: list[float] = []
        arch_ctrl_exceeds = skep_ctrl_exceeds = False
        try:
            drop_fid = choose_control_drop_fact(base.packet, arch_base + skep_base)
            ctrl = build_positive_control_scenario(base, drop_fact_id=drop_fid)
            arch_ctrl, skep_ctrl = _resample_dual(
                ctrl, client=client, cycle_fn=cycle_fn, condition=CONDITION_CONTROL,
                operator_name=_CONTROL_SENTINEL, k=config.k_resamples, sink=records)
            arch_ctrl_cross = cross_distances(arch_base, arch_ctrl)
            skep_ctrl_cross = cross_distances(skep_base, skep_ctrl)
            acv = classify_operator(arch_ctrl_cross, arch_within,
                                    seed=config.seed, operator_name=_CONTROL_SENTINEL)
            scv = classify_operator(skep_ctrl_cross, skep_within,
                                    seed=config.seed, operator_name=_CONTROL_SENTINEL)
            arch_ctrl_exceeds = acv.effect_size > 0.0 and acv.p_value < 0.05
            skep_ctrl_exceeds = scv.effect_size > 0.0 and scv.p_value < 0.05
        except ValueError:
            pass

        scenario_results.append(ScenarioDualFramingResult(
            scenario_id=sid,
            architect=AgentFramingResult(
                agent=AGENT_ARCHITECT, within_distances=tuple(arch_within),
                control_distances=tuple(arch_ctrl_cross),
                control_exceeds_noise=arch_ctrl_exceeds, operator_results=tuple(arch_ops)),
            skeptic=AgentFramingResult(
                agent=AGENT_SKEPTIC, within_distances=tuple(skep_within),
                control_distances=tuple(skep_ctrl_cross),
                control_exceeds_noise=skep_ctrl_exceeds, operator_results=tuple(skep_ops)),
            mirror=tuple(mirror_records),
            skipped_operators=tuple(skipped),
        ))
        total_cost = sum(r.cost_usd for r in records)

    traces_dir = Path(config.traces_root) / run_id
    traces_dir.mkdir(parents=True, exist_ok=True)
    traces_path = traces_dir / "traces.jsonl"
    with traces_path.open("w", encoding="utf-8") as fh:
        for r in records:
            fh.write(json.dumps(r.to_dict(), sort_keys=True) + "\n")

    control_valid_architect = bool(scenario_results) and all(
        s.architect.control_exceeds_noise for s in scenario_results)
    control_valid_skeptic = bool(scenario_results) and all(
        s.skeptic.control_exceeds_noise for s in scenario_results)

    summary = DualAgentFramingSummary(
        run_id=run_id,
        timestamp_iso=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        git_sha=_git_sha(), provider=config.provider, model=config.model,
        k_resamples=config.k_resamples, operator_names=config.operator_names,
        scenario_results=tuple(scenario_results), deferred_scenario_ids=deferred,
        control_valid_architect=control_valid_architect,
        control_valid_skeptic=control_valid_skeptic,
        total_cost_usd=total_cost, halt_reason=halt_reason, traces_path=str(traces_path),
    )
    (traces_dir / "summary.json").write_text(
        json.dumps(dataclasses.asdict(summary), indent=2, sort_keys=True), encoding="utf-8")
    return summary
