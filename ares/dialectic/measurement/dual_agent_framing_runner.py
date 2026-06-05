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
