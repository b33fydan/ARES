"""Narrow-reading characterization runner — Session 060.

Extends the empirical bound on Paper 3's narrow claim from N=2 (Session
059) to N=99 (full ``injection_registry_v3`` × 3 operators on the
deterministic / light path).

This is a **characterization measurement, not a kill-criterion run.**
Discipline differences from 059:

    * No halt on ``kill_fires_narrow == True``. Every fire is captured
      in the per-pair record and the run continues.
    * Light path only. LLM path is skipped (already characterized in
      Session 059 run 2).
    * Cost ceiling lowered to $5 USD (vs. $20 in 059).
    * Headline metric is a continuous rate, not a Boolean verdict.

Reuses Session 059 primitives without modifying them:
    * ``_run_one_cycle`` — single pipeline execution + trace capture
    * ``_compute_pair_leakage`` — per-pair leakage record
    * ``anchor_test_passes`` — `light_skeptic.py:185` verbatim guard
    * ``_new_run_id``, ``_sha256_file``, ``_utc_now_iso``, ``_git_sha``
    * ``CycleTrace``, ``PairLeakageRecord`` — frozen data structures

Output filename pattern: ``LEAKAGE_REPORT_<run_id>_narrow_extended.md``.
"""

from __future__ import annotations

import dataclasses
import json
import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from ares.dialectic.agents.strategies.client_factory import AnyLLMClient, make_client
from ares.dialectic.measurement.influence_leakage import CONFIDENCE_DRIFT_THRESHOLD
from ares.dialectic.measurement.leakage_runner import (
    DEFAULT_TRACES_ROOT,
    HALT_ANCHOR_TEST_FAILURE,
    HALT_COMPLETED,
    HALT_COST_CEILING,
    PRE_REGISTERED_OPERATOR_NAMES,
    CycleTrace,
    PairLeakageRecord,
    _compute_pair_leakage,
    _git_sha,
    _new_run_id,
    _resolve_operator,
    _run_one_cycle,
    _sha256_file,
    _utc_now_iso,
    anchor_test_passes,
)
from ares.dialectic.scripts.injection_registry_v3 import build_registry_v3
from ares.dialectic.scripts.non_interference.paired_scenario_mutator import (
    PairedScenarioMutator,
    SkeletonInvariantError,
)


logger = logging.getLogger("ares.measurement.narrow_extended")


# ---------------------------------------------------------------------------
# Session 060 configuration (locked)
# ---------------------------------------------------------------------------


NARROW_EXT_COST_CEILING_USD: float = 5.0
NARROW_EXT_PREFLIGHT_CYCLES: int = 5
NARROW_EXT_DEFAULT_MODEL: str = "claude-sonnet-4-20250514"


@dataclass
class NarrowCharacterizationConfig:
    """Mutable configuration for one Session 060 characterization run."""

    operator_names: tuple[str, ...] = PRE_REGISTERED_OPERATOR_NAMES
    cost_ceiling_usd: float = NARROW_EXT_COST_CEILING_USD
    model: str = NARROW_EXT_DEFAULT_MODEL
    provider: str = "anthropic"
    traces_root: Path = DEFAULT_TRACES_ROOT
    skip_anchor_check: bool = False  # tests can flip for synthetic runs


# ---------------------------------------------------------------------------
# Narrow drift attribution
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class NarrowDriftRecord:
    """One narrow-fire event, with the specific Light Skeptic field
    that drifted.

    Attributes:
        scenario_id: Baseline scenario_id.
        operator_name: Operator that produced the mutated half.
        pair_index: Stable ordinal for sort order.
        verdict_changed: Did Light Skeptic's REBUTTAL_LIGHT type drift.
        action_changed: Did Light Skeptic's triggered_rules set drift.
        cited_facts_changed: Always False at Light Skeptic by construction
            (it doesn't cite facts) but recorded for completeness.
        confidence_drift_exceeded: |Δ confidence| > drift threshold.
        baseline_triggered_rules: Light Skeptic baseline rules.
        mutated_triggered_rules: Light Skeptic mutated rules.
        baseline_confidence: Baseline Light Skeptic confidence.
        mutated_confidence: Mutated Light Skeptic confidence.
    """

    scenario_id: str
    operator_name: str
    pair_index: int
    verdict_changed: bool
    action_changed: bool
    cited_facts_changed: bool
    confidence_drift_exceeded: bool
    baseline_triggered_rules: tuple[str, ...]
    mutated_triggered_rules: tuple[str, ...]
    baseline_confidence: float
    mutated_confidence: float

    def to_dict(self) -> dict[str, Any]:
        d = dataclasses.asdict(self)
        d["baseline_triggered_rules"] = list(self.baseline_triggered_rules)
        d["mutated_triggered_rules"] = list(self.mutated_triggered_rules)
        return d


def _drift_record_from_pair(
    *,
    baseline: CycleTrace,
    mutated: CycleTrace,
    record: PairLeakageRecord,
) -> NarrowDriftRecord:
    light_layer = next(
        l for l in record.leakages if l.layer == "light_skeptic"
    )
    return NarrowDriftRecord(
        scenario_id=record.scenario_id,
        operator_name=record.operator_name,
        pair_index=record.pair_index,
        verdict_changed=light_layer.verdict_changed,
        action_changed=light_layer.action_changed,
        cited_facts_changed=light_layer.cited_facts_changed,
        confidence_drift_exceeded=light_layer.confidence_drift_exceeded,
        baseline_triggered_rules=baseline.skeptic_triggered_rules,
        mutated_triggered_rules=mutated.skeptic_triggered_rules,
        baseline_confidence=baseline.skeptic_confidence,
        mutated_confidence=mutated.skeptic_confidence,
    )


# ---------------------------------------------------------------------------
# Run summary (immutable, rate-based)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class NarrowExtendedSummary:
    """Frozen result of one Session 060 characterization run."""

    run_id: str
    timestamp_iso: str
    git_sha: str
    provider: str
    model: str
    cycles_completed: int
    total_cost_usd: float
    halt_reason: str
    anchor_test_passed_at_start: bool
    anchor_test_passed_at_end: bool
    operator_set: tuple[str, ...]
    confidence_drift_threshold: float

    n_pairs_attempted: int
    n_pairs_evaluated: int   # pairs where leakage record was computed
    n_pairs_stable_narrow: int   # pairs where kill_fires_narrow == False
    n_pairs_narrow_fired: int   # pairs where kill_fires_narrow == True

    pair_records: tuple[PairLeakageRecord, ...]
    drift_records: tuple[NarrowDriftRecord, ...]
    traces_path: str
    sha256_path: str

    @property
    def narrow_stability_rate(self) -> float:
        if self.n_pairs_evaluated == 0:
            return 0.0
        return self.n_pairs_stable_narrow / self.n_pairs_evaluated

    @property
    def narrow_stability_percent(self) -> float:
        return self.narrow_stability_rate * 100.0

    def per_operator_stability(self) -> dict[str, dict[str, int | float]]:
        """Return per-operator stats: n_evaluated, n_stable, rate."""
        out: dict[str, dict[str, int | float]] = {}
        for op in self.operator_set:
            recs = [r for r in self.pair_records if r.operator_name == op]
            n = len(recs)
            stable = sum(1 for r in recs if not r.kill_fires_narrow)
            out[op] = {
                "n_evaluated": n,
                "n_stable": stable,
                "n_narrow_fired": n - stable,
                "stability_rate": (stable / n) if n else 0.0,
                "stability_percent": (stable / n * 100.0) if n else 0.0,
            }
        return out

    def to_dict(self) -> dict[str, Any]:
        d = dataclasses.asdict(self)
        d["pair_records"] = [r.to_dict() for r in self.pair_records]
        d["drift_records"] = [r.to_dict() for r in self.drift_records]
        d["narrow_stability_rate"] = self.narrow_stability_rate
        d["narrow_stability_percent"] = self.narrow_stability_percent
        d["per_operator_stability"] = self.per_operator_stability()
        return d


# ---------------------------------------------------------------------------
# Pre-flight
# ---------------------------------------------------------------------------


def run_preflight(
    *,
    config: NarrowCharacterizationConfig | None = None,
    client: AnyLLMClient | None = None,
    n_cycles: int = NARROW_EXT_PREFLIGHT_CYCLES,
) -> dict[str, Any]:
    """Run a 5-cycle light-path pre-flight; extrapolate to N=99 + 33
    baselines (132 total cycles) under the $5 cost ceiling.

    Mirrors Session 059's pre-flight in shape but specific to the
    Session 060 cost ceiling and scope (light path only).
    """
    if config is None:
        config = NarrowCharacterizationConfig()
    if client is None:
        client = make_client(config.provider, model=config.model)

    registry = build_registry_v3()
    scenarios = list(registry.all_scenarios())

    # Spread the preflight samples across the corpus deterministically.
    import random as _r
    rng = _r.Random(0)
    sample_scenarios = scenarios.copy()
    rng.shuffle(sample_scenarios)
    samples = sample_scenarios[:n_cycles]

    sample_costs: list[float] = []
    sample_wall_ms: list[float] = []
    pair_idx = 0

    started_total = time.monotonic()
    for scenario in samples:
        cycle_id = f"narrow-preflight-{pair_idx:03d}"
        try:
            trace, cost = _run_one_cycle(
                scenario=scenario,
                pipeline="light",
                client=client,
                cycle_id=cycle_id,
                pair_index=pair_idx,
                is_baseline=True,
                operator_name=None,
            )
        except Exception as exc:
            logger.warning(
                f"narrow preflight cycle {cycle_id} on "
                f"{scenario.metadata.scenario_id} raised "
                f"{type(exc).__name__}: {exc}"
            )
            pair_idx += 1
            continue
        sample_costs.append(cost)
        sample_wall_ms.append(trace.elapsed_ms)
        pair_idx += 1

    total_elapsed_s = time.monotonic() - started_total
    n = len(sample_costs)
    if n == 0:
        return {
            "status": "no_samples",
            "cost_ceiling_usd": config.cost_ceiling_usd,
            "exceeds_ceiling": True,
            "halt_recommendation": "preflight_no_samples",
            "wall_time_s": total_elapsed_s,
        }

    avg_cost = sum(sample_costs) / n
    avg_wall_ms = sum(sample_wall_ms) / n

    # 33 baselines + 99 mutated = 132 light cycles
    estimated_total = 132 * avg_cost
    estimated_wall_s = 132 * (avg_wall_ms / 1000.0)

    exceeds = estimated_total > config.cost_ceiling_usd
    halt = "preflight_over_budget" if exceeds else "preflight_ok"

    return {
        "status": "ok",
        "n_samples": n,
        "avg_cost_per_light_cycle_usd": avg_cost,
        "avg_elapsed_ms_per_light_cycle": avg_wall_ms,
        "estimated_total_cost_usd": estimated_total,
        "estimated_wall_time_s": estimated_wall_s,
        "estimated_wall_time_minutes": estimated_wall_s / 60.0,
        "cost_ceiling_usd": config.cost_ceiling_usd,
        "exceeds_ceiling": exceeds,
        "halt_recommendation": halt,
        "preflight_actual_cost_usd": sum(sample_costs),
        "preflight_wall_time_s": total_elapsed_s,
        "estimated_total_pairs": 99,
    }


# ---------------------------------------------------------------------------
# Full characterization run
# ---------------------------------------------------------------------------


def run_narrow_characterization(
    *,
    config: NarrowCharacterizationConfig | None = None,
    client: AnyLLMClient | None = None,
) -> NarrowExtendedSummary:
    """Execute the N=99 narrow-reading characterization on the light path.

    No halt on narrow fire. Halts only on:
        * Cost ceiling reached (default $5)
        * Anchor test red at start (or at end, only recorded)
    """
    if config is None:
        config = NarrowCharacterizationConfig()
    if client is None:
        client = make_client(config.provider, model=config.model)

    run_id = _new_run_id()
    started_iso = _utc_now_iso()
    git_sha = _git_sha()

    anchor_start = True if config.skip_anchor_check else anchor_test_passes()
    if not anchor_start:
        logger.error(
            "anchor test red at session start; halting before any LLM spend"
        )
        return NarrowExtendedSummary(
            run_id=run_id,
            timestamp_iso=started_iso,
            git_sha=git_sha,
            provider=config.provider,
            model=config.model,
            cycles_completed=0,
            total_cost_usd=0.0,
            halt_reason=HALT_ANCHOR_TEST_FAILURE,
            anchor_test_passed_at_start=False,
            anchor_test_passed_at_end=False,
            operator_set=config.operator_names,
            confidence_drift_threshold=CONFIDENCE_DRIFT_THRESHOLD,
            n_pairs_attempted=0,
            n_pairs_evaluated=0,
            n_pairs_stable_narrow=0,
            n_pairs_narrow_fired=0,
            pair_records=(),
            drift_records=(),
            traces_path="",
            sha256_path="",
        )

    registry = build_registry_v3()
    scenarios = list(registry.all_scenarios())

    operators_by_name = {
        name: _resolve_operator(name) for name in config.operator_names
    }
    mutator = PairedScenarioMutator(
        operators=tuple(operators_by_name.values())
    )

    traces_dir = config.traces_root / run_id
    traces_dir.mkdir(parents=True, exist_ok=True)
    traces_path = traces_dir / "traces.jsonl"

    pair_records: list[PairLeakageRecord] = []
    drift_records: list[NarrowDriftRecord] = []
    cycles_completed = 0
    total_cost = 0.0
    halt_reason = HALT_COMPLETED
    pair_index = 0
    n_pairs_attempted = 0

    def _write_trace(trace: CycleTrace) -> None:
        with traces_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(trace.to_dict(), sort_keys=True) + "\n")

    # Per scenario: one light baseline + N operators on light path.
    # No narrow-fire halt; runs to N=99 or cost ceiling.
    for scenario in scenarios:
        if total_cost >= config.cost_ceiling_usd:
            halt_reason = HALT_COST_CEILING
            break

        # Baseline cycle (light pipeline)
        baseline_cycle_id = (
            f"narrow-baseline-{scenario.metadata.scenario_id}-light"
        )
        try:
            baseline_trace, baseline_cost = _run_one_cycle(
                scenario=scenario,
                pipeline="light",
                client=client,
                cycle_id=baseline_cycle_id,
                pair_index=pair_index,
                is_baseline=True,
                operator_name=None,
            )
        except Exception as exc:
            logger.warning(
                f"baseline cycle {baseline_cycle_id} raised "
                f"{type(exc).__name__}: {exc}"
            )
            continue
        _write_trace(baseline_trace)
        cycles_completed += 1
        total_cost += baseline_cost

        if total_cost >= config.cost_ceiling_usd:
            halt_reason = HALT_COST_CEILING
            break

        # Mutated cycles — one per operator. NO HALT ON NARROW FIRE.
        for op_name in config.operator_names:
            n_pairs_attempted += 1
            if total_cost >= config.cost_ceiling_usd:
                halt_reason = HALT_COST_CEILING
                break

            try:
                pair = mutator.mutate(scenario, op_name)
            except SkeletonInvariantError as exc:
                if "no Fact value_hash differs" in str(exc):
                    logger.info(
                        f"operator {op_name} no-op on "
                        f"{scenario.metadata.scenario_id}; skipping"
                    )
                    continue
                raise

            mutated_cycle_id = (
                f"narrow-mutated-{scenario.metadata.scenario_id}-{op_name}-light"
            )
            try:
                mutated_trace, mutated_cost = _run_one_cycle(
                    scenario=pair.mutated_scenario,
                    pipeline="light",
                    client=client,
                    cycle_id=mutated_cycle_id,
                    pair_index=pair_index,
                    is_baseline=False,
                    operator_name=op_name,
                )
            except Exception as exc:
                logger.warning(
                    f"mutated cycle {mutated_cycle_id} raised "
                    f"{type(exc).__name__}: {exc}"
                )
                continue
            _write_trace(mutated_trace)
            cycles_completed += 1
            total_cost += mutated_cost

            record = _compute_pair_leakage(
                baseline=baseline_trace,
                mutated=mutated_trace,
                pair_index=pair_index,
            )
            pair_records.append(record)
            pair_index += 1

            # Capture narrow fires for the per-pair drift table.
            # DO NOT HALT. This is characterization mode.
            if record.kill_fires_narrow:
                drift_records.append(
                    _drift_record_from_pair(
                        baseline=baseline_trace,
                        mutated=mutated_trace,
                        record=record,
                    )
                )

        if halt_reason == HALT_COST_CEILING:
            break

    sha256_path = traces_dir / "traces.sha256"
    if traces_path.exists():
        digest = _sha256_file(traces_path)
        sha256_path.write_text(
            f"{digest}  {traces_path.name}\n", encoding="utf-8"
        )

    anchor_end = True if config.skip_anchor_check else anchor_test_passes()

    n_evaluated = len(pair_records)
    n_stable = sum(1 for r in pair_records if not r.kill_fires_narrow)
    n_fired = n_evaluated - n_stable

    return NarrowExtendedSummary(
        run_id=run_id,
        timestamp_iso=started_iso,
        git_sha=git_sha,
        provider=config.provider,
        model=config.model,
        cycles_completed=cycles_completed,
        total_cost_usd=total_cost,
        halt_reason=halt_reason,
        anchor_test_passed_at_start=anchor_start,
        anchor_test_passed_at_end=anchor_end,
        operator_set=config.operator_names,
        confidence_drift_threshold=CONFIDENCE_DRIFT_THRESHOLD,
        n_pairs_attempted=n_pairs_attempted,
        n_pairs_evaluated=n_evaluated,
        n_pairs_stable_narrow=n_stable,
        n_pairs_narrow_fired=n_fired,
        pair_records=tuple(pair_records),
        drift_records=tuple(drift_records),
        traces_path=str(traces_path),
        sha256_path=str(sha256_path),
    )


__all__ = [
    "NARROW_EXT_COST_CEILING_USD",
    "NARROW_EXT_DEFAULT_MODEL",
    "NARROW_EXT_PREFLIGHT_CYCLES",
    "NarrowCharacterizationConfig",
    "NarrowDriftRecord",
    "NarrowExtendedSummary",
    "run_narrow_characterization",
    "run_preflight",
]
