"""InfluenceLeakage runner — Session 059.

Pair iteration over (scenario, operator) for the three pre-registered
clean operators. Per pair: run baseline + mutated through both pipelines
(LLM Skeptic full + Light Skeptic deterministic), capture per-layer
trace data, compute :class:`InfluenceLeakage` per layer, persist as
JSONL, track aggregate USD cost, halt on any of:

    * cost ceiling reached (default $20)
    * deterministic path kill criterion fires (light path leak > 0)
    * anchor test red

Cost tracking is implemented by injecting a shared
:class:`LLMCallLogger` into every LLM strategy in a cycle and reading
``total_cost_estimate_usd`` after the cycle returns. No edits to existing
runner signatures; this module wraps and observes only.

Pre-flight mode runs a small subset (default 5 cycles) to estimate
aggregate cost; the runner halts after pre-flight unless explicitly
told to proceed.
"""

from __future__ import annotations

import dataclasses
import json
import logging
import os
import random
import subprocess
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional

from ares.dialectic.agents.strategies.client import AnthropicClient
from ares.dialectic.agents.strategies.guarded_cycle import (
    GuardedCycleResult,
    run_guarded_cycle,
)
from ares.dialectic.agents.strategies.light_guarded_cycle import (
    LightGuardedCycleResult,
    run_light_guarded_cycle,
)
from ares.dialectic.agents.strategies.llm_strategy import (
    LLMExplanationFinder,
    LLMNarrativeGenerator,
    LLMThreatAnalyzer,
)
from ares.dialectic.agents.strategies.observability import LLMCallLogger
from ares.dialectic.coordinator.firewall import OracleFirewall
from ares.dialectic.measurement.influence_leakage import (
    CONFIDENCE_DRIFT_THRESHOLD,
    InfluenceLeakage,
    KILL_THRESHOLD,
    cited_facts_changed,
    confidence_drift_exceeds_threshold,
)
from ares.dialectic.scripts.injection_registry_v3 import build_registry_v3
from ares.dialectic.scripts.non_interference.paired_scenario_mutator import (
    OPERATORS_V1,
    MutationOperator,
    PairedScenarioMutator,
    SkeletonInvariantError,
)
from ares.dialectic.scripts.non_interference.paired_scenario_mutator_v2 import (
    OPERATORS_V2,
)
from ares.dialectic.scripts.scenario_corpus import BenchmarkScenario


logger = logging.getLogger("ares.measurement.leakage")


# ---------------------------------------------------------------------------
# Pre-registered run configuration (locked)
# ---------------------------------------------------------------------------


PRE_REGISTERED_OPERATOR_NAMES: tuple[str, ...] = (
    "framing_prefix_v1",
    "framing_suffix_v1",
    "synonym_substitution_conservative_v2",
)

DEFAULT_COST_CEILING_USD: float = 20.0
DEFAULT_PREFLIGHT_CYCLES: int = 5
DEFAULT_MODEL: str = "claude-sonnet-4-20250514"

DEFAULT_TRACES_ROOT: Path = (
    Path(__file__).resolve().parents[3] / "data" / "paper_3" / "leakage_runs"
)


# ---------------------------------------------------------------------------
# Halt reasons
# ---------------------------------------------------------------------------


HALT_COMPLETED: str = "completed"
HALT_COST_CEILING: str = "cost_ceiling"
HALT_DETERMINISTIC_KILL: str = "deterministic_kill"
HALT_ANCHOR_TEST_FAILURE: str = "anchor_test_failure"
HALT_PREFLIGHT_OVER_BUDGET: str = "preflight_over_budget"


# ---------------------------------------------------------------------------
# Trace records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CycleTrace:
    """One pipeline cycle's captured state.

    Holds enough to recompute :class:`InfluenceLeakage` deterministically
    without re-running the LLM. Stored as one JSONL row per cycle.
    """

    cycle_id: str
    scenario_id: str
    operator_name: str | None      # None for baseline cycles
    pair_index: int
    is_baseline: bool
    pipeline: str                   # "llm" or "light"

    # Per-layer label + confidence + cited fact ids
    architect_message_type: str
    architect_confidence: float
    architect_cited_facts: tuple[str, ...]

    skeptic_message_type: str       # for llm pipeline; for light, "REBUTTAL_LIGHT"
    skeptic_confidence: float
    skeptic_cited_facts: tuple[str, ...]   # () for light path
    skeptic_triggered_rules: tuple[str, ...]   # () for llm path

    oracle_outcome: str
    oracle_confidence: float
    oracle_supporting_facts: tuple[str, ...]

    final_outcome: str
    final_confidence: float

    cost_usd: float
    tokens_in: int
    tokens_out: int
    elapsed_ms: float

    def to_dict(self) -> dict[str, Any]:
        d = dataclasses.asdict(self)
        # Tuples don't survive asdict cleanly into JSON; ensure lists.
        for key in (
            "architect_cited_facts",
            "skeptic_cited_facts",
            "skeptic_triggered_rules",
            "oracle_supporting_facts",
        ):
            d[key] = list(d[key])
        return d


# ---------------------------------------------------------------------------
# Per-pair leakage record
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PairLeakageRecord:
    """All :class:`InfluenceLeakage` vectors computed for one pair on one path."""

    scenario_id: str
    operator_name: str
    pair_index: int
    pipeline: str   # "llm" or "light"
    leakages: tuple[InfluenceLeakage, ...]  # one per layer
    first_diverging_layer: str | None       # None if no divergence

    @property
    def aggregate_max_scalar(self) -> float:
        return max((l.weighted_scalar for l in self.leakages), default=0.0)

    @property
    def kill_fires(self) -> bool:
        """Backwards-compat: True iff any layer (including Architect)
        leaks. This was the run-1 implementation. Retained so the report
        can show what the original kill rule reported, not used for the
        halt decision in run-2+."""
        return any(l.kill_fires for l in self.leakages)

    def _layer(self, name: str) -> InfluenceLeakage | None:
        return next((l for l in self.leakages if l.layer == name), None)

    @property
    def kill_fires_narrow(self) -> bool:
        """Narrow reading: Light Skeptic's judgment-level output only.

        This matches the original Phase 7 / Paper 3 framing: *Light
        Skeptic's InfluenceLeakage 4-bit vector must not change*. Returns
        True iff the light_skeptic layer (light pipeline only) leaks.
        """
        if self.pipeline != "light":
            return False
        light = self._layer("light_skeptic")
        return bool(light and light.kill_fires)

    @property
    def kill_fires_brief_broad(self) -> bool:
        """Brief's broad reading: deterministic path = OracleJudge +
        Light Skeptic + final_verdict. Excludes Architect (the Architect
        is the LLM input that the deterministic path is supposed to
        absorb, not part of the deterministic path itself)."""
        if self.pipeline != "light":
            return False
        layers = [
            self._layer("light_skeptic"),
            self._layer("oracle"),
            self._layer("final_verdict"),
        ]
        return any(l and l.kill_fires for l in layers)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "operator_name": self.operator_name,
            "pair_index": self.pair_index,
            "pipeline": self.pipeline,
            "leakages": [l.to_dict() for l in self.leakages],
            "first_diverging_layer": self.first_diverging_layer,
            "aggregate_max_scalar": self.aggregate_max_scalar,
            "kill_fires": self.kill_fires,
            "kill_fires_narrow": self.kill_fires_narrow,
            "kill_fires_brief_broad": self.kill_fires_brief_broad,
        }


# ---------------------------------------------------------------------------
# Run summary
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RunSummary:
    """Everything the report renderer needs."""

    run_id: str
    timestamp_iso: str
    git_sha: str
    cycles_completed: int
    total_cost_usd: float
    halt_reason: str
    deterministic_kill_fired: bool
    anchor_test_passed_at_start: bool
    anchor_test_passed_at_end: bool
    operator_set: tuple[str, ...]
    pre_registered_weights: dict[str, float]
    confidence_drift_threshold: float
    pair_records: tuple[PairLeakageRecord, ...]
    traces_path: str
    sha256_path: str

    def to_dict(self) -> dict[str, Any]:
        return {
            **{
                k: v for k, v in dataclasses.asdict(self).items()
                if k != "pair_records"
            },
            "pair_records": [r.to_dict() for r in self.pair_records],
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _git_sha(default: str = "unknown") -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if result.returncode == 0:
            return result.stdout.strip() or default
    except Exception:
        pass
    return default


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _resolve_operator(name: str) -> MutationOperator:
    by_name: dict[str, MutationOperator] = {}
    for op in OPERATORS_V1:
        by_name[op.operator_name] = op
    for op in OPERATORS_V2:
        by_name[op.operator_name] = op
    if name not in by_name:
        raise KeyError(
            f"unknown operator {name!r}; known: {sorted(by_name)}"
        )
    return by_name[name]


def _stance_for_oracle(outcome_label: str) -> str:
    return "conclusive" if outcome_label != "INCONCLUSIVE" else "inconclusive"


def _stance_for_final_verdict(outcome_label: str) -> str:
    return {
        "THREAT_CONFIRMED": "ESCALATE",
        "THREAT_DISMISSED": "DISMISS",
    }.get(outcome_label, "HOLD")


def _trace_extract_llm(
    cycle_id: str,
    scenario_id: str,
    operator_name: str | None,
    pair_index: int,
    is_baseline: bool,
    result: GuardedCycleResult,
    cost_usd: float,
    tokens_in: int,
    tokens_out: int,
    elapsed_ms: float,
) -> CycleTrace:
    arch = result.cycle_result.architect_message
    skep = result.cycle_result.skeptic_message
    verdict = result.cycle_result.verdict
    return CycleTrace(
        cycle_id=cycle_id,
        scenario_id=scenario_id,
        operator_name=operator_name,
        pair_index=pair_index,
        is_baseline=is_baseline,
        pipeline="llm",
        architect_message_type=arch.message_type.value,
        architect_confidence=float(arch.confidence),
        architect_cited_facts=tuple(sorted(arch.get_all_fact_ids())),
        skeptic_message_type=skep.message_type.value,
        skeptic_confidence=float(skep.confidence),
        skeptic_cited_facts=tuple(sorted(skep.get_all_fact_ids())),
        skeptic_triggered_rules=(),
        oracle_outcome=verdict.outcome.value,
        oracle_confidence=float(verdict.confidence),
        oracle_supporting_facts=tuple(sorted(verdict.supporting_fact_ids)),
        final_outcome=verdict.outcome.value,
        final_confidence=float(verdict.confidence),
        cost_usd=cost_usd,
        tokens_in=tokens_in,
        tokens_out=tokens_out,
        elapsed_ms=elapsed_ms,
    )


def _trace_extract_light(
    cycle_id: str,
    scenario_id: str,
    operator_name: str | None,
    pair_index: int,
    is_baseline: bool,
    result: LightGuardedCycleResult,
    cost_usd: float,
    tokens_in: int,
    tokens_out: int,
    elapsed_ms: float,
) -> CycleTrace:
    arch = result.cycle_result.architect_message
    judgment = result.light_judgment
    verdict = result.cycle_result.verdict
    return CycleTrace(
        cycle_id=cycle_id,
        scenario_id=scenario_id,
        operator_name=operator_name,
        pair_index=pair_index,
        is_baseline=is_baseline,
        pipeline="light",
        architect_message_type=arch.message_type.value,
        architect_confidence=float(arch.confidence),
        architect_cited_facts=tuple(sorted(arch.get_all_fact_ids())),
        skeptic_message_type="REBUTTAL_LIGHT",
        skeptic_confidence=float(judgment.confidence),
        skeptic_cited_facts=(),
        skeptic_triggered_rules=tuple(judgment.triggered_rules),
        oracle_outcome=verdict.outcome.value,
        oracle_confidence=float(verdict.confidence),
        oracle_supporting_facts=tuple(sorted(verdict.supporting_fact_ids)),
        final_outcome=verdict.outcome.value,
        final_confidence=float(verdict.confidence),
        cost_usd=cost_usd,
        tokens_in=tokens_in,
        tokens_out=tokens_out,
        elapsed_ms=elapsed_ms,
    )


# ---------------------------------------------------------------------------
# Cycle execution with cost tracking
# ---------------------------------------------------------------------------


def _build_llm_strategies(
    client: AnthropicClient,
    call_logger: LLMCallLogger,
) -> tuple[LLMThreatAnalyzer, LLMExplanationFinder, LLMNarrativeGenerator]:
    """Construct the three LLM strategies sharing a single call_logger."""
    threat = LLMThreatAnalyzer(client, call_logger=call_logger)
    expl = LLMExplanationFinder(client, call_logger=call_logger)
    narr = LLMNarrativeGenerator(client, call_logger=call_logger)
    return threat, expl, narr


def _run_one_cycle(
    *,
    scenario: BenchmarkScenario,
    pipeline: str,
    client: AnthropicClient,
    cycle_id: str,
    pair_index: int,
    is_baseline: bool,
    operator_name: str | None,
) -> tuple[CycleTrace, float]:
    """Execute one cycle on the requested pipeline and capture the trace.

    Returns (trace, cost_usd).
    """
    started = time.monotonic()
    call_logger = LLMCallLogger()
    threat, expl, narr = _build_llm_strategies(client, call_logger)
    firewall = OracleFirewall()

    if pipeline == "llm":
        result = run_guarded_cycle(
            scenario.packet,
            threat_analyzer=threat,
            explanation_finder=expl,
            narrative_generator=narr,
            firewall=firewall,
            enable_hot_swap=True,
            hot_swap_factory=lambda: LLMThreatAnalyzer(
                client, call_logger=call_logger
            ),
            agent_id_prefix="ares-leakage",
        )
        elapsed_ms = (time.monotonic() - started) * 1000.0
        cost = call_logger.total_cost_estimate_usd
        trace = _trace_extract_llm(
            cycle_id=cycle_id,
            scenario_id=scenario.metadata.scenario_id,
            operator_name=operator_name,
            pair_index=pair_index,
            is_baseline=is_baseline,
            result=result,
            cost_usd=cost,
            tokens_in=call_logger.total_input_tokens,
            tokens_out=call_logger.total_output_tokens,
            elapsed_ms=elapsed_ms,
        )
    elif pipeline == "light":
        result = run_light_guarded_cycle(
            scenario.packet,
            threat_analyzer=threat,
            narrative_generator=narr,
            firewall=firewall,
            agent_id_prefix="ares-leakage-light",
        )
        elapsed_ms = (time.monotonic() - started) * 1000.0
        cost = call_logger.total_cost_estimate_usd
        trace = _trace_extract_light(
            cycle_id=cycle_id,
            scenario_id=scenario.metadata.scenario_id,
            operator_name=operator_name,
            pair_index=pair_index,
            is_baseline=is_baseline,
            result=result,
            cost_usd=cost,
            tokens_in=call_logger.total_input_tokens,
            tokens_out=call_logger.total_output_tokens,
            elapsed_ms=elapsed_ms,
        )
    else:
        raise ValueError(f"unknown pipeline {pipeline!r}")

    return trace, cost


# ---------------------------------------------------------------------------
# Per-pair leakage computation
# ---------------------------------------------------------------------------


def _compute_pair_leakage(
    *,
    baseline: CycleTrace,
    mutated: CycleTrace,
    pair_index: int,
) -> PairLeakageRecord:
    """Compute per-layer InfluenceLeakage for a baseline+mutated trace pair."""
    if baseline.pipeline != mutated.pipeline:
        raise ValueError(
            f"pipeline mismatch: baseline={baseline.pipeline} "
            f"mutated={mutated.pipeline}"
        )
    pipeline = baseline.pipeline

    layers: list[InfluenceLeakage] = []

    # Architect layer
    layers.append(
        InfluenceLeakage(
            verdict_changed=baseline.architect_message_type
            != mutated.architect_message_type,
            action_changed=baseline.architect_message_type
            != mutated.architect_message_type,
            cited_facts_changed=cited_facts_changed(
                baseline.architect_cited_facts, mutated.architect_cited_facts
            ),
            confidence_drift_exceeded=confidence_drift_exceeds_threshold(
                baseline.architect_confidence, mutated.architect_confidence
            ),
            layer="architect",
            scenario_id=mutated.scenario_id,
            operator_name=mutated.operator_name or "unknown",
            pair_index=pair_index,
        )
    )

    # Skeptic layer (LLM or Light)
    skep_layer_name = "skeptic_llm" if pipeline == "llm" else "light_skeptic"
    if pipeline == "llm":
        skep_action_baseline = baseline.skeptic_message_type
        skep_action_mutated = mutated.skeptic_message_type
        skep_facts_b = baseline.skeptic_cited_facts
        skep_facts_m = mutated.skeptic_cited_facts
    else:
        skep_action_baseline = "|".join(sorted(baseline.skeptic_triggered_rules))
        skep_action_mutated = "|".join(sorted(mutated.skeptic_triggered_rules))
        skep_facts_b = ()
        skep_facts_m = ()

    layers.append(
        InfluenceLeakage(
            verdict_changed=baseline.skeptic_message_type
            != mutated.skeptic_message_type,
            action_changed=skep_action_baseline != skep_action_mutated,
            cited_facts_changed=cited_facts_changed(skep_facts_b, skep_facts_m),
            confidence_drift_exceeded=confidence_drift_exceeds_threshold(
                baseline.skeptic_confidence, mutated.skeptic_confidence
            ),
            layer=skep_layer_name,
            scenario_id=mutated.scenario_id,
            operator_name=mutated.operator_name or "unknown",
            pair_index=pair_index,
        )
    )

    # Oracle layer
    layers.append(
        InfluenceLeakage(
            verdict_changed=baseline.oracle_outcome != mutated.oracle_outcome,
            action_changed=_stance_for_oracle(baseline.oracle_outcome)
            != _stance_for_oracle(mutated.oracle_outcome),
            cited_facts_changed=cited_facts_changed(
                baseline.oracle_supporting_facts,
                mutated.oracle_supporting_facts,
            ),
            confidence_drift_exceeded=confidence_drift_exceeds_threshold(
                baseline.oracle_confidence, mutated.oracle_confidence
            ),
            layer="oracle",
            scenario_id=mutated.scenario_id,
            operator_name=mutated.operator_name or "unknown",
            pair_index=pair_index,
        )
    )

    # Final verdict layer
    layers.append(
        InfluenceLeakage(
            verdict_changed=baseline.final_outcome != mutated.final_outcome,
            action_changed=_stance_for_final_verdict(baseline.final_outcome)
            != _stance_for_final_verdict(mutated.final_outcome),
            cited_facts_changed=cited_facts_changed(
                baseline.oracle_supporting_facts,
                mutated.oracle_supporting_facts,
            ),
            confidence_drift_exceeded=confidence_drift_exceeds_threshold(
                baseline.final_confidence, mutated.final_confidence
            ),
            layer="final_verdict",
            scenario_id=mutated.scenario_id,
            operator_name=mutated.operator_name or "unknown",
            pair_index=pair_index,
        )
    )

    first_diverging = next(
        (l.layer for l in layers if not l.all_zero),
        None,
    )

    return PairLeakageRecord(
        scenario_id=mutated.scenario_id,
        operator_name=mutated.operator_name or "unknown",
        pair_index=pair_index,
        pipeline=pipeline,
        leakages=tuple(layers),
        first_diverging_layer=first_diverging,
    )


# ---------------------------------------------------------------------------
# Anchor-test guard
# ---------------------------------------------------------------------------


def anchor_test_passes() -> bool:
    """Run the verbatim Light Skeptic anchor test. True iff green.

    The anchor lives at ``ares/dialectic/tests/agents/test_light_skeptic_anchor.py``
    and protects the Paper 3 kill-criterion line. If the test goes red,
    the runner halts before any further LLM spend.
    """
    repo_root = Path(__file__).resolve().parents[3]
    test_path = (
        repo_root
        / "ares"
        / "dialectic"
        / "tests"
        / "agents"
        / "test_light_skeptic_anchor.py"
    )
    if not test_path.exists():
        # Anchor test missing entirely is a failure mode.
        logger.warning(f"anchor test not found at {test_path}")
        return False
    try:
        result = subprocess.run(
            ["python", "-m", "pytest", str(test_path), "-q", "--no-header"],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
            cwd=str(repo_root),
        )
        return result.returncode == 0
    except Exception as exc:
        logger.warning(f"anchor test execution failed: {exc}")
        return False


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


@dataclass
class RunnerConfig:
    """Mutable configuration container for one run."""

    operator_names: tuple[str, ...] = PRE_REGISTERED_OPERATOR_NAMES
    cost_ceiling_usd: float = DEFAULT_COST_CEILING_USD
    pipelines: tuple[str, ...] = ("llm", "light")
    model: str = DEFAULT_MODEL
    traces_root: Path = DEFAULT_TRACES_ROOT
    skip_anchor_check: bool = False    # tests can flip this for synthetic runs


def _new_run_id() -> str:
    return f"{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"


def _write_jsonl(path: Path, records: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for r in records:
            fh.write(json.dumps(r, sort_keys=True) + "\n")


def _sha256_file(path: Path) -> str:
    import hashlib
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _select_preflight_pairs(
    scenarios: list[BenchmarkScenario],
    operator_names: tuple[str, ...],
    n_pairs: int,
    seed: int = 0,
) -> list[tuple[BenchmarkScenario, str]]:
    """Pick n_pairs (scenario, operator_name) combinations spread across
    the corpus and operators. Deterministic given seed."""
    rng = random.Random(seed)
    all_pairs = [(s, op) for s in scenarios for op in operator_names]
    rng.shuffle(all_pairs)
    return all_pairs[:n_pairs]


def run_preflight(
    *,
    config: RunnerConfig | None = None,
    n_pairs: int = DEFAULT_PREFLIGHT_CYCLES,
    client: AnthropicClient | None = None,
) -> dict[str, Any]:
    """Run the pre-flight estimator.

    Executes one *light-pipeline* cycle for each of n_pairs randomly-
    selected (scenario, operator) baselines. Extrapolates aggregate
    cost for the full 264-cycle measurement run.

    Returns a dict suitable for surfacing to the user.
    """
    if config is None:
        config = RunnerConfig()
    if client is None:
        client = AnthropicClient(model=config.model)

    registry = build_registry_v3()
    scenarios = list(registry.all_scenarios())
    pairs = _select_preflight_pairs(
        scenarios, config.operator_names, n_pairs, seed=0
    )

    sample_costs: list[float] = []
    sample_elapsed: list[float] = []
    pair_index = 0

    started_total = time.monotonic()
    for scenario, op_name in pairs:
        # One light-pipeline baseline cycle for sampling.
        cycle_id = f"preflight-{pair_index:03d}-{uuid.uuid4().hex[:4]}"
        try:
            trace, cost = _run_one_cycle(
                scenario=scenario,
                pipeline="light",
                client=client,
                cycle_id=cycle_id,
                pair_index=pair_index,
                is_baseline=True,
                operator_name=None,
            )
        except Exception as exc:
            logger.warning(
                f"preflight cycle {cycle_id} on {scenario.metadata.scenario_id} "
                f"raised {type(exc).__name__}: {exc}"
            )
            pair_index += 1
            continue
        sample_costs.append(cost)
        sample_elapsed.append(trace.elapsed_ms)
        pair_index += 1

    total_elapsed_s = time.monotonic() - started_total
    n_samples = len(sample_costs)
    if n_samples == 0:
        return {
            "status": "no_samples",
            "estimated_total_cost_usd": None,
            "cost_ceiling_usd": config.cost_ceiling_usd,
            "n_samples": 0,
            "exceeds_ceiling": True,
            "halt_recommendation": HALT_PREFLIGHT_OVER_BUDGET,
            "wall_time_s": total_elapsed_s,
        }

    avg_cost_per_light_cycle = sum(sample_costs) / n_samples
    avg_elapsed_ms_light = sum(sample_elapsed) / n_samples

    # Extrapolation:
    #   - 33 baselines + 99 mutated = 132 cycles per path
    #   - light path: 132 cycles at avg light cost
    #   - llm path:   132 cycles at ~2.5x light cost (LLM Skeptic adds calls)
    light_path_total = 132 * avg_cost_per_light_cycle
    llm_path_total = 132 * avg_cost_per_light_cycle * 2.5
    estimated_total = light_path_total + llm_path_total

    # Wall time extrapolation
    wall_per_light_s = avg_elapsed_ms_light / 1000.0
    wall_per_llm_s = wall_per_light_s * 2.0
    wall_total_s = (132 * wall_per_light_s) + (132 * wall_per_llm_s)

    exceeds = estimated_total > config.cost_ceiling_usd
    halt = HALT_PREFLIGHT_OVER_BUDGET if exceeds else "preflight_ok"

    return {
        "status": "ok",
        "n_samples": n_samples,
        "avg_cost_per_light_cycle_usd": avg_cost_per_light_cycle,
        "avg_elapsed_ms_per_light_cycle": avg_elapsed_ms_light,
        "estimated_light_path_cost_usd": light_path_total,
        "estimated_llm_path_cost_usd": llm_path_total,
        "estimated_total_cost_usd": estimated_total,
        "estimated_wall_time_s": wall_total_s,
        "estimated_wall_time_minutes": wall_total_s / 60.0,
        "cost_ceiling_usd": config.cost_ceiling_usd,
        "exceeds_ceiling": exceeds,
        "halt_recommendation": halt,
        "preflight_actual_cost_usd": sum(sample_costs),
        "preflight_wall_time_s": total_elapsed_s,
    }


def run_full_measurement(
    *,
    config: RunnerConfig | None = None,
    client: AnthropicClient | None = None,
) -> RunSummary:
    """Execute the 264-cycle measurement run.

    Halts on cost ceiling, deterministic kill, or anchor-test failure.
    Persists traces JSONL + SHA256. Returns a frozen RunSummary suitable
    for the report renderer.
    """
    if config is None:
        config = RunnerConfig()
    if client is None:
        client = AnthropicClient(model=config.model)

    run_id = _new_run_id()
    started_iso = _utc_now_iso()
    git_sha = _git_sha()

    anchor_start = True if config.skip_anchor_check else anchor_test_passes()
    if not anchor_start:
        logger.error("anchor test red at session start; halting before any LLM spend")
        return RunSummary(
            run_id=run_id,
            timestamp_iso=started_iso,
            git_sha=git_sha,
            cycles_completed=0,
            total_cost_usd=0.0,
            halt_reason=HALT_ANCHOR_TEST_FAILURE,
            deterministic_kill_fired=False,
            anchor_test_passed_at_start=False,
            anchor_test_passed_at_end=False,
            operator_set=config.operator_names,
            pre_registered_weights={
                "verdict_changed": 0.40,
                "action_changed": 0.20,
                "cited_facts_changed": 0.20,
                "confidence_drift_exceeded": 0.20,
            },
            confidence_drift_threshold=CONFIDENCE_DRIFT_THRESHOLD,
            pair_records=(),
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

    all_traces: list[CycleTrace] = []
    pair_records: list[PairLeakageRecord] = []
    cycles_completed = 0
    total_cost = 0.0
    deterministic_kill_fired = False
    halt_reason = HALT_COMPLETED
    pair_index = 0
    deterministic_active = True   # flips False on first deterministic kill;
                                  # the LLM path keeps running afterwards.

    def _open_traces_writer():
        return traces_path.open("a", encoding="utf-8")

    # Per-scenario, per-pipeline: capture baseline once, then run mutated
    # for each operator on the same scenario.
    for scenario in scenarios:
        if total_cost >= config.cost_ceiling_usd:
            halt_reason = HALT_COST_CEILING
            break
        for pipeline in config.pipelines:
            # Halt-scope fix: deterministic-path kill only halts the
            # deterministic path. LLM path continues under its own
            # cost share. Cost ceiling halts everything.
            if pipeline == "light" and not deterministic_active:
                continue
            if total_cost >= config.cost_ceiling_usd:
                halt_reason = HALT_COST_CEILING
                break

            # Baseline cycle for this (scenario, pipeline)
            cycle_id = f"baseline-{scenario.metadata.scenario_id}-{pipeline}"
            try:
                baseline_trace, baseline_cost = _run_one_cycle(
                    scenario=scenario,
                    pipeline=pipeline,
                    client=client,
                    cycle_id=cycle_id,
                    pair_index=pair_index,
                    is_baseline=True,
                    operator_name=None,
                )
            except Exception as exc:
                logger.warning(
                    f"baseline cycle {cycle_id} raised {type(exc).__name__}: {exc}"
                )
                continue
            all_traces.append(baseline_trace)
            with _open_traces_writer() as fh:
                fh.write(json.dumps(baseline_trace.to_dict(), sort_keys=True) + "\n")
            cycles_completed += 1
            total_cost += baseline_cost

            if total_cost >= config.cost_ceiling_usd:
                halt_reason = HALT_COST_CEILING
                break

            # Mutated cycles, one per operator
            for op_name, op in operators_by_name.items():
                if total_cost >= config.cost_ceiling_usd:
                    halt_reason = HALT_COST_CEILING
                    break
                # Mutator may produce a no-op pair; in that case we have
                # nothing to compare. Skip silently.
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
                    f"mutated-{scenario.metadata.scenario_id}-{op_name}-{pipeline}"
                )
                try:
                    mutated_trace, mutated_cost = _run_one_cycle(
                        scenario=pair.mutated_scenario,
                        pipeline=pipeline,
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
                all_traces.append(mutated_trace)
                with _open_traces_writer() as fh:
                    fh.write(json.dumps(mutated_trace.to_dict(), sort_keys=True) + "\n")
                cycles_completed += 1
                total_cost += mutated_cost

                # Compute leakage for this pair
                record = _compute_pair_leakage(
                    baseline=baseline_trace,
                    mutated=mutated_trace,
                    pair_index=pair_index,
                )
                pair_records.append(record)
                pair_index += 1

                # Halt-scope fix: kill is decided on the BRIEF'S BROAD
                # reading (light_skeptic + oracle + final_verdict, no
                # architect). On fire, flip deterministic_active and
                # break out of the OPERATOR loop only. The pipeline
                # loop will skip remaining `light` cycles via the
                # check above; the scenario loop continues so the LLM
                # path keeps producing data. The kill is captured in
                # `deterministic_kill_fired`; halt_reason stays
                # HALT_COMPLETED unless cost or anchor halts us.
                if pipeline == "light" and record.kill_fires_brief_broad:
                    deterministic_kill_fired = True
                    deterministic_active = False
                    break

            if total_cost >= config.cost_ceiling_usd:
                halt_reason = HALT_COST_CEILING
                break

    sha256_path = traces_dir / "traces.sha256"
    if traces_path.exists():
        digest = _sha256_file(traces_path)
        sha256_path.write_text(f"{digest}  {traces_path.name}\n", encoding="utf-8")

    anchor_end = True if config.skip_anchor_check else anchor_test_passes()

    return RunSummary(
        run_id=run_id,
        timestamp_iso=started_iso,
        git_sha=git_sha,
        cycles_completed=cycles_completed,
        total_cost_usd=total_cost,
        halt_reason=halt_reason,
        deterministic_kill_fired=deterministic_kill_fired,
        anchor_test_passed_at_start=anchor_start,
        anchor_test_passed_at_end=anchor_end,
        operator_set=config.operator_names,
        pre_registered_weights={
            "verdict_changed": 0.40,
            "action_changed": 0.20,
            "cited_facts_changed": 0.20,
            "confidence_drift_exceeded": 0.20,
        },
        confidence_drift_threshold=CONFIDENCE_DRIFT_THRESHOLD,
        pair_records=tuple(pair_records),
        traces_path=str(traces_path),
        sha256_path=str(sha256_path),
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


__all__ = [
    "CycleTrace",
    "DEFAULT_COST_CEILING_USD",
    "DEFAULT_MODEL",
    "DEFAULT_PREFLIGHT_CYCLES",
    "DEFAULT_TRACES_ROOT",
    "HALT_ANCHOR_TEST_FAILURE",
    "HALT_COMPLETED",
    "HALT_COST_CEILING",
    "HALT_DETERMINISTIC_KILL",
    "HALT_PREFLIGHT_OVER_BUDGET",
    "PRE_REGISTERED_OPERATOR_NAMES",
    "PairLeakageRecord",
    "RunSummary",
    "RunnerConfig",
    "anchor_test_passes",
    "run_full_measurement",
    "run_preflight",
]
