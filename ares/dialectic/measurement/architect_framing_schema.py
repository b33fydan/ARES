"""Frozen schema for the Architect-path framing-sensitivity measurement (Session 077)."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from ares.dialectic.agents.strategies.client_factory import VALID_PROVIDERS
from ares.dialectic.measurement.leakage_runner import (
    DEFAULT_MODEL, DEFAULT_TRACES_ROOT, PRE_REGISTERED_OPERATOR_NAMES,
)

CONDITION_BASELINE: str = "baseline"
CONDITION_CONTROL: str = "control"
ARCHITECT_FRAMING_HARD_CEILING_USD: float = 8.0  # tighter than leakage runner's 20.0

VERDICT_REAL: str = "framing_channel_real"
VERDICT_NOISE: str = "within_noise"
VERDICT_INCONCLUSIVE: str = "inconclusive"


def framing_condition(operator_name: str) -> str:
    return f"framing:{operator_name}"


@dataclass(frozen=True)
class ArchitectFramingConfig:
    s059_traces_path: Path
    scenario_ids: tuple[str, ...] = ()          # () => auto-select from S059 traces
    k_resamples: int = 8
    max_scenarios: int = 6                       # budget guard; no silent truncation (logged)
    operator_names: tuple[str, ...] = PRE_REGISTERED_OPERATOR_NAMES
    model: str = DEFAULT_MODEL
    provider: str = "anthropic"
    cost_ceiling_usd: float = 6.0
    traces_root: Path = DEFAULT_TRACES_ROOT
    seed: int = 0

    def __post_init__(self) -> None:
        if self.k_resamples < 2:
            raise ValueError(f"k_resamples must be >= 2, got {self.k_resamples}")
        if not self.operator_names:
            raise ValueError("operator_names must be non-empty")
        if self.provider not in VALID_PROVIDERS:
            raise ValueError(f"provider must be one of {sorted(VALID_PROVIDERS)}")
        if self.cost_ceiling_usd > ARCHITECT_FRAMING_HARD_CEILING_USD:
            raise ValueError(
                f"cost_ceiling_usd {self.cost_ceiling_usd} exceeds hard cap "
                f"{ARCHITECT_FRAMING_HARD_CEILING_USD}"
            )


@dataclass(frozen=True)
class ResampleRecord:
    scenario_id: str
    condition: str                       # baseline | framing:<op> | control
    resample_index: int
    architect_cited_facts: tuple[str, ...]
    architect_confidence: float
    final_outcome: str
    oracle_supporting_facts: tuple[str, ...]
    cost_usd: float
    elapsed_ms: float

    def to_dict(self) -> dict:
        return {
            "scenario_id": self.scenario_id,
            "condition": self.condition,
            "resample_index": self.resample_index,
            "architect_cited_facts": list(self.architect_cited_facts),
            "architect_confidence": self.architect_confidence,
            "final_outcome": self.final_outcome,
            "oracle_supporting_facts": list(self.oracle_supporting_facts),
            "cost_usd": self.cost_usd,
            "elapsed_ms": self.elapsed_ms,
        }


@dataclass(frozen=True)
class OperatorFramingResult:
    operator_name: str
    n_cross: int
    cross_median: float
    within_median: float
    effect_size: float                   # cross_median - within_median
    p_value: float
    ci_low: float
    ci_high: float
    verdict: str                         # VERDICT_REAL | VERDICT_NOISE | VERDICT_INCONCLUSIVE


@dataclass(frozen=True)
class ScenarioFramingResult:
    scenario_id: str
    within_distances: tuple[float, ...]
    control_distances: tuple[float, ...]
    control_exceeds_noise: bool
    operator_results: tuple[OperatorFramingResult, ...]
    skipped_operators: tuple[str, ...] = field(default_factory=tuple)  # no-op mutations


@dataclass(frozen=True)
class ArchitectFramingSummary:
    run_id: str
    timestamp_iso: str
    git_sha: str
    provider: str
    model: str
    k_resamples: int
    operator_names: tuple[str, ...]
    scenario_results: tuple[ScenarioFramingResult, ...]
    deferred_scenario_ids: tuple[str, ...]   # selected but not run (budget) — logged, not silent
    control_valid: bool
    total_cost_usd: float
    halt_reason: str
    traces_path: str
