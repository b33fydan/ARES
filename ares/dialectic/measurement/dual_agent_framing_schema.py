"""Frozen schema for the dual-agent framing-sensitivity measurement (Session 084).

Peer of architect_framing_schema. Records BOTH agents' cited facts per resample
(the live CycleTrace already carries skeptic_cited_facts), so one run measures the
Architect path, the Skeptic path, and the paired mirror.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from ares.dialectic.agents.strategies.client_factory import VALID_PROVIDERS
from ares.dialectic.measurement.architect_framing_schema import OperatorFramingResult
from ares.dialectic.measurement.leakage_runner import (
    DEFAULT_MODEL, DEFAULT_TRACES_ROOT, PRE_REGISTERED_OPERATOR_NAMES,
)

DUAL_AGENT_FRAMING_HARD_CEILING_USD: float = 40.0
AGENT_ARCHITECT: str = "architect"
AGENT_SKEPTIC: str = "skeptic"


@dataclass(frozen=True)
class DualAgentFramingConfig:
    s059_traces_path: Path
    scenario_ids: tuple[str, ...] = ()
    k_resamples: int = 20
    max_scenarios: int = 17
    operator_names: tuple[str, ...] = PRE_REGISTERED_OPERATOR_NAMES
    model: str = DEFAULT_MODEL
    provider: str = "anthropic"
    cost_ceiling_usd: float = 32.0
    traces_root: Path = DEFAULT_TRACES_ROOT
    seed: int = 0

    def __post_init__(self) -> None:
        if self.k_resamples < 2:
            raise ValueError(f"k_resamples must be >= 2, got {self.k_resamples}")
        if not self.operator_names:
            raise ValueError("operator_names must be non-empty")
        if self.provider not in VALID_PROVIDERS:
            raise ValueError(f"provider must be one of {sorted(VALID_PROVIDERS)}")
        if self.cost_ceiling_usd > DUAL_AGENT_FRAMING_HARD_CEILING_USD:
            raise ValueError(
                f"cost_ceiling_usd {self.cost_ceiling_usd} exceeds hard cap "
                f"{DUAL_AGENT_FRAMING_HARD_CEILING_USD}"
            )


@dataclass(frozen=True)
class DualAgentResampleRecord:
    scenario_id: str
    condition: str
    resample_index: int
    architect_cited_facts: tuple[str, ...]
    skeptic_cited_facts: tuple[str, ...]
    architect_confidence: float
    skeptic_confidence: float
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
            "skeptic_cited_facts": list(self.skeptic_cited_facts),
            "architect_confidence": self.architect_confidence,
            "skeptic_confidence": self.skeptic_confidence,
            "final_outcome": self.final_outcome,
            "oracle_supporting_facts": list(self.oracle_supporting_facts),
            "cost_usd": self.cost_usd,
            "elapsed_ms": self.elapsed_ms,
        }


@dataclass(frozen=True)
class AgentFramingResult:
    agent: str
    within_distances: tuple[float, ...]
    control_distances: tuple[float, ...]
    control_exceeds_noise: bool
    operator_results: tuple[OperatorFramingResult, ...]


@dataclass(frozen=True)
class MirrorRecord:
    scenario_id: str
    operator_name: str
    architect_jaccard: float
    architect_direction: str
    skeptic_jaccard: float
    skeptic_direction: str
    mirror_class: str


@dataclass(frozen=True)
class ScenarioDualFramingResult:
    scenario_id: str
    architect: AgentFramingResult
    skeptic: AgentFramingResult
    mirror: tuple[MirrorRecord, ...]
    skipped_operators: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class DualAgentFramingSummary:
    run_id: str
    timestamp_iso: str
    git_sha: str
    provider: str
    model: str
    k_resamples: int
    operator_names: tuple[str, ...]
    scenario_results: tuple[ScenarioDualFramingResult, ...]
    deferred_scenario_ids: tuple[str, ...]
    control_valid_architect: bool
    control_valid_skeptic: bool
    total_cost_usd: float
    halt_reason: str
    traces_path: str
