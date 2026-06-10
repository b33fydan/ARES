# ares/dialectic/measurement/read_depth_tier4_schema.py
"""Frozen result schema for the tier-4 LLM anchor (Phase C).

Peer to read_depth_frontier_schema (which stays byte-stable). Carries the
noise-controlled fields (CI, per-operator p-values) the exact deterministic
TierCoordinate does not.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import Any, Mapping, Tuple

READ_DEPTH_TIER4_HARD_CEILING_USD = 15.0


@dataclass(frozen=True)
class Tier4OperatorRecord:
    operator_name: str
    perturbed_malign_rate: float
    flipped: bool
    p_value: float
    n_resamples: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "Tier4OperatorRecord":
        return cls(operator_name=str(d["operator_name"]),
                   perturbed_malign_rate=float(d["perturbed_malign_rate"]),
                   flipped=bool(d["flipped"]), p_value=float(d["p_value"]),
                   n_resamples=int(d["n_resamples"]))


@dataclass(frozen=True)
class Tier4ScenarioRecord:
    scenario_id: str
    is_malign: bool
    stratum: str
    baseline_malign_rate: float
    baseline_majority_malign: bool
    operator_records: Tuple[Tier4OperatorRecord, ...]

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["operator_records"] = [o.to_dict() for o in self.operator_records]
        return d

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "Tier4ScenarioRecord":
        return cls(scenario_id=str(d["scenario_id"]), is_malign=bool(d["is_malign"]),
                   stratum=str(d["stratum"]),
                   baseline_malign_rate=float(d["baseline_malign_rate"]),
                   baseline_majority_malign=bool(d["baseline_majority_malign"]),
                   operator_records=tuple(
                       Tier4OperatorRecord.from_dict(o)
                       for o in d["operator_records"]))


@dataclass(frozen=True)
class Tier4Coordinate:
    tier_id: str
    view: str
    x_semantic: float
    x_semantic_ci_low: float
    x_semantic_ci_high: float
    tpr: float
    fpr: float
    youden_j: float
    n_malign: int
    n_benign: int
    k_resamples: int
    model: str
    provider: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "Tier4Coordinate":
        return cls(tier_id=str(d["tier_id"]), view=str(d["view"]),
                   x_semantic=float(d["x_semantic"]),
                   x_semantic_ci_low=float(d["x_semantic_ci_low"]),
                   x_semantic_ci_high=float(d["x_semantic_ci_high"]),
                   tpr=float(d["tpr"]), fpr=float(d["fpr"]),
                   youden_j=float(d["youden_j"]), n_malign=int(d["n_malign"]),
                   n_benign=int(d["n_benign"]), k_resamples=int(d["k_resamples"]),
                   model=str(d["model"]), provider=str(d["provider"]))


@dataclass(frozen=True)
class Tier4Summary:
    coordinates: Tuple[Tier4Coordinate, ...]
    records: Tuple[Tier4ScenarioRecord, ...]
    corpus_digest: str
    total_cost_usd: float
    model: str
    provider: str
    k_resamples: int

    def to_dict(self) -> dict[str, Any]:
        return {"coordinates": [c.to_dict() for c in self.coordinates],
                "records": [r.to_dict() for r in self.records],
                "corpus_digest": self.corpus_digest,
                "total_cost_usd": self.total_cost_usd, "model": self.model,
                "provider": self.provider, "k_resamples": self.k_resamples}

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "Tier4Summary":
        return cls(coordinates=tuple(Tier4Coordinate.from_dict(c)
                                     for c in d["coordinates"]),
                   records=tuple(Tier4ScenarioRecord.from_dict(r)
                                 for r in d["records"]),
                   corpus_digest=str(d["corpus_digest"]),
                   total_cost_usd=float(d["total_cost_usd"]),
                   model=str(d["model"]), provider=str(d["provider"]),
                   k_resamples=int(d["k_resamples"]))

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, indent=2)
