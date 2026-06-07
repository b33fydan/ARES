# ares/dialectic/measurement/read_depth_frontier_schema.py
"""Frozen result schema for the read-depth robustness frontier (Phase B).

Every type is a frozen dataclass with ``to_dict``/``from_dict`` so a run can
be persisted to JSON and re-read by the Phase-C plotting/report stage. A
tier-4 (LLM anchor) coordinate is intentionally absent in Phase B — the
deterministic harness populates only the four offline rungs.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import Any, Mapping, Tuple

VIEW_STANDALONE = "standalone"
VIEW_CUMULATIVE = "cumulative"
VIEWS: Tuple[str, ...] = (VIEW_STANDALONE, VIEW_CUMULATIVE)


@dataclass(frozen=True)
class FrontierConfig:
    """Run configuration (operating point + operator rosters + seed)."""

    operating_point: float = 0.0
    semantic_operator_names: Tuple[str, ...] = ()
    lexical_operator_names: Tuple[str, ...] = ()
    seed: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "operating_point": self.operating_point,
            "semantic_operator_names": list(self.semantic_operator_names),
            "lexical_operator_names": list(self.lexical_operator_names),
            "seed": self.seed,
        }

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "FrontierConfig":
        return cls(
            operating_point=float(d["operating_point"]),
            semantic_operator_names=tuple(d["semantic_operator_names"]),
            lexical_operator_names=tuple(d["lexical_operator_names"]),
            seed=int(d["seed"]),
        )


@dataclass(frozen=True)
class TierCoordinate:
    """One (X, Y) point: a tier under one view."""

    tier_id: str
    view: str
    x_semantic: float
    x_lexical: float
    tpr: float
    fpr: float
    youden_j: float
    n_malign: int
    n_benign: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "TierCoordinate":
        return cls(
            tier_id=str(d["tier_id"]),
            view=str(d["view"]),
            x_semantic=float(d["x_semantic"]),
            x_lexical=float(d["x_lexical"]),
            tpr=float(d["tpr"]),
            fpr=float(d["fpr"]),
            youden_j=float(d["youden_j"]),
            n_malign=int(d["n_malign"]),
            n_benign=int(d["n_benign"]),
        )


@dataclass(frozen=True)
class ScenarioVerdictRecord:
    """Per (scenario, tier, view) verdict + perturbation flip counts.

    ``n_mut_*`` is the number of perturbations in that family that actually
    mutated the scenario (no-ops excluded). It is a scenario+family property,
    repeated across the scenario's tier records for convenience.
    """

    scenario_id: str
    tier_id: str
    view: str
    is_malign: bool
    stratum: str
    baseline_malign_verdict: bool
    malign_score: float
    n_mut_semantic: int
    flips_semantic: int
    n_mut_lexical: int
    flips_lexical: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "ScenarioVerdictRecord":
        return cls(
            scenario_id=str(d["scenario_id"]),
            tier_id=str(d["tier_id"]),
            view=str(d["view"]),
            is_malign=bool(d["is_malign"]),
            stratum=str(d["stratum"]),
            baseline_malign_verdict=bool(d["baseline_malign_verdict"]),
            malign_score=float(d["malign_score"]),
            n_mut_semantic=int(d["n_mut_semantic"]),
            flips_semantic=int(d["flips_semantic"]),
            n_mut_lexical=int(d["n_mut_lexical"]),
            flips_lexical=int(d["flips_lexical"]),
        )


@dataclass(frozen=True)
class PositiveControlRecord:
    """Did injecting a genuine authorization fact MOVE this tier's verdict?"""

    scenario_id: str
    tier_id: str
    view: str
    baseline_malign_verdict: bool
    controlled_malign_verdict: bool
    moved: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "PositiveControlRecord":
        return cls(
            scenario_id=str(d["scenario_id"]),
            tier_id=str(d["tier_id"]),
            view=str(d["view"]),
            baseline_malign_verdict=bool(d["baseline_malign_verdict"]),
            controlled_malign_verdict=bool(d["controlled_malign_verdict"]),
            moved=bool(d["moved"]),
        )


@dataclass(frozen=True)
class FrontierSummary:
    """The full Phase-B result: coordinates + per-scenario records + controls."""

    coordinates: Tuple[TierCoordinate, ...]
    records: Tuple[ScenarioVerdictRecord, ...]
    positive_control_records: Tuple[PositiveControlRecord, ...]
    corpus_digest: str
    config: FrontierConfig

    def to_dict(self) -> dict[str, Any]:
        return {
            "coordinates": [c.to_dict() for c in self.coordinates],
            "records": [r.to_dict() for r in self.records],
            "positive_control_records": [
                p.to_dict() for p in self.positive_control_records
            ],
            "corpus_digest": self.corpus_digest,
            "config": self.config.to_dict(),
        }

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "FrontierSummary":
        return cls(
            coordinates=tuple(
                TierCoordinate.from_dict(x) for x in d["coordinates"]
            ),
            records=tuple(
                ScenarioVerdictRecord.from_dict(x) for x in d["records"]
            ),
            positive_control_records=tuple(
                PositiveControlRecord.from_dict(x)
                for x in d["positive_control_records"]
            ),
            corpus_digest=str(d["corpus_digest"]),
            config=FrontierConfig.from_dict(d["config"]),
        )

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, indent=2)
