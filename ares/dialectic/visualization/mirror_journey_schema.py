"""Schema for the ARES-VISION "Mirror" journey (mirror-v1).

One document per measurement run. Consumed by the standalone renderer at
skyframe-main/assets/ares/mirror.html. New file (ARES "new files only" rule);
peer of cycle_trace.py.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

_VALID_DIRECTIONS: frozenset[str] = frozenset({"collapse", "expand", "none"})


@dataclass(frozen=True)
class AgentFraming:
    """One agent's baseline->framed cited-fact shift for the hero scenario."""

    agent: str  # "architect" | "skeptic"
    baseline_facts: tuple[str, ...]
    framed_facts: tuple[str, ...]
    jaccard: float       # Jaccard DISTANCE, [0, 1]
    within_noise: float  # baseline within-distance, [0, 1]
    p_value: float
    direction: str       # "collapse" | "expand" | "none"

    def __post_init__(self) -> None:
        for name in ("jaccard", "within_noise", "p_value"):
            v = getattr(self, name)
            if not 0.0 <= v <= 1.0:
                raise ValueError(f"{name} must be in [0, 1]; got {v}")
        if self.direction not in _VALID_DIRECTIONS:
            raise ValueError(
                f"direction must be one of {sorted(_VALID_DIRECTIONS)}; "
                f"got {self.direction!r}"
            )


@dataclass(frozen=True)
class Hero:
    """The INJ-020 mirror: the page centerpiece."""

    scenario_id: str
    facts: tuple[str, ...]   # union of all facts, sorted
    threat_fact: str
    architect: AgentFraming
    skeptic: AgentFraming
    verdict: str
    verdict_held_fraction: float

    def __post_init__(self) -> None:
        if not self.scenario_id:
            raise ValueError("scenario_id must be non-empty")
        if self.threat_fact not in self.facts:
            raise ValueError("threat_fact must be one of facts")
        if not 0.0 <= self.verdict_held_fraction <= 1.0:
            raise ValueError("verdict_held_fraction must be in [0, 1]")


@dataclass(frozen=True)
class Landscape:
    """Aggregate prevalence across the 17 measured scenarios (S084)."""

    opposed: int
    aligned: int
    single: int
    none_: int
    architect_real: int
    skeptic_real: int
    n_scenarios: int

    def __post_init__(self) -> None:
        for name in ("opposed", "aligned", "single", "none_",
                     "architect_real", "skeptic_real", "n_scenarios"):
            if getattr(self, name) < 0:
                raise ValueError(f"{name} must be >= 0")


@dataclass(frozen=True)
class MirrorJourney:
    schema_version: str
    run_id: str
    hero: Hero
    landscape: Landscape

    def __post_init__(self) -> None:
        if self.schema_version != "mirror-v1":
            raise ValueError(
                f"schema_version must be 'mirror-v1'; got {self.schema_version!r}"
            )
        if not self.run_id:
            raise ValueError("run_id must be non-empty")


def _agent_to_dict(a: AgentFraming) -> dict:
    return {
        "agent": a.agent,
        "baseline_facts": list(a.baseline_facts),
        "framed_facts": list(a.framed_facts),
        "jaccard": a.jaccard,
        "within_noise": a.within_noise,
        "p_value": a.p_value,
        "direction": a.direction,
    }


def mirror_journey_to_json(journey: MirrorJourney) -> str:
    """Serialize to deterministic JSON (sorted keys, indent=2)."""
    payload = {
        "schema_version": journey.schema_version,
        "run_id": journey.run_id,
        "hero": {
            "scenario_id": journey.hero.scenario_id,
            "facts": list(journey.hero.facts),
            "threat_fact": journey.hero.threat_fact,
            "architect": _agent_to_dict(journey.hero.architect),
            "skeptic": _agent_to_dict(journey.hero.skeptic),
            "verdict": journey.hero.verdict,
            "verdict_held_fraction": journey.hero.verdict_held_fraction,
        },
        "landscape": {
            "opposed": journey.landscape.opposed,
            "aligned": journey.landscape.aligned,
            "single": journey.landscape.single,
            "none": journey.landscape.none_,
            "architect_real": journey.landscape.architect_real,
            "skeptic_real": journey.landscape.skeptic_real,
            "n_scenarios": journey.landscape.n_scenarios,
        },
    }
    return json.dumps(payload, indent=2, sort_keys=True)
