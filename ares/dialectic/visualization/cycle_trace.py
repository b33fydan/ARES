"""v2 schema for the Prism (Labyrinth panel and beyond).

One CycleSnapshot per (pipeline, baseline-or-mutated) cycle. Four snapshots
per pair (baseline_llm, mutated_llm, baseline_light, mutated_light).
"""

from __future__ import annotations

import json
from dataclasses import dataclass


_VALID_PIPELINES: frozenset[str] = frozenset({"llm", "light"})


@dataclass(frozen=True)
class CycleSnapshot:
    """Per-layer outputs of one pipeline cycle.

    Fields mirror the JSONL trace row (one row from
    ``data/paper_3/leakage_runs/<run_id>/traces.jsonl``).

    Bookkeeping fields like ``cycle_id``, ``operator_name``, ``pair_index``,
    and cost/token counters live on the containing ``PairTrace``, not here —
    this dataclass stays focused on per-layer outputs.
    """

    architect_confidence: float
    architect_cited_facts: tuple[str, ...]
    architect_message_type: str
    skeptic_confidence: float
    skeptic_cited_facts: tuple[str, ...]
    skeptic_message_type: str
    skeptic_triggered_rules: tuple[str, ...]
    oracle_outcome: str
    oracle_confidence: float
    oracle_supporting_facts: tuple[str, ...]
    final_outcome: str
    final_confidence: float
    pipeline: str  # "llm" or "light"

    def __post_init__(self) -> None:
        for name in (
            "architect_confidence",
            "skeptic_confidence",
            "oracle_confidence",
            "final_confidence",
        ):
            value = getattr(self, name)
            if not 0.0 <= value <= 1.0:
                raise ValueError(
                    f"{name} must be in [0.0, 1.0]; got {value}"
                )
        if self.pipeline not in _VALID_PIPELINES:
            raise ValueError(
                f"pipeline must be one of {sorted(_VALID_PIPELINES)}; "
                f"got {self.pipeline!r}"
            )


_VALID_DIVERGING_LAYERS: frozenset[str] = frozenset(
    {"Architect", "Skeptic", "Oracle", "Final", "None"}
)


@dataclass(frozen=True)
class PairTrace:
    """One (scenario, operator) pair, packaged for renderer consumption.

    Both LLM and light pipelines are included when available. At least one
    complete pipeline pair (baseline + mutated) must exist. Per-layer
    leakage bits are populated from the LLM pipeline only (light pipeline
    leakage is reported via narrow_leakage / broad_leakage flags).
    """

    pair_index: int
    scenario_id: str
    operator: str
    baseline_llm: CycleSnapshot | None
    mutated_llm: CycleSnapshot | None
    baseline_light: CycleSnapshot | None
    mutated_light: CycleSnapshot | None
    narrow_leakage: bool
    broad_leakage: bool
    first_diverging_layer: str
    llm_architect_bits: tuple[bool, bool, bool, bool]
    llm_skeptic_bits: tuple[bool, bool, bool, bool]
    llm_oracle_bits: tuple[bool, bool, bool, bool]
    llm_final_bits: tuple[bool, bool, bool, bool]

    def __post_init__(self) -> None:
        if self.pair_index < 0:
            raise ValueError(
                f"pair_index must be >= 0; got {self.pair_index}"
            )
        if not self.scenario_id:
            raise ValueError("scenario_id must be non-empty")
        if not self.operator:
            raise ValueError("operator must be non-empty")
        if self.first_diverging_layer not in _VALID_DIVERGING_LAYERS:
            raise ValueError(
                f"first_diverging_layer must be one of "
                f"{sorted(_VALID_DIVERGING_LAYERS)}; "
                f"got {self.first_diverging_layer!r}"
            )

        has_llm = self.baseline_llm is not None and self.mutated_llm is not None
        has_light = (
            self.baseline_light is not None and self.mutated_light is not None
        )
        if not (has_llm or has_light):
            raise ValueError(
                f"pair {self.pair_index} "
                f"({self.scenario_id}/{self.operator}) must have at least "
                "one complete pipeline pair (both baseline and mutated)"
            )

        for name in (
            "llm_architect_bits",
            "llm_skeptic_bits",
            "llm_oracle_bits",
            "llm_final_bits",
        ):
            bits = getattr(self, name)
            if len(bits) != 4:
                raise ValueError(
                    f"{name} must have exactly 4 bits; got {len(bits)}"
                )
            for b in bits:
                if not isinstance(b, bool):
                    raise TypeError(
                        f"{name} elements must be bool; got "
                        f"{type(b).__name__}"
                    )


@dataclass(frozen=True)
class CycleTimelineV2:
    """Top-level v2 timeline. One document per measurement run."""

    schema_version: str
    run_id: str
    operators: tuple[str, ...]
    pairs: tuple[PairTrace, ...]

    def __post_init__(self) -> None:
        if self.schema_version != "v2":
            raise ValueError(
                f"schema_version must be 'v2'; got {self.schema_version!r}"
            )
        if not self.run_id:
            raise ValueError("run_id must be non-empty")
        if not self.operators:
            raise ValueError("operators must be non-empty")
        if not self.pairs:
            raise ValueError("pairs must be non-empty")


def _snapshot_to_dict(snap: CycleSnapshot | None) -> dict | None:
    if snap is None:
        return None
    return {
        "architect_confidence": snap.architect_confidence,
        "architect_cited_facts": list(snap.architect_cited_facts),
        "architect_message_type": snap.architect_message_type,
        "skeptic_confidence": snap.skeptic_confidence,
        "skeptic_cited_facts": list(snap.skeptic_cited_facts),
        "skeptic_message_type": snap.skeptic_message_type,
        "skeptic_triggered_rules": list(snap.skeptic_triggered_rules),
        "oracle_outcome": snap.oracle_outcome,
        "oracle_confidence": snap.oracle_confidence,
        "oracle_supporting_facts": list(snap.oracle_supporting_facts),
        "final_outcome": snap.final_outcome,
        "final_confidence": snap.final_confidence,
        "pipeline": snap.pipeline,
    }


def _pair_to_dict(pair: PairTrace) -> dict:
    return {
        "pair_index": pair.pair_index,
        "scenario_id": pair.scenario_id,
        "operator": pair.operator,
        "baseline_llm": _snapshot_to_dict(pair.baseline_llm),
        "mutated_llm": _snapshot_to_dict(pair.mutated_llm),
        "baseline_light": _snapshot_to_dict(pair.baseline_light),
        "mutated_light": _snapshot_to_dict(pair.mutated_light),
        "narrow_leakage": pair.narrow_leakage,
        "broad_leakage": pair.broad_leakage,
        "first_diverging_layer": pair.first_diverging_layer,
        "llm_architect_bits": list(pair.llm_architect_bits),
        "llm_skeptic_bits": list(pair.llm_skeptic_bits),
        "llm_oracle_bits": list(pair.llm_oracle_bits),
        "llm_final_bits": list(pair.llm_final_bits),
    }


def cycle_timeline_to_json(timeline: CycleTimelineV2) -> str:
    """Serialize a CycleTimelineV2 to deterministic JSON (sorted keys, indent=2)."""
    payload = {
        "schema_version": timeline.schema_version,
        "run_id": timeline.run_id,
        "operators": list(timeline.operators),
        "pairs": [_pair_to_dict(p) for p in timeline.pairs],
    }
    return json.dumps(payload, indent=2, sort_keys=True)
