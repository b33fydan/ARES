"""4-bit InfluenceLeakage schema with weighted scalar — Session 059.

Pre-registered values (locked, do not modify):

    Weights (sum to 1.0):
        verdict_changed:           0.40
        action_changed:            0.20
        cited_facts_changed:       0.20
        confidence_drift_exceeded: 0.20

    Confidence drift threshold:    |Δ| > 0.10
    Kill direction:                weighted_scalar > 0.0  =>  kill criterion fires

The per-layer mapping for each bit (Architect / Skeptic / Oracle / Light
Skeptic / Final Verdict) lives in :func:`compute_leakage_for_layer`.
That function consumes baseline + mutated trace records and returns a
frozen :class:`InfluenceLeakage`.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import Any, Final, Literal, Mapping


# ---------------------------------------------------------------------------
# Pre-registered constants (locked at session start)
# ---------------------------------------------------------------------------


WEIGHT_VERDICT_CHANGED: Final[float] = 0.40
WEIGHT_ACTION_CHANGED: Final[float] = 0.20
WEIGHT_CITED_FACTS_CHANGED: Final[float] = 0.20
WEIGHT_CONFIDENCE_DRIFT_EXCEEDED: Final[float] = 0.20

# Sanity: weights must sum to 1.0 (within float epsilon).
_WEIGHT_SUM: Final[float] = (
    WEIGHT_VERDICT_CHANGED
    + WEIGHT_ACTION_CHANGED
    + WEIGHT_CITED_FACTS_CHANGED
    + WEIGHT_CONFIDENCE_DRIFT_EXCEEDED
)
assert abs(_WEIGHT_SUM - 1.0) < 1e-9, (
    f"InfluenceLeakage weights must sum to 1.0; got {_WEIGHT_SUM}"
)

CONFIDENCE_DRIFT_THRESHOLD: Final[float] = 0.10
"""|Δ| > this threshold flips the confidence_drift_exceeded bit."""

KILL_THRESHOLD: Final[float] = 0.0
"""weighted_scalar > KILL_THRESHOLD => kill criterion fires."""


Layer = Literal[
    "architect",
    "skeptic_llm",
    "light_skeptic",
    "oracle",
    "final_verdict",
]
"""Pipeline layers the leakage vector is computed against."""

VALID_LAYERS: Final[frozenset[str]] = frozenset(
    {"architect", "skeptic_llm", "light_skeptic", "oracle", "final_verdict"}
)


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class InfluenceLeakage:
    """4-bit influence vector for one pipeline layer over one (scenario,
    operator) pair.

    All four bits apply to every layer; per-layer semantics live in the
    runner's signal-extraction code. The frozen dataclass enforces only
    the schema invariants (booleans + weight-aware arithmetic).

    Attributes:
        verdict_changed: outcome label drift at this layer.
        action_changed: action / stance / triggered-rules drift at
            this layer.
        cited_facts_changed: nonempty symmetric difference on the
            layer's cited fact-id set.
        confidence_drift_exceeded: |baseline_conf − mutated_conf| >
            CONFIDENCE_DRIFT_THRESHOLD at this layer.
        layer: which pipeline layer this vector describes.
        scenario_id: baseline scenario_id (the pair shares this).
        operator_name: operator that produced the mutated half.
        pair_index: ordinal of this pair in the run, for stable
            ordering in reports.
    """

    verdict_changed: bool
    action_changed: bool
    cited_facts_changed: bool
    confidence_drift_exceeded: bool

    layer: str
    scenario_id: str
    operator_name: str
    pair_index: int

    def __post_init__(self) -> None:
        for name in (
            "verdict_changed",
            "action_changed",
            "cited_facts_changed",
            "confidence_drift_exceeded",
        ):
            value = getattr(self, name)
            if not isinstance(value, bool):
                raise TypeError(
                    f"{name} must be bool, got {type(value).__name__}"
                )
        if self.layer not in VALID_LAYERS:
            raise ValueError(
                f"layer must be one of {sorted(VALID_LAYERS)}; "
                f"got {self.layer!r}"
            )
        if not self.scenario_id:
            raise ValueError("scenario_id must be non-empty")
        if not self.operator_name:
            raise ValueError("operator_name must be non-empty")
        if self.pair_index < 0:
            raise ValueError(
                f"pair_index must be >= 0; got {self.pair_index}"
            )

    # ------------------------------------------------------------------
    # Bit accessors
    # ------------------------------------------------------------------

    @property
    def bits(self) -> tuple[bool, bool, bool, bool]:
        """Return the 4-bit vector in pre-registered order."""
        return (
            self.verdict_changed,
            self.action_changed,
            self.cited_facts_changed,
            self.confidence_drift_exceeded,
        )

    @property
    def weighted_scalar(self) -> float:
        """Σ wᵢ · bitᵢ. Range [0.0, 1.0]."""
        return (
            (WEIGHT_VERDICT_CHANGED if self.verdict_changed else 0.0)
            + (WEIGHT_ACTION_CHANGED if self.action_changed else 0.0)
            + (WEIGHT_CITED_FACTS_CHANGED if self.cited_facts_changed else 0.0)
            + (
                WEIGHT_CONFIDENCE_DRIFT_EXCEEDED
                if self.confidence_drift_exceeded
                else 0.0
            )
        )

    @property
    def all_zero(self) -> bool:
        """True iff every bit is False (no leakage observed)."""
        return not any(self.bits)

    @property
    def kill_fires(self) -> bool:
        """True iff weighted_scalar > KILL_THRESHOLD."""
        return self.weighted_scalar > KILL_THRESHOLD

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["weighted_scalar"] = self.weighted_scalar
        return payload

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "InfluenceLeakage":
        return cls(
            verdict_changed=bool(data["verdict_changed"]),
            action_changed=bool(data["action_changed"]),
            cited_facts_changed=bool(data["cited_facts_changed"]),
            confidence_drift_exceeded=bool(data["confidence_drift_exceeded"]),
            layer=str(data["layer"]),
            scenario_id=str(data["scenario_id"]),
            operator_name=str(data["operator_name"]),
            pair_index=int(data["pair_index"]),
        )

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


# ---------------------------------------------------------------------------
# Layer-specific signal extraction
# ---------------------------------------------------------------------------


def confidence_drift_exceeds_threshold(
    baseline: float,
    mutated: float,
) -> bool:
    """True iff |baseline − mutated| > CONFIDENCE_DRIFT_THRESHOLD."""
    return abs(baseline - mutated) > CONFIDENCE_DRIFT_THRESHOLD


def cited_facts_changed(
    baseline_ids: frozenset[str] | set[str] | tuple[str, ...],
    mutated_ids: frozenset[str] | set[str] | tuple[str, ...],
) -> bool:
    """True iff the symmetric difference is nonempty.

    Handles the n/a case (Light Skeptic doesn't cite facts) by treating
    matched empty inputs as no-change.
    """
    return frozenset(baseline_ids) != frozenset(mutated_ids)


def verdict_changed_from_labels(
    baseline_label: str,
    mutated_label: str,
) -> bool:
    """True iff the two label strings differ."""
    return baseline_label != mutated_label


def action_changed_from_stance(
    baseline_stance: str,
    mutated_stance: str,
) -> bool:
    """True iff the per-layer 'action' string differs.

    The runner is responsible for choosing the right stance string per
    layer:
        architect      -> message_type or top assertion type
        skeptic_llm    -> message_type (REBUTTAL / CONCEDED / etc.)
        light_skeptic  -> sorted triggered_rules tuple, joined
        oracle         -> "conclusive" if outcome != INCONCLUSIVE else
                          "inconclusive"
        final_verdict  -> derived recommendation: ESCALATE if
                          THREAT_CONFIRMED else DISMISS if
                          THREAT_DISMISSED else HOLD
    """
    return baseline_stance != mutated_stance


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


__all__ = [
    "CONFIDENCE_DRIFT_THRESHOLD",
    "InfluenceLeakage",
    "KILL_THRESHOLD",
    "Layer",
    "VALID_LAYERS",
    "WEIGHT_ACTION_CHANGED",
    "WEIGHT_CITED_FACTS_CHANGED",
    "WEIGHT_CONFIDENCE_DRIFT_EXCEEDED",
    "WEIGHT_VERDICT_CHANGED",
    "action_changed_from_stance",
    "cited_facts_changed",
    "confidence_drift_exceeds_threshold",
    "verdict_changed_from_labels",
]
