"""Frozen schema for a single full-corpus injection benchmark result.

Session 048: Each scenario execution against the 27-scenario
InjectionCorpusRegistry emits one FramingBenchmarkResult. The schema
is the sole contract between the runner and the analysis layer; new
failure modes become typed fields rather than silent swallows.

Categories are normalized to lowercase strings matching the
InjectionCorpusRegistry taxonomy: "direct" | "framing" | "propagation".
``framing_strategy`` is populated only for Category B expansion
scenarios (INJ-013..INJ-027); all other scenarios carry ``None``.

``pipeline_error`` is populated when the guarded cycle raised any
exception during execution. The scenario is still emitted as a
result — the runner never lets a per-scenario failure bubble out.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any, Mapping, Optional


VALID_CATEGORIES: frozenset[str] = frozenset({"direct", "framing", "propagation"})


@dataclass(frozen=True)
class FramingBenchmarkResult:
    """One scenario's execution outcome in the full-corpus benchmark.

    Attributes:
        scenario_id: Canonical injection scenario ID ("INJ-NNN").
        category: Normalized category label — one of
            {"direct", "framing", "propagation"}.
        framing_strategy: The Category B expansion ``framing_strategy``
            identifier, or ``None`` for scenarios outside that corpus.
        expected_verdict: Expected verdict label from the scenario
            metadata (e.g., "THREAT_CONFIRMED").
        actual_verdict: Final verdict label emitted by OracleJudge,
            normalized to uppercase. Empty string when
            ``pipeline_error`` is populated.
        firewall_detected: Whether the OracleFirewall flagged the
            Architect's output (not-passed).
        taint_score: Firewall taint score in [0.0, 1.0].
        confidence_trajectory: Per-phase confidence values captured
            during the cycle. Conventionally (architect, skeptic,
            final_verdict). Empty tuple when pipeline_error is set.
        pipeline_error: Free-form error string when the cycle raised.
            ``None`` on successful execution.
        elapsed_ms: Wall-clock runtime in milliseconds; non-negative.
    """

    scenario_id: str
    category: str
    framing_strategy: Optional[str]
    expected_verdict: str
    actual_verdict: str
    firewall_detected: bool
    taint_score: float
    confidence_trajectory: tuple[float, ...]
    pipeline_error: Optional[str]
    elapsed_ms: int

    def __post_init__(self) -> None:
        """Validate invariants that would otherwise silently corrupt analysis.

        Raises:
            ValueError: If taint_score is outside [0, 1] or elapsed_ms is
                negative, or if category is not one of the valid labels.
            TypeError: If confidence_trajectory is not a tuple (lists and
                sequences are rejected so immutability survives).
        """
        if not isinstance(self.confidence_trajectory, tuple):
            raise TypeError(
                "confidence_trajectory must be a tuple, "
                f"got {type(self.confidence_trajectory).__name__}"
            )
        if self.category not in VALID_CATEGORIES:
            raise ValueError(
                f"category must be one of {sorted(VALID_CATEGORIES)}, "
                f"got '{self.category}'"
            )
        if not 0.0 <= self.taint_score <= 1.0:
            raise ValueError(
                f"taint_score must be in [0.0, 1.0], got {self.taint_score}"
            )
        if self.elapsed_ms < 0:
            raise ValueError(
                f"elapsed_ms must be non-negative, got {self.elapsed_ms}"
            )

    # ------------------------------------------------------------------
    # Serialization helpers
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable dict representation of the result.

        The confidence_trajectory tuple is converted to a list so the
        output survives ``json.dumps`` without a custom encoder.
        """
        payload = asdict(self)
        payload["confidence_trajectory"] = list(self.confidence_trajectory)
        return payload

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "FramingBenchmarkResult":
        """Reconstruct a result from its ``to_dict`` output.

        Args:
            data: Mapping matching the ``to_dict`` layout.

        Returns:
            A new FramingBenchmarkResult with validated fields.
        """
        trajectory = tuple(float(x) for x in data["confidence_trajectory"])
        return cls(
            scenario_id=str(data["scenario_id"]),
            category=str(data["category"]),
            framing_strategy=data.get("framing_strategy"),
            expected_verdict=str(data["expected_verdict"]),
            actual_verdict=str(data["actual_verdict"]),
            firewall_detected=bool(data["firewall_detected"]),
            taint_score=float(data["taint_score"]),
            confidence_trajectory=trajectory,
            pipeline_error=data.get("pipeline_error"),
            elapsed_ms=int(data["elapsed_ms"]),
        )

    def to_json(self) -> str:
        """Render the result as a canonical JSON string."""
        return json.dumps(self.to_dict(), sort_keys=True)
