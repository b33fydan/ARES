"""Session 050 v3 schema — FramingBenchmarkResult + 3-way pipeline_variant.

Session 049's :class:`FramingBenchmarkResultV2` restricts
``pipeline_variant`` to ``{"full", "ablated"}`` — a sealed enum,
tested by an explicit set-equality assertion on the v2 do-not-modify
list. Adding ``"light"`` to that set would trip the test.

V3 is the narrow fix: a second composition layer that accepts all three
variants and delegates to a v1 result for every field. Callers that
need the pre-existing behaviour can continue to use v2; runners that
emit light results use v3 directly.

Round-trip contract: any v2 serialised dict reads back losslessly as
v3 (``full``/``ablated`` match the valid-variant set). v3 dicts carrying
``"light"`` load correctly here.

Public API:
    FramingBenchmarkResultV3          Frozen (v1 inner + pipeline_variant)
    VALID_PIPELINE_VARIANTS_V3        {"full", "ablated", "light"}
    DEFAULT_PIPELINE_VARIANT_V3       "full"
    to_v3()                           v1 -> v3 lift
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Mapping, Optional

from ares.dialectic.schemas.framing_benchmark_result import (
    FramingBenchmarkResult,
)


VALID_PIPELINE_VARIANTS_V3: frozenset[str] = frozenset({"full", "ablated", "light"})
DEFAULT_PIPELINE_VARIANT_V3: str = "full"


@dataclass(frozen=True)
class FramingBenchmarkResultV3:
    """A v1 result composed with a 3-way pipeline_variant label.

    Attributes:
        inner: The underlying :class:`FramingBenchmarkResult`.
        pipeline_variant: One of ``{"full", "ablated", "light"}``.
    """

    inner: FramingBenchmarkResult
    pipeline_variant: str = DEFAULT_PIPELINE_VARIANT_V3

    def __post_init__(self) -> None:
        if not isinstance(self.inner, FramingBenchmarkResult):
            raise TypeError(
                "inner must be a FramingBenchmarkResult, "
                f"got {type(self.inner).__name__}"
            )
        if self.pipeline_variant not in VALID_PIPELINE_VARIANTS_V3:
            raise ValueError(
                f"pipeline_variant must be one of "
                f"{sorted(VALID_PIPELINE_VARIANTS_V3)}, "
                f"got '{self.pipeline_variant}'"
            )

    # ------------------------------------------------------------------
    # Accessors — ergonomic forwarding to the inner v1 result
    # ------------------------------------------------------------------

    @property
    def scenario_id(self) -> str:
        return self.inner.scenario_id

    @property
    def category(self) -> str:
        return self.inner.category

    @property
    def framing_strategy(self) -> Optional[str]:
        return self.inner.framing_strategy

    @property
    def expected_verdict(self) -> str:
        return self.inner.expected_verdict

    @property
    def actual_verdict(self) -> str:
        return self.inner.actual_verdict

    @property
    def firewall_detected(self) -> bool:
        return self.inner.firewall_detected

    @property
    def taint_score(self) -> float:
        return self.inner.taint_score

    @property
    def confidence_trajectory(self) -> tuple[float, ...]:
        return self.inner.confidence_trajectory

    @property
    def pipeline_error(self) -> Optional[str]:
        return self.inner.pipeline_error

    @property
    def elapsed_ms(self) -> int:
        return self.inner.elapsed_ms

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        payload = self.inner.to_dict()
        payload["pipeline_variant"] = self.pipeline_variant
        return payload

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "FramingBenchmarkResultV3":
        inner = FramingBenchmarkResult.from_dict(data)
        variant = str(data.get("pipeline_variant", DEFAULT_PIPELINE_VARIANT_V3))
        return cls(inner=inner, pipeline_variant=variant)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


def to_v3(
    result: FramingBenchmarkResult,
    pipeline_variant: str = DEFAULT_PIPELINE_VARIANT_V3,
) -> FramingBenchmarkResultV3:
    """Lift a v1 result into v3, annotating it with ``pipeline_variant``."""
    return FramingBenchmarkResultV3(
        inner=result,
        pipeline_variant=pipeline_variant,
    )
