"""Session 049 v2 schema — FramingBenchmarkResult + pipeline_variant.

Session 048's :class:`FramingBenchmarkResult` is a 10-field frozen
dataclass whose test suite explicitly enumerates the exact field set via
``set(to_dict().keys()) == {...}``. That test is on the Session 049
do-not-modify list, so extending v1 with a new field would trip it.

V2 wraps (composes) a v1 result and adds ``pipeline_variant`` as a
sibling field. Readers of either version can call
:func:`to_v2` / :func:`from_v1` to normalize mixed result sets without
mutating the underlying v1 objects.

Both variants serialise to dict shapes that are JSON-safe; v2 adds
``pipeline_variant`` to the top level alongside the v1 fields so the
output is still a flat dict, friendly to every downstream tool.

Public API:
    FramingBenchmarkResultV2        Frozen (v1 inner + pipeline_variant)
    VALID_PIPELINE_VARIANTS         {"full", "ablated"}
    DEFAULT_PIPELINE_VARIANT        "full"
    to_v2()                         v1 -> v2 (legacy Session 048 outputs)
    from_v1()                       alias for to_v2() for readability
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Mapping, Optional

from ares.dialectic.schemas.framing_benchmark_result import (
    FramingBenchmarkResult,
)


VALID_PIPELINE_VARIANTS: frozenset[str] = frozenset({"full", "ablated"})
DEFAULT_PIPELINE_VARIANT: str = "full"


@dataclass(frozen=True)
class FramingBenchmarkResultV2:
    """A v1 result composed with a pipeline_variant label.

    Attributes:
        inner: The underlying Session 048 :class:`FramingBenchmarkResult`.
            All v1 fields remain accessible via ``.inner.<field>``.
        pipeline_variant: Which pipeline variant produced the inner
            result. ``"full"`` is the Session 048 default pipeline
            (Architect -> firewall -> Skeptic -> Oracle); ``"ablated"``
            is the Session 049 Skeptic-removed variant.
    """

    inner: FramingBenchmarkResult
    pipeline_variant: str = DEFAULT_PIPELINE_VARIANT

    def __post_init__(self) -> None:
        if not isinstance(self.inner, FramingBenchmarkResult):
            raise TypeError(
                "inner must be a FramingBenchmarkResult, "
                f"got {type(self.inner).__name__}"
            )
        if self.pipeline_variant not in VALID_PIPELINE_VARIANTS:
            raise ValueError(
                f"pipeline_variant must be one of "
                f"{sorted(VALID_PIPELINE_VARIANTS)}, "
                f"got '{self.pipeline_variant}'"
            )

    # ------------------------------------------------------------------
    # Convenience accessors (forwarded to inner for ergonomics)
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
        """Flat dict with v1 fields + pipeline_variant at the top level."""
        payload = self.inner.to_dict()
        payload["pipeline_variant"] = self.pipeline_variant
        return payload

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "FramingBenchmarkResultV2":
        """Reconstruct from either v1 or v2 serialised output.

        v1 dicts (Session 048 ``raw_results.json``) default
        ``pipeline_variant`` to ``"full"`` — the Session 048 pipeline.
        """
        inner = FramingBenchmarkResult.from_dict(data)
        variant = str(data.get("pipeline_variant", DEFAULT_PIPELINE_VARIANT))
        return cls(inner=inner, pipeline_variant=variant)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


def to_v2(
    result: FramingBenchmarkResult,
    pipeline_variant: str = DEFAULT_PIPELINE_VARIANT,
) -> FramingBenchmarkResultV2:
    """Lift a v1 result into v2, annotating it with ``pipeline_variant``."""
    return FramingBenchmarkResultV2(
        inner=result,
        pipeline_variant=pipeline_variant,
    )


# Readability alias — tells the call-site that the v1 is from a legacy source.
from_v1 = to_v2
