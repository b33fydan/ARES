"""Tests for FramingBenchmarkResultV2 — v1 composition + pipeline_variant.

Covers:
    1. Composition preserves every v1 field via property forwarding.
    2. pipeline_variant validation — only "full" or "ablated" accepted.
    3. JSON round-trip survives both v1-only and v2 shapes.
    4. to_v2() / from_v1() lift a v1 result without mutation.
    5. Backwards-compat: v1 dicts (Session 048) default to "full".
    6. Frozen immutability enforcement.
"""

from __future__ import annotations

import json
from dataclasses import FrozenInstanceError

import pytest

from ares.dialectic.schemas.framing_benchmark_result import (
    FramingBenchmarkResult,
)
from ares.dialectic.schemas.framing_benchmark_result_v2 import (
    DEFAULT_PIPELINE_VARIANT,
    VALID_PIPELINE_VARIANTS,
    FramingBenchmarkResultV2,
    from_v1,
    to_v2,
)


def _v1(**overrides) -> FramingBenchmarkResult:
    base = dict(
        scenario_id="INJ-013",
        category="framing",
        framing_strategy="severity_downgrade_routine",
        expected_verdict="THREAT_CONFIRMED",
        actual_verdict="THREAT_CONFIRMED",
        firewall_detected=False,
        taint_score=0.25,
        confidence_trajectory=(0.8, 0.3, 0.7),
        pipeline_error=None,
        elapsed_ms=4200,
    )
    base.update(overrides)
    return FramingBenchmarkResult(**base)


# =============================================================================
# Composition + forwarding
# =============================================================================


class TestComposition:
    def test_inner_is_v1_instance(self):
        v2 = FramingBenchmarkResultV2(inner=_v1())
        assert isinstance(v2.inner, FramingBenchmarkResult)

    def test_inner_preserved_exactly(self):
        v1 = _v1()
        v2 = FramingBenchmarkResultV2(inner=v1, pipeline_variant="ablated")
        assert v2.inner is v1

    def test_default_pipeline_variant_is_full(self):
        v2 = FramingBenchmarkResultV2(inner=_v1())
        assert v2.pipeline_variant == "full"

    def test_explicit_pipeline_variant_set(self):
        v2 = FramingBenchmarkResultV2(inner=_v1(), pipeline_variant="ablated")
        assert v2.pipeline_variant == "ablated"


class TestPropertyForwarding:
    def test_scenario_id_forwards(self):
        v2 = FramingBenchmarkResultV2(inner=_v1(scenario_id="INJ-028"))
        assert v2.scenario_id == "INJ-028"

    def test_category_forwards(self):
        v2 = FramingBenchmarkResultV2(inner=_v1(category="direct",
                                                framing_strategy=None))
        assert v2.category == "direct"

    def test_framing_strategy_forwards(self):
        v2 = FramingBenchmarkResultV2(inner=_v1(framing_strategy=None))
        assert v2.framing_strategy is None

    def test_expected_verdict_forwards(self):
        v2 = FramingBenchmarkResultV2(inner=_v1(expected_verdict="INCONCLUSIVE"))
        assert v2.expected_verdict == "INCONCLUSIVE"

    def test_actual_verdict_forwards(self):
        v2 = FramingBenchmarkResultV2(inner=_v1(actual_verdict="THREAT_DISMISSED"))
        assert v2.actual_verdict == "THREAT_DISMISSED"

    def test_firewall_detected_forwards(self):
        v2 = FramingBenchmarkResultV2(inner=_v1(firewall_detected=True,
                                                taint_score=0.9))
        assert v2.firewall_detected is True

    def test_taint_score_forwards(self):
        v2 = FramingBenchmarkResultV2(inner=_v1(taint_score=0.65))
        assert v2.taint_score == 0.65

    def test_trajectory_forwards(self):
        v2 = FramingBenchmarkResultV2(
            inner=_v1(confidence_trajectory=(0.1, 0.2, 0.3)),
        )
        assert v2.confidence_trajectory == (0.1, 0.2, 0.3)

    def test_pipeline_error_forwards(self):
        v2 = FramingBenchmarkResultV2(
            inner=_v1(
                pipeline_error="RuntimeError: oops",
                actual_verdict="",
                confidence_trajectory=(),
            ),
        )
        assert v2.pipeline_error == "RuntimeError: oops"

    def test_elapsed_ms_forwards(self):
        v2 = FramingBenchmarkResultV2(inner=_v1(elapsed_ms=9999))
        assert v2.elapsed_ms == 9999


# =============================================================================
# Validation
# =============================================================================


class TestValidation:
    def test_valid_pipeline_variants_constant(self):
        assert VALID_PIPELINE_VARIANTS == frozenset({"full", "ablated"})

    def test_default_pipeline_variant_constant(self):
        assert DEFAULT_PIPELINE_VARIANT == "full"

    def test_rejects_unknown_variant(self):
        with pytest.raises(ValueError, match="pipeline_variant"):
            FramingBenchmarkResultV2(inner=_v1(), pipeline_variant="partial")

    def test_rejects_empty_variant(self):
        with pytest.raises(ValueError, match="pipeline_variant"):
            FramingBenchmarkResultV2(inner=_v1(), pipeline_variant="")

    def test_rejects_non_v1_inner(self):
        with pytest.raises(TypeError, match="inner"):
            FramingBenchmarkResultV2(inner="not a result")  # type: ignore[arg-type]

    def test_rejects_inner_dict(self):
        with pytest.raises(TypeError, match="inner"):
            FramingBenchmarkResultV2(inner={"scenario_id": "X"})  # type: ignore[arg-type]


# =============================================================================
# Frozen enforcement
# =============================================================================


class TestFrozen:
    def test_cannot_mutate_inner(self):
        v2 = FramingBenchmarkResultV2(inner=_v1())
        with pytest.raises(FrozenInstanceError):
            v2.inner = _v1(scenario_id="INJ-X")  # type: ignore[misc]

    def test_cannot_mutate_pipeline_variant(self):
        v2 = FramingBenchmarkResultV2(inner=_v1())
        with pytest.raises(FrozenInstanceError):
            v2.pipeline_variant = "ablated"  # type: ignore[misc]

    def test_equal_instances_are_hashable(self):
        v1 = _v1()
        v2a = FramingBenchmarkResultV2(inner=v1, pipeline_variant="full")
        v2b = FramingBenchmarkResultV2(inner=v1, pipeline_variant="full")
        assert hash(v2a) == hash(v2b)


# =============================================================================
# Serialization
# =============================================================================


class TestSerialization:
    def test_to_dict_includes_variant(self):
        v2 = FramingBenchmarkResultV2(inner=_v1(), pipeline_variant="ablated")
        d = v2.to_dict()
        assert d["pipeline_variant"] == "ablated"

    def test_to_dict_includes_all_v1_fields(self):
        v2 = FramingBenchmarkResultV2(inner=_v1())
        d = v2.to_dict()
        for key in (
            "scenario_id", "category", "framing_strategy",
            "expected_verdict", "actual_verdict", "firewall_detected",
            "taint_score", "confidence_trajectory", "pipeline_error",
            "elapsed_ms",
        ):
            assert key in d

    def test_roundtrip_preserves_variant(self):
        v2 = FramingBenchmarkResultV2(inner=_v1(), pipeline_variant="ablated")
        rebuilt = FramingBenchmarkResultV2.from_dict(v2.to_dict())
        assert rebuilt.pipeline_variant == "ablated"

    def test_roundtrip_preserves_inner_fields(self):
        v2 = FramingBenchmarkResultV2(
            inner=_v1(scenario_id="INJ-028", firewall_detected=True,
                      taint_score=0.77),
        )
        rebuilt = FramingBenchmarkResultV2.from_dict(v2.to_dict())
        assert rebuilt.scenario_id == "INJ-028"
        assert rebuilt.firewall_detected is True
        assert rebuilt.taint_score == 0.77

    def test_v1_dict_defaults_to_full(self):
        """Session 048 outputs lack pipeline_variant — should load as full."""
        v1 = _v1()
        rebuilt = FramingBenchmarkResultV2.from_dict(v1.to_dict())
        assert rebuilt.pipeline_variant == "full"

    def test_to_json_is_valid_json(self):
        v2 = FramingBenchmarkResultV2(inner=_v1(), pipeline_variant="ablated")
        data = json.loads(v2.to_json())
        assert data["pipeline_variant"] == "ablated"


# =============================================================================
# to_v2 / from_v1 helpers
# =============================================================================


class TestToV2Helper:
    def test_to_v2_defaults_to_full(self):
        v1 = _v1()
        v2 = to_v2(v1)
        assert v2.pipeline_variant == "full"

    def test_to_v2_with_explicit_variant(self):
        v1 = _v1()
        v2 = to_v2(v1, pipeline_variant="ablated")
        assert v2.pipeline_variant == "ablated"

    def test_to_v2_preserves_inner_reference(self):
        v1 = _v1()
        v2 = to_v2(v1, "ablated")
        assert v2.inner is v1

    def test_to_v2_rejects_bad_variant(self):
        v1 = _v1()
        with pytest.raises(ValueError, match="pipeline_variant"):
            to_v2(v1, "mystery")

    def test_from_v1_is_alias_for_to_v2(self):
        assert from_v1 is to_v2
