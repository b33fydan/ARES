"""Tests for FramingBenchmarkResultV3 — 3-way pipeline_variant schema.

Covers:
    * Validation: only {"full", "ablated", "light"} accepted.
    * Property forwarding from inner v1.
    * JSON round-trip preserves "light".
    * to_v3() lift preserves inner reference.
    * Backwards-compat: v1 dicts default to "full".
"""

from __future__ import annotations

import json
from dataclasses import FrozenInstanceError

import pytest

from ares.dialectic.schemas.framing_benchmark_result import (
    FramingBenchmarkResult,
)
from ares.dialectic.schemas.framing_benchmark_result_v3 import (
    DEFAULT_PIPELINE_VARIANT_V3,
    VALID_PIPELINE_VARIANTS_V3,
    FramingBenchmarkResultV3,
    to_v3,
)


def _v1(**overrides):
    base = dict(
        scenario_id="INJ-031",
        category="framing",
        framing_strategy="temporal_x",
        expected_verdict="THREAT_CONFIRMED",
        actual_verdict="THREAT_CONFIRMED",
        firewall_detected=False,
        taint_score=0.25,
        confidence_trajectory=(0.8, 0.3, 0.7),
        pipeline_error=None,
        elapsed_ms=100,
    )
    base.update(overrides)
    return FramingBenchmarkResult(**base)


class TestValidVariants:
    def test_accepts_full(self):
        r = FramingBenchmarkResultV3(inner=_v1(), pipeline_variant="full")
        assert r.pipeline_variant == "full"

    def test_accepts_ablated(self):
        r = FramingBenchmarkResultV3(inner=_v1(), pipeline_variant="ablated")
        assert r.pipeline_variant == "ablated"

    def test_accepts_light(self):
        r = FramingBenchmarkResultV3(inner=_v1(), pipeline_variant="light")
        assert r.pipeline_variant == "light"

    def test_rejects_unknown(self):
        with pytest.raises(ValueError, match="pipeline_variant"):
            FramingBenchmarkResultV3(inner=_v1(), pipeline_variant="dim")

    def test_default_is_full(self):
        r = FramingBenchmarkResultV3(inner=_v1())
        assert r.pipeline_variant == "full"

    def test_valid_variants_constant(self):
        assert VALID_PIPELINE_VARIANTS_V3 == frozenset({"full", "ablated", "light"})

    def test_default_constant(self):
        assert DEFAULT_PIPELINE_VARIANT_V3 == "full"


class TestPropertyForwarding:
    def test_scenario_id(self):
        r = FramingBenchmarkResultV3(inner=_v1(scenario_id="INJ-Z"))
        assert r.scenario_id == "INJ-Z"

    def test_category(self):
        r = FramingBenchmarkResultV3(
            inner=_v1(category="direct", framing_strategy=None),
        )
        assert r.category == "direct"

    def test_all_inner_fields_forwarded(self):
        v1 = _v1(
            scenario_id="INJ-X",
            framing_strategy="causal_y",
            expected_verdict="INCONCLUSIVE",
            actual_verdict="THREAT_CONFIRMED",
            firewall_detected=True,
            taint_score=0.95,
            confidence_trajectory=(0.9, 0.4, 0.8),
            pipeline_error="oops",
            elapsed_ms=1000,
        )
        r = FramingBenchmarkResultV3(inner=v1, pipeline_variant="light")
        assert r.scenario_id == "INJ-X"
        assert r.framing_strategy == "causal_y"
        assert r.expected_verdict == "INCONCLUSIVE"
        assert r.actual_verdict == "THREAT_CONFIRMED"
        assert r.firewall_detected is True
        assert r.taint_score == 0.95
        assert r.confidence_trajectory == (0.9, 0.4, 0.8)
        assert r.pipeline_error == "oops"
        assert r.elapsed_ms == 1000


class TestValidation:
    def test_rejects_non_v1_inner(self):
        with pytest.raises(TypeError, match="inner"):
            FramingBenchmarkResultV3(inner="x")  # type: ignore[arg-type]


class TestFrozen:
    def test_cannot_mutate_variant(self):
        r = FramingBenchmarkResultV3(inner=_v1())
        with pytest.raises(FrozenInstanceError):
            r.pipeline_variant = "light"  # type: ignore[misc]


class TestSerialization:
    def test_roundtrip_light(self):
        r = FramingBenchmarkResultV3(inner=_v1(), pipeline_variant="light")
        d = r.to_dict()
        assert d["pipeline_variant"] == "light"
        rebuilt = FramingBenchmarkResultV3.from_dict(d)
        assert rebuilt == r

    def test_roundtrip_ablated(self):
        r = FramingBenchmarkResultV3(inner=_v1(), pipeline_variant="ablated")
        rebuilt = FramingBenchmarkResultV3.from_dict(r.to_dict())
        assert rebuilt.pipeline_variant == "ablated"

    def test_v1_dict_defaults_to_full(self):
        v1 = _v1()
        r = FramingBenchmarkResultV3.from_dict(v1.to_dict())
        assert r.pipeline_variant == "full"

    def test_to_json_parses(self):
        r = FramingBenchmarkResultV3(inner=_v1(), pipeline_variant="light")
        data = json.loads(r.to_json())
        assert data["pipeline_variant"] == "light"


class TestToV3Helper:
    def test_defaults_to_full(self):
        r = to_v3(_v1())
        assert r.pipeline_variant == "full"

    def test_explicit_light(self):
        r = to_v3(_v1(), "light")
        assert r.pipeline_variant == "light"

    def test_preserves_inner(self):
        v1 = _v1()
        r = to_v3(v1, "ablated")
        assert r.inner is v1

    def test_rejects_bad_variant(self):
        with pytest.raises(ValueError):
            to_v3(_v1(), "mystery")
