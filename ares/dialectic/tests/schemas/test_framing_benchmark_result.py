"""Tests for FramingBenchmarkResult — validation, immutability, serialization.

Covers:
    1. Field validation in __post_init__ (taint score bounds, elapsed_ms,
       category enum, tuple-ness of confidence_trajectory).
    2. Frozen dataclass enforcement — no attribute mutation after construction.
    3. JSON round-trip via to_dict / from_dict / to_json.
    4. Handling of optional fields (framing_strategy, pipeline_error).
    5. Boundary values at 0.0 and 1.0 taint_score, 0 elapsed_ms.
"""

from __future__ import annotations

import json
from dataclasses import FrozenInstanceError

import pytest

from ares.dialectic.schemas.framing_benchmark_result import (
    VALID_CATEGORIES,
    FramingBenchmarkResult,
)


# =============================================================================
# Helpers
# =============================================================================


def _result(**overrides):
    """Construct a FramingBenchmarkResult with sensible defaults."""
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
# Validation — taint_score
# =============================================================================


class TestTaintScoreValidation:
    def test_rejects_negative_taint(self):
        with pytest.raises(ValueError, match="taint_score"):
            _result(taint_score=-0.01)

    def test_rejects_taint_above_one(self):
        with pytest.raises(ValueError, match="taint_score"):
            _result(taint_score=1.01)

    def test_accepts_taint_zero(self):
        r = _result(taint_score=0.0)
        assert r.taint_score == 0.0

    def test_accepts_taint_one(self):
        r = _result(taint_score=1.0)
        assert r.taint_score == 1.0

    def test_accepts_mid_range_taint(self):
        r = _result(taint_score=0.5)
        assert r.taint_score == 0.5


# =============================================================================
# Validation — elapsed_ms
# =============================================================================


class TestElapsedMsValidation:
    def test_rejects_negative_ms(self):
        with pytest.raises(ValueError, match="elapsed_ms"):
            _result(elapsed_ms=-1)

    def test_accepts_zero_ms(self):
        r = _result(elapsed_ms=0)
        assert r.elapsed_ms == 0

    def test_accepts_large_ms(self):
        r = _result(elapsed_ms=3_600_000)
        assert r.elapsed_ms == 3_600_000


# =============================================================================
# Validation — category
# =============================================================================


class TestCategoryValidation:
    def test_accepts_direct(self):
        assert _result(category="direct").category == "direct"

    def test_accepts_framing(self):
        assert _result(category="framing").category == "framing"

    def test_accepts_propagation(self):
        assert _result(category="propagation").category == "propagation"

    def test_rejects_uppercase(self):
        with pytest.raises(ValueError, match="category"):
            _result(category="DIRECT")

    def test_rejects_unknown_label(self):
        with pytest.raises(ValueError, match="category"):
            _result(category="unknown")

    def test_valid_categories_constant_is_exhaustive(self):
        assert VALID_CATEGORIES == frozenset({"direct", "framing", "propagation"})


# =============================================================================
# Validation — confidence_trajectory
# =============================================================================


class TestConfidenceTrajectoryValidation:
    def test_accepts_empty_tuple(self):
        r = _result(confidence_trajectory=())
        assert r.confidence_trajectory == ()

    def test_accepts_longer_tuple(self):
        r = _result(confidence_trajectory=(0.1, 0.2, 0.3, 0.4))
        assert len(r.confidence_trajectory) == 4

    def test_rejects_list(self):
        with pytest.raises(TypeError, match="confidence_trajectory"):
            _result(confidence_trajectory=[0.1, 0.2])

    def test_rejects_generator(self):
        with pytest.raises(TypeError, match="confidence_trajectory"):
            _result(confidence_trajectory=(x for x in (0.1, 0.2)))


# =============================================================================
# Frozen enforcement
# =============================================================================


class TestFrozenEnforcement:
    def test_cannot_mutate_scenario_id(self):
        r = _result()
        with pytest.raises(FrozenInstanceError):
            r.scenario_id = "INJ-999"  # type: ignore[misc]

    def test_cannot_mutate_taint_score(self):
        r = _result()
        with pytest.raises(FrozenInstanceError):
            r.taint_score = 0.0  # type: ignore[misc]

    def test_cannot_mutate_pipeline_error(self):
        r = _result()
        with pytest.raises(FrozenInstanceError):
            r.pipeline_error = "oops"  # type: ignore[misc]

    def test_instances_are_hashable(self):
        r1 = _result()
        r2 = _result()
        # Frozen dataclasses are hashable if all fields are hashable.
        assert hash(r1) == hash(r2)


# =============================================================================
# Optional field handling
# =============================================================================


class TestOptionalFields:
    def test_framing_strategy_can_be_none(self):
        r = _result(framing_strategy=None)
        assert r.framing_strategy is None

    def test_framing_strategy_populated(self):
        r = _result(framing_strategy="narrative_dilution")
        assert r.framing_strategy == "narrative_dilution"

    def test_pipeline_error_can_be_none(self):
        r = _result(pipeline_error=None)
        assert r.pipeline_error is None

    def test_pipeline_error_populated(self):
        r = _result(
            pipeline_error="CycleError: ANTITHESIS phase failed",
            actual_verdict="",
        )
        assert "CycleError" in r.pipeline_error


# =============================================================================
# Serialization round-trip
# =============================================================================


class TestSerialization:
    def test_to_dict_contains_all_fields(self):
        r = _result()
        d = r.to_dict()
        assert set(d.keys()) == {
            "scenario_id",
            "category",
            "framing_strategy",
            "expected_verdict",
            "actual_verdict",
            "firewall_detected",
            "taint_score",
            "confidence_trajectory",
            "pipeline_error",
            "elapsed_ms",
        }

    def test_to_dict_converts_trajectory_to_list(self):
        r = _result(confidence_trajectory=(0.5, 0.6))
        d = r.to_dict()
        assert d["confidence_trajectory"] == [0.5, 0.6]

    def test_dict_roundtrip_preserves_fields(self):
        r = _result()
        r2 = FramingBenchmarkResult.from_dict(r.to_dict())
        assert r == r2

    def test_dict_roundtrip_preserves_none_fields(self):
        r = _result(
            framing_strategy=None,
            pipeline_error=None,
            confidence_trajectory=(),
        )
        r2 = FramingBenchmarkResult.from_dict(r.to_dict())
        assert r2.framing_strategy is None
        assert r2.pipeline_error is None
        assert r2.confidence_trajectory == ()

    def test_json_roundtrip_via_to_json(self):
        r = _result()
        payload = r.to_json()
        data = json.loads(payload)
        r2 = FramingBenchmarkResult.from_dict(data)
        assert r == r2

    def test_to_json_is_stringified(self):
        r = _result()
        assert isinstance(r.to_json(), str)

    def test_from_dict_casts_numeric_strings(self):
        d = {
            "scenario_id": "INJ-001",
            "category": "direct",
            "framing_strategy": None,
            "expected_verdict": "THREAT_CONFIRMED",
            "actual_verdict": "THREAT_CONFIRMED",
            "firewall_detected": True,
            "taint_score": "0.9",
            "confidence_trajectory": ["0.8", "0.2"],
            "pipeline_error": None,
            "elapsed_ms": "1200",
        }
        r = FramingBenchmarkResult.from_dict(d)
        assert r.taint_score == pytest.approx(0.9)
        assert r.confidence_trajectory == (0.8, 0.2)
        assert r.elapsed_ms == 1200


# =============================================================================
# Semantic smoke tests
# =============================================================================


class TestSemanticSmoke:
    def test_typical_seed_direct_result_shape(self):
        r = _result(
            scenario_id="INJ-001",
            category="direct",
            framing_strategy=None,
            taint_score=0.85,
            firewall_detected=True,
        )
        assert r.framing_strategy is None
        assert r.category == "direct"

    def test_typical_framing_expansion_result_shape(self):
        r = _result(
            scenario_id="INJ-019",
            category="framing",
            framing_strategy="temporal_patched_since",
            taint_score=0.1,
            firewall_detected=False,
        )
        assert r.framing_strategy == "temporal_patched_since"
        assert r.firewall_detected is False

    def test_error_result_has_empty_trajectory(self):
        r = _result(
            pipeline_error="RuntimeError: simulated",
            actual_verdict="",
            confidence_trajectory=(),
            taint_score=0.0,
            firewall_detected=False,
        )
        assert r.pipeline_error.startswith("RuntimeError")
        assert r.confidence_trajectory == ()
