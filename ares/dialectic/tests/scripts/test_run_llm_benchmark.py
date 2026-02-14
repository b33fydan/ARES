"""Tests for run_llm_benchmark.py — serialization, deserialization, and script logic.

Tests cover the JSON round-trip for BenchmarkRun frozen dataclasses,
including frozenset handling and datetime conversion.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from ares.dialectic.scripts.benchmark_runner import BenchmarkRun, ScenarioResult, run_benchmark
from ares.dialectic.scripts.run_llm_benchmark import (
    deserialize_benchmark_run,
    serialize_benchmark_run,
)
from ares.dialectic.scripts.scenario_corpus import get_all_scenarios

ALL_SCENARIOS = get_all_scenarios()


def _make_rule_based_run() -> BenchmarkRun:
    """Helper: run the rule-based baseline for testing."""
    return run_benchmark(ALL_SCENARIOS, strategy_type="rule_based")


class TestSerializeBenchmarkRun:
    """Tests for serialize_benchmark_run()."""

    def test_serialize_benchmark_run_returns_dict(self) -> None:
        run = _make_rule_based_run()
        result = serialize_benchmark_run(run)
        assert isinstance(result, dict)
        assert "run_id" in result
        assert "results" in result
        assert len(result["results"]) == 12

    def test_serialize_preserves_scenario_ids(self) -> None:
        run = _make_rule_based_run()
        result = serialize_benchmark_run(run)
        ids = {r["scenario_id"] for r in result["results"]}
        expected_ids = {s.metadata.scenario_id for s in ALL_SCENARIOS}
        assert ids == expected_ids

    def test_serialize_frozenset_as_sorted_list(self) -> None:
        run = _make_rule_based_run()
        result = serialize_benchmark_run(run)
        for r in result["results"]:
            assert isinstance(r["architect_fact_ids_cited"], list)
            assert isinstance(r["skeptic_fact_ids_cited"], list)

    def test_serialize_is_json_compatible(self) -> None:
        run = _make_rule_based_run()
        result = serialize_benchmark_run(run)
        json_str = json.dumps(result, default=str)
        assert len(json_str) > 0

    def test_serialize_includes_strategy_type(self) -> None:
        run = _make_rule_based_run()
        result = serialize_benchmark_run(run)
        assert result["strategy_type"] == "rule_based"
        for r in result["results"]:
            assert r["strategy_type"] == "rule_based"

    def test_serialize_includes_cost_fields_none_for_rule_based(self) -> None:
        run = _make_rule_based_run()
        result = serialize_benchmark_run(run)
        for r in result["results"]:
            assert r["cost_usd"] is None
            assert r["token_usage"] is None


class TestDeserializeBenchmarkRun:
    """Tests for deserialize_benchmark_run()."""

    def test_round_trip_serialize_deserialize(self) -> None:
        run = _make_rule_based_run()
        serialized = serialize_benchmark_run(run)
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump(serialized, f, default=str)
            tmp_path = Path(f.name)
        try:
            restored = deserialize_benchmark_run(tmp_path)
            assert restored.run_id == run.run_id
            assert restored.scenario_count == run.scenario_count
            assert len(restored.results) == len(run.results)
            for orig, rest in zip(run.results, restored.results):
                assert orig.scenario_id == rest.scenario_id
                assert orig.verdict_outcome == rest.verdict_outcome
        finally:
            tmp_path.unlink()

    def test_deserialize_restores_frozensets(self) -> None:
        run = _make_rule_based_run()
        serialized = serialize_benchmark_run(run)
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump(serialized, f, default=str)
            tmp_path = Path(f.name)
        try:
            restored = deserialize_benchmark_run(tmp_path)
            for r in restored.results:
                assert isinstance(r.architect_fact_ids_cited, frozenset)
                assert isinstance(r.skeptic_fact_ids_cited, frozenset)
        finally:
            tmp_path.unlink()

    def test_deserialize_restores_frozen_dataclass(self) -> None:
        run = _make_rule_based_run()
        serialized = serialize_benchmark_run(run)
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump(serialized, f, default=str)
            tmp_path = Path(f.name)
        try:
            restored = deserialize_benchmark_run(tmp_path)
            assert isinstance(restored, BenchmarkRun)
            with pytest.raises(AttributeError):
                restored.run_id = "tampered"  # type: ignore[misc]
        finally:
            tmp_path.unlink()

    def test_deserialize_nonexistent_file_raises(self) -> None:
        with pytest.raises(FileNotFoundError):
            deserialize_benchmark_run(Path("/nonexistent/path.json"))


class TestRoundTripFidelity:
    """Tests verifying data fidelity across serialize/deserialize cycle."""

    def test_round_trip_preserves_fact_coverage(self) -> None:
        run = _make_rule_based_run()
        serialized = serialize_benchmark_run(run)
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump(serialized, f, default=str)
            tmp_path = Path(f.name)
        try:
            restored = deserialize_benchmark_run(tmp_path)
            for orig, rest in zip(run.results, restored.results):
                assert abs(orig.fact_coverage_ratio - rest.fact_coverage_ratio) < 1e-9
        finally:
            tmp_path.unlink()

    def test_round_trip_preserves_confidence_values(self) -> None:
        run = _make_rule_based_run()
        serialized = serialize_benchmark_run(run)
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump(serialized, f, default=str)
            tmp_path = Path(f.name)
        try:
            restored = deserialize_benchmark_run(tmp_path)
            for orig, rest in zip(run.results, restored.results):
                assert abs(orig.verdict_confidence - rest.verdict_confidence) < 1e-9
                assert abs(orig.architect_confidence - rest.architect_confidence) < 1e-9
                assert abs(orig.skeptic_confidence - rest.skeptic_confidence) < 1e-9
        finally:
            tmp_path.unlink()
