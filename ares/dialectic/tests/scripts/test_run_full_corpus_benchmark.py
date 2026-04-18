"""Tests for run_full_corpus_benchmark — Session 048 runner.

Covers:
    1. Dry-run enumerates all 27 scenarios without running the pipeline.
    2. --limit caps the scenarios executed and honours 0 / >count edge cases.
    3. Per-scenario exceptions are captured into ``pipeline_error``.
    4. Category + framing_strategy assignment matches the registry.
    5. raw_results.json is written with the expected schema shape.
    6. Other scenarios continue to execute when one raises.

Every test uses an injected fake runner — no real guarded cycle is
invoked and no API keys are required.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from pathlib import Path

import pytest

from ares.dialectic.schemas.framing_benchmark_result import (
    FramingBenchmarkResult,
)
from ares.dialectic.scripts.injection_registry import build_registry
from ares.dialectic.scripts.run_full_corpus_benchmark import (
    DEFAULT_OUTPUT_DIR,
    LIVE_MODEL_ID,
    FullCorpusBenchmarkRun,
    _scenario_category,
    _scenario_framing_strategy,
    build_arg_parser,
    execute_benchmark,
    list_scenarios,
    main,
    serialize_run,
    write_raw_results,
)


# =============================================================================
# Helpers
# =============================================================================


def _fake_verdict(outcome="threat_confirmed", a=0.8, s=0.3, c=0.75):
    """Build a minimal Verdict-like stub exposing the fields the runner reads."""
    return SimpleNamespace(
        outcome=SimpleNamespace(value=outcome),
        architect_confidence=a,
        skeptic_confidence=s,
        confidence=c,
    )


def _fake_firewall(passed=True, taint=0.0):
    """Build a minimal FirewallVerdict-like stub."""
    return SimpleNamespace(passed=passed, taint_score=taint)


def _fake_cycle_result(verdict):
    return SimpleNamespace(verdict=verdict)


def _fake_guarded(
    *,
    outcome="threat_confirmed",
    arch_conf=0.8,
    skep_conf=0.3,
    final_conf=0.75,
    firewall_passed=True,
    taint=0.0,
):
    """Build a GuardedCycleResult-like stub matching runner expectations."""
    return SimpleNamespace(
        cycle_result=_fake_cycle_result(
            _fake_verdict(outcome, arch_conf, skep_conf, final_conf),
        ),
        firewall_verdict=_fake_firewall(firewall_passed, taint),
    )


def _ok_runner(scenario):
    """A runner that pretends every scenario passed cleanly."""
    return _fake_guarded(
        outcome="threat_confirmed",
        firewall_passed=True,
        taint=0.1,
    )


def _always_detect_runner(scenario):
    """A runner that always fails the firewall."""
    return _fake_guarded(
        outcome="threat_dismissed",
        firewall_passed=False,
        taint=0.85,
    )


def _failing_runner(scenario):
    """A runner that always raises."""
    raise RuntimeError(f"synthetic failure for {scenario.metadata.scenario_id}")


def _selective_failing_runner(fail_ids):
    """Return a runner that raises only on specific scenario IDs."""
    def _inner(scenario):
        sid = scenario.metadata.scenario_id
        if sid in fail_ids:
            raise RuntimeError(f"planned failure on {sid}")
        return _fake_guarded(taint=0.2)
    return _inner


REGISTRY = build_registry()


# =============================================================================
# Dry-run and scenario enumeration
# =============================================================================


class TestDryRun:
    def test_list_scenarios_returns_all_27_ids(self):
        ids = list_scenarios(REGISTRY)
        assert len(ids) == 27

    def test_list_scenarios_covers_seed_corpus(self):
        ids = set(list_scenarios(REGISTRY))
        assert {f"INJ-{i:03d}" for i in range(1, 13)} <= ids

    def test_list_scenarios_covers_expansion_corpus(self):
        ids = set(list_scenarios(REGISTRY))
        assert {f"INJ-{i:03d}" for i in range(13, 28)} <= ids

    def test_cli_dry_run_prints_every_id(self, capsys):
        exit_code = main(["--dry-run"])
        assert exit_code == 0
        captured = capsys.readouterr()
        for i in range(1, 28):
            assert f"INJ-{i:03d}" in captured.out

    def test_cli_dry_run_announces_count(self, capsys):
        main(["--dry-run"])
        captured = capsys.readouterr()
        assert "27 scenarios registered" in captured.out


# =============================================================================
# --limit handling
# =============================================================================


class TestLimitHandling:
    def test_limit_caps_execution(self):
        run = execute_benchmark(
            REGISTRY, _ok_runner, model_label="test", limit=3,
        )
        assert run.total_scenarios == 3
        assert len(run.results) == 3

    def test_limit_zero_runs_nothing(self):
        run = execute_benchmark(
            REGISTRY, _ok_runner, model_label="test", limit=0,
        )
        assert run.total_scenarios == 0
        assert run.results == ()

    def test_limit_larger_than_corpus_runs_all(self):
        run = execute_benchmark(
            REGISTRY, _ok_runner, model_label="test", limit=9999,
        )
        assert run.total_scenarios == 27

    def test_limit_none_runs_all(self):
        run = execute_benchmark(
            REGISTRY, _ok_runner, model_label="test", limit=None,
        )
        assert run.total_scenarios == 27

    def test_negative_limit_raises(self):
        with pytest.raises(ValueError, match="non-negative"):
            execute_benchmark(
                REGISTRY, _ok_runner, model_label="test", limit=-1,
            )

    def test_limit_preserves_registry_order(self):
        run = execute_benchmark(
            REGISTRY, _ok_runner, model_label="test", limit=5,
        )
        ids = [r.scenario_id for r in run.results]
        expected = [s.metadata.scenario_id for s in REGISTRY.all_scenarios()[:5]]
        assert ids == expected


# =============================================================================
# Result shape and metadata
# =============================================================================


class TestResultShape:
    def test_every_result_is_frozen_schema(self):
        run = execute_benchmark(REGISTRY, _ok_runner, model_label="test")
        for r in run.results:
            assert isinstance(r, FramingBenchmarkResult)

    def test_run_record_is_frozen(self):
        run = execute_benchmark(REGISTRY, _ok_runner, model_label="test")
        with pytest.raises(Exception):
            run.model = "new"  # type: ignore[misc]

    def test_result_ids_match_registry(self):
        run = execute_benchmark(REGISTRY, _ok_runner, model_label="test")
        result_ids = [r.scenario_id for r in run.results]
        registry_ids = [s.metadata.scenario_id for s in REGISTRY.all_scenarios()]
        assert result_ids == registry_ids

    def test_run_timestamp_is_utc(self):
        run = execute_benchmark(REGISTRY, _ok_runner, model_label="test")
        assert run.timestamp.tzinfo is not None

    def test_run_id_is_short_hex(self):
        run = execute_benchmark(REGISTRY, _ok_runner, model_label="test")
        assert len(run.run_id) == 12
        int(run.run_id, 16)  # must be valid hex

    def test_total_elapsed_ms_non_negative(self):
        run = execute_benchmark(REGISTRY, _ok_runner, model_label="test")
        assert run.total_elapsed_ms >= 0


# =============================================================================
# Category and framing strategy assignment
# =============================================================================


class TestCategoryAssignment:
    def test_all_results_have_valid_category(self):
        run = execute_benchmark(REGISTRY, _ok_runner, model_label="test")
        for r in run.results:
            assert r.category in {"direct", "framing", "propagation"}

    def test_seed_direct_ids_have_direct_category(self):
        run = execute_benchmark(REGISTRY, _ok_runner, model_label="test")
        by_id = {r.scenario_id: r for r in run.results}
        for sid in ("INJ-001", "INJ-002", "INJ-003", "INJ-004"):
            assert by_id[sid].category == "direct"

    def test_seed_framing_ids_have_framing_category(self):
        run = execute_benchmark(REGISTRY, _ok_runner, model_label="test")
        by_id = {r.scenario_id: r for r in run.results}
        for sid in ("INJ-005", "INJ-006", "INJ-007", "INJ-008"):
            assert by_id[sid].category == "framing"

    def test_propagation_ids_have_propagation_category(self):
        run = execute_benchmark(REGISTRY, _ok_runner, model_label="test")
        by_id = {r.scenario_id: r for r in run.results}
        for sid in ("INJ-009", "INJ-010", "INJ-011", "INJ-012"):
            assert by_id[sid].category == "propagation"

    def test_expansion_ids_have_framing_category(self):
        run = execute_benchmark(REGISTRY, _ok_runner, model_label="test")
        by_id = {r.scenario_id: r for r in run.results}
        for i in range(13, 28):
            sid = f"INJ-{i:03d}"
            assert by_id[sid].category == "framing"

    def test_scenario_category_helper_raises_on_unknown(self):
        with pytest.raises(KeyError):
            _scenario_category(REGISTRY, "INJ-999")


class TestFramingStrategyAssignment:
    def test_seed_direct_have_no_framing_strategy(self):
        run = execute_benchmark(REGISTRY, _ok_runner, model_label="test")
        by_id = {r.scenario_id: r for r in run.results}
        for sid in ("INJ-001", "INJ-002", "INJ-003", "INJ-004"):
            assert by_id[sid].framing_strategy is None

    def test_seed_framing_have_no_framing_strategy(self):
        run = execute_benchmark(REGISTRY, _ok_runner, model_label="test")
        by_id = {r.scenario_id: r for r in run.results}
        for sid in ("INJ-005", "INJ-006", "INJ-007", "INJ-008"):
            assert by_id[sid].framing_strategy is None

    def test_propagation_have_no_framing_strategy(self):
        run = execute_benchmark(REGISTRY, _ok_runner, model_label="test")
        by_id = {r.scenario_id: r for r in run.results}
        for sid in ("INJ-009", "INJ-010", "INJ-011", "INJ-012"):
            assert by_id[sid].framing_strategy is None

    def test_expansion_all_have_framing_strategy(self):
        run = execute_benchmark(REGISTRY, _ok_runner, model_label="test")
        by_id = {r.scenario_id: r for r in run.results}
        for i in range(13, 28):
            sid = f"INJ-{i:03d}"
            assert by_id[sid].framing_strategy is not None

    def test_expansion_strategies_are_unique(self):
        run = execute_benchmark(REGISTRY, _ok_runner, model_label="test")
        strategies = [
            r.framing_strategy
            for r in run.results
            if r.framing_strategy is not None
        ]
        assert len(strategies) == len(set(strategies))

    def test_framing_strategy_helper_returns_none_for_seed(self):
        assert _scenario_framing_strategy(REGISTRY, "INJ-001") is None

    def test_framing_strategy_helper_returns_strategy_for_expansion(self):
        assert (
            _scenario_framing_strategy(REGISTRY, "INJ-013")
            == "severity_downgrade_routine"
        )


# =============================================================================
# Pipeline error handling
# =============================================================================


class TestPipelineErrorCapture:
    def test_all_scenarios_capture_error_when_runner_always_raises(self):
        run = execute_benchmark(
            REGISTRY, _failing_runner, model_label="test",
        )
        assert all(r.pipeline_error is not None for r in run.results)

    def test_pipeline_error_includes_exception_message(self):
        run = execute_benchmark(
            REGISTRY, _failing_runner, model_label="test", limit=1,
        )
        assert run.results[0].pipeline_error is not None
        assert "synthetic failure" in run.results[0].pipeline_error

    def test_pipeline_error_includes_exception_type(self):
        run = execute_benchmark(
            REGISTRY, _failing_runner, model_label="test", limit=1,
        )
        assert run.results[0].pipeline_error.startswith("RuntimeError")

    def test_other_scenarios_continue_after_one_fails(self):
        runner = _selective_failing_runner({"INJ-005"})
        run = execute_benchmark(REGISTRY, runner, model_label="test")
        by_id = {r.scenario_id: r for r in run.results}
        assert by_id["INJ-005"].pipeline_error is not None
        for sid, r in by_id.items():
            if sid == "INJ-005":
                continue
            assert r.pipeline_error is None

    def test_failed_result_has_empty_verdict_and_trajectory(self):
        run = execute_benchmark(
            REGISTRY, _failing_runner, model_label="test", limit=1,
        )
        r = run.results[0]
        assert r.actual_verdict == ""
        assert r.confidence_trajectory == ()

    def test_failed_result_has_zero_taint_and_no_detection(self):
        run = execute_benchmark(
            REGISTRY, _failing_runner, model_label="test", limit=1,
        )
        r = run.results[0]
        assert r.firewall_detected is False
        assert r.taint_score == 0.0

    def test_failed_result_elapsed_still_non_negative(self):
        run = execute_benchmark(
            REGISTRY, _failing_runner, model_label="test", limit=1,
        )
        assert run.results[0].elapsed_ms >= 0


# =============================================================================
# Runner success path
# =============================================================================


class TestRunnerSuccess:
    def test_successful_runner_produces_no_pipeline_errors(self):
        run = execute_benchmark(REGISTRY, _ok_runner, model_label="test")
        assert all(r.pipeline_error is None for r in run.results)

    def test_successful_runner_verdict_is_uppercase(self):
        run = execute_benchmark(REGISTRY, _ok_runner, model_label="test")
        assert run.results[0].actual_verdict == "THREAT_CONFIRMED"

    def test_successful_runner_records_trajectory(self):
        run = execute_benchmark(REGISTRY, _ok_runner, model_label="test")
        assert run.results[0].confidence_trajectory == (0.8, 0.3, 0.75)

    def test_firewall_detection_tracked_when_blocked(self):
        run = execute_benchmark(
            REGISTRY, _always_detect_runner, model_label="test",
        )
        assert all(r.firewall_detected for r in run.results)
        assert all(r.taint_score == pytest.approx(0.85) for r in run.results)

    def test_firewall_clean_when_passed(self):
        run = execute_benchmark(REGISTRY, _ok_runner, model_label="test")
        assert all(not r.firewall_detected for r in run.results)


# =============================================================================
# Serialization and file output
# =============================================================================


class TestSerialization:
    def test_serialize_run_shape(self):
        run = execute_benchmark(REGISTRY, _ok_runner, model_label="test")
        payload = serialize_run(run)
        assert payload["run_id"] == run.run_id
        assert payload["model"] == "test"
        assert payload["total_scenarios"] == 27
        assert len(payload["results"]) == 27

    def test_write_raw_results_creates_file(self, tmp_path):
        run = execute_benchmark(REGISTRY, _ok_runner, model_label="test")
        out_path = write_raw_results(run, tmp_path)
        assert out_path.exists()
        assert out_path.name == "raw_results.json"

    def test_write_raw_results_produces_valid_json(self, tmp_path):
        run = execute_benchmark(REGISTRY, _ok_runner, model_label="test")
        out_path = write_raw_results(run, tmp_path)
        data = json.loads(out_path.read_text(encoding="utf-8"))
        assert len(data["results"]) == 27
        assert data["results"][0]["scenario_id"] == "INJ-001"

    def test_write_raw_results_creates_output_dir(self, tmp_path):
        run = execute_benchmark(REGISTRY, _ok_runner, model_label="test")
        nested = tmp_path / "a" / "b" / "c"
        out_path = write_raw_results(run, nested)
        assert out_path.exists()

    def test_results_roundtrip_through_schema(self, tmp_path):
        run = execute_benchmark(REGISTRY, _ok_runner, model_label="test")
        out_path = write_raw_results(run, tmp_path)
        data = json.loads(out_path.read_text(encoding="utf-8"))
        for raw in data["results"]:
            rebuilt = FramingBenchmarkResult.from_dict(raw)
            assert rebuilt.scenario_id == raw["scenario_id"]


# =============================================================================
# CLI surface
# =============================================================================


class TestCLIContract:
    def test_parser_defines_dry_run_flag(self):
        parser = build_arg_parser()
        args = parser.parse_args(["--dry-run"])
        assert args.dry_run is True

    def test_parser_defines_limit_flag(self):
        parser = build_arg_parser()
        args = parser.parse_args(["--limit", "5"])
        assert args.limit == 5

    def test_parser_defines_output_dir_flag(self):
        parser = build_arg_parser()
        args = parser.parse_args(["--output-dir", "out/x"])
        assert args.output_dir == Path("out/x")

    def test_parser_default_output_dir_is_session_048(self):
        parser = build_arg_parser()
        args = parser.parse_args([])
        assert args.output_dir == DEFAULT_OUTPUT_DIR

    def test_live_model_id_constant_matches_session_target(self):
        assert LIVE_MODEL_ID == "claude-sonnet-4-6"


# =============================================================================
# Run record plumbing
# =============================================================================


class TestRunRecord:
    def test_run_record_exposes_all_results(self):
        run = execute_benchmark(
            REGISTRY, _ok_runner, model_label="test", limit=4,
        )
        assert isinstance(run, FullCorpusBenchmarkRun)
        assert len(run.results) == 4

    def test_run_record_stores_model_label(self):
        run = execute_benchmark(
            REGISTRY, _ok_runner, model_label="rule_based", limit=1,
        )
        assert run.model == "rule_based"
