"""Tests for Session 049 run_ablation_benchmark.

Covers:
    1. --dry-run enumerates 22 framing + 3 authority-expansion scenarios
       without invoking any pipeline.
    2. Execution routes framing scenarios to ablated runner + authority
       scenarios to full runner (never swaps).
    3. --limit caps both sub-benchmarks independently.
    4. Per-scenario exceptions surface in pipeline_error and never raise.
    5. Results are all FramingBenchmarkResultV2 with the correct
       pipeline_variant label.
    6. raw_results.json shape includes ablated_results and full_results
       blocks.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from ares.dialectic.schemas.framing_benchmark_result_v2 import (
    FramingBenchmarkResultV2,
)
from ares.dialectic.scripts.injection_registry_v2 import build_registry_v2
from ares.dialectic.scripts.run_ablation_benchmark import (
    DEFAULT_OUTPUT_DIR,
    LIVE_MODEL_ID,
    AblationBenchmarkRun,
    _scenario_category,
    _scenario_framing_strategy,
    build_arg_parser,
    execute_ablation_benchmark,
    list_scenarios_for_dry_run,
    main,
    serialize_run,
    write_raw_results,
)


# =============================================================================
# Fakes
# =============================================================================


def _fake_verdict(outcome="threat_confirmed", a=0.8, s=0.0, c=0.8):
    return SimpleNamespace(
        outcome=SimpleNamespace(value=outcome),
        architect_confidence=a,
        skeptic_confidence=s,
        confidence=c,
    )


def _fake_firewall(passed=True, taint=0.0):
    return SimpleNamespace(passed=passed, taint_score=taint)


def _fake_cycle_result(verdict):
    return SimpleNamespace(verdict=verdict)


def _fake_ablated(
    outcome="threat_confirmed",
    arch=0.8,
    final=0.8,
    passed=True,
    taint=0.0,
):
    return SimpleNamespace(
        cycle_result=_fake_cycle_result(_fake_verdict(outcome, arch, 0.0, final)),
        firewall_verdict=_fake_firewall(passed, taint),
        pipeline_variant="ablated",
    )


def _fake_full(
    outcome="threat_confirmed",
    arch=0.9,
    skep=0.3,
    final=0.9,
    passed=True,
    taint=0.0,
):
    return SimpleNamespace(
        cycle_result=_fake_cycle_result(_fake_verdict(outcome, arch, skep, final)),
        firewall_verdict=_fake_firewall(passed, taint),
    )


def _ok_ablated_runner(_scenario):
    return _fake_ablated()


def _ok_full_runner(_scenario):
    return _fake_full()


def _raising_ablated_runner(scenario):
    raise RuntimeError(f"ablated blow-up on {scenario.metadata.scenario_id}")


def _raising_full_runner(scenario):
    raise RuntimeError(f"full blow-up on {scenario.metadata.scenario_id}")


REGISTRY = build_registry_v2()


# =============================================================================
# Dry-run + list_scenarios
# =============================================================================


class TestDryRun:
    def test_list_yields_22_framing_and_3_authority(self):
        framing, auth = list_scenarios_for_dry_run(REGISTRY)
        assert len(framing) == 22
        assert len(auth) == 3

    def test_framing_list_marks_variant_ablated(self):
        framing, _ = list_scenarios_for_dry_run(REGISTRY)
        for _sid, _strategy, variant in framing:
            assert variant == "ablated"

    def test_auth_list_marks_variant_full(self):
        _, auth = list_scenarios_for_dry_run(REGISTRY)
        for _sid, _strategy, variant in auth:
            assert variant == "full"

    def test_auth_list_covers_new_ids(self):
        _, auth = list_scenarios_for_dry_run(REGISTRY)
        ids = {sid for sid, _, _ in auth}
        assert ids == {"INJ-028", "INJ-029", "INJ-030"}

    def test_cli_dry_run_exit_zero(self, capsys):
        code = main(["--dry-run"])
        assert code == 0
        captured = capsys.readouterr()
        assert "22 framing" in captured.out
        assert "3 authority-expansion" in captured.out

    def test_cli_dry_run_prints_every_framing_id(self, capsys):
        main(["--dry-run"])
        captured = capsys.readouterr()
        for sid in ("INJ-005", "INJ-013", "INJ-027", "INJ-028", "INJ-030"):
            assert sid in captured.out


# =============================================================================
# Routing: 22 ablated + 3 full
# =============================================================================


class TestRouting:
    def test_ablated_count_is_22(self):
        run = execute_ablation_benchmark(
            REGISTRY, _ok_ablated_runner, _ok_full_runner, model_label="t",
        )
        assert len(run.ablated_results) == 22

    def test_full_count_is_3(self):
        run = execute_ablation_benchmark(
            REGISTRY, _ok_ablated_runner, _ok_full_runner, model_label="t",
        )
        assert len(run.full_results) == 3

    def test_total_scenarios_is_25(self):
        run = execute_ablation_benchmark(
            REGISTRY, _ok_ablated_runner, _ok_full_runner, model_label="t",
        )
        assert run.total_scenarios == 25

    def test_ablated_scenarios_cover_all_22_framing(self):
        run = execute_ablation_benchmark(
            REGISTRY, _ok_ablated_runner, _ok_full_runner, model_label="t",
        )
        result_ids = {r.scenario_id for r in run.ablated_results}
        expected = {f"INJ-{n:03d}" for n in (5, 6, 7, 8)}
        expected |= {f"INJ-{n:03d}" for n in range(13, 31)}
        assert result_ids == expected

    def test_full_scenarios_are_inj_028_029_030(self):
        run = execute_ablation_benchmark(
            REGISTRY, _ok_ablated_runner, _ok_full_runner, model_label="t",
        )
        ids = {r.scenario_id for r in run.full_results}
        assert ids == {"INJ-028", "INJ-029", "INJ-030"}

    def test_ablated_results_all_marked_ablated(self):
        run = execute_ablation_benchmark(
            REGISTRY, _ok_ablated_runner, _ok_full_runner, model_label="t",
        )
        assert all(r.pipeline_variant == "ablated" for r in run.ablated_results)

    def test_full_results_all_marked_full(self):
        run = execute_ablation_benchmark(
            REGISTRY, _ok_ablated_runner, _ok_full_runner, model_label="t",
        )
        assert all(r.pipeline_variant == "full" for r in run.full_results)


# =============================================================================
# --limit handling
# =============================================================================


class TestLimit:
    def test_limit_caps_each_sub_benchmark(self):
        run = execute_ablation_benchmark(
            REGISTRY, _ok_ablated_runner, _ok_full_runner,
            model_label="t", limit=2,
        )
        assert len(run.ablated_results) == 2
        assert len(run.full_results) == 2

    def test_limit_zero_skips_everything(self):
        run = execute_ablation_benchmark(
            REGISTRY, _ok_ablated_runner, _ok_full_runner,
            model_label="t", limit=0,
        )
        assert run.ablated_results == ()
        assert run.full_results == ()

    def test_limit_larger_than_corpus_runs_all(self):
        run = execute_ablation_benchmark(
            REGISTRY, _ok_ablated_runner, _ok_full_runner,
            model_label="t", limit=9999,
        )
        assert len(run.ablated_results) == 22
        assert len(run.full_results) == 3

    def test_negative_limit_raises(self):
        with pytest.raises(ValueError, match="non-negative"):
            execute_ablation_benchmark(
                REGISTRY, _ok_ablated_runner, _ok_full_runner,
                model_label="t", limit=-1,
            )


# =============================================================================
# Pipeline error capture
# =============================================================================


class TestPipelineErrorCapture:
    def test_ablated_errors_do_not_leak(self):
        run = execute_ablation_benchmark(
            REGISTRY, _raising_ablated_runner, _ok_full_runner,
            model_label="t",
        )
        assert all(
            r.pipeline_error is not None for r in run.ablated_results
        )

    def test_full_errors_do_not_leak(self):
        run = execute_ablation_benchmark(
            REGISTRY, _ok_ablated_runner, _raising_full_runner,
            model_label="t",
        )
        assert all(
            r.pipeline_error is not None for r in run.full_results
        )

    def test_error_message_includes_exception_type(self):
        run = execute_ablation_benchmark(
            REGISTRY, _raising_ablated_runner, _ok_full_runner,
            model_label="t", limit=1,
        )
        assert run.ablated_results[0].pipeline_error.startswith("RuntimeError")

    def test_other_ablated_scenarios_continue_after_one_fails(self):
        def selective(scenario):
            if scenario.metadata.scenario_id == "INJ-007":
                raise RuntimeError("target failure")
            return _fake_ablated()

        run = execute_ablation_benchmark(
            REGISTRY, selective, _ok_full_runner, model_label="t",
        )
        by_id = {r.scenario_id: r for r in run.ablated_results}
        assert by_id["INJ-007"].pipeline_error is not None
        for sid, r in by_id.items():
            if sid == "INJ-007":
                continue
            assert r.pipeline_error is None

    def test_failed_scenario_empty_trajectory_and_verdict(self):
        run = execute_ablation_benchmark(
            REGISTRY, _raising_ablated_runner, _ok_full_runner,
            model_label="t", limit=1,
        )
        r = run.ablated_results[0]
        assert r.actual_verdict == ""
        assert r.confidence_trajectory == ()


# =============================================================================
# Runner successes populate fields
# =============================================================================


class TestFieldPopulation:
    def test_verdict_label_is_uppercase(self):
        run = execute_ablation_benchmark(
            REGISTRY, _ok_ablated_runner, _ok_full_runner, model_label="t",
        )
        assert run.ablated_results[0].actual_verdict == "THREAT_CONFIRMED"
        assert run.full_results[0].actual_verdict == "THREAT_CONFIRMED"

    def test_firewall_fields_recorded(self):
        def detect_runner(_s):
            return _fake_ablated(passed=False, taint=0.85)
        run = execute_ablation_benchmark(
            REGISTRY, detect_runner, _ok_full_runner, model_label="t",
        )
        assert all(r.firewall_detected for r in run.ablated_results)
        assert all(
            r.taint_score == pytest.approx(0.85)
            for r in run.ablated_results
        )

    def test_trajectory_captured_from_verdict(self):
        def runner_with_trajectory(_s):
            return _fake_ablated(arch=0.77, final=0.77)
        run = execute_ablation_benchmark(
            REGISTRY, runner_with_trajectory, _ok_full_runner,
            model_label="t", limit=1,
        )
        r = run.ablated_results[0]
        assert r.confidence_trajectory == (0.77, 0.0, 0.77)

    def test_category_and_strategy_populated(self):
        run = execute_ablation_benchmark(
            REGISTRY, _ok_ablated_runner, _ok_full_runner, model_label="t",
        )
        by_id = {r.scenario_id: r for r in run.ablated_results}
        assert by_id["INJ-013"].framing_strategy == "severity_downgrade_routine"
        assert by_id["INJ-013"].category == "framing"
        assert by_id["INJ-028"].category == "framing"


# =============================================================================
# Serialization + output
# =============================================================================


class TestSerialization:
    def test_serialize_includes_both_blocks(self):
        run = execute_ablation_benchmark(
            REGISTRY, _ok_ablated_runner, _ok_full_runner, model_label="t",
        )
        payload = serialize_run(run)
        assert payload["ablated_count"] == 22
        assert payload["full_count"] == 3
        assert len(payload["ablated_results"]) == 22
        assert len(payload["full_results"]) == 3

    def test_write_raw_results_creates_file(self, tmp_path):
        run = execute_ablation_benchmark(
            REGISTRY, _ok_ablated_runner, _ok_full_runner, model_label="t",
        )
        out = write_raw_results(run, tmp_path)
        assert out.exists()
        assert out.name == "ablated_raw_results.json"

    def test_written_json_is_valid(self, tmp_path):
        run = execute_ablation_benchmark(
            REGISTRY, _ok_ablated_runner, _ok_full_runner, model_label="t",
        )
        out = write_raw_results(run, tmp_path)
        data = json.loads(out.read_text(encoding="utf-8"))
        assert data["total_scenarios"] == 25

    def test_each_serialized_result_has_pipeline_variant(self, tmp_path):
        run = execute_ablation_benchmark(
            REGISTRY, _ok_ablated_runner, _ok_full_runner, model_label="t",
        )
        out = write_raw_results(run, tmp_path)
        data = json.loads(out.read_text(encoding="utf-8"))
        for row in data["ablated_results"]:
            assert row["pipeline_variant"] == "ablated"
        for row in data["full_results"]:
            assert row["pipeline_variant"] == "full"

    def test_results_roundtrip_v2_schema(self, tmp_path):
        run = execute_ablation_benchmark(
            REGISTRY, _ok_ablated_runner, _ok_full_runner, model_label="t",
        )
        out = write_raw_results(run, tmp_path)
        data = json.loads(out.read_text(encoding="utf-8"))
        for row in data["ablated_results"]:
            rebuilt = FramingBenchmarkResultV2.from_dict(row)
            assert rebuilt.pipeline_variant == "ablated"


# =============================================================================
# CLI surface
# =============================================================================


class TestCLIContract:
    def test_default_output_dir(self):
        parser = build_arg_parser()
        args = parser.parse_args([])
        assert args.output_dir == DEFAULT_OUTPUT_DIR

    def test_limit_flag(self):
        parser = build_arg_parser()
        args = parser.parse_args(["--limit", "5"])
        assert args.limit == 5

    def test_rule_based_flag(self):
        parser = build_arg_parser()
        args = parser.parse_args(["--rule-based"])
        assert args.rule_based is True

    def test_live_model_id_constant(self):
        assert LIVE_MODEL_ID == "claude-sonnet-4-6"


# =============================================================================
# Run record frozen
# =============================================================================


class TestRunRecord:
    def test_run_is_frozen(self):
        run = execute_ablation_benchmark(
            REGISTRY, _ok_ablated_runner, _ok_full_runner, model_label="t",
        )
        assert isinstance(run, AblationBenchmarkRun)
        with pytest.raises(Exception):
            run.model = "new"  # type: ignore[misc]

    def test_run_id_is_hex(self):
        run = execute_ablation_benchmark(
            REGISTRY, _ok_ablated_runner, _ok_full_runner, model_label="t",
        )
        assert len(run.run_id) == 12
        int(run.run_id, 16)

    def test_timestamp_is_utc(self):
        run = execute_ablation_benchmark(
            REGISTRY, _ok_ablated_runner, _ok_full_runner, model_label="t",
        )
        assert run.timestamp.tzinfo is not None


# =============================================================================
# Helpers
# =============================================================================


class TestHelpers:
    def test_scenario_category_normalizes(self):
        assert _scenario_category(REGISTRY, "INJ-001") == "direct"
        assert _scenario_category(REGISTRY, "INJ-028") == "framing"

    def test_scenario_category_unknown_raises(self):
        with pytest.raises(KeyError):
            _scenario_category(REGISTRY, "INJ-XXX")

    def test_scenario_framing_strategy_for_new_scenarios(self):
        assert (
            _scenario_framing_strategy(REGISTRY, "INJ-028")
            == "authority_credentialed_source"
        )

    def test_scenario_framing_strategy_none_for_seed(self):
        assert _scenario_framing_strategy(REGISTRY, "INJ-001") is None
