"""Tests for run_three_way_benchmark — Session 050 runner.

Covers:
    * --dry-run prints scenario routing with reuse-vs-live tags.
    * Reuse selection honours Session 048/049 presence.
    * --no-reuse forces fresh runs.
    * --limit caps framing scenarios.
    * Pipeline errors captured into pipeline_error, never raise.
    * Light results always populated; full/ablated populated only for
      scenarios without a reusable result.
    * Results serialise to the V2 schema shape.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from ares.dialectic.schemas.framing_benchmark_result_v3 import (
    FramingBenchmarkResultV3,
)
from ares.dialectic.scripts.injection_registry_v3 import build_registry_v3
from ares.dialectic.scripts.run_three_way_benchmark import (
    DEFAULT_OUTPUT_DIR,
    LIVE_MODEL_ID,
    SESSION_048_INPUT,
    SESSION_049_INPUT,
    ThreeWayBenchmarkRun,
    _scenario_category,
    _scenario_framing_strategy,
    build_arg_parser,
    execute_three_way_benchmark,
    list_framing_scenarios,
    main,
    serialize_run,
    write_raw_results,
)


REGISTRY = build_registry_v3()


def _fake_verdict(outcome="threat_confirmed", a=0.8, s=0.5, c=0.7):
    return SimpleNamespace(
        outcome=SimpleNamespace(value=outcome),
        architect_confidence=a,
        skeptic_confidence=s,
        confidence=c,
    )


def _fake_firewall(passed=True, taint=0.0):
    return SimpleNamespace(passed=passed, taint_score=taint)


def _fake_cycle(verdict):
    return SimpleNamespace(verdict=verdict)


def _fake_light(_s):
    return SimpleNamespace(
        cycle_result=_fake_cycle(_fake_verdict(s=0.8)),
        firewall_verdict=_fake_firewall(),
    )


def _fake_full(_s):
    return SimpleNamespace(
        cycle_result=_fake_cycle(_fake_verdict(a=0.9, s=0.3, c=0.9)),
        firewall_verdict=_fake_firewall(),
    )


def _fake_ablated(_s):
    return SimpleNamespace(
        cycle_result=_fake_cycle(_fake_verdict(a=0.7, s=0.0, c=0.7)),
        firewall_verdict=_fake_firewall(),
    )


def _raising(kind):
    def _inner(scenario):
        raise RuntimeError(f"{kind} blew up on {scenario.metadata.scenario_id}")
    return _inner


class TestDryRun:
    def test_list_framing_returns_25(self):
        rows = list_framing_scenarios(REGISTRY)
        assert len(rows) == 25

    def test_list_covers_new_temporal_ids(self):
        ids = {sid for sid, _ in list_framing_scenarios(REGISTRY)}
        assert {"INJ-031", "INJ-032", "INJ-033"} <= ids

    def test_cli_dry_run_exits_zero(self, capsys):
        code = main(["--dry-run"])
        assert code == 0

    def test_cli_dry_run_shows_all_framing_ids(self, capsys):
        main(["--dry-run"])
        out = capsys.readouterr().out
        for sid in ("INJ-005", "INJ-014", "INJ-020", "INJ-031"):
            assert sid in out

    def test_cli_dry_run_marks_new_scenarios_live(self, capsys):
        main(["--dry-run"])
        out = capsys.readouterr().out
        # INJ-031..033 don't exist in Session 048/049, so they should be
        # labelled live-full / live-ablated.
        for sid in ("INJ-031", "INJ-032", "INJ-033"):
            # Find the line for this scenario and verify live markers.
            lines = [ln for ln in out.splitlines() if sid in ln]
            assert lines
            assert "live-full" in lines[0]
            assert "live-ablated" in lines[0]


class TestReuseSelection:
    def _tmp_prev(self, tmp_path):
        s48 = {"results": [{
            "scenario_id": "INJ-005", "category": "framing",
            "framing_strategy": None, "expected_verdict": "THREAT_CONFIRMED",
            "actual_verdict": "THREAT_CONFIRMED", "firewall_detected": False,
            "taint_score": 0.0, "confidence_trajectory": [0.9, 0.2, 0.85],
            "pipeline_error": None, "elapsed_ms": 100,
        }]}
        s49 = {
            "ablated_results": [{
                "scenario_id": "INJ-005", "category": "framing",
                "framing_strategy": None, "expected_verdict": "THREAT_CONFIRMED",
                "actual_verdict": "THREAT_CONFIRMED", "firewall_detected": False,
                "taint_score": 0.0, "confidence_trajectory": [0.9, 0.0, 0.9],
                "pipeline_error": None, "elapsed_ms": 50,
                "pipeline_variant": "ablated",
            }],
            "full_results": [],
        }
        s48_path = tmp_path / "s48.json"
        s48_path.write_text(json.dumps(s48), encoding="utf-8")
        s49_path = tmp_path / "s49.json"
        s49_path.write_text(json.dumps(s49), encoding="utf-8")
        return s48_path, s49_path

    def test_reuses_inj_005_when_present(self, tmp_path):
        s48, s49 = self._tmp_prev(tmp_path)
        run = execute_three_way_benchmark(
            REGISTRY, _fake_light, _fake_full, _fake_ablated,
            model_label="t",
            session_048_path=s48, session_049_path=s49,
        )
        assert "INJ-005" in run.full_reused_ids
        assert "INJ-005" in run.ablated_reused_ids

    def test_runs_live_when_no_prev_entry(self, tmp_path):
        s48, s49 = self._tmp_prev(tmp_path)
        run = execute_three_way_benchmark(
            REGISTRY, _fake_light, _fake_full, _fake_ablated,
            model_label="t",
            session_048_path=s48, session_049_path=s49,
        )
        # INJ-031..033 have no prior entries → live runs.
        live_full_ids = {r.scenario_id for r in run.full_live_results}
        live_ablated_ids = {r.scenario_id for r in run.ablated_live_results}
        assert {"INJ-031", "INJ-032", "INJ-033"} <= live_full_ids
        assert {"INJ-031", "INJ-032", "INJ-033"} <= live_ablated_ids

    def test_no_reuse_makes_everything_live(self, tmp_path):
        s48, s49 = self._tmp_prev(tmp_path)
        run = execute_three_way_benchmark(
            REGISTRY, _fake_light, _fake_full, _fake_ablated,
            model_label="t", reuse_full=False, reuse_ablated=False,
            session_048_path=s48, session_049_path=s49,
        )
        assert run.full_reused_ids == ()
        assert run.ablated_reused_ids == ()
        assert len(run.full_live_results) == 25
        assert len(run.ablated_live_results) == 25

    def test_missing_previous_files_ok(self, tmp_path):
        run = execute_three_way_benchmark(
            REGISTRY, _fake_light, _fake_full, _fake_ablated,
            model_label="t",
            session_048_path=tmp_path / "missing.json",
            session_049_path=tmp_path / "missing.json",
        )
        # Everything goes live.
        assert len(run.full_live_results) == 25


class TestLimit:
    def test_limit_caps_framing(self):
        run = execute_three_way_benchmark(
            REGISTRY, _fake_light, _fake_full, _fake_ablated,
            model_label="t", limit=3, reuse_full=False, reuse_ablated=False,
        )
        assert len(run.light_results) == 3
        assert len(run.full_live_results) == 3
        assert len(run.ablated_live_results) == 3

    def test_limit_zero_runs_nothing(self):
        run = execute_three_way_benchmark(
            REGISTRY, _fake_light, _fake_full, _fake_ablated,
            model_label="t", limit=0,
        )
        assert run.light_results == ()

    def test_negative_limit_raises(self):
        with pytest.raises(ValueError, match="non-negative"):
            execute_three_way_benchmark(
                REGISTRY, _fake_light, _fake_full, _fake_ablated,
                model_label="t", limit=-1,
            )


class TestPipelineErrorCapture:
    def test_light_error_captured(self):
        run = execute_three_way_benchmark(
            REGISTRY, _raising("light"), _fake_full, _fake_ablated,
            model_label="t", reuse_full=False, reuse_ablated=False, limit=1,
        )
        assert run.light_results[0].pipeline_error is not None

    def test_full_error_captured(self):
        run = execute_three_way_benchmark(
            REGISTRY, _fake_light, _raising("full"), _fake_ablated,
            model_label="t", reuse_full=False, reuse_ablated=False, limit=1,
        )
        assert run.full_live_results[0].pipeline_error is not None

    def test_ablated_error_captured(self):
        run = execute_three_way_benchmark(
            REGISTRY, _fake_light, _fake_full, _raising("ablated"),
            model_label="t", reuse_full=False, reuse_ablated=False, limit=1,
        )
        assert run.ablated_live_results[0].pipeline_error is not None


class TestRoutingAndLabels:
    def test_light_variant_label(self):
        run = execute_three_way_benchmark(
            REGISTRY, _fake_light, _fake_full, _fake_ablated,
            model_label="t", reuse_full=False, reuse_ablated=False, limit=1,
        )
        assert run.light_results[0].pipeline_variant == "light"

    def test_full_variant_label(self):
        run = execute_three_way_benchmark(
            REGISTRY, _fake_light, _fake_full, _fake_ablated,
            model_label="t", reuse_full=False, reuse_ablated=False, limit=1,
        )
        assert run.full_live_results[0].pipeline_variant == "full"

    def test_ablated_variant_label(self):
        run = execute_three_way_benchmark(
            REGISTRY, _fake_light, _fake_full, _fake_ablated,
            model_label="t", reuse_full=False, reuse_ablated=False, limit=1,
        )
        assert run.ablated_live_results[0].pipeline_variant == "ablated"


class TestSerialization:
    def test_serialise_includes_counts(self):
        run = execute_three_way_benchmark(
            REGISTRY, _fake_light, _fake_full, _fake_ablated,
            model_label="t", reuse_full=False, reuse_ablated=False, limit=2,
        )
        payload = serialize_run(run)
        assert payload["light_count"] == 2
        assert payload["full_live_count"] == 2
        assert payload["ablated_live_count"] == 2

    def test_write_raw_creates_file(self, tmp_path):
        run = execute_three_way_benchmark(
            REGISTRY, _fake_light, _fake_full, _fake_ablated,
            model_label="t", reuse_full=False, reuse_ablated=False, limit=1,
        )
        out = write_raw_results(run, tmp_path)
        assert out.exists()
        assert out.name == "light_raw_results.json"

    def test_written_json_parses(self, tmp_path):
        run = execute_three_way_benchmark(
            REGISTRY, _fake_light, _fake_full, _fake_ablated,
            model_label="t", reuse_full=False, reuse_ablated=False, limit=1,
        )
        out = write_raw_results(run, tmp_path)
        data = json.loads(out.read_text(encoding="utf-8"))
        assert "light_results" in data
        assert "full_live_results" in data
        assert "ablated_live_results" in data


class TestCLI:
    def test_parser_flags(self):
        parser = build_arg_parser()
        args = parser.parse_args([
            "--dry-run", "--limit", "3",
            "--output-dir", "out/x",
            "--rule-based", "--no-reuse",
        ])
        assert args.dry_run
        assert args.limit == 3
        assert args.output_dir == Path("out/x")
        assert args.rule_based
        assert args.no_reuse

    def test_default_output_dir(self):
        parser = build_arg_parser()
        args = parser.parse_args([])
        assert args.output_dir == DEFAULT_OUTPUT_DIR

    def test_default_inputs(self):
        parser = build_arg_parser()
        args = parser.parse_args([])
        assert args.session_048 == SESSION_048_INPUT
        assert args.session_049 == SESSION_049_INPUT

    def test_live_model_id(self):
        assert LIVE_MODEL_ID == "claude-sonnet-4-6"


class TestRunRecord:
    def test_is_frozen(self):
        run = execute_three_way_benchmark(
            REGISTRY, _fake_light, _fake_full, _fake_ablated,
            model_label="t", limit=1, reuse_full=False, reuse_ablated=False,
        )
        assert isinstance(run, ThreeWayBenchmarkRun)
        with pytest.raises(Exception):
            run.model = "x"  # type: ignore[misc]

    def test_run_id_is_hex(self):
        run = execute_three_way_benchmark(
            REGISTRY, _fake_light, _fake_full, _fake_ablated,
            model_label="t", limit=1, reuse_full=False, reuse_ablated=False,
        )
        assert len(run.run_id) == 12
        int(run.run_id, 16)


class TestHelpers:
    def test_category_normalization(self):
        assert _scenario_category(REGISTRY, "INJ-001") == "direct"
        assert _scenario_category(REGISTRY, "INJ-031") == "framing"

    def test_framing_strategy_for_new_scenarios(self):
        assert (
            _scenario_framing_strategy(REGISTRY, "INJ-031")
            == "temporal_ongoing_investigation"
        )
        assert (
            _scenario_framing_strategy(REGISTRY, "INJ-033")
            == "temporal_compressed_timeline"
        )
