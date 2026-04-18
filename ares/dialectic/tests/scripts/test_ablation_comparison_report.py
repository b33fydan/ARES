"""Tests for ablation_comparison_report — Session 049 analysis.

Covers:
    1. Scenario matching: pairs by scenario_id; skips unmatched entries.
    2. Per-family delta math (full_acc, ablated_acc, delta_pp).
    3. Finding-9 rubric threshold boundaries (<0.55, [0.55,0.70), >=0.70).
    4. Verdict-flip detection: flipped when full != ablated; not flipped
       when identical including case.
    5. CSV + markdown output shape.
    6. CLI glue (build_arg_parser, main) + input/output contracts.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from ares.dialectic.schemas.framing_benchmark_result import (
    FramingBenchmarkResult,
)
from ares.dialectic.schemas.framing_benchmark_result_v2 import (
    FramingBenchmarkResultV2,
)
from ares.dialectic.scripts.analysis.ablation_comparison_report import (
    FAMILY_CSV_HEADER,
    FINDING_9_AMBIGUOUS,
    FINDING_9_AMBIGUOUS_MAX_EXCLUSIVE,
    FINDING_9_NOT_SUPPORTED,
    FINDING_9_SUPPORTED,
    FINDING_9_SUPPORTED_MAX_EXCLUSIVE,
    SCENARIO_CSV_HEADER,
    FamilyDelta,
    FindingNineVerdict,
    ScenarioDelta,
    build_arg_parser,
    compute_family_deltas,
    compute_finding_9,
    load_session_048,
    load_session_049,
    main,
    match_scenarios,
    print_finding_line,
    render_summary_markdown,
    run_comparison,
    write_family_csv,
    write_scenario_csv,
    write_summary_markdown,
)


# =============================================================================
# Fixture builders
# =============================================================================


def _v1(**overrides) -> FramingBenchmarkResult:
    base = dict(
        scenario_id="INJ-013",
        category="framing",
        framing_strategy="severity_downgrade_routine",
        expected_verdict="THREAT_CONFIRMED",
        actual_verdict="THREAT_CONFIRMED",
        firewall_detected=False,
        taint_score=0.2,
        confidence_trajectory=(0.8, 0.3, 0.7),
        pipeline_error=None,
        elapsed_ms=100,
    )
    base.update(overrides)
    return FramingBenchmarkResult(**base)


def _v2(variant="ablated", **overrides) -> FramingBenchmarkResultV2:
    return FramingBenchmarkResultV2(
        inner=_v1(**overrides),
        pipeline_variant=variant,
    )


# =============================================================================
# match_scenarios
# =============================================================================


class TestMatchScenarios:
    def test_pairs_by_id(self):
        full = [_v1(scenario_id="INJ-013")]
        ablated = [_v2(scenario_id="INJ-013")]
        deltas = match_scenarios(full, ablated)
        assert len(deltas) == 1
        assert deltas[0].scenario_id == "INJ-013"

    def test_skips_unmatched_from_ablated(self):
        full = [_v1(scenario_id="INJ-013")]
        ablated = [_v2(scenario_id="INJ-999")]
        deltas = match_scenarios(full, ablated)
        assert deltas == ()

    def test_skips_unmatched_from_full(self):
        full = [
            _v1(scenario_id="INJ-013"),
            _v1(scenario_id="INJ-099"),
        ]
        ablated = [_v2(scenario_id="INJ-013")]
        deltas = match_scenarios(full, ablated)
        assert len(deltas) == 1
        assert deltas[0].scenario_id == "INJ-013"

    def test_full_correct_detected(self):
        full = [_v1(scenario_id="A", actual_verdict="THREAT_CONFIRMED",
                    expected_verdict="THREAT_CONFIRMED")]
        ablated = [_v2(scenario_id="A", actual_verdict="INCONCLUSIVE",
                       expected_verdict="THREAT_CONFIRMED")]
        d = match_scenarios(full, ablated)[0]
        assert d.full_correct is True
        assert d.ablated_correct is False

    def test_verdict_flipped_true(self):
        full = [_v1(scenario_id="A", actual_verdict="THREAT_CONFIRMED")]
        ablated = [_v2(scenario_id="A", actual_verdict="INCONCLUSIVE")]
        d = match_scenarios(full, ablated)[0]
        assert d.verdict_flipped is True

    def test_verdict_flipped_false_when_same(self):
        full = [_v1(scenario_id="A", actual_verdict="THREAT_CONFIRMED")]
        ablated = [_v2(scenario_id="A", actual_verdict="THREAT_CONFIRMED")]
        d = match_scenarios(full, ablated)[0]
        assert d.verdict_flipped is False

    def test_case_insensitive_correctness_check(self):
        full = [_v1(scenario_id="A", actual_verdict="threat_confirmed",
                    expected_verdict="THREAT_CONFIRMED")]
        ablated = [_v2(scenario_id="A", actual_verdict="threat_confirmed",
                       expected_verdict="THREAT_CONFIRMED")]
        d = match_scenarios(full, ablated)[0]
        assert d.full_correct is True
        assert d.ablated_correct is True

    def test_empty_actual_verdict_not_correct(self):
        full = [_v1(scenario_id="A", actual_verdict="",
                    pipeline_error="boom",
                    confidence_trajectory=())]
        ablated = [_v2(scenario_id="A", actual_verdict="",
                       pipeline_error="boom",
                       confidence_trajectory=())]
        d = match_scenarios(full, ablated)[0]
        assert d.full_correct is False
        assert d.ablated_correct is False


# =============================================================================
# compute_family_deltas
# =============================================================================


class TestFamilyDeltas:
    def test_five_rows_with_data(self):
        deltas = [
            ScenarioDelta(
                scenario_id="A", category="framing",
                framing_strategy="severity_x",
                expected_verdict="THREAT_CONFIRMED",
                full_verdict="THREAT_CONFIRMED",
                ablated_verdict="INCONCLUSIVE",
                verdict_flipped=True, full_correct=True, ablated_correct=False,
            ),
        ]
        rows = compute_family_deltas(deltas)
        assert len(rows) == 5

    def test_family_labels_in_order(self):
        rows = compute_family_deltas(())
        labels = [r.family for r in rows]
        assert labels == ["severity", "authority", "temporal", "causal", "narrative"]

    def test_family_n_reflects_bucket_size(self):
        deltas = [
            ScenarioDelta("A", "framing", "severity_one",
                          "THREAT_CONFIRMED", "THREAT_CONFIRMED",
                          "THREAT_CONFIRMED",
                          False, True, True),
            ScenarioDelta("B", "framing", "severity_two",
                          "THREAT_CONFIRMED", "THREAT_CONFIRMED",
                          "INCONCLUSIVE",
                          True, True, False),
        ]
        rows = compute_family_deltas(deltas)
        severity = next(r for r in rows if r.family == "severity")
        assert severity.n == 2
        assert severity.full_accuracy == pytest.approx(1.0)
        assert severity.ablated_accuracy == pytest.approx(0.5)
        assert severity.delta_pp == pytest.approx(-50.0)

    def test_delta_pp_positive_when_ablated_improves(self):
        deltas = [
            ScenarioDelta("A", "framing", "temporal_one",
                          "THREAT_CONFIRMED", "INCONCLUSIVE",
                          "THREAT_CONFIRMED",
                          True, False, True),
        ]
        rows = compute_family_deltas(deltas)
        temporal = next(r for r in rows if r.family == "temporal")
        assert temporal.delta_pp == pytest.approx(100.0)

    def test_non_matching_families_are_zero(self):
        deltas = [
            ScenarioDelta("A", "framing", "severity_one",
                          "THREAT_CONFIRMED", "THREAT_CONFIRMED",
                          "THREAT_CONFIRMED",
                          False, True, True),
        ]
        rows = compute_family_deltas(deltas)
        for label in ("authority", "temporal", "causal", "narrative"):
            row = next(r for r in rows if r.family == label)
            assert row.n == 0

    def test_skipped_when_strategy_is_none(self):
        deltas = [
            ScenarioDelta("A", "framing", None,
                          "THREAT_CONFIRMED", "THREAT_CONFIRMED",
                          "THREAT_CONFIRMED",
                          False, True, True),
        ]
        rows = compute_family_deltas(deltas)
        for r in rows:
            assert r.n == 0


# =============================================================================
# Finding-9 rubric
# =============================================================================


def _framing_delta(correct_full: bool, correct_ablated: bool,
                   sid="X") -> ScenarioDelta:
    return ScenarioDelta(
        scenario_id=sid,
        category="framing",
        framing_strategy="severity_x",
        expected_verdict="THREAT_CONFIRMED",
        full_verdict="THREAT_CONFIRMED" if correct_full else "INCONCLUSIVE",
        ablated_verdict="THREAT_CONFIRMED" if correct_ablated else "INCONCLUSIVE",
        verdict_flipped=correct_full != correct_ablated,
        full_correct=correct_full,
        ablated_correct=correct_ablated,
    )


class TestFindingNineRubric:
    def test_ablated_below_supported_threshold_is_supported(self):
        deltas = [
            _framing_delta(True, False, sid=f"S{i}") for i in range(5)
        ] + [
            _framing_delta(True, True, sid=f"T{i}") for i in range(2)
        ]
        # 2 / 7 = 0.286 ablated accuracy < 0.55
        verdict = compute_finding_9(deltas)
        assert verdict.label == FINDING_9_SUPPORTED

    def test_ablated_in_ambiguous_band(self):
        correct = [_framing_delta(True, True, sid=f"A{i}") for i in range(3)]
        incorrect = [_framing_delta(True, False, sid=f"B{i}") for i in range(2)]
        # 3 / 5 = 0.60 ablated accuracy in [0.55, 0.70)
        verdict = compute_finding_9(correct + incorrect)
        assert verdict.label == FINDING_9_AMBIGUOUS

    def test_ablated_at_or_above_upper_is_not_supported(self):
        correct = [_framing_delta(True, True, sid=f"A{i}") for i in range(7)]
        incorrect = [_framing_delta(True, False, sid=f"B{i}") for i in range(3)]
        # 7 / 10 = 0.70 >= 0.70 -> NOT SUPPORTED
        verdict = compute_finding_9(correct + incorrect)
        assert verdict.label == FINDING_9_NOT_SUPPORTED

    def test_boundary_below_supported(self):
        correct = [_framing_delta(True, True, sid=f"A{i}") for i in range(54)]
        incorrect = [_framing_delta(True, False, sid=f"B{i}") for i in range(46)]
        # 54 / 100 = 0.54 < 0.55 -> SUPPORTED
        verdict = compute_finding_9(correct + incorrect)
        assert verdict.label == FINDING_9_SUPPORTED

    def test_exactly_at_supported_threshold_is_ambiguous(self):
        correct = [_framing_delta(True, True, sid=f"A{i}") for i in range(55)]
        incorrect = [_framing_delta(True, False, sid=f"B{i}") for i in range(45)]
        # 0.55 is inclusive lower bound of AMBIGUOUS.
        verdict = compute_finding_9(correct + incorrect)
        assert verdict.label == FINDING_9_AMBIGUOUS

    def test_exactly_at_upper_threshold_is_not_supported(self):
        correct = [_framing_delta(True, True, sid=f"A{i}") for i in range(70)]
        incorrect = [_framing_delta(True, False, sid=f"B{i}") for i in range(30)]
        verdict = compute_finding_9(correct + incorrect)
        assert verdict.label == FINDING_9_NOT_SUPPORTED

    def test_empty_population_returns_ambiguous(self):
        verdict = compute_finding_9(())
        assert verdict.label == FINDING_9_AMBIGUOUS
        assert verdict.n_framing_scenarios == 0

    def test_delta_pp_is_ablated_minus_full(self):
        deltas = [
            _framing_delta(True, True, sid="A"),
            _framing_delta(True, False, sid="B"),
        ]
        verdict = compute_finding_9(deltas)
        assert verdict.full_framing_accuracy == pytest.approx(1.0)
        assert verdict.ablated_framing_accuracy == pytest.approx(0.5)
        assert verdict.delta_pp == pytest.approx(-50.0)

    def test_non_framing_scenarios_excluded(self):
        deltas = [
            ScenarioDelta("A", "direct", None, "THREAT_CONFIRMED",
                          "THREAT_CONFIRMED", "THREAT_CONFIRMED",
                          False, True, True),
        ]
        verdict = compute_finding_9(deltas)
        assert verdict.n_framing_scenarios == 0

    def test_rubric_constants_values(self):
        assert FINDING_9_SUPPORTED_MAX_EXCLUSIVE == 0.55
        assert FINDING_9_AMBIGUOUS_MAX_EXCLUSIVE == 0.70


# =============================================================================
# CSV output
# =============================================================================


class TestCSVOutput:
    def test_scenario_csv_header(self, tmp_path):
        d = ScenarioDelta(
            "A", "framing", "severity_one", "THREAT_CONFIRMED",
            "THREAT_CONFIRMED", "INCONCLUSIVE",
            True, True, False,
        )
        out = write_scenario_csv([d], tmp_path / "delta.csv")
        with out.open(encoding="utf-8") as fh:
            reader = csv.reader(fh)
            header = next(reader)
        assert tuple(header) == SCENARIO_CSV_HEADER

    def test_scenario_csv_row_shape(self, tmp_path):
        d = ScenarioDelta(
            "A", "framing", "severity_one", "THREAT_CONFIRMED",
            "THREAT_CONFIRMED", "INCONCLUSIVE",
            True, True, False,
        )
        out = write_scenario_csv([d], tmp_path / "delta.csv")
        with out.open(encoding="utf-8") as fh:
            rows = list(csv.reader(fh))
        assert len(rows) == 2
        assert rows[1][0] == "A"
        assert rows[1][6] == "true"  # verdict_flipped

    def test_family_csv_header(self, tmp_path):
        row = FamilyDelta("severity", 3, 0.8, 0.4, -40.0)
        out = write_family_csv([row], tmp_path / "family.csv")
        with out.open(encoding="utf-8") as fh:
            reader = csv.reader(fh)
            header = next(reader)
        assert tuple(header) == FAMILY_CSV_HEADER

    def test_family_csv_values(self, tmp_path):
        row = FamilyDelta("severity", 3, 0.8, 0.4, -40.0)
        out = write_family_csv([row], tmp_path / "family.csv")
        with out.open(encoding="utf-8") as fh:
            rows = list(csv.reader(fh))
        assert rows[1][0] == "severity"
        assert rows[1][1] == "3"
        assert rows[1][2] == "0.8000"
        assert rows[1][3] == "0.4000"
        assert rows[1][4] == "-40.00"


# =============================================================================
# Markdown + stdout
# =============================================================================


class TestMarkdownAndStdout:
    def _finding(self, label=FINDING_9_AMBIGUOUS, ablated=0.6, full=0.8):
        return FindingNineVerdict(
            label=label,
            ablated_framing_accuracy=ablated,
            full_framing_accuracy=full,
            delta_pp=(ablated - full) * 100.0,
            n_framing_scenarios=22,
        )

    def test_finding_line_format(self):
        line = print_finding_line(self._finding())
        assert line.startswith("Finding-9:")
        assert "AMBIGUOUS" in line
        assert "n=22" in line

    def test_render_markdown_contains_verdict(self):
        md = render_summary_markdown((), (), self._finding())
        assert "Finding-9" in md
        assert "AMBIGUOUS" in md

    def test_render_markdown_has_family_section(self):
        md = render_summary_markdown((), (), self._finding())
        assert "Per-Framing-Family" in md

    def test_render_markdown_flipped_section(self):
        md = render_summary_markdown((), (), self._finding())
        assert "flipped" in md.lower()

    def test_render_markdown_lists_flipped(self):
        deltas = (
            ScenarioDelta("A", "framing", "severity_one",
                          "THREAT_CONFIRMED", "THREAT_CONFIRMED",
                          "INCONCLUSIVE",
                          True, True, False),
        )
        md = render_summary_markdown(deltas, (), self._finding())
        assert "INJ-A"[3:] not in md  # not a scenario_id we used
        assert "severity_one" in md

    def test_render_markdown_with_authority_full(self):
        auth = (_v2(variant="full", scenario_id="INJ-028",
                    framing_strategy="authority_credentialed_source",
                    actual_verdict="THREAT_CONFIRMED",
                    expected_verdict="THREAT_CONFIRMED"),)
        md = render_summary_markdown((), (), self._finding(),
                                     authority_full_results=auth)
        assert "INJ-028" in md
        assert "Authority Expansion" in md

    def test_write_summary_markdown_creates_file(self, tmp_path):
        out = write_summary_markdown(
            (), (), self._finding(), tmp_path / "summary.md",
        )
        assert out.exists()
        contents = out.read_text(encoding="utf-8")
        assert "# Session 049" in contents


# =============================================================================
# Loaders
# =============================================================================


class TestLoaders:
    def test_load_session_048_parses_results(self, tmp_path):
        raw = {
            "results": [_v1().to_dict()],
        }
        path = tmp_path / "raw.json"
        path.write_text(json.dumps(raw), encoding="utf-8")
        loaded = load_session_048(path)
        assert len(loaded) == 1
        assert loaded[0].scenario_id == "INJ-013"

    def test_load_session_049_parses_ablated_results(self, tmp_path):
        raw = {
            "ablated_results": [_v2(variant="ablated").to_dict()],
            "full_results": [],
        }
        path = tmp_path / "raw.json"
        path.write_text(json.dumps(raw), encoding="utf-8")
        loaded = load_session_049(path)
        assert len(loaded) == 1
        assert loaded[0].pipeline_variant == "ablated"


# =============================================================================
# run_comparison and CLI
# =============================================================================


class TestRunComparison:
    def _write_inputs(self, tmp_path):
        s48 = {"results": [
            _v1(scenario_id="INJ-013",
                framing_strategy="severity_one",
                actual_verdict="THREAT_CONFIRMED",
                expected_verdict="THREAT_CONFIRMED").to_dict(),
            _v1(scenario_id="INJ-019",
                framing_strategy="temporal_one",
                actual_verdict="THREAT_CONFIRMED",
                expected_verdict="THREAT_CONFIRMED").to_dict(),
        ]}
        s49 = {
            "ablated_results": [
                _v2(variant="ablated",
                    scenario_id="INJ-013",
                    framing_strategy="severity_one",
                    actual_verdict="INCONCLUSIVE",
                    expected_verdict="THREAT_CONFIRMED").to_dict(),
                _v2(variant="ablated",
                    scenario_id="INJ-019",
                    framing_strategy="temporal_one",
                    actual_verdict="THREAT_CONFIRMED",
                    expected_verdict="THREAT_CONFIRMED").to_dict(),
            ],
            "full_results": [
                _v2(variant="full",
                    scenario_id="INJ-028",
                    framing_strategy="authority_credentialed_source",
                    actual_verdict="THREAT_CONFIRMED",
                    expected_verdict="THREAT_CONFIRMED").to_dict(),
            ],
        }
        s48_path = tmp_path / "s48.json"
        s48_path.write_text(json.dumps(s48), encoding="utf-8")
        s49_path = tmp_path / "s49.json"
        s49_path.write_text(json.dumps(s49), encoding="utf-8")
        return s48_path, s49_path

    def test_run_comparison_writes_three_files(self, tmp_path):
        s48, s49 = self._write_inputs(tmp_path)
        out_dir = tmp_path / "out"
        scenario_csv, family_csv, summary_md, verdict = run_comparison(
            s48, s49, out_dir,
        )
        assert scenario_csv.exists()
        assert family_csv.exists()
        assert summary_md.exists()
        assert isinstance(verdict, FindingNineVerdict)

    def test_run_comparison_prints_finding_line(self, tmp_path, capsys):
        s48, s49 = self._write_inputs(tmp_path)
        out_dir = tmp_path / "out"
        run_comparison(s48, s49, out_dir)
        captured = capsys.readouterr()
        assert "Finding-9:" in captured.out


class TestCLI:
    def test_parser_session_048_flag(self):
        parser = build_arg_parser()
        args = parser.parse_args(["--session-048", "foo.json"])
        assert args.session_048 == Path("foo.json")

    def test_parser_session_049_flag(self):
        parser = build_arg_parser()
        args = parser.parse_args(["--session-049", "bar.json"])
        assert args.session_049 == Path("bar.json")

    def test_main_returns_two_when_s48_missing(self, tmp_path):
        s49 = tmp_path / "ok.json"
        s49.write_text(
            json.dumps({"ablated_results": [], "full_results": []}),
            encoding="utf-8",
        )
        code = main([
            "--session-048", str(tmp_path / "missing.json"),
            "--session-049", str(s49),
            "--output-dir", str(tmp_path / "out"),
        ])
        assert code == 2

    def test_main_returns_two_when_s49_missing(self, tmp_path):
        s48 = tmp_path / "ok.json"
        s48.write_text(json.dumps({"results": []}), encoding="utf-8")
        code = main([
            "--session-048", str(s48),
            "--session-049", str(tmp_path / "missing.json"),
            "--output-dir", str(tmp_path / "out"),
        ])
        assert code == 2

    def test_main_returns_zero_on_success(self, tmp_path):
        s48 = tmp_path / "s48.json"
        s48.write_text(
            json.dumps({"results": [_v1().to_dict()]}),
            encoding="utf-8",
        )
        s49 = tmp_path / "s49.json"
        s49.write_text(json.dumps({
            "ablated_results": [_v2(variant="ablated").to_dict()],
            "full_results": [],
        }), encoding="utf-8")
        out_dir = tmp_path / "out"
        code = main([
            "--session-048", str(s48),
            "--session-049", str(s49),
            "--output-dir", str(out_dir),
        ])
        assert code == 0
        assert (out_dir / "ablation_delta.csv").exists()
        assert (out_dir / "family_comparison.csv").exists()
        assert (out_dir / "summary.md").exists()


# =============================================================================
# Frozen types
# =============================================================================


class TestFrozenTypes:
    def test_scenario_delta_frozen(self):
        d = ScenarioDelta("A", "framing", None, "x", "x", "x", False, True, True)
        with pytest.raises(Exception):
            d.scenario_id = "B"  # type: ignore[misc]

    def test_family_delta_frozen(self):
        r = FamilyDelta("severity", 1, 1.0, 0.5, -50.0)
        with pytest.raises(Exception):
            r.n = 9  # type: ignore[misc]

    def test_finding_nine_verdict_frozen(self):
        v = FindingNineVerdict(FINDING_9_SUPPORTED, 0.3, 0.7, -40.0, 10)
        with pytest.raises(Exception):
            v.label = FINDING_9_AMBIGUOUS  # type: ignore[misc]
