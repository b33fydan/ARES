"""Tests for three_way_comparison_report — Session 050 analysis."""

from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from ares.dialectic.schemas.framing_benchmark_result import (
    FramingBenchmarkResult,
)
from ares.dialectic.schemas.framing_benchmark_result_v3 import (
    FramingBenchmarkResultV3,
)
from ares.dialectic.scripts.analysis.three_way_comparison_report import (
    FAMILY_CSV_HEADER,
    FINDING_11_NOT_SUPPORTED,
    FINDING_11_PARTIAL,
    FINDING_11_PARTIAL_DELTA,
    FINDING_11_SUPPORTED,
    FINDING_11_SUPPORTED_DELTA,
    SCENARIO_CSV_HEADER,
    FindingElevenVerdict,
    ThreeWayFamilyRow,
    ThreeWayScenarioRow,
    build_scenario_rows,
    compute_family_rows,
    compute_finding_11,
    find_light_only_wins,
    load_session_048,
    load_session_049_ablated,
    load_session_049_full,
    load_session_050,
    main,
    merge_sources,
    print_finding_11_line,
    render_finding_11_markdown,
    render_summary_markdown,
    run_comparison,
    write_family_csv,
    write_finding_11_markdown,
    write_scenario_csv,
    write_summary_markdown,
)


def _v1(**overrides) -> FramingBenchmarkResult:
    base = dict(
        scenario_id="INJ-013",
        category="framing",
        framing_strategy="severity_one",
        expected_verdict="THREAT_CONFIRMED",
        actual_verdict="THREAT_CONFIRMED",
        firewall_detected=False,
        taint_score=0.0,
        confidence_trajectory=(0.8, 0.3, 0.7),
        pipeline_error=None,
        elapsed_ms=100,
    )
    base.update(overrides)
    return FramingBenchmarkResult(**base)


def _v3(variant="light", **overrides) -> FramingBenchmarkResultV3:
    return FramingBenchmarkResultV3(
        inner=_v1(**overrides),
        pipeline_variant=variant,
    )


# =============================================================================
# merge_sources
# =============================================================================


class TestMergeSources:
    def test_basic_match(self):
        s048 = [_v1(scenario_id="A")]
        s049 = [_v3(variant="ablated", scenario_id="A")]
        s050 = [_v3(variant="light", scenario_id="A")]
        merged = merge_sources(
            s048_full=s048, s049_ablated=s049, s050_rows=s050,
        )
        assert "A" in merged.full_by_id
        assert "A" in merged.ablated_by_id
        assert "A" in merged.light_by_id

    def test_light_only_source_adds_to_light_index(self):
        s050 = [_v3(variant="light", scenario_id="A")]
        merged = merge_sources(
            s048_full=(), s049_ablated=(), s050_rows=s050,
        )
        assert "A" in merged.light_by_id

    def test_s050_full_backfills_when_no_s048(self):
        s050 = [_v3(variant="full", scenario_id="B")]
        merged = merge_sources(
            s048_full=(), s049_ablated=(), s050_rows=s050,
        )
        assert "B" in merged.full_by_id

    def test_s050_full_does_not_override_s048(self):
        s048 = [_v1(scenario_id="A", actual_verdict="THREAT_CONFIRMED")]
        s050 = [
            _v3(variant="full", scenario_id="A", actual_verdict="INCONCLUSIVE"),
        ]
        merged = merge_sources(
            s048_full=s048, s049_ablated=(), s050_rows=s050,
        )
        assert merged.full_by_id["A"].actual_verdict == "THREAT_CONFIRMED"

    def test_s049_full_backfill(self):
        s049_full = [_v3(variant="full", scenario_id="Q")]
        merged = merge_sources(
            s048_full=(), s049_ablated=(),
            s049_full=s049_full, s050_rows=(),
        )
        assert "Q" in merged.full_by_id


# =============================================================================
# build_scenario_rows
# =============================================================================


class TestBuildScenarioRows:
    def _merged(self, *, a_full="THREAT_CONFIRMED", a_abl="INCONCLUSIVE",
                a_light="THREAT_CONFIRMED"):
        s048 = [_v1(scenario_id="A", framing_strategy="severity_x",
                    expected_verdict="THREAT_CONFIRMED", actual_verdict=a_full)]
        s049 = [_v3(variant="ablated", scenario_id="A",
                    framing_strategy="severity_x",
                    expected_verdict="THREAT_CONFIRMED", actual_verdict=a_abl)]
        s050 = [_v3(variant="light", scenario_id="A",
                    framing_strategy="severity_x",
                    expected_verdict="THREAT_CONFIRMED", actual_verdict=a_light)]
        return merge_sources(s048_full=s048, s049_ablated=s049, s050_rows=s050)

    def test_row_created_for_matched_scenarios(self):
        merged = self._merged()
        rows = build_scenario_rows(merged)
        assert len(rows) == 1
        assert rows[0].scenario_id == "A"

    def test_correctness_booleans(self):
        merged = self._merged(
            a_full="THREAT_CONFIRMED",
            a_abl="INCONCLUSIVE",
            a_light="THREAT_CONFIRMED",
        )
        rows = build_scenario_rows(merged)
        row = rows[0]
        assert row.full_correct is True
        assert row.ablated_correct is False
        assert row.light_correct is True

    def test_skipped_when_not_in_all_three(self):
        # Only in light, not in full/ablated.
        merged = merge_sources(
            s048_full=(), s049_ablated=(),
            s050_rows=[_v3(variant="light", scenario_id="A")],
        )
        rows = build_scenario_rows(merged)
        assert rows == ()


# =============================================================================
# compute_family_rows
# =============================================================================


class TestComputeFamilyRows:
    def test_five_rows_by_default(self):
        rows = compute_family_rows(())
        assert len(rows) == 5

    def test_labels_canonical_order(self):
        rows = compute_family_rows(())
        labels = [r.family for r in rows]
        assert labels == ["severity", "authority", "temporal", "causal", "narrative"]

    def test_bucket_size_and_accuracy(self):
        sr = [
            ThreeWayScenarioRow("A", "framing", "severity_one",
                                "THREAT_CONFIRMED", "THREAT_CONFIRMED",
                                "THREAT_CONFIRMED", "THREAT_CONFIRMED",
                                True, True, True),
            ThreeWayScenarioRow("B", "framing", "severity_two",
                                "THREAT_CONFIRMED", "THREAT_CONFIRMED",
                                "INCONCLUSIVE", "THREAT_CONFIRMED",
                                True, True, False, True).__dict__
            if False else ThreeWayScenarioRow("B", "framing", "severity_two",
                                               "THREAT_CONFIRMED", "THREAT_CONFIRMED",
                                               "INCONCLUSIVE", "THREAT_CONFIRMED",
                                               True, False, True),
        ]
        rows = compute_family_rows(sr)
        severity = next(r for r in rows if r.family == "severity")
        assert severity.n == 2
        assert severity.full_accuracy == pytest.approx(1.0)
        assert severity.ablated_accuracy == pytest.approx(0.5)
        assert severity.light_accuracy == pytest.approx(1.0)

    def test_non_matching_families_stay_zero(self):
        sr = [
            ThreeWayScenarioRow("A", "framing", "severity_one",
                                "THREAT_CONFIRMED", "THREAT_CONFIRMED",
                                "THREAT_CONFIRMED", "THREAT_CONFIRMED",
                                True, True, True),
        ]
        rows = compute_family_rows(sr)
        for label in ("authority", "temporal", "causal", "narrative"):
            row = next(r for r in rows if r.family == label)
            assert row.n == 0

    def test_no_strategy_rows_skipped(self):
        sr = [
            ThreeWayScenarioRow("A", "framing", None,
                                "INCONCLUSIVE", "INCONCLUSIVE",
                                "INCONCLUSIVE", "INCONCLUSIVE",
                                True, True, True),
        ]
        rows = compute_family_rows(sr)
        for r in rows:
            assert r.n == 0


# =============================================================================
# compute_finding_11 (the rubric)
# =============================================================================


def _framing_row(
    *,
    full_correct: bool = True,
    ablated_correct: bool = True,
    light_correct: bool = True,
    sid: str = "X",
) -> ThreeWayScenarioRow:
    return ThreeWayScenarioRow(
        scenario_id=sid,
        category="framing",
        framing_strategy="severity_one",
        expected_verdict="THREAT_CONFIRMED",
        full_verdict=("THREAT_CONFIRMED" if full_correct else "INCONCLUSIVE"),
        ablated_verdict=("THREAT_CONFIRMED" if ablated_correct else "INCONCLUSIVE"),
        light_verdict=("THREAT_CONFIRMED" if light_correct else "INCONCLUSIVE"),
        full_correct=full_correct,
        ablated_correct=ablated_correct,
        light_correct=light_correct,
    )


class TestFindingElevenRubric:
    def test_label_supported_when_light_within_5pp(self):
        # 8 correct full, 8 correct light → delta 0 → SUPPORTED
        rows = (
            [_framing_row(sid=f"A{i}") for i in range(8)]
            + [_framing_row(full_correct=False, ablated_correct=False,
                            light_correct=False, sid=f"B{i}") for i in range(2)]
        )
        v = compute_finding_11(rows)
        assert v.label == FINDING_11_SUPPORTED

    def test_label_partial_when_delta_in_5_to_10(self):
        # full=10/10=1.0, light=9/10=0.9, delta=-0.1 → exactly at 10pp boundary
        # which per spec is "full - 0.10 <= light < full - 0.05" → PARTIAL.
        rows = (
            [_framing_row(sid=f"A{i}") for i in range(9)]
            + [_framing_row(light_correct=False, sid="B0")]
        )
        v = compute_finding_11(rows)
        assert v.label == FINDING_11_PARTIAL

    def test_label_not_supported_when_below_10pp(self):
        # full=10/10=1.0, light=8/10=0.8 → -0.20 pp → NOT SUPPORTED
        rows = (
            [_framing_row(sid=f"A{i}") for i in range(8)]
            + [_framing_row(light_correct=False, sid="B1")]
            + [_framing_row(light_correct=False, sid="B2")]
        )
        v = compute_finding_11(rows)
        assert v.label == FINDING_11_NOT_SUPPORTED

    def test_light_beats_full_still_supported(self):
        # full=5/10, light=9/10 → delta +0.4 → SUPPORTED (>= full - 0.05)
        rows = (
            [_framing_row(sid=f"A{i}") for i in range(5)]
            + [_framing_row(full_correct=False, sid=f"B{i}") for i in range(4)]
            + [_framing_row(full_correct=False, light_correct=False, sid="C0")]
        )
        v = compute_finding_11(rows)
        assert v.label == FINDING_11_SUPPORTED

    def test_non_framing_scenarios_excluded(self):
        rows = (
            ThreeWayScenarioRow("A", "direct", None, "X", "X", "X", "X",
                                True, True, True),
        )
        v = compute_finding_11(rows)
        assert v.n_framing_scenarios == 0

    def test_empty_returns_partial(self):
        v = compute_finding_11(())
        assert v.label == FINDING_11_PARTIAL
        assert v.n_framing_scenarios == 0

    def test_threshold_constants(self):
        assert FINDING_11_SUPPORTED_DELTA == 0.05
        assert FINDING_11_PARTIAL_DELTA == 0.10

    def test_verdict_fields_populated(self):
        rows = [_framing_row(sid=f"A{i}") for i in range(5)]
        v = compute_finding_11(rows)
        assert v.n_framing_scenarios == 5
        assert v.full_framing_accuracy == 1.0
        assert v.ablated_framing_accuracy == 1.0
        assert v.light_framing_accuracy == 1.0


# =============================================================================
# find_light_only_wins
# =============================================================================


class TestLightOnlyWins:
    def test_finds_scenarios_only_light_correct(self):
        rows = (
            _framing_row(full_correct=False, ablated_correct=False,
                         light_correct=True, sid="W1"),
            _framing_row(full_correct=True, ablated_correct=True,
                         light_correct=True, sid="W2"),
        )
        wins = find_light_only_wins(rows)
        ids = {r.scenario_id for r in wins}
        assert ids == {"W1"}

    def test_empty_when_no_wins(self):
        rows = (_framing_row(sid="A"),)
        assert find_light_only_wins(rows) == ()


# =============================================================================
# CSV output
# =============================================================================


class TestCSVShape:
    def test_scenario_csv_header(self, tmp_path):
        rows = [_framing_row(sid="A")]
        out = write_scenario_csv(rows, tmp_path / "s.csv")
        with out.open(encoding="utf-8") as fh:
            reader = csv.reader(fh)
            header = next(reader)
        assert tuple(header) == SCENARIO_CSV_HEADER

    def test_family_csv_header(self, tmp_path):
        rows = [ThreeWayFamilyRow("severity", 3, 0.9, 0.6, 0.8)]
        out = write_family_csv(rows, tmp_path / "f.csv")
        with out.open(encoding="utf-8") as fh:
            reader = csv.reader(fh)
            header = next(reader)
        assert tuple(header) == FAMILY_CSV_HEADER

    def test_scenario_csv_row_count(self, tmp_path):
        rows = [_framing_row(sid=str(i)) for i in range(5)]
        out = write_scenario_csv(rows, tmp_path / "s.csv")
        with out.open(encoding="utf-8") as fh:
            data = list(csv.reader(fh))
        assert len(data) == 6  # header + 5

    def test_family_csv_values(self, tmp_path):
        rows = [ThreeWayFamilyRow("causal", 3, 1.0, 0.6667, 0.8)]
        out = write_family_csv(rows, tmp_path / "f.csv")
        with out.open(encoding="utf-8") as fh:
            data = list(csv.reader(fh))
        assert data[1][0] == "causal"
        assert data[1][1] == "3"
        assert data[1][2] == "1.0000"
        assert data[1][3] == "0.6667"
        assert data[1][4] == "0.8000"


# =============================================================================
# Markdown
# =============================================================================


class TestMarkdown:
    def _v(self, label=FINDING_11_PARTIAL):
        return FindingElevenVerdict(
            label=label,
            full_framing_accuracy=0.79,
            ablated_framing_accuracy=0.68,
            light_framing_accuracy=0.72,
            delta_light_minus_full=-0.07,
            n_framing_scenarios=22,
        )

    def test_rendered_finding_markdown_contains_label(self):
        md = render_finding_11_markdown(self._v(FINDING_11_SUPPORTED))
        assert "SUPPORTED" in md
        assert "0.05" in md

    def test_rendered_summary_has_finding_section(self):
        md = render_summary_markdown((), (), self._v())
        assert "Finding-11 Verdict" in md

    def test_rendered_summary_has_family_table(self):
        md = render_summary_markdown((), (), self._v())
        assert "Per-Framing-Family" in md

    def test_rendered_summary_has_light_only_section(self):
        md = render_summary_markdown((), (), self._v())
        assert "Light-Pipeline Standalone Wins" in md

    def test_render_summary_lists_scenarios(self):
        rows = (_framing_row(sid="INJ-099"),)
        md = render_summary_markdown(rows, (), self._v())
        assert "INJ-099" in md

    def test_write_finding_md(self, tmp_path):
        out = write_finding_11_markdown(
            self._v(), tmp_path / "finding_11.md",
        )
        assert out.exists()
        assert "# Finding-11 Verdict" in out.read_text(encoding="utf-8")

    def test_write_summary_md(self, tmp_path):
        out = write_summary_markdown(
            (), (), self._v(), tmp_path / "summary.md",
        )
        assert out.exists()


class TestPrintFindingLine:
    def test_contains_label_and_numbers(self):
        v = FindingElevenVerdict(
            label=FINDING_11_SUPPORTED,
            full_framing_accuracy=0.80,
            ablated_framing_accuracy=0.65,
            light_framing_accuracy=0.78,
            delta_light_minus_full=-0.02,
            n_framing_scenarios=10,
        )
        line = print_finding_11_line(v)
        assert "Finding-11:" in line
        assert "SUPPORTED" in line
        assert "light_framing_accuracy=0.7800" in line
        assert "n=10" in line


# =============================================================================
# Loaders
# =============================================================================


class TestLoaders:
    def test_load_s048(self, tmp_path):
        raw = {"results": [_v1().to_dict()]}
        path = tmp_path / "s048.json"
        path.write_text(json.dumps(raw), encoding="utf-8")
        loaded = load_session_048(path)
        assert len(loaded) == 1

    def test_load_s049_ablated(self, tmp_path):
        raw = {
            "ablated_results": [_v3(variant="ablated").to_dict()],
            "full_results": [],
        }
        path = tmp_path / "s049.json"
        path.write_text(json.dumps(raw), encoding="utf-8")
        loaded = load_session_049_ablated(path)
        assert len(loaded) == 1
        assert loaded[0].pipeline_variant == "ablated"

    def test_load_s049_full(self, tmp_path):
        raw = {
            "ablated_results": [],
            "full_results": [_v3(variant="full").to_dict()],
        }
        path = tmp_path / "s049.json"
        path.write_text(json.dumps(raw), encoding="utf-8")
        loaded = load_session_049_full(path)
        assert len(loaded) == 1
        assert loaded[0].pipeline_variant == "full"

    def test_load_s050(self, tmp_path):
        raw = {
            "light_results": [_v3(variant="light").to_dict()],
            "full_live_results": [_v3(variant="full", scenario_id="A").to_dict()],
            "ablated_live_results": [_v3(variant="ablated", scenario_id="B").to_dict()],
        }
        path = tmp_path / "s050.json"
        path.write_text(json.dumps(raw), encoding="utf-8")
        loaded = load_session_050(path)
        assert len(loaded) == 3
        variants = {r.pipeline_variant for r in loaded}
        assert variants == {"light", "full", "ablated"}


# =============================================================================
# CLI + run_comparison
# =============================================================================


class TestRunComparison:
    def _write_inputs(self, tmp_path):
        s48 = {"results": [_v1(scenario_id="A").to_dict()]}
        s49 = {
            "ablated_results": [
                _v3(variant="ablated", scenario_id="A").to_dict(),
            ],
            "full_results": [],
        }
        s50 = {
            "light_results": [
                _v3(variant="light", scenario_id="A").to_dict(),
            ],
            "full_live_results": [],
            "ablated_live_results": [],
        }
        s48_p = tmp_path / "s48.json"
        s48_p.write_text(json.dumps(s48), encoding="utf-8")
        s49_p = tmp_path / "s49.json"
        s49_p.write_text(json.dumps(s49), encoding="utf-8")
        s50_p = tmp_path / "s50.json"
        s50_p.write_text(json.dumps(s50), encoding="utf-8")
        return s48_p, s49_p, s50_p

    def test_writes_four_artifacts(self, tmp_path):
        s48, s49, s50 = self._write_inputs(tmp_path)
        out_dir = tmp_path / "out"
        scenario_csv, family_csv, verdict_md, summary_md, v = run_comparison(
            s48, s49, s50, out_dir,
        )
        assert scenario_csv.exists()
        assert family_csv.exists()
        assert verdict_md.exists()
        assert summary_md.exists()
        assert isinstance(v, FindingElevenVerdict)

    def test_prints_finding_line(self, tmp_path, capsys):
        s48, s49, s50 = self._write_inputs(tmp_path)
        out_dir = tmp_path / "out"
        run_comparison(s48, s49, s50, out_dir)
        captured = capsys.readouterr()
        assert "Finding-11:" in captured.out


class TestCLI:
    def test_default_inputs(self):
        from ares.dialectic.scripts.analysis.three_way_comparison_report import (
            build_arg_parser,
        )
        parser = build_arg_parser()
        args = parser.parse_args([])
        assert args.session_048 == Path("results/session_048/raw_results.json")
        assert args.session_049 == Path("results/session_049/ablated_raw_results.json")
        assert args.session_050 == Path("results/session_050/light_raw_results.json")

    def test_main_missing_s048_returns_two(self, tmp_path):
        code = main([
            "--session-048", str(tmp_path / "missing_048.json"),
            "--session-049", str(tmp_path / "missing_049.json"),
            "--session-050", str(tmp_path / "missing_050.json"),
            "--output-dir", str(tmp_path / "out"),
        ])
        assert code == 2

    def test_main_success(self, tmp_path):
        s48 = tmp_path / "s48.json"
        s48.write_text(json.dumps({"results": [_v1().to_dict()]}), encoding="utf-8")
        s49 = tmp_path / "s49.json"
        s49.write_text(
            json.dumps({"ablated_results": [], "full_results": []}),
            encoding="utf-8",
        )
        s50 = tmp_path / "s50.json"
        s50.write_text(
            json.dumps({
                "light_results": [],
                "full_live_results": [],
                "ablated_live_results": [],
            }),
            encoding="utf-8",
        )
        out_dir = tmp_path / "out"
        code = main([
            "--session-048", str(s48),
            "--session-049", str(s49),
            "--session-050", str(s50),
            "--output-dir", str(out_dir),
        ])
        assert code == 0
        assert (out_dir / "three_way_delta.csv").exists()
        assert (out_dir / "family_three_way.csv").exists()
        assert (out_dir / "finding_11_verdict.md").exists()
        assert (out_dir / "summary.md").exists()


class TestFrozenTypes:
    def test_scenario_row_frozen(self):
        r = _framing_row()
        with pytest.raises(Exception):
            r.scenario_id = "Y"  # type: ignore[misc]

    def test_family_row_frozen(self):
        r = ThreeWayFamilyRow("severity", 1, 1.0, 1.0, 1.0)
        with pytest.raises(Exception):
            r.n = 9  # type: ignore[misc]

    def test_verdict_frozen(self):
        v = FindingElevenVerdict(
            FINDING_11_SUPPORTED, 0.8, 0.6, 0.77, -0.03, 10,
        )
        with pytest.raises(Exception):
            v.label = FINDING_11_PARTIAL  # type: ignore[misc]
