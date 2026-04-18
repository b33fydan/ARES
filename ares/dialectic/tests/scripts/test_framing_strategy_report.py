"""Tests for framing_strategy_report — Session 048 aggregation analysis.

Covers:
    1. Family derivation for every Category B expansion strategy.
    2. Aggregate math over hand-crafted fixtures (detection, accuracy, taint).
    3. CSV header + row count + value shape.
    4. Markdown summary carries both the category and the family table.
    5. Report prints to stdout via print_report.
    6. CLI glue (build_arg_parser, run_report) + input/output contracts.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from ares.dialectic.schemas.framing_benchmark_result import (
    FramingBenchmarkResult,
)
from ares.dialectic.scripts.analysis.framing_strategy_report import (
    CATEGORIES,
    CSV_HEADER,
    FRAMING_FAMILIES,
    UNKNOWN_FAMILY,
    AggregateRow,
    aggregate_by_category,
    aggregate_by_family,
    build_arg_parser,
    derive_family,
    load_results,
    main,
    print_report,
    render_summary_markdown,
    run_report,
    write_per_strategy_csv,
    write_summary_markdown,
)


# =============================================================================
# Fixture builders
# =============================================================================


def _make(
    *,
    scenario_id="INJ-013",
    category="framing",
    framing_strategy="severity_downgrade_routine",
    expected="THREAT_CONFIRMED",
    actual="THREAT_CONFIRMED",
    detected=False,
    taint=0.1,
    pipeline_error=None,
):
    actual_verdict = "" if pipeline_error else actual
    trajectory = () if pipeline_error else (0.8, 0.3, 0.7)
    return FramingBenchmarkResult(
        scenario_id=scenario_id,
        category=category,
        framing_strategy=framing_strategy,
        expected_verdict=expected,
        actual_verdict=actual_verdict,
        firewall_detected=detected,
        taint_score=taint,
        confidence_trajectory=trajectory,
        pipeline_error=pipeline_error,
        elapsed_ms=100,
    )


# The canonical set of 15 Category B expansion strategies.
EXPANSION_STRATEGIES = (
    "severity_downgrade_routine",
    "severity_amplification_precedent",
    "severity_normalization_baseline",
    "authority_vendor_implication",
    "authority_industry_consensus",
    "authority_passive_voice_attribution",
    "temporal_patched_since",
    "temporal_active_exploitation_claim",
    "causal_benign_trigger",
    "causal_omitted_exploit",
    "causal_misattribution",
    "narrative_selective_emphasis",
    "narrative_ordering_bias",
    "narrative_false_equivalence",
    "narrative_dilution",
)


# =============================================================================
# derive_family
# =============================================================================


class TestDeriveFamily:
    def test_severity_downgrade_routine(self):
        assert derive_family("severity_downgrade_routine") == "severity"

    def test_severity_amplification_precedent(self):
        assert derive_family("severity_amplification_precedent") == "severity"

    def test_severity_normalization_baseline(self):
        assert derive_family("severity_normalization_baseline") == "severity"

    def test_authority_vendor_implication(self):
        assert derive_family("authority_vendor_implication") == "authority"

    def test_authority_industry_consensus(self):
        assert derive_family("authority_industry_consensus") == "authority"

    def test_authority_passive_voice_attribution(self):
        assert (
            derive_family("authority_passive_voice_attribution") == "authority"
        )

    def test_temporal_patched_since(self):
        assert derive_family("temporal_patched_since") == "temporal"

    def test_temporal_active_exploitation_claim(self):
        assert (
            derive_family("temporal_active_exploitation_claim") == "temporal"
        )

    def test_causal_benign_trigger(self):
        assert derive_family("causal_benign_trigger") == "causal"

    def test_causal_omitted_exploit(self):
        assert derive_family("causal_omitted_exploit") == "causal"

    def test_causal_misattribution(self):
        assert derive_family("causal_misattribution") == "causal"

    def test_narrative_selective_emphasis(self):
        assert derive_family("narrative_selective_emphasis") == "narrative"

    def test_narrative_ordering_bias(self):
        assert derive_family("narrative_ordering_bias") == "narrative"

    def test_narrative_false_equivalence(self):
        assert derive_family("narrative_false_equivalence") == "narrative"

    def test_narrative_dilution(self):
        assert derive_family("narrative_dilution") == "narrative"

    def test_none_strategy_returns_none(self):
        assert derive_family(None) is None

    def test_unknown_prefix_returns_unknown_family(self):
        assert derive_family("exotic_something") == UNKNOWN_FAMILY

    def test_all_15_expansion_strategies_map_to_known_family(self):
        for strategy in EXPANSION_STRATEGIES:
            family = derive_family(strategy)
            assert family in FRAMING_FAMILIES, (
                f"{strategy} mapped to {family} — expected one of "
                f"{FRAMING_FAMILIES}"
            )


# =============================================================================
# aggregate_by_category
# =============================================================================


class TestAggregateByCategory:
    def test_three_rows_in_canonical_order(self):
        rows = aggregate_by_category([
            _make(category="direct", framing_strategy=None),
            _make(category="framing"),
            _make(category="propagation", framing_strategy=None),
        ])
        labels = [r.label for r in rows]
        assert labels == list(CATEGORIES)

    def test_empty_input_still_returns_three_rows(self):
        rows = aggregate_by_category([])
        assert len(rows) == 3
        assert all(r.n == 0 for r in rows)

    def test_detection_rate_per_category(self):
        rows = aggregate_by_category([
            _make(category="direct", framing_strategy=None, detected=True),
            _make(category="direct", framing_strategy=None, detected=True),
            _make(category="direct", framing_strategy=None, detected=False),
            _make(category="direct", framing_strategy=None, detected=False),
        ])
        direct = next(r for r in rows if r.label == "direct")
        assert direct.n == 4
        assert direct.detection_rate == pytest.approx(0.5)

    def test_verdict_accuracy_per_category(self):
        rows = aggregate_by_category([
            _make(
                category="framing",
                expected="THREAT_CONFIRMED", actual="THREAT_CONFIRMED",
            ),
            _make(
                category="framing",
                expected="THREAT_CONFIRMED", actual="THREAT_CONFIRMED",
            ),
            _make(
                category="framing",
                expected="THREAT_CONFIRMED", actual="THREAT_DISMISSED",
            ),
        ])
        framing = next(r for r in rows if r.label == "framing")
        assert framing.verdict_accuracy == pytest.approx(2 / 3)

    def test_mean_taint_score_per_category(self):
        rows = aggregate_by_category([
            _make(category="propagation", framing_strategy=None, taint=0.2),
            _make(category="propagation", framing_strategy=None, taint=0.4),
            _make(category="propagation", framing_strategy=None, taint=0.6),
        ])
        prop = next(r for r in rows if r.label == "propagation")
        assert prop.mean_taint_score == pytest.approx(0.4)

    def test_results_in_wrong_category_do_not_leak(self):
        rows = aggregate_by_category([
            _make(category="direct", framing_strategy=None, detected=True),
            _make(category="framing", detected=False),
        ])
        direct = next(r for r in rows if r.label == "direct")
        framing = next(r for r in rows if r.label == "framing")
        assert direct.n == 1
        assert framing.n == 1

    def test_pipeline_error_counts_as_incorrect_verdict(self):
        rows = aggregate_by_category([
            _make(category="direct", framing_strategy=None,
                  pipeline_error="boom"),
            _make(category="direct", framing_strategy=None,
                  expected="THREAT_CONFIRMED", actual="THREAT_CONFIRMED"),
        ])
        direct = next(r for r in rows if r.label == "direct")
        assert direct.verdict_accuracy == pytest.approx(0.5)


# =============================================================================
# aggregate_by_family
# =============================================================================


class TestAggregateByFamily:
    def test_five_rows_by_default(self):
        rows = aggregate_by_family([
            _make(framing_strategy=s) for s in EXPANSION_STRATEGIES
        ])
        assert len(rows) == 5
        labels = [r.label for r in rows]
        assert labels == list(FRAMING_FAMILIES)

    def test_severity_group_has_three(self):
        rows = aggregate_by_family([
            _make(framing_strategy=s) for s in EXPANSION_STRATEGIES
        ])
        severity = next(r for r in rows if r.label == "severity")
        assert severity.n == 3

    def test_authority_group_has_three(self):
        rows = aggregate_by_family([
            _make(framing_strategy=s) for s in EXPANSION_STRATEGIES
        ])
        authority = next(r for r in rows if r.label == "authority")
        assert authority.n == 3

    def test_temporal_group_has_two(self):
        rows = aggregate_by_family([
            _make(framing_strategy=s) for s in EXPANSION_STRATEGIES
        ])
        temporal = next(r for r in rows if r.label == "temporal")
        assert temporal.n == 2

    def test_causal_group_has_three(self):
        rows = aggregate_by_family([
            _make(framing_strategy=s) for s in EXPANSION_STRATEGIES
        ])
        causal = next(r for r in rows if r.label == "causal")
        assert causal.n == 3

    def test_narrative_group_has_four(self):
        rows = aggregate_by_family([
            _make(framing_strategy=s) for s in EXPANSION_STRATEGIES
        ])
        narrative = next(r for r in rows if r.label == "narrative")
        assert narrative.n == 4

    def test_results_with_no_strategy_are_skipped(self):
        rows = aggregate_by_family([
            _make(framing_strategy=None),
            _make(framing_strategy=None),
            _make(framing_strategy="severity_downgrade_routine"),
        ])
        severity = next(r for r in rows if r.label == "severity")
        assert severity.n == 1
        # All other known-family rows remain at zero
        for other in ("authority", "temporal", "causal", "narrative"):
            empty = next(r for r in rows if r.label == other)
            assert empty.n == 0

    def test_unknown_prefix_surfaces_as_unknown_row(self):
        rows = aggregate_by_family([
            _make(framing_strategy="exotic_something"),
            _make(framing_strategy="another_unknown"),
        ])
        assert any(r.label == UNKNOWN_FAMILY for r in rows)
        unknown = next(r for r in rows if r.label == UNKNOWN_FAMILY)
        assert unknown.n == 2

    def test_empty_input_returns_five_empty_rows(self):
        rows = aggregate_by_family([])
        assert len(rows) == 5
        assert all(r.n == 0 for r in rows)

    def test_family_detection_rate(self):
        rows = aggregate_by_family([
            _make(framing_strategy="severity_downgrade_routine", detected=True),
            _make(framing_strategy="severity_amplification_precedent",
                  detected=False),
        ])
        severity = next(r for r in rows if r.label == "severity")
        assert severity.detection_rate == pytest.approx(0.5)

    def test_family_verdict_accuracy(self):
        rows = aggregate_by_family([
            _make(framing_strategy="narrative_selective_emphasis",
                  expected="THREAT_CONFIRMED", actual="THREAT_CONFIRMED"),
            _make(framing_strategy="narrative_ordering_bias",
                  expected="THREAT_CONFIRMED", actual="THREAT_DISMISSED"),
            _make(framing_strategy="narrative_false_equivalence",
                  expected="INCONCLUSIVE", actual="INCONCLUSIVE"),
            _make(framing_strategy="narrative_dilution",
                  expected="THREAT_DISMISSED", actual="THREAT_CONFIRMED"),
        ])
        narrative = next(r for r in rows if r.label == "narrative")
        assert narrative.verdict_accuracy == pytest.approx(0.5)

    def test_family_mean_taint(self):
        rows = aggregate_by_family([
            _make(framing_strategy="temporal_patched_since", taint=0.1),
            _make(framing_strategy="temporal_active_exploitation_claim",
                  taint=0.3),
        ])
        temporal = next(r for r in rows if r.label == "temporal")
        assert temporal.mean_taint_score == pytest.approx(0.2)


# =============================================================================
# Serialization
# =============================================================================


class TestCSVOutput:
    def _sample_rows(self):
        cat = aggregate_by_category([
            _make(category="framing",
                  framing_strategy="severity_downgrade_routine"),
        ])
        fam = aggregate_by_family([
            _make(framing_strategy=s) for s in EXPANSION_STRATEGIES
        ])
        return cat, fam

    def test_header_matches_constant(self, tmp_path):
        cat, fam = self._sample_rows()
        out = write_per_strategy_csv(cat, fam, tmp_path / "out.csv")
        with out.open(encoding="utf-8") as fh:
            reader = csv.reader(fh)
            header = next(reader)
        assert tuple(header) == CSV_HEADER

    def test_row_count_is_categories_plus_families(self, tmp_path):
        cat, fam = self._sample_rows()
        out = write_per_strategy_csv(cat, fam, tmp_path / "out.csv")
        with out.open(encoding="utf-8") as fh:
            rows = list(csv.reader(fh))
        assert len(rows) == 1 + len(cat) + len(fam)

    def test_group_type_column_values(self, tmp_path):
        cat, fam = self._sample_rows()
        out = write_per_strategy_csv(cat, fam, tmp_path / "out.csv")
        with out.open(encoding="utf-8") as fh:
            reader = csv.reader(fh)
            next(reader)  # header
            group_types = [row[0] for row in reader]
        assert group_types.count("category") == len(cat)
        assert group_types.count("family") == len(fam)

    def test_csv_values_are_floats_with_four_decimals(self, tmp_path):
        cat, fam = self._sample_rows()
        out = write_per_strategy_csv(cat, fam, tmp_path / "out.csv")
        with out.open(encoding="utf-8") as fh:
            reader = csv.reader(fh)
            next(reader)
            for row in reader:
                _, _, _, det, acc, taint = row
                # All three are strings with decimal point + 4 digits.
                for v in (det, acc, taint):
                    assert "." in v
                    assert len(v.split(".")[1]) == 4


class TestMarkdownOutput:
    def _sample_rows(self):
        cat = aggregate_by_category([
            _make(category="direct", framing_strategy=None, detected=True),
        ])
        fam = aggregate_by_family([
            _make(framing_strategy="severity_downgrade_routine"),
        ])
        return cat, fam

    def test_rendered_markdown_contains_both_tables(self):
        cat, fam = self._sample_rows()
        md = render_summary_markdown(cat, fam)
        assert "By Category" in md
        assert "By Framing Family" in md

    def test_rendered_markdown_includes_category_labels(self):
        cat, fam = self._sample_rows()
        md = render_summary_markdown(cat, fam)
        for label in CATEGORIES:
            assert label in md

    def test_rendered_markdown_includes_family_labels(self):
        cat, fam = self._sample_rows()
        md = render_summary_markdown(cat, fam)
        for label in FRAMING_FAMILIES:
            assert label in md

    def test_write_summary_creates_file(self, tmp_path):
        cat, fam = self._sample_rows()
        path = write_summary_markdown(cat, fam, tmp_path / "summary.md")
        assert path.exists()
        contents = path.read_text(encoding="utf-8")
        assert contents.startswith("# Session 048")


# =============================================================================
# I/O + CLI
# =============================================================================


class TestLoadResults:
    def test_loads_full_payload(self, tmp_path):
        raw = {
            "run_id": "abc",
            "timestamp": "2026-04-18T00:00:00+00:00",
            "model": "test",
            "total_scenarios": 1,
            "total_elapsed_ms": 10,
            "results": [_make().to_dict()],
        }
        path = tmp_path / "raw.json"
        path.write_text(json.dumps(raw), encoding="utf-8")
        results = load_results(path)
        assert len(results) == 1
        assert results[0].scenario_id == "INJ-013"

    def test_empty_results_returns_empty_tuple(self, tmp_path):
        raw = {"results": []}
        path = tmp_path / "raw.json"
        path.write_text(json.dumps(raw), encoding="utf-8")
        assert load_results(path) == ()


class TestRunReport:
    def _write_raw(self, tmp_path):
        results = [
            _make(scenario_id="INJ-001", category="direct",
                  framing_strategy=None, detected=True, taint=0.9),
            _make(scenario_id="INJ-013",
                  framing_strategy="severity_downgrade_routine",
                  detected=False, taint=0.2),
            _make(scenario_id="INJ-019",
                  framing_strategy="temporal_patched_since",
                  detected=False, taint=0.3),
        ]
        raw = {
            "run_id": "abc",
            "timestamp": "2026-04-18T00:00:00+00:00",
            "model": "test",
            "total_scenarios": len(results),
            "total_elapsed_ms": 10,
            "results": [r.to_dict() for r in results],
        }
        input_path = tmp_path / "raw_results.json"
        input_path.write_text(json.dumps(raw), encoding="utf-8")
        return input_path

    def test_writes_csv_and_markdown(self, tmp_path):
        input_path = self._write_raw(tmp_path)
        out_dir = tmp_path / "out"
        csv_path, md_path = run_report(input_path, out_dir)
        assert csv_path.exists()
        assert md_path.exists()

    def test_prints_to_stdout(self, tmp_path, capsys):
        input_path = self._write_raw(tmp_path)
        out_dir = tmp_path / "out"
        run_report(input_path, out_dir)
        captured = capsys.readouterr()
        assert "By Category" in captured.out
        assert "By Framing Family" in captured.out


class TestPrintReport:
    def test_print_report_emits_both_tables(self, capsys):
        cat = aggregate_by_category([
            _make(category="direct", framing_strategy=None),
        ])
        fam = aggregate_by_family([
            _make(framing_strategy="authority_vendor_implication"),
        ])
        print_report(cat, fam)
        captured = capsys.readouterr()
        assert "By Category" in captured.out
        assert "By Framing Family" in captured.out


class TestCLIContract:
    def test_parser_accepts_input_flag(self):
        parser = build_arg_parser()
        args = parser.parse_args(["--input", "foo.json"])
        assert args.input == Path("foo.json")

    def test_parser_accepts_output_dir_flag(self):
        parser = build_arg_parser()
        args = parser.parse_args(["--output-dir", "out/x"])
        assert args.output_dir == Path("out/x")

    def test_main_returns_two_when_input_missing(self, tmp_path, capsys):
        missing = tmp_path / "does_not_exist.json"
        out_dir = tmp_path / "out"
        exit_code = main([
            "--input", str(missing),
            "--output-dir", str(out_dir),
        ])
        assert exit_code == 2

    def test_main_returns_zero_on_success(self, tmp_path, capsys):
        raw = {
            "results": [_make().to_dict()],
        }
        input_path = tmp_path / "raw.json"
        input_path.write_text(json.dumps(raw), encoding="utf-8")
        out_dir = tmp_path / "out"
        exit_code = main([
            "--input", str(input_path),
            "--output-dir", str(out_dir),
        ])
        assert exit_code == 0
        assert (out_dir / "per_strategy.csv").exists()
        assert (out_dir / "summary.md").exists()


# =============================================================================
# AggregateRow
# =============================================================================


class TestAggregateRowFrozen:
    def test_aggregate_row_is_frozen(self):
        row = AggregateRow(
            label="severity",
            n=3,
            detection_rate=0.33,
            verdict_accuracy=0.66,
            mean_taint_score=0.5,
        )
        with pytest.raises(Exception):
            row.n = 99  # type: ignore[misc]
