"""Benchmark report generator — formatted ASCII output.

Produces a human-readable report from a BenchmarkRun, with optional
delta analysis against a baseline run.

Public API:
    generate_report() -> str
"""

from __future__ import annotations

from typing import Dict, Optional, Sequence, Union

from ares.dialectic.scripts.benchmark_runner import BenchmarkRun, ScenarioResult
from ares.dialectic.scripts.scenario_corpus import BenchmarkScenario


def generate_report(
    run: BenchmarkRun,
    scenarios: Union[list[BenchmarkScenario], tuple[BenchmarkScenario, ...]],
    baseline_run: Optional[BenchmarkRun] = None,
) -> str:
    """Generate a formatted benchmark report as a string.

    Args:
        run: The benchmark run to report on.
        scenarios: The scenarios that were run (for metadata access).
        baseline_run: Optional baseline run for delta comparison.

    Returns:
        Formatted report string (clean ASCII, no Markdown, no ANSI colors).
    """
    metadata_map: Dict[str, BenchmarkScenario] = {
        s.metadata.scenario_id: s for s in scenarios
    }
    result_map: Dict[str, ScenarioResult] = {
        r.scenario_id: r for r in run.results
    }
    baseline_map: Dict[str, ScenarioResult] = {}
    if baseline_run is not None:
        baseline_map = {r.scenario_id: r for r in baseline_run.results}

    lines: list[str] = []

    # --- Header ---
    lines.append("=" * 78)
    lines.append("ARES BENCHMARK REPORT")
    lines.append("=" * 78)
    lines.append(f"Run ID:         {run.run_id}")
    lines.append(f"Timestamp:      {run.timestamp.isoformat()}")
    lines.append(f"Strategy:       {run.strategy_type}")
    lines.append(f"Scenarios:      {run.scenario_count}")
    lines.append(f"Total duration: {run.total_duration_ms} ms")
    if run.total_cost_usd is not None:
        lines.append(f"Total cost:     ${run.total_cost_usd:.6f}")
    lines.append("")

    # --- Summary Table ---
    lines.append("-" * 78)
    lines.append("SCENARIO SUMMARY")
    lines.append("-" * 78)
    header = (
        f"{'ID':<8} {'Name':<30} {'Tier':>4} "
        f"{'Expected':<18} {'Actual':<18} {'Match':>5} "
        f"{'Conf':>5} {'Cov':>5}"
    )
    lines.append(header)
    lines.append("-" * 78)

    match_count = 0
    total_confidence = 0.0
    total_coverage = 0.0

    for result in run.results:
        scenario = metadata_map.get(result.scenario_id)
        name = scenario.metadata.name[:30] if scenario else "Unknown"
        tier = scenario.metadata.difficulty_tier if scenario else 0
        expected = scenario.metadata.expected_verdict if scenario else "?"

        actual = result.verdict_outcome
        match = _verdict_matches(expected, actual)
        if match:
            match_count += 1
        match_str = "Y" if match else "N"

        total_confidence += result.verdict_confidence
        total_coverage += result.fact_coverage_ratio

        row = (
            f"{result.scenario_id:<8} {name:<30} {tier:>4} "
            f"{expected:<18} {actual:<18} {match_str:>5} "
            f"{result.verdict_confidence:>5.2f} {result.fact_coverage_ratio:>5.2f}"
        )
        lines.append(row)

    lines.append("-" * 78)
    lines.append("")

    # --- Aggregate Metrics ---
    n = len(run.results) or 1
    lines.append("-" * 78)
    lines.append("AGGREGATE METRICS")
    lines.append("-" * 78)
    lines.append(f"Verdict match rate:     {match_count}/{len(run.results)} "
                 f"({match_count / n * 100:.1f}%)")
    lines.append(f"Average confidence:     {total_confidence / n:.3f}")
    lines.append(f"Average fact coverage:  {total_coverage / n:.3f}")
    lines.append(f"Total duration:         {run.total_duration_ms} ms")
    if run.total_cost_usd is not None:
        lines.append(f"Total cost (USD):       ${run.total_cost_usd:.6f}")
    lines.append("")

    # --- Verdict Distribution ---
    lines.append("-" * 78)
    lines.append("VERDICT DISTRIBUTION")
    lines.append("-" * 78)
    dist: Dict[str, int] = {}
    for result in run.results:
        dist[result.verdict_outcome] = dist.get(result.verdict_outcome, 0) + 1
    for outcome in ("threat_confirmed", "threat_dismissed", "inconclusive"):
        count = dist.get(outcome, 0)
        lines.append(f"  {outcome:<22} {count}")
    lines.append("")

    # --- Anomaly Flags ---
    mismatches: list[str] = []
    for result in run.results:
        scenario = metadata_map.get(result.scenario_id)
        if scenario and not _verdict_matches(
            scenario.metadata.expected_verdict, result.verdict_outcome
        ):
            mismatches.append(
                f"  {result.scenario_id}: expected {scenario.metadata.expected_verdict}, "
                f"got {result.verdict_outcome}"
            )

    lines.append("-" * 78)
    lines.append("ANOMALY FLAGS (expected != actual)")
    lines.append("-" * 78)
    if mismatches:
        lines.extend(mismatches)
    else:
        lines.append("  None — all verdicts match expectations")
    lines.append("")

    # --- Delta Analysis ---
    if baseline_run is not None:
        lines.append("-" * 78)
        lines.append("DELTA ANALYSIS (baseline -> current)")
        lines.append("-" * 78)
        delta_header = (
            f"{'ID':<8} {'Base Verdict':<18} {'Base Conf':>9} "
            f"{'Curr Verdict':<18} {'Curr Conf':>9} {'Delta':>7}"
        )
        lines.append(delta_header)
        lines.append("-" * 78)

        for result in run.results:
            baseline = baseline_map.get(result.scenario_id)
            if baseline is None:
                lines.append(f"{result.scenario_id:<8} {'(no baseline)':<18}")
                continue

            delta = result.verdict_confidence - baseline.verdict_confidence
            delta_str = f"{delta:+.3f}"

            row = (
                f"{result.scenario_id:<8} "
                f"{baseline.verdict_outcome:<18} {baseline.verdict_confidence:>9.3f} "
                f"{result.verdict_outcome:<18} {result.verdict_confidence:>9.3f} "
                f"{delta_str:>7}"
            )
            lines.append(row)

        lines.append("-" * 78)
        lines.append("")

    lines.append("=" * 78)
    lines.append("END OF REPORT")
    lines.append("=" * 78)

    return "\n".join(lines)


def _verdict_matches(expected: str, actual: str) -> bool:
    """Check if expected verdict matches actual (case-insensitive)."""
    return expected.lower() == actual.lower()
