"""Multi-turn benchmark report generator — formatted ASCII output.

Produces human-readable reports from MultiTurnBenchmarkRun results,
with optional comparison against a single-turn BenchmarkRun baseline
to measure whether iterative debate improves verdict accuracy.

Public API:
    generate_multi_turn_report() -> str
    generate_comparison_report() -> str
"""

from __future__ import annotations

from typing import Dict, Optional

from ares.dialectic.scripts.multi_turn_benchmark import (
    MultiTurnBenchmarkRun,
    MultiTurnScenarioResult,
)


def generate_multi_turn_report(run: MultiTurnBenchmarkRun) -> str:
    """Generate a formatted report for a multi-turn benchmark run.

    Similar to benchmark_report.generate_report() but includes:
    - Per-scenario round count and termination reason
    - Average rounds used across all scenarios
    - Round snapshot evolution for each scenario

    Args:
        run: The multi-turn benchmark run to report on.

    Returns:
        Formatted report string (clean ASCII, no Markdown, no ANSI colors).
    """
    lines: list = []

    # --- Header ---
    lines.append("=" * 90)
    lines.append("ARES MULTI-TURN BENCHMARK REPORT")
    lines.append("=" * 90)
    lines.append(f"Run ID:             {run.run_id}")
    lines.append(f"Timestamp:          {run.timestamp}")
    lines.append(f"Strategy:           {run.strategy_type}")
    lines.append(f"Max Rounds:         {run.max_rounds}")
    lines.append(f"Confidence Delta:   {run.confidence_delta}")
    lines.append(f"Require New Evid:   {run.require_new_evidence}")
    lines.append(f"Scenarios:          {run.scenario_count}")
    lines.append(f"Total duration:     {run.total_duration_ms} ms")
    lines.append(f"Total cost:         ${run.total_cost_usd:.6f}")
    lines.append("")

    # --- Summary Table ---
    lines.append("-" * 90)
    lines.append("SCENARIO SUMMARY")
    lines.append("-" * 90)
    header = (
        f"{'ID':<8} {'Name':<25} {'Expected':<18} {'Actual':<18} "
        f"{'Match':>5} {'Conf':>5} {'Rnds':>4} {'Termination':<20}"
    )
    lines.append(header)
    lines.append("-" * 90)

    match_count = 0
    total_confidence = 0.0
    total_coverage = 0.0

    for result in run.results:
        name = result.scenario_name[:25]
        match = result.verdict_matches
        if match:
            match_count += 1
        match_str = "Y" if match else "N"

        total_confidence += result.verdict_confidence
        total_coverage += result.coverage

        row = (
            f"{result.scenario_id:<8} {name:<25} "
            f"{result.expected_verdict:<18} {result.verdict_outcome:<18} "
            f"{match_str:>5} {result.verdict_confidence:>5.2f} "
            f"{result.rounds_used:>4} {result.termination_reason:<20}"
        )
        lines.append(row)

    lines.append("-" * 90)
    lines.append("")

    # --- Aggregate Metrics ---
    n = len(run.results) or 1
    lines.append("-" * 90)
    lines.append("AGGREGATE METRICS")
    lines.append("-" * 90)
    lines.append(
        f"Verdict match rate:     {match_count}/{len(run.results)} "
        f"({match_count / n * 100:.1f}%)"
    )
    lines.append(f"Average confidence:     {total_confidence / n:.3f}")
    lines.append(f"Average fact coverage:  {total_coverage / n:.3f}")
    lines.append(f"Average rounds used:    {run.avg_rounds_used:.1f}")
    lines.append(f"Total duration:         {run.total_duration_ms} ms")
    lines.append(f"Total cost (USD):       ${run.total_cost_usd:.6f}")
    cost_per_scenario = run.total_cost_usd / n if n > 0 else 0.0
    lines.append(f"Cost per scenario:      ${cost_per_scenario:.6f}")
    lines.append("")

    # --- Termination Distribution ---
    lines.append("-" * 90)
    lines.append("TERMINATION REASON DISTRIBUTION")
    lines.append("-" * 90)
    term_dist: Dict[str, int] = {}
    for result in run.results:
        term_dist[result.termination_reason] = (
            term_dist.get(result.termination_reason, 0) + 1
        )
    for reason, count in sorted(term_dist.items()):
        lines.append(f"  {reason:<30} {count}")
    lines.append("")

    # --- Round Snapshot Evolution ---
    lines.append("-" * 90)
    lines.append("ROUND SNAPSHOT EVOLUTION")
    lines.append("-" * 90)
    for result in run.results:
        if not result.round_snapshots:
            lines.append(f"  {result.scenario_id}: (no snapshots — ERROR)")
            continue
        lines.append(f"  {result.scenario_id} ({result.scenario_name[:30]}):")
        for snap in result.round_snapshots:
            lines.append(
                f"    Round {snap.round_number}: "
                f"arch_conf={snap.architect_confidence:.2f} "
                f"skep_conf={snap.skeptic_confidence:.2f} "
                f"new_facts(A={snap.architect_new_fact_count},"
                f"S={snap.skeptic_new_fact_count}) "
                f"assertions(A={snap.architect_assertion_count},"
                f"S={snap.skeptic_assertion_count})"
            )
    lines.append("")

    # --- Anomaly Flags ---
    mismatches: list = []
    for result in run.results:
        if not result.verdict_matches:
            mismatches.append(
                f"  {result.scenario_id}: expected {result.expected_verdict}, "
                f"got {result.verdict_outcome}"
            )

    lines.append("-" * 90)
    lines.append("ANOMALY FLAGS (expected != actual)")
    lines.append("-" * 90)
    if mismatches:
        lines.extend(mismatches)
    else:
        lines.append("  None — all verdicts match expectations")
    lines.append("")

    lines.append("=" * 90)
    lines.append("END OF REPORT")
    lines.append("=" * 90)

    return "\n".join(lines)


def generate_comparison_report(
    single_turn_run: object,
    multi_turn_run: MultiTurnBenchmarkRun,
) -> str:
    """Generate a comparison report: single-turn vs multi-turn.

    Shows per-scenario verdict changes, confidence deltas, round counts,
    and aggregate cost/accuracy comparisons.

    Args:
        single_turn_run: BenchmarkRun from benchmark_runner (single-turn).
        multi_turn_run: MultiTurnBenchmarkRun from multi_turn_benchmark.

    Returns:
        Formatted comparison report string.
    """
    lines: list = []

    # Build lookup maps
    st_map: Dict[str, object] = {r.scenario_id: r for r in single_turn_run.results}
    mt_map: Dict[str, MultiTurnScenarioResult] = {
        r.scenario_id: r for r in multi_turn_run.results
    }

    # Collect all scenario IDs (union of both runs)
    all_ids = sorted(
        set(st_map.keys()) | set(mt_map.keys()),
        key=lambda x: x,
    )

    # --- Header ---
    lines.append("=" * 100)
    lines.append("SINGLE-TURN vs MULTI-TURN COMPARISON")
    lines.append("=" * 100)

    # Single-turn summary
    st_match_count = sum(
        1 for r in single_turn_run.results
        if _verdict_matches_st(r, single_turn_run)
    )
    st_total = len(single_turn_run.results) or 1
    st_pct = st_match_count / st_total * 100

    # Multi-turn summary
    mt_match_count = multi_turn_run.matches
    mt_total = len(multi_turn_run.results) or 1
    mt_pct = multi_turn_run.match_rate * 100

    lines.append(
        f"Single-turn: {st_match_count}/{len(single_turn_run.results)} "
        f"({st_pct:.1f}% accuracy)"
    )
    lines.append(
        f"Multi-turn:  {mt_match_count}/{len(multi_turn_run.results)} "
        f"({mt_pct:.1f}% accuracy)"
    )
    lines.append("")

    # --- Per-scenario comparison table ---
    lines.append("-" * 100)
    header = (
        f"{'ID':<8} {'ST Verdict':<18} {'MT Verdict':<18} "
        f"{'ST Conf':>7} {'MT Conf':>7} {'Rounds':>6} {'Termination':<20}"
    )
    lines.append(header)
    lines.append("-" * 100)

    for sid in all_ids:
        st_result = st_map.get(sid)
        mt_result = mt_map.get(sid)

        if st_result is None:
            lines.append(f"{sid:<8} {'(not in ST)':<18}")
            continue
        if mt_result is None:
            lines.append(f"{sid:<8} {st_result.verdict_outcome:<18} {'(not in MT)':<18}")
            continue

        st_verdict = st_result.verdict_outcome
        mt_verdict = mt_result.verdict_outcome
        st_conf = st_result.verdict_confidence
        mt_conf = mt_result.verdict_confidence
        rounds = mt_result.rounds_used
        term = mt_result.termination_reason

        row = (
            f"{sid:<8} {st_verdict:<18} {mt_verdict:<18} "
            f"{st_conf:>7.3f} {mt_conf:>7.3f} {rounds:>6} {term:<20}"
        )
        lines.append(row)

    lines.append("-" * 100)
    lines.append("")

    # --- Aggregate Comparison ---
    lines.append("-" * 100)
    lines.append("AGGREGATE COMPARISON")
    lines.append("-" * 100)

    # Match rate delta
    match_delta = mt_pct - st_pct
    lines.append(
        f"Match Rate:       {st_match_count}/{len(single_turn_run.results)} "
        f"({st_pct:.1f}%) -> {mt_match_count}/{len(multi_turn_run.results)} "
        f"({mt_pct:.1f}%)   delta {match_delta:+.1f}%"
    )

    # Avg confidence
    st_avg_conf = (
        sum(r.verdict_confidence for r in single_turn_run.results) / st_total
    )
    mt_avg_conf = (
        sum(r.verdict_confidence for r in multi_turn_run.results) / mt_total
    )
    conf_delta = mt_avg_conf - st_avg_conf
    lines.append(
        f"Avg Confidence:   {st_avg_conf:.3f} -> {mt_avg_conf:.3f}"
        f"   delta {conf_delta:+.3f}"
    )

    # Avg coverage
    st_avg_cov = (
        sum(r.fact_coverage_ratio for r in single_turn_run.results) / st_total
    )
    mt_avg_cov = (
        sum(r.coverage for r in multi_turn_run.results) / mt_total
    )
    cov_delta = mt_avg_cov - st_avg_cov
    lines.append(
        f"Avg Coverage:     {st_avg_cov:.3f} -> {mt_avg_cov:.3f}"
        f"   delta {cov_delta:+.3f}"
    )

    # Avg rounds
    lines.append(f"Avg Rounds:       N/A -> {multi_turn_run.avg_rounds_used:.1f}")

    # Cost comparison
    st_cost = single_turn_run.total_cost_usd or 0.0
    mt_cost = multi_turn_run.total_cost_usd
    cost_delta = mt_cost - st_cost
    lines.append(
        f"Total Cost:       ${st_cost:.4f} -> ${mt_cost:.4f}"
        f"   delta ${cost_delta:+.4f}"
    )

    st_per = st_cost / st_total
    mt_per = mt_cost / mt_total
    lines.append(
        f"Cost/Scenario:    ${st_per:.4f} -> ${mt_per:.4f}"
    )

    lines.append("")
    lines.append("=" * 100)
    lines.append("END OF COMPARISON REPORT")
    lines.append("=" * 100)

    return "\n".join(lines)


def _verdict_matches_st(result: object, run: object) -> bool:
    """Check if a single-turn result matches expected verdict.

    Uses scenario_id convention — looks up expected verdict from the
    result's verdict_outcome against scenario corpus metadata. For
    comparison purposes, we match on the raw verdict_outcome field.

    This is a best-effort matcher for single-turn results which don't
    carry expected_verdict directly. Falls back to checking if the
    scenario corpus has this ID.

    Args:
        result: A ScenarioResult from benchmark_runner.
        run: The BenchmarkRun (unused but available for future).

    Returns:
        True if verdict is not "ERROR" (conservative estimate).
    """
    # Import here to avoid circular dependency
    from ares.dialectic.scripts.scenario_corpus import get_scenario_by_id

    try:
        scenario = get_scenario_by_id(result.scenario_id)
        expected = scenario.metadata.expected_verdict
        return result.verdict_outcome.lower() == expected.lower()
    except (KeyError, ValueError):
        return result.verdict_outcome != "ERROR"
