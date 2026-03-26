"""ARES Full Corpus Benchmark Runner — 33 scenarios, FP/FN/tier analysis.

Session 022: Upgraded benchmark runner that defaults to the full 33-scenario
corpus (get_full_corpus) and integrates benchmark_analysis.py for FP/FN
classification and per-tier accuracy breakdown after each run.

Peer to run_anchored_benchmark.py — does NOT modify it.

Usage:
    python -m ares.dialectic.scripts.run_full_benchmark --mode single-turn
    python -m ares.dialectic.scripts.run_full_benchmark --mode multi-turn-original
    python -m ares.dialectic.scripts.run_full_benchmark --mode multi-turn-anchored
    python -m ares.dialectic.scripts.run_full_benchmark --mode compare-all
    python -m ares.dialectic.scripts.run_full_benchmark --mode compare-all --original-only
    python -m ares.dialectic.scripts.run_full_benchmark --mode compare-all --expanded-only
"""

from __future__ import annotations

import argparse
import os
import sys
import time


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        description="ARES Full Corpus Benchmark — 33-scenario baseline with FP/FN analysis",
    )
    parser.add_argument(
        "--mode",
        choices=[
            "single-turn",
            "multi-turn-original",
            "multi-turn-anchored",
            "compare-all",
        ],
        default="compare-all",
        help="Benchmark mode (default: compare-all)",
    )
    parser.add_argument(
        "--max-rounds",
        type=int,
        default=3,
        help="Max debate rounds for multi-turn (default: 3)",
    )
    parser.add_argument(
        "--confidence-delta",
        type=float,
        default=0.05,
        help="Convergence threshold for multi-turn (default: 0.05)",
    )
    parser.add_argument(
        "--original-only",
        action="store_true",
        help="Run only the original 18 scenarios (SC-001 to SC-018)",
    )
    parser.add_argument(
        "--expanded-only",
        action="store_true",
        help="Run only the 15 expanded scenarios (SC-019 to SC-033)",
    )
    return parser


def _get_scenarios(args: argparse.Namespace) -> list:
    """Select scenario set based on CLI flags."""
    if args.original_only and args.expanded_only:
        print("ERROR: Cannot use --original-only and --expanded-only together")
        sys.exit(1)

    if args.original_only:
        from ares.dialectic.scripts.mixed_source_scenarios import get_combined_corpus
        return list(get_combined_corpus())
    elif args.expanded_only:
        from ares.dialectic.scripts.expanded_scenarios import get_expanded_scenarios
        return list(get_expanded_scenarios())
    else:
        from ares.dialectic.scripts.expanded_scenarios import get_full_corpus
        return list(get_full_corpus())


def _get_client():
    """Create an AnthropicClient for LLM runs.

    Checks ANTHROPIC_API_KEY env var first, then falls back to .env file.
    """
    api_key = os.environ.get("ANTHROPIC_API_KEY")

    if not api_key:
        # Try loading from .env file
        env_path = os.path.join(os.path.dirname(__file__), "..", "..", "..", ".env")
        env_path = os.path.normpath(env_path)
        if os.path.exists(env_path):
            try:
                with open(env_path, "rb") as f:
                    raw = f.read()
                # Handle UTF-16 encoded .env files
                for encoding in ("utf-8", "utf-16"):
                    try:
                        text = raw.decode(encoding)
                        for line in text.splitlines():
                            line = line.strip()
                            if line.startswith("ANTHROPIC_API_KEY="):
                                api_key = line.split("=", 1)[1].strip()
                                break
                        if api_key:
                            break
                    except (UnicodeDecodeError, ValueError):
                        continue
            except OSError:
                pass

    if not api_key:
        print("ERROR: ANTHROPIC_API_KEY not found in environment or .env file")
        sys.exit(1)

    from ares.dialectic.agents.strategies.client import AnthropicClient
    return AnthropicClient(api_key=api_key)


def _run_single_turn(scenarios, client, call_logger):
    """Run single-turn LLM benchmark."""
    from ares.dialectic.scripts.benchmark_runner import run_benchmark

    print("--- Running: Single-Turn LLM ---")
    run = run_benchmark(
        scenarios=scenarios,
        strategy_type="llm",
        include_narration=True,
        client=client,
        call_logger=call_logger,
    )
    return run


def _run_multi_turn_original(scenarios, client, call_logger, args):
    """Run multi-turn with original (unanchored) prompts."""
    from ares.dialectic.scripts.multi_turn_benchmark import run_multi_turn_benchmark
    from ares.dialectic.agents.strategies.multi_turn_strategies import (
        MultiTurnLLMExplanationFinder,
        MultiTurnLLMNarrativeGenerator,
        MultiTurnLLMThreatAnalyzer,
    )

    print(f"--- Running: Multi-Turn ORIGINAL (max_rounds={args.max_rounds}) ---")
    run = run_multi_turn_benchmark(
        scenarios=scenarios,
        client=client,
        call_logger=call_logger,
        max_rounds=args.max_rounds,
        confidence_delta=args.confidence_delta,
        threat_analyzer_factory=lambda: MultiTurnLLMThreatAnalyzer(
            client, call_logger=call_logger
        ),
        explanation_finder_factory=lambda: MultiTurnLLMExplanationFinder(
            client, call_logger=call_logger
        ),
        narrative_generator_factory=lambda: MultiTurnLLMNarrativeGenerator(
            client, call_logger=call_logger
        ),
    )
    return run


def _run_multi_turn_anchored(scenarios, client, call_logger, args):
    """Run multi-turn with anchored prompts."""
    from ares.dialectic.scripts.multi_turn_benchmark import run_multi_turn_benchmark
    from ares.dialectic.agents.strategies.anchored_strategies import (
        AnchoredMultiTurnExplanationFinder,
        AnchoredMultiTurnNarrativeGenerator,
        AnchoredMultiTurnThreatAnalyzer,
    )

    print(f"--- Running: Multi-Turn ANCHORED (max_rounds={args.max_rounds}) ---")
    run = run_multi_turn_benchmark(
        scenarios=scenarios,
        client=client,
        call_logger=call_logger,
        max_rounds=args.max_rounds,
        confidence_delta=args.confidence_delta,
        threat_analyzer_factory=lambda: AnchoredMultiTurnThreatAnalyzer(
            client, call_logger=call_logger
        ),
        explanation_finder_factory=lambda: AnchoredMultiTurnExplanationFinder(
            client, call_logger=call_logger
        ),
        narrative_generator_factory=lambda: AnchoredMultiTurnNarrativeGenerator(
            client, call_logger=call_logger
        ),
    )
    return run


def _print_single_turn_table(label: str, scenarios, run):
    """Print a per-scenario result table for a single-turn run."""
    expected_by_id = {s.metadata.scenario_id: s.metadata.expected_verdict for s in scenarios}

    print(f"\n{'=' * 70}")
    print(f"  {label}")
    print(f"{'=' * 70}")
    print(f"{'Scenario':<10} {'Expected':<18} {'Actual':<18} {'Match':<6} {'Arch':>5} {'Skep':>5}")
    print("-" * 68)

    for r in run.results:
        expected = expected_by_id.get(r.scenario_id, "???")
        match = "Y" if r.verdict_outcome.lower() == expected.lower() else "X"
        print(
            f"{r.scenario_id:<10} {expected:<18} "
            f"{r.verdict_outcome:<18} {match:<6} "
            f"{r.architect_confidence:>5.2f} {r.skeptic_confidence:>5.2f}"
        )

    matches = sum(
        1 for r in run.results
        if r.verdict_outcome.lower() == expected_by_id.get(r.scenario_id, "").lower()
    )
    total = len(run.results)
    print(f"\nACCURACY: {matches}/{total} ({matches / total * 100:.1f}%)")
    cost = getattr(run, "total_cost_usd", None)
    if cost is not None:
        print(f"COST: ${cost:.4f}")


def _print_multi_turn_table(label: str, scenarios, run):
    """Print a per-scenario result table for a multi-turn run."""
    print(f"\n{'=' * 85}")
    print(f"  {label}")
    print(f"{'=' * 85}")
    print(
        f"{'Scenario':<10} {'Expected':<18} {'Actual':<18} {'Match':<6} "
        f"{'Arch':>5} {'Skep':>5} {'Rnds':>4} {'Term':<20}"
    )
    print("-" * 85)

    for r in run.results:
        match = "Y" if r.verdict_matches else "X"
        print(
            f"{r.scenario_id:<10} {r.expected_verdict:<18} "
            f"{r.verdict_outcome:<18} {match:<6} "
            f"{r.architect_confidence:>5.2f} {r.skeptic_confidence:>5.2f} "
            f"{r.rounds_used:>4} {r.termination_reason:<20}"
        )

    total = len(run.results)
    print(f"\nACCURACY: {run.matches}/{total} ({run.match_rate * 100:.1f}%)")
    print(f"AVG ROUNDS: {run.avg_rounds_used:.1f}")
    print(f"COST: ${run.total_cost_usd:.4f}")


def _print_analysis(label: str, scenarios, results):
    """Print FP/FN/tier analysis using benchmark_analysis.py."""
    from ares.dialectic.scripts.benchmark_analysis import (
        analyze_benchmark_errors,
        compute_tier_accuracy,
        format_analysis_report,
    )

    classifications = analyze_benchmark_errors(scenarios, results)
    tier_accuracy = compute_tier_accuracy(scenarios, classifications)
    report = format_analysis_report(label, classifications, tier_accuracy)
    print(report)


def _print_comparison_table(scenarios, st_run, orig_run, anch_run):
    """Print a side-by-side comparison of all three runs."""
    expected_by_id = {s.metadata.scenario_id: s.metadata.expected_verdict for s in scenarios}

    print(f"\n{'=' * 90}")
    print("  COMPARISON: Single-Turn vs Multi-Turn (Original) vs Multi-Turn (Anchored)")
    print(f"{'=' * 90}")
    print(
        f"{'Scenario':<10} {'Expected':<18} "
        f"{'Single':>8} {'Orig MT':>8} {'Anch MT':>8}"
    )
    print("-" * 60)

    st_results = {r.scenario_id: r for r in st_run.results}
    orig_results = {r.scenario_id: r for r in orig_run.results}
    anch_results = {r.scenario_id: r for r in anch_run.results}

    for s in scenarios:
        sid = s.metadata.scenario_id
        expected = s.metadata.expected_verdict

        st_r = st_results.get(sid)
        orig_r = orig_results.get(sid)
        anch_r = anch_results.get(sid)

        def _fmt(result, is_st=False, _expected=expected):
            if result is None:
                return "   --   "
            if is_st:
                actual = result.verdict_outcome
                match = actual.lower() == _expected.lower()
            else:
                actual = result.verdict_outcome
                match = result.verdict_matches
            symbol = "Y" if match else "X"
            return f"{actual[:6]:>6} {symbol}"

        print(
            f"{sid:<10} {expected:<18} "
            f"{_fmt(st_r, True):>8} {_fmt(orig_r):>8} {_fmt(anch_r):>8}"
        )

    # Summary row
    def _accuracy(run, is_st=False):
        if is_st:
            m = sum(
                1 for r in run.results
                if r.verdict_outcome.lower() == expected_by_id.get(r.scenario_id, "").lower()
            )
        else:
            m = run.matches
        t = len(run.results)
        return f"{m}/{t} ({m / t * 100:.0f}%)"

    print("-" * 60)
    print(
        f"{'ACCURACY':<10} {'':<18} "
        f"{_accuracy(st_run, True):>8} {_accuracy(orig_run):>8} {_accuracy(anch_run):>8}"
    )

    st_cost = getattr(st_run, "total_cost_usd", None) or 0
    print(
        f"{'COST':<10} {'':<18} "
        f"{'${:.3f}'.format(st_cost):>8} "
        f"{'${:.3f}'.format(orig_run.total_cost_usd):>8} "
        f"{'${:.3f}'.format(anch_run.total_cost_usd):>8}"
    )


def main() -> None:
    """Run the full corpus benchmark with FP/FN analysis."""
    parser = build_parser()
    args = parser.parse_args()

    scenarios = _get_scenarios(args)
    total = len(scenarios)
    label = (
        "original (18)" if args.original_only
        else "expanded (15)" if args.expanded_only
        else f"full corpus ({total})"
    )

    print(f"=== ARES FULL CORPUS BENCHMARK ({total} scenarios, {label}) ===")
    print(f"Mode: {args.mode}")
    print()

    client = _get_client()
    from ares.dialectic.agents.strategies.observability import LLMCallLogger
    call_logger = LLMCallLogger()

    start_time = time.perf_counter()

    if args.mode == "single-turn":
        run = _run_single_turn(scenarios, client, call_logger)
        _print_single_turn_table("Single-Turn LLM", scenarios, run)
        _print_analysis("Single-Turn LLM", scenarios, run.results)

    elif args.mode == "multi-turn-original":
        run = _run_multi_turn_original(scenarios, client, call_logger, args)
        _print_multi_turn_table("Multi-Turn ORIGINAL", scenarios, run)
        _print_analysis("Multi-Turn ORIGINAL", scenarios, run.results)

    elif args.mode == "multi-turn-anchored":
        run = _run_multi_turn_anchored(scenarios, client, call_logger, args)
        _print_multi_turn_table("Multi-Turn ANCHORED", scenarios, run)
        _print_analysis("Multi-Turn ANCHORED", scenarios, run.results)

    elif args.mode == "compare-all":
        st_run = _run_single_turn(scenarios, client, call_logger)
        _print_single_turn_table("Single-Turn LLM", scenarios, st_run)
        _print_analysis("Single-Turn LLM", scenarios, st_run.results)

        orig_run = _run_multi_turn_original(scenarios, client, call_logger, args)
        _print_multi_turn_table("Multi-Turn ORIGINAL", scenarios, orig_run)
        _print_analysis("Multi-Turn ORIGINAL", scenarios, orig_run.results)

        anch_run = _run_multi_turn_anchored(scenarios, client, call_logger, args)
        _print_multi_turn_table("Multi-Turn ANCHORED", scenarios, anch_run)
        _print_analysis("Multi-Turn ANCHORED", scenarios, anch_run.results)

        _print_comparison_table(scenarios, st_run, orig_run, anch_run)

    elapsed = time.perf_counter() - start_time
    print(f"\n=== BENCHMARK COMPLETE ({elapsed:.1f}s total) ===")


if __name__ == "__main__":
    main()
