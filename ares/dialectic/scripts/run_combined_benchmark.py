"""ARES Combined Benchmark Runner — single-turn and multi-turn across all 18 scenarios.

Runs the combined 18-scenario corpus (original 12 + 6 mixed-source) through
rule-based or LLM strategy paths. Supports filtering by scenario set and
optional multi-turn comparison.

Usage:
    # Rule-based benchmark (all 18 scenarios)
    python -m ares.dialectic.scripts.run_combined_benchmark --strategy rule_based

    # Rule-based benchmark (mixed-source only)
    python -m ares.dialectic.scripts.run_combined_benchmark --strategy rule_based --mixed-only

    # Rule-based benchmark (original 12 only — regression check)
    python -m ares.dialectic.scripts.run_combined_benchmark --strategy rule_based --original-only

    # LLM single-turn benchmark (all 18)
    python -m ares.dialectic.scripts.run_combined_benchmark --strategy llm

    # LLM single-turn + multi-turn comparison (all 18)
    python -m ares.dialectic.scripts.run_combined_benchmark --strategy llm --compare-multi-turn --max-rounds 3

    # LLM multi-turn only (mixed-source scenarios)
    python -m ares.dialectic.scripts.run_combined_benchmark --strategy llm --multi-turn-only --mixed-only --max-rounds 3
"""

from __future__ import annotations

import argparse
import os
import sys


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser.

    Returns:
        Configured ArgumentParser instance.
    """
    parser = argparse.ArgumentParser(
        description="ARES Combined Benchmark Runner — 18 scenarios across 3 telemetry sources",
    )
    parser.add_argument(
        "--strategy",
        choices=["rule_based", "llm"],
        default="rule_based",
        help="Strategy type: rule_based (default) or llm",
    )
    parser.add_argument(
        "--mixed-only",
        action="store_true",
        help="Run only the 6 mixed-source scenarios (SC-013 to SC-018)",
    )
    parser.add_argument(
        "--original-only",
        action="store_true",
        help="Run only the original 12 scenarios (SC-001 to SC-012)",
    )
    parser.add_argument(
        "--compare-multi-turn",
        action="store_true",
        help="Also run multi-turn benchmark and compare against single-turn",
    )
    parser.add_argument(
        "--multi-turn-only",
        action="store_true",
        help="Run multi-turn only (skip single-turn)",
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
        "--run-name",
        type=str,
        default="combined_v1",
        help="Descriptive name for this run (default: combined_v1)",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default=None,
        help="Directory for results files (default: benchmark_results/)",
    )
    return parser


def _select_scenarios(args: argparse.Namespace) -> list:
    """Select scenario set based on CLI flags.

    Args:
        args: Parsed CLI arguments.

    Returns:
        List of BenchmarkScenario instances.

    Raises:
        ValueError: If conflicting flags are set.
    """
    if args.mixed_only and args.original_only:
        raise ValueError("Cannot use --mixed-only and --original-only together")

    if args.mixed_only:
        from ares.dialectic.scripts.mixed_source_scenarios import (
            get_mixed_source_scenarios,
        )
        return list(get_mixed_source_scenarios())
    elif args.original_only:
        from ares.dialectic.scripts.scenario_corpus import get_all_scenarios
        return list(get_all_scenarios())
    else:
        from ares.dialectic.scripts.mixed_source_scenarios import get_combined_corpus
        return list(get_combined_corpus())


def _get_client():
    """Create an AnthropicClient for LLM runs.

    Returns:
        AnthropicClient instance.

    Raises:
        SystemExit: If ANTHROPIC_API_KEY is not set.
    """
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("ERROR: ANTHROPIC_API_KEY environment variable required for LLM strategy")
        sys.exit(1)

    from ares.dialectic.agents.strategies.client import AnthropicClient
    return AnthropicClient(api_key=api_key)


def main() -> None:
    """Run the combined benchmark."""
    parser = build_parser()
    args = parser.parse_args()

    # Select scenarios
    try:
        scenarios = _select_scenarios(args)
    except ValueError as e:
        print(f"ERROR: {e}")
        sys.exit(1)

    label = "mixed-source" if args.mixed_only else "original" if args.original_only else "combined"
    print(f"=== ARES {label.upper()} BENCHMARK ({len(scenarios)} scenarios) ===")
    print(f"Strategy: {args.strategy}")
    print()

    # Lazy imports to avoid hard dependency on LLM libraries for rule-based runs
    from ares.dialectic.scripts.benchmark_runner import run_benchmark
    from ares.dialectic.scripts.benchmark_report import generate_report

    client = None
    call_logger = None

    if args.strategy == "llm":
        client = _get_client()
        from ares.dialectic.agents.strategies.observability import LLMCallLogger
        call_logger = LLMCallLogger()

    # --- Single-turn run ---
    single_turn_run = None
    if not args.multi_turn_only:
        print(f"--- Single-turn ({args.strategy}) ---")
        single_turn_run = run_benchmark(
            scenarios=scenarios,
            strategy_type=args.strategy,
            include_narration=True,
            client=client,
            call_logger=call_logger,
        )

        # Import scenarios tuple for report generation
        report = generate_report(single_turn_run, scenarios)
        print(report)
        print()

    # --- Multi-turn run ---
    if args.compare_multi_turn or args.multi_turn_only:
        if args.strategy != "llm":
            print("WARNING: Multi-turn requires LLM strategy. Skipping multi-turn.")
        else:
            from ares.dialectic.scripts.multi_turn_benchmark import (
                run_multi_turn_benchmark,
            )
            from ares.dialectic.scripts.multi_turn_benchmark_report import (
                generate_multi_turn_report,
                generate_comparison_report,
            )

            print(f"--- Multi-turn (max_rounds={args.max_rounds}, delta={args.confidence_delta}) ---")
            multi_turn_run = run_multi_turn_benchmark(
                scenarios=scenarios,
                client=client,
                call_logger=call_logger,
                max_rounds=args.max_rounds,
                confidence_delta=args.confidence_delta,
            )

            mt_report = generate_multi_turn_report(multi_turn_run)
            print(mt_report)

            if single_turn_run is not None:
                comparison = generate_comparison_report(single_turn_run, multi_turn_run)
                print(comparison)

    print("=== BENCHMARK COMPLETE ===")


if __name__ == "__main__":
    main()
