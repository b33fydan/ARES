"""ARES Multi-Turn Benchmark Runner Script — execute and save multi-turn results.

Runs the 12-scenario benchmark corpus through multi-turn LLM-powered
dialectical debate, saves results as JSON for cross-session comparison,
and generates formatted reports with optional comparison against a
single-turn baseline.

Usage:
    python -m ares.dialectic.scripts.run_multi_turn_llm_benchmark
    python -m ares.dialectic.scripts.run_multi_turn_llm_benchmark --max-rounds 5
    python -m ares.dialectic.scripts.run_multi_turn_llm_benchmark --compare-single-turn benchmark_results/llm_v2.json

Arguments:
    --max-rounds          : Maximum debate rounds per scenario (default 3)
    --confidence-delta    : Confidence stabilization threshold (default 0.05)
    --run-name            : Descriptive name for this run (default: multi_turn_v1)
    --output-dir          : Directory for results (default: benchmark_results/)
    --compare-single-turn : Path to single-turn JSON for comparison report
    --no-new-evidence     : Disable require_new_evidence termination (default: enabled)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Optional


def serialize_multi_turn_run(run: Any) -> dict:
    """Serialize a MultiTurnBenchmarkRun to a JSON-compatible dict.

    Handles tuple → list and frozen types for JSON serialization.

    Args:
        run: A MultiTurnBenchmarkRun frozen dataclass instance.

    Returns:
        Dictionary suitable for ``json.dump()``.
    """
    return {
        "run_id": run.run_id,
        "timestamp": run.timestamp,
        "strategy_type": run.strategy_type,
        "max_rounds": run.max_rounds,
        "confidence_delta": run.confidence_delta,
        "require_new_evidence": run.require_new_evidence,
        "scenario_count": run.scenario_count,
        "total_cost_usd": run.total_cost_usd,
        "total_duration_ms": run.total_duration_ms,
        "match_rate": run.match_rate,
        "avg_rounds_used": run.avg_rounds_used,
        "results": [
            {
                "scenario_id": r.scenario_id,
                "scenario_name": r.scenario_name,
                "expected_verdict": r.expected_verdict,
                "verdict_outcome": r.verdict_outcome,
                "verdict_confidence": r.verdict_confidence,
                "architect_confidence": r.architect_confidence,
                "skeptic_confidence": r.skeptic_confidence,
                "coverage": r.coverage,
                "narrator_output": r.narrator_output,
                "duration_ms": r.duration_ms,
                "rounds_used": r.rounds_used,
                "max_rounds_configured": r.max_rounds_configured,
                "termination_reason": r.termination_reason,
                "round_snapshots": [
                    {
                        "round_number": s.round_number,
                        "architect_confidence": s.architect_confidence,
                        "skeptic_confidence": s.skeptic_confidence,
                        "architect_new_fact_count": s.architect_new_fact_count,
                        "skeptic_new_fact_count": s.skeptic_new_fact_count,
                        "architect_assertion_count": s.architect_assertion_count,
                        "skeptic_assertion_count": s.skeptic_assertion_count,
                    }
                    for s in r.round_snapshots
                ],
                "validation_errors": r.validation_errors,
                "fallback_triggers": r.fallback_triggers,
                "token_usage": r.token_usage,
                "cost_usd": r.cost_usd,
            }
            for r in run.results
        ],
    }


def main(argv: Optional[list] = None) -> Any:
    """Run the ARES multi-turn benchmark and save results.

    Args:
        argv: Command-line arguments (defaults to sys.argv[1:]).

    Returns:
        The MultiTurnBenchmarkRun instance.
    """
    parser = argparse.ArgumentParser(
        description="ARES Multi-Turn Benchmark Runner"
    )
    parser.add_argument(
        "--max-rounds",
        type=int,
        default=3,
        help="Maximum debate rounds per scenario (default: 3)",
    )
    parser.add_argument(
        "--confidence-delta",
        type=float,
        default=0.05,
        help="Confidence stabilization threshold (default: 0.05)",
    )
    parser.add_argument(
        "--run-name",
        default="multi_turn_v1",
        help="Descriptive name for this run (default: multi_turn_v1)",
    )
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Output directory for results",
    )
    parser.add_argument(
        "--compare-single-turn",
        default=None,
        help="Path to single-turn benchmark JSON for comparison report",
    )
    parser.add_argument(
        "--no-new-evidence",
        action="store_true",
        help="Disable require_new_evidence termination condition",
    )
    parser.add_argument(
        "--strategy",
        choices=["llm", "multi_turn_llm"],
        default="multi_turn_llm",
        help="Strategy type: 'multi_turn_llm' (round-aware, default) or 'llm' (non-round-aware)",
    )
    args = parser.parse_args(argv)

    # Determine output directory
    if args.output_dir:
        output_dir = Path(args.output_dir)
    else:
        output_dir = Path(__file__).parent / "benchmark_results"
    output_dir.mkdir(parents=True, exist_ok=True)

    # Import after argument parsing (faster startup for --help)
    from ares.dialectic.scripts.scenario_corpus import get_all_scenarios
    from ares.dialectic.scripts.multi_turn_benchmark import run_multi_turn_benchmark
    from ares.dialectic.scripts.multi_turn_benchmark_report import (
        generate_multi_turn_report,
        generate_comparison_report,
    )
    from ares.dialectic.agents.strategies.client import AnthropicClient
    from ares.dialectic.agents.strategies.observability import LLMCallLogger

    scenarios = get_all_scenarios()
    print(
        f"ARES Multi-Turn Benchmark: {len(scenarios)} scenarios, "
        f"max_rounds={args.max_rounds}"
    )
    print(f"Output: {output_dir}")

    # Set up client
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("ERROR: ANTHROPIC_API_KEY environment variable not set.")
        sys.exit(1)
    client = AnthropicClient(api_key=api_key)
    call_logger = LLMCallLogger()

    # Build strategy factories based on --strategy flag
    strategy_factories: dict = {}
    if args.strategy == "multi_turn_llm":
        from ares.dialectic.agents.strategies.multi_turn_strategies import (
            MultiTurnLLMExplanationFinder,
            MultiTurnLLMNarrativeGenerator,
            MultiTurnLLMThreatAnalyzer,
        )
        strategy_factories["threat_analyzer_factory"] = (
            lambda: MultiTurnLLMThreatAnalyzer(client, call_logger=call_logger)
        )
        strategy_factories["explanation_finder_factory"] = (
            lambda: MultiTurnLLMExplanationFinder(client, call_logger=call_logger)
        )
        strategy_factories["narrative_generator_factory"] = (
            lambda: MultiTurnLLMNarrativeGenerator(client, call_logger=call_logger)
        )
        print(f"Strategy: multi_turn_llm (round-aware)")
    else:
        # Default LLM strategies (no factories — benchmark creates them)
        print(f"Strategy: llm (non-round-aware)")

    # Run benchmark
    print(f"\nRunning multi-turn benchmark (max_rounds={args.max_rounds})...")
    run = run_multi_turn_benchmark(
        scenarios=scenarios,
        client=client,
        call_logger=call_logger,
        max_rounds=args.max_rounds,
        confidence_delta=args.confidence_delta,
        require_new_evidence=not args.no_new_evidence,
        **strategy_factories,
    )

    # Save results as JSON
    results_json = serialize_multi_turn_run(run)
    json_path = output_dir / f"{args.run_name}.json"
    with open(json_path, "w") as f:
        json.dump(results_json, f, indent=2, default=str)
    print(f"Results saved: {json_path}")

    # Generate and save report
    report = generate_multi_turn_report(run)
    report_path = output_dir / f"{args.run_name}_report.txt"
    with open(report_path, "w") as f:
        f.write(report)
    print(f"Report saved: {report_path}")

    # Generate comparison report if single-turn baseline provided
    if args.compare_single_turn:
        st_json_path = Path(args.compare_single_turn)
        if not st_json_path.is_absolute():
            st_json_path = output_dir / st_json_path
        if st_json_path.exists():
            from ares.dialectic.scripts.run_llm_benchmark import (
                deserialize_benchmark_run,
            )

            st_run = deserialize_benchmark_run(st_json_path)
            comparison = generate_comparison_report(st_run, run)
            comp_path = output_dir / f"{args.run_name}_vs_single_turn_report.txt"
            with open(comp_path, "w") as f:
                f.write(comparison)
            print(f"Comparison report saved: {comp_path}")
        else:
            print(f"WARNING: Single-turn baseline not found: {st_json_path}")

    # Print summary to console
    print(f"\n{'=' * 60}")
    print(report)

    return run


if __name__ == "__main__":
    main()
