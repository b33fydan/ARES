"""ARES Benchmark Runner Script — execute and save benchmark results.

Runs the 12-scenario benchmark corpus through rule-based or LLM strategy
paths, saves results as JSON for cross-session comparison, and generates
formatted reports with optional delta analysis against a baseline run.

Usage:
    python -m ares.dialectic.scripts.run_llm_benchmark --strategy rule_based --run-name baseline
    python -m ares.dialectic.scripts.run_llm_benchmark --strategy llm --run-name llm_v1
    python -m ares.dialectic.scripts.run_llm_benchmark --strategy llm --run-name llm_v2 --baseline llm_v1

Arguments:
    --strategy    : "rule_based" or "llm"
    --run-name    : Descriptive name for this run (used in filenames)
    --output-dir  : Directory for results (default: ares/dialectic/scripts/benchmark_results/)
    --baseline    : Optional run-name of a previous run to generate delta report against
    --no-narration: Skip narrator output (faster, cheaper)

Known limitations:
    - benchmark_runner.run_benchmark() does not pass call_logger to LLM
      strategy constructors, so LLMCallRecord observability data is not
      captured.  The validation_errors and fallback_triggers fields on
      ScenarioResult are hardcoded to 0 for all runs.
    - benchmark_runner.run_benchmark() does not catch per-scenario
      exceptions — a single scenario failure crashes the entire run.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Optional


def serialize_benchmark_run(run: Any) -> dict:
    """Serialize a BenchmarkRun to a JSON-compatible dict.

    Handles frozenset → sorted list and datetime → ISO format conversions.

    Args:
        run: A BenchmarkRun frozen dataclass instance.

    Returns:
        Dictionary suitable for ``json.dump()``.
    """
    return {
        "run_id": run.run_id,
        "timestamp": run.timestamp.isoformat(),
        "strategy_type": run.strategy_type,
        "scenario_count": run.scenario_count,
        "total_duration_ms": run.total_duration_ms,
        "total_cost_usd": run.total_cost_usd,
        "results": [
            {
                "scenario_id": r.scenario_id,
                "strategy_type": r.strategy_type,
                "verdict_outcome": r.verdict_outcome,
                "verdict_confidence": r.verdict_confidence,
                "architect_confidence": r.architect_confidence,
                "skeptic_confidence": r.skeptic_confidence,
                "architect_assertion_count": r.architect_assertion_count,
                "skeptic_assertion_count": r.skeptic_assertion_count,
                "architect_fact_ids_cited": sorted(r.architect_fact_ids_cited),
                "skeptic_fact_ids_cited": sorted(r.skeptic_fact_ids_cited),
                "total_facts_available": r.total_facts_available,
                "fact_coverage_ratio": r.fact_coverage_ratio,
                "validation_errors": r.validation_errors,
                "fallback_triggers": r.fallback_triggers,
                "duration_ms": r.duration_ms,
                "token_usage": r.token_usage,
                "cost_usd": r.cost_usd,
                "narrator_output": r.narrator_output,
            }
            for r in run.results
        ],
    }


def deserialize_benchmark_run(json_path: Path) -> Any:
    """Deserialize a BenchmarkRun from a JSON file.

    Restores frozenset fields and datetime from their serialized forms.

    Args:
        json_path: Path to the JSON file.

    Returns:
        A BenchmarkRun frozen dataclass instance.

    Raises:
        FileNotFoundError: If the file does not exist.
    """
    from ares.dialectic.scripts.benchmark_runner import BenchmarkRun, ScenarioResult

    with open(json_path, "r") as f:
        data = json.load(f)

    results = tuple(
        ScenarioResult(
            scenario_id=r["scenario_id"],
            strategy_type=r["strategy_type"],
            verdict_outcome=r["verdict_outcome"],
            verdict_confidence=r["verdict_confidence"],
            architect_confidence=r["architect_confidence"],
            skeptic_confidence=r["skeptic_confidence"],
            architect_assertion_count=r["architect_assertion_count"],
            skeptic_assertion_count=r["skeptic_assertion_count"],
            architect_fact_ids_cited=frozenset(r["architect_fact_ids_cited"]),
            skeptic_fact_ids_cited=frozenset(r["skeptic_fact_ids_cited"]),
            total_facts_available=r["total_facts_available"],
            fact_coverage_ratio=r["fact_coverage_ratio"],
            validation_errors=r["validation_errors"],
            fallback_triggers=r["fallback_triggers"],
            duration_ms=r["duration_ms"],
            token_usage=r["token_usage"],
            cost_usd=r["cost_usd"],
            narrator_output=r["narrator_output"],
        )
        for r in data["results"]
    )

    return BenchmarkRun(
        run_id=data["run_id"],
        timestamp=datetime.fromisoformat(data["timestamp"]),
        strategy_type=data["strategy_type"],
        scenario_count=data["scenario_count"],
        results=results,
        total_duration_ms=data["total_duration_ms"],
        total_cost_usd=data["total_cost_usd"],
    )


def main(argv: Optional[list[str]] = None) -> Any:
    """Run the ARES benchmark and save results.

    Args:
        argv: Command-line arguments (defaults to sys.argv[1:]).

    Returns:
        The BenchmarkRun instance.
    """
    parser = argparse.ArgumentParser(description="ARES Benchmark Runner")
    parser.add_argument(
        "--strategy",
        required=True,
        choices=["rule_based", "llm"],
        help="Strategy type: rule_based or llm",
    )
    parser.add_argument(
        "--run-name",
        required=True,
        help="Descriptive name for this run (used in filenames)",
    )
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Output directory for results",
    )
    parser.add_argument(
        "--baseline",
        default=None,
        help="Run-name of a previous run for delta report",
    )
    parser.add_argument(
        "--no-narration",
        action="store_true",
        help="Skip narrator output (faster, cheaper)",
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
    from ares.dialectic.scripts.benchmark_runner import run_benchmark
    from ares.dialectic.scripts.benchmark_report import generate_report

    scenarios = get_all_scenarios()
    print(f"ARES Benchmark: {len(scenarios)} scenarios, strategy={args.strategy}")
    print(f"Output: {output_dir}")

    # Set up client for LLM runs
    client = None
    if args.strategy == "llm":
        from ares.dialectic.agents.strategies.client import AnthropicClient

        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            print("ERROR: ANTHROPIC_API_KEY environment variable not set.")
            sys.exit(1)
        client = AnthropicClient(api_key=api_key)

    # Run benchmark
    print(f"\nRunning {args.strategy} benchmark...")
    run = run_benchmark(
        scenarios=scenarios,
        strategy_type=args.strategy,
        include_narration=not args.no_narration,
        client=client,
    )

    # Save results as JSON
    results_json = serialize_benchmark_run(run)
    json_path = output_dir / f"{args.run_name}.json"
    with open(json_path, "w") as f:
        json.dump(results_json, f, indent=2, default=str)
    print(f"Results saved: {json_path}")

    # Generate and save report
    report = generate_report(run, scenarios)
    report_path = output_dir / f"{args.run_name}_report.txt"
    with open(report_path, "w") as f:
        f.write(report)
    print(f"Report saved: {report_path}")

    # Generate delta report if baseline specified
    if args.baseline:
        baseline_json_path = output_dir / f"{args.baseline}.json"
        if baseline_json_path.exists():
            baseline_run = deserialize_benchmark_run(baseline_json_path)
            delta_report = generate_report(run, scenarios, baseline_run=baseline_run)
            delta_path = output_dir / f"{args.run_name}_vs_{args.baseline}_report.txt"
            with open(delta_path, "w") as f:
                f.write(delta_report)
            print(f"Delta report saved: {delta_path}")
        else:
            print(f"WARNING: Baseline file not found: {baseline_json_path}")

    # Print summary to console
    print(f"\n{'=' * 60}")
    print(report)

    return run


if __name__ == "__main__":
    main()
