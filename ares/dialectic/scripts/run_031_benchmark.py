"""Session 031 — Run the full 33-scenario LLM benchmark and save results.

Executes the complete corpus benchmark using single-turn LLM strategy
(v2 prompts), saves timestamped JSON results suitable for diagnosis,
and generates formatted reports with optional rule-based delta.

Usage:
    python -m ares.dialectic.scripts.run_031_benchmark
    python -m ares.dialectic.scripts.run_031_benchmark --include-rule-based
    python -m ares.dialectic.scripts.run_031_benchmark --output-dir results/
    python -m ares.dialectic.scripts.run_031_benchmark --no-narration
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        description="Session 031: Run 33-scenario LLM benchmark and save results",
    )
    parser.add_argument(
        "--output-dir",
        default="ares/dialectic/scripts/benchmark_results",
        help="Directory to save results (default: benchmark_results/)",
    )
    parser.add_argument(
        "--include-rule-based",
        action="store_true",
        help="Also run rule-based baseline for delta comparison",
    )
    parser.add_argument(
        "--no-narration",
        action="store_true",
        help="Skip OracleNarrator output (faster, cheaper)",
    )
    return parser


def main(argv: Optional[list[str]] = None) -> None:
    """Entry point for the Session 031 benchmark CLI."""
    parser = build_parser()
    args = parser.parse_args(argv)

    from ares.dialectic.scripts.benchmark_report import generate_report
    from ares.dialectic.scripts.benchmark_runner import run_benchmark
    from ares.dialectic.scripts.expanded_scenarios import get_full_corpus
    from ares.dialectic.scripts.run_llm_benchmark import serialize_benchmark_run

    scenarios = list(get_full_corpus())
    print(f"Running ARES benchmark: {len(scenarios)} scenarios, single-turn LLM v2")
    print("=" * 60)

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    include_narration = not args.no_narration

    # --- Optional rule-based baseline ---
    baseline_run = None
    if args.include_rule_based:
        print("\n[1/2] Running rule-based baseline...")
        baseline_run = run_benchmark(
            scenarios,
            strategy_type="rule_based",
            include_narration=include_narration,
        )
        baseline_path = out_dir / f"full_baseline_{ts}.json"
        baseline_path.write_text(
            json.dumps(serialize_benchmark_run(baseline_run), indent=2),
            encoding="utf-8",
        )
        correct = sum(
            1 for r, s in zip(baseline_run.results, scenarios)
            if r.verdict_outcome == s.metadata.expected_verdict.lower()
        )
        print(f"  Rule-based: {correct}/{len(scenarios)} "
              f"({100 * correct / len(scenarios):.1f}%)")
        print(f"  Saved: {baseline_path.name}")

    # --- LLM benchmark ---
    phase_label = "[2/2]" if args.include_rule_based else "[1/1]"
    print(f"\n{phase_label} Running LLM benchmark (this makes API calls)...")

    # Load API key
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        env_path = Path(__file__).resolve().parent.parent.parent.parent / ".env"
        if env_path.exists():
            try:
                raw = env_path.read_bytes()
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
    from ares.dialectic.agents.strategies.observability import LLMCallLogger

    client = AnthropicClient(api_key=api_key)
    call_logger = LLMCallLogger()

    llm_run = run_benchmark(
        scenarios,
        strategy_type="llm",
        include_narration=include_narration,
        client=client,
        call_logger=call_logger,
    )

    # --- Print per-scenario results ---
    print()
    misclassified = []
    for result, scenario in zip(llm_run.results, scenarios):
        expected = scenario.metadata.expected_verdict.lower()
        actual = result.verdict_outcome
        match = actual == expected
        cost_str = f"${result.cost_usd:.3f}" if result.cost_usd else "$0.000"
        mark = "+" if match else "X"
        print(f"  {result.scenario_id}: {actual:<20s} "
              f"(expected: {expected:<20s}) {mark}  {cost_str}")
        if not match:
            misclassified.append(result.scenario_id)

    # --- Summary ---
    correct = len(scenarios) - len(misclassified)
    accuracy = 100 * correct / len(scenarios) if scenarios else 0
    total_cost = llm_run.total_cost_usd or 0.0
    duration_s = llm_run.total_duration_ms / 1000.0

    print()
    print("=" * 60)
    print(f"Accuracy: {correct}/{len(scenarios)} ({accuracy:.1f}%)")
    print(f"Total cost: ${total_cost:.2f}")
    print(f"Duration: {duration_s:.1f}s")
    if misclassified:
        print(f"Misclassified: {', '.join(misclassified)}")
    else:
        print("Misclassified: (none)")

    # --- Save results ---
    results_path = out_dir / f"full_llm_{ts}.json"
    results_path.write_text(
        json.dumps(serialize_benchmark_run(llm_run), indent=2),
        encoding="utf-8",
    )

    report_text = generate_report(llm_run, scenarios, baseline_run=baseline_run)
    report_path = out_dir / f"full_report_{ts}.txt"
    report_path.write_text(report_text, encoding="utf-8")

    summary = {
        "timestamp": ts,
        "accuracy": accuracy,
        "correct": correct,
        "total": len(scenarios),
        "misclassified": misclassified,
        "total_cost_usd": total_cost,
        "duration_s": duration_s,
        "results_file": results_path.name,
    }
    summary_path = out_dir / f"full_summary_{ts}.json"
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print()
    print(f"Results saved to: {results_path}")
    print(f"Report saved to:  {report_path}")
    print(f"Summary saved to: {summary_path}")


if __name__ == "__main__":
    main()
