"""Session 033 — Run v3 prompts benchmark with injectable runner.

Executes the full 33-scenario corpus_v2 benchmark using v3 prompts
via run_benchmark_custom(), saves results for threshold sweep.

Usage:
    python -m ares.dialectic.scripts.run_033_v3_benchmark
    python -m ares.dialectic.scripts.run_033_v3_benchmark --no-narration
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
        description="Session 033: v3 prompts benchmark via injectable runner",
    )
    parser.add_argument(
        "--output-dir",
        default="ares/dialectic/scripts/benchmark_results",
        help="Directory for results",
    )
    parser.add_argument(
        "--no-narration",
        action="store_true",
        help="Skip narrator output",
    )
    return parser


def main(argv: Optional[list[str]] = None) -> None:
    """Entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # Load API key
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        env_path = Path(__file__).resolve().parent.parent.parent.parent / ".env"
        if env_path.exists():
            try:
                raw = env_path.read_bytes()
                for enc in ("utf-8", "utf-16"):
                    try:
                        text = raw.decode(enc)
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
        print("ERROR: ANTHROPIC_API_KEY not found")
        sys.exit(1)

    from ares.dialectic.agents.strategies.client import AnthropicClient
    from ares.dialectic.agents.strategies.llm_strategy_v3 import (
        LLMExplanationFinderV3,
        LLMNarrativeGeneratorV3,
        LLMThreatAnalyzerV3,
    )
    from ares.dialectic.agents.strategies.observability import LLMCallLogger
    from ares.dialectic.scripts.benchmark_runner_v2 import run_benchmark_custom
    from ares.dialectic.scripts.run_llm_benchmark import serialize_benchmark_run
    from ares.dialectic.scripts.scenario_corpus_v2 import get_full_corpus_v2

    scenarios = list(get_full_corpus_v2())
    client = AnthropicClient(api_key=api_key)
    call_logger = LLMCallLogger()

    include_narration = not args.no_narration

    ta = LLMThreatAnalyzerV3(client, call_logger=call_logger)
    ef = LLMExplanationFinderV3(client, call_logger=call_logger)
    ng = LLMNarrativeGeneratorV3(client, call_logger=call_logger) if include_narration else None

    print(f"Running v3 benchmark: {len(scenarios)} scenarios (corpus_v2)")
    print("=" * 60)

    run = run_benchmark_custom(
        scenarios, ta, ef, ng,
        call_logger=call_logger,
        include_narration=include_narration,
        strategy_label="llm_v3",
    )

    # Print per-scenario results
    print()
    misclassified = []
    for result, scenario in zip(run.results, scenarios):
        expected = scenario.metadata.expected_verdict.lower()
        actual = result.verdict_outcome
        match = actual == expected
        cost_str = f"${result.cost_usd:.3f}" if result.cost_usd else "$0.000"
        mark = "+" if match else "X"
        print(f"  {result.scenario_id}: {actual:<20s} "
              f"(expected: {expected:<20s}) {mark}  {cost_str}  "
              f"arch={result.architect_confidence:.2f} skep={result.skeptic_confidence:.2f} "
              f"cov={result.fact_coverage_ratio:.2f}")
        if not match:
            misclassified.append(result.scenario_id)

    correct = len(scenarios) - len(misclassified)
    accuracy = 100 * correct / len(scenarios) if scenarios else 0
    total_cost = run.total_cost_usd or 0.0
    duration_s = run.total_duration_ms / 1000.0

    print()
    print("=" * 60)
    print(f"V1 Oracle + v3 Prompts Accuracy: {correct}/{len(scenarios)} ({accuracy:.1f}%)")
    print(f"Cost: ${total_cost:.2f}, Duration: {duration_s:.1f}s")
    if misclassified:
        print(f"Misclassified: {', '.join(misclassified)}")
    else:
        print("Misclassified: (none)")

    # Save results
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    results_path = out_dir / f"v3_corpus_v2_{ts}.json"
    results_path.write_text(
        json.dumps(serialize_benchmark_run(run), indent=2),
        encoding="utf-8",
    )
    print(f"\nResults saved to: {results_path}")

    # Also save as the canonical name for the threshold sweep
    canonical = out_dir / "v3_corpus_v2.json"
    canonical.write_text(
        json.dumps(serialize_benchmark_run(run), indent=2),
        encoding="utf-8",
    )
    print(f"Canonical: {canonical}")


if __name__ == "__main__":
    main()
