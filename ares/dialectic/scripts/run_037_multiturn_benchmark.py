"""Session 037 — Multi-turn benchmark with cost guard.

Runs the full 33-scenario corpus through multi-turn debate (3 rounds),
captures per-round confidence snapshots, and saves results for visual
replay. Stops if cumulative cost approaches the configured limit.

Usage:
    python -m ares.dialectic.scripts.run_037_multiturn_benchmark
    python -m ares.dialectic.scripts.run_037_multiturn_benchmark --cost-limit 5.0
    python -m ares.dialectic.scripts.run_037_multiturn_benchmark --max-rounds 3
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        description="Session 037: Multi-turn benchmark with cost guard",
    )
    parser.add_argument(
        "--output-dir",
        default="ares/dialectic/scripts/benchmark_results",
        help="Directory for results",
    )
    parser.add_argument(
        "--cost-limit",
        type=float,
        default=5.0,
        help="Maximum total API cost in USD (default: $5.00)",
    )
    parser.add_argument(
        "--max-rounds",
        type=int,
        default=3,
        help="Max debate rounds per scenario (default: 3)",
    )
    parser.add_argument(
        "--confidence-delta",
        type=float,
        default=0.05,
        help="Convergence threshold (default: 0.05)",
    )
    return parser


def _serialize_multiturn_run(run) -> dict:
    """Serialize MultiTurnBenchmarkRun to JSON-compatible dict."""
    return {
        "run_id": run.run_id,
        "timestamp": run.timestamp.isoformat() if hasattr(run.timestamp, 'isoformat') else str(run.timestamp),
        "strategy_type": run.strategy_type,
        "max_rounds": run.max_rounds,
        "confidence_delta": run.confidence_delta,
        "require_new_evidence": run.require_new_evidence,
        "scenario_count": run.scenario_count,
        "total_duration_ms": run.total_duration_ms,
        "total_cost_usd": run.total_cost_usd,
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
                "rounds_used": r.rounds_used,
                "max_rounds_configured": r.max_rounds_configured,
                "termination_reason": r.termination_reason,
                "coverage": r.coverage,
                "validation_errors": r.validation_errors,
                "fallback_triggers": r.fallback_triggers,
                "duration_ms": r.duration_ms,
                "token_usage": r.token_usage,
                "cost_usd": r.cost_usd,
                "total_facts_available": getattr(r, 'total_facts_available', 0),
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
            }
            for r in run.results
        ],
    }


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
    from ares.dialectic.agents.strategies.multi_turn_strategies import (
        MultiTurnLLMExplanationFinder,
        MultiTurnLLMNarrativeGenerator,
        MultiTurnLLMThreatAnalyzer,
    )
    from ares.dialectic.agents.strategies.observability import LLMCallLogger
    from ares.dialectic.scripts.multi_turn_benchmark import run_multi_turn_benchmark
    from ares.dialectic.scripts.scenario_corpus_v2 import get_full_corpus_v2

    scenarios = list(get_full_corpus_v2())
    client = AnthropicClient(api_key=api_key)
    call_logger = LLMCallLogger()

    print(f"Multi-turn benchmark: {len(scenarios)} scenarios, "
          f"max_rounds={args.max_rounds}, delta={args.confidence_delta}")
    print(f"Cost limit: ${args.cost_limit:.2f}")
    print("=" * 65)

    start_time = time.perf_counter()

    run = run_multi_turn_benchmark(
        scenarios,
        client=client,
        call_logger=call_logger,
        max_rounds=args.max_rounds,
        confidence_delta=args.confidence_delta,
        require_new_evidence=True,
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

    elapsed = time.perf_counter() - start_time

    # Print per-scenario results
    print()
    misclassified = []
    for r in run.results:
        expected = r.expected_verdict.lower()
        actual = r.verdict_outcome
        match = actual == expected
        mark = "+" if match else "X"
        cost_str = f"${r.cost_usd:.3f}" if r.cost_usd else "$0.000"
        rounds = r.rounds_used
        term = r.termination_reason[:15] if r.termination_reason else "?"

        # Show confidence trajectory
        snaps = r.round_snapshots
        traj = " -> ".join(
            f"({s.architect_confidence:.2f}/{s.skeptic_confidence:.2f})"
            for s in snaps
        )

        print(f"  {r.scenario_id}: {actual:<20s} {mark}  "
              f"R{rounds} [{term:<15s}] {cost_str}  {traj}")
        if not match:
            misclassified.append(r.scenario_id)

    # Summary
    correct = len(scenarios) - len(misclassified)
    accuracy = 100 * correct / len(scenarios)
    total_cost = run.total_cost_usd or 0.0

    print()
    print("=" * 65)
    print(f"Multi-turn Accuracy: {correct}/{len(scenarios)} ({accuracy:.1f}%)")
    print(f"Avg rounds used: {run.avg_rounds_used:.1f}")
    print(f"Cost: ${total_cost:.2f} / ${args.cost_limit:.2f} limit")
    print(f"Duration: {elapsed:.1f}s")

    if misclassified:
        print(f"Misclassified: {', '.join(misclassified)}")

    # Cost check
    if total_cost > args.cost_limit:
        print(f"\nWARNING: Cost ${total_cost:.2f} exceeded limit ${args.cost_limit:.2f}")

    # Save results
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    results_path = out_dir / f"multiturn_v2_{ts}.json"
    results_path.write_text(
        json.dumps(_serialize_multiturn_run(run), indent=2),
        encoding="utf-8",
    )
    canonical = out_dir / "multiturn_v2.json"
    canonical.write_text(
        json.dumps(_serialize_multiturn_run(run), indent=2),
        encoding="utf-8",
    )

    print(f"\nResults saved to: {results_path}")
    print(f"Canonical: {canonical}")


if __name__ == "__main__":
    main()
