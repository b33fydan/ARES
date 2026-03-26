"""CLI runner for the selective escalation benchmark.

Session 024: Runs the full selective escalation pipeline against the
33-scenario corpus, computes calibration metrics, and prints a
comprehensive comparison report.

Usage:
    python -m ares.dialectic.scripts.run_selective_benchmark
    python -m ares.dialectic.scripts.run_selective_benchmark --max-rounds 2
    python -m ares.dialectic.scripts.run_selective_benchmark --original-strategies
"""

from __future__ import annotations

import argparse
import os
import sys
import time


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        description="ARES Selective Escalation Benchmark — two-gate architecture evaluation",
    )
    parser.add_argument(
        "--max-rounds",
        type=int,
        default=3,
        help="Max debate rounds for multi-turn escalation (default: 3)",
    )
    parser.add_argument(
        "--original-strategies",
        action="store_true",
        help="Use original (unanchored) multi-turn strategies instead of anchored",
    )
    parser.add_argument(
        "--threshold-low",
        type=float,
        default=0.35,
        help="EscalationGate lower threshold (default: 0.35)",
    )
    parser.add_argument(
        "--threshold-high",
        type=float,
        default=0.65,
        help="EscalationGate upper threshold (default: 0.65)",
    )
    return parser


def _get_client():
    """Create an AnthropicClient for LLM runs."""
    api_key = os.environ.get("ANTHROPIC_API_KEY")

    if not api_key:
        env_path = os.path.join(os.path.dirname(__file__), "..", "..", "..", ".env")
        env_path = os.path.normpath(env_path)
        if os.path.exists(env_path):
            try:
                with open(env_path, "rb") as f:
                    raw = f.read()
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


def main() -> None:
    """Run the selective escalation benchmark with calibration metrics."""
    parser = build_parser()
    args = parser.parse_args()

    # Load corpus
    from ares.dialectic.scripts.expanded_scenarios import get_full_corpus
    scenarios = list(get_full_corpus())
    total = len(scenarios)

    print(f"=== ARES SELECTIVE ESCALATION BENCHMARK ({total} scenarios) ===")
    print(f"EscalationGate thresholds: [{args.threshold_low}, {args.threshold_high}]")
    print(f"MiscalibrationDetector: defaults")
    print(f"Multi-turn max_rounds: {args.max_rounds}")
    strategy_label = "original" if args.original_strategies else "anchored"
    print(f"Multi-turn strategy: {strategy_label}")
    print()

    # Setup
    client = _get_client()
    from ares.dialectic.agents.strategies.observability import LLMCallLogger
    call_logger = LLMCallLogger()

    from ares.dialectic.coordinator.escalation import EscalationGate
    from ares.dialectic.coordinator.miscalibration import MiscalibrationDetector
    gate = EscalationGate(
        threshold_low=args.threshold_low,
        threshold_high=args.threshold_high,
    )
    detector = MiscalibrationDetector()

    # Run selective escalation
    from ares.dialectic.scripts.selective_escalation import (
        run_selective_escalation,
        format_selective_report,
    )

    start_time = time.perf_counter()
    print("--- Running Selective Escalation Pipeline ---")

    summary = run_selective_escalation(
        scenarios=scenarios,
        escalation_gate=gate,
        miscalibration_detector=detector,
        client=client,
        call_logger=call_logger,
        max_rounds=args.max_rounds,
        use_anchored=not args.original_strategies,
    )

    elapsed = time.perf_counter() - start_time
    print(f"\n--- Pipeline complete ({elapsed:.1f}s) ---\n")

    # Print selective escalation report
    report = format_selective_report(summary)
    print(report)

    # Compute calibration metrics
    from ares.dialectic.coordinator.calibration import CalibrationEvaluator
    evaluator = CalibrationEvaluator(n_bins=5)

    # Single-turn calibration
    st_preds = [
        (r.single_turn_confidence, r.single_turn_verdict == r.expected_verdict)
        for r in summary.results
    ]
    st_cal = evaluator.evaluate(st_preds)

    # Selective escalation calibration (use single-turn confidence as proxy)
    sel_preds = [
        (r.single_turn_confidence, r.final_correct)
        for r in summary.results
    ]
    sel_cal = evaluator.evaluate(sel_preds)

    print("\n" + "=" * 60)
    print("CALIBRATION METRICS")
    print("=" * 60)
    print()
    print("--- Single-Turn ---")
    print(f"  Brier score:              {st_cal.brier_score:.4f}")
    print(f"  ECE:                      {st_cal.expected_calibration_error:.4f}")
    print(f"  Overconfidence ratio:     {st_cal.overconfidence_ratio:.1%}")
    print(f"  Underconfidence ratio:    {st_cal.underconfidence_ratio:.1%}")
    print()
    print("--- Selective Escalation ---")
    print(f"  Brier score:              {sel_cal.brier_score:.4f}")
    print(f"  ECE:                      {sel_cal.expected_calibration_error:.4f}")
    print(f"  Overconfidence ratio:     {sel_cal.overconfidence_ratio:.1%}")
    print(f"  Underconfidence ratio:    {sel_cal.underconfidence_ratio:.1%}")
    print()
    brier_delta = sel_cal.brier_score - st_cal.brier_score
    ece_delta = sel_cal.expected_calibration_error - st_cal.expected_calibration_error
    brier_sign = "+" if brier_delta >= 0 else ""
    ece_sign = "+" if ece_delta >= 0 else ""
    print(f"  Brier delta:              {brier_sign}{brier_delta:.4f} {'(worse)' if brier_delta > 0 else '(better)' if brier_delta < 0 else '(same)'}")
    print(f"  ECE delta:                {ece_sign}{ece_delta:.4f} {'(worse)' if ece_delta > 0 else '(better)' if ece_delta < 0 else '(same)'}")

    # Per-bin details
    print()
    print("--- Single-Turn Bin Details ---")
    print(f"  {'Bin':<12} {'Count':>6} {'Avg Conf':>10} {'Accuracy':>10} {'Gap':>8}")
    for b in st_cal.bin_details:
        if b.count > 0:
            print(f"  [{b.bin_lower:.1f},{b.bin_upper:.1f})  {b.count:>6} {b.avg_confidence:>10.3f} {b.accuracy:>10.3f} {b.calibration_gap:>8.3f}")

    # LLM cost summary
    print()
    print("--- LLM Cost Summary ---")
    logger_summary = call_logger.summary()
    print(f"  Total API calls:          {logger_summary['total_calls']}")
    print(f"  Total input tokens:       {logger_summary['total_input_tokens']:,}")
    print(f"  Total output tokens:      {logger_summary['total_output_tokens']:,}")
    print(f"  Estimated total cost:     ${logger_summary['estimated_cost_usd']:.4f}")
    print(f"  Fallback count:           {logger_summary['fallback_count']}")
    print(f"  Error count:              {logger_summary['error_count']}")

    # The verdict
    print()
    print("=" * 60)
    if summary.accuracy_delta > 0:
        print(f"VERDICT: Selective escalation BEATS single-turn by {summary.accuracy_delta:.1%}")
    elif summary.accuracy_delta < 0:
        print(f"VERDICT: Selective escalation LOSES to single-turn by {abs(summary.accuracy_delta):.1%}")
    else:
        print("VERDICT: Selective escalation TIES with single-turn")
    print(f"  at {summary.cost_ratio:.1f}x the cost")
    print("=" * 60)


if __name__ == "__main__":
    main()
