"""Session 032 — Benchmark with V2 Oracle rescoring + v3 prompts.

Runs the benchmark with v3 prompts, then applies OracleJudgeV2 rescoring
to compare V1 vs V2 verdicts on the same LLM outputs.

Usage:
    python -m ares.dialectic.scripts.run_032_benchmark
    python -m ares.dialectic.scripts.run_032_benchmark --compare-031
    python -m ares.dialectic.scripts.run_032_benchmark --v2-rescore-only path/to/031_results.json
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
        description="Session 032: Benchmark with V2 Oracle + v3 prompts",
    )
    parser.add_argument(
        "--output-dir",
        default="ares/dialectic/scripts/benchmark_results",
        help="Directory for results (default: benchmark_results/)",
    )
    parser.add_argument(
        "--compare-031",
        action="store_true",
        help="Load Session 031 results for delta comparison",
    )
    parser.add_argument(
        "--v2-rescore-only",
        type=str,
        default=None,
        help="Path to existing results JSON — only apply V2 rescoring (no API calls)",
    )
    parser.add_argument(
        "--no-narration",
        action="store_true",
        help="Skip narrator output",
    )
    return parser


def _rescore_with_v2(results_data: dict, scenarios) -> list:
    """Apply OracleJudgeV2 rescoring to existing benchmark results.

    Takes the architect/skeptic confidence from each result and
    re-computes the verdict using V2 scoring logic.

    Returns list of dicts with v1_verdict, v2_verdict, expected.
    """
    from ares.dialectic.agents.oracle_v2 import OracleJudgeV2, ScoringConfig

    expected_by_id = {s.metadata.scenario_id: s.metadata.expected_verdict.lower() for s in scenarios}
    rescored = []

    for r in results_data["results"]:
        sid = r["scenario_id"]
        arch_conf = r["architect_confidence"]
        skep_conf = r["skeptic_confidence"]

        # V2 rescoring uses only confidence values
        outcome_v2, reasoning = OracleJudgeV2._apply_scoring(
            arch_conf, skep_conf, ScoringConfig()
        )

        expected = expected_by_id.get(sid, "unknown")
        rescored.append({
            "scenario_id": sid,
            "expected": expected,
            "v1_verdict": r["verdict_outcome"],
            "v2_verdict": outcome_v2.value,
            "v1_match": r["verdict_outcome"] == expected,
            "v2_match": outcome_v2.value == expected,
            "arch_conf": arch_conf,
            "skep_conf": skep_conf,
            "v2_reasoning": reasoning,
        })

    return rescored


def _print_comparison(rescored: list, label: str) -> None:
    """Print a side-by-side V1 vs V2 comparison table."""
    print(f"\n{'=' * 85}")
    print(f"  {label}")
    print(f"{'=' * 85}")
    print(f"{'ID':<8} {'Expected':<20} {'V1 Verdict':<20} {'V2 Verdict':<20} {'V1':>3} {'V2':>3}")
    print("-" * 85)

    v1_correct = 0
    v2_correct = 0
    flips = []

    for r in rescored:
        v1_mark = "+" if r["v1_match"] else "X"
        v2_mark = "+" if r["v2_match"] else "X"
        if r["v1_match"]:
            v1_correct += 1
        if r["v2_match"]:
            v2_correct += 1

        line = (
            f"{r['scenario_id']:<8} {r['expected']:<20} "
            f"{r['v1_verdict']:<20} {r['v2_verdict']:<20} "
            f"{v1_mark:>3} {v2_mark:>3}"
        )

        if r["v1_verdict"] != r["v2_verdict"]:
            line += "  <-- FLIP"
            flips.append(r)

        print(line)

    total = len(rescored)
    print(f"\n{'V1 Accuracy':>15}: {v1_correct}/{total} ({100 * v1_correct / total:.1f}%)")
    print(f"{'V2 Accuracy':>15}: {v2_correct}/{total} ({100 * v2_correct / total:.1f}%)")
    print(f"{'Delta':>15}: {v2_correct - v1_correct:+d}")

    if flips:
        print(f"\n  Verdict flips ({len(flips)}):")
        for f in flips:
            direction = "+" if f["v2_match"] and not f["v1_match"] else ("-" if f["v1_match"] and not f["v2_match"] else "~")
            print(f"    {direction} {f['scenario_id']}: {f['v1_verdict']} -> {f['v2_verdict']} "
                  f"(expected: {f['expected']}, arch={f['arch_conf']:.2f}, skep={f['skep_conf']:.2f})")


def main(argv: Optional[list[str]] = None) -> None:
    """Entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    # --- V2 rescore-only mode (no API calls) ---
    if args.v2_rescore_only:
        print("V2 rescore-only mode (no API calls)")
        path = Path(args.v2_rescore_only)
        data = json.loads(path.read_text(encoding="utf-8"))

        from ares.dialectic.scripts.scenario_corpus_v2 import get_full_corpus_v2
        scenarios = list(get_full_corpus_v2())

        rescored = _rescore_with_v2(data, scenarios)
        _print_comparison(rescored, "V2 Rescore of Existing Results (corpus_v2)")

        rescore_path = out_dir / f"v2_rescore_{ts}.json"
        rescore_path.write_text(json.dumps(rescored, indent=2), encoding="utf-8")
        print(f"\nRescore saved to: {rescore_path}")
        return

    # --- Full benchmark with v3 prompts ---
    print("Running Session 032 benchmark: v3 prompts + V2 Oracle rescoring")
    print("=" * 60)

    from ares.dialectic.scripts.scenario_corpus_v2 import get_full_corpus_v2
    scenarios = list(get_full_corpus_v2())

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
        print("ERROR: ANTHROPIC_API_KEY not found")
        sys.exit(1)

    from ares.dialectic.agents.strategies.client import AnthropicClient
    from ares.dialectic.agents.strategies.observability import LLMCallLogger
    from ares.dialectic.scripts.benchmark_runner import run_benchmark
    from ares.dialectic.scripts.run_llm_benchmark import serialize_benchmark_run

    client = AnthropicClient(api_key=api_key)
    call_logger = LLMCallLogger()

    # Run with v3 strategies
    from ares.dialectic.agents.strategies.llm_strategy_v3 import (
        LLMExplanationFinderV3,
        LLMNarrativeGeneratorV3,
        LLMThreatAnalyzerV3,
    )

    include_narration = not args.no_narration

    print(f"\nRunning {len(scenarios)} scenarios with v3 prompts...")
    llm_run = run_benchmark(
        scenarios,
        strategy_type="llm",
        include_narration=include_narration,
        client=client,
        call_logger=call_logger,
        threat_analyzer=LLMThreatAnalyzerV3(client, call_logger=call_logger),
        explanation_finder=LLMExplanationFinderV3(client, call_logger=call_logger),
        narrative_generator=LLMNarrativeGeneratorV3(client, call_logger=call_logger) if include_narration else None,
    )

    # Save raw results
    results_path = out_dir / f"v3_llm_{ts}.json"
    results_path.write_text(
        json.dumps(serialize_benchmark_run(llm_run), indent=2),
        encoding="utf-8",
    )

    # Rescore with V2
    data = json.loads(results_path.read_text(encoding="utf-8"))
    rescored = _rescore_with_v2(data, scenarios)
    _print_comparison(rescored, "v3 Prompts: V1 Oracle vs V2 Oracle (corpus_v2)")

    rescore_path = out_dir / f"v3_v2_rescore_{ts}.json"
    rescore_path.write_text(json.dumps(rescored, indent=2), encoding="utf-8")

    # Compare with Session 031 if requested
    if args.compare_031:
        s031_files = sorted(out_dir.glob("full_llm_*.json"))
        if s031_files:
            s031_path = s031_files[-1]
            print(f"\nComparing against Session 031: {s031_path.name}")
            s031_data = json.loads(s031_path.read_text(encoding="utf-8"))
            s031_rescored = _rescore_with_v2(s031_data, scenarios)
            _print_comparison(s031_rescored, "Session 031 Results: V1 vs V2 Rescore (corpus_v2)")

    cost = llm_run.total_cost_usd or 0.0
    duration = llm_run.total_duration_ms / 1000.0
    print(f"\nCost: ${cost:.2f}, Duration: {duration:.1f}s")
    print(f"Results: {results_path}")
    print(f"Rescore: {rescore_path}")


if __name__ == "__main__":
    main()
