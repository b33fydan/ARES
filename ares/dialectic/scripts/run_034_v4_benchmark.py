"""Session 034 — Run v4 prompts benchmark (Architect mixed-signal calibration).

Executes the full 33-scenario corpus_v2 benchmark using v4 prompts
via run_benchmark_custom(), saves results, and compares against v3 baseline.

Usage:
    python -m ares.dialectic.scripts.run_034_v4_benchmark
    python -m ares.dialectic.scripts.run_034_v4_benchmark --no-narration
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


TARGET_SCENARIOS = {"SC-001", "SC-012", "SC-026", "SC-027", "SC-030"}


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        description="Session 034: v4 Architect calibration benchmark",
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
    from ares.dialectic.agents.strategies.llm_strategy_v4 import (
        LLMExplanationFinderV4,
        LLMNarrativeGeneratorV4,
        LLMThreatAnalyzerV4,
    )
    from ares.dialectic.agents.strategies.observability import LLMCallLogger
    from ares.dialectic.scripts.benchmark_runner_v2 import run_benchmark_custom
    from ares.dialectic.scripts.run_llm_benchmark import serialize_benchmark_run
    from ares.dialectic.scripts.scenario_corpus_v2 import get_full_corpus_v2

    scenarios = list(get_full_corpus_v2())
    client = AnthropicClient(api_key=api_key)
    call_logger = LLMCallLogger()

    include_narration = not args.no_narration

    ta = LLMThreatAnalyzerV4(client, call_logger=call_logger)
    ef = LLMExplanationFinderV4(client, call_logger=call_logger)
    ng = LLMNarrativeGeneratorV4(client, call_logger=call_logger) if include_narration else None

    print(f"Running v4 benchmark: {len(scenarios)} scenarios (corpus_v2)")
    print("Target scenarios: " + ", ".join(sorted(TARGET_SCENARIOS)))
    print("=" * 70)

    run = run_benchmark_custom(
        scenarios, ta, ef, ng,
        call_logger=call_logger,
        include_narration=include_narration,
        strategy_label="llm_v4",
    )

    # Load v3 results for comparison
    v3_path = out_dir / "v3_corpus_v2.json"
    v3_by_id = {}
    if v3_path.exists():
        v3_data = json.loads(v3_path.read_text(encoding="utf-8"))
        v3_by_id = {r["scenario_id"]: r for r in v3_data["results"]}

    # Print per-scenario results
    print()
    misclassified = []
    target_results = []

    for result, scenario in zip(run.results, scenarios):
        expected = scenario.metadata.expected_verdict.lower()
        actual = result.verdict_outcome
        match = actual == expected
        cost_str = f"${result.cost_usd:.3f}" if result.cost_usd else "$0.000"
        mark = "+" if match else "X"

        # Compare with v3
        v3r = v3_by_id.get(result.scenario_id, {})
        v3_arch = v3r.get("architect_confidence", 0)
        delta_arch = result.architect_confidence - v3_arch if v3r else 0

        target_flag = " ***" if result.scenario_id in TARGET_SCENARIOS else ""

        print(f"  {result.scenario_id}: {actual:<20s} "
              f"(expected: {expected:<20s}) {mark}  {cost_str}  "
              f"arch={result.architect_confidence:.2f} skep={result.skeptic_confidence:.2f} "
              f"cov={result.fact_coverage_ratio:.2f}"
              f"  [v3 arch={v3_arch:.2f} d={delta_arch:+.2f}]{target_flag}")

        if not match:
            misclassified.append(result.scenario_id)

        if result.scenario_id in TARGET_SCENARIOS:
            target_results.append({
                "id": result.scenario_id,
                "expected": expected,
                "v4_verdict": actual,
                "v4_match": match,
                "v4_arch": result.architect_confidence,
                "v3_arch": v3_arch,
                "arch_delta": delta_arch,
            })

    correct = len(scenarios) - len(misclassified)
    accuracy = 100 * correct / len(scenarios)
    total_cost = run.total_cost_usd or 0.0
    duration_s = run.total_duration_ms / 1000.0
    v3_correct = sum(1 for r, s in zip(v3_data["results"], scenarios)
                     if r["verdict_outcome"] == s.metadata.expected_verdict.lower()) if v3_by_id else 0

    print()
    print("=" * 70)
    print(f"v4 Accuracy: {correct}/{len(scenarios)} ({accuracy:.1f}%)")
    print(f"v3 Accuracy: {v3_correct}/{len(scenarios)} ({100 * v3_correct / len(scenarios):.1f}%)")
    print(f"Delta: {correct - v3_correct:+d}")
    print(f"Cost: ${total_cost:.2f}, Duration: {duration_s:.1f}s")

    if misclassified:
        print(f"Misclassified: {', '.join(misclassified)}")

    # Target scenario report
    print()
    print("-" * 70)
    print("TARGET SCENARIO ANALYSIS (mixed-signal calibration)")
    print("-" * 70)
    flipped = 0
    for t in target_results:
        status = "FIXED" if t["v4_match"] else "STILL WRONG"
        if not t["v4_match"] and t["v4_arch"] < 0.70:
            status = "ARCH CALIBRATED (but still wrong)"
        print(f"  {t['id']}: arch {t['v3_arch']:.2f} -> {t['v4_arch']:.2f} "
              f"({t['arch_delta']:+.2f})  verdict={t['v4_verdict']}  [{status}]")
        if t["v4_match"]:
            flipped += 1
    print(f"  Target fixes: {flipped}/5")

    # Check for regressions from v3
    if v3_by_id:
        regressions = []
        for result, scenario in zip(run.results, scenarios):
            expected = scenario.metadata.expected_verdict.lower()
            v3r = v3_by_id.get(result.scenario_id, {})
            v3_match = v3r.get("verdict_outcome", "") == expected
            v4_match = result.verdict_outcome == expected
            if v3_match and not v4_match:
                regressions.append(result.scenario_id)
        if regressions:
            print(f"\n  REGRESSIONS from v3: {', '.join(regressions)}")
        else:
            print(f"\n  REGRESSIONS from v3: (none)")

    # Save results
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    results_path = out_dir / f"v4_corpus_v2_{ts}.json"
    results_path.write_text(
        json.dumps(serialize_benchmark_run(run), indent=2),
        encoding="utf-8",
    )
    canonical = out_dir / "v4_corpus_v2.json"
    canonical.write_text(
        json.dumps(serialize_benchmark_run(run), indent=2),
        encoding="utf-8",
    )
    print(f"\nResults saved to: {results_path}")
    print(f"Canonical: {canonical}")


if __name__ == "__main__":
    main()
