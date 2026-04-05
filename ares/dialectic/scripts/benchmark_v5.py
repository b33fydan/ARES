"""Run v5 kill chain prompts through the 39-scenario corpus and compare to v4 baseline.

Session 042: Benchmark script for v5 prompts.
- Phase A: Single live run with v5 strategies (39 API calls)
- Phase B: Rescore with V2 Oracle at delta=0.30
- Phase C: Compare against v4+V1 baseline from Session 041

CLI:
    python -m ares.dialectic.scripts.benchmark_v5
    python -m ares.dialectic.scripts.benchmark_v5 --dry-run
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from ares.dialectic.agents.oracle_v2 import OracleJudgeV2, ScoringConfig
from ares.dialectic.scripts.benchmark_runner import BenchmarkRun, ScenarioResult
from ares.dialectic.scripts.sweep_oracle_v2 import rescore_results, _verdicts_match


# V4+V1 baseline from Session 041 (saved sweep_results.json)
V4_V1_BASELINE = {
    "SC": {"correct": 26, "total": 33},
    "PT": {"correct": 2, "total": 6},
    "combined": {"correct": 28, "total": 39},
}


def _load_baseline(path: Path) -> dict | None:
    """Try to load the Session 041 sweep results for more accurate baseline."""
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text())
        return data.get("v1_baseline")
    except (json.JSONDecodeError, KeyError):
        return None


def run_v5_benchmark(
    dry_run: bool = False,
    include_narration: bool = False,
) -> None:
    """Execute the v5 benchmark pipeline."""

    # --- Load corpus ---
    print("[V5-BENCH] Loading corpus...")
    from ares.dialectic.scripts.pentagi_scenarios import get_pentagi_corpus
    corpus = list(get_pentagi_corpus())

    expected_verdicts = {
        s.metadata.scenario_id: s.metadata.expected_verdict
        for s in corpus
    }
    print(f"[V5-BENCH] Corpus: {len(corpus)} scenarios")

    # --- Load or use hardcoded V4 baseline ---
    sweep_path = Path("benchmark_results/v2_sweep/sweep_results.json")
    saved_baseline = _load_baseline(sweep_path)
    if saved_baseline:
        v4_sc = saved_baseline.get("sc_correct", V4_V1_BASELINE["SC"]["correct"])
        v4_pt = saved_baseline.get("pt_correct", V4_V1_BASELINE["PT"]["correct"])
        v4_combined = saved_baseline.get("combined_correct", V4_V1_BASELINE["combined"]["correct"])
        v4_total = saved_baseline.get("total", V4_V1_BASELINE["combined"]["total"])
        print(f"[V5-BENCH] V4+V1 baseline loaded from {sweep_path}")
    else:
        v4_sc = V4_V1_BASELINE["SC"]["correct"]
        v4_pt = V4_V1_BASELINE["PT"]["correct"]
        v4_combined = V4_V1_BASELINE["combined"]["correct"]
        v4_total = V4_V1_BASELINE["combined"]["total"]
        print("[V5-BENCH] Using hardcoded V4+V1 baseline")

    # --- Build strategies ---
    if dry_run:
        from ares.dialectic.agents.strategies.rule_based import (
            RuleBasedExplanationFinder,
            RuleBasedNarrativeGenerator,
            RuleBasedThreatAnalyzer,
        )
        threat_analyzer = RuleBasedThreatAnalyzer()
        explanation_finder = RuleBasedExplanationFinder()
        narrative_generator = RuleBasedNarrativeGenerator()
        strategy_label = "rule_based_v5_dryrun"
        print("[V5-BENCH] Using rule-based strategies (dry-run)")
    else:
        import os

        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            env_path = Path(__file__).resolve().parent.parent.parent.parent / ".env"
            if env_path.exists():
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

        if not api_key:
            print("[V5-BENCH] ERROR: ANTHROPIC_API_KEY not found. Use --dry-run for testing.")
            return

        from ares.dialectic.agents.strategies.client import AnthropicClient
        from ares.dialectic.agents.strategies.llm_strategy_v5 import (
            LLMThreatAnalyzerV5,
            LLMExplanationFinderV5,
            LLMNarrativeGeneratorV5,
        )

        client = AnthropicClient(api_key=api_key)
        threat_analyzer = LLMThreatAnalyzerV5(client)
        explanation_finder = LLMExplanationFinderV5(client)
        narrative_generator = LLMNarrativeGeneratorV5(client)
        strategy_label = "llm_v5"
        print("[V5-BENCH] Using LLM V5 strategies (live)")

    # --- Phase A: Single run ---
    from ares.dialectic.scripts.benchmark_runner_v2 import run_benchmark_custom

    print(f"\n[V5-BENCH] Phase A: Running {len(corpus)} scenarios...")
    phase_a_start = time.perf_counter()

    benchmark_run = run_benchmark_custom(
        scenarios=corpus,
        threat_analyzer=threat_analyzer,
        explanation_finder=explanation_finder,
        narrative_generator=narrative_generator,
        include_narration=include_narration,
        strategy_label=strategy_label,
    )

    phase_a_time = time.perf_counter() - phase_a_start
    print(f"[V5-BENCH] Phase A complete: {phase_a_time:.1f}s, "
          f"cost=${benchmark_run.total_cost_usd or 0:.2f}")

    # --- V5+V1 accuracy ---
    v5_v1_sc = 0
    v5_v1_pt = 0
    for result in benchmark_run.results:
        if result.verdict_outcome == "ERROR":
            continue
        sid = result.scenario_id
        expected = expected_verdicts.get(sid, "UNKNOWN")
        correct = _verdicts_match(result.verdict_outcome.upper(), expected)
        if sid.startswith("SC") and correct:
            v5_v1_sc += 1
        elif sid.startswith("PT") and correct:
            v5_v1_pt += 1

    v5_v1_combined = v5_v1_sc + v5_v1_pt

    # --- Phase B: Rescore with V2 at delta=0.30 ---
    print("\n[V5-BENCH] Phase B: Rescoring with V2 Oracle (delta=0.30)...")
    v2_config = ScoringConfig(confirm_delta=0.30, dismiss_delta=0.30)
    v2_result = rescore_results(benchmark_run, expected_verdicts, v2_config)

    # --- Phase C: Report ---
    sc_total = 33
    pt_total = 6
    total = sc_total + pt_total

    v5_v2_sc = v2_result.sc_correct
    v5_v2_pt = v2_result.pt_correct
    v5_v2_combined = v2_result.combined_correct

    print()
    print("V5 KILL CHAIN PROMPT BENCHMARK")
    print("=" * 70)
    print(f"{'Config':<20}{'SC (33)':<12}{'PT (6)':<12}{'Combined':<18}{'vs V4+V1'}")
    print("-" * 70)

    v4_pct = v4_combined / v4_total * 100
    print(f"{'V4+V1 (baseline)':<20}{v4_sc}/{sc_total:<11}{v4_pt}/{pt_total:<11}"
          f"{v4_combined}/{v4_total} ({v4_pct:.1f}%){'':>5}--")

    v5v1_pct = v5_v1_combined / total * 100
    v5v1_delta = v5_v1_combined - v4_combined
    v5v1_sign = "+" if v5v1_delta >= 0 else ""
    print(f"{'V5+V1':<20}{v5_v1_sc}/{sc_total:<11}{v5_v1_pt}/{pt_total:<11}"
          f"{v5_v1_combined}/{total} ({v5v1_pct:.1f}%){'':>5}{v5v1_sign}{v5v1_delta}")

    v5v2_pct = v5_v2_combined / total * 100
    v5v2_delta = v5_v2_combined - v4_combined
    v5v2_sign = "+" if v5v2_delta >= 0 else ""
    print(f"{'V5+V2 (0.30)':<20}{v5_v2_sc}/{sc_total:<11}{v5_v2_pt}/{pt_total:<11}"
          f"{v5_v2_combined}/{total} ({v5v2_pct:.1f}%){'':>5}{v5v2_sign}{v5v2_delta}")

    print("=" * 70)

    # --- Per-scenario detail ---
    print("\nPER-SCENARIO DETAIL:")
    print(f"{'Scenario':<12}{'Expected':<20}{'V5+V1 Verdict':<20}"
          f"{'Arch':<8}{'Skep':<8}{'Correct'}")
    print("-" * 78)

    for result in benchmark_run.results:
        sid = result.scenario_id
        expected = expected_verdicts.get(sid, "UNKNOWN")
        verdict = result.verdict_outcome.upper()
        correct = _verdicts_match(verdict, expected)
        marker = "OK" if correct else "MISS"
        print(f"{sid:<12}{expected:<20}{verdict:<20}"
              f"{result.architect_confidence:<8.2f}{result.skeptic_confidence:<8.2f}"
              f"{marker}")

    # --- Changes from baseline ---
    print("\nCHANGES (V5+V1 vs V4+V1 baseline):")
    has_changes = False
    for result in benchmark_run.results:
        sid = result.scenario_id
        expected = expected_verdicts.get(sid, "UNKNOWN")
        v5_verdict = result.verdict_outcome.upper()
        v5_correct = _verdicts_match(v5_verdict, expected)

        # We don't have per-scenario V4 results, so flag all misses
        # and correct ones for PT scenarios (where we know V4 was 2/6)
        if sid.startswith("PT"):
            has_changes = True
            status = "CORRECT" if v5_correct else "MISS"
            print(f"  {status:>12} {sid}: V5={v5_verdict} "
                  f"(expected={expected}) "
                  f"[arch={result.architect_confidence:.2f}, "
                  f"skep={result.skeptic_confidence:.2f}]")

    # V2 rescore changes
    regressions = [c for c in v2_result.comparisons if c.is_regression]
    improvements = [c for c in v2_result.comparisons if c.is_improvement]
    if regressions or improvements:
        print(f"\nV2 RESCORE (delta=0.30) changes vs V5+V1:")
        for c in improvements:
            print(f"  IMPROVEMENT {c.scenario_id}: "
                  f"V1={c.v1_verdict} -> V2={c.v2_verdict} "
                  f"[arch={c.architect_confidence:.2f}, skep={c.skeptic_confidence:.2f}]")
        for c in regressions:
            print(f"  REGRESSION  {c.scenario_id}: "
                  f"V1={c.v1_verdict} -> V2={c.v2_verdict} "
                  f"[arch={c.architect_confidence:.2f}, skep={c.skeptic_confidence:.2f}]")

    if not has_changes and not regressions and not improvements:
        print("  (no changes detected)")

    print()

    # --- Save results ---
    output_dir = Path("benchmark_results/v5_killchain")
    output_dir.mkdir(parents=True, exist_ok=True)
    out_path = output_dir / "results.json"

    results_data = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "strategy": strategy_label,
        "v4_v1_baseline": {
            "sc_correct": v4_sc,
            "pt_correct": v4_pt,
            "combined_correct": v4_combined,
            "total": v4_total,
        },
        "v5_v1": {
            "sc_correct": v5_v1_sc,
            "pt_correct": v5_v1_pt,
            "combined_correct": v5_v1_combined,
            "total": total,
        },
        "v5_v2_delta030": {
            "sc_correct": v5_v2_sc,
            "pt_correct": v5_v2_pt,
            "combined_correct": v5_v2_combined,
            "total": total,
            "regressions": v2_result.regressions,
            "improvements": v2_result.improvements,
        },
        "per_scenario": [
            {
                "scenario_id": r.scenario_id,
                "expected": expected_verdicts.get(r.scenario_id, "UNKNOWN"),
                "verdict": r.verdict_outcome,
                "architect_confidence": r.architect_confidence,
                "skeptic_confidence": r.skeptic_confidence,
                "correct": _verdicts_match(r.verdict_outcome.upper(),
                                           expected_verdicts.get(r.scenario_id, "UNKNOWN")),
                "duration_ms": r.duration_ms,
                "cost_usd": r.cost_usd,
            }
            for r in benchmark_run.results
        ],
    }

    out_path.write_text(json.dumps(results_data, indent=2))
    print(f"[V5-BENCH] Results saved to {out_path}")


def main(argv: list[str] | None = None) -> None:
    """CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description="V5 Kill Chain Prompt Benchmark — compare to V4 baseline",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Use rule-based strategies (no API key needed)",
    )
    parser.add_argument(
        "--include-narration", action="store_true", default=False,
        help="Include OracleNarrator (slower, costs more)",
    )
    args = parser.parse_args(argv)

    run_v5_benchmark(
        dry_run=args.dry_run,
        include_narration=args.include_narration,
    )


if __name__ == "__main__":
    main()
