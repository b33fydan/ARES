"""Session 034 — V2 Oracle threshold sweep on v4 benchmark data.

Loads v4 benchmark results and rescores with OracleJudgeV2
across a range of configurations to find the optimal thresholds.

No API calls — operates on saved data.

Usage:
    python -m ares.dialectic.scripts.run_034_threshold_sweep
    python -m ares.dialectic.scripts.run_034_threshold_sweep --results path/to/v4_results.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        description="Session 034: V2 threshold sweep on v4 benchmark data",
    )
    parser.add_argument(
        "--results",
        default="ares/dialectic/scripts/benchmark_results/v4_corpus_v2.json",
        help="Path to v4 benchmark results JSON",
    )
    parser.add_argument(
        "--output-dir",
        default="ares/dialectic/scripts/benchmark_results",
        help="Directory for sweep results",
    )
    return parser


def _rescore(results: list, scenarios_by_id: dict, config) -> dict:
    """Rescore all scenarios with a given ScoringConfig."""
    from ares.dialectic.agents.oracle_v2 import OracleJudgeV2

    correct = 0
    confirmed_correct = 0
    dismissed_correct = 0
    inconclusive_correct = 0
    regressions_from_v1 = []

    for r in results:
        sid = r["scenario_id"]
        scenario = scenarios_by_id.get(sid)
        if scenario is None:
            continue

        expected = scenario.metadata.expected_verdict.lower()
        v1_verdict = r["verdict_outcome"]
        v1_match = v1_verdict == expected

        outcome_v2, _ = OracleJudgeV2._apply_scoring(
            r["architect_confidence"],
            r["skeptic_confidence"],
            config,
        )
        v2_verdict = outcome_v2.value
        v2_match = v2_verdict == expected

        if v2_match:
            correct += 1
            if expected == "threat_confirmed":
                confirmed_correct += 1
            elif expected == "threat_dismissed":
                dismissed_correct += 1
            else:
                inconclusive_correct += 1

        if v1_match and not v2_match:
            regressions_from_v1.append(sid)

    return {
        "correct": correct,
        "confirmed_correct": confirmed_correct,
        "dismissed_correct": dismissed_correct,
        "inconclusive_correct": inconclusive_correct,
        "regressions": regressions_from_v1,
    }


def main(argv: Optional[list[str]] = None) -> None:
    """Entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)

    results_path = Path(args.results)
    if not results_path.exists():
        print(f"ERROR: Results file not found: {results_path}")
        print("Run the v4 benchmark first: python -m ares.dialectic.scripts.run_034_v4_benchmark")
        sys.exit(1)

    data = json.loads(results_path.read_text(encoding="utf-8"))
    results = data["results"]
    total = len(results)

    from ares.dialectic.agents.oracle_v2 import ScoringConfig
    from ares.dialectic.scripts.scenario_corpus_v2 import get_full_corpus_v2

    scenarios_by_id = {s.metadata.scenario_id: s for s in get_full_corpus_v2()}

    # V1 accuracy on this data
    v1_correct = sum(
        1 for r in results
        if r["verdict_outcome"] == scenarios_by_id.get(r["scenario_id"], type("X", (), {"metadata": type("M", (), {"expected_verdict": ""})()})()).metadata.expected_verdict.lower()
    )

    # Sweep
    deltas = [0.10, 0.15, 0.20, 0.25, 0.30, 0.35]
    dom_maxes = [0.55, 0.60, 0.65]
    min_winners = [0.55, 0.60, 0.65]

    print(f"V2 Oracle Threshold Sweep on v4 data ({total} scenarios)")
    print(f"V1 Oracle accuracy: {v1_correct}/{total} ({100 * v1_correct / total:.1f}%)")
    print("=" * 70)

    best_accuracy = 0
    best_config = None
    best_result = None
    best_zero_reg = None
    best_zero_reg_acc = 0
    all_results = []

    for dom_max in dom_maxes:
        for min_w in min_winners:
            for delta in deltas:
                config = ScoringConfig(
                    confirm_delta=delta,
                    dismiss_delta=delta,
                    min_winner_confidence=min_w,
                    dominant_threshold=0.85,
                    dominant_opponent_max=dom_max,
                )

                result = _rescore(results, scenarios_by_id, config)
                acc = result["correct"]
                regs = len(result["regressions"])

                entry = {
                    "delta": delta,
                    "min_winner": min_w,
                    "dom_max": dom_max,
                    "accuracy": acc,
                    "regressions": regs,
                    "confirmed": result["confirmed_correct"],
                    "dismissed": result["dismissed_correct"],
                    "inconclusive": result["inconclusive_correct"],
                    "regression_ids": result["regressions"],
                }
                all_results.append(entry)

                if acc > best_accuracy or (acc == best_accuracy and regs < len(best_result.get("regression_ids", []))):
                    best_accuracy = acc
                    best_config = config
                    best_result = entry

                if regs == 0 and acc > best_zero_reg_acc:
                    best_zero_reg_acc = acc
                    best_zero_reg = entry

    sorted_results = sorted(all_results, key=lambda x: (-x["accuracy"], x["regressions"]))

    print(f"\n{'Delta':>6} {'MinW':>5} {'DMax':>5} {'Acc':>6} {'Conf':>5} "
          f"{'Dism':>5} {'Incl':>5} {'Regs':>5}")
    print("-" * 55)

    for entry in sorted_results[:20]:
        marker = " <-- BEST" if entry is best_result else ""
        if entry == best_zero_reg:
            marker = " <-- BEST (0 reg)"
        print(f"{entry['delta']:>6.2f} {entry['min_winner']:>5.2f} "
              f"{entry['dom_max']:>5.2f} "
              f"{entry['accuracy']:>3d}/{total} "
              f"{entry['confirmed']:>5d} {entry['dismissed']:>5d} "
              f"{entry['inconclusive']:>5d} {entry['regressions']:>5d}{marker}")

    print(f"\n{'=' * 55}")
    print(f"V1 Oracle: {v1_correct}/{total} ({100 * v1_correct / total:.1f}%)")
    print(f"BEST overall: {best_accuracy}/{total} ({100 * best_accuracy / total:.1f}%)")
    if best_config:
        print(f"  delta={best_config.confirm_delta}, min_w={best_config.min_winner_confidence}, "
              f"dom_max={best_config.dominant_opponent_max}")
        if best_result and best_result["regression_ids"]:
            print(f"  V1 regressions: {', '.join(best_result['regression_ids'])}")

    if best_zero_reg:
        print(f"BEST zero-regression: {best_zero_reg_acc}/{total} ({100 * best_zero_reg_acc / total:.1f}%)")
        print(f"  delta={best_zero_reg['delta']}, min_w={best_zero_reg['min_winner']}, "
              f"dom_max={best_zero_reg['dom_max']}")

    # Save
    out_dir = Path(args.output_dir)
    sweep_path = out_dir / "v4_threshold_sweep.json"
    sweep_data = {
        "v1_accuracy": v1_correct,
        "total_scenarios": total,
        "best_overall": {
            "accuracy": best_accuracy,
            "config": {
                "confirm_delta": best_config.confirm_delta if best_config else None,
                "min_winner": best_config.min_winner_confidence if best_config else None,
                "dom_max": best_config.dominant_opponent_max if best_config else None,
            },
            "regressions": best_result["regression_ids"] if best_result else [],
        },
        "best_zero_regression": {
            "accuracy": best_zero_reg_acc,
            "config": best_zero_reg if best_zero_reg else None,
        },
        "all_results": sorted_results,
    }
    sweep_path.write_text(json.dumps(sweep_data, indent=2), encoding="utf-8")
    print(f"\nSweep saved to: {sweep_path}")


if __name__ == "__main__":
    main()
