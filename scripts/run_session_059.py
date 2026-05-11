"""Session 059 — InfluenceLeakage measurement runner CLI.

Single-entry runner that:
    1. Verifies the anchor test is green.
    2. Runs the pre-flight estimator (5 light cycles by default).
    3. Surfaces the aggregate cost estimate to stdout.
    4. Halts unless --confirm-live is passed.
    5. Executes the full 264-cycle live measurement run.
    6. Emits LEAKAGE_REPORT_<run_id>.md at repo root.
    7. Persists traces JSONL + SHA256 manifest.

Pre-registered values (locked, not tunable via CLI):
    - operator set: framing_prefix_v1, framing_suffix_v1, synonym_substitution_conservative_v2
    - weights: 0.40 / 0.20 / 0.20 / 0.20
    - confidence drift threshold: |Δ| > 0.10
    - kill direction: weighted_scalar > 0.0

Cost ceiling defaults to $20 USD; can be lowered (not raised) via flag
for safety drills.

Usage:
    # Pre-flight only:
    python scripts/run_session_059.py --preflight-only

    # Full live run (after Dan's GO):
    python scripts/run_session_059.py --confirm-live

    # Dry-run scaffold check (no LLM calls, anchor test only):
    python scripts/run_session_059.py --dry-run
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

# Allow running this script directly from the repo root without
# `pip install -e .` by prepending the repo root to sys.path.
_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from ares.dialectic.measurement.leakage_report import write_report
from ares.dialectic.measurement.leakage_runner import (
    DEFAULT_COST_CEILING_USD,
    DEFAULT_PREFLIGHT_CYCLES,
    HALT_PREFLIGHT_OVER_BUDGET,
    RunnerConfig,
    anchor_test_passes,
    run_full_measurement,
    run_preflight,
)


def _format_preflight_summary(result: dict) -> str:
    if result.get("status") == "no_samples":
        return (
            "Pre-flight produced zero successful samples. "
            "Halt recommended."
        )
    lines = [
        "Pre-flight estimate:",
        f"  samples completed:        {result['n_samples']} / {DEFAULT_PREFLIGHT_CYCLES}",
        f"  avg cost per light cycle: ${result['avg_cost_per_light_cycle_usd']:.5f}",
        f"  avg wall per light cycle: {result['avg_elapsed_ms_per_light_cycle']:.0f} ms",
        f"  estimated light path:     ${result['estimated_light_path_cost_usd']:.4f}",
        f"  estimated llm path:       ${result['estimated_llm_path_cost_usd']:.4f}",
        f"  ESTIMATED TOTAL:          ${result['estimated_total_cost_usd']:.4f}",
        f"  ESTIMATED WALL TIME:      {result['estimated_wall_time_minutes']:.1f} minutes",
        f"  cost ceiling:             ${result['cost_ceiling_usd']:.2f}",
        f"  exceeds ceiling:          {result['exceeds_ceiling']}",
        f"  halt recommendation:      {result['halt_recommendation']}",
        f"  preflight actual cost:    ${result['preflight_actual_cost_usd']:.5f}",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="[%(asctime)s] %(levelname)s %(name)s :: %(message)s",
        datefmt="%H:%M:%S",
    )

    parser = argparse.ArgumentParser(
        description=(
            "Session 059 — InfluenceLeakage first measurement run. "
            "Pre-flight by default; --confirm-live triggers the 264-cycle "
            "live measurement."
        ),
    )
    parser.add_argument(
        "--preflight-only",
        action="store_true",
        help="Run the 5-cycle pre-flight estimator and exit.",
    )
    parser.add_argument(
        "--confirm-live",
        action="store_true",
        help=(
            "Run the full live measurement after the pre-flight passes. "
            "REQUIRES Dan's explicit GO. Without this flag, the script "
            "halts after pre-flight."
        ),
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help=(
            "No LLM calls. Verify anchor test is green and exit. "
            "Useful for scaffold sanity checks."
        ),
    )
    parser.add_argument(
        "--cost-ceiling",
        type=float,
        default=DEFAULT_COST_CEILING_USD,
        help=(
            f"Cost ceiling in USD (default: {DEFAULT_COST_CEILING_USD}). "
            "Cannot be raised above default to prevent unintended overspend."
        ),
    )
    args = parser.parse_args(argv)

    # Cost ceiling safety: don't allow raising above the pre-registered $20.
    if args.cost_ceiling > DEFAULT_COST_CEILING_USD:
        print(
            f"[FATAL] cost_ceiling ${args.cost_ceiling} > pre-registered "
            f"${DEFAULT_COST_CEILING_USD}; refusing.",
            file=sys.stderr,
        )
        return 2

    # Anchor test check
    print("[1/3] Anchor-test guard ...")
    if not anchor_test_passes():
        print(
            "[FATAL] Anchor test (light_skeptic.py:185) is RED. "
            "Halting before any LLM spend.",
            file=sys.stderr,
        )
        return 3
    print("       anchor test green [ok]")

    if args.dry_run:
        print("[done] dry run complete; anchor green; no LLM calls made.")
        return 0

    # Pre-flight
    print("[2/3] Pre-flight estimator (5 light cycles) ...")
    config = RunnerConfig(cost_ceiling_usd=args.cost_ceiling)
    preflight = run_preflight(config=config)
    print(_format_preflight_summary(preflight))

    if preflight.get("halt_recommendation") == HALT_PREFLIGHT_OVER_BUDGET:
        print(
            "\n[HALT] Pre-flight estimate exceeds cost ceiling. "
            "Live run not initiated.",
            file=sys.stderr,
        )
        return 4

    if args.preflight_only or not args.confirm_live:
        print(
            "\n[done] Pre-flight complete. "
            "Pass --confirm-live to execute the 264-cycle live run."
        )
        return 0

    # Full live run
    print("\n[3/3] LIVE MEASUREMENT RUN — 264 cycles ...")
    summary = run_full_measurement(config=config)

    print(f"\nrun_id:           {summary.run_id}")
    print(f"halt_reason:      {summary.halt_reason}")
    print(f"cycles_completed: {summary.cycles_completed}")
    print(f"total_cost_usd:   ${summary.total_cost_usd:.4f}")
    print(f"deterministic_kill_fired: {summary.deterministic_kill_fired}")
    print(f"anchor_at_start:  {summary.anchor_test_passed_at_start}")
    print(f"anchor_at_end:    {summary.anchor_test_passed_at_end}")

    report_path = write_report(summary)
    print(f"\nLEAKAGE_REPORT written: {report_path}")
    print(f"traces:                  {summary.traces_path}")
    print(f"sha256:                  {summary.sha256_path}")

    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
