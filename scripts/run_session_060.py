"""Session 060 — narrow-reading characterization runner CLI.

Extends the Paper 3 narrow claim's empirical bound from N=2 (Session
059) to up to N=99 on the deterministic / light path.

Pre-registered values (locked from Session 059, not tunable):
    - operator set: framing_prefix_v1, framing_suffix_v1,
      synonym_substitution_conservative_v2
    - confidence drift threshold: |delta| > 0.10
    - pipeline: light only

Locked at Session 060:
    - cost ceiling: $5 USD (cannot be raised above default)
    - no halt on narrow fire (characterization mode)

Usage:
    # Anchor + pre-flight only (no live run):
    python scripts/run_session_060.py --preflight-only

    # Full live characterization (after Dan's GO):
    python scripts/run_session_060.py --confirm-live

    # Anchor-only sanity check:
    python scripts/run_session_060.py --dry-run
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from ares.dialectic.measurement.leakage_runner import anchor_test_passes
from ares.dialectic.measurement.narrow_characterization_runner import (
    NARROW_EXT_COST_CEILING_USD,
    NARROW_EXT_PREFLIGHT_CYCLES,
    NarrowCharacterizationConfig,
    run_narrow_characterization,
    run_preflight,
)
from ares.dialectic.measurement.narrow_extended_report import write_report


def _format_preflight(result: dict) -> str:
    if result.get("status") == "no_samples":
        return "Pre-flight produced zero successful samples. Halt recommended."
    lines = [
        "Narrow-extended pre-flight:",
        f"  samples completed:        {result['n_samples']} / {NARROW_EXT_PREFLIGHT_CYCLES}",
        f"  avg cost per light cycle: ${result['avg_cost_per_light_cycle_usd']:.5f}",
        f"  avg wall per light cycle: {result['avg_elapsed_ms_per_light_cycle']:.0f} ms",
        f"  ESTIMATED TOTAL:          ${result['estimated_total_cost_usd']:.4f}",
        f"  ESTIMATED WALL TIME:      {result['estimated_wall_time_minutes']:.1f} minutes",
        f"  cost ceiling:             ${result['cost_ceiling_usd']:.2f}",
        f"  exceeds ceiling:          {result['exceeds_ceiling']}",
        f"  halt recommendation:      {result['halt_recommendation']}",
        f"  preflight actual cost:    ${result['preflight_actual_cost_usd']:.5f}",
        f"  estimated total pairs:    {result['estimated_total_pairs']}",
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
            "Session 060 - narrow-reading characterization run. "
            "Extends Paper 3 narrow-claim N from 2 (Session 059) to up "
            "to 99 on the light path. No halt on narrow fire."
        ),
    )
    parser.add_argument(
        "--preflight-only",
        action="store_true",
        help="Run anchor check + 5-cycle pre-flight and exit.",
    )
    parser.add_argument(
        "--confirm-live",
        action="store_true",
        help=(
            "Run the full characterization (~132 light cycles) after "
            "pre-flight passes. Requires Dan's explicit GO."
        ),
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Anchor test only; no LLM calls.",
    )
    parser.add_argument(
        "--cost-ceiling",
        type=float,
        default=NARROW_EXT_COST_CEILING_USD,
        help=(
            f"Cost ceiling in USD (default and max: "
            f"${NARROW_EXT_COST_CEILING_USD})."
        ),
    )
    args = parser.parse_args(argv)

    if args.cost_ceiling > NARROW_EXT_COST_CEILING_USD:
        print(
            f"[FATAL] cost_ceiling ${args.cost_ceiling} > pre-registered "
            f"${NARROW_EXT_COST_CEILING_USD}; refusing.",
            file=sys.stderr,
        )
        return 2

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

    print("[2/3] Narrow-extended pre-flight (5 light cycles) ...")
    config = NarrowCharacterizationConfig(cost_ceiling_usd=args.cost_ceiling)
    preflight = run_preflight(config=config)
    print(_format_preflight(preflight))

    if preflight.get("halt_recommendation") in (
        "preflight_over_budget",
        "preflight_no_samples",
    ):
        print(
            "\n[HALT] Pre-flight indicates we cannot complete within "
            "the cost ceiling. Live run not initiated.",
            file=sys.stderr,
        )
        return 4

    if args.preflight_only or not args.confirm_live:
        print(
            "\n[done] Pre-flight complete. "
            "Pass --confirm-live to execute the characterization run."
        )
        return 0

    print("\n[3/3] LIVE NARROW CHARACTERIZATION RUN (light path; N up to 99) ...")
    summary = run_narrow_characterization(config=config)

    print(f"\nrun_id:                       {summary.run_id}")
    print(f"halt_reason:                  {summary.halt_reason}")
    print(f"cycles_completed:             {summary.cycles_completed}")
    print(f"total_cost_usd:               ${summary.total_cost_usd:.4f}")
    print(f"n_pairs_evaluated:            {summary.n_pairs_evaluated}")
    print(f"n_pairs_stable_narrow:        {summary.n_pairs_stable_narrow}")
    print(f"n_pairs_narrow_fired:         {summary.n_pairs_narrow_fired}")
    print(f"narrow_stability_rate:        "
          f"{summary.narrow_stability_rate:.4f} "
          f"({summary.narrow_stability_percent:.2f}%)")
    print(f"anchor_at_start:              {summary.anchor_test_passed_at_start}")
    print(f"anchor_at_end:                {summary.anchor_test_passed_at_end}")

    report_path = write_report(summary)
    print(f"\nReport written: {report_path}")
    print(f"traces:         {summary.traces_path}")
    print(f"sha256:         {summary.sha256_path}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
