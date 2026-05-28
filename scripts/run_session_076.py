"""Session 076 — Multi-model narrow characterization CLI.

Extends the Sonnet 4.6 narrow characterization (Session 060: 100.00%
stability, 98/98 pairs, zero narrow fires) to GPT-4o and Gemini 2.5 Pro.

Uses the same NarrowCharacterizationConfig from Session 060 with the
multi-provider dispatch wired in Session 074-075.

The .env at repo root is UTF-16 LE (Windows Notepad default). This script
loads it into os.environ before constructing any client.

Usage:
    # Dry-run (anchor check only, no LLM calls):
    python scripts/run_session_076.py --provider openai --dry-run

    # Pre-flight only (5 light cycles, cost estimate):
    python scripts/run_session_076.py --provider openai --preflight-only

    # Full live narrow characterization (after Dan's GO):
    python scripts/run_session_076.py --provider openai --confirm-live

    # Gemini:
    python scripts/run_session_076.py --provider gemini --confirm-live
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


def _load_env() -> int:
    """Load the UTF-16 LE .env file into os.environ.

    Returns the number of keys loaded.
    """
    env_path = _REPO_ROOT / ".env"
    if not env_path.exists():
        return 0
    with open(env_path, "r", encoding="utf-16") as f:
        content = f.read()
    loaded = 0
    for line in content.strip().splitlines():
        line = line.strip()
        if "=" in line and not line.startswith("#"):
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip()
            if key and value:
                os.environ[key] = value
                loaded += 1
    return loaded


from ares.dialectic.agents.strategies.client_factory import (
    PROVIDER_DEFAULTS,
    VALID_PROVIDERS,
)
from ares.dialectic.measurement.leakage_runner import anchor_test_passes
from ares.dialectic.measurement.narrow_characterization_runner import (
    NARROW_EXT_COST_CEILING_USD,
    NARROW_EXT_PREFLIGHT_CYCLES,
    NarrowCharacterizationConfig,
    run_narrow_characterization,
    run_preflight,
)
from ares.dialectic.measurement.narrow_extended_report import write_report


def _format_preflight(result: dict, provider: str, model: str) -> str:
    if result.get("status") == "no_samples":
        return "Pre-flight produced zero successful samples. Halt recommended."
    lines = [
        f"Narrow-extended pre-flight ({provider} / {model}):",
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


def _persist_summary(summary, traces_dir: Path) -> None:
    """Write summary.json alongside traces for cross-model discovery."""
    summary_path = traces_dir / "summary.json"
    summary_path.write_text(
        json.dumps(summary.to_dict(), indent=2, default=str),
        encoding="utf-8",
    )


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="[%(asctime)s] %(levelname)s %(name)s :: %(message)s",
        datefmt="%H:%M:%S",
    )

    parser = argparse.ArgumentParser(
        description=(
            "Session 076 — Multi-model narrow characterization. "
            "Extends Sonnet 4.6 narrow stability (Session 060: 98/98) "
            "to GPT-4o and Gemini 2.5 Pro on the deterministic path."
        ),
    )
    parser.add_argument(
        "--provider",
        required=True,
        choices=sorted(VALID_PROVIDERS),
        help="LLM provider to use (anthropic, openai, gemini).",
    )
    parser.add_argument(
        "--model",
        default=None,
        help=(
            "Model ID override. Defaults to provider default: "
            + ", ".join(f"{k}={v}" for k, v in sorted(PROVIDER_DEFAULTS.items()))
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
            "Run the full narrow characterization (~132 light cycles) after "
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

    # Load .env (UTF-16 LE)
    n_loaded = _load_env()
    print(f"[env] loaded {n_loaded} keys from .env (UTF-16 LE)")

    resolved_model = args.model or PROVIDER_DEFAULTS[args.provider]
    print(
        f"[config] provider={args.provider}  model={resolved_model}  "
        f"ceiling=${args.cost_ceiling}"
    )

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

    config = NarrowCharacterizationConfig(
        cost_ceiling_usd=args.cost_ceiling,
        model=resolved_model,
        provider=args.provider,
    )

    # Pre-flight
    print(
        f"[2/3] Narrow-extended pre-flight "
        f"(5 light cycles, {args.provider}) ..."
    )
    preflight = run_preflight(config=config)
    print(_format_preflight(preflight, args.provider, resolved_model))

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

    # Full narrow characterization
    print(
        f"\n[3/3] LIVE NARROW CHARACTERIZATION "
        f"({args.provider} / {resolved_model}, ~132 light cycles) ..."
    )
    summary = run_narrow_characterization(config=config)

    print(f"\nprovider:                     {summary.provider}")
    print(f"model:                        {summary.model}")
    print(f"run_id:                       {summary.run_id}")
    print(f"halt_reason:                  {summary.halt_reason}")
    print(f"cycles_completed:             {summary.cycles_completed}")
    print(f"total_cost_usd:               ${summary.total_cost_usd:.4f}")
    print(f"n_pairs_evaluated:            {summary.n_pairs_evaluated}")
    print(f"n_pairs_stable_narrow:        {summary.n_pairs_stable_narrow}")
    print(f"n_pairs_narrow_fired:         {summary.n_pairs_narrow_fired}")
    print(
        f"narrow_stability_rate:        "
        f"{summary.narrow_stability_rate:.4f} "
        f"({summary.narrow_stability_percent:.2f}%)"
    )
    print(f"anchor_at_start:              {summary.anchor_test_passed_at_start}")
    print(f"anchor_at_end:                {summary.anchor_test_passed_at_end}")

    # Persist summary.json for cross-model discovery
    traces_dir = Path(summary.traces_path).parent
    _persist_summary(summary, traces_dir)
    print(f"\nsummary.json:   {traces_dir / 'summary.json'}")

    report_path = write_report(summary)
    print(f"Report written: {report_path}")
    print(f"traces:         {summary.traces_path}")
    print(f"sha256:         {summary.sha256_path}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
