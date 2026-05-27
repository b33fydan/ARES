"""Session 075 — Multi-model InfluenceLeakage validation CLI.

Step 5 of the V4 Tribunal sequence: run the same 98-pair InfluenceLeakage
measurement from Session 059 with GPT-4o and Gemini 2.5 Pro, then compare
against the Sonnet 4.6 baseline (narrow: 0/98 fires, LLM-path: 73/98
diverge at Architect layer).

The .env at repo root is UTF-16 LE (Windows Notepad default). This script
loads it into os.environ before constructing any client.

Usage:
    # Pre-flight only (estimate cost for one provider):
    python scripts/run_session_075.py --provider openai --preflight-only

    # Full live run (after Dan's GO):
    python scripts/run_session_075.py --provider openai --confirm-live

    # Dry-run scaffold check:
    python scripts/run_session_075.py --provider openai --dry-run

    # Light pipeline only (cheaper — proves core narrow claim):
    python scripts/run_session_075.py --provider openai --confirm-live --light-only
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


def _format_preflight_summary(result: dict, provider: str, model: str) -> str:
    if result.get("status") == "no_samples":
        return (
            "Pre-flight produced zero successful samples. "
            "Halt recommended."
        )
    lines = [
        f"Pre-flight estimate ({provider} / {model}):",
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
            "Session 075 — Multi-model InfluenceLeakage validation. "
            "Runs the 98-pair measurement from S059 with a non-Anthropic provider."
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
        help="Run the 5-cycle pre-flight estimator and exit.",
    )
    parser.add_argument(
        "--confirm-live",
        action="store_true",
        help="Run the full live measurement after the pre-flight passes.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="No LLM calls. Verify anchor test is green and exit.",
    )
    parser.add_argument(
        "--light-only",
        action="store_true",
        help=(
            "Run only the light (deterministic) pipeline. Cheaper, and "
            "sufficient to prove the core narrow non-interference claim."
        ),
    )
    parser.add_argument(
        "--cost-ceiling",
        type=float,
        default=DEFAULT_COST_CEILING_USD,
        help=f"Cost ceiling in USD (default: {DEFAULT_COST_CEILING_USD}).",
    )
    args = parser.parse_args(argv)

    if args.cost_ceiling > DEFAULT_COST_CEILING_USD:
        print(
            f"[FATAL] cost_ceiling ${args.cost_ceiling} > pre-registered "
            f"${DEFAULT_COST_CEILING_USD}; refusing.",
            file=sys.stderr,
        )
        return 2

    # Load .env (UTF-16 LE)
    n_loaded = _load_env()
    print(f"[env] loaded {n_loaded} keys from .env (UTF-16 LE)")

    resolved_model = args.model or PROVIDER_DEFAULTS[args.provider]
    pipelines = ("light",) if args.light_only else ("llm", "light")

    print(f"[config] provider={args.provider}  model={resolved_model}  "
          f"pipelines={pipelines}  ceiling=${args.cost_ceiling}")

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

    config = RunnerConfig(
        cost_ceiling_usd=args.cost_ceiling,
        model=resolved_model,
        provider=args.provider,
        pipelines=pipelines,
    )

    # Pre-flight
    print(f"[2/3] Pre-flight estimator (5 light cycles, {args.provider}) ...")
    preflight = run_preflight(config=config)
    print(_format_preflight_summary(preflight, args.provider, resolved_model))

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
            "Pass --confirm-live to execute the live run."
        )
        return 0

    # Full live run
    n_cycles_est = 132 * len(pipelines)
    print(f"\n[3/3] LIVE MEASUREMENT RUN — ~{n_cycles_est} cycles "
          f"({args.provider} / {resolved_model}) ...")
    summary = run_full_measurement(config=config)

    print(f"\nprovider:         {summary.provider}")
    print(f"model:            {summary.model}")
    print(f"run_id:           {summary.run_id}")
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
