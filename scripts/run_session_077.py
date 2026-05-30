"""Session 077 — Architect-path framing-sensitivity measurement CLI.

Mirrors run_session_075.py: UTF-16 .env load, anchor guard, preflight ->
--confirm-live gate, cost-ceiling hard cap.
"""
from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


def _load_env() -> int:
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
            if key.strip() and value.strip():
                os.environ[key.strip()] = value.strip()
                loaded += 1
    return loaded


from ares.dialectic.agents.strategies.client_factory import PROVIDER_DEFAULTS, VALID_PROVIDERS
from ares.dialectic.measurement.architect_framing_schema import (
    ArchitectFramingConfig, ARCHITECT_FRAMING_HARD_CEILING_USD,
)
from ares.dialectic.measurement.architect_framing_runner import run_measurement, run_preflight
from ares.dialectic.measurement.architect_framing_report import write_report
from ares.dialectic.measurement.architect_framing_selection import select_diverging_scenarios
from ares.dialectic.measurement.leakage_runner import DEFAULT_TRACES_ROOT, anchor_test_passes

_DEFAULT_S059 = DEFAULT_TRACES_ROOT / "20260510-193950-f401a8" / "traces.jsonl"


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s :: %(message)s",
                        datefmt="%H:%M:%S")
    p = argparse.ArgumentParser(description="Session 077 — Architect framing measurement")
    p.add_argument("--provider", required=True, choices=sorted(VALID_PROVIDERS))
    p.add_argument("--model", default=None)
    p.add_argument("--k", type=int, default=8)
    p.add_argument("--max-scenarios", type=int, default=6)
    p.add_argument("--s059-traces", default=str(_DEFAULT_S059))
    p.add_argument("--cost-ceiling", type=float, default=6.0)
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--preflight-only", action="store_true")
    p.add_argument("--confirm-live", action="store_true")
    args = p.parse_args(argv)

    if args.cost_ceiling > ARCHITECT_FRAMING_HARD_CEILING_USD:
        print(f"[FATAL] cost_ceiling ${args.cost_ceiling} > hard cap "
              f"${ARCHITECT_FRAMING_HARD_CEILING_USD}; refusing.", file=sys.stderr)
        return 2

    print(f"[env] loaded {_load_env()} keys from .env (UTF-16 LE)")
    model = args.model or PROVIDER_DEFAULTS[args.provider]

    print("[1/3] anchor-test guard ...")
    if not anchor_test_passes():
        print("[FATAL] anchor test RED; halting before spend.", file=sys.stderr)
        return 3
    print("       anchor green [ok]")

    if args.dry_run:
        print("[done] dry run complete; anchor green; no LLM calls made.")
        return 0

    sids = tuple(select_diverging_scenarios(Path(args.s059_traces)))
    cfg = ArchitectFramingConfig(
        s059_traces_path=Path(args.s059_traces), scenario_ids=sids, k_resamples=args.k,
        max_scenarios=args.max_scenarios, model=model, provider=args.provider,
        cost_ceiling_usd=args.cost_ceiling,
    )
    print(f"[config] provider={args.provider} model={model} k={args.k} "
          f"scenarios={len(sids)} (cap {args.max_scenarios}) ceiling=${args.cost_ceiling}")

    from ares.dialectic.agents.strategies.client_factory import make_client
    client = make_client(args.provider, model=model)

    print("[2/3] pre-flight estimator ...")
    pf = run_preflight(config=cfg, client=client)
    print(f"   est total: ${pf.get('estimated_total_cost_usd')}  "
          f"cycles: {pf.get('n_cycles')}  exceeds_ceiling: {pf.get('exceeds_ceiling')}")
    if pf.get("exceeds_ceiling"):
        print("[HALT] preflight exceeds ceiling; live run not initiated.", file=sys.stderr)
        return 4

    if args.preflight_only or not args.confirm_live:
        print("[done] pre-flight complete. Pass --confirm-live to run.")
        return 0

    print("[3/3] LIVE measurement ...")
    summary = run_measurement(config=cfg, client=client)
    report = write_report(summary)
    print(f"control_valid: {summary.control_valid}  cost: ${summary.total_cost_usd:.2f}")
    print(f"report: {report}")
    print(f"traces: {summary.traces_path}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
