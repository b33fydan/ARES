"""Session 088 — Read-depth frontier Phase C: tier-4 LLM anchor + verdict.

Mirrors run_session_084.py: UTF-16 .env load, preflight -> --confirm-live gate,
$15 hard cap. Offline by default (--dry-run prints the cost estimate). The live
run requires --confirm-live and the committed pre-registration doc.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

_PREREG = _REPO_ROOT / "docs" / "paper_4" / "PREREGISTRATION_read_depth_frontier_phase_c.md"


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
                import os
                os.environ[key.strip()] = value.strip()
                loaded += 1
    return loaded


def main(argv=None) -> int:
    from ares.dialectic.measurement.read_depth_tier4_anchor import (
        Tier4Config, estimate_cost_usd, run_tier4_anchor, make_live_cycle_fn,
    )
    from ares.dialectic.measurement.read_depth_tier4_schema import (
        READ_DEPTH_TIER4_HARD_CEILING_USD,
    )
    p = argparse.ArgumentParser(description="Session 088 — read-depth Phase C anchor")
    p.add_argument("--provider", required=True)
    p.add_argument("--model", default="claude-sonnet-4-20250514")
    p.add_argument("--k", type=int, default=20)
    p.add_argument("--cost-ceiling", type=float, default=15.0)
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--preflight-only", action="store_true")
    p.add_argument("--confirm-live", action="store_true")
    args = p.parse_args(argv)

    if args.cost_ceiling > READ_DEPTH_TIER4_HARD_CEILING_USD:
        print(f"[FATAL] cost_ceiling ${args.cost_ceiling} > hard cap "
              f"${READ_DEPTH_TIER4_HARD_CEILING_USD}; refusing.", file=sys.stderr)
        return 2

    cfg = Tier4Config(k_resamples=args.k, model=args.model, provider=args.provider)
    est = estimate_cost_usd(cfg)
    print(f"[preflight] cost estimate ${est} (ceiling ${args.cost_ceiling})")

    if args.dry_run or args.preflight_only:
        return 0
    if not args.confirm_live:
        print("[halt] live run needs --confirm-live", file=sys.stderr)
        return 1
    if not _PREREG.is_file():
        print("[halt] pre-registration doc missing; commit it first.", file=sys.stderr)
        return 1
    if est > args.cost_ceiling:
        print(f"[halt] estimate ${est} exceeds ceiling ${args.cost_ceiling}", file=sys.stderr)
        return 1

    print(f"[env] loaded {_load_env()} keys from .env (UTF-16 LE)")
    summary = run_tier4_anchor(cfg, cycle_fn=make_live_cycle_fn(cfg))
    out_dir = _REPO_ROOT / "data" / "paper_4" / "read_depth_frontier"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "tier4_summary.json").write_text(summary.to_json(), encoding="utf-8")
    print(f"[done] spent ${summary.total_cost_usd}; wrote tier4_summary.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
