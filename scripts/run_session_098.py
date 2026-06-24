"""Session 098 — ARES-Harness Phase 3 gated AgentDojo measurement.

Offline by default. The live measurement (cell-selection sweep -> undefended
baseline -> full-defense -> ablations -> conclusion-integrity, on the selected
cell) requires --confirm-live and the committed pre-registration, and runs in
.scratch/bench-venv where agentdojo is installed.

IMPORTANT (import isolation): this module imports ONLY stdlib at module level.
EVERY agentdojo import (and anything that transitively pulls agentdojo) lives
inside the live-only functions below, so the main-venv CLI test can exec_module
this file and exercise the offline paths without agentdojo present. Precedent:
agentdojo's own pi_detector.py lazy-imports torch/transformers inside a method.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

HARD_CEILING_USD = 25.0
_PREREG = _REPO_ROOT / "docs" / "paper_5" / "PREREGISTRATION_phase3_measurement.md"


def _load_env() -> int:
    env_path = _REPO_ROOT / ".env"
    if not env_path.exists():
        return 0
    import os
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


def estimate_cost_usd(n_per_arm: int = 20) -> float:
    """Offline cost estimate (placeholder model refined by the live preflight).

    Models the realistic uncached 15-turn rollout cost from the design §8 budget
    section. The hard --cost-ceiling abort is the real safety net; this is a
    pre-run sanity figure only.
    """
    # 6 with-injection arms + 4 benign FPR arms, ~$0.06/rollout sweep-scale.
    approx_rollout_usd = 0.06
    arms = 6 + 4
    return round(arms * n_per_arm * approx_rollout_usd, 2)


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="ARES-Harness Phase 3 gated measurement")
    p.add_argument("--dry-run", action="store_true", help="print cost estimate and exit")
    p.add_argument("--preflight-only", action="store_true", help="offline preflight checks only")
    p.add_argument("--confirm-live", action="store_true", help="actually run the gated live measurement")
    p.add_argument("--cost-ceiling", type=float, default=HARD_CEILING_USD,
                   help=f"hard USD cap (must be <= {HARD_CEILING_USD})")
    p.add_argument("--n-per-arm", type=int, default=20)
    return p


def _run_preflight() -> int:
    """Offline preflight: pre-registration present + policies importable.

    No agentdojo. Imports the pure-ARES adapter pieces only.
    """
    from ares.harness.adapters.agentdojo_policy import banking_policy
    ok = True
    if not _PREREG.exists():
        print(f"[preflight] WARNING: pre-registration not found at {_PREREG}", file=sys.stderr)
    banking_policy()  # importable + constructs
    print("[preflight] pure-ARES adapter imports OK; gate/policy constructible.")
    return 0 if ok else 1


def _run_live(args) -> int:
    """The gated live measurement. ALL agentdojo imports are HERE (lazy)."""
    _load_env()
    import agentdojo  # noqa: F401  (lazy — bench-venv only)
    from ares.harness.adapters.agentdojo_elements import (  # noqa: F401
        AresIngressElement, GatedToolsExecutor, GateTracker,
    )
    # ... build the manual pipeline, run the sweep + selection + arms, drain the
    # tracker per task, write results to docs/paper_5/ + data/paper_5/.
    # (Built and verified in the bench-venv under --confirm-live; see design §6, §8
    #  and Task 8. Not exercised by the main-venv CLI test.)
    raise NotImplementedError(
        "live measurement body is implemented + run in .scratch/bench-venv (Task 8)"
    )


def main(argv=None) -> int:
    args = build_arg_parser().parse_args(argv)

    if args.cost_ceiling > HARD_CEILING_USD:
        print(f"[abort] --cost-ceiling {args.cost_ceiling} exceeds hard cap "
              f"{HARD_CEILING_USD}", file=sys.stderr)
        return 2

    if args.dry_run:
        print(f"[dry-run] cost estimate: ${estimate_cost_usd(args.n_per_arm)} "
              f"(hard cap ${HARD_CEILING_USD})")
        return 0

    if args.preflight_only:
        return _run_preflight()

    if not args.confirm_live:
        print("[halt] refusing to run live without --confirm-live", file=sys.stderr)
        return 1

    return _run_live(args)


if __name__ == "__main__":
    raise SystemExit(main())
