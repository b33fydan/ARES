"""Session 089 — OOV adversarial evasion experiment (read-depth Phase D).

Mirrors run_session_088.py: UTF-16 .env load, preflight -> --confirm-live gate,
$10 hard cap, pre-registration-file gate. Offline by default (--dry-run prints
the cost estimate). The live run requires --confirm-live and the committed
pre-registration.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

_PREREG = _REPO_ROOT / "docs" / "paper_4" / "PREREGISTRATION_oov_evasion_phase_d.md"


def _load_env() -> int:
    env_path = _REPO_ROOT / ".env"
    if not env_path.exists():
        return 0
    with open(env_path, "r", encoding="utf-16") as f:
        content = f.read()
    loaded = 0
    import os
    for line in content.strip().splitlines():
        line = line.strip()
        if "=" in line and not line.startswith("#"):
            key, _, value = line.partition("=")
            if key.strip() and value.strip():
                os.environ[key.strip()] = value.strip()
                loaded += 1
    return loaded


def write_verdict_artifacts(out_dir: Path, summary, disguises) -> None:
    """Write the verdict (oov_summary.json + oov_report.md) plus the new
    audit sidecar (oov_disguises.json) carrying every candidate's disguise."""
    from ares.dialectic.measurement.read_depth_oov_report import render_oov_report
    from ares.dialectic.measurement.read_depth_oov_audit import dump_disguises
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "oov_summary.json").write_text(summary.to_json(), encoding="utf-8")
    (out_dir / "oov_report.md").write_text(
        render_oov_report(summary), encoding="utf-8")
    header = {"corpus_digest": summary.corpus_digest,
              "oov_corpus_digest": summary.oov_corpus_digest,
              "model": summary.model, "provider": summary.provider,
              "k": summary.k, "verdict": summary.verdict}
    (out_dir / "oov_disguises.json").write_text(
        dump_disguises(header, disguises), encoding="utf-8")


def main(argv=None) -> int:
    from ares.dialectic.measurement.read_depth_oov_schema import (
        ARM_BLACK, ARM_WHITE, ARMS, READ_DEPTH_OOV_HARD_CEILING_USD,
    )
    from ares.dialectic.measurement.read_depth_oov_runner import (
        OOVConfig, estimate_cost_usd, run_oov_experiment_audited,
    )
    p = argparse.ArgumentParser(description="Session 089 — OOV evasion (Phase D)")
    p.add_argument("--provider", required=True)
    p.add_argument("--model", default="claude-sonnet-4-20250514")
    p.add_argument("--k", type=int, default=8)
    p.add_argument("--arm", choices=["black", "white", "both"], default="both")
    p.add_argument("--cost-ceiling", type=float, default=10.0)
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--preflight-only", action="store_true")
    p.add_argument("--confirm-live", action="store_true")
    args = p.parse_args(argv)

    if args.cost_ceiling > READ_DEPTH_OOV_HARD_CEILING_USD:
        print(f"[FATAL] cost_ceiling ${args.cost_ceiling} > hard cap "
              f"${READ_DEPTH_OOV_HARD_CEILING_USD}; refusing.", file=sys.stderr)
        return 2

    arms = ARMS if args.arm == "both" else (
        ARM_BLACK if args.arm == "black" else ARM_WHITE,)
    cfg = OOVConfig(k=args.k, model=args.model, provider=args.provider, arms=arms,
                    cost_ceiling_usd=args.cost_ceiling)
    est = estimate_cost_usd(cfg)
    print(f"[preflight] cost estimate ${est} (ceiling ${args.cost_ceiling})")

    if args.dry_run or args.preflight_only:
        return 0
    if not args.confirm_live:
        print("[halt] live run needs --confirm-live", file=sys.stderr)
        return 1
    if not _PREREG.is_file():
        print("[halt] pre-registration doc missing; commit it first.",
              file=sys.stderr)
        return 1
    if est > args.cost_ceiling:
        print(f"[halt] estimate ${est} exceeds ceiling ${args.cost_ceiling}",
              file=sys.stderr)
        return 1

    print(f"[env] loaded {_load_env()} keys from .env (UTF-16 LE)")
    from ares.dialectic.measurement.read_depth_oov_generator import (
        make_live_generate_fn,
    )
    from ares.dialectic.measurement.read_depth_oov_validator import (
        make_live_judge_fn,
    )
    summary, disguises = run_oov_experiment_audited(
        cfg, generate_fn=make_live_generate_fn(args.model, args.provider),
        judge_fn=make_live_judge_fn(args.model, args.provider))
    out_dir = _REPO_ROOT / "data" / "paper_4" / "read_depth_oov"
    write_verdict_artifacts(out_dir, summary, disguises)
    print(f"[done] verdict {summary.verdict}; spent ${summary.total_cost_usd}; "
          f"wrote oov_summary.json + oov_report.md + oov_disguises.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
