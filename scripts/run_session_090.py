# scripts/run_session_090.py
"""Session 090 — OOV evasion judge-robustness AUDIT (read-depth Phase E).

Reads the oov_disguises.json sidecar from the verdict re-run, re-judges the
evading disguises + calibration controls with an independent panel (default
GPT-4o + Gemini), applies the pre-registered Phase E rule, and writes
oov_audit.json + oov_audit_report.md. Mirrors run_session_089: UTF-16 .env,
preflight -> --confirm-live gate, $10 hard cap, pre-registration-file gate.
Offline by default (--dry-run prints the cost estimate).
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

_PREREG = _REPO_ROOT / "docs" / "paper_4" / "PREREGISTRATION_oov_audit_phase_e.md"
_DEFAULT_SIDECAR = (_REPO_ROOT / "data" / "paper_4" / "read_depth_oov"
                    / "oov_disguises.json")


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


def _parse_judges(spec: str):
    """'openai,gemini' or 'openai:gpt-4o,gemini:gemini-2.5-pro' -> [(provider, model)]."""
    out = []
    for tok in spec.split(","):
        tok = tok.strip()
        if not tok:
            continue
        provider, _, model = tok.partition(":")
        out.append((provider.strip(), model.strip()))
    return out


def main(argv=None) -> int:
    from ares.dialectic.measurement.read_depth_oov_schema import (
        READ_DEPTH_OOV_HARD_CEILING_USD,
    )
    from ares.dialectic.measurement.read_depth_oov_audit import (
        load_disguises, run_audit_preflight,
    )
    p = argparse.ArgumentParser(description="Session 090 — OOV judge audit (Phase E)")
    p.add_argument("--judges", default="openai,gemini")
    p.add_argument("--sidecar", default=str(_DEFAULT_SIDECAR))
    p.add_argument("--cost-ceiling", type=float, default=10.0)
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--preflight-only", action="store_true")
    p.add_argument("--confirm-live", action="store_true")
    args = p.parse_args(argv)

    if args.cost_ceiling > READ_DEPTH_OOV_HARD_CEILING_USD:
        print(f"[FATAL] cost_ceiling ${args.cost_ceiling} > hard cap "
              f"${READ_DEPTH_OOV_HARD_CEILING_USD}; refusing.", file=sys.stderr)
        return 2

    judges = _parse_judges(args.judges)
    sidecar = Path(args.sidecar)
    if not sidecar.is_file():
        print(f"[halt] sidecar {sidecar} not found; run the verdict re-run "
              f"(run_session_089 --confirm-live) first.", file=sys.stderr)
        return 1
    header, records = load_disguises(sidecar.read_text(encoding="utf-8"))
    pf = run_audit_preflight(records, tuple(lbl for lbl, _ in judges))
    print(f"[preflight] cost estimate ${pf['estimate_usd']} "
          f"(ceiling ${args.cost_ceiling}); evading={pf['n_evading']} "
          f"pos={pf['n_pos_controls']} neg={pf['n_neg_controls']}")

    if args.dry_run or args.preflight_only:
        return 0
    if not args.confirm_live:
        print("[halt] live run needs --confirm-live", file=sys.stderr)
        return 1
    if not _PREREG.is_file():
        print("[halt] Phase E pre-registration doc missing; commit it first.",
              file=sys.stderr)
        return 1
    if pf["estimate_usd"] > args.cost_ceiling:
        print(f"[halt] estimate ${pf['estimate_usd']} exceeds ceiling "
              f"${args.cost_ceiling}", file=sys.stderr)
        return 1

    print(f"[env] loaded {_load_env()} keys from .env (UTF-16 LE)")
    from ares.dialectic.measurement.read_depth_oov_audit import (
        make_audit_judge, run_audit, render_audit_report,
    )
    panel = tuple((prov, make_audit_judge(prov, model)) for prov, model in judges)
    summary = run_audit(records, panel, cost_ceiling_usd=args.cost_ceiling,
                        base_oov_corpus_digest=str(header.get("oov_corpus_digest", "")))
    out_dir = sidecar.parent
    (out_dir / "oov_audit.json").write_text(summary.to_json(), encoding="utf-8")
    (out_dir / "oov_audit_report.md").write_text(
        render_audit_report(summary), encoding="utf-8")
    print(f"[done] audit {summary.audit_verdict}; spent ${summary.total_cost_usd}; "
          f"wrote oov_audit.json + oov_audit_report.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
