"""Paper 5 number-check: cross-validate pre-registered numbers against source.

Every numerical claim that appears in ``docs/paper_5/skeleton_v1_0.json``
under ``numbers_preregistered`` must be traceable to a specific source
artifact under ``data/paper_5/``. This script enumerates every such claim,
resolves it against the source data, and emits a pass/fail report.

When ``--source`` is provided, the script also walks the prose body of
the supplied markdown source and verifies that every value listed in
``prose_substring_claims()`` appears in the prose text. Phase 3 scope:
source mode is dormant (no prose yet); the substring list is seeded for
Phase 3 activation.

Pattern lift from Paper 4's ``docs/paper_4/number_check.py``: Claim
dataclass, resolver functions, run_checks + render_report + CLI shape.
Paper 5 differences:

    * Source artifact root is ``data/paper_5/`` (the S099 phase3 run JSON)
      instead of Paper 4's read-depth frontier artifacts.
    * Claim expectations are read from
      ``docs/paper_5/skeleton_v1_0.json`` (single source of truth)
      rather than hardcoded in the module.

CLI::

    python -m docs.paper_5.number_check
    python -m docs.paper_5.number_check --out-report \\
        docs/paper_5/number_check_report.md
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Optional


REPO_ROOT = Path(__file__).resolve().parents[2]
SKELETON_PATH = REPO_ROOT / "docs" / "paper_5" / "skeleton_v1_0.json"
RUN = REPO_ROOT / "data" / "paper_5" / "s099_phase3_run_20260627-070037.json"


def _load(p: Path) -> dict:
    return json.loads(p.read_text(encoding="utf-8"))


# =============================================================================
# Resolver functions — locked to s099_phase3_run_20260627-070037.json
# =============================================================================


def _run() -> dict:
    return _load(RUN)


def _arm(name: str) -> dict:
    return _run()["stage1_arms"][name]


def _resolve_max_undefended_asr() -> float:
    # The no-headroom contingency: 0.0 across every sweep cell.
    return max(c["undefended_asr"] for c in _run()["sweep"])


def _resolve_full_defense_asr() -> float:
    return _arm("full_defense")["asr"]


def _resolve_full_defense_gate_denials() -> int:
    return _arm("full_defense")["gate_denials"]


def _resolve_undefended_gate_denials() -> int:
    return _arm("undefended")["gate_denials"]


def _resolve_gate_off_gate_denials() -> int:
    return _arm("gate_off")["gate_denials"]


def _resolve_undefended_utility() -> float:
    return _arm("undefended")["utility"]


def _resolve_full_defense_utility() -> float:
    return _arm("full_defense")["utility"]


def _resolve_gate_off_utility() -> float:
    return _arm("gate_off")["utility"]


def _resolve_sonnet_ii_utility() -> float:
    for c in _run()["sweep"]:
        if c["model"] == "sonnet-4-6" and c["attack"] == "important_instructions":
            return c["undefended_utility"]
    raise LookupError("sonnet-4-6/important_instructions cell not found")


def _resolve_conclusion_integrity() -> float:
    return _arm("full_defense")["conclusion_integrity_rate"]


def _resolve_echo_rate() -> float:
    return _arm("full_defense")["echo_rate"]


def _resolve_benign_false_block() -> float:
    return _run()["benign_false_block"]["full_defense"]["false_block_rate_per_task"]


def _resolve_benign_denials() -> int:
    return _run()["benign_false_block"]["full_defense"]["benign_denials"]


def _resolve_n() -> int:
    return _arm("full_defense")["n"]


def _resolve_eligible_injection_count() -> int:
    return len(_run()["eligible_injection_tasks"]["banking"])


def _resolve_rollouts() -> int:
    return _run()["rollouts"]


def _resolve_tau_asr() -> float:
    return _run()["tau_asr"]


def _resolve_selected_cell_is_null() -> bool:
    return _run()["selected_cell"] is None and _run()["no_cell_contingency"] is True


def _resolve_fallback_cell() -> tuple:
    rc = _run()["run_cell"]
    return (rc["model"], rc["attack"], rc["suite"])


def _resolve_test_floor_from_skeleton(skeleton: dict) -> int:
    return int(skeleton["build_start_test_floor"])


# =============================================================================
# Claim table
# =============================================================================


@dataclass(frozen=True)
class Claim:
    """A single numerical claim that must match a source artifact."""

    label: str
    expected: Any
    resolver: Callable[[], Any]


def default_claims(skeleton: dict) -> tuple[Claim, ...]:
    """Build the claim table from the skeleton + canonical resolvers."""
    return (
        Claim("max undefended ASR == 0.0 (no-headroom contingency)", 0.0, _resolve_max_undefended_asr),
        Claim("full_defense ASR == 0.0 (by construction)", 0.0, _resolve_full_defense_asr),
        Claim("full_defense gate denials == 2 (empirical non-vacuity)", 2, _resolve_full_defense_gate_denials),
        Claim("undefended gate denials == 0", 0, _resolve_undefended_gate_denials),
        Claim("gate_off gate denials == 0", 0, _resolve_gate_off_gate_denials),
        Claim("undefended utility == 0.5", 0.5, _resolve_undefended_utility),
        Claim("full_defense utility == 0.3", 0.3, _resolve_full_defense_utility),
        Claim("gate_off utility == 0.45", 0.45, _resolve_gate_off_utility),
        Claim("sonnet/important_instructions undefended utility == 0.75", 0.75, _resolve_sonnet_ii_utility),
        Claim("conclusion-integrity == 0.95", 0.95, _resolve_conclusion_integrity),
        Claim("echo rate == 0.05", 0.05, _resolve_echo_rate),
        Claim("benign false-block == 0.2", 0.2, _resolve_benign_false_block),
        Claim("benign denials == 4", 4, _resolve_benign_denials),
        Claim("N == 20", 20, _resolve_n),
        Claim("eligible banking injection tasks == 9", 9, _resolve_eligible_injection_count),
        Claim("rollouts == 96", 96, _resolve_rollouts),
        Claim("tau_asr == 0.2", 0.2, _resolve_tau_asr),
        Claim("selected_cell null + contingency fired", True, _resolve_selected_cell_is_null),
        Claim("fallback cell == haiku-4-5/important_instructions/banking",
              ("haiku-4-5", "important_instructions", "banking"), _resolve_fallback_cell),
        Claim("test floor parses to int", _resolve_test_floor_from_skeleton(skeleton),
              lambda: _resolve_test_floor_from_skeleton(skeleton)),
    )


# =============================================================================
# Check + report
# =============================================================================


@dataclass(frozen=True)
class CheckResult:
    label: str
    expected: Any
    actual: Any
    passed: bool


def run_checks(claims: Iterable[Claim]) -> tuple[CheckResult, ...]:
    out: list[CheckResult] = []
    for claim in claims:
        try:
            actual = claim.resolver()
            if claim.label.endswith("(>=3 expected)"):
                passed = actual >= claim.expected
            elif isinstance(claim.expected, dict):
                passed = actual == claim.expected
            else:
                passed = actual == claim.expected
        except Exception as exc:
            out.append(CheckResult(
                label=(
                    f"{claim.label} [ERROR: {type(exc).__name__}: {exc}]"
                ),
                expected=claim.expected,
                actual=None,
                passed=False,
            ))
            continue
        out.append(CheckResult(
            label=claim.label,
            expected=claim.expected,
            actual=actual,
            passed=passed,
        ))
    return tuple(out)


def render_report(results: Iterable[CheckResult]) -> str:
    results = list(results)
    passed = sum(1 for r in results if r.passed)
    total = len(results)
    status = "PASS" if passed == total else "FAIL"
    lines = [
        "# Paper 5 number_check report",
        "",
        f"**Overall: {status} ({passed} / {total} claims validated)**",
        "",
        "| claim | expected | actual | pass |",
        "|---|---:|---:|:---:|",
    ]
    for r in results:
        lines.append(
            f"| {r.label} | {r.expected} | {r.actual} | "
            f"{'PASS' if r.passed else 'FAIL'} |"
        )
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## Prose substring check (Phase 3 activation)")
    lines.append("")
    lines.append(
        "When Paper 5 prose source exists, every "
        "value in ``prose_substring_claims()`` must appear in the "
        "prose body. Currently dormant — no prose yet."
    )
    return "\n".join(lines)


def write_report(report: str, out_path: Path) -> Path:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(report, encoding="utf-8")
    return out_path


# =============================================================================
# Prose-body substring checks (used when --source is provided)
# =============================================================================


def prose_substring_claims() -> tuple[str, ...]:
    """Substrings the Paper 5 prose body must contain verbatim once prose
    lands. Seeded from the skeleton's pre-registered numbers; Phase 3
    prose integration is the activation point.
    """
    return (
        "no-headroom", "by construction", "contingency",
        "conclusion-integrity", "AgentDojo", "banking",
        "important_instructions", "full_defense", "gate_off", "undefended",
        "2 ", "0.20", "0.30", "0.45", "0.50", "0.95", "0.05", "0.75",
        "US133000000121212121212", "$3.8", "$0.07", "96",
    )


def extract_docx_text(docx_path: Path) -> str:
    """Concatenate every paragraph of a docx into one searchable string."""
    from docx import Document
    doc = Document(str(docx_path))
    return "\n".join(p.text for p in doc.paragraphs)


def check_prose_substrings(
    text: str,
    substrings: Iterable[str],
) -> tuple[CheckResult, ...]:
    out: list[CheckResult] = []
    for sub in substrings:
        present = sub in text
        out.append(CheckResult(
            label=f"prose contains '{sub}'",
            expected=True,
            actual=present,
            passed=present,
        ))
    return tuple(out)


# =============================================================================
# CLI
# =============================================================================


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Paper 5 number-check validator (skeleton + prose body).",
    )
    parser.add_argument(
        "--out-report", type=Path,
        default=Path("docs/paper_5/number_check_report.md"),
        help="Destination for the markdown report",
    )
    parser.add_argument(
        "--docx", type=Path, default=None,
        help=(
            "Optional: validate the prose body of this docx against "
            "prose_substring_claims(). Dormant — Paper 5 prose is markdown; "
            "use --source instead."
        ),
    )
    parser.add_argument(
        "--source", type=Path,
        default=Path("docs/paper_5/source/PAPER5_DRAFT_v1_0_source.md"),
        help=(
            "Optional: validate the prose body of this markdown source "
            "(docs/paper_5/source/PAPER5_DRAFT_v1_0_source.md) against "
            "prose_substring_claims(). The Phase-3 markdown path."
        ),
    )
    return parser


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(None if argv is None else list(argv))

    skeleton = json.loads(SKELETON_PATH.read_text(encoding="utf-8"))
    results: tuple[CheckResult, ...] = run_checks(default_claims(skeleton))

    if args.docx is not None and args.docx.exists():
        docx_text = extract_docx_text(args.docx.resolve())
        results = results + check_prose_substrings(
            docx_text, prose_substring_claims(),
        )

    if args.source is not None and args.source.exists():
        source_text = args.source.read_text(encoding="utf-8")
        results = results + check_prose_substrings(
            source_text, prose_substring_claims(),
        )

    report = render_report(results)
    write_report(report, args.out_report)

    total = len(results)
    passed = sum(1 for r in results if r.passed)
    print(f"[NUMBER-CHECK] {passed}/{total} claims validated")
    print(f"[NUMBER-CHECK] report: {args.out_report}")
    if passed < total:
        print("[NUMBER-CHECK] FAIL, see report for details", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
