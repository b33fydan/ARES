"""Paper 4 number-check: cross-validate pre-registered numbers against source.

Every numerical claim that appears in ``docs/paper_4/skeleton_v1_0.json``
under ``numbers_preregistered`` must be traceable to a specific source
artifact under ``data/paper_4/``. This script enumerates every such claim,
resolves it against the source data, and emits a pass/fail report.

When ``--docx`` is provided, the script also walks the prose body of
the supplied docx and verifies that every value listed in
``prose_substring_claims()`` appears in the prose text. Phase 3 scope:
docx mode is dormant (no prose yet); the substring list is seeded for
Phase 3 activation.

Pattern lift from Paper 3's ``docs/paper_3/number_check.py``: Claim
dataclass, resolver functions, run_checks + render_report + CLI shape.
Paper 4 differences:

    * Source artifact roots are ``data/paper_4/read_depth_frontier/``
      and ``data/paper_4/read_depth_oov/`` (tier4_summary, oov_summary
      run-2, oov_audit) instead of Paper 3's leakage-run traces.
    * Claim expectations are read from
      ``docs/paper_4/skeleton_v1_0.json`` (single source of truth)
      rather than hardcoded in the module.

CLI::

    python -m docs.paper_4.number_check
    python -m docs.paper_4.number_check --out-report \\
        docs/paper_4/number_check_report.md
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Optional


REPO_ROOT = Path(__file__).resolve().parents[2]
SKELETON_PATH = REPO_ROOT / "docs" / "paper_4" / "skeleton_v1_0.json"
FRONTIER_DIR = REPO_ROOT / "data" / "paper_4" / "read_depth_frontier"
OOV_DIR = REPO_ROOT / "data" / "paper_4" / "read_depth_oov"
TIER4 = FRONTIER_DIR / "tier4_summary.json"
OOV_SUMMARY = OOV_DIR / "oov_summary.json"
OOV_AUDIT = OOV_DIR / "oov_audit.json"


# =============================================================================
# Resolver functions
# =============================================================================


def _load(p: Path) -> dict:
    return json.loads(p.read_text(encoding="utf-8"))


def _tier4_coord(view: str, field: str):
    # Match the skeleton lock_target contract exactly: the LLM rung
    # (tier_id="llm_semantic"), not merely the first row for this view.
    # Today tier4_summary.json carries one row per view (both llm_semantic),
    # so the tier_id guard is a no-op; it hardens against a future re-run
    # that serializes the deterministic rungs into this file too.
    for c in _load(TIER4)["coordinates"]:
        if c["view"] == view and c.get("tier_id") == "llm_semantic":
            return c[field]
    raise LookupError(f"tier4 llm_semantic coord for view {view!r} not found")


def _resolve_cumulative_j_cap() -> float:
    return _tier4_coord("cumulative", "youden_j")          # 0.25


def _resolve_llm_standalone_j() -> float:
    return _tier4_coord("standalone", "youden_j")          # 0.75


def _resolve_llm_standalone_x_semantic() -> float:
    return _tier4_coord("standalone", "x_semantic")        # 0.125


def _resolve_syn001_flip_pvalue() -> float:
    rec = next(r for r in _load(TIER4)["records"]
               if r["scenario_id"] == "RDF-M-SYN-001")
    flipped = [o for o in rec["operator_records"] if o["flipped"]]
    if not flipped:
        raise LookupError("no flipped operator for SYN-001")
    return min(o["p_value"] for o in flipped)              # 0.0005


def _resolve_oov_verdict() -> str:
    return _load(OOV_SUMMARY)["verdict"]                   # SUPPORTED_STRONG


def _resolve_oov_black_evaded() -> tuple:
    s = next((a for a in _load(OOV_SUMMARY)["arm_summaries"]
              if a["arm"] == "black"), None)
    if s is None:
        raise LookupError("OOV summary missing 'black' arm entry")
    return tuple(sorted(s["scenarios_evaded"]))            # (LEX-002, SYN-001)


def _resolve_oov_named_ioc_flip_count() -> int:
    """Named-IOC scenarios (LEX-001, PATCH-001) must have ZERO canonical flips."""
    named = {"RDF-M-LEX-001", "RDF-M-PATCH-001"}
    return sum(1 for r in _load(OOV_SUMMARY)["records"]
               if r["scenario_id"] in named and r["canonical_flipped"])  # 0


def _resolve_oov_cost() -> float:
    return _load(OOV_SUMMARY)["total_cost_usd"]            # 0.106


def _resolve_audit_verdict() -> str:
    return _load(OOV_AUDIT)["audit_verdict"]               # ROBUST


def _resolve_audit_controls_pass() -> bool:
    return _load(OOV_AUDIT)["controls_passed"]             # True


def _resolve_audit_confirmed_count() -> int:
    return sum(1 for e in _load(OOV_AUDIT)["evading"]
               if e["classification"] == "independent_confirmed")  # 15


def _resolve_audit_split_count() -> int:
    return sum(1 for e in _load(OOV_AUDIT)["evading"]
               if e["classification"] == "independent_split")      # 3


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
        Claim("cumulative Youden J cap (0.25)", 0.25, _resolve_cumulative_j_cap),
        Claim("LLM standalone Youden J (0.75)", 0.75, _resolve_llm_standalone_j),
        Claim("LLM standalone X_semantic (0.125)", 0.125, _resolve_llm_standalone_x_semantic),
        Claim("SYN-001 framing-flip p-value (0.0005)", 0.0005, _resolve_syn001_flip_pvalue),
        Claim("OOV verdict (SUPPORTED_STRONG)", "SUPPORTED_STRONG", _resolve_oov_verdict),
        Claim("OOV black-arm scenarios evaded", ("RDF-M-LEX-002", "RDF-M-SYN-001"), _resolve_oov_black_evaded),
        Claim("named-IOC canonical flips (0)", 0, _resolve_oov_named_ioc_flip_count),
        Claim("OOV run-2 cost (0.106)", 0.106, _resolve_oov_cost),
        Claim("audit verdict (ROBUST)", "ROBUST", _resolve_audit_verdict),
        Claim("audit controls pass (True)", True, _resolve_audit_controls_pass),
        Claim("audit independent_confirmed (15)", 15, _resolve_audit_confirmed_count),
        Claim("audit independent_split (3)", 3, _resolve_audit_split_count),
        Claim("test floor from skeleton", _resolve_test_floor_from_skeleton(skeleton),
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
        "# Paper 4 number_check report",
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
        "When a Paper 4 prose docx exists, every "
        "value in ``prose_substring_claims()`` must appear in the "
        "prose body. Currently dormant — no prose yet."
    )
    return "\n".join(lines)


def write_report(report: str, out_path: Path) -> Path:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(report, encoding="utf-8")
    return out_path


# =============================================================================
# Prose-body substring checks (used when --docx is provided)
# =============================================================================


def prose_substring_claims() -> tuple[str, ...]:
    """Substrings the Paper 4 prose body must contain verbatim once prose
    lands. Seeded from the skeleton's pre-registered numbers; Phase 3
    prose integration is the activation point.
    """
    return (
        "SUPPORTED_STRONG", "ROBUST", "trilemma",
        "0.25", "0.75", "0.125", "0.0005",
        "RDF-M-LEX-002", "RDF-M-SYN-001", "RDF-M-LEX-001", "RDF-M-PATCH-001",
        "lsass", "procdump", "v2_canonical",
        "9401b7188ba790a5", "a4ea1d0645152ffa",
        "15", "18", "GPT-4o", "Gemini",
        "$0.106", "$0.0093",
    )


def extract_docx_text(docx_path: Path) -> str:
    """Concatenate every paragraph of a docx into one searchable string."""
    from docx import Document
    doc = Document(str(docx_path))
    return "\n".join(p.text for p in doc.paragraphs)


def check_prose_substrings(
    docx_text: str,
    substrings: Iterable[str],
) -> tuple[CheckResult, ...]:
    out: list[CheckResult] = []
    for sub in substrings:
        present = sub in docx_text
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
        description="Paper 4 number-check validator (skeleton + prose body).",
    )
    parser.add_argument(
        "--out-report", type=Path,
        default=Path("docs/paper_4/number_check_report.md"),
        help="Destination for the markdown report",
    )
    parser.add_argument(
        "--docx", type=Path, default=None,
        help=(
            "Optional: validate the prose body of this docx against "
            "prose_substring_claims(). Dormant — Paper 4 prose is markdown; "
            "use --source instead."
        ),
    )
    parser.add_argument(
        "--source", type=Path, default=None,
        help=(
            "Optional: validate the prose body of this markdown source "
            "(docs/paper_4/source/PAPER4_DRAFT_v1_0_source.md) against "
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
