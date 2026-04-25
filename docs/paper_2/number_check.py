"""Paper 2 number-check: cross-validate claims against source CSVs.

Every numerical claim that appears in a Paper 2 figure caption
(``make_figures.py`` docstrings), in the skeleton's caption stubs, or
in the v1.1 prose body must be traceable to a specific CSV or summary
file under ``results/``. This script enumerates every such claim,
resolves it against the source data, and emits a pass/fail report.
The script exits with a non-zero status if any claim fails.

The claim table is the single source of truth, new figures add new
rows; removed figures strike rows. Every row includes:

    * a short label (used in the report)
    * the expected numeric value (float or int)
    * the source file + extraction instructions (function reference)
    * the tolerance (relative or absolute)

When ``--docx`` is provided, the script also walks the prose body of
the supplied docx and verifies that every value listed in
``prose_substring_claims()`` appears in the prose text.

Callers can also pass a broken fixture via ``--override-claims``
to exercise the failure path during testing.

CLI:
    python -m docs.paper_2.number_check
    python -m docs.paper_2.number_check --results-root results/
    python -m docs.paper_2.number_check \\
        --docx docs/paper_2/PAPER2_DRAFT_v1_1.docx \\
        --out-report docs/paper_2/number_check_v1_1_report.md
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Optional


# =============================================================================
# Resolver functions — read one number out of a CSV / JSON source
# =============================================================================


def _session_048_json(results_root: Path) -> dict[str, Any]:
    path = results_root / "session_048" / "raw_results.json"
    return json.loads(path.read_text(encoding="utf-8"))


def _session_050_family_csv(results_root: Path) -> list[dict[str, str]]:
    path = results_root / "session_050" / "family_three_way.csv"
    with path.open("r", encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def _session_050_scenarios_csv(results_root: Path) -> list[dict[str, str]]:
    path = results_root / "session_050" / "three_way_delta.csv"
    with path.open("r", encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def _session_050_finding_11_md(results_root: Path) -> str:
    path = results_root / "session_050" / "finding_11_verdict.md"
    return path.read_text(encoding="utf-8")


def _parse_accuracy_from_md(text: str, label: str) -> float:
    for line in text.splitlines():
        stripped = line.strip().replace("*", "")
        if label.lower() in stripped.lower():
            for token in stripped.replace("|", " ").split():
                try:
                    return float(token)
                except ValueError:
                    continue
    raise LookupError(f"Could not find accuracy for '{label}' in Finding 11 md")


# =============================================================================
# Individual resolvers
# =============================================================================


def _resolve_s048_total_scenarios(results_root: Path) -> int:
    return int(_session_048_json(results_root)["total_scenarios"])


def _resolve_s048_category_count(results_root: Path, category: str) -> int:
    rows = _session_048_json(results_root)["results"]
    return sum(1 for r in rows if r["category"] == category)


def _resolve_s048_category_detection(results_root: Path, category: str) -> float:
    rows = [r for r in _session_048_json(results_root)["results"]
            if r["category"] == category]
    if not rows:
        return 0.0
    return sum(1 for r in rows if r["firewall_detected"]) / len(rows)


def _resolve_s048_category_accuracy(results_root: Path, category: str) -> float:
    rows = [r for r in _session_048_json(results_root)["results"]
            if r["category"] == category]
    if not rows:
        return 0.0
    return sum(
        1 for r in rows
        if r["actual_verdict"].strip().upper() ==
           r["expected_verdict"].strip().upper()
    ) / len(rows)


def _resolve_s050_family_n(results_root: Path, family: str) -> int:
    for row in _session_050_family_csv(results_root):
        if row["family"] == family:
            return int(row["n"])
    raise LookupError(f"Family '{family}' not found in s050 family CSV")


def _resolve_s050_family_accuracy(
    results_root: Path, family: str, variant: str,
) -> float:
    key = f"{variant}_acc"
    for row in _session_050_family_csv(results_root):
        if row["family"] == family:
            return float(row[key])
    raise LookupError(f"Family '{family}' not found in s050 family CSV")


def _resolve_s050_total_scenarios(results_root: Path) -> int:
    return len(_session_050_scenarios_csv(results_root))


def _resolve_s050_finding_11_light(results_root: Path) -> float:
    return _parse_accuracy_from_md(
        _session_050_finding_11_md(results_root),
        label="light framing accuracy",
    )


def _resolve_s050_finding_11_full(results_root: Path) -> float:
    return _parse_accuracy_from_md(
        _session_050_finding_11_md(results_root),
        label="full framing accuracy",
    )


def _resolve_s050_finding_11_ablated(results_root: Path) -> float:
    return _parse_accuracy_from_md(
        _session_050_finding_11_md(results_root),
        label="ablated framing accuracy",
    )


# =============================================================================
# Claim table
# =============================================================================


@dataclass(frozen=True)
class Claim:
    """A single numerical claim that must match a source file.

    Attributes:
        label: Short human-readable identifier used in the report.
        expected: The value asserted by the caption.
        resolver: Callable that returns the actual value given
            ``results_root``.
        tolerance: Absolute tolerance. Defaults to 1e-4 for floats, 0
            for integers (exact match).
    """

    label: str
    expected: float
    resolver: Callable[[Path], float]
    tolerance: float = 1e-4


# The canonical claim set is built from the caption stubs in Paper 2.
def default_claims() -> tuple[Claim, ...]:
    return (
        Claim(
            label="Session 048 total scenarios",
            expected=27,
            resolver=lambda root: _resolve_s048_total_scenarios(root),
            tolerance=0,
        ),
        Claim(
            label="Session 048 direct n",
            expected=4,
            resolver=lambda root: _resolve_s048_category_count(root, "direct"),
            tolerance=0,
        ),
        Claim(
            label="Session 048 framing n",
            expected=19,
            resolver=lambda root: _resolve_s048_category_count(root, "framing"),
            tolerance=0,
        ),
        Claim(
            label="Session 048 propagation n",
            expected=4,
            resolver=lambda root: _resolve_s048_category_count(
                root, "propagation",
            ),
            tolerance=0,
        ),
        Claim(
            label="Session 048 direct detection",
            expected=1.00,
            resolver=lambda root: _resolve_s048_category_detection(
                root, "direct",
            ),
            tolerance=1e-4,
        ),
        Claim(
            label="Session 048 framing detection",
            expected=0.00,
            resolver=lambda root: _resolve_s048_category_detection(
                root, "framing",
            ),
            tolerance=1e-4,
        ),
        Claim(
            label="Session 048 propagation detection",
            expected=0.75,
            resolver=lambda root: _resolve_s048_category_detection(
                root, "propagation",
            ),
            tolerance=1e-4,
        ),
        Claim(
            label="Session 048 direct accuracy",
            expected=0.75,
            resolver=lambda root: _resolve_s048_category_accuracy(root, "direct"),
            tolerance=1e-4,
        ),
        Claim(
            label="Session 048 framing accuracy",
            expected=0.7894736842105263,
            resolver=lambda root: _resolve_s048_category_accuracy(
                root, "framing",
            ),
            tolerance=1e-4,
        ),
        Claim(
            label="Session 048 propagation accuracy",
            expected=0.75,
            resolver=lambda root: _resolve_s048_category_accuracy(
                root, "propagation",
            ),
            tolerance=1e-4,
        ),
        Claim(
            label="Session 050 total scenarios",
            expected=25,
            resolver=lambda root: _resolve_s050_total_scenarios(root),
            tolerance=0,
        ),
        Claim(
            label="Session 050 temporal n",
            expected=5,
            resolver=lambda root: _resolve_s050_family_n(root, "temporal"),
            tolerance=0,
        ),
        Claim(
            label="Session 050 authority n",
            expected=6,
            resolver=lambda root: _resolve_s050_family_n(root, "authority"),
            tolerance=0,
        ),
        Claim(
            label="Session 050 temporal full accuracy",
            expected=1.0,
            resolver=lambda root: _resolve_s050_family_accuracy(
                root, "temporal", "full",
            ),
            tolerance=1e-4,
        ),
        Claim(
            label="Session 050 temporal light accuracy",
            expected=1.0,
            resolver=lambda root: _resolve_s050_family_accuracy(
                root, "temporal", "light",
            ),
            tolerance=1e-4,
        ),
        Claim(
            label="Session 050 Finding-11 light accuracy",
            expected=0.84,
            resolver=lambda root: _resolve_s050_finding_11_light(root),
            tolerance=1e-3,
        ),
        Claim(
            label="Session 050 Finding-11 full accuracy",
            expected=0.84,
            resolver=lambda root: _resolve_s050_finding_11_full(root),
            tolerance=1e-3,
        ),
        Claim(
            label="Session 050 Finding-11 ablated accuracy",
            expected=0.72,
            resolver=lambda root: _resolve_s050_finding_11_ablated(root),
            tolerance=1e-3,
        ),
        # === Per-family three-way cells (Section 7.3 of v1.1 prose) ===
        Claim(
            label="Session 050 severity n",
            expected=3,
            resolver=lambda root: _resolve_s050_family_n(root, "severity"),
            tolerance=0,
        ),
        Claim(
            label="Session 050 causal n",
            expected=3,
            resolver=lambda root: _resolve_s050_family_n(root, "causal"),
            tolerance=0,
        ),
        Claim(
            label="Session 050 narrative n",
            expected=4,
            resolver=lambda root: _resolve_s050_family_n(root, "narrative"),
            tolerance=0,
        ),
        Claim(
            label="Session 050 severity full accuracy",
            expected=1.0,
            resolver=lambda root: _resolve_s050_family_accuracy(
                root, "severity", "full",
            ),
            tolerance=1e-4,
        ),
        Claim(
            label="Session 050 severity light accuracy",
            expected=1.0,
            resolver=lambda root: _resolve_s050_family_accuracy(
                root, "severity", "light",
            ),
            tolerance=1e-4,
        ),
        Claim(
            label="Session 050 severity ablated accuracy",
            expected=0.6667,
            resolver=lambda root: _resolve_s050_family_accuracy(
                root, "severity", "ablated",
            ),
            tolerance=1e-3,
        ),
        Claim(
            label="Session 050 authority full accuracy",
            expected=0.8333,
            resolver=lambda root: _resolve_s050_family_accuracy(
                root, "authority", "full",
            ),
            tolerance=1e-3,
        ),
        Claim(
            label="Session 050 authority light accuracy",
            expected=0.8333,
            resolver=lambda root: _resolve_s050_family_accuracy(
                root, "authority", "light",
            ),
            tolerance=1e-3,
        ),
        Claim(
            label="Session 050 authority ablated accuracy",
            expected=0.8333,
            resolver=lambda root: _resolve_s050_family_accuracy(
                root, "authority", "ablated",
            ),
            tolerance=1e-3,
        ),
        Claim(
            label="Session 050 temporal ablated accuracy",
            expected=0.6,
            resolver=lambda root: _resolve_s050_family_accuracy(
                root, "temporal", "ablated",
            ),
            tolerance=1e-3,
        ),
        Claim(
            label="Session 050 causal full accuracy",
            expected=1.0,
            resolver=lambda root: _resolve_s050_family_accuracy(
                root, "causal", "full",
            ),
            tolerance=1e-4,
        ),
        Claim(
            label="Session 050 causal light accuracy",
            expected=1.0,
            resolver=lambda root: _resolve_s050_family_accuracy(
                root, "causal", "light",
            ),
            tolerance=1e-4,
        ),
        Claim(
            label="Session 050 causal ablated accuracy",
            expected=1.0,
            resolver=lambda root: _resolve_s050_family_accuracy(
                root, "causal", "ablated",
            ),
            tolerance=1e-4,
        ),
        Claim(
            label="Session 050 narrative full accuracy",
            expected=0.75,
            resolver=lambda root: _resolve_s050_family_accuracy(
                root, "narrative", "full",
            ),
            tolerance=1e-4,
        ),
        Claim(
            label="Session 050 narrative light accuracy",
            expected=0.75,
            resolver=lambda root: _resolve_s050_family_accuracy(
                root, "narrative", "light",
            ),
            tolerance=1e-4,
        ),
        Claim(
            label="Session 050 narrative ablated accuracy",
            expected=0.5,
            resolver=lambda root: _resolve_s050_family_accuracy(
                root, "narrative", "ablated",
            ),
            tolerance=1e-4,
        ),
    )


# =============================================================================
# Check + report
# =============================================================================


@dataclass(frozen=True)
class CheckResult:
    label: str
    expected: float
    actual: float
    tolerance: float
    passed: bool


def run_checks(
    claims: Iterable[Claim],
    results_root: Path,
) -> tuple[CheckResult, ...]:
    out: list[CheckResult] = []
    for claim in claims:
        try:
            actual = float(claim.resolver(results_root))
            diff = abs(actual - claim.expected)
            passed = diff <= claim.tolerance
        except Exception as exc:
            actual = float("nan")
            passed = False
            # embed the error label so it shows up in the report
            out.append(CheckResult(
                label=f"{claim.label} [ERROR: {type(exc).__name__}: {exc}]",
                expected=claim.expected,
                actual=actual,
                tolerance=claim.tolerance,
                passed=passed,
            ))
            continue
        out.append(CheckResult(
            label=claim.label,
            expected=claim.expected,
            actual=actual,
            tolerance=claim.tolerance,
            passed=passed,
        ))
    return tuple(out)


def render_report(results: Iterable[CheckResult]) -> str:
    lines = ["# Paper 2 number_check report", ""]
    results = list(results)
    passed = sum(1 for r in results if r.passed)
    total = len(results)
    status = "PASS" if passed == total else "FAIL"
    lines.append(f"**Overall: {status} ({passed} / {total} claims validated)**")
    lines.append("")
    lines.append("| claim | expected | actual | tol | pass |")
    lines.append("|---|---:|---:|---:|:---:|")
    for r in results:
        lines.append(
            f"| {r.label} | {r.expected} | "
            f"{r.actual} | {r.tolerance} | "
            f"{'✓' if r.passed else '✗'} |"
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
    """Substrings that the v1.1 docx body must contain verbatim.

    Each entry is a substring that, if missing from the prose, indicates
    the v1.1 build has lost a numerical claim relative to the source
    artifacts. Counts and INJ-IDs are checked here because they appear
    only in body prose, not in the figure captions.
    """
    return (
        # Corpus split. The prose enumerates the 27 = 4+19+4 split as
        # individual category phrases; we check those rather than the
        # arithmetic gloss. Bare "19" and "25" appear many times in the
        # body and are tracked as sanity floor.
        "27",          # total scenarios
        "19",          # framing for ablation
        "25",          # framing for three-way
        "4 direct",    # direct category sentence
        "19 framing",  # framing category sentence
        "4 propagation",  # propagation category sentence
        # Firewall detection (Findings 7 & 8).
        "0 of 19",     # framing detection
        "4 of 4",      # direct detection
        "3 of 4",      # propagation detection
        # Headline accuracies.
        "0.7895",      # Session 048 framing accuracy
        "0.8400",      # Session 050 full / light
        "0.7200",      # Session 050 ablated
        "21/25",       # full and light count form
        "18/25",       # ablated count form
        # INJ identifiers referenced in Findings 9, 10, 11.
        "INJ-006", "INJ-008", "INJ-014", "INJ-020",
        "INJ-024", "INJ-025", "INJ-027",
    )


def extract_docx_text(docx_path: Path) -> str:
    """Concatenate every paragraph of a docx into one searchable string."""
    from docx import Document  # local import to keep CSV-only mode dep-free
    doc = Document(str(docx_path))
    return "\n".join(p.text for p in doc.paragraphs)


def check_prose_substrings(
    docx_text: str,
    substrings: Iterable[str],
) -> tuple[CheckResult, ...]:
    """Return one CheckResult per substring (passed iff present in text)."""
    out: list[CheckResult] = []
    for sub in substrings:
        present = sub in docx_text
        out.append(CheckResult(
            label=f"prose contains '{sub}'",
            expected=1.0,
            actual=1.0 if present else 0.0,
            tolerance=0.0,
            passed=present,
        ))
    return tuple(out)


# =============================================================================
# CLI
# =============================================================================


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Paper 2 number-check validator (caption + prose body).",
    )
    parser.add_argument(
        "--results-root", type=Path, default=Path("results"),
        help="Root directory containing session_048/049/050 artifacts",
    )
    parser.add_argument(
        "--out-report", type=Path,
        default=Path("docs/paper_2/number_check_report.md"),
        help="Destination for the markdown report",
    )
    parser.add_argument(
        "--docx", type=Path, default=None,
        help=(
            "Optional: validate the prose body of this docx (typically "
            "PAPER2_DRAFT_v1_1.docx) against prose_substring_claims()."
        ),
    )
    return parser


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(None if argv is None else list(argv))

    results: tuple[CheckResult, ...] = run_checks(
        default_claims(), args.results_root,
    )

    if args.docx is not None:
        docx_text = extract_docx_text(args.docx.resolve())
        results = results + check_prose_substrings(
            docx_text, prose_substring_claims(),
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
