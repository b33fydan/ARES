"""Paper 2 number-check: cross-validate caption claims against source CSVs.

Every numerical claim that appears in a Paper 2 figure caption
(``make_figures.py`` docstrings) or in the skeleton's caption stubs
must be traceable to a specific CSV or summary file under ``results/``.
This script enumerates every such claim, resolves it against the source
data, and emits a pass/fail report. The script exits with a non-zero
status if any claim fails.

The claim table is the single source of truth — new figures add new
rows; removed figures strike rows. Every row includes:

    * a short label (used in the report)
    * the expected numeric value (float or int)
    * the source file + extraction instructions (function reference)
    * the tolerance (relative or absolute)

Callers can also pass a broken fixture via ``--override-claims``
to exercise the failure path during testing.

CLI:
    python -m docs.paper_2.number_check
    python -m docs.paper_2.number_check --results-root results/
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
# CLI
# =============================================================================


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Paper 2 caption number-check validator",
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
    return parser


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(None if argv is None else list(argv))

    results = run_checks(default_claims(), args.results_root)
    report = render_report(results)
    write_report(report, args.out_report)

    total = len(results)
    passed = sum(1 for r in results if r.passed)
    print(f"[NUMBER-CHECK] {passed}/{total} claims validated")
    print(f"[NUMBER-CHECK] report: {args.out_report}")
    if passed < total:
        print("[NUMBER-CHECK] FAIL — see report for details", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
