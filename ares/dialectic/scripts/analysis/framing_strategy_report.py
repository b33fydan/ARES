"""Session 048 framing-strategy aggregation report.

Reads a ``raw_results.json`` produced by
``run_full_corpus_benchmark`` and aggregates it two ways:

    * By category — one row per {direct, framing, propagation}
    * By framing family — one row per {severity, authority, temporal,
      causal, narrative}, derived from the ``framing_strategy`` prefix
      on Category B expansion scenarios (INJ-013..INJ-027)

Emits:

    * ``per_strategy.csv`` — one row per category + one per family
    * ``summary.md``       — two markdown tables (categories, families)

Also prints the same content to stdout.

CLI:
    python -m ares.dialectic.scripts.analysis.framing_strategy_report \
        --input results/session_048/raw_results.json \
        --output-dir results/session_048/
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional, Sequence

from ares.dialectic.schemas.framing_benchmark_result import (
    FramingBenchmarkResult,
)


# The five framing families in canonical report order.
FRAMING_FAMILIES: tuple[str, ...] = (
    "severity",
    "authority",
    "temporal",
    "causal",
    "narrative",
)

# Categories in canonical report order.
CATEGORIES: tuple[str, ...] = ("direct", "framing", "propagation")

# Anything that does not begin with one of the known family prefixes is
# grouped here so the aggregation never silently drops a row.
UNKNOWN_FAMILY = "unknown"


# =============================================================================
# Aggregation
# =============================================================================


@dataclass(frozen=True)
class AggregateRow:
    """Frozen aggregate summary for one (category or family) bucket.

    Attributes:
        label: Category label ("direct", ...) or family label ("severity", ...).
        n: Number of scenarios included.
        detection_rate: Fraction where ``firewall_detected`` is True.
        verdict_accuracy: Fraction where actual_verdict == expected_verdict.
        mean_taint_score: Arithmetic mean of taint_score across the bucket.
    """

    label: str
    n: int
    detection_rate: float
    verdict_accuracy: float
    mean_taint_score: float


def derive_family(framing_strategy: Optional[str]) -> Optional[str]:
    """Derive the framing family from a framing_strategy identifier.

    ``None`` strategy returns ``None`` (not in any family bucket —
    typically a seed injection scenario or a propagation scenario).

    Strategies whose prefix does not match one of the known families
    return ``UNKNOWN_FAMILY``; aggregation will include them in a
    separate bucket so the input is never silently dropped.
    """
    if framing_strategy is None:
        return None
    prefix = framing_strategy.split("_", 1)[0]
    if prefix in FRAMING_FAMILIES:
        return prefix
    return UNKNOWN_FAMILY


def _verdict_matches(result: FramingBenchmarkResult) -> bool:
    """True when actual_verdict matches expected (case-insensitive, trimmed)."""
    actual = result.actual_verdict.strip().upper()
    expected = result.expected_verdict.strip().upper()
    if not actual:
        return False
    return actual == expected


def _aggregate_group(
    label: str,
    results: Sequence[FramingBenchmarkResult],
) -> AggregateRow:
    """Compute AggregateRow metrics for a non-empty group of results."""
    n = len(results)
    if n == 0:
        return AggregateRow(
            label=label,
            n=0,
            detection_rate=0.0,
            verdict_accuracy=0.0,
            mean_taint_score=0.0,
        )
    detected = sum(1 for r in results if r.firewall_detected)
    correct = sum(1 for r in results if _verdict_matches(r))
    mean_taint = sum(r.taint_score for r in results) / n
    return AggregateRow(
        label=label,
        n=n,
        detection_rate=detected / n,
        verdict_accuracy=correct / n,
        mean_taint_score=mean_taint,
    )


def aggregate_by_category(
    results: Sequence[FramingBenchmarkResult],
) -> tuple[AggregateRow, ...]:
    """Return one AggregateRow per category, in canonical order.

    Categories with zero results still appear as a row (n=0) so
    downstream analyses always see the full 3-row shape.
    """
    rows: list[AggregateRow] = []
    for category in CATEGORIES:
        bucket = [r for r in results if r.category == category]
        rows.append(_aggregate_group(category, bucket))
    return tuple(rows)


def aggregate_by_family(
    results: Sequence[FramingBenchmarkResult],
) -> tuple[AggregateRow, ...]:
    """Return one AggregateRow per framing family, in canonical order.

    Scenarios with ``framing_strategy is None`` are excluded; unknown
    prefixes surface as an ``UNKNOWN_FAMILY`` row only when present so
    that the common case returns exactly 5 rows.
    """
    rows: list[AggregateRow] = []
    grouped: dict[str, list[FramingBenchmarkResult]] = {
        f: [] for f in FRAMING_FAMILIES
    }
    unknown_bucket: list[FramingBenchmarkResult] = []

    for r in results:
        family = derive_family(r.framing_strategy)
        if family is None:
            continue
        if family in grouped:
            grouped[family].append(r)
        else:
            unknown_bucket.append(r)

    for family in FRAMING_FAMILIES:
        rows.append(_aggregate_group(family, grouped[family]))
    if unknown_bucket:
        rows.append(_aggregate_group(UNKNOWN_FAMILY, unknown_bucket))
    return tuple(rows)


# =============================================================================
# Input
# =============================================================================


def load_results(path: Path) -> tuple[FramingBenchmarkResult, ...]:
    """Load FramingBenchmarkResult list from ``raw_results.json``."""
    payload = json.loads(path.read_text(encoding="utf-8"))
    raw_list = payload.get("results", [])
    return tuple(FramingBenchmarkResult.from_dict(r) for r in raw_list)


# =============================================================================
# CSV output
# =============================================================================


CSV_HEADER: tuple[str, ...] = (
    "group_type",
    "label",
    "n",
    "detection_rate",
    "verdict_accuracy",
    "mean_taint_score",
)


def _csv_rows(
    category_rows: Sequence[AggregateRow],
    family_rows: Sequence[AggregateRow],
) -> list[tuple[str, str, int, float, float, float]]:
    out: list[tuple[str, str, int, float, float, float]] = []
    for row in category_rows:
        out.append((
            "category",
            row.label,
            row.n,
            row.detection_rate,
            row.verdict_accuracy,
            row.mean_taint_score,
        ))
    for row in family_rows:
        out.append((
            "family",
            row.label,
            row.n,
            row.detection_rate,
            row.verdict_accuracy,
            row.mean_taint_score,
        ))
    return out


def write_per_strategy_csv(
    category_rows: Sequence[AggregateRow],
    family_rows: Sequence[AggregateRow],
    out_path: Path,
) -> Path:
    """Write the per-strategy CSV with both category and family rows."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(CSV_HEADER)
        for row in _csv_rows(category_rows, family_rows):
            writer.writerow([
                row[0],
                row[1],
                row[2],
                f"{row[3]:.4f}",
                f"{row[4]:.4f}",
                f"{row[5]:.4f}",
            ])
    return out_path


# =============================================================================
# Markdown output
# =============================================================================


def _render_markdown_table(
    title: str,
    rows: Sequence[AggregateRow],
) -> str:
    lines = [
        f"### {title}",
        "",
        "| label | n | detection_rate | verdict_accuracy | mean_taint_score |",
        "|---|---:|---:|---:|---:|",
    ]
    for row in rows:
        lines.append(
            f"| {row.label} | {row.n} | {row.detection_rate:.4f} | "
            f"{row.verdict_accuracy:.4f} | {row.mean_taint_score:.4f} |"
        )
    lines.append("")
    return "\n".join(lines)


def render_summary_markdown(
    category_rows: Sequence[AggregateRow],
    family_rows: Sequence[AggregateRow],
    *,
    input_path: Optional[Path] = None,
) -> str:
    """Render both aggregation tables as markdown."""
    header = [
        "# Session 048 — Framing Strategy Report",
        "",
    ]
    if input_path is not None:
        header.append(f"Input: `{input_path}`")
        header.append("")
    header.append("")
    body = [
        _render_markdown_table("By Category", category_rows),
        _render_markdown_table("By Framing Family", family_rows),
    ]
    return "\n".join(header + body)


def write_summary_markdown(
    category_rows: Sequence[AggregateRow],
    family_rows: Sequence[AggregateRow],
    out_path: Path,
    *,
    input_path: Optional[Path] = None,
) -> Path:
    """Write the markdown summary to disk and return the path."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        render_summary_markdown(
            category_rows, family_rows, input_path=input_path,
        ),
        encoding="utf-8",
    )
    return out_path


# =============================================================================
# CLI
# =============================================================================


def build_arg_parser() -> argparse.ArgumentParser:
    """Construct the CLI argument parser."""
    parser = argparse.ArgumentParser(
        description=(
            "Aggregate the Session 048 full-corpus benchmark results "
            "by category and by framing strategy family."
        ),
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=Path("results/session_048/raw_results.json"),
        help="Path to raw_results.json written by run_full_corpus_benchmark.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("results/session_048"),
        help="Destination directory for per_strategy.csv + summary.md.",
    )
    return parser


def print_report(
    category_rows: Sequence[AggregateRow],
    family_rows: Sequence[AggregateRow],
) -> None:
    """Print both aggregation tables to stdout."""
    print(render_summary_markdown(category_rows, family_rows))


def run_report(
    input_path: Path,
    output_dir: Path,
) -> tuple[Path, Path]:
    """Perform a full report run and return the written artifact paths."""
    results = load_results(input_path)
    category_rows = aggregate_by_category(results)
    family_rows = aggregate_by_family(results)

    csv_path = write_per_strategy_csv(
        category_rows, family_rows, output_dir / "per_strategy.csv",
    )
    md_path = write_summary_markdown(
        category_rows, family_rows, output_dir / "summary.md",
        input_path=input_path,
    )
    print_report(category_rows, family_rows)
    return csv_path, md_path


def main(argv: Optional[Iterable[str]] = None) -> int:
    """CLI entry point for the framing-strategy report."""
    parser = build_arg_parser()
    args = parser.parse_args(None if argv is None else list(argv))

    if not args.input.exists():
        print(
            f"[FRAMING-REPORT] ERROR: input not found at {args.input}",
            file=sys.stderr,
        )
        return 2

    csv_path, md_path = run_report(args.input, args.output_dir)
    print(f"[FRAMING-REPORT] Wrote {csv_path}")
    print(f"[FRAMING-REPORT] Wrote {md_path}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
