"""Run misclassification diagnosis on saved benchmark results.

Session 031: CLI wrapper for the diagnosis engine. Reads saved JSON
results and produces a failure mode classification report.

Usage:
    python -m ares.dialectic.scripts.run_diagnosis --results path/to/benchmark.json
    python -m ares.dialectic.scripts.run_diagnosis --results path/to/benchmark.json --output diagnosis.txt
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        description="Diagnose ARES benchmark misclassifications",
    )
    parser.add_argument(
        "--results",
        required=True,
        help="Path to benchmark results JSON",
    )
    parser.add_argument(
        "--output",
        help="Path to save diagnosis report (default: auto-named alongside results)",
    )
    return parser


def main(argv: Optional[list[str]] = None) -> None:
    """Entry point for the diagnosis CLI."""
    parser = build_parser()
    args = parser.parse_args(argv)

    results_path = Path(args.results)
    if not results_path.exists():
        print(f"ERROR: Results file not found: {results_path}")
        sys.exit(1)

    from ares.dialectic.scripts.misclassification_diagnosis import (
        diagnose_benchmark,
        format_diagnosis_report,
    )

    print(f"Diagnosing: {results_path.name}")
    report = diagnose_benchmark(str(results_path))

    text = format_diagnosis_report(report)
    print(text)

    # Save to file
    if args.output:
        output_path = Path(args.output)
    else:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        output_path = results_path.parent / f"diagnosis_{ts}.txt"

    output_path.write_text(text, encoding="utf-8")
    print(f"\nDiagnosis saved to: {output_path}")


if __name__ == "__main__":
    main()
