# scripts/run_session_087.py
"""Session 087 CLI — run the offline read-depth robustness frontier (Phase B).

Gate-free: deterministic, offline, zero cost. Writes a markdown report and the
(X, Y) coordinate JSON that Phase C's frontier plot consumes.

Usage:
    python -m scripts.run_session_087 --out-dir data/paper_4/read_depth_frontier
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List, Optional

from ares.dialectic.measurement.read_depth_frontier_report import (
    coordinates_json,
    render_report,
)
from ares.dialectic.measurement.read_depth_frontier_runner import run_frontier

_DEFAULT_OUT = "data/paper_4/read_depth_frontier"


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Read-depth frontier (Phase B).")
    parser.add_argument("--out-dir", default=_DEFAULT_OUT,
                        help="directory for report + coordinates")
    args = parser.parse_args(argv)

    summary = run_frontier()

    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "frontier_report.md").write_text(render_report(summary),
                                            encoding="utf-8")
    (out / "frontier_coordinates.json").write_text(coordinates_json(summary),
                                                    encoding="utf-8")

    print(f"[s087] wrote frontier artifacts to {out} "
          f"(corpus {summary.corpus_digest})")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
