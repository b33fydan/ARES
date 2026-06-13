"""Paper 4 figure renderer — Session 094 (Phase 2).

Renders fig_1..6 (the read-depth robustness trilemma) from the closed
S088-S090 artifacts to vector PDF at acmart sigconf column widths. Every
plotted value traces to a file under data/paper_4/ (no hardcoded magic
numbers in the data figures).

Usage::

    python -m docs.paper_4.build_figures
    python -m docs.paper_4.build_figures --figure 2   # render one

Output: docs/paper_4/figures/fig_{1..6}.pdf
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import matplotlib
matplotlib.use("pdf")
# TrueType (fonttype 42), not matplotlib's PDF-default Type 3 which ACM
# camera-ready / IEEE PDF eXpress reject (Paper 3 B3 lesson).
matplotlib.rcParams["pdf.fonttype"] = 42
matplotlib.rcParams["ps.fonttype"] = 42
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch

REPO = Path(__file__).resolve().parents[2]
OUT = REPO / "docs" / "paper_4" / "figures"
FRONTIER = REPO / "data" / "paper_4" / "read_depth_frontier"
OOV = REPO / "data" / "paper_4" / "read_depth_oov"

SINGLE_COL = 3.333
DOUBLE_COL = 7.0

# Palette (carried from Paper 3 for cross-paper visual consistency).
C_STABLE = "#2E7D32"      # robust / resist / pass (green)
C_DIVERGE = "#C62828"     # evaded / flip / fail (red)
C_LADDER = "#1565C0"      # ladder / detection (blue)
C_ADVERSARY = "#E65100"   # OOV adversary (orange)
C_AUDIT = "#4A148C"       # independent judges (purple)
C_GOODCORNER = "#FFF9C4"  # good-corner shading (pale yellow)
C_BORDER = "#BDBDBD"
C_CODEBG = "#F5F5F5"
C_HIGHLIGHT = "#FFF9C4"
C_LINENUM = "#9E9E9E"


def _load(p: Path) -> dict:
    return json.loads(p.read_text(encoding="utf-8"))


def _save(fig: "plt.Figure", name: str) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    path = OUT / f"{name}.pdf"
    fig.savefig(path, bbox_inches="tight", pad_inches=0.04)
    plt.close(fig)
    print(f"  {name}.pdf  ({path.stat().st_size:,} bytes)")


# --- render fns added in later tasks ---


ALL_FIGURES: dict[int, "callable"] = {}


def main() -> int:
    parser = argparse.ArgumentParser(description="Paper 4 figure renderer")
    parser.add_argument("--figure", type=int, default=None,
                        help="Render a single figure (1-6). Default: all.")
    args = parser.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    targets = ({args.figure: ALL_FIGURES[args.figure]}
               if args.figure else ALL_FIGURES)
    print(f"Rendering {len(targets)} figure(s) to {OUT}/")
    for num, fn in sorted(targets.items()):
        print(f"  fig_{num}...", end="", flush=True)
        fn()
    print(f"\nDone. {len(targets)} PDF(s) written.")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
