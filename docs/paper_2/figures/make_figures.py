"""Paper 2 figure generator — reads Session 048/049/050 CSV/JSON outputs
and emits grayscale-safe, 300 DPI PNG figures into the same directory.

Each figure has a dedicated builder function. Each builder writes a
docstring that is the intended caption — downstream ``number_check.py``
scrapes those captions and verifies any "n=N" / "accuracy=X.XXXX"
claim against the source CSV/JSON that produced the figure.

Design constraints:
    * Grayscale-safe palette (four tones + hatches on bars so the
      figures survive black-and-white print).
    * 300 DPI PNG (print-ready).
    * No LLM calls; pure data read + matplotlib render.
    * Deterministic output given identical inputs.

CLI:
    python -m docs.paper_2.figures.make_figures \
        --out-dir docs/paper_2/figures \
        --results-root results/
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Iterable, Optional

import matplotlib

matplotlib.use("Agg")

import matplotlib.patches as mpatches
import matplotlib.pyplot as plt


# =============================================================================
# Style
# =============================================================================


# Grayscale-safe palette (darkest -> lightest). Each colour is a
# print-safe hex triple chosen to keep >= 35% luminance steps.
PALETTE = {
    "dark": "#1f1f1f",
    "mid": "#595959",
    "light": "#a0a0a0",
    "pale": "#d9d9d9",
    "accent": "#000000",
}

# Bar hatches — survive mono printing.
HATCHES = ("", "///", "xxx", "\\\\\\")

FIGSIZE_WIDE = (9.0, 5.2)
FIGSIZE_SQUARE = (7.2, 6.4)
FIGSIZE_TALL = (7.2, 8.4)
FIGSIZE_RUBRIC = (10.0, 6.0)
DPI = 300


def _apply_style() -> None:
    plt.rcParams.update({
        "font.size": 10,
        "axes.labelsize": 11,
        "axes.titlesize": 12,
        "figure.titlesize": 13,
        "legend.fontsize": 9,
        "xtick.labelsize": 9,
        "ytick.labelsize": 9,
        "savefig.dpi": DPI,
        "figure.dpi": DPI,
        "savefig.bbox": "tight",
        "axes.spines.top": False,
        "axes.spines.right": False,
    })


# =============================================================================
# Data loaders
# =============================================================================


def _load_session_048(results_root: Path):
    """Return the Session 048 raw_results.json payload."""
    path = results_root / "session_048" / "raw_results.json"
    return json.loads(path.read_text(encoding="utf-8"))


def _load_session_050_family(results_root: Path) -> list[dict]:
    """Return the Session 050 per-family three-way table."""
    path = results_root / "session_050" / "family_three_way.csv"
    with path.open("r", encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def _load_session_050_scenarios(results_root: Path) -> list[dict]:
    """Return the Session 050 per-scenario three-way table."""
    path = results_root / "session_050" / "three_way_delta.csv"
    with path.open("r", encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def _load_finding_11(results_root: Path) -> dict:
    """Parse the Session 050 finding_11_verdict.md for headline numbers."""
    path = results_root / "session_050" / "finding_11_verdict.md"
    text = path.read_text(encoding="utf-8")
    # Look for the key numbers in the markdown.
    out = {"label": None, "full": None, "ablated": None, "light": None, "n": None}
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("**Finding-11:"):
            out["label"] = stripped.split("Finding-11:")[1].rstrip("*").strip()
        for key, needle in (
            ("full", "full framing accuracy"),
            ("ablated", "ablated framing accuracy"),
            ("light", "light framing accuracy"),
            ("n", "n (framing scenarios)"),
        ):
            if needle in stripped.lower():
                # Extract the last float on the line.
                for token in stripped.replace("|", " ").split():
                    token = token.replace("*", "").strip()
                    try:
                        out[key] = float(token)
                        break
                    except ValueError:
                        continue
    if out["n"] is not None:
        out["n"] = int(out["n"])
    return out


# =============================================================================
# Figure 1 — System architecture
# =============================================================================


def make_fig1_architecture(out_path: Path) -> Path:
    """Figure 1: ARES architecture block diagram.

    Caption: 'The ARES pipeline comprises four components — Architect
    (LLM), OracleFirewall (deterministic regex + evidence-graph rules),
    Skeptic (LLM or Light), and OracleJudge (deterministic decision
    table). Session 050 replaces the LLM Skeptic with four evidence-graph
    rules; the other three components are unchanged across all three
    pipeline variants.'
    """
    fig, ax = plt.subplots(figsize=FIGSIZE_WIDE)

    boxes = [
        ("Evidence\nPacket", 0.08, 0.48),
        ("Architect\n(LLM)", 0.28, 0.48),
        ("Oracle\nFirewall", 0.48, 0.48),
        ("Skeptic\n(LLM | Null | Light)", 0.68, 0.48),
        ("OracleJudge\n(deterministic)", 0.88, 0.48),
    ]
    box_w, box_h = 0.17, 0.32
    for text, x, y in boxes:
        rect = mpatches.FancyBboxPatch(
            (x - box_w / 2, y - box_h / 2), box_w, box_h,
            boxstyle="round,pad=0.01",
            linewidth=1.5, edgecolor=PALETTE["dark"], facecolor="white",
        )
        ax.add_patch(rect)
        ax.text(x, y, text, ha="center", va="center", fontsize=10)

    # Arrows between boxes.
    for i in range(len(boxes) - 1):
        x_from = boxes[i][1] + box_w / 2
        x_to = boxes[i + 1][1] - box_w / 2
        ax.annotate(
            "", xy=(x_to, 0.48), xytext=(x_from, 0.48),
            arrowprops=dict(arrowstyle="->", color=PALETTE["dark"],
                            linewidth=1.4),
        )

    # Light Skeptic highlighted below the Skeptic box.
    ax.annotate(
        "Light Skeptic: four evidence-graph rules\n"
        "(authorization | benign_indicator | kill_chain_stage | default_floor)",
        xy=(0.68, 0.32), xycoords="data",
        xytext=(0.68, 0.06), textcoords="data",
        ha="center", fontsize=8, color=PALETTE["dark"],
        arrowprops=dict(arrowstyle="->", color=PALETTE["mid"],
                        linewidth=1.0, linestyle="dashed"),
    )

    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.set_aspect("equal", adjustable="datalim")
    ax.axis("off")
    ax.set_title("ARES pipeline — three Skeptic variants share the same frame",
                 loc="left", pad=8)

    fig.savefig(out_path)
    plt.close(fig)
    return out_path


# =============================================================================
# Figure 2 — Firewall detection + verdict accuracy (Session 048)
# =============================================================================


def make_fig2_firewall_detection(out_path: Path, results_root: Path) -> Path:
    """Figure 2: Per-category firewall detection and verdict accuracy.

    Caption: 'Session 048 live benchmark (claude-sonnet-4-6, n=27):
    the OracleFirewall catches every direct injection (4/4 = 1.00) and
    most propagation scenarios (3/4 = 0.75), but flags zero of the 19
    framing scenarios (0/19 = 0.00). Verdict accuracy is comparable
    across categories (0.75 / 0.79 / 0.75), which confirms that the
    dialectical pipeline rescues framing even when the firewall cannot.'
    """
    payload = _load_session_048(results_root)
    rows = payload.get("results", [])

    categories = ("direct", "framing", "propagation")
    detect_rate: dict[str, float] = {}
    accuracy: dict[str, float] = {}
    counts: dict[str, int] = {}

    for cat in categories:
        subset = [r for r in rows if r["category"] == cat]
        n = len(subset)
        counts[cat] = n
        if n == 0:
            detect_rate[cat] = 0.0
            accuracy[cat] = 0.0
            continue
        detect_rate[cat] = sum(1 for r in subset if r["firewall_detected"]) / n
        accuracy[cat] = sum(
            1 for r in subset
            if r["actual_verdict"].strip().upper() ==
               r["expected_verdict"].strip().upper()
        ) / n

    fig, ax = plt.subplots(figsize=FIGSIZE_WIDE)

    x = range(len(categories))
    width = 0.38

    bars_det = ax.bar(
        [xi - width / 2 for xi in x],
        [detect_rate[c] for c in categories],
        width, label="Firewall detection",
        facecolor=PALETTE["dark"], edgecolor="black", linewidth=0.8,
    )
    bars_acc = ax.bar(
        [xi + width / 2 for xi in x],
        [accuracy[c] for c in categories],
        width, label="Verdict accuracy",
        facecolor=PALETTE["light"], edgecolor="black", linewidth=0.8,
        hatch="///",
    )

    for bars, values in ((bars_det, [detect_rate[c] for c in categories]),
                         (bars_acc, [accuracy[c] for c in categories])):
        for rect, v in zip(bars, values):
            ax.text(
                rect.get_x() + rect.get_width() / 2,
                rect.get_height() + 0.02,
                f"{v:.2f}",
                ha="center", va="bottom", fontsize=9,
            )

    ax.set_xticks(list(x))
    ax.set_xticklabels(
        [f"{c}\n(n={counts[c]})" for c in categories],
    )
    ax.set_ylabel("Rate")
    ax.set_ylim(0, 1.15)
    ax.set_title(
        "Session 048 — Firewall detection vs verdict accuracy",
        loc="left", pad=8,
    )
    ax.legend(loc="upper right", frameon=False)
    fig.savefig(out_path)
    plt.close(fig)
    return out_path


# =============================================================================
# Figure 3 — Per-family three-way heatmap (Session 050)
# =============================================================================


def make_fig3_family_heatmap(out_path: Path, results_root: Path) -> Path:
    """Figure 3: Per-family accuracy heatmap, three-way.

    Caption: 'Per-family verdict accuracy across three pipeline variants
    on Session 050 (n=15 strategies across 5 families). Ablation (no
    Skeptic) drops accuracy by 25-50 pp on severity, temporal, and
    narrative; the Light Skeptic (4 deterministic rules) restores the
    full-pipeline value exactly on every family except authority
    (tied at 0.833). Causal is Skeptic-independent; authority is
    Skeptic-ambiguous.'
    """
    rows = _load_session_050_family(results_root)

    families = [r["family"] for r in rows]
    variants = ("full_acc", "ablated_acc", "light_acc")
    variant_labels = ("Full", "Ablated", "Light")

    data = []
    for r in rows:
        data.append([float(r[v]) for v in variants])

    import numpy as np

    matrix = np.array(data)

    fig, ax = plt.subplots(figsize=FIGSIZE_SQUARE)
    im = ax.imshow(matrix, cmap="Greys", aspect="auto", vmin=0, vmax=1)

    ax.set_xticks(range(len(variant_labels)))
    ax.set_xticklabels(variant_labels)
    ax.set_yticks(range(len(families)))
    ax.set_yticklabels(families)

    for i in range(matrix.shape[0]):
        for j in range(matrix.shape[1]):
            val = matrix[i, j]
            color = "white" if val >= 0.6 else "black"
            ax.text(
                j, i, f"{val:.2f}",
                ha="center", va="center", color=color, fontsize=10,
            )

    ax.set_title(
        "Session 050 — Per-family verdict accuracy (3-way, n_per_family in rows)",
        loc="left", pad=8,
    )
    # n-per-family on the right axis
    n_by_family = {r["family"]: int(r["n"]) for r in rows}
    for i, fam in enumerate(families):
        ax.text(
            matrix.shape[1] - 0.35, i,
            f"n={n_by_family[fam]}",
            ha="left", va="center", fontsize=8, color=PALETTE["mid"],
        )

    cbar = fig.colorbar(im, ax=ax, shrink=0.65)
    cbar.ax.set_ylabel("Accuracy", rotation=90, labelpad=8)
    fig.savefig(out_path)
    plt.close(fig)
    return out_path


# =============================================================================
# Figure 4 — Per-scenario three-way verdict grid
# =============================================================================


def make_fig4_scenario_verdicts(out_path: Path, results_root: Path) -> Path:
    """Figure 4: Per-scenario verdicts across expected/full/ablated/light.

    Caption: 'Session 050 per-scenario verdicts (n=25). Each row is one
    framing scenario; columns show expected verdict (ground truth) and
    the three pipeline variants. Solid tiles = verdict matched expected;
    hatched tiles = mismatch. The light pipeline matches full on 21/25
    scenarios; the two disagreements (INJ-008 lost, INJ-025 rescued)
    cancel out at the aggregate level.'
    """
    rows = _load_session_050_scenarios(results_root)

    # Sort by scenario_id.
    rows_sorted = sorted(rows, key=lambda r: r["scenario_id"])

    scenario_ids = [r["scenario_id"] for r in rows_sorted]
    n = len(rows_sorted)

    columns = ("expected", "full", "ablated", "light")
    column_labels = ("Expected", "Full", "Ablated", "Light")

    # Verdict abbreviation.
    def _abbr(v: str) -> str:
        v = v.strip().upper()
        if v == "THREAT_CONFIRMED":
            return "CONF"
        if v == "THREAT_DISMISSED":
            return "DISM"
        if v == "INCONCLUSIVE":
            return "INCN"
        return v[:4] or "—"

    def _cell_correct(r: dict, col: str) -> bool:
        if col == "expected":
            return True
        return r[f"{col}_correct"].lower() == "true"

    fig, ax = plt.subplots(figsize=FIGSIZE_TALL)

    # Draw grid.
    cell_w, cell_h = 1.0, 1.0
    for i, r in enumerate(rows_sorted):
        y = n - 1 - i
        for j, col in enumerate(columns):
            verdict = r[col] if col != "expected" else r["expected"]
            correct = _cell_correct(r, col)
            face = PALETTE["light"] if correct else "white"
            rect = mpatches.Rectangle(
                (j * cell_w, y * cell_h), cell_w, cell_h,
                facecolor=face,
                edgecolor="black", linewidth=0.6,
                hatch=("" if correct else "xxx"),
            )
            ax.add_patch(rect)
            ax.text(
                j * cell_w + cell_w / 2,
                y * cell_h + cell_h / 2,
                _abbr(verdict),
                ha="center", va="center", fontsize=7,
            )

    # Axes.
    ax.set_xlim(0, len(columns))
    ax.set_ylim(0, n)
    ax.set_xticks([j + 0.5 for j in range(len(columns))])
    ax.set_xticklabels(column_labels)
    ax.set_yticks([n - 1 - i + 0.5 for i in range(n)])
    ax.set_yticklabels(scenario_ids, fontsize=7)
    ax.tick_params(axis="y", length=0)
    ax.tick_params(axis="x", length=0)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["left"].set_visible(False)
    ax.spines["bottom"].set_visible(False)
    ax.set_title(
        "Session 050 — Per-scenario verdict grid (n=25 framing scenarios)",
        loc="left", pad=8,
    )

    # Legend.
    correct_patch = mpatches.Patch(
        facecolor=PALETTE["light"], edgecolor="black", label="Matches expected",
    )
    wrong_patch = mpatches.Patch(
        facecolor="white", edgecolor="black", hatch="xxx",
        label="Verdict miss",
    )
    ax.legend(handles=[correct_patch, wrong_patch],
              loc="lower right", frameon=False, fontsize=8)

    fig.savefig(out_path)
    plt.close(fig)
    return out_path


# =============================================================================
# Figure 5 — Rubric bands with landed value
# =============================================================================


def make_fig5_rubric_bands(out_path: Path, results_root: Path) -> Path:
    """Figure 5: Pre-registered Finding-11 rubric bands with landed value.

    Caption: 'Finding-11 rubric (pre-registered in the Session 050
    prompt): light_framing_accuracy >= full - 0.05 -> SUPPORTED;
    full - 0.10 <= light < full - 0.05 -> PARTIAL; light < full - 0.10
    -> NOT SUPPORTED. Landed value: light = 0.8400, full = 0.8400 on
    n=25 -> SUPPORTED. Delta = 0.0000.'
    """
    numbers = _load_finding_11(results_root)
    full = numbers.get("full") or 0.0
    light = numbers.get("light") or 0.0
    ablated = numbers.get("ablated") or 0.0

    fig, ax = plt.subplots(figsize=FIGSIZE_RUBRIC)

    # Three bands, each shaded differently.
    lower_not = max(0.0, full - 0.10)
    upper_partial = max(0.0, full - 0.05)

    ax.axhspan(0.0, lower_not, color=PALETTE["dark"], alpha=0.32,
               label="NOT SUPPORTED")
    ax.axhspan(lower_not, upper_partial, color=PALETTE["mid"], alpha=0.32,
               label="PARTIAL")
    ax.axhspan(upper_partial, 1.0, color=PALETTE["light"], alpha=0.32,
               label="SUPPORTED")

    # Draw the landed value as a solid horizontal line + marker.
    ax.axhline(light, color=PALETTE["accent"], linewidth=2.0,
               label=f"Light = {light:.4f}")

    # Reference lines for full and ablated.
    ax.axhline(full, color=PALETTE["dark"], linewidth=1.0,
               linestyle="--", label=f"Full = {full:.4f}")
    ax.axhline(ablated, color=PALETTE["mid"], linewidth=1.0,
               linestyle=":", label=f"Ablated = {ablated:.4f}")

    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.set_xticks([])
    ax.set_yticks([0.0, 0.2, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0])
    ax.set_ylabel("Framing accuracy")

    label = numbers.get("label") or "UNKNOWN"
    n = numbers.get("n") or 0
    ax.set_title(
        f"Session 050 — Finding-11 rubric: {label} (n={n})",
        loc="left", pad=8,
    )
    ax.legend(loc="center left", frameon=False)

    fig.savefig(out_path)
    plt.close(fig)
    return out_path


# =============================================================================
# Main entry
# =============================================================================


FIGURE_BUILDERS = (
    ("fig1_architecture.png", "architecture", make_fig1_architecture, False),
    ("fig2_firewall_detection.png", "firewall_detection",
     make_fig2_firewall_detection, True),
    ("fig3_family_heatmap.png", "family_heatmap",
     make_fig3_family_heatmap, True),
    ("fig4_scenario_verdicts.png", "scenario_verdicts",
     make_fig4_scenario_verdicts, True),
    ("fig5_rubric_bands.png", "rubric_bands",
     make_fig5_rubric_bands, True),
)


def build_all(
    out_dir: Path,
    results_root: Path,
) -> list[Path]:
    """Render every figure and return the list of output paths."""
    _apply_style()
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for filename, _label, builder, needs_root in FIGURE_BUILDERS:
        out_path = out_dir / filename
        if needs_root:
            builder(out_path, results_root)
        else:
            builder(out_path)
        written.append(out_path)
    return written


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Paper 2 figure generator")
    parser.add_argument(
        "--out-dir", type=Path,
        default=Path(__file__).resolve().parent,
        help="Destination directory for PNG figures",
    )
    parser.add_argument(
        "--results-root", type=Path,
        default=Path("results"),
        help="Root directory containing session_048/, session_049/, session_050/",
    )
    args = parser.parse_args(None if argv is None else list(argv))

    written = build_all(args.out_dir, args.results_root)
    for p in written:
        size_kb = p.stat().st_size // 1024
        print(f"[FIGURES] wrote {p} ({size_kb} KB)")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
