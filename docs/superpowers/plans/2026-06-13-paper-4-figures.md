# Paper 4 Figures (Phase 2) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Render the 6 Paper 4 figures (`fig_1..6`) to publication-quality vector PDFs at `docs/paper_4/figures/`, every plotted value traced to a closed S088–S090 artifact, mirroring the proven Paper 3 renderer.

**Architecture:** A single `docs/paper_4/build_figures.py` module (mirrors `docs/paper_3/build_figures.py`): module-level `matplotlib.use("pdf")` + `pdf.fonttype/ps.fonttype = 42` (TrueType, ACM-safe), a shared color palette + `SINGLE_COL`/`DOUBLE_COL` widths + `_save()`, one `render_fig_N()` per figure, and an `ALL_FIGURES` CLI. Data figures (fig_2/3/4/6) load their values from the on-disk artifacts (no hardcoded magic numbers — drift-proof, mirroring the number_check ethos); conceptual figures (fig_1/5) are `FancyBboxPatch` diagrams. Output is committed PDFs (like Paper 3).

**Tech Stack:** Python 3.11, matplotlib (PDF backend), stdlib `json`/`pathlib`/`argparse`. No new dependencies (matplotlib already used by Paper 3).

---

## Scope

**This plan (Phase 2):** the figure renderer + 6 rendered PDFs + a fonttype guard test + an "all 6 render to non-trivial PDF" smoke test + a CLAUDE.md canonical-artifact line. No prose, no acmart/PDF build, no new measurement.

**Out of scope (later phases):** Phase 3 prose (`source/`), Phase 4 acmart build + PDF substring gate. The tables (`tbl_1..4`) are authored in the Phase-3/Phase-4 LaTeX, not here.

---

## Data provenance (READ THESE — exact values to plot)

All figures trace to files already on disk. The data figures must LOAD and compute from these (not hardcode), so a future re-run can't silently desync the figure from the result.

- `data/paper_4/read_depth_frontier/frontier_coordinates.json` — deterministic rungs, both views (`coordinates[]` with `tier_id`, `view`, `x_semantic`, `youden_j`, `tpr`, `fpr`).
- `data/paper_4/read_depth_frontier/tier4_summary.json` — the `llm_semantic` rung, both views (`coordinates[]` with `view`, `tier_id="llm_semantic"`, `x_semantic`, `youden_j`).
- `data/paper_4/read_depth_oov/oov_summary.json` — OOV per-record flips (`records[]` with `arm`, `scenario_id`, `canonical_flipped`); K=8 per (scenario, arm).
- `data/paper_4/read_depth_oov/oov_audit.json` — audit (`evading[]` with `classification`/`independents`, `controls[]`, `per_scenario_confirmed`).

**The 5-rung frontier (fig_2), verified from the artifacts:**

| tier_id | standalone (X_sem, J) | cumulative (X_sem, J) |
|---|---|---|
| v1_field | (0.0, 0.0) | (0.0, 0.0) |
| v2_structured | (0.0, 0.25) | (0.0, 0.25) |
| v2_lexical | (0.0, 0.50) | (0.0, 0.25) |
| v2_canonical | (0.0, 0.75) | (0.0, 0.25) |
| llm_semantic | (0.125, 0.75) | (0.0, 0.25) |

Good corner = `X_sem ≤ 0.10` AND `J ≥ 0.50`. **Standalone:** `v2_canonical` (0.0, 0.75) sits INSIDE it (the "lone escape"), `v2_lexical` (0.0, 0.50) on its lower edge, `llm_semantic` (0.125, 0.75) just OUTSIDE (X_sem > 0.10). **Cumulative:** every rung caps at J=0.25 → corner EMPTY. That standalone→cumulative collapse is the trilemma; fig_2 is the paper's money figure.

**OOV per-scenario canonical flips out of K=8 (fig_3), verified:**

| scenario | black flips/8 | white flips/8 |
|---|---|---|
| RDF-M-LEX-001 (lsass, named-IOC) | 0 | 0 |
| RDF-M-LEX-002 (exe-in-temp) | 2 | 3 |
| RDF-M-SYN-001 (synonym-dropper) | 7 | 6 |
| RDF-M-PATCH-001 (procdump, named-IOC) | 0 | 0 |

Evaded pair = LEX-002 + SYN-001 (nonzero); resist pair = LEX-001 + PATCH-001 (zero, named-IOC). These are *verification targets* — compute them in code from `records[]`, don't hardcode.

**Audit per-judge malign verdicts on the 18 evading disguises (fig_4), verified:**

| judge | malign verdicts / 18 |
|---|---|
| Sonnet (original) | 18 |
| Gemini | 18 |
| GPT-4o (openai) | 15 |

15 both-independents-confirmed + 3 split (the 3 splits are GPT-4o=benign / Gemini=malign → GPT-4o is the stricter judge). Calibration controls: 4, all pass. Verdict ROBUST. Compute from `evading[]`/`controls[]`.

**Worked disguise (fig_6) — first black, independent_confirmed RDF-M-SYN-001 entry in `oov_audit.json`:**
- original: `binary dropped to C:\Users\Public\` / `loader running from public folder`
- evading: `payload written to C:\Users\Public\` / `launcher operational from common folder`
- both independents (GPT-4o + Gemini) read it malign. Load the first matching `evading[]` entry; don't transcribe by hand.

---

## File Structure

**Create:**
- `docs/paper_4/build_figures.py` — the renderer (≈ Paper 3's shape, Paper 4 content).
- `docs/paper_4/figures/fig_1.pdf` … `fig_6.pdf` — rendered output (committed, like Paper 3).
- `tests/paper_4/test_build_figures.py` — fonttype guard + all-6-render smoke test.

**Modify (Task 5):**
- `CLAUDE.md` — add the Paper 4 figure renderer to Canonical Artifacts + a one-line note in the Paper 4 tooling block.

**Reference (read / mirror):**
- `docs/paper_3/build_figures.py` (module shape, palette, `_save`, conceptual-diagram + bar-chart + code-snippet idioms).
- `tests/paper_3/test_build_figures_fonttype.py`.

---

## Task 1: Module scaffold + fonttype guard

**Files:**
- Create: `docs/paper_4/build_figures.py`
- Create: `tests/paper_4/test_build_figures.py`

- [ ] **Step 1: Write the fonttype guard test (it will fail — module missing)**

`tests/paper_4/test_build_figures.py`:
```python
"""Paper 4 figure renderer guards: TrueType embedding (ACM-safe) + all
six figures render to non-trivial vector PDFs traced to closed artifacts."""
from __future__ import annotations

import matplotlib


def test_build_figures_sets_truetype_fonttype():
    import docs.paper_4.build_figures  # noqa: F401  (import sets rcParams)
    assert matplotlib.rcParams["pdf.fonttype"] == 42
    assert matplotlib.rcParams["ps.fonttype"] == 42
```

- [ ] **Step 2: Run it, verify it FAILS**

Run: `python -m pytest tests/paper_4/test_build_figures.py -q`
Expected: ERROR/FAIL (no module `docs.paper_4.build_figures`).

- [ ] **Step 3: Create the module scaffold**

`docs/paper_4/build_figures.py` — mirror Paper 3's header exactly:
```python
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
```

- [ ] **Step 4: Run the fonttype test, verify it PASSES**

Run: `python -m pytest tests/paper_4/test_build_figures.py -q`
Expected: 1 passed (the smoke test for all-6 is added in Task 5).

- [ ] **Step 5: Commit**
```bash
git add docs/paper_4/build_figures.py tests/paper_4/test_build_figures.py
git commit -F - <<'EOF'
feat(s094): Paper 4 figure renderer scaffold + fonttype guard

matplotlib PDF backend, TrueType (fonttype 42), acmart column widths,
artifact loaders. Render fns land per figure in following commits.
EOF
```

---

## Task 2: fig_2 — the money figure (frontier, standalone vs cumulative)

**Files:** Modify `docs/paper_4/build_figures.py` (add `render_fig_2`, register in `ALL_FIGURES`).

This is the paper's centerpiece. Two side-by-side panels (double-column), x-axis `X_sem` (framing-flip rate, 0→0.4), y-axis Youden's `J` (0→1). Plot all 5 rungs per panel from the artifacts; shade the good corner; show it occupied in standalone (v2_canonical) and empty in cumulative.

- [ ] **Step 1: Implement `render_fig_2`**

```python
_LADDER_ORDER = ["v1_field", "v2_structured", "v2_lexical",
                 "v2_canonical", "llm_semantic"]
_TIER_LABEL = {
    "v1_field": "v1_field", "v2_structured": "v2_struct",
    "v2_lexical": "v2_lexical", "v2_canonical": "v2_canon",
    "llm_semantic": "LLM",
}
GOOD_X_MAX = 0.10   # framing-robust band (prereg)
GOOD_J_MIN = 0.50   # high-detection band (prereg)


def _frontier_points(view: str) -> dict:
    """tier_id -> (x_semantic, youden_j) for `view`, merging the
    deterministic rungs (frontier_coordinates.json) with llm_semantic
    (tier4_summary.json). Pure read from disk — no hardcoded values."""
    pts = {}
    for c in _load(FRONTIER / "frontier_coordinates.json")["coordinates"]:
        if c["view"] == view:
            pts[c["tier_id"]] = (c["x_semantic"], c["youden_j"])
    for c in _load(FRONTIER / "tier4_summary.json")["coordinates"]:
        if c["view"] == view and c["tier_id"] == "llm_semantic":
            pts[c["tier_id"]] = (c["x_semantic"], c["youden_j"])
    return pts


def render_fig_2() -> None:
    fig, axes = plt.subplots(1, 2, figsize=(DOUBLE_COL, 3.0), sharey=True)
    for ax, view in zip(axes, ("standalone", "cumulative")):
        pts = _frontier_points(view)
        # good-corner shading
        ax.add_patch(mpatches.Rectangle(
            (0, GOOD_J_MIN), GOOD_X_MAX, 1.0 - GOOD_J_MIN,
            facecolor=C_GOODCORNER, edgecolor=C_STABLE, linewidth=1.0,
            linestyle="--", zorder=0))
        # jitter overlapping points horizontally so all 5 are visible
        seen: dict = {}
        for tier in _LADDER_ORDER:
            x, j = pts[tier]
            key = (round(x, 4), round(j, 4))
            n = seen.get(key, 0); seen[key] = n + 1
            xx = x + n * 0.012
            occupied = (x <= GOOD_X_MAX and j >= GOOD_J_MIN)
            color = C_DIVERGE if (tier == "v2_canonical" and occupied) else C_LADDER
            ax.scatter([xx], [j], s=46, color=color, zorder=3,
                       edgecolor="white", linewidth=0.6)
            ax.annotate(_TIER_LABEL[tier], (xx, j),
                        textcoords="offset points", xytext=(5, 3),
                        fontsize=6.0, color="#333333")
        ax.set_title(view, fontsize=8, fontweight="bold")
        ax.set_xlabel(r"$X_{\mathrm{sem}}$ (framing-flip rate)", fontsize=7.5)
        ax.set_xlim(-0.03, 0.42)
        ax.set_ylim(-0.05, 1.05)
        ax.tick_params(labelsize=7)
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)
        ax.axvline(GOOD_X_MAX, color=C_BORDER, lw=0.6, ls=":")
        ax.axhline(GOOD_J_MIN, color=C_BORDER, lw=0.6, ls=":")
    axes[0].set_ylabel("Youden's J (TPR - FPR)", fontsize=7.5)
    axes[0].text(0.005, 0.96, "good corner", fontsize=6, color=C_STABLE,
                 style="italic", va="top")
    axes[1].text(0.20, 0.27, "all rungs cap\nat J = 0.25", fontsize=6.5,
                 color=C_DIVERGE, ha="left", va="center", style="italic")
    fig.suptitle("Read-depth frontier: good corner occupied standalone, "
                 "empty cumulative", fontsize=8.5, fontweight="bold")
    fig.tight_layout(rect=(0, 0, 1, 0.95))
    _save(fig, "fig_2")


ALL_FIGURES[2] = render_fig_2
```

- [ ] **Step 2: Render + sanity-check**

Run: `python -m docs.paper_4.build_figures --figure 2`
Expected: `fig_2.pdf` written, > 5,000 bytes. (The controller visually inspects this PDF before sign-off.)

- [ ] **Step 3: Commit**
```bash
git add docs/paper_4/build_figures.py docs/paper_4/figures/fig_2.pdf
git commit -F - <<'EOF'
feat(s094): Paper 4 fig_2 (money figure) — frontier standalone vs cumulative

5 rungs per panel loaded from frontier_coordinates.json + tier4_summary.json;
good-corner shaded; v2_canonical occupies it standalone, empty cumulative.
EOF
```

---

## Task 3: fig_3 + fig_4 (OOV evasion + independent audit, data charts)

**Files:** Modify `docs/paper_4/build_figures.py` (add `render_fig_3`, `render_fig_4`, register both).

- [ ] **Step 1: Implement `render_fig_3` (per-scenario canonical flips, black vs white)**

```python
_OOV_SCENARIOS = ["RDF-M-LEX-001", "RDF-M-LEX-002",
                  "RDF-M-SYN-001", "RDF-M-PATCH-001"]
_OOV_SHORT = {"RDF-M-LEX-001": "LEX-001\n(lsass)",
              "RDF-M-LEX-002": "LEX-002\n(exe-in-temp)",
              "RDF-M-SYN-001": "SYN-001\n(synonym)",
              "RDF-M-PATCH-001": "PATCH-001\n(procdump)"}


def _oov_flips(arm: str) -> dict:
    """scenario_id -> count of canonical_flipped over its K records, for arm."""
    recs = [r for r in _load(OOV / "oov_summary.json")["records"]
            if r["arm"] == arm]
    out = {s: 0 for s in _OOV_SCENARIOS}
    for r in recs:
        if r["canonical_flipped"]:
            out[r["scenario_id"]] += 1
    return out


def render_fig_3() -> None:
    black = _oov_flips("black")
    white = _oov_flips("white")
    fig, ax = plt.subplots(figsize=(SINGLE_COL, 2.3))
    x = range(len(_OOV_SCENARIOS)); w = 0.38
    ax.bar([i - w / 2 for i in x], [black[s] for s in _OOV_SCENARIOS], w,
           color=C_ADVERSARY, label="black-box", edgecolor="white", linewidth=0.5)
    ax.bar([i + w / 2 for i in x], [white[s] for s in _OOV_SCENARIOS], w,
           color=C_AUDIT, label="white-box", edgecolor="white", linewidth=0.5)
    ax.set_xticks(list(x))
    ax.set_xticklabels([_OOV_SHORT[s] for s in _OOV_SCENARIOS], fontsize=6.0)
    ax.set_ylabel("canonical flips (of K=8)", fontsize=7.5)
    ax.set_ylim(0, 8.5)
    ax.tick_params(axis="y", labelsize=7)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.legend(fontsize=6.5, loc="upper left", framealpha=0.9)
    ax.text(0.5, 8.0, "evaded", fontsize=6.5, color=C_DIVERGE,
            ha="center", style="italic")
    ax.text(2.5, 8.0, "", fontsize=6.5)
    ax.axvspan(0.5, 2.5, color=C_DIVERGE, alpha=0.05)
    fig.tight_layout()
    _save(fig, "fig_3")


ALL_FIGURES[3] = render_fig_3
```
(LEX-002 + SYN-001 are the evaded pair; LEX-001 + PATCH-001 named-IOC resist with zero bars. Expected counts black 0/2/7/0, white 0/3/6/0.)

- [ ] **Step 2: Implement `render_fig_4` (independent-judge audit)**

```python
_JUDGES = [("sonnet", "Sonnet\n(original)", C_BORDER),
           ("gemini", "Gemini", C_AUDIT),
           ("openai", "GPT-4o", C_ADVERSARY)]


def _audit_malign_counts() -> dict:
    """judge -> count of malign verdicts over the evading disguises.
    sonnet is malign on every evading entry by construction; the
    independents come from each entry's `independents` list."""
    ev = _load(OOV / "oov_audit.json")["evading"]
    counts = {"sonnet": 0, "gemini": 0, "openai": 0}
    for e in ev:
        if e.get("sonnet_malign", True):
            counts["sonnet"] += 1
        for judge, verdict in e["independents"]:
            if verdict:
                counts[judge] += 1
    return counts


def render_fig_4() -> None:
    audit = _load(OOV / "oov_audit.json")
    counts = _audit_malign_counts()
    n_ev = len(audit["evading"])
    n_conf = sum(1 for e in audit["evading"]
                 if e["classification"] == "independent_confirmed")
    n_split = sum(1 for e in audit["evading"]
                  if e["classification"] == "independent_split")
    n_ctrl = len(audit["controls"])
    fig, ax = plt.subplots(figsize=(SINGLE_COL, 2.3))
    xs = range(len(_JUDGES))
    ax.bar(list(xs), [counts[k] for k, _, _ in _JUDGES],
           0.6, color=[c for _, _, c in _JUDGES], edgecolor="white", linewidth=0.5)
    for i, (k, _, _) in enumerate(_JUDGES):
        ax.text(i, counts[k] + 0.3, str(counts[k]), ha="center",
                fontsize=8, fontweight="bold")
    ax.set_xticks(list(xs))
    ax.set_xticklabels([lbl for _, lbl, _ in _JUDGES], fontsize=6.5)
    ax.set_ylabel(f"malign verdicts (of {n_ev} evading)", fontsize=7.5)
    ax.set_ylim(0, n_ev + 3)
    ax.tick_params(axis="y", labelsize=7)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.set_title(f"Audit: {n_conf} confirmed / {n_split} split; "
                 f"{n_ctrl}/{n_ctrl} controls pass -> ROBUST",
                 fontsize=7.0, fontweight="bold")
    fig.tight_layout()
    _save(fig, "fig_4")


ALL_FIGURES[4] = render_fig_4
```
(Expected bar heights: Sonnet 18, Gemini 18, GPT-4o 15; title "15 confirmed / 3 split; 4/4 controls pass -> ROBUST".)

- [ ] **Step 3: Render both + sanity-check**

Run: `python -m docs.paper_4.build_figures --figure 3 && python -m docs.paper_4.build_figures --figure 4`
Expected: `fig_3.pdf`, `fig_4.pdf` written, each > 4,000 bytes. (Controller visually inspects.)

- [ ] **Step 4: Commit**
```bash
git add docs/paper_4/build_figures.py docs/paper_4/figures/fig_3.pdf docs/paper_4/figures/fig_4.pdf
git commit -F - <<'EOF'
feat(s094): Paper 4 fig_3 (OOV per-scenario flips) + fig_4 (independent audit)

fig_3: black/white canonical flips per scenario (LEX-002+SYN-001 evade,
named-IOC resist), computed from oov_summary.json records. fig_4: per-judge
malign counts (Sonnet/Gemini 18, GPT-4o 15) + controls, from oov_audit.json.
EOF
```

---

## Task 4: fig_1 + fig_5 + fig_6 (ladder, method pipeline, worked disguise)

**Files:** Modify `docs/paper_4/build_figures.py` (add `render_fig_1`, `render_fig_5`, `render_fig_6`, register all).

- [ ] **Step 1: Implement `render_fig_1` (the read-depth ladder, conceptual)**

A 5-rung ascending staircase (v1_field bottom → llm_semantic top); each rung a labeled box with "reads:" text; an up-arrow annotation "deeper reading -> more detection AND more attacker-controlled surface".
```python
def render_fig_1() -> None:
    rungs = [
        ("v1_field", "reads: field presence only"),
        ("v2_structured", "reads: high-threat field + stage logic"),
        ("v2_lexical", "reads: exe-in-user-path regex"),
        ("v2_canonical", "reads: canonicalize-then-match"),
        ("llm_semantic", "reads: full LLM by meaning"),
    ]
    fig, ax = plt.subplots(figsize=(DOUBLE_COL, 3.0))
    ax.set_xlim(0, 10); ax.set_ylim(0, 6); ax.axis("off")
    bw, bh = 5.2, 0.8
    for i, (name, reads) in enumerate(rungs):
        x = 0.6 + i * 0.7
        y = 0.6 + i * 1.0
        shade = 0.30 + 0.14 * i
        ax.add_patch(FancyBboxPatch(
            (x, y), bw, bh, boxstyle="round,pad=0.06",
            facecolor=C_LADDER, alpha=shade, edgecolor=C_LADDER, linewidth=1.0))
        ax.text(x + 0.15, y + bh / 2, name, ha="left", va="center",
                fontsize=7.5, fontweight="bold", family="monospace")
        ax.text(x + bw - 0.15, y + bh / 2, reads, ha="right", va="center",
                fontsize=6.0, color="#333333", style="italic")
    ax.annotate("", xy=(0.35, 5.6), xytext=(0.35, 0.5),
                arrowprops=dict(arrowstyle="->", color=C_DIVERGE, lw=1.4))
    ax.text(0.05, 3.0, "read depth", rotation=90, va="center", ha="center",
            fontsize=7, color=C_DIVERGE, fontweight="bold")
    ax.text(9.6, 0.2, "deeper -> more detection AND more\nattacker-controlled "
            "surface (the trilemma)", ha="right", va="bottom",
            fontsize=6.5, color=C_DIVERGE, style="italic")
    _save(fig, "fig_1")


ALL_FIGURES[1] = render_fig_1
```

- [ ] **Step 2: Implement `render_fig_5` (method pipeline, conceptual)**

"LLM proposes, code disposes" + independent audit. Boxes left→right: `LLM adversary\n(generate disguises)` → `deterministic gate\n(skeleton + novelty)` → `LLM judge\n(meaning-preserving?)` → `verdict`; a separate lower box `independent audit\n(GPT-4o + Gemini + calibration controls)` feeding the verdict. Color the LLM boxes `C_ADVERSARY`/`C_AUDIT`, the deterministic gate `C_STABLE`.
```python
def render_fig_5() -> None:
    fig, ax = plt.subplots(figsize=(DOUBLE_COL, 2.4))
    ax.set_xlim(0, 12); ax.set_ylim(0, 5); ax.axis("off")
    boxes = [
        (0.3, 3.0, "LLM adversary\n(generate\ndisguises)", C_ADVERSARY),
        (3.2, 3.0, "deterministic gate\n(skeleton +\nnovelty)", C_STABLE),
        (6.1, 3.0, "LLM judge\n(meaning-\npreserving?)", C_AUDIT),
        (9.0, 3.0, "verdict", C_LADDER),
    ]
    bw, bh = 2.4, 1.4
    for x, y, label, color in boxes:
        ax.add_patch(FancyBboxPatch((x, y), bw, bh, boxstyle="round,pad=0.08",
                     facecolor=color, alpha=0.85, edgecolor="black", linewidth=0.8))
        ax.text(x + bw / 2, y + bh / 2, label, ha="center", va="center",
                fontsize=7, fontweight="bold", color="white")
    for x1 in (0.3, 3.2, 6.1):
        ax.annotate("", xy=(x1 + bw + 0.45, 3.0 + bh / 2),
                    xytext=(x1 + bw + 0.05, 3.0 + bh / 2),
                    arrowprops=dict(arrowstyle="->", color="black", lw=1.2))
    ax.add_patch(FancyBboxPatch((6.1, 0.5), 5.3, 1.2, boxstyle="round,pad=0.08",
                 facecolor=C_AUDIT, alpha=0.5, edgecolor=C_AUDIT, linewidth=1.0))
    ax.text(8.75, 1.1, "independent audit: GPT-4o + Gemini\n+ calibration controls",
            ha="center", va="center", fontsize=6.5, fontweight="bold", color="#222222")
    ax.annotate("", xy=(9.0 + bw / 2, 2.95), xytext=(9.0 + bw / 2, 1.75),
                arrowprops=dict(arrowstyle="->", color=C_AUDIT, lw=1.1))
    ax.text(6.0, 4.7, "LLM proposes, code disposes", ha="center", va="top",
            fontsize=8, fontweight="bold", color="#222222")
    _save(fig, "fig_5")


ALL_FIGURES[5] = render_fig_5
```

- [ ] **Step 3: Implement `render_fig_6` (worked OOV disguise, snippet)**

Load the first `evading` entry for RDF-M-SYN-001 (arm black, classification independent_confirmed) from `oov_audit.json`; render original vs evading side-by-side, both judges' verdict shown.
```python
def _first_syn001_disguise() -> dict:
    for e in _load(OOV / "oov_audit.json")["evading"]:
        if (e["scenario_id"] == "RDF-M-SYN-001" and e["arm"] == "black"
                and e["classification"] == "independent_confirmed"):
            return e
    raise LookupError("no confirmed black SYN-001 evading disguise found")


def render_fig_6() -> None:
    e = _first_syn001_disguise()
    orig = [v for _, v in e["original_values"]]
    new = [v for _, v in e["value_rewrites"]]
    fig, ax = plt.subplots(figsize=(DOUBLE_COL, 1.9))
    ax.set_xlim(0, 12); ax.set_ylim(0, len(orig) + 1.6); ax.axis("off")
    ax.text(3.0, len(orig) + 1.1, "original (canonical matches)", ha="center",
            fontsize=7, fontweight="bold", color=C_STABLE)
    ax.text(9.0, len(orig) + 1.1, "OOV disguise (canonical misses)", ha="center",
            fontsize=7, fontweight="bold", color=C_DIVERGE)
    for i, (o, n) in enumerate(zip(orig, new)):
        y = len(orig) - i
        ax.add_patch(mpatches.Rectangle((0.2, y - 0.35), 5.6, 0.7,
                     facecolor=C_CODEBG, edgecolor=C_BORDER, linewidth=0.5))
        ax.text(0.4, y, o, ha="left", va="center", fontsize=6.0, family="monospace")
        ax.add_patch(mpatches.Rectangle((6.2, y - 0.35), 5.6, 0.7,
                     facecolor="#FFEBEE", edgecolor=C_DIVERGE, linewidth=0.5))
        ax.text(6.4, y, n, ha="left", va="center", fontsize=6.0, family="monospace")
        ax.annotate("", xy=(6.15, y), xytext=(5.85, y),
                    arrowprops=dict(arrowstyle="->", color="#999999", lw=0.8))
    ax.text(6.0, 0.2, "meaning preserved -> both independents (GPT-4o + Gemini) "
            "read it malign", ha="center", va="bottom", fontsize=6.0,
            color=C_DIVERGE, style="italic")
    _save(fig, "fig_6")


ALL_FIGURES[6] = render_fig_6
```

- [ ] **Step 4: Render all three + sanity-check**

Run: `python -m docs.paper_4.build_figures --figure 1 && python -m docs.paper_4.build_figures --figure 5 && python -m docs.paper_4.build_figures --figure 6`
Expected: three PDFs written, each > 3,000 bytes. (Controller visually inspects.)

- [ ] **Step 5: Commit**
```bash
git add docs/paper_4/build_figures.py docs/paper_4/figures/fig_1.pdf docs/paper_4/figures/fig_5.pdf docs/paper_4/figures/fig_6.pdf
git commit -F - <<'EOF'
feat(s094): Paper 4 fig_1 (read-depth ladder) + fig_5 (method pipeline) + fig_6 (worked disguise)

fig_1/fig_5 conceptual diagrams; fig_6 loads the first confirmed black
SYN-001 disguise from oov_audit.json (binary->payload, loader->launcher).
EOF
```

---

## Task 5: All-six smoke test + render-all + CLAUDE.md

**Files:**
- Modify: `tests/paper_4/test_build_figures.py`
- Modify: `CLAUDE.md`

- [ ] **Step 1: Add the all-six render smoke test**

Append to `tests/paper_4/test_build_figures.py`:
```python
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def test_all_six_figures_render_nontrivial_pdfs(tmp_path, monkeypatch):
    import docs.paper_4.build_figures as bf
    monkeypatch.setattr(bf, "OUT", tmp_path)
    assert sorted(bf.ALL_FIGURES) == [1, 2, 3, 4, 5, 6]
    for num, fn in bf.ALL_FIGURES.items():
        fn()
        pdf = tmp_path / f"fig_{num}.pdf"
        assert pdf.exists(), num
        assert pdf.stat().st_size > 2000, (num, pdf.stat().st_size)
        assert pdf.read_bytes()[:4] == b"%PDF", num
```

- [ ] **Step 2: Run the figure tests**

Run: `python -m pytest tests/paper_4/test_build_figures.py -q`
Expected: 2 passed (fonttype + all-six render).

- [ ] **Step 3: Render the full set to the committed location**

Run: `python -m docs.paper_4.build_figures`
Expected: "Done. 6 PDF(s) written." All six in `docs/paper_4/figures/`.

- [ ] **Step 4: Update CLAUDE.md**

In `## Canonical Artifacts`, after the Paper 4 number-check line, add:
```
- **Paper 4 figure renderer:** `docs/paper_4/build_figures.py`
```
In the `### Paper 4 scaffold` tooling block, change the "Out of scope" line to record figures as DONE and append a figures bullet:
```
- Figures (Phase 2): `docs/paper_4/build_figures.py` -> 6 vector PDFs `docs/paper_4/figures/fig_{1..6}.pdf` (TrueType/fonttype 42; data figures loaded from the S088-S090 artifacts). fig_2 is the money figure (frontier standalone vs cumulative). Test `tests/paper_4/test_build_figures.py`.
```
(Do NOT change the floor — figure tests add to the count but the floor is a minimum; freshness still passes. Optionally re-run the collect count and bump if you want it tight.)

- [ ] **Step 5: Commit**
```bash
git add tests/paper_4/test_build_figures.py docs/paper_4/figures CLAUDE.md
git commit -F - <<'EOF'
feat(s094): Paper 4 all-six figure smoke test + render full set + CLAUDE.md

6 PDFs rendered to docs/paper_4/figures/; smoke test asserts each is a
non-trivial %PDF; CLAUDE.md records the Phase-2 figure renderer.
EOF
```

---

## Task 6: Full-suite regression + visual sign-off

**Files:** none (verification only)

- [ ] **Step 1: Full suite**

Run: `python -m pytest tests/ ares/ -q`
Expected: prior 4,413 + the 2 new figure tests = 4,415 passed, 76 skipped, 0 failed. Record the count.

- [ ] **Step 2: Confirm artifacts untouched**

Run: `git status --short data/paper_4/`
Expected: empty (figures read the artifacts; never write them).

- [ ] **Step 3: Visual sign-off (controller)**

The controller renders each PDF to PNG and inspects: fig_2 shows v2_canonical inside the good corner standalone and an empty corner cumulative; fig_3 shows the evaded vs resist split; fig_4 shows GPT-4o=15 < Sonnet/Gemini=18; fig_1/5/6 are legible. Any visual defect → fix the render fn and re-commit.

---

## Self-Review (completed during plan authoring)

**Spec coverage:** spec §7 lists exactly fig_1..6 + tbl_1..4. All 6 figures have tasks (Tasks 2-4); tables are explicitly Phase-3/4 (LaTeX), not figures. Each figure's host_section + purpose matches the skeleton. fig_2 is correctly the centerpiece (double-col, both views). Data figures load from the 4 artifacts named in the skeleton `source` fields.

**Placeholder scan:** every render fn has complete code; data figures compute from artifacts (no magic numbers); expected verification values are given for fig_2/3/4/6.

**Type consistency:** `_load`, `OUT`, `FRONTIER`, `OOV`, `_save`, `ALL_FIGURES` defined in Task 1 and used consistently in Tasks 2-4. Tier ids match `light_skeptic_v2_ladder.py` / the artifacts (`v1_field`, `v2_structured`, `v2_lexical`, `v2_canonical`, `llm_semantic`). Scenario ids match the artifacts.

**Visual correctness is human-verified** (Task 6 Step 3), since unit tests can only assert a non-trivial %PDF renders, not that it looks right.
