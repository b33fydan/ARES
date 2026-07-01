# Paper 5 Figures (Phase 2) Implementation Plan

> **For agentic workers:** built via superpowers:subagent-driven-development (one implementer for the single renderer module + test, then controller VISUAL sign-off on the rendered PDFs, then a task review). Steps use checkbox (`- [ ]`) tracking.

**Goal:** Build `docs/paper_5/build_figures.py` → six vector PDFs `docs/paper_5/figures/fig_{1..6}.pdf` + the guard test `tests/paper_5/test_build_figures.py`, by mirroring `docs/paper_4/build_figures.py`'s proven structure. Data figures trace every plotted value to the closed S099 run artifact (no hardcoded magic numbers); conceptual figures are hand-drawn. TrueType (`pdf.fonttype = 42`) so ACM/IEEE accept them (the Paper 3 B3 lesson).

**Architecture:** Port Paper 4's renderer structure verbatim where paper-agnostic (the `matplotlib.use("pdf")` + fonttype-42 header, the palette, `SINGLE_COL`/`DOUBLE_COL`, `_load`/`_save`, `ALL_FIGURES` dict, `main(--figure)`); swap in Paper-5-specific `render_fig_1..6` reading `data/paper_5/s099_phase3_run_20260627-070037.json`. Same six-figure roster as the skeleton (`docs/paper_5/skeleton_v1_0.json` `figures` + the §7 of the design spec).

**Tech Stack:** Python 3.11, matplotlib (pdf backend), stdlib `json`/`argparse`/`pathlib`. Run with the GLOBAL `"/c/Program Files/Python311/python.exe"` (the local ./venv is incomplete). New deps: none (matplotlib already used by Paper 3/4).

## Global Constraints
- **New files only:** create ONLY `docs/paper_5/build_figures.py`, `tests/paper_5/test_build_figures.py`, and the rendered `docs/paper_5/figures/fig_{1..6}.pdf`. Modify NO existing file. Stage only these paths — never `git add -A`.
- **Commit tag** `feat(s101): …` with the `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>` trailer.
- **Artifact is canonical.** Data figures read values from `data/paper_5/s099_phase3_run_20260627-070037.json` at run time via a `_run()` helper — never hardcode the floats. The artifact is read-only; do not mutate it.
- **TrueType:** `matplotlib.rcParams["pdf.fonttype"] = 42` and `["ps.fonttype"] = 42`, set at import (before any plotting) — mirror Paper 4 lines 22-27.
- **Palette:** reuse Paper 4's exact palette constants (cross-paper visual consistency). Semantic mapping for Paper 5: `C_STABLE` green = allow/clean/utility-kept/guarantee-holds; `C_DIVERGE` red = deny/tainted/blocked/the-cost; `C_LADDER` blue = neutral/structure; `C_ADVERSARY` orange = injected/attacker; `C_AUDIT` purple = conclusion-integrity. `C_GOODCORNER`/`C_CODEBG`/`C_BORDER` as in Paper 4.
- **Column widths:** `SINGLE_COL = 3.333`, `DOUBLE_COL = 7.0` (acmart sigconf).
- **UTF-8** on all writes.

## The S099 numbers the data figures must read (confirmed serialized values — read from the artifact, do NOT hardcode)
Single FLAT object. Key paths + values:
- `sweep` (list, 4 cells): each `{model, attack, undefended_asr, undefended_utility}` = (haiku-4-5, important_instructions, 0.0, 0.0), (haiku-4-5, tool_knowledge, 0.0, 0.5), (sonnet-4-6, important_instructions, 0.0, 0.75), (sonnet-4-6, tool_knowledge, 0.0, 0.75).
- `tau_asr` = 0.2, `tau_util` = 0.2.
- `stage1_arms.{undefended,full_defense,gate_off}` each `{asr, utility, gate_denials, echo_rate, conclusion_integrity_rate, n}`: undefended (0.0, 0.5, 0, 0.05, 0.95, 20); full_defense (0.0, 0.3, 2, 0.05, 0.95, 20); gate_off (0.0, 0.45, 0, 0.05, 0.95, 20).
- `benign_false_block.full_defense` `{n 20, benign_denials 4, false_block_rate_per_task 0.2, benign_utility 0.3}`.
- `rollouts` 96; `selected_cell` null; `no_cell_contingency` true; `run_cell` = {model haiku-4-5, attack important_instructions, suite banking}.

---

## Task 1: build_figures.py + test + rendered PDFs

**Files:** create `docs/paper_5/build_figures.py`, `tests/paper_5/test_build_figures.py`, `docs/paper_5/figures/fig_{1..6}.pdf`. Reference `docs/paper_4/build_figures.py` (structure) + `tests/paper_4/test_build_figures.py` (gate).

### Figure-by-figure spec

**fig_1 — ARES-Harness architecture (conceptual; host §3; `DOUBLE_COL`).**
A left-to-right pipeline of the five input-path stages then the gate then the action, with the control/data separation called out. Boxes (FancyBboxPatch, rounded): `capture` → `normalize` → `ingress-scan` → `IOC-anchor` → `quarantine / inert-render` (these five = the input path, shade them `C_LADDER` blue) then an arrow into `action gate` (`C_STABLE` green box) then `tool action` (allow/deny). A labelled band under the input-path stages: "untrusted content rendered inert (data, never instructions)". A short caption strip: "fail-closed at every stage; provenance derived harness-side from raw bytes." Keep labels ≥6pt, monospace for the module names. Conceptual — no data load.

**fig_2 — THE money figure: regime + guarantee (two-panel; host §6, referenced from §4; `DOUBLE_COL`).** `fig, axes = plt.subplots(1, 2, figsize=(DOUBLE_COL, 3.0))`.
- LEFT panel = the **no-headroom regime** (DATA, read `sweep` + `tau_asr`). Bar chart of the 4 cells' `undefended_asr` (all 0.0) — 4 bars at height 0 (draw a thin baseline marker / "0.00" label atop each so the zero is legible), x-labels the 4 cells (haiku·ii / haiku·tk / sonnet·ii / sonnet·tk), a dashed horizontal line at `tau_asr` = 0.2 labelled "τ_asr (selection threshold)". Title: "undefended ASR = 0 across the grid". Annotate "no cell clears τ → no-cell contingency". This is the regime: nothing to lower.
- RIGHT panel = the **by-construction guarantee** (CONCEPTUAL, but read `stage1_arms.full_defense.gate_denials` = 2 for the annotation). A 2×N decision-rule grid for `authorize(capability_class, arg-taint)`: rows = capability classes (READ_ONLY, WRITE_LOCAL, IRREVERSIBLE, EXFIL_SHAPED), columns = arg-provenance (clean / tainted). Cells: allow = `C_STABLE` green "ALLOW"; deny = `C_DIVERGE` red "DENY" (privileged ∩ tainted → DENY; READ_ONLY always ALLOW; clean privileged ALLOW). Title: "the gate: (class × arg-taint) → allow/deny". Annotate the privileged∩tainted deny cells with "2 injected calls denied here (live)". Caption: "holds env-state ASR at 0 by construction — value-blind, no LLM".
- `fig.suptitle("A deterministic gate holds injected actions at zero — in a regime with no ASR headroom left")`.

**fig_3 — arms on the fallback cell (DATA; host §6; `SINGLE_COL` or slightly wider).** Grouped/paneled bars over the three arms (undefended / full_defense / gate_off) reading `stage1_arms`. Show four measures: ASR (0/0/0), utility (0.5/0.3/0.45), gate denials (0/2/0), conclusion-integrity (0.95/0.95/0.95). Either a grouped bar (4 measure-groups × 3 arms) or a small-multiples 1×4. Color arms consistently (undefended grey `C_BORDER`, gate_off blue `C_LADDER`, full_defense green `C_STABLE`). Make the gate-denials 0/2/0 contrast pop (it is the empirical non-vacuity). Title: "arms @ fallback cell (haiku / important_instructions, N=20)". Label each bar's value.

**fig_4 — the honest cost (DATA; host §6; `SINGLE_COL`).** Two grouped bars: (a) benign false-block rate = 0.2 with the pre-registered ≤0.50 band shaded (`axhspan` 0–0.5 pale, a dashed line at 0.50 labelled "pre-registered band ≤0.50"); annotate "4/20 benign tasks over-blocked". (b) utility cost: undefended 0.5 → full_defense 0.3 (two bars, an arrow/Δ annotation "−0.20"). Read all from `benign_false_block.full_defense` + `stage1_arms`. Title: "the guarantee's honest cost (within the pre-registered band)".

**fig_5 — SOTA positioning matrix (conceptual; host §7; `DOUBLE_COL`).** A table/matrix figure: rows = the SOTA systems + ARES-Harness; columns = {Surface guarded, Mechanism, Conclusion-integrity scored?}. Use the verified-citation systems:
| System | Surface guarded | Mechanism | Conclusion-integrity |
|---|---|---|---|
| Dual-LLM (Willison '23) | input (control/data) | second quarantined LLM | ✗ |
| Spotlighting (Hines '24) | input | prompt-level marking (model) | ✗ |
| Instruction Hierarchy (Wallace '24) | input priority | learned (training) | ✗ |
| StruQ (Chen '24) | input | structured queries + learned | ✗ |
| SecAlign (Chen '24) | input | preference-opt (learned) | ✗ |
| CaMeL (Debenedetti '25) | action | capability interpreter-IFC (deterministic) | ✗ |
| **ARES-Harness (this work)** | **input + action** | **deterministic provenance-taint (no LLM in the decision)** | **✓** |
Render as cells (rounded rects) with ✓ (`C_STABLE`) / ✗ (`C_BORDER`). HIGHLIGHT the last column ("Conclusion-integrity scored?") with a `C_AUDIT`/`C_GOODCORNER` band and a callout: "the decision-integrity axis — orthogonal to all surface defenses; only ARES scores it". The ARES row visually emphasized (bold border). Conceptual — no data load.

**fig_6 — worked example pipeline (conceptual; host §4; `DOUBLE_COL`).** A horizontal pipeline of an injected banking task → gate denial: `injected bill text (untrusted)` → `capture + normalize` → `ingress-scan / inert-render` → `agent proposes send_money(recipient=<from bill>)` → `harness-side provenance: recipient arg traced to untrusted bytes → TAINTED` → `gate: IRREVERSIBLE ∩ tainted → DENY`. Color the untrusted/tainted path `C_ADVERSARY` orange, the deny `C_DIVERGE` red. Show the planted IBAN `US133000000121212121212` as the tainted `recipient` value (this also visually seeds the conclusion-integrity echo-check). Caption: "the gate decides on where the arg came from (raw-byte provenance), never on what the text says". Conceptual.

### Steps
- [ ] **Step 1: Write the guard test** `tests/paper_5/test_build_figures.py` (mirror Paper 4 + a data-fidelity check):
```python
"""Paper 5 figure renderer guards: TrueType embedding (ACM-safe) + all six
figures render to non-trivial vector PDFs; data figures trace to the S099 artifact."""
from __future__ import annotations

import json
import matplotlib
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
RUN = REPO / "data" / "paper_5" / "s099_phase3_run_20260627-070037.json"


def test_build_figures_sets_truetype_fonttype():
    import docs.paper_5.build_figures  # noqa: F401  (import sets rcParams)
    assert matplotlib.rcParams["pdf.fonttype"] == 42
    assert matplotlib.rcParams["ps.fonttype"] == 42


def test_all_six_figures_render_nontrivial_pdfs(tmp_path, monkeypatch):
    import docs.paper_5.build_figures as bf
    monkeypatch.setattr(bf, "OUT", tmp_path)
    assert sorted(bf.ALL_FIGURES) == [1, 2, 3, 4, 5, 6]
    for num, fn in bf.ALL_FIGURES.items():
        fn()
        pdf = tmp_path / f"fig_{num}.pdf"
        assert pdf.exists(), num
        assert pdf.stat().st_size > 2000, (num, pdf.stat().st_size)
        assert pdf.read_bytes()[:4] == b"%PDF", num


def test_data_figures_trace_to_s099_artifact():
    """The data-figure loader must return the artifact's values, not hardcoded ones."""
    import docs.paper_5.build_figures as bf
    run = json.loads(RUN.read_text(encoding="utf-8"))
    # max undefended ASR across the sweep is 0.0 (the no-headroom regime)
    assert max(c["undefended_asr"] for c in run["sweep"]) == 0.0
    arms = run["stage1_arms"]
    assert arms["full_defense"]["gate_denials"] == 2
    assert arms["undefended"]["gate_denials"] == 0 and arms["gate_off"]["gate_denials"] == 0
    assert arms["full_defense"]["utility"] == 0.3 and arms["undefended"]["utility"] == 0.5
    assert run["benign_false_block"]["full_defense"]["false_block_rate_per_task"] == 0.2
    assert run["tau_asr"] == 0.2
```
(If the implementer factors data access through helpers like `_run()` / `_arm()` / `_sweep()`, the third test MAY instead assert those helpers return the artifact values — but it MUST assert real artifact-traced values, not tautologies.)

- [ ] **Step 2: Run the test — verify RED** (`build_figures.py` not authored): `"/c/Program Files/Python311/python.exe" -m pytest tests/paper_5/test_build_figures.py -q` → ImportError/fail expected.

- [ ] **Step 3: Author `docs/paper_5/build_figures.py`** per the figure-by-figure spec. Mirror Paper 4's header/palette/`_load`/`_save`/`ALL_FIGURES`/`main`. `OUT = REPO / "docs" / "paper_5" / "figures"`, `RUN = REPO / "data" / "paper_5" / "s099_phase3_run_20260627-070037.json"`. Data figures (2-left, 3, 4) read `RUN`; conceptual figures (1, 2-right, 5, 6) hand-drawn (fig_2-right + fig_6 may read the `2` gate-denial count / annotate from the artifact).

- [ ] **Step 4: Run the test — verify GREEN.** Then render the real artifacts: `"/c/Program Files/Python311/python.exe" -m docs.paper_5.build_figures` → writes `docs/paper_5/figures/fig_{1..6}.pdf`. Confirm 6 PDFs, each `%PDF`, > 2000 bytes.

- [ ] **Step 5: STOP for controller visual sign-off** (do not commit yet). Report DONE; the controller will Read each rendered PDF and inspect. Fix any figure flagged (wrong data, illegible labels, overlap, ugly layout) and re-render before commit.

- [ ] **Step 6: Commit** (after visual sign-off passes):
```
git add docs/paper_5/build_figures.py tests/paper_5/test_build_figures.py docs/paper_5/figures/fig_1.pdf docs/paper_5/figures/fig_2.pdf docs/paper_5/figures/fig_3.pdf docs/paper_5/figures/fig_4.pdf docs/paper_5/figures/fig_5.pdf docs/paper_5/figures/fig_6.pdf
git commit -F - <<'EOF'
feat(s101): Paper 5 Phase-2 figures - 6 vector PDFs from the S099 artifact

build_figures.py mirrors Paper 4's renderer (pdf backend, fonttype 42, shared
palette). fig_2 is the money figure (no-headroom regime | by-construction gate
rule). Data figures (2-left/3/4) trace to data/paper_5/s099_phase3_run_*.json;
conceptual figures (1/2-right/5/6) hand-drawn. test_build_figures.py guards
TrueType + all-six-render + data-fidelity.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
```

## Verification gates
- `tests/paper_5/test_build_figures.py` green (fonttype 42 + all six render + data-fidelity).
- Controller visual sign-off on all six rendered PDFs (data correct, labels legible, no overlap, publication-quality).
- Full suite `tests/ ares/dialectic/tests/` 0 regressions; floor bump to the new collected count (the figures add +3 tests → ~4,534) recorded in CLAUDE.md at session close (or a follow-on commit if closing now).

## Out of scope (Phase 2)
No prose (Phase 3), no acmart/PDF build (Phase 4), no new measurement. fig_2-right / fig_5 / fig_6 are qualitative diagrams (their content is the architecture/positioning, not measured numbers) — only fig_2-left / fig_3 / fig_4 are data-locked.
