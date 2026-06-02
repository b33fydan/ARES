# Paper 3 Submission De-risk Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the three fixable Paper 3 submission blockers (B1 placeholder captions, B2 build non-reproducibility, B3 Type 3 fonts) so the AISec '26 PDF is submission-grade, with zero regressions.

**Architecture:** `build_acmart.py` becomes the single source of truth for the `.tex` again — its figure emitter is switched from `\framebox` placeholders to `\includegraphics` of the real S073 vector PDFs (B2), and its caption roster drops the stale spike sentence (B1). `build_figures.py` gains TrueType font embedding (B3). The committed `.tex`/`.pdf` and figure PDFs are then regenerated and recompiled, and every submission gate is re-run.

**Tech Stack:** Python 3.11, pytest, matplotlib (pdf backend), MiKTeX (pdflatex/bibtex), poppler (pdftotext/pdfinfo/pdffonts).

**Spec:** `docs/superpowers/specs/2026-06-02-paper3-submission-derisk-fixes-design.md`

**Scope guards (do NOT touch):** canonical source markdown (`docs/paper_3/source/PAPER3_DRAFT_v1_0_source.md`), `references.bib` (B4 deferred), figure *plotting* logic in `build_figures.py`, `oracle.py` / measurement / anchor tests.

**Offline only — no API spend.** Run all `git` / `pdflatex` / `pytest` via the Bash tool (git-bash). Recompile uses a subshell `cd` to keep relative `../figures/` and `references.bib` paths resolvable.

---

### Task 1: B3 — TrueType fonts in the figure renderer

**Files:**
- Modify: `docs/paper_3/build_figures.py:22` (insert after `matplotlib.use("pdf")`)
- Test: `tests/paper_3/test_build_figures_fonttype.py` (create)

- [ ] **Step 1: Write the failing test**

Create `tests/paper_3/test_build_figures_fonttype.py`:

```python
"""B3 guard: the figure renderer must embed TrueType fonts (fonttype 42),
not matplotlib's PDF-backend default of Type 3, which ACM camera-ready /
IEEE PDF eXpress reject. Importing build_figures must set the rcParam."""
from __future__ import annotations

import matplotlib


def test_build_figures_sets_truetype_fonttype():
    import docs.paper_3.build_figures  # noqa: F401  (import side effect sets rcParams)
    assert matplotlib.rcParams["pdf.fonttype"] == 42
    assert matplotlib.rcParams["ps.fonttype"] == 42
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/paper_3/test_build_figures_fonttype.py -v`
Expected: FAIL — `assert 3 == 42` (matplotlib default is Type 3).

- [ ] **Step 3: Write minimal implementation**

In `docs/paper_3/build_figures.py`, insert immediately after line 22 (`matplotlib.use("pdf")`), before `import matplotlib.pyplot as plt`:

```python
matplotlib.use("pdf")
# B3 fix (Session 080): embed TrueType fonts (fonttype 42) instead of the
# matplotlib PDF-backend default of Type 3, which ACM camera-ready /
# IEEE PDF eXpress reject.
matplotlib.rcParams["pdf.fonttype"] = 42
matplotlib.rcParams["ps.fonttype"] = 42
import matplotlib.pyplot as plt
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/paper_3/test_build_figures_fonttype.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add docs/paper_3/build_figures.py tests/paper_3/test_build_figures_fonttype.py
git commit -F - <<'EOF'
fix(s080): embed TrueType fonts in Paper 3 figure renderer (B3)

matplotlib's PDF backend defaults to Type 3 fonts, which ACM camera-ready
/ IEEE PDF eXpress reject. Set pdf.fonttype/ps.fonttype = 42 so the six
figures embed TrueType. Plotting logic unchanged.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
```

---

### Task 2: B2 — `build_acmart.py` emits real figures (`\includegraphics`)

**Files:**
- Modify: `docs/paper_3/build_acmart.py` (`render_figure_placeholder`, ~lines 279-300)
- Test: `tests/paper_3/test_build_acmart_figures.py` (create)

- [ ] **Step 1: Write the failing test**

Create `tests/paper_3/test_build_acmart_figures.py`:

```python
"""B1+B2 guards for acmart figure rendering in build_acmart.py.

B2: figures render as \\includegraphics of the S073 vector PDFs (so the
documented build reproduces the committed .tex), not \\framebox boxes.
B1 (added in Task 3): captions carry no placeholder spike text."""
from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SOURCE = REPO_ROOT / "docs" / "paper_3" / "source" / "PAPER3_DRAFT_v1_0_source.md"
REFS = REPO_ROOT / "docs" / "paper_3" / "references.bib"


def _build_tex(tmp_path) -> str:
    from docs.paper_3.build_acmart import build_tex
    src = SOURCE.read_text(encoding="utf-8")
    # build_tex returns the .tex string; it copies references.bib into the
    # out dir as a side effect, so point it at tmp_path.
    return build_tex(src, REFS, tmp_path / "paper.tex")


def test_figures_use_includegraphics_not_framebox(tmp_path):
    tex = _build_tex(tmp_path)
    assert tex.count("\\includegraphics") == 6
    assert "\\framebox" not in tex
    assert "[Placeholder:" not in tex


def test_figure_width_matches_span(tmp_path):
    tex = _build_tex(tmp_path)
    # fig_1 is the only double-column figure -> \textwidth
    assert "\\includegraphics[width=\\textwidth]{../figures/fig_1.pdf}" in tex
    for fid in ("fig_2", "fig_3", "fig_4", "fig_5", "fig_6"):
        assert f"\\includegraphics[width=\\columnwidth]{{../figures/{fid}.pdf}}" in tex
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/paper_3/test_build_acmart_figures.py -v`
Expected: FAIL — current output uses `\framebox`, 0 `\includegraphics`.

- [ ] **Step 3: Write minimal implementation**

In `docs/paper_3/build_acmart.py`, inside `render_figure_placeholder`, replace this block:

```python
    env = "figure*" if spec.span == "double" else "figure"
    safe_fig_id = latex_escape(spec.fig_id)
    canonical_n = _canonical_figure_number(spec.fig_id)
    # Width = full column width (``\linewidth``); height fixed in inches.
    # ``\framebox[\linewidth]{...}`` puts a visible border around the area.
    body = (
        f"\\framebox[\\linewidth]{{"
        f"\\rule{{0pt}}{{{spec.height_in}in}}"
        f"\\textit{{[Placeholder: {safe_fig_id} ({spec.span} column, "
        f"{spec.height_in}\\,in)]}}"
        f"}}"
    )
```

with:

```python
    env = "figure*" if spec.span == "double" else "figure"
    canonical_n = _canonical_figure_number(spec.fig_id)
    # Real vector figure (Session 073 assets). Double-column floats
    # (``figure*``) span ``\textwidth``; single-column floats span
    # ``\columnwidth``. Matches the assets rendered by build_figures.py.
    width = "\\textwidth" if spec.span == "double" else "\\columnwidth"
    body = f"\\includegraphics[width={width}]{{../figures/{spec.fig_id}.pdf}}"
```

(The `safe_fig_id` local is removed because it was only used by the placeholder text; `latex_escape` is still used by the caption/Description lines below, so the import stays. `height_in` is now unused by this function but stays in the dataclass to minimize the diff.)

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/paper_3/test_build_acmart_figures.py -v`
Expected: PASS (both tests).

- [ ] **Step 5: Empty-diff proof — build now reproduces the committed `.tex`**

The on-disk `.tex` is still the committed S073 artifact (Tasks 1-2 only touch `.py`). With the mechanism fixed but captions unchanged, the regenerated `.tex` must equal it byte-for-byte:

```bash
python -m docs.paper_3.build_acmart --out .scratch/regen_t2.tex
diff .scratch/regen_t2.tex docs/paper_3/acmart_spike/paper_3_acmart.tex && echo "EMPTY DIFF -- build reproduces committed .tex (B2 closed)"
```

Expected: no diff output, then `EMPTY DIFF -- build reproduces committed .tex (B2 closed)`. If the diff is non-empty, STOP — the emitter does not match the committed artifact; reconcile before continuing.

- [ ] **Step 6: Commit**

```bash
git add docs/paper_3/build_acmart.py tests/paper_3/test_build_acmart_figures.py
git commit -F - <<'EOF'
fix(s080): build_acmart emits real figures, restoring reproducibility (B2)

render_figure_placeholder now emits \includegraphics of the S073 vector
PDFs (width per span) instead of \framebox placeholders. Verified by an
empty-diff proof: regenerating the .tex from the script now reproduces the
committed artifact byte-for-byte. Closes the silent figure-regression hole.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
```

---

### Task 3: B1 — Strip placeholder caption text

**Files:**
- Modify: `docs/paper_3/build_acmart.py` (`_FIGURE_ROSTER`, 6 `caption=` fields, ~lines 151-213)
- Modify: `tests/paper_3/test_build_acmart_figures.py` (add caption assertions)

- [ ] **Step 1: Write the failing test**

Append to `tests/paper_3/test_build_acmart_figures.py`:

```python
def test_captions_have_no_placeholder_text(tmp_path):
    tex = _build_tex(tmp_path)
    assert "Placeholder for spike measurement" not in tex


def test_captions_keep_real_descriptions(tmp_path):
    tex = _build_tex(tmp_path)
    # spot-check three captions survive intact after the spike strip
    # (underscores are LaTeX-escaped in the rendered caption)
    assert "compressed from Paper 2." in tex
    assert "Byte-stability result (98/98 paired trials) and LLM Skeptic comparison." in tex
    assert "Oracle decision logic, THREAT\\_CONFIRMED branch (oracle.py:101-111)." in tex
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/paper_3/test_build_acmart_figures.py -v`
Expected: `test_captions_have_no_placeholder_text` FAILS (spike text still present).

- [ ] **Step 3: Write minimal implementation**

In `docs/paper_3/build_acmart.py`, in `_FIGURE_ROSTER`, edit each of the six `caption` fields to drop the trailing spike sentence. Exact edits:

fig_1 — `"compressed from Paper 2. Placeholder for spike measurement."` → `"compressed from Paper 2."`

fig_2 — `"confidence-axis drift. Placeholder for spike measurement."` → `"confidence-axis drift."`

fig_3 — `"comparison. Placeholder for spike measurement."` → `"comparison."`

fig_4 — replace:
```python
            "Decoupling: Verdict structure showing decision and explanation "
            "surfaces sourced from different paths. Placeholder for spike "
            "measurement."
```
with:
```python
            "Decoupling: Verdict structure showing decision and explanation "
            "surfaces sourced from different paths."
```

fig_5 — replace:
```python
            "light_skeptic.py:185 with annotation showing the discard. "
            "Placeholder for spike measurement."
```
with:
```python
            "light_skeptic.py:185 with annotation showing the discard."
```

fig_6 — replace:
```python
            "Oracle decision logic, THREAT_CONFIRMED branch "
            "(oracle.py:101-111). Placeholder for spike measurement."
```
with:
```python
            "Oracle decision logic, THREAT_CONFIRMED branch "
            "(oracle.py:101-111)."
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/paper_3/test_build_acmart_figures.py -v`
Expected: PASS (all four tests).

- [ ] **Step 5: Caption-only diff proof**

```bash
python -m docs.paper_3.build_acmart --out .scratch/regen_t3.tex
diff .scratch/regen_t3.tex docs/paper_3/acmart_spike/paper_3_acmart.tex
```

Expected: the ONLY differing lines are the six `\caption{...}` and six `\Description{...}` lines (regenerated version drops the placeholder sentence). No structural, figure-mechanism, or width changes. If anything else differs, STOP and reconcile.

- [ ] **Step 6: Commit**

```bash
git add docs/paper_3/build_acmart.py tests/paper_3/test_build_acmart_figures.py
git commit -F - <<'EOF'
fix(s080): drop placeholder spike text from Paper 3 figure captions (B1)

All six \caption + \Description fields rendered "Placeholder for spike
measurement." in the submission PDF. Strip the stale S072 spike sentence
from _FIGURE_ROSTER; real descriptions kept verbatim.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
```

---

### Task 4: Regenerate artifacts + recompile + submission gates

**Files:**
- Modify (regenerate): `docs/paper_3/acmart_spike/paper_3_acmart.tex`, `docs/paper_3/acmart_spike/paper_3_acmart.pdf`
- Modify (re-render): `docs/paper_3/figures/fig_{1..6}.pdf`

- [ ] **Step 1: Regenerate the canonical `.tex` (clean captions) and re-render figures (TrueType)**

```bash
python -m docs.paper_3.build_acmart
python -m docs.paper_3.build_figures
```

Expected: `[ACMART SPIKE] wrote docs/paper_3/acmart_spike/paper_3_acmart.tex` and `Done. 6 PDF(s) written.`

- [ ] **Step 2: Recompile the PDF (subshell cd; relative paths require cwd = spike dir)**

```bash
( cd docs/paper_3/acmart_spike \
  && pdflatex -interaction=nonstopmode paper_3_acmart.tex > /dev/null \
  && bibtex paper_3_acmart > /dev/null \
  && pdflatex -interaction=nonstopmode paper_3_acmart.tex > /dev/null \
  && pdflatex -interaction=nonstopmode paper_3_acmart.tex > /dev/null ) \
  && echo "RECOMPILE OK"
```

Expected: `RECOMPILE OK`. (A non-zero pdflatex exit prints nothing after; if so, re-run the last `pdflatex` without `> /dev/null` to read the error.)

- [ ] **Step 3: Gate — locked substrings 25/25**

Run: `python docs/paper_3/acmart_spike/verify_pdf_substrings.py`
Expected: `VERDICT: 25 / 25 substrings present in PDF`.

- [ ] **Step 4: Gate — page budget**

Run: `python docs/paper_3/acmart_spike/page_audit.py`
Expected: `end-of-body : page 10` (≤ 10) and overall ≤ 12 (expect 11). If body > 10, STOP — figure reflow pushed the budget; investigate before committing.

- [ ] **Step 5: Gate — no Type 3 fonts**

```bash
pdffonts docs/paper_3/acmart_spike/paper_3_acmart.pdf | grep -i "type 3" && echo "FAIL: Type3 present" || echo "PASS: no Type3"
```

Expected: `PASS: no Type3`.

- [ ] **Step 6: Gate — double-blind metadata still clean**

```bash
pdfinfo docs/paper_3/acmart_spike/paper_3_acmart.pdf | grep -i "^author" && echo "FAIL: Author leak" || echo "PASS: no Author"
```

Expected: `PASS: no Author`.

- [ ] **Step 7: Commit the regenerated artifacts**

```bash
git add docs/paper_3/acmart_spike/paper_3_acmart.tex docs/paper_3/acmart_spike/paper_3_acmart.pdf docs/paper_3/figures/
git commit -F - <<'EOF'
build(s080): regenerate Paper 3 .tex/.pdf + figures (B1+B2+B3 applied)

Regenerated the acmart .tex from build_acmart (clean captions, real
\includegraphics) and re-rendered the six figures with TrueType fonts;
recompiled. Gates: substrings 25/25, body 10pp / overall 11pp, no Type 3
fonts, metadata author-clean.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
```

---

### Task 5: Full regression gate

**Files:** none (verification only)

- [ ] **Step 1: Paper 3 suite**

Run: `python -m pytest tests/paper_3/ -q`
Expected: prior 99 passed / 3 skipped, plus the ~6 new tests → all pass.

- [ ] **Step 2: Full zero-regression suite (the real gate — NOT `pytest -q`)**

Run: `python -m pytest ares/ tests/ -q`
Expected: ≥ 4168 passed + the new tests, 75 skipped, 0 failed. The CLAUDE.md freshness self-test (`tests/test_claude_md_freshness.py`) must pass — the test floor (3,937) is a collected-count minimum, and adding tests only raises the collected count, so **do NOT change the floor**.

- [ ] **Step 3: If all green, the implementation is complete.**

Hand off to `superpowers:finishing-a-development-branch` for squash-merge to `main`, then update the CLAUDE.md ledger + Notion debrief. (Out of this plan's scope.)

---

## Self-Review

**Spec coverage:** B1 → Task 3; B2 → Task 2 (+ empty-diff proof); B3 → Task 1; regenerate/recompile → Task 4; all gates (substrings, page budget, fonts, metadata, full suite) → Tasks 4-5. Scope guards restated in the header. No spec requirement is unaddressed.

**Placeholder scan:** every code/edit step contains literal code; every command has expected output. No TBD/TODO.

**Type/name consistency:** `_build_tex(tmp_path)` helper defined in Task 2 is reused in Task 3; `build_tex(src, REFS, out)` matches the real signature; `render_figure_placeholder` name kept (not renamed) consistently; figure ids `fig_1..fig_6` and width-per-span (`\textwidth` for fig_1, `\columnwidth` for the rest) consistent across tasks.
