# Paper 3 submission-blocker fixes (B1 + B2 + B3) — design

**Date:** 2026-06-02 (post-S079; effectively Session 080)
**Anchor:** CC
**Source of findings:** `docs/paper_3/acmart_spike/SUBMISSION_DERISK_2026-06-02.md` (2026-06-02 de-risk pass)
**Goal:** Turn Paper 3 into a submission-grade artifact for AISec '26 (deadline 2026-07-24, firm) by closing the three fixable blockers, with zero regressions and the build pipeline made honest again.

## Problem

The 2026-06-02 de-risk pass found three fixable issues in the committed submission PDF
(`docs/paper_3/acmart_spike/paper_3_acmart.pdf`, committed `a60c35b` / S073):

- **B1 (blocker).** All six figure `\caption` + `\Description` fields render
  *"Placeholder for spike measurement."* in the PDF. The figure *content* is real and
  publication-quality (S073); only the caption text is stale S072 spike boilerplate.
- **B2 (high).** `build_acmart.py` still emits `\framebox` placeholder boxes. S073
  hand-edited the `.tex` to `\includegraphics` without updating the script, so
  re-running the documented build (`python -m docs.paper_3.build_acmart`) silently
  **regresses the real figures back to placeholder boxes**. "Build reproduces from
  canonical markdown" is currently **false**.
- **B3 (medium / camera-ready).** The six figures embed **Type 3** fonts (matplotlib's
  DejaVu default — `build_figures.py` never sets `pdf.fonttype`). ACM camera-ready /
  IEEE PDF eXpress commonly reject Type 3.

## Goals

1. Remove the placeholder caption text (B1).
2. Restore `build_acmart.py` as the single source of truth so the documented build
   reproduces the committed `.tex` (B2).
3. Re-render the figures with Type-1 / embeddable fonts (B3).
4. Zero regressions; all submission gates green; a submission-grade PDF banked.

## Non-goals / scope guards

- **Do NOT** modify the canonical source markdown
  (`docs/paper_3/source/PAPER3_DRAFT_v1_0_source.md`).
- **Do NOT** touch `references.bib` — B4 (the `.docx` note-field deanon fingerprint) is
  Dan's deferred strategy call, explicitly out of scope here.
- **Do NOT** change figure *content* (`build_figures.py` plotting logic) — only the font
  `rcParams`.
- **Do NOT** touch `oracle.py`, the measurement harness, or any Paper 3 anchor test.

## Chosen approach: A — `build_acmart.py` as source of truth

Considered: (A) fix the script to emit real figures + clean captions and regenerate;
(B) accept the hand-edited `.tex` as canonical and retire the script; (C) = A plus a
script-vs-`.tex` regression test. **A is chosen** — it is the only option that actually
restores reproducibility (B2), and it is low-risk because the script's scaffolding
(`\setcounter`, env, `\caption`, `\Description`, `\label`) is already byte-identical to
the committed `.tex`; S073 changed only one body line per figure.

### B1 + B2 — `docs/paper_3/build_acmart.py`

- In `render_figure_placeholder`, replace the `\framebox{…}` body line with an
  `\includegraphics` line (keep the function name to minimize the diff and avoid touching
  its two call sites — `render_body` and `render_supplementary_figures_appendix`; the
  now-stale "placeholder" name is flagged as optional later cleanup):
  - `span == "double"` → `\includegraphics[width=\textwidth]{../figures/<fig_id>.pdf}`
  - `span == "single"` → `\includegraphics[width=\columnwidth]{../figures/<fig_id>.pdf}`
  - Every other emitted line is unchanged.
- `_FIGURE_ROSTER`: drop the trailing `". Placeholder for spike measurement."` from each
  of the six `caption` strings; keep the real description verbatim. (The `caption` field
  feeds both `\caption` and `\Description`, so this fixes both surfaces.)
- `height_in` becomes vestigial (it only sized the framebox `\rule`). Leave it in the
  dataclass to minimize the diff; flag as optional later cleanup.

### Two-step diff proof (isolates B2 from B1)

1. **Mechanism-only** change (framebox→includegraphics), spike captions still present →
   regenerate `.tex` → `diff` against the committed `.tex` must be **empty**. This proves
   the script now reproduces the committed artifact exactly (B2 closed, in isolation).
2. **Caption strip** in `_FIGURE_ROSTER` → regenerate → `diff` shows **only** the 6
   `\caption` + 6 `\Description` lines (B1).
3. Overwrite the committed `.tex` with the regenerated output.

### B3 — `docs/paper_3/build_figures.py`

- Immediately after `matplotlib.use("pdf")`, set
  `matplotlib.rcParams["pdf.fonttype"] = 42` and
  `matplotlib.rcParams["ps.fonttype"] = 42` (TrueType embedding).
- Re-render all six figure PDFs by re-running the figure builder.

## Tests (TDD, offline, no API)

- **New** `tests/paper_3/test_build_acmart_figures.py`:
  - `build_tex(...)` output contains exactly six `\includegraphics{../figures/fig_N.pdf}`
    (all six ids), **0** `\framebox`, **0** occurrences of `"Placeholder for spike"`.
  - Width per span: `fig_1` (double) → `width=\textwidth`; the other five →
    `width=\columnwidth`.
- **New** font test (own file or added to the above): importing `build_figures` leaves
  `matplotlib.rcParams["pdf.fonttype"] == 42`.
- **Regression net:** existing `tests/paper_3/` (99 pass / 3 skip), `verify_pdf_substrings.py`,
  `page_audit.py`.

## Verification gates (offline, in order)

1. Regenerate `.tex` from `build_acmart`; two-step diff proof passes.
2. Re-render figures; recompile in `acmart_spike` (`pdflatex ×2` + `bibtex`).
3. `verify_pdf_substrings.py` → **25/25**.
4. `page_audit.py` → body ≤ 10 / overall ≤ 12 (expect 10 / 11).
5. `pdffonts` → **no Type 3** (figures now Type 1 / TrueType).
6. `pdfinfo` + `pdfinfo -meta` → no `/Author`, empty `dc:*` (author-clean, unchanged).
7. `pytest tests/paper_3/` + full suite (`pytest ares/ tests/`) → zero regressions.

## Artifacts changed

| File | Change |
|---|---|
| `docs/paper_3/build_acmart.py` | figure emit → `\includegraphics`; roster captions stripped |
| `docs/paper_3/build_figures.py` | `pdf.fonttype`/`ps.fonttype` = 42 |
| `docs/paper_3/figures/fig_{1..6}.pdf` | re-rendered (Type-1 fonts) |
| `docs/paper_3/acmart_spike/paper_3_acmart.{tex,pdf}` | regenerated / recompiled |
| `tests/paper_3/test_build_acmart_figures.py` (+ font test) | **new** |
| `docs/paper_3/acmart_spike/SUBMISSION_DERISK_2026-06-02.md` | already written (audit record) |

## Risks

- **Recompile reflow.** Re-rendered figures could shift pagination → body must stay ≤ 10.
  Mitigation: only the font *type* changes, not figure dimensions, so reflow risk is
  minimal; `page_audit` is the gate.
- **Script output ≠ committed `.tex`.** Caught by the step-1 empty-diff proof *before* any
  caption change, so a mismatch surfaces in isolation.

## Git

Branch `session/080-paper3-submission-derisk`; squash-merge to `main` after zero
regressions; update CLAUDE.md ledger + Notion debrief.
