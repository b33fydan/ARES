# SESSION 073 — Paper 3 real figures (audit → render → re-gate)

**Lane**: Execution (CC). Paper 3 is a format-compliant, verified acmart sigconf artifact at 4ddbf18, EXCEPT fig_1–fig_6 are placeholders. This session replaces them with real, publication-quality figures generated from source data.

**Two phases. Phase 1 is non-destructive and STOPS for Dan. Do not render anything in Phase 1.**

---

## HARD RULES (non-negotiable, this is an evidentiary-integrity project)

1. **NO fabricated, synthetic, illustrative, or "representative" figure data. Ever.** Every figure renders from real data already in the repo.
2. **Figures render from the same source artifacts that `number_check` validates against** (JSONL traces, markdown leakage reports, Python source files — no CSVs in the Paper 3 pipeline), so a figure and a verified number in the prose can never disagree. Trace each figure to that source.
3. **If a figure's intended content or its backing data is ambiguous or missing → STOP and report.** Do not invent a plausible plot. A fabricated figure is the worst possible defect in this paper.
4. **No author-identifying content in any figure**: no "Skyframe," no personal paths, no identifying watermark/metadata, in titles, legends, captions, axis labels, or embedded file metadata. Anonymous build.

---

## Phase 1 — Figure audit + manifest (NO rendering; STOP at end)

For each of fig_1 through fig_6:
- Read its inline reference(s) and caption in the canonical source to determine **intended content** (what claim/structure the figure makes).
- Locate the **backing data file(s)** in the repo (JSONL traces / leakage reports / source code). Confirm it's the same source `number_check` uses where the figure shows a verified number.
- Note **column width**: single-col (~3.3in) or double-col (~7in) per current placement. (Recall: Fig 1 double-col body; Fig 3/4/6 body finding sections; Fig 2/5 Appendix A.)
- Classify data status: **DATA** / **DESIGN-REQUIRED** / **AMBIGUOUS** / **MISSING**.
  - **DATA** (Rule 1 applies): figure renders from real source artifacts. Applies to fig_3 (LEAKAGE_REPORT §2 per-bit + §3 per-layer), fig_5 (light_skeptic.py:185), fig_6 (oracle.py:88-115). STOP on ambiguous backing fully intact.
  - **DESIGN-REQUIRED**: figure is a schematic/architecture diagram, not a data plot. Applies ONLY to fig_1 (pipeline architecture), fig_2 (InfluenceLeakage 4-bit decomposition), fig_4 (Verdict two-surface structure). Frozen list — no other figure may be reclassified into this bucket.
    - Guardrail: each DESIGN-REQUIRED schematic must faithfully depict the real implemented structure (fig_4 matches the actual Verdict object in oracle.py, fig_2 matches the actual 4-bit decomposition). STOP if the diagram would misrepresent the implementation.
  - **AMBIGUOUS** / **MISSING**: STOP and report.

Output a manifest table: `fig# | section | placement | intended content | backing data path | col width | data status`.

**STOP. Report the manifest and request Dan's confirmation/correction before any rendering.** Flag every AMBIGUOUS/MISSING row explicitly — those need Dan's input, not a CC guess.

---

## fig_1 disposition (Flag 4)

Do NOT reuse `docs/paper_2/figures/fig1_architecture.png` blindly. Two problems:
1. Built non-anonymous (Skyframe / author / metadata risk → Hard Rule 4 violation).
2. Raster, not vector.

Phase 1: inspect fig1_architecture.png for embedded text and metadata. Report findings.
Phase 2: fig_1 gets a fresh anonymized vector render (new file). Only exception: the PNG proves clean on inspection AND high enough DPI — and even then, lean vector for camera-ready.

---

## Phase 2 — Render (ONLY on GO, only for confirmed rows)

1. New file `docs/paper_3/build_figures.py`: renders each confirmed figure from its backing data to **vector PDF** at the correct sigconf column width.
   - Consistent house style across all six. Colorblind-safe palette. Legible at print size. No chartjunk.
   - Map to ARES's existing visual identity where it fits (agent colors etc.), but legibility and anonymity win over branding.
2. Swap each placeholder for its real figure. Preserve canonical figure numbering (the `\setcounter` scheme from S072).
3. **Re-measure pages.** Real figures resize the layout. Report body + overall vs 10/12 (AISec limits: ≤10 body, ≤12 overall; current measured state: 10 body / 11 overall).
   - Body is at the 10-page cap with zero slack. Body figures (1, 3, 4, 6) must land footprint-neutral or smaller versus their placeholders. No room to grow the body.
   - Overall has 1 page slack (11 → 12). Appendix figures (2, 5) can use this.
   - Re-measure after every render, not just at the end.
   - If over 10 body: lever is figure *sizing* or relocating another figure to Appendix A. **Prose stays locked** (§4.4, §6.6, findings, the 25 substrings — all untouchable). Report before acting.
4. Re-run gates: pdftotext substring gate (25/25), `tests/paper_3/`, freshness. Zero regressions.

**STOP for commit GO.** Nothing merged without it.

---

## OUT OF SCOPE
- Prose edits of any kind. Source is frozen.
- arXiv anything (parked).
- anonymous.4open.science mirror + semantic deanon pass (Dan-manual, not CC).
- Notion (connector down; handoff stays in docs/ markdown).

---

## Discipline
- Phase 1 produces a decision artifact, not changes. Phase 2 is new files + figure swaps only.
- Figures trace to verified source data or they don't ship.
- STOP at the Phase 1 manifest AND at the Phase 2 commit gate.

---

*Staged by strategy window, 2026-05-23, Session 072 close. Map the figures before rendering them; never fabricate one.*
