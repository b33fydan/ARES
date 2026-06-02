# Paper 3 — Submission de-risk pass (post-S079, 2026-06-02)

**Pass type:** offline verification only. No API spend. **No edits to any canonical
artifact** — this document is an audit + checklist. (New file; allowed under the
"new files only" constraint.)
**Artifact audited:** `docs/paper_3/acmart_spike/paper_3_acmart.pdf`
(11 pp, committed `a60c35b`, Session 073).
**Verified against:** AISec '26 Call for Papers, https://aisec.cc/ (fetched 2026-06-02).
**Supersedes:** the verification portions of `ANONYMIZATION_PLAN.md` item 4 (that
file's manual 4open.science steps are carried forward in §E below).

## Verdict

**Submittable after one blocker is fixed.** The blocker is cosmetic-but-fatal:
all six figure captions still literally read *"Placeholder for spike measurement."*
The figure *content* is real and publication-quality (S073) — only the caption text
is stale spike boilerplate. Double-blind anonymization is essentially clean (one
soft-deanon fingerprint, Dan's call). One reproducibility gap means the documented
build no longer regenerates the committed `.tex` — it matters for *how* the blocker
gets fixed. Three quality fixes are recommended before camera-ready; the cheapest
(Type-1 fonts) is worth doing now.

## A. Verified clean ✓

| Check | Result | How verified |
|---|---|---|
| Locked-substring gate | **25/25 PASS** | `verify_pdf_substrings.py` |
| Paper 3 test suite | **99 passed / 3 skipped** | `pytest tests/paper_3/` |
| PDF `/Author` metadata | **absent** (no leak) | `pdfinfo` — no Author line |
| XMP `dc:*` fields | **empty** | `pdfinfo -meta` |
| Running headers | **"Anon."** on all body pages | rendered text, ×5 |
| Institution leak ("Skyframe Innovations") | **already stripped** → `journal = {Preprint}` | `references.bib:39`; absent in rendered PDF |
| URL / GitHub / email / ORCID leak | **none** | grep of rendered PDF + source markdown |
| Fonts | **all embedded** | `pdffonts` |
| Figure content | **real, publication-quality** | rendered fig_1 + fig_3 to PNG, inspected |
| GenAI use declaration | **present**, after refs, CFP-aware | rendered text (Appendix B) |
| Page budget | **body 10 / overall 11** (CFP: 10 / 12) | `page_audit.py` |

## B. Findings to fix (by severity)

### B1 — BLOCKER · all 6 figure captions read "Placeholder for spike measurement."
- **Evidence:** `paper_3_acmart.tex` caption lines 85 / 142 / 171 / 180 / 294 / 303;
  rendered in the PDF (e.g. *"Figure 1: ARES three-agent pipeline … Placeholder for
  spike measurement."*). The same stale sentence is duplicated into each `\Description{}`
  accessibility field.
- **Why it matters:** a reviewer sees "Placeholder for spike measurement" on every
  figure. Reads as unfinished; risks a poor first impression at minimum.
- **Fix:** remove the trailing spike sentence from all 6 `\caption` + `\Description`
  (the rest of each caption is already real). Cleanest path is via B2 (one regenerate).
- **Whose call:** CC-fixable (final wording is a small content decision).

### B2 — HIGH · `build_acmart.py` does **not** reproduce the committed `.tex`
- **The "build reproduces from canonical markdown" property is currently FALSE.**
- S073 (`a60c35b`) hand-edited the `.tex` — 6 figures swapped from `\framebox`
  placeholders to `\includegraphics{../figures/fig_N.pdf}` (12 lines) — but did **not**
  update `build_acmart.py`. The script (last touched S072 `4ddbf18`) still emits
  `\framebox` placeholders.
- **Proof:** regenerating from the script yields **0 `\includegraphics` / 6 `\framebox`**;
  the committed `.tex` has **6 / 0**. `diff` = 12 changed lines.
- **Consequence:** re-running the documented build
  (`python -m docs.paper_3.build_acmart`) silently **regresses the real figures back to
  placeholder boxes**. The committed `.tex` is a hand-edited artifact, not generated
  output.
- **Fix:** update `_FIGURE_ROSTER` captions to final text **and** change
  `render_figure_placeholder` to emit `\includegraphics{../figures/<fig_id>.pdf}`
  (keep the `\setcounter{figure}` numbering + the body/appendix routing intact). One
  `build_acmart` run then regenerates a correct `.tex` with correct captions — **this
  closes B1 and B2 together.** Recompile (`pdflatex ×2` + `bibtex`); re-run the gates.
- **Whose call:** CC-fixable (mechanical; preserves all existing structure).

### B3 — MEDIUM (camera-ready) · figures embed Type 3 fonts
- **Evidence:** `pdffonts` shows figure text as **Type 3** `DejaVuSans*` (matplotlib
  default). Body fonts are Type 1 (LinLibertine / Inconsolata — fine).
- **Why it matters:** ACM camera-ready / IEEE PDF eXpress commonly reject Type 3
  fonts. Usually tolerated at review; a camera-ready blocker. Cheaper to fix now.
- **Fix:** in `build_figures.py` set `matplotlib.rcParams['pdf.fonttype'] = 42`
  (and `ps.fonttype = 42`), re-render the 6 figures, recompile, re-check `pdffonts`.
- **Whose call:** CC-fixable.

### B4 — LOW / JUDGMENT · local `.docx` path renders in the published bibliography
- **Evidence:** the Paper 2 self-cite renders as *"… Preprint (2026). Canonical draft
  at docs/paper_2/PAPER2_DRAFT_v1_2.docx."* — the `note` field of `gmys-casiano-2026`
  (`references.bib:40`).
- **Why it matters:** soft-deanon fingerprint (exposes repo workflow structure) +
  non-standard citation (a published reference shouldn't point at a local file). The
  bib header (`references.bib:19–25`) claims `note` fields "are removed entirely" — this
  one slipped through.
- **Fix:** drop the `note` from `gmys-casiano-2026`, or replace it with Paper 2's arXiv
  ID once it posts (existing TODO at `references.bib:33`).
- **Whose call:** **Dan** — `ANONYMIZATION_PLAN.md` item 3 logged this as a deferred
  strategy decision. (Recommendation: drop the note.)

### B5 — JUDGMENT (likely no action) · self-cite volume + appendix-routed figures
- ~10+ `[Gmys-Casiano 2026]` cites to a single prior author — standard third-person
  double-blind practice, a mild de-anon signal. Acceptable; Dan's final read.
- Fig 2 + Fig 5 are routed to the supplementary appendix (S072 triage). The CFP confirms
  committee members may skip appendices → the **body must stand alone**. Recommend a
  final read of §4 / §5 to confirm the prose doesn't *depend* on Fig 2 / Fig 5.

## C. AISec '26 CFP compliance (verified 2026-06-02, https://aisec.cc/)

| Requirement | CFP | This paper | Status |
|---|---|---|---|
| Submission deadline | **July 24 2026 (firm)** | targets 2026-07-24 | ✓ (~52 days out) |
| Body length | ≤ 10 pp, **excl.** bib + well-marked appendices | 10 pp | ✓ — **at the limit, no slack** |
| Overall length | ≤ 12 pp | 11 pp | ✓ |
| Format | double-column ACM (sigconf) | `sigconf, anonymous, review` | ✓ |
| GenAI-use declaration | **mandatory**, after refs/appendices | present (Appendix B) | ✓ |
| Anonymity | double-blind | anonymous mode on; metadata clean | ✓ |

> Body is *exactly* 10 pages — the caption fix (B1) only ever *shortens* captions, so it
> is safe for the budget. Don't let any future edit push the body past 10.

## D. Pre-submission checklist (supersedes `ANONYMIZATION_PLAN.md` item 4)

**CC-fixable (with Dan's go-ahead):**
- [ ] B1 + B2 — rewrite 6 captions + make `build_acmart.py` emit `\includegraphics`, then regenerate the `.tex` from the script (one honest pass)
- [ ] B3 — Type-1 (`fonttype 42`) in `build_figures.py`, re-render the 6 figures
- [ ] Recompile (`pdflatex ×2` + `bibtex`); re-run `verify_pdf_substrings.py` (expect 25/25), `page_audit.py` (expect body ≤ 10 / overall ≤ 12), `pytest tests/paper_3/`
- [ ] Re-confirm `pdffonts` shows **no Type 3**; `pdfinfo` / XMP still author-clean

**Dan strategy calls:**
- [ ] B4 — drop the `note` `.docx` path (recommend: yes)
- [ ] B5 — final self-cite + appendix-dependency read

**Dan manual (submission logistics):**
- [ ] anonymous.4open.science mirror (steps in §E); wire URL into Appendix B only if adding one
- [ ] Eyeball running headers ("Anon.") on every page of the *final* recompiled PDF
- [ ] Upload PDF to the AISec submission portal (HotCRP — link from https://aisec.cc/)
- [ ] Buffer: start the formal packet by **~2026-07-10** (≥ 2 weeks before the firm deadline)

## E. anonymous.4open.science mirror (carried from `ANONYMIZATION_PLAN.md` item 1, CFP-confirmed)

1. Ensure the intended commit is pushed (origin/main @ current HEAD).
2. https://anonymous.4open.science/ → submit the GitHub repo URL + commit SHA.
3. The service returns an anonymized URL `https://anonymous.4open.science/r/<id>/`.
4. The source has **0** github.com / personal URLs today (the codebase is referenced
   narratively, "publicly available under GPL-3.0", with no URL — re-verified
   2026-06-02). If you add a URL, put `\url{…}` in Appendix B; otherwise leave it for
   camera-ready.
