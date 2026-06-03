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

### B4 — ✅ RESOLVED (2026-06-02, post-S080) · local `.docx` path removed from the bibliography
- **Was:** the Paper 2 self-cite rendered *"… Preprint (2026). Canonical draft at
  docs/paper_2/PAPER2_DRAFT_v1_2.docx."* — the `note` field of `gmys-casiano-2026`
  (soft-deanon fingerprint + non-standard citation; the bib header claimed `note` fields
  were "removed entirely", but this one slipped through).
- **Fix applied:** dropped the `note` field; the bibliography now renders just
  *"… Preprint (2026)."*. Recompiled — `.docx` path count in the PDF is now **0**; gates
  re-green (substrings 25/25, body 10 / overall 11, author-clean).
- **Coupling caught by the test gate:** the `note`'s `\url{}` was doubling as the entry's
  stable identifier (`test_citation_existence.py`). Resolved honestly via the designed
  escape hatch — `gmys-casiano-2026` added to `ACKNOWLEDGED_PLACEHOLDERS` (it is a
  *verified* self-cite that simply has no public ID until Paper 2 posts to arXiv), not by
  weakening the rule or re-adding the leak.

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
| Submission portal | HotCRP **https://aisec26.hotcrp.com/** | — | Dan-manual upload |
| Abstract registration | **none** (single firm paper deadline) | n/a | ✓ confirmed 2026-06-02 |

> Body is *exactly* 10 pages — the caption fix (B1) only ever *shortens* captions, so it
> is safe for the budget. Don't let any future edit push the body past 10.

## D. Pre-submission checklist (supersedes `ANONYMIZATION_PLAN.md` item 4)

**CC-fixable — ✅ DONE (2026-06-02; S080 + B4 follow-up):**
- [x] B1 + B2 — captions stripped + `build_acmart.py` emits `\includegraphics`; `.tex` regenerated (empty-diff proof)
- [x] B3 — Type-1 (`fonttype 42`) in `build_figures.py`; 6 figures re-rendered (now CID TrueType)
- [x] Recompile + gates: `verify_pdf_substrings.py` 25/25, `page_audit.py` body 10 / overall 11, `pytest tests/paper_3/` 104 pass; full suite 4173+75skip+0fail
- [x] `pdffonts` shows **no Type 3**; `pdfinfo` / XMP author-clean
- [x] B4 — `.docx` note-field dropped from `references.bib`; bibliography clean

**Dan strategy calls:**
- [ ] B5 — final self-cite + appendix-dependency read (low priority; both judged acceptable)

**Dan manual (submission logistics):**
- [ ] anonymous.4open.science mirror — **optional** (only matters if you want reviewers to inspect code; AISec recommends it *when linking a repo* — see §E). **Never print the real `github.com/...` URL.**
- [ ] Eyeball running headers ("Anon.") on every page of the *final* recompiled PDF
- [ ] Upload PDF to the AISec HotCRP portal: **https://aisec26.hotcrp.com/** (single **firm** deadline 2026-07-24; **no** separate abstract registration)
- [ ] Buffer: start the formal packet by **~2026-07-10**

## E. anonymous.4open.science mirror (carried from `ANONYMIZATION_PLAN.md` item 1, CFP-confirmed)

1. Ensure the intended commit is pushed (origin/main @ current HEAD).
2. https://anonymous.4open.science/ → submit the GitHub repo URL + commit SHA.
3. The service returns an anonymized URL `https://anonymous.4open.science/r/<id>/`.
4. The source has **0** github.com / personal URLs today (the codebase is referenced
   narratively, "publicly available under GPL-3.0", with no URL — re-verified
   2026-06-02). If you add a URL, put `\url{…}` in Appendix B; otherwise leave it for
   camera-ready.

> **AISec '26 policy note (verified 2026-06-02 against aisec.cc):** the CFP says
> *"Ensure that there is no way to identify authors, including … when linking code
> repositories (consider using anonymous.4open.science)."* So the mirror is the
> **recommended** path *only if you choose to link a repo* — the paper links none, so it
> is compliant as-is. The repo (`github.com/b33fydan/ARES`) is public and ARES has a
> public following, but that does **not** break double-blind: AISec's policy governs the
> *artifact*, is silent on prior public dissemination/publicity, and reviewers are not to
> actively de-anonymize. The one rule that matters: **never print the real GitHub URL in
> the submission PDF.** (No separate abstract-registration deadline; single firm deadline
> 2026-07-24; portal https://aisec26.hotcrp.com/.)
