# Paper 3 docx pipeline — fate decision (Part B item 5)

**Session 072. Awaiting strategy GO on retirement.**

## Recommendation: **retire `docs/paper_3/build_v1_0.py`**

The docx pipeline served Sessions 064–071 as a verification artifact: number_check ran against the rendered docx prose, and the test suite's docx-pending tests activated once the docx existed. That role is now superseded by the sigconf LaTeX path:

| Concern | Old (docx) | New (LaTeX) |
|---|---|---|
| Submission artifact | docx (single-column, non-compliant with AISec sigconf) | sigconf PDF (compliant with AISec CFP) |
| Prose substring gate | `number_check --docx` against rendered docx body | `verify_pdf_substrings.py` against pdftotext of compiled PDF (25/25 PASS) |
| Citation rendering | Manually-written natural prose; no auto-formatting | natbib `\citep` / `\citet` from pandoc-style markers in canonical source |
| Bib rendering | Custom `_format_reference` (ACM-ish but compressed) | ACM-Reference-Format.bst (official ACM style) |
| Figure placement | Inline only | Floated with `[!htbp]` + `\FloatBarrier` for appendix grouping |
| Page-budget audit | None | `page_audit.py` reads `.aux` for end-of-body / end-of-bib / end-of-appendix labels |

## What retirement entails

If strategy approves retirement:

1. **Move `docs/paper_3/build_v1_0.py`** → `docs/paper_3/retired/build_v1_0_docx.py` (keep code in tree for historical reference; signal retirement via path).
2. **Move `docs/paper_3/PAPER3_DRAFT_v1_0.docx`** → `docs/paper_3/retired/` (archival).
3. **Delete or skip the docx-pending tests** in `tests/paper_3/test_citation_existence.py` (lines that gate on `DOCX_PATH.exists()` — currently shown as `skipped` in test output). They become permanently skipped after archival, or removed entirely.
4. **Promote `docs/paper_3/build_acmart.py`** to the canonical build script. Rename to `docs/paper_3/build_v1_0.py`? Or keep `build_acmart.py` and document the rename intent? **Recommend keep the acmart name** — the LaTeX path is now the canonical path; the `v1_0` suffix in the docx pipeline was always a version-versus-pipeline confusion.
5. **Update CLAUDE.md** under "Canonical Artifacts":
   - Remove "Paper 3 v1.0 draft (canonical, anonymized...): `docs/paper_3/PAPER3_DRAFT_v1_0.docx`"
   - Add "Paper 3 v1.0 submission artifact: `docs/paper_3/acmart_spike/paper_3_acmart.pdf`" (or relocate the spike dir to a canonical name like `docs/paper_3/submission/`)

## What retirement does NOT entail

- **Canonical markdown source stays as-is.** `docs/paper_3/source/PAPER3_DRAFT_v1_0_source.md` is the source of truth for both pipelines today; it remains the source of truth for LaTeX alone after retirement.
- **`build_references.py` (the BibTeX helper) stays.** Its `parse_bib_file` + `extract_citations` + `citation_to_bibkey` helpers are still used by the test suite for structural invariants on `references.bib`. The bibliography helpers are pipeline-neutral.
- **`number_check.py` stays.** Its 12 skeleton-vs-source claims are pipeline-neutral. The `--docx` mode becomes dormant or is removed; the prose-substring list moves to `verify_pdf_substrings.py` as the active gate.

## What the test suite looks like after retirement

| Test file | Status |
|---|---|
| `tests/paper_3/test_skeleton_audit.py` | Unchanged (35 tests) |
| `tests/paper_3/test_number_check.py` | Unchanged (27 tests) |
| `tests/paper_3/test_citation_existence.py` | 18 always-on + 3 docx-pending → either drop the docx-pending tests or keep them as permanently skipped |

Current count: 99 passed + 3 skipped. Post-retirement: ~96 passed + 0 skipped (cleaner), or 99 passed + 3 permanently skipped (lossless).

## Alternative: keep docx as internal-only verification artifact

If strategy wants to retain the docx for redundancy:

- Update `build_v1_0.py` to parse pandoc-style markers `[@key]` / `@key` and render them as literal `(Author, Year)` / `Author (Year)` (or similar) in the docx body. The custom `_format_reference` already produces compressed ACM-ish references; minor cosmetic.
- Update the docx-pending tests to check the new marker-rendering codepath.
- Maintain two pipelines indefinitely. Each future schema / prose / bib change touches both.

**Recommendation against this option.** The docx no longer represents the submission artifact (LaTeX does), no longer represents the verification gate (`verify_pdf_substrings.py` does), and no longer represents the rendering target (acmart does). Maintaining it is double-cost without payoff.

## STOP for strategy decision

Strategy GO/NO-GO on retirement → I will execute the file moves + CLAUDE.md update + test-skip cleanup in a single commit. Until then, the docx pipeline is left untouched and the spike artifacts at `docs/paper_3/acmart_spike/` remain the LaTeX-side staging.
