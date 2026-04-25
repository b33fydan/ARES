# Paper 1 — Canonical Artifact Decision

**Last updated:** 2026-04-25
**Decided in:** Session 053

## Canonical artifact

`docs/paper_1/ARES_Preprint_Asymmetric_Calibration_Failure.pdf` — the
published preprint, 11 pages, generated 2026-03-29.

This single file is the source of truth for everything that cites
"Paper 1." Other artifacts (the generator script, working titles in
session notes, paraphrased summaries in CLAUDE.md or memory) are
descriptive, not authoritative.

## Title reconciliation

| Where it appeared | Title |
|---|---|
| Canonical PDF (cover + page-1) | **The Problem Is Inside the Black Box: Asymmetric Calibration Failure in Multi-Agent LLM Debate** |
| `generate_paper.py` (lines 183-185) | (matches PDF, all-caps formatting) |
| CLAUDE.md / memory (pre-Session 053) | "Structured Dialectical Debate Degrades LLM Accuracy in Cybersecurity Threat Analysis" |
| `docs/paper_2/source/PAPER2_DRAFT_v1_1_source.md` (in-text citation) | (Gmys-Casiano, 2026) — author-year only, not a title reference |

The CLAUDE.md / memory string was a working paraphrase that never
reached the published artifact. The canonical title is the long form
on the PDF cover. Bib entry `gmys-casiano-2026` in
`docs/paper_2/references.bib` was updated to the canonical title in
this session.

## Author and identifier metadata

| Field | Value |
|---|---|
| Author | Daniel Gmys-Casiano |
| Affiliation | Skyframe Innovations |
| Contact | dan@skyframeinnovations.com |
| Year | 2026 |
| Pages | 11 |
| PDF creation timestamp | 2026-03-29T20:23:52Z |
| License | GPL-3.0 (per the framework release) |
| Stable identifier | (none yet — venue, DOI, arXiv ID pending) |

## Generator script disposition

`generate_paper.py` (~1,060 lines, repo root) is the script that
produced the canonical PDF. It is **kept for reproducibility** but is
**not canonical** for the paper's content. Two reasons:

1. **Single source of truth.** Two independent artifacts (script +
   PDF) drift. One artifact (PDF) cannot.
2. **Content lives in the PDF.** The script's body strings are
   already serialized into the PDF; reading the PDF is faithful,
   re-running the script regenerates the same content but adds risk
   of unintended divergence (font availability, library version, etc.).

If the canonical PDF needs to be regenerated (e.g., layout change,
typo discovered), the workflow is:

1. Edit `generate_paper.py`
2. Run it locally
3. Diff the new PDF against the current canonical
4. Commit both the script change and the new PDF
5. Update **Last updated** in this file

This contrasts with Paper 2, where the docx is built from a markdown
source on every run. Paper 1 is frozen; Paper 2 is fluid.

## Missing artifact: `ARES_Paper_Draft.docx`

Earlier session prompts (Session 052 and the Paper 2 references task)
referenced `ARES_Paper_Draft.docx` as a place to look for Paper 1
metadata. That file does not exist in the repo and there is no record
of it ever being committed. Treat it as a phantom reference. The
canonical PDF is sufficient for all metadata needs.

## Update protocol

When the canonical artifact, title, or any metadata field changes:

1. Update the relevant table in this file
2. Update the **Last updated** date at the top
3. Update `gmys-casiano-2026` in `docs/paper_2/references.bib`
4. Update CLAUDE.md if the canonical path changes
5. Run the test suite (`tests/test_claude_md_freshness.py` validates
   that declared canonical paths exist on disk)
