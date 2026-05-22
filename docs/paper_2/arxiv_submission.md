# arXiv submission packet — Paper 2 v1.2

**Prepared:** 2026-05-22 (Session 069, GO 2)
**Target archive:** arXiv cs.CR primary
**Post order:** 2 of 2 (post AFTER Paper 1 has its arXiv ID)
**Posting blocker:** PDF generation from .docx (manual step — see below).

---

## Title-mismatch flag (strategy review needed)

The canonical title on the compiled v1.2 docx (`docs/paper_2/PAPER2_DRAFT_v1_2.docx`) is:

> **The Deterministic Skeptic: Four Rules Match an LLM Agent in Adversarial Cybersecurity Threat Analysis**

The working title in `docs/paper_3/references.bib` `gmys-casiano-2026` is:

> *Light Skeptic: A Deterministic Primitive for Adversarial Multi-Agent LLM Pipelines*

These differ. The docx title is what readers and arXiv will see; the bib title is what Paper 3 currently cites. **Recommendation**: use the docx title for arXiv submission (it's the actual canonical artifact). Update Paper 3's `references.bib` to match the docx canonical title AFTER posting, so the cite name matches the published artifact. This packet uses the docx title.

---

## Submission form fields (paste into arxiv.org/submit)

### Title
The Deterministic Skeptic: Four Rules Match an LLM Agent in Adversarial Cybersecurity Threat Analysis

### Authors
Daniel Gmys-Casiano

### Affiliation
Skyframe Innovations

### Author email (corresponding)
danny.casiano@gmail.com

### Subject classification
- **Primary:** cs.CR (Cryptography and Security)
- **Secondary:** cs.AI (Artificial Intelligence)

### Abstract (paste verbatim — extracted from v1.2 docx XML)

> Multi-agent LLM pipelines for adversarial cybersecurity analysis typically combine a threat-hypothesis agent (Architect), an adversarial-challenge agent (Skeptic), and an adjudication layer (Oracle). We report a three-way benchmark that measures each non-adjudication component's contribution to verdict accuracy against a pre-registered rubric, on a corpus of 27 prompt-injection scenarios spanning direct-instruction, subtle-framing, and cross-agent-propagation attacks. A deterministic syntactic firewall catches 4 of 4 direct-injection scenarios and 0 of 19 framing scenarios, the designed-outcome ceiling of surface-pattern defenses. A Skeptic-ablation experiment on the same 19 framing scenarios drops verdict accuracy by 10.5 percentage points, an AMBIGUOUS result under the pre-registered rubric; half of that drop is attributable not to lost reasoning but to the Oracle's decision table requiring a non-zero `skeptic_confidence` to return the THREAT_DISMISSED verdict class. We replace the LLM Skeptic with a four-rule deterministic engine that reasons over structured evidence fields (authorization markers, benign-explanation markers, kill-chain stage) and evaluate it against the full pipeline on an expanded 25-scenario framing corpus. The Light Skeptic matches the LLM Skeptic's framing accuracy to the exact decimal (21/25 both, 0.8400), clearing a pre-registered SUPPORTED threshold by 5 percentage points of headroom. The two variants disagree on two scenarios with offsetting errors: one rule-over-reach, one ordering-driven reasoning failure. We discuss five generalizable observations: ablation in multi-agent pipelines conflates reasoning contribution with verdict-space access; syntactic defenses have a structural ceiling against semantic attacks; evidence-graph reasoning substitutes for LLM reasoning when domain structure is available; LLM and deterministic failure modes differ in kind, not only in rate; and deterministic verification converts semantic attacks into data integrity attacks rather than eliminating them. The framework, corpus, and benchmark artifacts are publicly available under GPL-3.0.

### Keywords (free-form)
deterministic rule engine, multi-agent LLM, adversarial cybersecurity, prompt injection, framing attacks, ablation, evidence-grounded reasoning, semantic defense, data integrity

### Comments (optional, ~200 chars)
13 sections, 5 figures. v1.2 adds fifth generalizable observation on semantic→data-integrity attack conversion. Builds on arXiv:[Paper 1 ID once posted]. ARES framework at https://github.com/b33fydan/ARES under GPL-3.0.

### License
Same as Paper 1 (recommended **CC BY 4.0** for paper text; GPL-3.0 separately for framework code).

---

## File to upload — generation required

`docs/paper_2/PAPER2_DRAFT_v1_2.docx` (598,381 bytes, 13 sections, 5 figures)

**No PDF currently exists for v1.2.** Generation step:

```
1. Open docs/paper_2/PAPER2_DRAFT_v1_2.docx in Microsoft Word.
2. File > Export > Create PDF/XPS Document.
3. Save as docs/paper_2/PAPER2_DRAFT_v1_2.pdf.
4. Verify:
   - Page count is roughly 13-15 (ACM single-column at standard font).
   - All 5 figures rendered cleanly.
   - Title/abstract/authors visible on page 1.
   - References section complete.
```

Alternative if Word isn't preferred: LibreOffice headless (`soffice --headless --convert-to pdf PAPER2_DRAFT_v1_2.docx`) or any docx→PDF service. **Verify font embedding is on** — arXiv rejects PDFs with missing font references.

**Once PDF exists**, upload to arXiv at the submission portal.

---

## After posting

Once arXiv assigns a paper number for Paper 2 (e.g., `arXiv:2605.YYYYY`):

1. Update `docs/paper_3/references.bib` — the `gmys-casiano-2026` entry there points at Paper 2. Add `eprint = {2605.YYYYY}` and `doi = {10.48550/arXiv.2605.YYYYY}` fields, and update the note field to reflect that Paper 2 is now posted.
2. Update `docs/paper_2/references.bib` — entry self-cite (rare; Paper 2's own bib points at Paper 1 not itself).
3. Update `CLAUDE.md` "Where We Are" and "Canonical Artifacts" sections to include the arXiv ID.
4. Update `docs/paper_2/source/PAPER2_DRAFT_v1_2_source.md` self-cite line (if any) — Paper 2 cites Paper 1 as `(Gmys-Casiano, 2026)`; that cite resolves correctly already, but the new arXiv ID for Paper 1 should land in `docs/paper_2/references.bib` before any v1.3 rebuild.

---

## Pre-posting checklist

1. ✅ Paper 1 has been posted to arXiv (we have its arXiv ID).
2. ⬜ `docs/paper_2/references.bib` `gmys-casiano-2026` entry (which points at Paper 1) updated with Paper 1's arXiv `eprint` / `doi`.
3. ⬜ v1.2 docx regenerated if step 2 changed bib entries that get rendered into the docx (build_v1_2.py re-run if so).
4. ⬜ PDF generated from v1.2 docx and visually inspected.
5. ⬜ Submit via arxiv.org/submit using the metadata above.

---

## AISec '26 / Paper 2 venue considerations

- AISec '26 prohibits "papers that have been published previously or that are simultaneously submitted to a journal or conference/workshop **with proceedings**." arXiv is NOT a venue with proceedings, so posting Paper 2 to arXiv does NOT preclude AISec submission.
- If Paper 2 is submitted to AISec '26 (alongside Paper 3 — Dan to confirm whether both go to AISec '26 or Paper 2 to a separate venue), the AISec review is double-blind. Paper 2 on arXiv during the review window is acceptable per ASIACCS-family norms IF self-cites are in third-person form. Paper 2 has no Gmys-Casiano self-cites in its own text (it cites Paper 1 only). So no anonymization concern for Paper 2's own arXiv version.

---

## Open questions for strategy review

1. **Title reconciliation** — docx title vs bib working title. Recommend docx title (canonical). Confirm.
2. **License choice** — same as Paper 1, confirm CC BY 4.0.
3. **Paper 2 venue** — AISec '26 alongside Paper 3, OR a separate venue (USENIX Sec workshop track, ACSAC, AISec '27)? Decision affects timing of arXiv posting.
4. **Bib update timing** — update `references.bib` for Paper 1 arXiv ID before vs after Paper 2 arXiv submission. Recommend: update bib first, regenerate v1.2 (or skip regen — the bib is read from `references.bib` not embedded in the docx, depending on build script behavior). Verify.
