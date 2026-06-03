# Paper 3 — Pre-flight sign-off (2026-06-03)

**Verdict: GO — submission-grade.** Every hard gate passes at HEAD; the two
remaining items are Dan-strategy judgment calls and both resolve favorably.
No code or canonical artifact was modified in this pass; no API spend.

- **Artifact:** `docs/paper_3/acmart_spike/paper_3_acmart.pdf`
- **Commit:** `main` @ `5cd8d43` (== `origin/main`, in sync). The PDF was last
  recompiled in `c5724d6` (the B4 fix), so it reflects **all of B1–B4**.
- **Pass type:** offline re-verification only. New-file record (allowed under the
  "new files only" constraint).
- **Builds on:** `SUBMISSION_DERISK_2026-06-02.md` (S080). This pass re-runs every
  §A / §D gate at HEAD and additionally **closes B5b with evidence**.

## A. Hard gates re-run at HEAD — all PASS

| Gate | Result | How verified |
|---|---|---|
| Paper 3 test suite | **104 passed / 3 skipped** | `pytest tests/paper_3/` |
| Locked-substring gate | **25 / 25** | `verify_pdf_substrings.py` |
| Page budget | **body 10 pp / overall 11 pp** (CFP 10 / 12) | `page_audit.py` (`end-of-body` p10, `end-of-appendix` p11) |
| Fonts | **all embedded; 0 Type 3** (body Type 1, figures CID TrueType) | `pdffonts` |
| `/Author` docinfo | **absent** | `pdfinfo` |
| XMP `dc:creator` | **`Anonymous Author(s)`**; other `dc:*` empty | `pdfinfo -meta` |
| Running headers | **"Anon." ×5** | `pdftotext` |
| Placeholder caption text (B1) | **0** | `pdftotext` grep |
| `.docx` path in PDF (B4) | **0** | `pdftotext` grep |
| GitHub / Skyframe / email / ORCID / `danny` leak | **0** | `pdftotext` grep |
| First-person self-citation ("our prior work") | **none** — third-person only | source grep |
| GenAI-use declaration | **present** (Appendix B, Claude Code disclosed) | `pdftotext` |

## B. Judgment items (Dan's call) — both resolve favorably

### B5a — self-cite renders the author's real name in one reference entry
The Paper 2 self-cite renders as:
> *Daniel Gmys-Casiano. 2026. The Deterministic Skeptic: Four Rules Match an LLM
> Agent in Adversarial Cybersecurity Threat Analysis. Preprint (2026).*

- **Compliant as-is.** Every in-text use is third person ("Paper 2 of the ARES
  program [Gmys-Casiano 2026] established…"); there is **no** first-person
  self-reference. Third-person self-citation with the real name in the reference
  list is standard ACM double-blind practice.
- **Only residual signal:** the cited Paper 2 has no public identifier yet
  ("Preprint (2026)."), so a reviewer cannot look it up. Combined with ~10 cites to
  the one prior author, this is a *soft* de-anon signal — judged acceptable in S080.
- **The one hard rule still holds:** no real GitHub URL anywhere (0 URLs).
- **If Dan wants maximum caution:** the only stronger move is to anonymize this one
  reference's author (e.g. "Anonymous. 2026."). Tradeoff: selectively blanking a
  single reference can itself flag which cite is the self-cite, so ACM norms favor
  leaving it. **Recommendation: leave as-is.**

### B5b — body dependency on appendix-routed figures (RESOLVED: body stands alone)
Fig 2 and Fig 5 sit in the page-11 appendix (Supplementary Figures); the CFP warns
committee members may skip appendices, so the body must stand alone. Verified:

- **Figure 2** (leakage decomposition) is **never referenced in the body.** Its full
  content is in prose: §4.2 (4-bit decomposition + weights), §7.2 ("73 of 98 =
  74.49%", per-operator bit rates 60.6 / 75.8 / 53.1%), §7.3 (first-diverging-layer
  decomposition: Architect 39, LLM Skeptic 34, others 0). Nothing is lost by skipping it.
- **Figure 5** (`light_skeptic.py:185` annotation) is referenced **once, parenthetically**
  ("…targets the line by number (including Figure 5 of this paper)"). The mechanism —
  the `_ = architect_output` discard at line 185 and its anchor test — is fully
  described in §5.2–§5.4 prose. The figure is illustrative, not load-bearing.

**Conclusion:** a reviewer who reads only the 10-page body loses no essential content.

## C. Remaining = Dan-manual (clock-bound: AISec '26 deadline **2026-07-24 firm**)

- [ ] **Upload the PDF to HotCRP: https://aisec26.hotcrp.com/** — single firm
      deadline; **no** separate abstract registration. Upload from `main` @ `5cd8d43`.
- [ ] (optional) **anonymous.4open.science mirror** — only if you want reviewers to
      inspect the code. Steps in `SUBMISSION_DERISK_2026-06-02.md` §E. The anonymized
      `https://anonymous.4open.science/r/<id>/` URL is **safe to print**; the real
      `github.com/...` URL is **never** safe in the submission PDF. Adding the mirror
      means a recompile (URL in Appendix B) → re-run §A gates after. CC can prep this
      on request.
- [ ] Eyeball "Anon." running headers on every page of the final PDF before upload.
- [ ] Buffer: start the formal packet by ~2026-07-10.

## D. What would invalidate this sign-off
- Any recompile that pushes the body past page 10 (currently *exactly* 10 — no slack).
- Printing the real `github.com/...` URL anywhere in the PDF.
- Re-introducing a `/Author` field, the `.docx` `note`, or any placeholder caption text.
- Editing `references.bib` without re-running `build_acmart` (it copies the bib at
  build time) → recompile via `python -m docs.paper_3.build_acmart` then pdflatex/bibtex.

## E. anonymous.4open.science mirror — ready-to-paste wording (NOT yet inserted)

Prepped per request; **not** added to the paper — linking a repo is optional and would
require a recompile + a §A gate re-run. Use only if you choose to let reviewers inspect
code. **Never** paste the real `github.com/...` URL into the submission PDF.

**Steps (from `SUBMISSION_DERISK_2026-06-02.md` §E):**
1. Confirm the intended commit is pushed: `origin/main` @ `5cd8d43` (already in sync).
2. https://anonymous.4open.science/ → submit the repo URL + commit SHA `5cd8d43`.
3. The service returns `https://anonymous.4open.science/r/<ID>/`.
4. Insert the block below into **Appendix B** (page 11 — keeps the body at 10 pp), swap
   `<ID>`, then `python -m docs.paper_3.build_acmart` → pdflatex ×2 + bibtex → re-run §A.

**Ready-to-paste (LaTeX, Appendix B — anonymized URL only):**
```latex
\textbf{Code and data availability.} The ARES implementation, the
\texttt{injection\_registry\_v3} corpus, the pre-registered \texttt{InfluenceLeakage}
schema, and the SHA256-verified leakage traces underlying Findings 1--3 are available
for review at an anonymized mirror: \url{https://anonymous.4open.science/r/<ID>/}
(GPL-3.0). The byte-stability and divergence results reproduce offline from the
archived traces.
```
