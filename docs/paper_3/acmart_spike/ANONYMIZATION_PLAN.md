# Paper 3 anonymization plan — Part B item 4

**Session 072. Mostly out of CC's reach — surfaces the manual steps for Dan to execute before the AISec deadline (2026-07-24).**

## What's already anonymized in the spike PDF

- **Author block redacted** at the start of the markdown source (`**[Author block redacted for double-blind review]**`), surfaced by the build script under acmart's `anonymous` documentclass option.
- **Self-cites in third-person form.** The `gmys-casiano-2026` bib key and `[Gmys-Casiano 2026]` inline cite text are third-person references to "the preceding ARES paper" — consistent with AISec's double-blind expectations (Session 069 GO 3 discipline).
- **Internal session bookkeeping stripped from rendered bibliography.** `references.bib` Session-numbered provenance (the "Session 068 verified" / "Session 071 bibkey renamed" trail) moved to `%` comments above each entry in Session 072 task 2; no longer leaks into the published references.
- **ACM email anonymized.** `\email{anonymous@aisec26.example}` in the acmart preamble — no real author email.

## What still needs to happen (manual, before submission)

### 1. anonymous.4open.science repo mirror

The submitted paper references the ARES codebase ("publicly available under GPL-3.0 for independent replication", Appendix B). The current repository on GitHub identifies the author. The standard double-blind workflow is to mirror to anonymous.4open.science:

1. Push the current branch state to a GitHub repo (already done — origin/main).
2. Visit https://anonymous.4open.science/ and submit the GitHub repo URL with the desired commit SHA.
3. The service generates an anonymous URL of the form `https://anonymous.4open.science/r/<random-id>/`.
4. **Wire the anonymous URL into the paper.** Search the markdown source + acmart preamble for any `github.com` / personal-domain references and replace with the 4open.science URL. Current count of GitHub / personal URL references in the source: **0** — the codebase is referenced narratively ("under GPL-3.0") without a URL.
5. **Decide whether to add an explicit URL.** The appendix declares the code is "publicly available" — reviewers may expect a URL. Either:
   - Add `\url{https://anonymous.4open.science/r/<id>/}` to the appendix once the mirror is set up.
   - Or leave the appendix as-is and trust reviewers to wait for the camera-ready URL.

### 2. Running-header audit

acmart's `anonymous` mode strips the author name from `\runningauthor`, replacing it with "Anon." (visible on every body page top of the spike PDF). The running title carries the paper's title (which is the same for anon + non-anon versions).

**Checklist for Dan to eyeball after the next compile:**
- [ ] Confirm every body page top shows "Anon." in the author position (not the real author name).
- [ ] Confirm the running title matches the `\title{...}` value in the preamble — no leak of "Paper 3 by [author]" or similar workflow shorthand.
- [ ] Confirm no `\thanks{}` or `\affiliation{}` block reveals the author (currently `\affiliation{\institution{Submission under double-blind review}\country{}}` — neutral).

### 3. Semantic deanonymization pass

Per brief: **Dan's job, not CC's.** CC can flag potentially identifying language; final call is human. Below is what I would flag based on what I have seen in the prose:

- **"Skyframe Innovations"** — appears in the redacted author block (line 8 of source markdown, inside the HTML comment) and in the `gmys-casiano-2026` bib `journal = {Preprint, Skyframe Innovations}`. The comment is stripped at build time so the markdown reference is fine. The bib entry's `journal` field IS rendered in the published bibliography as the venue/source. **Action needed:** decide whether "Preprint, Skyframe Innovations" reveals enough to deanonymize. Suggested replacement: `journal = {Preprint}` (drop the institution name). Trivial edit, awaits Dan's call.
- **`docs/paper_2/PAPER2_DRAFT_v1_2.docx`** path in the same bib entry's `note` — already audited in Session 072 third gate (kept per strategy decision; soft-deanon risk from "repo workflow structure" only).
- **"ARES" / "OracleJudge" / "Light Skeptic"** — kept as research-artifact identifiers per the markdown comment block. These are project terms, not author identifiers. Safe.
- **"Phase 5" / "Phase 6" / "Phase 7"** language — internal phase numbering. Doesn't reveal author but reveals a multi-phase research program. Probably fine in context (the paper describes itself as part of "the ARES program").
- **References to Paper 2 self-cite count** — multiple `[Gmys-Casiano 2026]` cites are expected for a forward-ref paper; consistent with double-blind norms.

### 4. Submission packet checklist (deadline 2026-07-24)

When strategy is ready to submit:

- [ ] Final compile with `[sigconf,anonymous,review]` (current spike configuration).
- [ ] Run `verify_pdf_substrings.py` — confirm 25/25 PASS.
- [ ] Run `tests/paper_3/` — confirm zero regressions.
- [ ] Eyeball running headers + body page top on every page.
- [ ] Confirm anonymous.4open.science URL is wired (if adding one).
- [ ] Final page count audit via `page_audit.py` — body ≤ 10, overall ≤ 12.
- [ ] Submit PDF via AISec submission portal.

### 5. Post-notification (2026-09-03)

If accepted:
- Remove `anonymous` option from `\documentclass[...]`.
- Restore real author block: `Daniel Gmys-Casiano, Skyframe Innovations`.
- Wire the Paper 2 arXiv ID into `gmys-casiano-2026.note` (currently a local path placeholder).
- Wire the anonymous.4open.science URL to a real GitHub URL.
- Camera-ready compile + submit.

## STOP for strategy direction

This is documentation only — no edits applied this session. Strategy decisions needed before the 2026-07-24 deadline:

1. **Skyframe Innovations in the `journal` field**: strip to `Preprint` or leave? Recommend strip.
2. **anonymous.4open.science URL**: wire into appendix or leave for camera-ready? Strategy call.
3. **Submission window timing**: when to start the formal submission packet pass? Recommend allow ≥ 2 weeks of buffer (start by 2026-07-10).
