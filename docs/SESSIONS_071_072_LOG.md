# ARES Sessions 071 + 072 — session log

**Captured:** 2026-05-24
**Scope:** Paper 3 v1.0 production pipeline — from docx prose-complete build (Session 071) to acmart sigconf submission artifact for AISec 2026 (Session 072).
**Status:** Sessions 071 + 072 squash-committed to `main`. Paper 3 is submission-ready for AISec 2026 (deadline 2026-07-24); awaiting strategy on two anonymization sub-decisions documented in `docs/paper_3/acmart_spike/ANONYMIZATION_PLAN.md`.

This log substitutes for the Notion page Dan asked for — the Notion MCP server's OAuth flow was unresolvable in-session, so this file lands the same content on disk in canonical form.

---

## Session 071 — Paper 3 v1.0 docx built + Path A bibkey reconcile (commit `5ced9c6`)

### Phase A — docx build
- New build script `docs/paper_3/build_v1_0.py` (since retired in Session 072 — see below) consumed the canonical source markdown and emitted `docs/paper_3/PAPER3_DRAFT_v1_0.docx`. Build order: Title → redacted author block → body sections → References → Appendix.
- Build pattern lifted from Paper 2's `build_v1_1.py` with HTML-comment stripping, inline markdown rendering, bullet-list handling.
- Completion gate `python -m docs.paper_3.number_check --docx` activated prose-substring mode against the docx body: **37/37 PASS** (12 skeleton-vs-source + 25 prose-substring).

### Phase B — Path A bibkey reconcile (the unanticipated work)
- The docx-pending citation-existence test (skipped Sessions 064–070, activated when the docx landed) surfaced a Session 068 bibkey-convention mismatch: Session 068 chose multi-author bibkeys (`greshake-abdelnabi-mishra-2023`, `guo-chen-zhang-2024`, `reiter-1978-closed-world`), but the Paper 3 prose used `Author et al. (Year)` narrative form, which round-trips through `citation_to_bibkey` to `firstauthor-year` keys — mismatching the bib.
- STOP-and-reported to strategy. Three paths considered:
  - **Path A** (chosen) — rename the three Session-068 multi-author bibkeys to canonical `firstauthor-year` form matching Paper 2's `lee-2024` / `hossain-2025` convention. `jacovi-goldberg-2020` and `berdoz-rugli-wattenhofer-2026` retained (parenthetical cite forms round-trip correctly).
  - **Path B** (rejected) — helper regex changes under the Session 055 lock.
  - **Path C** (rejected) — aliasing layer.
- Two §2 cite-form recasts to parenthetical were applied to eliminate a `wattenhofer-2026` narrative-regex partial-match false positive:
  - Jacovi: `Jacovi and Goldberg (2020) formalize ...` → `Faithfulness has been formalized ... (Jacovi, Goldberg, 2020)`
  - Berdoz §2: narrative → parenthetical `(Berdoz, Rugli, and Wattenhofer, 2026)` (§6.5 / §7.4 / §8.4 parenthetical forms unchanged)
- Anonymization held end-to-end. Figures fig_1–fig_6 referenced in prose but not yet rendered in the docx (out of scope for the verification gate). Full suite at session close: **4,113 passed + 75 skipped + 0 failed**.

---

## Session 072 — docx → acmart sigconf migration (the submission pivot)

### Why this session existed

The AISec 2026 CFP requires strict ACM `sigconf` 2-column format. The Session 071 docx (single-column Word) does not comply and would risk rejection at format screening. Session 072 was the measurement spike to determine whether Paper 3's prose + figures fit the AISec budget (10 pages body, 12 pages overall), and then the actual migration.

### Spike (Part A) — three-gate triage

**Toolchain bootstrap.** Project machine had no LaTeX. Installed MiKTeX 25.12 via `winget install MiKTeX.MiKTeX` (≈ 250 MB user install at `%LOCALAPPDATA%\Programs\MiKTeX\`). MiKTeX's `AutoInstall` registry key (`HKCU:\Software\MiKTeX.org\MiKTeX\2.9\MPM\AutoInstall`) flipped from `2` (ask) to `1` (auto-install) so pdflatex would fetch missing packages without hanging on prompts.

**Build script (new).** `docs/paper_3/build_acmart.py` consumes the same canonical source markdown as the docx pipeline. Emits `[sigconf,anonymous,review,nonacm=false]` `.tex` with:
- ACM CCS metadata + keywords stub blocks (per CFP requirement)
- Size-accurate `\framebox` figure placeholders for fig_1–fig_6 (Fig 1 double-column, others single-column)
- `\nocite{*}` + `\bibliographystyle{ACM-Reference-Format}` + `\bibliography{references}` (renders all verified entries despite literal cite text in body — needed for honest 12-page overall measurement)
- `\setcounter{figure}{N-1}` overrides before each figure environment (so canonical Figure 1/2/3/4/5/6 numbering survives the appendix relocation done later in the triage)

**Page-audit tooling (new).** `docs/paper_3/acmart_spike/page_audit.py` parses the `.aux` for `end-of-body`, `end-of-bib`, `end-of-appendix` boundary labels + section TOC entries + figure caption pages. The pdftotext substring gate `verify_pdf_substrings.py` re-verifies all 25 locked prose substrings against the compiled PDF text.

**Three triage gates:**

| Gate | Body | Overall | Status | Action taken next |
|---|---|---|---|---|
| First | 11 | 11 | over by 1 | Strategy decision: move Fig 2 + Fig 5 to a well-marked Supplementary Figures appendix; clean `references.bib` note fields (deanonymization fingerprint + math-mode rendering artifact). |
| Second | 11 | 11 | still over | Strategy decision: surgical cut of §10 closing recap paragraph (70 words, redundant Future-Work recap; §4 methodology stays untouched per pre-registration discipline). `\FloatBarrier` from `placeins` added so Fig 5 stays bound to Appendix A visually. |
| Third | **10** | **11** | **PASS** | GO to Part B (citation marker migration). |

**Locked-substring guard during the §10 cut.** Before-cut count of locked-substring presence in source markdown: 25/25. After-cut count: 25/25 (single instance of `"98"` removed, 34 other instances of `"98"` remain elsewhere).

**`references.bib` cleanup.** Session-numbered provenance (the "Verified Session 068 via web search", "Bibkey renamed Session 071 from ..." trail) moved from `note = {...}` fields to `%` comments above each entry. Rendered notes stripped. Eliminated:
- Math-mode rendering artifact on the bibliography page (underscores in `note` fields were triggering subscripts)
- Deanonymization fingerprint (Session-numbered workflow shorthand in the published bibliography)

Single minimal `\url`-wrapped `gmys-casiano-2026` note retained to satisfy the test suite's `_LOCAL_PATH_RE` canonical-path identifier check: `note = {Canonical draft at \url{docs/paper_2/PAPER2_DRAFT_v1_2.docx}}`.

### Part B — citation marker migration + pipeline reconcile

**Citation marker design.** Pandoc-style markers chosen as the pipeline-neutral source-of-truth: `[@key]` for parenthetical, `@key` for narrative. Negative lookbehind on the narrative form (`(?<![\[a-zA-Z0-9_])`) makes substitution order-independent (parenthetical and narrative substitutions can run in either order without corrupting each other).

**Migration.** 21 cite locations migrated:
- 13 parenthetical literals (`(Gmys-Casiano, 2026)` ×10, `(Berdoz, Rugli, and Wattenhofer, 2026)` ×3, `(Jacovi, Goldberg, 2020)` ×0 after revert) → `[@bibkey]`
- 7 narrative literals (`Guo et al. (2024)` ×2, `Greshake et al. (2023)` ×2, `Reiter (1978)` ×1, plus the two §2 reverts: `Jacovi and Goldberg (2020) formalize ...` and `Berdoz et al. (2026) approached an adjacent question ...`) → `@bibkey`

**§2 recasts reverted.** Session 071's parenthetical-form workarounds for the narrative-regex partial-match bug are no longer needed (the markers fully decouple the source-of-truth from the regex). Both Jacovi and Berdoz §2 references reverted to natural narrative prose.

**LaTeX rendering switch.** `\citestyle{acmauthoryear}` added to acmart preamble — switches from the sigconf-default numbered citation style (`[1]–[6]`) to ACM author-year inline cites (`[Gmys-Casiano 2026]`, `Guo et al. [2024]`, `Berdoz et al. [2026]`, `Jacovi and Goldberg [2020]`, `Reiter [1978]`, `Greshake et al. [2023]`). natbib `\citep` + `\citet` plumbing automatic.

**Anonymization (Session 072 third-gate Task 3).**
- Strip Session-numbered provenance from `references.bib` notes — DONE (above).
- Self-cite URL audit: `\url{docs/paper_2/PAPER2_DRAFT_v1_2.docx}` is a local repo path, not an external author-identifying resource. Per strategy decision: **keep**. Soft-deanon risk from repo workflow structure only; reviewers can't follow the link.
- **Skyframe Innovations strip (post-Part-B finalization)**: `journal = {Preprint, Skyframe Innovations}` → `journal = {Preprint}` per Decision 2.1. Trivial anonymization win; rendered bib entry [2] no longer names the institution.

**docx pipeline retirement (Decision 1).**
- `docs/paper_3/build_v1_0.py` moved to `docs/paper_3/retired/build_v1_0_docx.py`.
- `docs/paper_3/PAPER3_DRAFT_v1_0.docx` moved to `docs/paper_3/retired/PAPER3_DRAFT_v1_0.docx`.
- `tests/paper_3/test_citation_existence.py::TestDocxCitationsResolveAgainstBib` repointed at the archival snapshot. Preserves bibkey-drop regression guard at zero test-count cost (still active, 99 passed + 3 skipped in `tests/paper_3/`).
- CLAUDE.md canonical artifacts list updated.

### Verification at session close

| Check | Result |
|---|---|
| `tests/paper_3/` | 99 passed + 3 skipped, zero regressions |
| `tests/test_claude_md_freshness.py` | 5/5 PASS (declared paths + floor agree with reality) |
| `verify_pdf_substrings.py` on `paper_3_acmart.pdf` | 25/25 PASS |
| `page_audit.py` | end-of-body = page 10, end-of-bib = page 11, end-of-appendix = page 11 |
| PDF total | 11 pages, ~517 KB |
| AISec budget | body ≤ 10 ✓, overall ≤ 12 ✓ |

### New artifacts (all under `docs/paper_3/acmart_spike/` unless noted)

| Path | Purpose |
|---|---|
| `docs/paper_3/build_acmart.py` | LaTeX build script (canonical, from Session 072 onward) |
| `paper_3_acmart.tex` | Generated LaTeX source |
| `paper_3_acmart.pdf` | **Canonical submission artifact** for AISec 2026 |
| `page_audit.py` | `.aux`-based page-boundary auditor |
| `verify_pdf_substrings.py` | pdftotext substring gate (25 locked substrings) |
| `migrate_cites.py` | One-shot Part B citation migration tool |
| `DOCX_PIPELINE_FATE.md` | Decision 1 memo (retirement rationale + execution checklist) |
| `ANONYMIZATION_PLAN.md` | Decision 2 memo (3 sub-decisions, manual upload steps) |
| `docs/SESSIONS_071_072_LOG.md` | This file |

---

## Decisions executed this session

| Decision | Status | Notes |
|---|---|---|
| Retire docx pipeline | **DONE** | Files moved under `retired/`, tests repointed, CLAUDE.md updated. Tests pass. |
| Strip "Skyframe Innovations" from `gmys-casiano-2026` journal field | **DONE** | `journal = {Preprint}`. 25/25 pdftotext gate still PASS. |
| Keep self-cite `\url` pointer | **DONE** (no edit) | Local repo path, not external author-identifying. Per third-gate strategy call. |

## Decisions deferred to Dan (manual / out of CC's scope)

| Decision | Recommendation | Reasoning |
|---|---|---|
| Wire `anonymous.4open.science` URL into appendix | **Defer to camera-ready** | Requires manual GitHub interaction outside CC's scope. Appendix already says "publicly available under GPL-3.0" narratively without a URL — no anonymization gap for the review submission. When Paper 2's arXiv ID lands post-notification (2026-09-03), update both the `gmys-casiano-2026.note` field and the appendix to point at the real URLs. |
| Submission packet pass timing | **Start by 2026-07-10** | Deadline 2026-07-24; ≥ 2-week buffer for the human-eye semantic deanonymization pass (Dan's job, not CC's). Surface this as a calendar item. |
| Running-header audit | **Eyeball before submit** | Per `ANONYMIZATION_PLAN.md` § 2: confirm "Anon." on every body page top + no `\thanks{}` / affiliation leakage. acmart `anonymous` mode handles the bulk; the running-title carries the paper title (no author info). |

## Outstanding for future ARES sessions (Session 073+)

- arXiv submission of Paper 1 + Paper 2 v1.2 (parked, deadline-independent).
- Paper 2 arXiv ID landing — when it does, edit `gmys-casiano-2026.note` to append the arXiv URL.
- AISec notification (2026-09-03) — on accept, remove `anonymous` from acmart documentclass options, restore real `\author{Daniel Gmys-Casiano}\affiliation{Skyframe Innovations}` block, wire real GitHub URL into appendix, run camera-ready compile + submit.
- Optional: rename `docs/paper_3/acmart_spike/` to `docs/paper_3/submission/` once the spike is clearly done (current name reflects measurement-first scoping; submission name reflects the new canonical role).

---

*This log lives at `docs/SESSIONS_071_072_LOG.md`. Future ARES session logs can follow this pattern under `docs/SESSIONS_NNN_NNN_LOG.md` when on-disk continuity is preferable to Notion (e.g., MCP gating, offline archival, etc.).*
