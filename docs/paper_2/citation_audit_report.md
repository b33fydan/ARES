# Paper 2 v1.1 — Citation Existence Audit

**Audit date:** 2026-04-25
**Audited artifact:** `docs/paper_2/PAPER2_DRAFT_v1_1.docx`
**Bibliography under audit:** `docs/paper_2/references.bib`
**Auditor session:** 054

## Summary

**Status as of Session 055 remediation:**

| Status | Count | Cite keys |
|---|---:|---|
| VERIFIED | 5 | `berdoz-rugli-wattenhofer-2026`, `gmys-casiano-2026`, `hossain-2025`, `lee-2024`, `owasp-2025` |
| MISMATCH | 0 | — |
| HALLUCINATED | 0 | — *(was 1: `sabet-2025`, remediated Session 055 — see Remediation History below)* |
| UNRESOLVED | 0 | — |

**Total citations in v1.1 prose:** 5 *(was 6 prior to Session 055)*
**Total bib entries:** 5 *(was 6; `sabet-2025` removed from `references.bib`)*
**1-to-1 cite-key ↔ bib-entry mapping:** confirmed

## Remediation History

**Session 055 (2026-04-25)** — Applied B2 from
`docs/paper_2/sabet_remediation_findings.md` to v1.1 source markdown.
The fabricated `(Sabet et al., 2025)` citation and the surrounding
70-90% numerical claim were replaced with a directional statement
that requires no citation. The `sabet-2025` entry was removed from
`references.bib` (replaced with a comment block recording the
removal). The v1.1 docx was rebuilt and recompiled; `Sabet` no
longer appears anywhere in the rendered prose or References section.
The HALLUCINATED finding documented in this audit's original Section
6 entry is preserved below as a historical record of the bug and
the audit signal that surfaced it.

## Methodology

Citation enumeration combined parenthetical (`(Author, YYYY)`) and
narrative (`Author et al. (YYYY)`) regex passes against the v1.1 docx
prose; the existing `extract_citations` helper in
`docs/paper_2/build_references.py` only catches the parenthetical form,
which is why two of the six citations (Hossain, Lee) silently dropped
out of Session 052's coverage check.

Each cite key was then resolved via existing `citation_to_bibkey`,
matched against `references.bib`, and checked against authoritative
sources captured in Session 053:

- arXiv IDs verified live against `https://arxiv.org/abs/<id>`
- OWASP entry verified against the GenAI Security Project portal
- Paper 1 verified against the canonical PDF in `docs/paper_1/`

The audit checks four things: (1) bib entry exists, (2) bib entry
carries a stable identifier, (3) the identifier resolves, (4) bib
metadata matches the source. Anything that fails one of these is
flagged.

## Detail per citation

### 1. `gmys-casiano-2026` — **VERIFIED**

| Field | Value |
|---|---|
| Source title (bib) | The Problem Is Inside the Black Box: Asymmetric Calibration Failure in Multi-Agent LLM Debate |
| Source title (canonical) | (matches) |
| Authors | Daniel Gmys-Casiano |
| Identifier | `docs/paper_1/ARES_Preprint_Asymmetric_Calibration_Failure.pdf` (canonical artifact; no DOI / arXiv ID yet) |
| Verification | Session 053 PDF inspection + `docs/paper_1/CANONICAL.md` |
| Prose context | "(Gmys-Casiano, 2026)" — Section 1 / Section 2 / Section 3, supports claim that single-turn analysis is the production pipeline and that multi-turn debate degrades accuracy |

No discrepancy. Title was paraphrased in CLAUDE.md / memory pre-Session 053; bib carries the canonical title.

### 2. `berdoz-rugli-wattenhofer-2026` — **VERIFIED**

| Field | Value |
|---|---|
| Source title (bib) | Can AI Agents Agree? |
| Source title (arXiv) | (matches) |
| Authors | Frédéric Berdoz, Leonardo Rugli, Roger Wattenhofer |
| Identifier | arXiv:2603.01213 · DOI 10.48550/arXiv.2603.01213 |
| Verification | Session 053 live WebFetch against `https://arxiv.org/abs/2603.01213` |
| Prose context | Section 2 ("Prior ARES work"): "converging with ETH Zurich's independent consensus-failure finding in a synthetic Byzantine setting (Berdoz, Rugli, and Wattenhofer, 2026)" |

Note: Session 053 corrected the middle author from "Marco" (Tribunal-source paraphrase) to "Leonardo" per the canonical arXiv listing.

### 3. `hossain-2025` — **VERIFIED** (with prose-paraphrase caveat)

| Field | Value |
|---|---|
| Source title (bib) | A Multi-Agent LLM Defense Pipeline Against Prompt Injection Attacks |
| Source title (arXiv) | (matches) |
| Authors | S M Asif Hossain, Ruksat Khan Shayoni, Mohd Ruhul Ameen, Akif Islam, M. F. Mridha, Jungpil Shin |
| Identifier | arXiv:2509.14285 · DOI 10.48550/arXiv.2509.14285 · venue: 11th IEEE WIECON-ECE 2025 |
| Verification | Session 053 live WebFetch against `https://arxiv.org/abs/2509.14285` |
| Prose context | Section 2: "the Chain-of-Agents defense pipeline of Hossain et al. (2025), which pairs a domain-reasoning LLM with a guard-agent LLM that screens candidate outputs for policy violations before release. The authors report 100% attack mitigation on a corpus of 55 prompt-injection attacks across 8 categories." |

The bib entry resolves to a real paper whose abstract supports the
claim made in the prose. **However, the prose refers to it as the
"Chain-of-Agents defense pipeline"** — the paper's actual title is
the longer form recorded in the bib. The wording in the prose appears
to be a methodology paraphrase (chain-of-agents ≈ guard-agent
pipeline) rather than a strict title reference; the bib note records
this distinction. Surface for prose-author judgment whether to keep
the paraphrase, footnote it, or replace with the verbatim title.

### 4. `lee-2024` — **VERIFIED**

| Field | Value |
|---|---|
| Source title (bib) | Prompt Infection: LLM-to-LLM Prompt Injection within Multi-Agent Systems |
| Source title (arXiv) | (matches) |
| Authors | Donghyun Lee, Mo Tiwari |
| Identifier | arXiv:2410.07283 · DOI 10.48550/arXiv.2410.07283 (published 2024-10-09) |
| Verification | Session 053 web search confirmed |
| Prose context | Section 2: "Lee et al. (2024), in Prompt Infection, demonstrate that malicious prompts can self-replicate across multi-agent LLM systems" |

Two-author paper; "et al." in the prose is conventionally permitted
when the first-author surname is sufficient for disambiguation, but a
stricter style guide would prefer "Lee and Tiwari (2024)". Stylistic
note for prose-author consideration; not flagged as a mismatch.

### 5. `owasp-2025` — **VERIFIED**

| Field | Value |
|---|---|
| Source title (bib) | OWASP Top 10 for LLM Applications 2025 |
| Source title (canonical) | (matches; PDF v4.2.0a 2024-11-14) |
| Authors | OWASP Foundation (institutional) |
| Identifier | https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/ |
| Verification | Session 053 web search; OWASP GenAI Security Project portal |
| Prose context | Section 2 ("OWASP landscape") and Section 4 ("Mapping to the OWASP taxonomy") |

The 2025 edition adds a companion Top 10 for Agentic AI Applications;
the bib note documents both lists are tracked under one entry.

### 6. `sabet-2025` — **HALLUCINATED**

| Field | Value |
|---|---|
| Source title (bib) | PLACEHOLDER ("Empirical Comparison of Production Prompt-Injection Defenses: Lakera Guard, Rebuff, and Vigil") |
| Source title (canonical) | **No matching paper located** |
| Authors | PLACEHOLDER ("Sabet, M. and others") |
| Identifier | **None** |
| Verification | **FAILED** — Session 053 search across multiple query phrasings returned no 2025 paper authored by anyone named Sabet matching the cited claim. Session 054 re-searched specifically for "70-90% detection rate" + "Lakera Rebuff Vigil 2024 2025" and surfaced multiple plausible candidates (PINT benchmark, Lakera-affiliated whitepapers, arXiv 2506.19109, arXiv 2505.13028, ACL 2025 PIGuard) but none authored by Sabet and none with the specific 70-90% range as a headline claim. |
| Prose context | Section 2 (Related Work, "Prompt-injection defenses" subsection): "Empirical evaluations of these tools on prompt-injection benchmarks report detection rates that degrade substantially under distribution shift, with leading tools achieving accuracy in the 70-90% range depending on corpus and context (Sabet et al., 2025)." |

**Classification reasoning.** The citation has the structural shape
of a real academic reference (surname + "et al." + year + topic-
adjacent claim) and passed every existing structural validator
because no validator checked whether the paper actually exists. This
is the textbook signature of LLM hallucination during draft
authorship: a plausibly-shaped citation generated to support a
plausibly-true synthesized claim, with no real-world referent.

The 70-90% range itself is consistent with publicly-reported numbers
across multiple sources (PINT benchmark, vendor whitepapers, arXiv
2506.19109's empirical evaluation), but those sources do not
collectively appear in a single paper authored by Sabet. The most
defensible interpretation is that the claim is approximately true
but the citation is fabricated.

**Surface for human judgment.** Three remediation paths, not selected
here:

1. **Find a real source** — pick one of the candidate papers (e.g.,
   arXiv 2506.19109 "Enhancing Security in LLM Applications: A
   Performance Evaluation of Early Detection Systems") that supports
   the 70-90% range and update both prose and bib.
2. **Soften the claim** — replace the specific range with a
   directional statement ("performance varies substantially under
   distribution shift") and drop the citation, or attribute to "vendor
   benchmarks (e.g., Lakera PINT)".
3. **Drop the claim** — remove the sentence; the surrounding
   paragraph stands without it.

Track 3 of Session 054 documents Path 1 candidates and Path 2 prose
text in `docs/paper_2/sabet_remediation_findings.md` (sibling file).

## Limitations

This audit catches three failure modes:

1. **Missing bib entry** — cite key in prose with no bib match
2. **Missing identifier** — bib entry without a stable ID
3. **Hallucination** — no paper exists matching the bib metadata

It does **not** catch:

- **Bib metadata that resolves to a real-but-unrelated paper** — e.g.,
  if `sabet-2025` had been bound to a real but different arXiv ID,
  the network check would pass but the citation would still be
  semantically wrong. Detecting this requires comparing bib metadata
  against the *resolved paper's* metadata, which is future work.
- **Misattributed quotations** — e.g., a real paper but the quoted
  number is wrong.
- **Prose-bib mismatch** — e.g., the Hossain paraphrase noted above.
  The audit notes such cases but does not gate on them.

The structural test infrastructure introduced in Session 054
(`tests/paper_2/test_citation_existence.py`) catches modes 1-3
mechanically and gates the network half by env var so offline pytest
runs remain green.
