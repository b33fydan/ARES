# Meta-finding footnote candidate

**Session:** 054
**Status:** Draft only. Not inserted into PAPER2_DRAFT_v1_1.docx. Surface
for prose-author judgment whether to incorporate, transform, or reject.

## Context

Paper 2's Finding 7 establishes that deterministic syntactic firewalls
are architecturally blind to semantic framing attacks: 0/19 detection
rate on framing scenarios at a 0.5 taint threshold, by construction.
The architectural mechanism is that surface-form pattern matchers
have no representation of meaning, so attacks that manifest only in
the meaning of ordinary text produce no surface signature.

The v1.1 manuscript itself contains a concrete instance of this
failure class. A citation, `(Sabet et al., 2025)`, was generated
during draft authorship to support a plausible-sounding empirical
claim about prompt-injection defense detection rates. The citation
has the structural shape of a real reference (surname + et al. + year
+ topic-adjacent claim) and passed every structural validator we had
in place at the time of drafting: the bib parser accepted its
syntactic shape, the prose-citation regex bound it to a bib entry
key, and the rendered References section formatted it correctly.

Session 054's audit identified the citation as fabricated. No paper
by an author named Sabet matches the cited claim across multiple
search phrasings. The underlying numerical claim (70-90% detection
rate range) is approximately consistent with publicly-reported
numbers across multiple sources, but no single source authored by
Sabet exists.

## Candidate footnote text (short form)

> A note on this paper's own evidence base. The v1 draft of this paper
> contained a citation, `(Sabet et al., 2025)`, that a post-draft audit
> identified as fabricated: no paper by that author matches the cited
> claim. The citation passed every structural validator we maintained
> (bib syntax, cite-key regex, rendered-references formatting) for the
> same architectural reason that Section 5 documents for the syntactic
> firewall: structural defenses cannot detect content that has the
> right *shape* but wrong *meaning*. Network-resolution tests added in
> the audit cycle now flag missing identifiers and dead links, but
> cannot catch a citation that resolves to a real-but-unrelated paper.
> Semantic verification of bibliography against source metadata is an
> open problem in academic-tooling space and is in scope for the same
> class of defenses Section 8 advocates: structured representation of
> the underlying claim, not surface-pattern validation alone.

## Candidate footnote text (long form, ~one paragraph in Discussion)

> A reviewer may reasonably ask whether the architectural claim of
> this paper, that surface-pattern defenses are bounded against
> semantic attacks, applies recursively to academic writing about
> those defenses. The v1 draft of this paper contained a fabricated
> citation, `(Sabet et al., 2025)`, that supported an empirical claim
> about prompt-injection-defense detection rates. The citation
> passed our bib-syntax validator, our cite-key resolver, and our
> rendered-references compiler. It failed only when a human reviewer
> noted that the surname did not match anyone they recognized in
> the field, prompting an audit that found no matching paper across
> multiple search phrasings. The structural lesson generalizes
> beyond the v1 erratum: a defense layer that operates over the form
> of a citation cannot discriminate a real reference from one
> generated to fit a plausible shape, just as a regex over an
> Architect's interpretation field cannot discriminate factual
> content from semantically-framed content. Section 7's deterministic
> Light Skeptic substitutes structural reasoning over an evidence
> graph for surface-pattern matching; an analogous defense in
> bibliographic tooling would substitute structured queries against
> authoritative bibliographic databases for syntactic validation of
> cite keys. We do not implement that here. We note that the failure
> mode our paper documents is sufficiently general to apply to the
> paper itself.

## Rationale for the long form

If included as a Discussion-section paragraph rather than a footnote,
the meta-finding becomes a fifth generalizable observation in
Section 8 ("Failure modes apply recursively to defenses-of-defenses"),
which is intellectually honest and reinforces rather than weakens the
paper's claims. Including it as a footnote is the conservative move:
acknowledges the bug, doesn't try to make architectural hay from a
draft erratum.

The middle path is the short-form footnote on the relevant Related
Work paragraph. That keeps the acknowledgement local to the affected
sentence and avoids elevating a draft-bug into a publication thesis.

## Three insertion sites worth considering

1. **Section 2 (Related Work), end of "Prompt-injection defenses"
   subsection** — directly adjacent to where the Sabet citation
   appeared in v1. Local accountability, no rhetorical inflation.
2. **Section 8 (Discussion), as a fifth observation** — generalizes
   the failure-mode argument to defenses-of-defenses. Intellectually
   stronger but riskier rhetorically.
3. **A standalone footnote on the title page** — meta-acknowledgement
   of the paper's authorship process. Most honest about the v1.1 →
   v1.2 history. Probably the least common venue for this in the
   prompt-injection literature.

## Recommendation

If the prose author chooses to include this at all, the **short-form
footnote at insertion site 1** is the lowest-risk, highest-honesty
option. It acknowledges the specific bug in the place where the bug
appeared, ties it to the paper's central claim without overclaiming,
and notes the bounded improvement made by the Session 054 audit
infrastructure.

Including it is a strictly defensible choice. Not including it is
also defensible, provided the v1.2 prose remediation in
`docs/paper_2/sabet_remediation_findings.md` (B2 recommended) is
applied so the fabricated citation does not appear in the published
artifact.

## What this footnote does NOT claim

- It does not claim that LLM-assisted drafting is uniquely vulnerable
  to fabrication. Pre-LLM drafts have had this problem too; the rate
  may be higher with LLMs but the failure mode is not new.
- It does not claim the audit infrastructure introduced in Session
  054 (`tests/paper_2/test_citation_existence.py`) closes the
  fabrication gap. It closes the *structural* sub-class (missing
  bib entries, malformed identifiers, dead links). It does not
  catch real-but-unrelated-paper substitution, which is the next
  failure mode someone will hit.
- It does not claim that Paper 2's framework solves bibliographic
  hallucination. The framework is for cybersecurity threat
  evidence, not academic citations. The architectural argument
  generalizes; the implementation does not.
