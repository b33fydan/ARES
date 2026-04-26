# Sabet 2025 — Remediation Prep

**Session:** 054
**Status:** Path B (no genuine source). Candidate v1.2 prose changes prepared
for human selection. **No remediation applied.**

## Step 1 — Exact prose location

**Source artifact:** `docs/paper_2/source/PAPER2_DRAFT_v1_1_source.md`
**Section:** 2 (Related Work), subsection "Prompt-injection defenses"
**Containing paragraph (verbatim):**

> Production defenses against prompt injection have converged on a small
> number of architectures. Rebuff combines heuristic pattern matching,
> an LLM-based detection layer, a vector database of prior attacks, and
> canary tokens designed to detect prompt leakage. Vigil implements
> transformer-based classification and YARA-style signature rules over
> input and output text. Lakera Guard deploys purpose-built classifiers
> trained on a continuously updated adversarial corpus. **Empirical
> evaluations of these tools on prompt-injection benchmarks report
> detection rates that degrade substantially under distribution shift,
> with leading tools achieving accuracy in the 70–90% range depending
> on corpus and context (Sabet et al., 2025).** The common architecture
> is a defensive layer that processes attacker-influenced text, whether
> through classifiers, pattern matchers, or LLM graders. ARES's
> syntactic firewall is structurally within this class and inherits the
> same detection ceiling against semantic attacks documented in
> Finding 7. We do not claim our firewall outperforms these tools; we
> claim that the class as a whole is architecturally bounded against
> the framing-attack subspace we characterize in Section 4.

The bolded sentence is the citation site. The surrounding paragraph
remains valid even if the sentence is dropped — the next sentence
("The common architecture is a defensive layer...") flows directly
from the tool descriptions above it.

## Step 2 — Good-faith search trace

Five distinct query phrasings were attempted across Sessions 053 and
054 to locate the cited source:

| Query | Where | Result |
|---|---|---|
| `empirical comparison Lakera Guard Rebuff Vigil prompt injection defense 2025 arxiv` | Web search (Session 053) | Multiple papers found; **none authored by Sabet** |
| `"Sabet" prompt injection Lakera Rebuff Vigil 2025` | Web search (Session 053) | No results matching author "Sabet" + this domain |
| `"prompt injection" detection rate "70%" "80%" "90%" Lakera Rebuff Vigil benchmark 2024 2025` | Web search (Session 054) | PINT benchmark, vendor whitepapers; no Sabet author |
| Targeted lookup on candidate IDs (arXiv 2506.19109, 2505.13028) | arXiv | Real papers comparing these tools, **but neither authored by Sabet** |
| Author-only search across 2024-2025 prompt-injection literature | Web (implicit across the above) | No Sabet first-author paper in the prompt-injection-defense space |

**Strongest topical neighbors found** (none authored by Sabet, none
match the cited 70-90% range as a headline claim):

1. arXiv 2506.19109 — "Enhancing Security in LLM Applications: A
   Performance Evaluation of Early Detection Systems"
   - Compares LLM Guard, Vigil, Rebuff
   - Reports Vigil has lowest false-positive rate; Rebuff best
     average performance
   - Specific accuracy numbers not in the 70-90% range as a
     headline statistic
2. arXiv 2505.13028 — "Evaluating the Efficacy of LLM Safety
   Solutions: The Palit Benchmark Dataset"
   - Reports Lakera Guard at precision 0.964, recall 0.501,
     accuracy 0.746 (74.6%)
   - Numbers fall **partly** in the 70-90% range for Lakera
     specifically, but the cited generalization ("leading tools
     achieving accuracy in the 70-90% range") is not the paper's
     claim
3. Lakera PINT benchmark (vendor) — Lakera Guard scores 92.55% on
   the proprietary PINT benchmark; this is a single-tool number on
   a single benchmark, not a cross-tool empirical evaluation

**Conclusion.** The 70-90% range claim is *approximately consistent*
with publicly-reported numbers across these sources, but no single
paper aggregates them under a single citation, and none is authored
by Sabet. The most defensible interpretation is that the underlying
synthesis is true but the specific citation is fabricated — a
classic LLM hallucination pattern (real-shape citation for a
plausibly-true synthesized claim).

## Step 3 — Path A (real source) — NOT recommended

If forced to bind to a single arXiv source, the closest match is:

```bibtex
@article{moysidis-2025-palit,
  author  = {[verify against arXiv 2505.13028 listing]},
  title   = {Evaluating the Efficacy of {LLM} Safety Solutions: The Palit Benchmark Dataset},
  year    = {2025},
  journal = {arXiv preprint},
  eprint  = {2505.13028},
  archivePrefix = {arXiv},
  doi     = {10.48550/arXiv.2505.13028}
}
```

**However, this paper does NOT support the cited claim verbatim.**
Lakera Guard's 74.6% on the Palit benchmark is one data point, not a
cross-tool 70-90% range. Citing it would propagate the same
attribution error in a different shape.

**Recommendation: do NOT take Path A unless the prose is also
rewritten to reflect what the chosen source actually says.**

## Step 3 — Path B (soften the claim) — three v1.2 candidates

All three preserve the paragraph's core point (existing tools are
architecturally bounded) without depending on a fabricated citation.
Pick whichever fits the desired voice.

### Candidate B1 — softest (drops the claim entirely)

Replace the bolded sentence with nothing. Paragraph reads as:

> ...Lakera Guard deploys purpose-built classifiers trained on a
> continuously updated adversarial corpus. The common architecture is
> a defensive layer that processes attacker-influenced text, whether
> through classifiers, pattern matchers, or LLM graders. ARES's
> syntactic firewall is structurally within this class...

Loses: the empirical-degradation point.
Gains: zero citation risk; paragraph still flows.

### Candidate B2 — directional (keeps the point, drops the number + citation)

Replace the bolded sentence with:

> Empirical evaluations of these tools on adversarial corpora
> consistently report performance degradation under distribution
> shift, particularly against attacks that depart from the patterns
> present in the training or signature corpus. We omit specific
> per-tool numbers here because reported figures vary substantially
> by benchmark choice; the architectural point we make does not
> depend on a particular ranking among tools.

Loses: the numeric specificity.
Gains: keeps the argumentative move (architectural ceiling) without
a citation.

### Candidate B3 — vendor-attributed (concrete but unsourced numerically)

Replace the bolded sentence with:

> Vendor-published benchmarks for these tools (e.g., Lakera's PINT
> benchmark) report headline accuracy figures in the high 80s to
> low 90s; independent evaluations on out-of-distribution corpora
> typically report lower numbers, with cross-tool comparisons
> spanning roughly 70-90% accuracy depending on benchmark and
> context. We do not select among these as authoritative.

Loses: an academic citation.
Gains: keeps the 70-90% number with an honest provenance note;
acknowledges the methodological weakness rather than papering over
it.

## Recommendation summary

Default recommendation: **Candidate B2** for v1.2.

Rationale: the paragraph's argumentative work is architectural (these
defenses share a class boundary, ARES's firewall sits inside it). The
specific numbers are decorative for that argument, and removing them
also removes the citation-fabrication risk and the impulse to find a
source that supports a synthesized claim. B2 keeps the rhetorical
posture without inventing scholarship to back it.

Final selection is the prose author's call. None of B1 / B2 / B3 is
applied automatically by Session 054.
