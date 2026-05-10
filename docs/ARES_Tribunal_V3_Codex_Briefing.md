# ARES Tribunal V3 — Codex Briefing
## Look Deeper Into ARES and Tell Me What You Really Think

**Session:** 057-companion
**Date:** 2026-04-27
**Briefing for:** Codex (with full repo access)
**Predecessors in this round:** GPT-5.5 Pro (paper-only review, completed)
**Successor:** Synthesis with Anthropic Claude (strategy window) → next-tribunal pass

---

## Why this briefing exists

You have something the rest of the tribunal does not: the actual codebase. The other reviewers are working from papers, scoping documents, and `CLAUDE.md`. You can read what is actually there.

That asymmetry should change what you say. Do not write the architectural review a paper-only reviewer could write. Tell us what we cannot see by looking at our own work — what the code says that the docs do not, what is wired but unused, what is claimed but not implemented, what is implemented but not claimed.

Direct critique only. Flattery is friction.

---

## Context — what ARES is

ARES (Adversarial Reasoning Engine System) is a dialectical AI framework for cybersecurity threat analysis built on a closed-world evidence-graph architecture. Three agents — **Architect**, **Skeptic**, **OracleJudge** — operate inside a frame where hallucinations manifest as schema violations against a deterministic evidence graph. The OracleJudge is pure deterministic Python; agents are LLM-driven inside structural constraints.

Two papers have shipped:

- **Paper 1 (canonical):** *The Problem Is Inside the Black Box: Asymmetric Calibration Failure in Multi-Agent LLM Debate.* Documents that structured multi-turn debate degrades accuracy across all configurations tested. Single-turn 84.6% (kill-chain v5); multi-turn debate 61–67%. Mechanism: Architect retreat (~0.92 → ~0.48 confidence across rounds) plus Skeptic rigidity. Single-turn is production; debate stays in the lab.
- **Paper 2 (v1.1):** *The Deterministic Skeptic.* Documents semantic-framing attacks against syntactic prompt-injection firewalls. Syntactic firewall: 4/4 direct injections caught, 0/19 framing attacks caught. The deterministic Light Skeptic (four rules over an evidence graph) matches full-LLM Skeptic accuracy at 21/25 = 0.8400 on framing scenarios. **Finding 11** — that deterministic substitution is viable — is load-bearing for the paper's architectural claim.

Project state: 3,404 passing tests. Zero PLACEHOLDER citations. CLAUDE.md self-validating.

The next research arc is **Phase 7**. This briefing is part of selecting it.

---

## The three Phase 7 candidates (original framing)

- **Candidate A — Light Skeptic v2 with malign-side rules.** Extend the deterministic skeptic with rules that actively look for adversarial signature. Architectural fit: high. Cost: 3–5 sessions.
- **Candidate B — Multi-model validation (Opus 4.7, Sonnet 4.6, Haiku 4.5).** Run the existing benchmark suite across model families. Architectural fit: medium (no new architecture). Cost: 2–3 sessions, ~3x API spend.
- **Candidate C — Adaptive adversarial corpus authored against the four rules.** Author scenarios designed to satisfy all four Light Skeptic rules while still constituting injection. Cost: 4–6 sessions.

The original recommendation under tribunal: **C-first, A-second, B-parallel.**

---

## What the prior tribunal round produced (GPT-5.5 Pro)

GPT-5.5 was given Paper 2 only — no scoping document, no candidate list. It arrived independently at **C+A as a coupled pair** and added a fifth element we did not have in the scoping doc:

**The Non-Interference Harness.** Paired clean/poisoned variants. Same structured facts, different injected prose. The verdict must remain unchanged when only attacker-controlled text changes. Headline metric: **influence leakage** — how often attacker-controlled prose changes the result independently of structured evidence.

GPT-5.5 also reformulated C's research question. Instead of "are the four rules complete?" the test becomes "is attacker prose denied authority when structured evidence is held constant?" This sidesteps the original Assumption 1 problem (mechanical rule-satisfaction oracle) by changing the metric.

GPT-5.5 dropped Candidate B entirely (silence, not argument — it never saw B as a candidate).

GPT-5.5 doubled down on the autoimmune metaphor as engineering frame: *"the autoimmune metaphor finally becoming engineering."*

GPT-5.5's proposed paper title: ***"Prompt Injection Non-Interference in Closed-World LLM Security Pipelines."***

GPT-5.5's proposed slogan: ***"LLM proposes, deterministic code disposes."***

---

## The post-GPT-5.5 synthesis (Anthropic Claude)

Adopted from GPT-5.5: the Non-Interference Harness, the verdict-invariance reformulation, the paper title, the slogan.

Rejected from GPT-5.5: the Policy Kernel as Phase 7 scope (it is the long-term ARES vision, not the next-arc deliverable). The dropping of Candidate B (treated as silence rather than argument).

**Current proposed Phase 7 shape:** C+A coupled, with the Non-Interference Harness as the measurement spine. B-parallel still standing pending the rest of the tribunal.

That synthesis is what you are being asked to pressure-test.

---

## What we want from you

Six tasks. The first four require repo access. The last two are judgment calls.

### Task 1 — Reality-check the Non-Interference Harness

GPT-5.5 proposed paired clean/poisoned variants where structured facts stay fixed and only prose varies. Verdict invariance is the test.

Look at the code. Where does prose actually enter the pipeline? Can structured evidence genuinely be held constant while prose varies, or is there hidden coupling — for example, does the Architect's kill-chain stage classification depend on prose in ways that would mean a "prose-only" change actually changes structured evidence downstream?

If the harness is cleanly buildable, what does the minimum-viable implementation look like given the existing code? Concretely: which files would change, which scenarios would seed the first paired-variant set, and where does the influence-leakage metric attach?

If the harness is **not** cleanly buildable, what is the obstacle and what would have to change first? That answer is more valuable than a yes.

### Task 2 — Component replaceability audit

GPT-5.5 claimed: *"the Architect's kill-chain stage classification may be rule-replaceable because it is a finite-state assessment over structured evidence."*

That is a code-level claim, not a paper-level claim. You can verify or refute it.

Look at the Architect's code. Is kill-chain stage classification actually a finite-state assessment over structured fields? Or does it depend on LLM inference over prose in ways the paper does not surface?

If the latter, what would have to change to make it deterministic — and is that change in scope for Phase 7, or is it a separate arc that should not be folded into the C+A package?

### Task 3 — The `malign_score` channel

GPT-5.5 noted that the Light Skeptic has a `malign_score` channel that is not populated.

Verify this. Is the channel wired in but unused, or is it scaffolding waiting for Phase 7? If wired, what is the cost of populating it with the rules GPT-5.5 proposed:

- High-stage activity without `authorization_fact`
- Executable creation in user-writable paths
- Credential-access tool/context mismatch
- Suspicious patch claims that do not actually neutralize the active condition (the INJ-008 failure mode)
- Post-exploitation indicators without a valid change record

Are these rules expressible against the existing evidence schema, or do they require schema extensions? If they require extensions, that is the kind of finding the paper-only reviewers cannot produce — name it precisely.

### Task 4 — The mechanical rule-satisfaction question

The original tribunal briefing flagged this load-bearing assumption: *"authoring a corpus against the four rules requires a rule-satisfaction oracle separate from the corpus author's intuition. Otherwise the corpus tests author understanding, not defense sufficiency."*

GPT-5.5 sidestepped the problem by reformulating the test (verdict invariance under prose perturbation, rather than rule satisfaction). The synthesis adopted that reformulation as solving Assumption 1.

Code-level question: are the four current Light Skeptic rules expressed mechanically enough that someone could author against them deterministically, or are they semantic enough that the reformulation was the only available move? In other words: did GPT-5.5 **dissolve** the problem or just **reframe past** it?

If it is the latter, the rule-satisfaction oracle is still owed somewhere in the arc — even if it is not Phase 7's first deliverable.

### Task 5 — What would you disagree with in the synthesis?

Anthropic Claude gave a synthesis that:
- Ratifies GPT-5.5's Non-Interference Harness addition
- Accepts the reformulation as solving Assumption 1
- Recommends Phase 7 as "C+A coupled with NIH as measurement spine, B-parallel still standing"
- Notes that Assumption 2 (symmetric publishability) and Assumption 3 (autoimmune metaphor as evaluation axis) remain untested

What is wrong with that? Where does it overreach? Where is it under-tested?

Specifically: do **not** ratify for the sake of ratifying. If the synthesis is right in the main, name the part you would push back on anyway. The tribunal seat is earned by surfacing the strongest version of the dissent, not by performing concurrence.

### Task 6 — The verdict

Same three forms as the original tribunal:

- **Ratify** the post-GPT-5.5 recommendation. Note any amendments to cost estimates, sequencing, or pre-registration criteria.
- **Reframe** to a different sequence. State which and why. Specifically: do code-level findings change the C+A coupling, the NIH placement, or the standing of B?
- **Halt** if a code-level finding makes Phase 7 impossible to start until a prior deliverable lands. State which finding and what the prior deliverable is.

---

## Constraints on your response

- You have repo access. Use it. Paper-only commentary is not what we need from you.
- Cite code. If you claim "the Architect's kill-chain logic depends on LLM inference," cite the file and line. If you say `malign_score` is wired but unused, name the function and the call site.
- Argue substantively. Procedural ratification — "the recommendation is reasonable" without code-level grounding — does not earn the tribunal seat.
- Length proportional to substance. A 600-word verdict with sharp code-grounded dissent is more valuable than a 3,000-word ratification with no dissent.
- Show where you would update if presented with new evidence.

---

## Reference materials

In repo:
- `docs/paper_1/ARES_Preprint_Asymmetric_Calibration_Failure.pdf` — Paper 1 canonical
- `docs/paper_2/PAPER2_DRAFT_v1_1.docx` — Paper 2 v1.1
- `docs/PHASE_7_SCOPING.md` — original recommendation under review
- `docs/DOCUMENTATION_CHAPTER_CLOSEOUT.md` — Sessions 052–055 closeout
- `docs/paper_2/meta_finding_footnote_candidate.md` — parked v1.2 input
- `CLAUDE.md` — current project state, test floor 3,404

Code areas of particular interest for the tasks above:
- Light Skeptic implementation and `malign_score` channel
- Architect kill-chain stage classification logic
- Pipeline entry points for prose vs. structured evidence
- Existing benchmark harness (for the NIH attachment question)

---

## Format

Structure your response in six sections matching Tasks 1–6. Lead with code citations where the task requires them.

---

— End briefing.
