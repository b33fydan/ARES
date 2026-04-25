

**A.R.E.S.**

Adversarial Reasoning Engine System

**THE COMPENDIUM**

*Volume II: The Tribunal*

*On the Synthesis of Adversarial Counsel*

*and the Architecture That Emerged*

Skyframe Innovations

Daniel \[Skyframe\]

March 25, 2026

Sessions 001–020 · 1,595 Tests · Zero Regressions

*We are not looking for confirmation. We are looking for the question we have not yet thought to ask.*

— ARES Tribunal Battle Plan, Section 8

*Three minds. Three architectures. One answer.*

— Post-Tribunal synthesis note

# **I. The Tribunal**

Volume I of this Compendium recorded The Convergence — the moment when ARES’s empirical findings on multi-agent consensus failure aligned independently with formal academic research from ETH Zurich. That document closed with the infrastructure built, the first findings recorded, and a question: what comes next?

We answered that question by doing something unusual. We took the full project state — twenty sessions of architecture, benchmarks, failure diagnoses, and the ETH convergence — and submitted it to a panel of rival AI architectures for adversarial strategic review. Three systems received the same two documents: the Tribunal Battle Plan (a self-contained strategic brief with structured response format) and the Compendium Volume I (the full narrative record). Each was instructed to challenge assumptions, identify blind spots, propose directions, and stress-test our reasoning.

The Tribunal comprised:

* **GPT 5.4 Pro** (OpenAI) — given the full project document corpus

* **Gemini 3.1 Pro** (Google) — given the two Tribunal documents with prior conversational context

* **Perplexity/Opus 4.6** (Perplexity AI, likely backed by Claude Opus 4.6) — given the full project document corpus

What returned was not consensus by design. Each system processed the material independently, with different training, different reasoning architectures, and different analytical tendencies. The convergence that emerged was earned, not engineered.

# **II. What They Agreed On**

Four verdicts were unanimous across all three Tribunal members. In a process designed to produce disagreement, unanimity is signal.

## **Verdict 1: Ship Single-Turn**

All three systems independently concluded that the 83.3% single-turn accuracy is the production path. Not one suggested delaying deployment to wait for the debate architecture. GPT called it “the checkpoint verdict.” Gemini said “do not let the research problem block production deployment.” Perplexity framed it as a baseline already earned. The production question is settled.

## **Verdict 2: Per-Claim Debate Is the Research Path**

The Tribunal Battle Plan presented seven candidate directions (A through G, where G was a blank check for new ideas). All three Tribunal members, given seven options and freedom to propose their own, independently selected Direction B (Per-Claim Debate Architecture) as the highest-value next experiment. GPT recommended “claim-level adversarial audit.” Gemini said “force the debate down to the frozen EvidencePackets.” Perplexity advised implementing Direction B on the Oracle layer first as a proof-of-concept before full rewrite.

Three different AI architectures. Seven options. Same pick. This is the strongest signal the Tribunal produced.

## **Verdict 3: Expand the Corpus**

N=18 scenarios is sufficient to discover mechanisms but insufficient to support statistical claims about complementary accuracy patterns or ensemble strategies. GPT stated this most sharply: the current data is “enough to discover mechanisms, but not enough to be casual about claims.” Perplexity noted that at N=18, “you’re one scenario away from noise.” The corpus must expand to 30+ scenarios before the next round of benchmarking produces publishable numbers.

## **Verdict 4: The Failure Is Architectural**

Complete unanimity on the mechanistic diagnosis established in Volume I. Free-form debate corrupts calibration through asymmetric social dynamics — Architect retreat, Skeptic rigidity — and no amount of prompt engineering can fix an interaction-level failure. The fix must be structural.

# **III. What They Disagreed On**

Disagreement in the Tribunal was not about direction but about tactics. The most productive divergences:

## **The Oracle Question**

Perplexity and Gemini independently identified the Oracle as an under-examined component. Both argued that while the Architect’s retreat and the Skeptic’s rigidity have been diagnosed in detail, the Oracle’s behavior under asymmetric input has not been scrutinized. Is the Oracle propagating the calibration noise rather than correcting it? GPT did not raise this directly, though its “selective deliberation” wild card implicitly bypasses the Oracle problem by only invoking it when needed.

This is a legitimate blind spot. The Phase 3 architecture addresses it by changing the Oracle’s role: instead of passively synthesizing debate output, it actively extracts contested claims and aggregates deterministically.

## **The Wild Cards**

Each Tribunal member produced a genuinely distinct wild card:

**GPT: Selective Deliberation.** Run single-turn first, only escalate to adversarial review when confidence falls in an uncertainty band. Debate as exception handler, not default mode. The most pragmatic proposal.

**Perplexity: Adversarial Oracle.** Convert the Oracle from passive judge to active stress-tester that generates the strongest argument against whichever agent holds higher confidence. The most novel interaction redesign.

**Gemini: Deterministic Skeptic.** Replace the LLM Skeptic entirely with a Python function that queries the evidence graph. AI does creative threat hunting, code does rigorous fact-checking, LLM judges the final state. The most architecturally radical proposal.

None of these are mutually exclusive. They are ordered by how much existing architecture they preserve, which determines the sequence in which they should be tested.

# **IV. The Composed Insight**

No single Tribunal member stated the Phase 3 architecture. But all three contributed the pieces.

GPT provided the escalation logic: debate only when it helps, not on every case. Perplexity and Gemini provided the debate granularity: operate on specific claims, not overall verdicts. The ETH Zurich convergence from Volume I provided the theoretical grounding: interaction-level failures require structural, not parametric, fixes.

The composed architecture is Selective Escalation with Per-Claim Adversarial Audit:

* **Stage 1:** Single-turn analysis. Each agent examines the evidence independently. Oracle renders an initial verdict with confidence.

* **Stage 2:** Escalation gate. If confidence falls in the uncertainty band (0.35–0.65), the case is flagged for adversarial review. Deterministic threshold, not LLM-decided.

* **Stage 3:** Claim extraction. The Oracle identifies the 3–5 specific factual claims that are contested between Architect and Skeptic, each tied to specific frozen EvidencePackets.

* **Stage 4:** Per-claim debate. Architect and Skeptic argue each claim individually, citing specific evidence fields. No free-form verdict-level argumentation.

* **Stage 5:** Deterministic aggregation. Claim-level confidences are weighted by evidence support count and aggregated into a final verdict. The aggregation is code, not LLM judgment.

This design preserves single-turn reliability where it already works. It constrains debate to the domain where it demonstrably helps: genuine ambiguity. It grounds the debate in specific claims rather than free-form argumentation, directly addressing the diagnosed mechanism of asymmetric calibration failure. And it removes the Oracle from the calibration noise loop by making final aggregation deterministic.

# **V. What the Tribunal Missed**

No review process is complete. The Tribunal collectively failed to address several questions:

* **Model heterogeneity.** The Battle Plan listed heterogeneous agent models as Direction C. No Tribunal member seriously engaged with whether Claude Sonnet is the right model for all three agents, or whether the asymmetric calibration is model-specific.

* **Corpus expansion strategy.** All three flagged N=18 as insufficient. None proposed a concrete strategy for which types of scenarios to add — more ambiguity-tier? More cross-source? More benign-that-looks-threatening?

* **The content pipeline question.** Section 6 of the Battle Plan explicitly asked how the next phase maximizes both research value and content value. No Tribunal member addressed this in depth.

* **The ETH framing.** GPT overread the Compendium’s use of the ETH paper as a direct positioning claim rather than convergent evidence. The Compendium is clear that the two studies are complementary, not competing. This is a minor framing issue, not a substantive one.

These gaps do not change the strategic direction. They are noted here for completeness and will be addressed in the session-level execution.

# **VI. The Forcing Function**

Session 024 is a binary checkpoint. The selective escalation architecture either meets its success criteria or it does not.

## **Success Criteria**

* **Primary:** Selective escalation accuracy on the expanded corpus (N=30+) equals or exceeds single-turn accuracy (83%+).

* **Secondary:** Improved calibration (lower Brier score, lower ECE) on ambiguous-tier scenarios specifically, compared to both single-turn and original multi-turn.

* **Tertiary:** Escalation rate between 15–25% of corpus. Cost overhead no more than 40% above single-turn-only.

## **If It Works**

The result is publishable. The paper writes itself: structured selective escalation to per-claim adversarial audit improves calibration on ambiguous scenarios without degrading accuracy on clear cases. Venue: arXiv preprint, followed by workshop submission to NeurIPS or IEEE S\&P. The content pipeline produces the build narrative. The production system ships with single-turn default and selective escalation for edge cases.

## **If It Doesn’t**

The result is still publishable — as a deeper negative finding. The paper becomes: even claim-level debate with selective escalation fails to rescue multi-agent LLM consensus in a grounded cybersecurity domain. That is a stronger and more surprising finding than Volume I’s result, because it eliminates the most plausible structural fix.

Two reserve hypotheses are pre-loaded: the Adversarial Oracle (conservative, changes interaction dynamic) and the Deterministic Skeptic (radical, removes an LLM agent entirely). The sequence continues.

Either way, the work continues. Either way, it is honest.

# **VII. Expectations**

This section is included because the question was asked: what are the expectations?

The honest answer is: guarded optimism, grounded in evidence.

The SC-017 pattern (pending reconciliation of the data contradiction) demonstrated that debate can correct over-confidence on genuinely ambiguous evidence. The selective escalation architecture is designed specifically to exploit this pattern by routing only ambiguous cases through debate, while protecting clear-cut cases from calibration corruption.

If the hypothesis is correct — that debate helps on ambiguity and hurts on clarity — then selective escalation should produce a combined system that outperforms either mode alone. That is the bet.

If the hypothesis is wrong — if debate degrades accuracy even on ambiguous cases when constrained to per-claim argumentation — then we have disproven the strongest remaining argument for multi-agent debate in this domain. That is also valuable.

The infrastructure is built to produce an honest answer either way. That has always been the point.

# **VIII. A Note on Process**

The Tribunal was an experiment in using AI to review AI research about AI. Three systems built by three different companies, with three different training methodologies and three different reasoning architectures, were given the same brief and asked to stress-test the same body of work. The convergence that emerged was not designed. It was discovered.

This process produced several things that a traditional peer review would not have. It was faster (hours, not months). It was parallel (three reviewers simultaneously, not sequential). It was structurally adversarial (the brief explicitly instructed reviewers to challenge, not agree). And it produced a composed insight that no single reviewer stated but all contributed to.

Whether this constitutes a new methodology for research review or merely a useful one-off experiment is a question for later. What matters now is that it worked: the Tribunal surfaced a blind spot (the Oracle), caught a data contradiction (SC-017), and converged on an architectural direction that the project’s own team had identified as a candidate but had not committed to.

The Tribunal did what it was designed to do. It told us what we needed to hear, not what we wanted to hear. And because three different minds said the same thing, we can be reasonably confident that the signal is real.

*Volume II compiled March 25, 2026\. Skyframe Innovations.*

*All Tribunal responses, session data, and benchmark outputs are preserved in the project archive.*

**Tribunal Members:**

GPT 5.4 Pro (OpenAI) · Gemini 3.1 Pro (Google) · Perplexity/Opus 4.6 (Perplexity AI)

Reference: Berdoz, F., Rugli, L., & Wattenhofer, R. (2026). Can AI Agents Agree? arXiv:2603.01213v2. ETH Zurich.