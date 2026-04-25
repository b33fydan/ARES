

**A.R.E.S.**

Adversarial Reasoning Engine System

**PHASE 3 BATTLE PLAN**

*Selective Escalation Architecture*

Classification: Internal — Skyframe Innovations

March 25, 2026

Post-Tribunal Synthesis · Sessions 021–024+

20 Sessions · 1,595 Tests · Zero Regressions · $0.96 Total API Cost

Prepared for: Dan (Skyframe) \+ Claude Code

# **Section 0: Executive Summary**

The Tribunal has spoken. Three independent AI architectures (GPT 5.4 Pro, Gemini 3.1 Pro, Perplexity/Opus 4.6) consumed the full ARES project state and returned unanimous on the strategic direction. This Battle Plan translates that convergence into executable sessions.

## **The Unanimous Verdicts**

* **Ship single-turn.** 83.3% accuracy is the production path. Do not let research block deployment.

* **Per-claim debate is the research path.** All three Tribunal members independently selected Direction B as the highest-value experiment.

* **N=18 is a statistical liability.** Expand the corpus before making ensemble or complementary-strength claims.

* **The failure is interaction-level, not agent-level.** Prompt engineering cannot fix asymmetric calibration dynamics. The fix is architectural.

## **The Composed Insight**

No single Tribunal member stated this, but the pieces were on the table from all three. The Phase 3 architecture composes two ideas into one system:

**Selective Escalation:** Run single-turn first. Only escalate to adversarial review when the Oracle’s confidence falls in an uncertainty band (0.35–0.65).

**Per-Claim Audit:** When escalation triggers, debate operates on specific disputed evidential claims tied to frozen EvidencePackets — not free-form verdict-level argument.

This gives single-turn’s reliability on clear-cut cases, debate’s proven strength on genuine ambiguity (the SC-017 pattern), and none of the calibration corruption on cases where single-turn was already right.

# **Section 1: Pre-Flight — Verify Before Building**

Before any new architecture ships, one critical issue must be resolved.

## **The SC-017 Contradiction**

GPT 5.4 Pro identified a material inconsistency: the Compendium uses SC-017 (Cloud Backup vs. Exfiltration Ambiguity) as the flagship example of debate correcting an over-confident single-turn verdict. However, GPT flagged that the per-scenario table in the Battle Plan shows SC-017 wrong in all three modes.

**Action:** Pull the actual benchmark artifacts from C:\\ares-phase-zero. Cross-reference the saved run data against both the Compendium narrative and the Battle Plan table. Determine whether this is a data versioning issue (different runs produced different results) or a narrative error.

**Outcome:** Either reconcile SC-017 as a genuine debate win with corrected table data, or remove it as the flagship example and replace with whatever scenario the data actually supports. No public-facing document uses SC-017 as evidence until this is resolved.

**Estimated effort:** 30 minutes. Non-negotiable priority.

# **Section 2: Phase 3 Architecture — Selective Escalation**

The core architectural change is moving from “debate everything” to “debate only when it helps.”

## **2.1 The Flow**

1. **Single-Turn Pass.** Architect analyzes evidence, Skeptic analyzes evidence, Oracle renders verdict. Standard single-turn pipeline. If Oracle confidence is above 0.65 or below 0.35: verdict is final. Stop.

2. **Escalation Gate.** If Oracle confidence lands in the uncertainty band (0.35–0.65), the system flags the case for adversarial review. The gate is deterministic — no LLM decides whether to escalate.

3. **Claim Extraction.** The Oracle identifies the 3–5 specific factual claims that are contested between Architect and Skeptic analyses. Each claim is tied to specific frozen EvidencePackets.

4. **Per-Claim Adversarial Audit.** Architect and Skeptic debate each extracted claim individually. Each argument must cite specific evidence packet fields. Confidence is tracked per-claim, not per-verdict.

5. **Claim-Weighted Verdict.** Oracle aggregates per-claim confidences into a final verdict. The aggregation function is deterministic (weighted by evidence support count), not LLM-judged.

## **2.2 Why This Architecture**

This design directly addresses every diagnosed failure mode:

| Failure Mode | Old Architecture | New Architecture |
| :---- | :---- | :---- |
| **Architect Retreat** | Debates every case, retreats on clear threats | Clear threats never enter debate. Escalation only on genuine ambiguity. |
| **Skeptic Rigidity** | Argues against entire verdicts with free-form objections | Must attack specific claims with specific evidence citations. Vague objections are structurally impossible. |
| **Oracle Passivity** | Passively synthesizes asymmetric debate output | Actively extracts contested claims, then aggregates deterministically. Removed from calibration noise. |
| **Cost Overhead** | 3x cost on every scenario (multi-turn on everything) | Extra cost only on ambiguous cases. Clear verdicts stay at single-turn cost. |

## **2.3 The Uncertainty Band**

The escalation gate thresholds (0.35–0.65) are initial values. The benchmark data from Session 021’s expanded corpus will be used to calibrate these thresholds empirically. The key design principle: the band should be narrow enough that most cases resolve at single-turn, but wide enough to catch the cases where debate demonstrably helps.

Expected escalation rate based on current data: approximately 15–25% of scenarios should land in the uncertainty band. If the rate is below 10%, the band is too narrow. If above 40%, too wide.

# **Section 3: Session Sequence**

## **Session 021: Verification \+ Corpus Expansion**

**Goal:** Resolve the SC-017 contradiction and expand the scenario corpus from 18 to 30–35 scenarios.

**Deliverables:**

* **SC-017 reconciliation report.** Written finding: either the data supports the narrative or the narrative is corrected.

* **12–17 new benchmark scenarios.** Covering all four difficulty tiers, weighted toward the ambiguity tier (where debate has the best chance of helping).

* **Re-run all three modes on expanded corpus.** Establish new baseline accuracy numbers at N=30+.

* **Error type analysis.** Classify each wrong answer as false positive (benign flagged as threat) or false negative (threat missed). Calculate per-mode FP/FN ratios.

**Test target:** All existing 1,595 tests pass \+ new scenario tests.

**New files:** New scenario definitions, expanded benchmark runner output, SC-017 reconciliation doc.

## **Session 022: The Escalation Gate**

**Goal:** Implement the confidence-based escalation detector that decides whether a case proceeds to per-claim audit.

**Deliverables:**

* **EscalationGate class.** Frozen dataclass. Takes Oracle single-turn output, returns RESOLVED or ESCALATE based on confidence thresholds.

* **Threshold configuration.** Configurable band boundaries with defaults at 0.35/0.65. Stored as frozen config, not magic numbers.

* **Gate accuracy test.** Run the gate against the expanded corpus. Report: how many scenarios does the gate correctly identify as needing review vs. correctly resolve at single-turn?

* **Escalation rate metrics.** Percentage of corpus that triggers escalation. Target: 15–25%.

**Test target:** All prior tests pass \+ EscalationGate unit tests \+ integration tests with existing single-turn pipeline.

**New files:** escalation\_gate.py, test\_escalation\_gate.py, gate configuration.

## **Session 023: Per-Claim Evidence Extraction**

**Goal:** Build the claim extraction layer that decomposes a contested verdict into specific disputable claims tied to EvidencePackets.

**Deliverables:**

* **ClaimExtractor class.** Takes Architect analysis \+ Skeptic analysis \+ EvidencePackets. Outputs a list of ContestClaim frozen dataclasses, each with: claim text, supporting evidence packet IDs, contesting evidence packet IDs, claim confidence from each agent.

* **ContestClaim schema.** Frozen dataclass. Fields: claim\_id, claim\_text, architect\_confidence, skeptic\_confidence, supporting\_evidence\_ids, contesting\_evidence\_ids, evidence\_delta (what specific facts are in dispute).

* **Per-claim debate protocol.** New message format for claim-level argumentation. Each argument must reference specific ContestClaim IDs and specific EvidencePacket fields.

**Test target:** All prior tests pass \+ ClaimExtractor unit tests \+ ContestClaim schema validation tests \+ per-claim message format tests.

**New files:** claim\_extractor.py, contest\_claim.py, test\_claim\_extractor.py, per\_claim\_protocol.py.

## **Session 024: Integration \+ Benchmark**

**Goal:** Wire the selective escalation pipeline end-to-end and benchmark against the expanded corpus.

**Deliverables:**

* **SelectiveEscalationPipeline class.** Orchestrates: single-turn pass → escalation gate → claim extraction → per-claim debate → claim-weighted verdict.

* **Full corpus benchmark.** Run selective escalation against all 30+ scenarios. Compare accuracy against: (a) single-turn alone, (b) original multi-turn, (c) anchored multi-turn.

* **Cost analysis.** Total API cost for selective escalation vs. full multi-turn on all scenarios. Expected: significantly lower than full multi-turn, marginally higher than single-turn.

* **Calibration metrics.** Brier score, expected calibration error (ECE), and per-scenario confidence traces for the new pipeline.

* **Per-claim confidence analysis.** For escalated scenarios: did per-claim debate produce more calibrated confidences than verdict-level debate?

**Test target:** All prior tests pass \+ pipeline integration tests \+ benchmark regression tests.

**Success criteria (binary):** Selective escalation accuracy on the expanded corpus equals or exceeds single-turn accuracy (83%+), with improved calibration on ambiguous-tier scenarios specifically. If it does not, the result is documented honestly and we proceed to the reserve hypotheses.

# **Section 4: Reserve Hypotheses**

If the selective escalation architecture does not meet the Session 024 success criteria, two fallback directions are pre-loaded and ready to test. They are ordered conservative-first, radical-second.

## **Reserve A: Adversarial Oracle (Perplexity Wild Card)**

Convert the Oracle from passive judge to active stress-tester. After each debate round, the Oracle generates the strongest argument against whichever agent currently holds higher confidence, injecting it back into the debate. This forces both agents to defend their positions against a genuinely strong adversary, breaking the Skeptic rigidity problem by making the Skeptic answer to something other than the Architect.

**Why reserve, not primary:** This still operates at the verdict level, not the claim level. It changes the interaction dynamic but not the debate granularity. Test the structural fix first.

## **Reserve B: Deterministic Skeptic (Gemini Wild Card)**

Replace the LLM Skeptic entirely with a deterministic Python function that queries the evidence graph. If the Architect claims a privilege escalation occurred, the deterministic Skeptic checks the graph: does a logon event edge exist prior to this process execution? If yes, the claim passes. If no, schema violation error. AI does creative threat hunting (Architect), code does rigorous fact-checking (Skeptic), LLM judges the final state (Oracle).

**Why reserve, not primary:** This is the most architecturally radical change. It removes an entire LLM agent. If the per-claim debate approach works, it preserves the three-agent dialectical model. If it fails, the deterministic Skeptic tests whether the Skeptic role was ever appropriate for an LLM in the first place.

# **Section 5: Metrics and Measurement**

The Tribunal identified that raw accuracy is insufficient. Phase 3 adds the following metrics to every benchmark run:

| Metric | What It Measures | Source |
| :---- | :---- | :---- |
| **Accuracy** | Correct verdicts / total scenarios | Existing |
| **FP / FN Ratio** | False positives (benign flagged) vs. false negatives (threat missed). Not all errors are equal. | NEW |
| **Brier Score** | Calibration quality. Lower is better. Measures whether stated confidence matches actual accuracy. | NEW |
| **ECE** | Expected Calibration Error. Binned version of Brier score. Standard in ML calibration literature. | NEW |
| **Escalation Rate** | Percentage of scenarios that trigger the escalation gate. Target: 15–25%. | NEW |
| **Escalation Accuracy** | Of escalated scenarios, how many did per-claim debate improve vs. degrade vs. leave unchanged? | NEW |
| **Confidence Drift** | Per-claim confidence delta across debate rounds. Replaces verdict-level drift tracking. | NEW |
| **Cost per Scenario** | API cost broken down by single-turn-only vs. escalated scenarios. | Existing (extended) |

# **Section 6: Non-Negotiables**

Carried forward from all 20 prior sessions. No exceptions.

* **Zero regressions.** All existing 1,595 tests continue to pass after every session.

* **New files over modifications.** Strict discipline maintained.

* **Frozen dataclasses everywhere.** Immutability is not optional. ContestClaim, EscalationGate config, and all new schemas are frozen.

* **Measurement before optimization.** Every change is benchmarked before the next session begins.

* **Content pipeline stays active.** Build process IS the content.

* **Session-based development.** Each session has a brief, a deliverable, and a test count.

* **Session-based branching.** Squash merge to main only after all tests pass.

# **Section 7: Content Pipeline**

The next four sessions map directly to episode content:

| Episode | Session(s) | Narrative |
| :---- | :---- | :---- |
| **Episode 5** | Tribunal Synthesis | "We sent our research to three rival AIs and asked them to tear it apart. They all agreed on one thing." |
| **Episode 6** | Session 021–022 | "The experiment that proved us wrong told us exactly what to build next. Here’s the blueprint." |
| **Episode 7** | Session 023–024 | "Selective Escalation: teaching AI when to argue and when to shut up." |
| **Episode 8** | Results | "Did it work? The benchmark doesn’t lie." (Content depends on actual results — honest either way.) |

# **Section 8: Closing**

Three different AI architectures reviewed twenty sessions of work and converged on the same direction. That convergence is not coincidence. It is signal.

The selective escalation architecture is the composed insight that no single Tribunal member stated but all three contributed the pieces for. It preserves single-turn reliability where reliability already exists. It rescues the debate thesis by constraining it to the domain where it demonstrably helps: genuine ambiguity. And it grounds the debate in specific claims rather than free-form argumentation, directly addressing the diagnosed mechanism of asymmetric calibration failure.

The next four sessions will determine whether this architecture delivers. The measurement infrastructure is built. The benchmark corpus is expanding. The forcing function is set: Session 024 produces a binary verdict.

If it works, we have a publishable result and a production-viable system. If it doesn’t, we have two reserve hypotheses pre-loaded and an honest negative result that narrows the solution space further.

Either way, the content writes itself.

*End of Battle Plan. Sessions 021–024 commence on next available build day.*