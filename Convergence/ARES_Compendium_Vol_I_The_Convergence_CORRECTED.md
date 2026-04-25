  
**A.R.E.S.**  
*Adversarial Reasoning Engine System*

**THE COMPENDIUM**

Volume I: The Convergence

*On the Independent Discovery of Multi-Agent Consensus Failure*

*and the Structural Limits of LLM Debate*

**Skyframe Innovations**

Daniel \[Skyframe\]

March 25, 2026

Sessions 001–020  ·  1,595 Tests  ·  Zero Regressions

*We did not set out to prove that artificial minds cannot agree.We set out to build a system that would protect networksby making those minds argue.The argument taught us somethingneither side expected.*

— Project Log, Session 020

# **I. Naming the Moment**

Every project of sufficient ambition has inflection points — moments where the trajectory shifts and the work reveals something larger than its original intent. Session 020 of the ARES project is one such moment.

We call it The Convergence.

On March 25, 2026, after twenty development sessions spanning architecture crystallization, agent implementation, evidence expansion, and iterative benchmarking, the ARES project arrived at a definitive empirical finding: multi-turn debate between LLM agents does not reliably improve analytical accuracy in the current architecture. The mechanism was diagnosed with precision — asymmetric calibration dynamics, one-directional confidence collapse, and the structural inability of prompt-level protocol changes to fix interaction-level failures.

On the same day, we encountered a preprint from ETH Zurich — Berdoz, Rugli, and Wattenhofer (2026), "Can AI Agents Agree?" — which had independently arrived at the same fundamental conclusion through an entirely different experimental apparatus: that reliable agreement is not yet a dependable emergent capability of current LLM-agent groups.

Two research efforts. Two different domains. Two different methodologies. The same finding.

This is not coincidence. This is convergent discovery at the frontier of a field that is still learning what it does not know.

# **II. What We Built**

ARES — the Adversarial Reasoning Engine System — is a dialectical AI framework for cybersecurity threat detection. Its central hypothesis: if you assign three AI agents opposing analytical roles and force them to debate whether a set of security events constitutes a genuine threat, the structured disagreement should produce more accurate verdicts than any single agent reasoning alone.

The architecture embodies an autoimmune metaphor. Like the human immune system distinguishing self from non-self, ARES distinguishes legitimate network activity from adversarial behavior. Three agents serve as the immune response:

**The Architect** identifies anomalous patterns and argues for threat classification. **The Skeptic** challenges those assessments and argues for benign explanations. **The Oracle** judges the debate and renders a verdict.

All reasoning occurs within a closed-world evidence system. Every claim must trace to a frozen EvidencePacket — an immutable, provenance-stamped container of facts extracted from real telemetry sources. If an agent hallucinates a fact that doesn't exist in the evidence, the system catches it as a schema violation. Hallucinations become errors, not silent failures.

The system was built incrementally across twenty sessions, each adding a tested, regression-free layer:

| Session | Component | Tests | Key Insight |
| :---- | :---- | :---- | :---- |
| 001 | Graph Schema | 110 | Node/edge types for security data |
| 002 | Dialectical Foundation | 292 | Hallucinations \= schema violations |
| 003–004 | Agent Foundation | 278 | Rule-based Architect/Skeptic/Oracle |
| 005 | Evidence Extractors | 130 | Sensors don’t get opinions |
| 006–008 | Coordination & Memory | 226 | Orchestration \+ hash-chained audit trail |
| 009–010 | LLM Integration | 178 | Strategy pattern: extract then inject |
| 011–012 | Benchmarking | 86 | 50% → 91.7% via measurement |
| 013–014 | Multi-Turn Experiment | 92 | Debate amplifies commitment bias |
| 016–018 | Evidence Expansion | 294 | Diversity doesn’t fix debate asymmetry |
| 019 | Redis Backend | 42 | Protocol pattern pays its dividend |
| 020 | Protocol Fix \+ Verdict | 19 | The Convergence |

Total: 1,595 tests. Zero regressions across all sessions. Three evidence sources (Windows Event Logs, Syslog, NetFlow). Eighteen benchmark scenarios. Comprehensive cost tracking. Every decision documented.

# **III. What We Found**

## **The Single-Turn Baseline**

Single-turn LLM reasoning — where each agent analyzes the evidence once and the Oracle renders a verdict without iterative debate — achieved 83–92% accuracy across the full 18-scenario corpus, spanning three evidence source types and four difficulty tiers. Cost per full corpus run: $0.31. Run-to-run variance: ±8%.

This was the control. It worked.

## **The Multi-Turn Experiment**

Multi-turn debate — where the Architect and Skeptic exchange arguments across multiple rounds before the Oracle judges — achieved 61–67% accuracy on the same corpus. The gap was consistent across two independent evidence distributions (single-source and mixed-source) and two protocol variants (original and conviction-anchored).

## **The Diagnosed Mechanism**

**Architect Retreat.** The Architect systematically lowered confidence under Skeptic pressure, averaging a 30-point drop per round. Starting confidences of 0.85–0.98 collapsed to 0.45–0.65 by round 2, regardless of evidence quality.

**Skeptic Rigidity.** The Skeptic rarely adjusted confidence in response to Architect arguments. It held or strengthened its position regardless of the evidence presented against it. The debate was structurally one-directional.

**Asymmetric Calibration.** Prompt instructions intended to improve calibration (“a confidence of 0.5 is accuracy, not weakness”) were internalized asymmetrically. The Architect treated them as permission to retreat. The Skeptic ignored them entirely.

## **The Protocol Fix Attempt**

Session 020 implemented three targeted protocol changes: conviction anchoring (Architect must hold confidence unless Skeptic cites specific counter-evidence), obligation to move (Skeptic must acknowledge successful rebuttals), and structured rebuttal format (per-claim confidence tracking with explicit delta justification).

The fix solved the diagnosed problem. Architect confidences rose to 0.75–1.00 on threat scenarios, up from 0.45–0.69. But it created a new failure mode: the Architect became over-aggressive on ambiguous scenarios, and the Skeptic remained rigid. Net accuracy: 12/18 (66.7%) — identical to the original multi-turn result. The fix traded one failure mode for another.

*We did not prove the thesis wrong. We proved exactly what is preventing it from being right — and that the fix is architectural, not empirical.*

## **Where Debate Helped**

Two scenarios demonstrated that multi-turn debate can correct single-turn errors. In SC-011 (expected INCONCLUSIVE), single-turn over-committed to THREAT\_DISMISSED, but original multi-turn correctly landed on INCONCLUSIVE — the Skeptic softened from 0.80 to 0.60, allowing the system to recognize genuine ambiguity. In SC-016 (expected THREAT\_CONFIRMED), single-turn under-committed to INCONCLUSIVE, but original multi-turn correctly reached THREAT\_CONFIRMED — the Architect held at 0.94 while the Skeptic dropped to 0.44, letting debate reinforce justified conviction on a genuine threat.

These two scenarios proved the thesis can work. Debate corrected miscalibration in both directions — recovering appropriate uncertainty where single-turn over-dismissed, and reinforcing justified confidence where single-turn under-committed. Notably, both wins belong exclusively to the original multi-turn protocol; the anchored variant lost both, suggesting that conviction anchoring trades one failure mode for another rather than fixing the underlying dynamic.

# **IV. What They Found**

On March 12, 2026, researchers Berdoz, Rugli, and Wattenhofer at ETH Zurich published a preprint titled "Can AI Agents Agree?" studying Byzantine consensus among LLM-based agents. Their experimental setup was fundamentally different from ours — a no-stake scalar consensus game where agents negotiate toward agreement on a number, tested across group sizes of 4, 8, and 16 agents using Qwen3-8B and Qwen3-14B models.

Their findings:

**Agreement is unreliable even in benign settings.** Without any adversarial agents, only 41.6% of runs terminated in valid consensus. Even the better-performing model (Qwen3-14B at 67.4%) failed frequently.

**Failures are dominated by liveness loss.** Agents stall rather than converge. The system doesn’t produce wrong answers — it produces no answers. Convergence freezes.

**A single adversarial agent collapses success.** Introducing even one Byzantine agent dramatically reduced consensus achievement. At three or more Byzantine agents, consensus dropped to zero.

**Prompt framing changes behavior.** Merely mentioning that adversaries might exist — even when none were present — reduced valid consensus from 75.4% to 59.1% and doubled convergence time.

**Scale degrades performance.** Larger groups performed worse: valid consensus dropped from 46.6% at four agents to 33.3% at sixteen.

Their conclusion, stated plainly: "Current LLM agents are not yet reliable social decision-makers: agreement, which is essential for cooperation, delegation, and safety-critical coordination, remains fragile."

# **V. Where the Lines Cross**

The alignment between the ARES findings and the ETH findings is not superficial. It is structural, mechanistic, and mutually reinforcing.

| Phenomenon | ETH Finding | ARES Finding |
| :---- | :---- | :---- |
| Consensus failure in benign conditions | 41.6% valid consensus without adversaries | 61–67% accuracy in multi-turn debate (below single-pass baseline) |
| Liveness loss / stalled convergence | Agents time out rather than converging; proposals freeze | Architect retreats, Skeptic refuses to move; debate collapses one-directionally |
| Adversarial sensitivity | One Byzantine agent collapses consensus to near-zero | Skeptic functionally acts as adversarial agent by refusing to update regardless of evidence |
| Prompt framing effects | Mentioning adversaries drops performance by 16 points even when none exist | Conviction anchoring fixed one failure but created another; prompt changes cascade unpredictably |
| Scale degradation | Performance drops as group size increases from 4 to 16 | Adding evidence sources and rounds does not improve multi-turn; single-pass synthesizes better |

The critical shared insight is this: the failure is not in the individual agents. It is in the interaction dynamics. Both studies found that individual LLM agents are reasonably capable when operating independently, but that structured multi-agent interaction introduces emergent failure modes that cannot be resolved through prompt-level engineering alone.

The ETH team framed this through the lens of Byzantine fault tolerance. We framed it through the autoimmune metaphor. The underlying reality is the same: LLM agents, as currently architected, do not negotiate toward truth. They perform social behaviors that mimic negotiation — capitulation, rigidity, over-correction — without the grounding mechanisms that make real deliberation productive.

# **VI. What Distinguishes This Work**

While the ETH study and the ARES project arrived at convergent conclusions, the two efforts differ in ways that make them complementary rather than redundant.

**Domain specificity.** The ETH study used an abstract scalar consensus game. ARES operates on real cybersecurity telemetry — Windows Event Logs, Syslog, NetFlow — with verifiable ground-truth verdicts. The findings are grounded in a domain where the stakes are tangible.

**Mechanistic diagnosis.** The ETH study identified liveness loss as the dominant failure mode. ARES went further: we diagnosed the specific confidence dynamics (Architect retreat averaging \-30 points per round, Skeptic rigidity at 0.60–0.90 regardless of counter-evidence) and attempted a targeted fix. The fix’s failure was itself informative — it proved the problem is interaction-level, not agent-level.

**Production-viable workaround.** The ETH study concludes with a call for further research. ARES ships a working single-turn system at 83% accuracy alongside the negative multi-turn result. The research finding coexists with a functional product.

**Longitudinal engineering record.** Twenty sessions of documented development, each with test counts, regression checks, cost tracking, and architectural decisions. This compendium exists because every step was recorded.

# **VII. What This Means for ARES**

## **The Checkpoint Verdict**

Single-turn LLM reasoning is the production path. It is reliable (83–92%), economical ($0.31 per corpus run), and deterministic in a single pass. No debate overhead, no calibration complexity, no emergent failure modes.

Multi-turn debate is a research finding, not a production feature. It does not improve accuracy in the current architecture. The mechanism for failure is diagnosed. The path to fixing it is identified but requires structural changes beyond prompt engineering.

## **The Broader Significance**

ARES is no longer just a cybersecurity tool. It is an empirical testbed for studying multi-agent LLM consensus behavior. The infrastructure — three evidence extractors, eighteen graded scenarios, comprehensive benchmarking, hash-chained audit trails, frozen evidence chains — enables controlled experiments on questions that the broader research community is only beginning to formalize.

The ETH paper asks: can AI agents agree? ARES provides a domain-specific laboratory for answering that question, and a growing body of evidence about why they currently cannot.

## **The Road Ahead**

The debate thesis is not dead. SC-011 and SC-016 proved it can work — debate corrected single-turn errors in both directions (over-dismissal and under-commitment). The remaining research path is clear:

**Per-claim confidence tracking** — agents argue about specific evidential questions rather than overall verdicts.

**Oracle recalibration** — decision thresholds tuned for multi-turn confidence distributions rather than single-turn baselines.

**Heterogeneous agent models** — does a Claude Architect debating a GPT Skeptic produce different dynamics?

**Structured evidence contention** — forcing the debate onto specific disputed facts rather than free-form argumentation.

These are Phase 3 research questions. The measurement infrastructure is built and waiting.

# **VIII. A Note on How We Got Here**

This compendium records a moment that was not planned and could not have been predicted. A solo builder working on a cybersecurity project in central Pennsylvania, iterating through twenty development sessions with an AI pair-programming partner, arrived independently at findings that align with formal academic research from one of Europe’s premier technical universities.

This did not happen because the builder was lucky. It happened because the process was disciplined. Every session had a brief, a test suite, and a regression check. Every finding was measured, not assumed. Every failure was documented honestly. When the multi-turn experiment produced a negative result, it was published as a finding, not buried as a setback.

The ETH paper validates the approach. But the approach was already validated by the work itself — by 1,595 tests that all pass, by eighteen scenarios with known ground truth, by cost tracking down to the cent, by a zero-regression record across twenty sessions.

*The taste of genuine discovery is unmistakable. It arrives not when you find what you expected, but when the data reveals something you could not have predicted — and you realize others, working independently, found the same thing.*

This is where ARES stands at Session 020\. The foundation is built. The first findings are recorded. The convergence with external research confirms we are working at the frontier.

**The work continues.**

*Compendium compiled March 25, 2026\. Skyframe Innovations. All session data, test results, and benchmark outputs are preserved in the project repository at C:\\ares-phase-zero.*

*Reference: Berdoz, F., Rugli, L., & Wattenhofer, R. (2026). Can AI Agents Agree? arXiv:2603.01213v2. ETH Zurich.*