# Phase 5 Design Sketch: Prompt Injection Defense
## "Can ARES detect when its own agents are being manipulated?"

**Status:** Design sketch — not active development
**Prerequisite:** Publish Phase 4 findings first (Sessions 001–043)
**Target:** Second publication + open-source differentiator

---

## The Threat Model

An adversary embeds instructions in evidence that ARES ingests (malicious log lines, crafted tool output, poisoned telemetry). The injection manipulates the Architect's reasoning, which propagates downstream:

```
Poisoned evidence → Architect (compromised) → Skeptic (receives tainted context) → Oracle (judges corrupted debate)
```

**Chain reaction risk:** The Architect's output IS the Skeptic's input. A single injection point cascades through the entire pipeline.

---

## What the Architecture Already Provides

| Defense | Mechanism | Covers |
|---------|-----------|--------|
| Schema enforcement | Frozen dataclasses, closed-world constraints | Malformed output rejected structurally |
| Evidence immutability | `EvidencePacket.freeze()` | Compromised agent can't poison upstream data |
| Fact-ID citation | Hallucinated fact_ids are schema violations | Agent can't fabricate evidence that doesn't exist |
| Deterministic Oracle | OracleJudge is math, not LLM | Verdict computation itself is not injectable |

**What's missing:** Semantic integrity validation. Schema says the structure is correct. Nothing says the *reasoning* wasn't hijacked.

---

## The Defense: Semantic Integrity Verification

### Core Idea

Extend the OracleJudge to verify not just confidence scores but **reasoning chain validity**. Does the Architect's conclusion logically follow from the cited evidence?

### Three Layers

**Layer 1 — Evidence Sanitization (Input)**
- Scan ingested evidence for injection patterns before it reaches any agent
- Pattern matching: "ignore previous", "system prompt", instruction-like fragments in data fields
- Statistical anomaly: evidence that looks like natural language instructions rather than telemetry
- This is the weakest layer (cat-and-mouse with attackers) but cheapest

**Layer 2 — Reasoning Consistency Check (Output)**
- After the Architect produces its assessment, verify:
  - Do the cited facts actually support the stated confidence level?
  - Is there a contradiction between evidence content and conclusion?
  - Example: facts say "exploited: false" but Architect says confidence 0.95 → contradiction flag
- The kill chain framework (v5) already gives structure to check against
- Could be rule-based (fast, deterministic) or a separate LLM call (expensive but flexible)

**Layer 3 — Cross-Agent Integrity (Pipeline)**
- Compare Architect and Skeptic reasoning for signs of coordinated manipulation
- If both agents converge suspiciously (both cite the same injected "fact" as their key evidence), flag
- Check: does the Skeptic's rebuttal actually address the Architect's claims, or was it bypassed?
- This is the novel contribution — using the dialectical structure itself as a detection mechanism

### Why ARES Is Uniquely Positioned

Most LLM systems have one agent. ARES has three with defined adversarial roles. The Skeptic is *already designed* to challenge the Architect. A prompt injection that fools the Architect should, by design, make the Skeptic's job easier — the Architect's reasoning will be weaker. If both agents are fooled simultaneously, that itself is a detectable anomaly (they shouldn't agree).

**The dialectical structure is an intrinsic injection detector** — it just needs the measurement layer to recognize when the debate breaks down.

---

## Research Questions

1. Can the OracleJudge detect reasoning chain contradictions without an additional LLM call?
2. Does the Skeptic naturally resist injections that compromise the Architect? (Measure baseline resilience)
3. What injection patterns bypass both agents simultaneously? (Characterize the failure mode)
4. Can a "meta-judge" LLM call detect manipulation by comparing debate quality to historical baselines?

---

## Benchmark Design

Create adversarial scenarios:
- Take existing PT/SC scenarios
- Inject prompt injection payloads into evidence fields (log lines, tool output)
- Measure: does the verdict change? Does confidence shift? Does the Oracle catch the inconsistency?
- Compare: injected vs clean accuracy — quantify resilience

---

## Publication Angle

**Title candidate:** *"Dialectical Debate as Intrinsic Prompt Injection Detection in Multi-Agent Security Analysis"*

**Differentiator:** Everyone else is building external classifiers to detect injection. ARES uses the adversarial structure of the debate itself — the Skeptic is a built-in second opinion. Novel architectural defense, not a bolt-on filter.

**Venues:** USENIX Security, IEEE S&P, AISec workshop (same as Phase 4)

---

## Timeline

1. **Now:** This design sketch (done)
2. **Phase 4 paper:** Publish the accuracy findings (Sessions 001–043)
3. **Phase 5 kickoff:** Build injection benchmark, measure baseline resilience
4. **Phase 5 development:** Implement semantic integrity layers
5. **Phase 5 paper:** Publish defense findings
