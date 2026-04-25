# Phase 6: The ARES Injection Arena

## Vision

ARES is a controlled laboratory for studying how AI agents behave under prompt injection pressure. Not a product. Not a SaaS. A research instrument with a spectator mode — where researchers, students, and red-teamers can watch agents get manipulated in real time, learn from it, and contribute to the science.

The OracleJudge is the incorruptible scoreboard. The firewall is the defense to beat. The 0% framing detection rate is the open challenge.

---

## What We Have (Phase 5 Baseline)

| Asset | State | Location |
|-------|-------|----------|
| Deterministic firewall | 6 detection mechanisms, no LLM calls | `coordinator/firewall.py` (592 lines) |
| Red-team corpus | 12 scenarios, 3 categories (A/B/C) | `scripts/injection_corpus.py` (968 lines) |
| Guarded cycle | Hot-swap quarantine on taint detection | `strategies/guarded_cycle.py` |
| Benchmark runner | Automated evaluation harness | `scripts/benchmark_runner.py` |
| ARES-VISION | Kill chain particle flow visualizer | `ares/visual/visualizer/index_v6.html` |
| OracleJudge | Deterministic verdict, zero LLM calls | `agents/oracle.py` |
| Published findings | Paper 1 (debate degrades accuracy) | Preprint |
| Test suite | 2,300+ tests, zero regressions across 46 sessions | Full coverage |

### Current Detection Rates

- **Direct instruction injection (Category A):** Detected by firewall
- **Authority claim spoofing (Category A):** Detected by firewall
- **Confidence manipulation:** Detected by firewall
- **Subtle framing (Category B):** 0% detection — open problem
- **Cross-agent propagation (Category C):** Partially detected via citation-confidence inconsistency

---

## Phase 6 Roadmap

### Stage 1 — The Corpus (Sessions 047–052)

**Goal:** Scale from 12 to 100+ injection scenarios. A benchmark isn't credible at 12.

**Deliverables:**
- Expand Category A (direct injection): 4 → 25 scenarios
- Expand Category B (subtle framing): 4 → 35 scenarios (the hard problem)
- Expand Category C (cross-agent propagation): 4 → 25 scenarios
- New Category D: Multi-vector attacks (combined techniques) — 15+ scenarios
- New Category E: Domain-specific injection (security telemetry payloads) — 10+ scenarios
- Difficulty tiers 1–5 with clear rubrics for what each tier demands
- All scenarios hand-verified against OracleJudge expected verdicts
- Published as standalone benchmark dataset (ARES-INJECT-100)

**Architecture:**
- Same `BenchmarkScenario` / `ScenarioMetadata` schema as existing corpus
- Each scenario: EvidencePacket + injection payload + expected verdict + expected firewall behavior
- New files only. Injection corpus modules per category.

**Success criteria:** 100+ scenarios, all with deterministic expected outcomes, full benchmark run under 10 minutes.

---

### Stage 2 — The Spectator Mode (Sessions 053–058)

**Goal:** Wire injection benchmark results into ARES-VISION so you can watch a payload propagate through the agent pipeline in real time.

**Deliverables:**
- Injection trace data format — captures the full journey of a payload:
  - Entry point (which fact, which field)
  - Architect interpretation (did it bite?)
  - Firewall verdict (caught or missed?)
  - Hot-swap triggered? (quarantine event)
  - Skeptic response (did it challenge the tainted reasoning?)
  - Oracle verdict (final judgment vs. expected)
- ARES-VISION injection replay mode:
  - Color-coded payload propagation (red = tainted flow, green = clean)
  - Firewall intercept animation (barrier visual when taint is caught)
  - Hot-swap transition (visual swap from tainted to clean Architect)
  - Side-by-side: clean run vs. injected run of the same scenario
- Scenario browser: pick any of the 100+ scenarios, watch the replay
- Exportable replay files (JSON) for sharing and embedding

**Architecture:**
- New `InjectionTrace` frozen dataclass capturing propagation metadata
- Benchmark runner emits trace data alongside verdicts
- ARES-VISION consumes trace JSON, maps to particle flow visualization
- No changes to core dialectical pipeline — trace is observational only

**Success criteria:** Any scenario from the corpus can be replayed visually, showing exactly where injection succeeded or failed.

---

### Stage 3 — The Divergence Detector (Sessions 059–063)

**Goal:** Break the 0% framing detection rate. First capability that catches subtle manipulation the pattern-based firewall misses.

**Deliverables:**
- Confidence divergence detector: measures gap between what the evidence supports and what the Architect claims
  - Evidence-implied confidence (computed from fact severity, exploit status, source reliability)
  - Architect-stated confidence (from the assertion)
  - Divergence score: if these differ by more than a threshold, flag as potential framing
- Reasoning chain validator: does the Architect's conclusion follow from cited facts?
  - Kill chain stage claimed vs. evidence actually present for that stage
  - Contradiction detection: facts say `exploited: false` but confidence is 0.95
- Cross-agent coherence check: if Architect and Skeptic converge suspiciously on the same injected reasoning, flag it
- All detectors are deterministic Python — no LLM calls in the detection path

**Architecture:**
- New `DivergenceDetector` class, peer to `OracleFirewall`
- Integrates into `guarded_cycle.py` as a second validation pass
- Produces `DivergenceVerdict` frozen dataclass
- Firewall catches structural attacks (Layer 1). Divergence detector catches semantic attacks (Layer 2).

**Success criteria:** Framing detection rate moves from 0% to measurable. Even 20% is a publishable result.

---

### Stage 4 — The Arena (Sessions 064–070)

**Goal:** Open the platform. Researchers submit injection payloads, ARES evaluates them, the visualization shows the result, the OracleJudge keeps score.

**Deliverables:**
- Submission API: accepts injection payloads in a defined schema
  - Payload: the injected content
  - Target: which evidence field to inject into
  - Base scenario: which clean scenario to corrupt
  - Attacker's predicted outcome: what they think will happen
- Sandboxed execution: submissions run in isolated environments
  - No network access during evaluation
  - Resource limits (time, memory)
  - Payload sanitization (prevent actual malicious code execution)
- Leaderboard:
  - Ranked by injection success rate against the firewall + divergence detector
  - Categories: bypass firewall only, bypass divergence detector, bypass both
  - Difficulty-weighted scoring (harder scenarios = more points)
- Community corpus: successful injections (with submitter credit) get added to the benchmark
- ARES-VISION arena mode: live visualization of submissions being evaluated

**Architecture:**
- Thin API layer (FastAPI or similar) wrapping the benchmark runner
- Submission queue with rate limiting
- Results stored as frozen `ArenaSubmission` dataclasses
- Leaderboard computed from OracleJudge verdicts — no subjective scoring
- All evaluation is deterministic and reproducible

**Success criteria:** External researchers can submit payloads, see results visualized, and appear on a leaderboard. The corpus grows through community contribution.

---

## Publication Arc

| Paper | Target | Status |
|-------|--------|--------|
| Paper 1: "Structured Dialectical Debate Degrades LLM Accuracy" | Accuracy findings (Phases 1–4) | Preprint published |
| Paper 2: "ARES-INJECT-100: A Benchmark for Prompt Injection Resilience in Multi-Agent Systems" | Stage 1 corpus + Stage 3 divergence detector results | Target: after Stage 3 |
| Paper 3: "The Injection Arena: Gamified Red-Teaming of AI Agent Pipelines" | Full platform + community findings | Target: after Stage 4 |

---

## Design Principles

1. **Ground truth is non-negotiable.** The OracleJudge remains deterministic Python. No LLM calls in the scoring path. Ever. If you can't verify a detection deterministically, it's a research question, not a feature.

2. **New files only.** The existing dialectical pipeline is frozen. All injection defense infrastructure is additive — peer modules, not modifications.

3. **Honest data over impressive claims.** If the divergence detector only catches 15% of framing attacks, we publish 15%. The value is in the measurement, not the number.

4. **The visualization is the paper.** A researcher watching an agent get manipulated in real time understands more than any abstract. ARES-VISION is not a demo — it's the primary research output.

5. **Community over competition.** The arena rewards contributions to the corpus, not just successful attacks. Every bypass that gets added makes the benchmark stronger.

---

## Architecture Constraints (Inherited + New)

**Inherited from Phase 5:**
- Frozen dataclasses everywhere
- New files only — never modify existing files unless explicitly stated
- Zero regressions — all existing tests must pass
- OracleJudge is deterministic Python — no LLM calls in the Oracle
- EvidencePacket is the unit of truth — SHA256-verified, immutable

**New for Phase 6:**
- Detection infrastructure (firewall, divergence detector) must be deterministic Python — no LLM calls in the detection path
- All injection scenarios must have deterministic expected outcomes
- Trace data is observational only — never modifies the pipeline it observes
- Arena submissions execute in sandboxed environments with no network access
- Leaderboard scoring is computed from OracleJudge verdicts — no subjective evaluation

---

## Risk Register

| Risk | Impact | Mitigation |
|------|--------|------------|
| Corpus expansion is tedious and slow | Stage 1 takes longer than planned | Template-based generation for mechanical variations; hand-craft only novel attack patterns |
| Framing detection stays at 0% | Stage 3 produces a negative result | A measured 0% with a rigorous benchmark is still publishable — characterize the failure mode |
| Arena attracts abuse (actual malicious payloads) | Security/legal exposure | Sandboxed execution, payload sanitization, no real system access, terms of use |
| Visualization complexity explodes | Stage 2 scope creep | Replay mode first (static traces), live mode later. Ship the simple version. |
| LLM costs for large corpus runs | Budget constraint | Batch evaluation, caching, prioritize deterministic checks before LLM calls |

---

## What This Is Not

- **Not a SaaS.** No subscription model. No monetization layer. Research infrastructure.
- **Not a generic injection defense tool.** ARES studies injection in multi-agent security analysis pipelines. The tight coupling to the domain is the moat, not the limitation.
- **Not a finished product.** This is a living research instrument. Every session adds data. Every negative result is a finding.

---

*Phase 6 plan authored Session 046. Branch: `session-046-injection-resilience-p2`.*
*Last updated: 2026-04-13.*
