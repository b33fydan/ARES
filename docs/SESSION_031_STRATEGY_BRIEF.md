# SESSION 031: Strategy Brief — Benchmark Regeneration & Misclassification Diagnosis

**Purpose:** Strategy document for Dan and Claude (strategy window) to design the Session 031 Claude Code prompt. This is NOT the prompt itself — it's the context, options, and architectural considerations needed to build one.

**Date:** March 27, 2026
**Phase:** Phase 4 — Accuracy Improvement (Evidence Extraction + Prompt Engineering)

---

## Where We Are

### System State After Session 030
- **2,001 tests** (1,927 + 74 new, 65 skipped, 0 failures)
- **Visual pipeline corpus-proven:** 33/33 scenarios produce valid event sequences, zero anomalies
- **Benchmark infrastructure intact:** `run_benchmark()`, `generate_report()`, `run_llm_benchmark.py` all operational
- **Last known LLM accuracy:** 81.8% on 33-scenario corpus (Session 022, single-turn)
- **Prompt version:** v2 (from Session 011B — Architect aggression threshold, Skeptic plausibility gating, closed-world reinforcement)
- **API client:** Configured and operational

### What We Know About the 81.8% Ceiling

From the Session 022 full-corpus benchmark (33 scenarios, single-turn LLM v2):
- **27/33 scenarios** classified correctly
- **6 scenarios** misclassified
- The specific 6 misclassified scenario IDs and their failure modes have NOT been analyzed in this strategy window

From the 12-scenario pilot (Sessions 011B/013):
- SC-011 (Slow-Roll Exfiltration) was the persistent miss — Skeptic over-weighted benign cloud usage context
- Other 12-scenario failures were resolved by prompt v2 changes
- The 21 newer scenarios (SC-013 through SC-033) introduced cross-source complexity

### The Accuracy Lever

CC's analysis from the 024 readout was clear: the path from 81.8% to 90%+ runs through evidence extraction quality and how the LLM strategy weighs conflicting signals. This is NOT an architecture problem — the pipeline works. It's a data quality + prompt calibration problem.

The visual layer (Session 030) now serves as a diagnostic tool: for any misclassified scenario, we can see the evidence graph, which facts were ingested, which assertions formed, and where the reasoning diverged from expected.

---

## What Session 031 Must Do

### Phase A: Regenerate Benchmark (Live LLM)

Run the full 33-scenario corpus through single-turn LLM (v2 prompts) and capture complete results:
- Per-scenario verdict, confidence, fact coverage, assertion counts, cost
- Aggregate accuracy, total cost, duration
- Delta comparison against rule-based baseline
- Save raw results to JSON and formatted report to text file

This confirms whether 81.8% holds, improves, or degrades. The Anthropic model version may have changed since Session 022 — the benchmark captures the current state of the art.

### Phase B: Build Misclassification Diagnosis Tool

A new script that takes benchmark results and produces a structured per-scenario failure analysis:

1. **Identify misclassified scenarios** — expected verdict ≠ actual verdict
2. **For each miss, generate visual event sequence** — using ScenarioReplayer from Session 029/030
3. **Analyze evidence distribution** — which facts support threat vs benign, what the agent confidence split was
4. **Classify the failure mode** — categorize why the system got it wrong:
   - `SKEPTIC_OVERWEIGHT` — Skeptic assigned too-high confidence to weak benign evidence
   - `ARCHITECT_UNDERWEIGHT` — Architect missed key threat indicators
   - `EVIDENCE_GAP` — insufficient facts in packet to make correct determination
   - `CONFIDENCE_CALIBRATION` — right direction but wrong magnitude pushed verdict wrong way
   - `AMBIGUITY_MISMATCH` — system was correct-ish but expected verdict was INCONCLUSIVE
5. **Produce diagnosis report** — per-scenario failure narrative with concrete recommendations

### Phase C: Execute and Report

Run both scripts in sequence:
1. `run_full_benchmark.py` → saves results JSON + report text
2. `run_diagnosis.py` → reads results, produces diagnosis report

Dan brings both outputs back to the strategy window for Session 032 prompt engineering.

---

## Architectural Decisions

### Why a Separate Diagnosis Tool?

The benchmark runner produces raw metrics. The diagnosis tool interprets those metrics in context. Keeping them separate means:
- Benchmark can be re-run cheaply without re-running diagnosis
- Diagnosis can be re-run against saved results without API calls
- Different diagnosis strategies can be tested against the same benchmark data

### Why Classify Failure Modes?

Generic "this scenario failed" doesn't guide prompt engineering. Categorized failure modes map directly to prompt fixes:
- `SKEPTIC_OVERWEIGHT` → tighten Skeptic plausibility gating (same fix type as 011B)
- `ARCHITECT_UNDERWEIGHT` → add indicator emphasis to Architect prompt
- `EVIDENCE_GAP` → no prompt fix possible, scenario design issue
- `CONFIDENCE_CALIBRATION` → adjust confidence weighting in Oracle scoring
- `AMBIGUITY_MISMATCH` → may indicate the expected verdict is wrong, not the system

### Why Save Results to Files?

The benchmark costs real money (~$0.12–0.20 per full run based on Session 012 extrapolation). Saving raw results to JSON means we don't re-run the benchmark every time we want to look at the data. The diagnosis tool reads from the saved file, not from a fresh run.

---

## New Files Created This Session

```
ares/dialectic/scripts/
├── run_full_benchmark.py        # NEW: CLI — runs 33-scenario LLM benchmark, saves results
├── misclassification_diagnosis.py  # NEW: Diagnosis engine — failure mode classification
└── run_diagnosis.py             # NEW: CLI — reads benchmark results, produces diagnosis report

ares/dialectic/scripts/benchmark_results/
├── (created at runtime)         # JSON results + text reports from benchmark run
```

**Files Modified: NONE.** All existing 2,001 tests must remain collectible with current pass/skip/fail counts.

---

## Success Criteria

- [ ] All existing tests still pass (zero regressions)
- [ ] Full 33-scenario LLM benchmark completes without crashes
- [ ] Results saved to JSON file (recoverable without re-running)
- [ ] Formatted benchmark report saved to text file
- [ ] Misclassification diagnosis identifies each failed scenario
- [ ] Each failure has a classified failure mode with rationale
- [ ] Diagnosis report includes per-scenario evidence summary and recommendation
- [ ] No modifications to existing files
- [ ] All new dataclasses are frozen

---

## What Comes After (Session 032 Preview)

Session 031 produces the diagnosis. Session 032 acts on it:

- For `SKEPTIC_OVERWEIGHT` failures → targeted Skeptic prompt changes
- For `ARCHITECT_UNDERWEIGHT` failures → targeted Architect prompt changes
- For `CONFIDENCE_CALIBRATION` failures → Oracle scoring adjustments
- Re-run benchmark to measure improvement
- Iterate until accuracy > 85% or failure modes are exhausted

The Session 011B playbook (measure → diagnose → fix → re-measure) proved a 50% → 91.7% improvement in one iteration. Session 031/032 applies the same methodology to the 33-scenario corpus.

---

## Risk Assessment

**API cost:** ~$0.15–0.25 for a full 33-scenario run. Low risk.

**Model version drift:** Claude Sonnet may have updated since Session 022. Results may differ from the 81.8% baseline even without prompt changes. This is information, not a problem — the benchmark captures the current reality.

**Error resilience:** Session 012 added per-scenario error handling. If any scenario throws, the run continues and captures the error. The diagnosis tool should handle `ERROR` verdict outcomes gracefully.

---

## Session History Reference

| Session | What | Tests | Key Insight |
|---------|------|-------|-------------|
| 011A | Scenario corpus + benchmark | 60 | Measurement before optimization |
| 011B | Live LLM benchmark + prompt tuning | 12 | 50% → 91.7% via data-driven fixes |
| 012 | Benchmark runner hardening | 14 | Cost tracking + error resilience |
| 013–014 | Multi-turn thesis test | — | Debate degrades accuracy |
| 021 | 33-scenario expansion | — | 81.8% single-turn ceiling |
| 022–024 | Phase 3 selective escalation | ~145 | Multi-turn thesis formally dead |
| 029 | Visual emitter + nw_wrld | 46 | ARES has eyes |
| 030 | Visual corpus stress test | 74 | 33/33 validated, pipeline proven |
| **031** | **Benchmark regen + diagnosis** | **~0** | **See exactly why 81.8%, fix it** |

---

*You can't fix what you can't see. Session 031 sees everything.*
