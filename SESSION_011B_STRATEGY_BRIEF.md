# SESSION 011B: Strategy Brief — Live LLM Benchmark & Prompt Optimization

**Purpose:** Strategy document for Dan and Claude (strategy window) to design the Session 011b Claude Code prompt. This is NOT the prompt itself — it's the context, options, and architectural considerations needed to build one.

**Date:** February 14, 2026
**Phase:** Phase 2 — Prompt Optimization & Scenario Corpus (Part 2 of 2)

---

## Where We Are

### System State After Session 011a
- **1,164 tests passing** across 11 sessions, zero failures, zero regressions
- **12 benchmark scenarios** in `scenario_corpus.py` — Tier 1-4, covering privilege escalation, process chains, credential dumping, LOLBins, lateral movement, data staging, insider threat, false positives, red team exercises, multi-vector campaigns, slow exfiltration, and supply chain compromise
- **Benchmark runner** (`run_benchmark()`) executes scenarios through rule-based or LLM strategy paths and collects metrics: verdict, confidence, fact coverage, assertion counts, timing, token usage, cost
- **Benchmark report** (`generate_report()`) produces ASCII analysis with delta comparison support
- **All 12 scenarios pass through rule-based cycle** — this is the baseline
- **One live LLM data point** from Session 010: privilege escalation scenario, zero validation errors, Architect confidence 0.49→0.90, Skeptic 0.30→0.80, cost $0.03

### Complete File Tree (Session 011a)
```
ares/
├── graph/schema.py                          # Session 001 (110 tests)
└── dialectic/
    ├── evidence/
    │   ├── provenance.py                    # Provenance, SourceType
    │   ├── fact.py                          # Fact, EntityType
    │   ├── packet.py                        # EvidencePacket
    │   └── extractors/
    │       ├── protocol.py                  # ExtractionResult, ExtractorProtocol
    │       └── windows.py                   # WindowsEventExtractor
    ├── messages/
    │   ├── assertions.py                    # Assertion, AssertionType
    │   └── protocol.py                      # DialecticalMessage, Phase, MessageBuilder
    ├── coordinator/
    │   ├── validator.py                     # MessageValidator
    │   ├── cycle.py                         # CycleState, TerminationReason
    │   ├── coordinator.py                   # Coordinator
    │   └── orchestrator.py                  # DialecticalOrchestrator, CycleResult
    ├── agents/
    │   ├── context.py                       # TurnContext, DataRequest
    │   ├── base.py                          # AgentBase
    │   ├── patterns.py                      # AnomalyPattern, BenignExplanation, Verdict, VerdictOutcome
    │   ├── architect.py                     # ArchitectAgent
    │   ├── skeptic.py                       # SkepticAgent
    │   ├── oracle.py                        # OracleJudge, OracleNarrator
    │   └── strategies/
    │       ├── __init__.py                  # Public exports
    │       ├── protocol.py                  # ThreatAnalyzer, ExplanationFinder, NarrativeGenerator
    │       ├── rule_based.py                # Rule-based strategies
    │       ├── llm_strategy.py              # LLM strategies
    │       ├── client.py                    # AnthropicClient with retry
    │       ├── prompts.py                   # System prompt templates ← MODIFY TARGET
    │       ├── observability.py             # LLMCallRecord, LLMCallLogger
    │       └── live_cycle.py                # run_cycle_with_strategies()
    ├── memory/
    │   ├── errors.py
    │   ├── entry.py                         # MemoryEntry
    │   ├── protocol.py                      # MemoryBackend protocol
    │   ├── chain.py                         # HashChain
    │   ├── stream.py                        # MemoryStream
    │   └── backends/
    │       └── in_memory.py                 # InMemoryBackend
    ├── multi_turn/
    │   └── cycle.py                         # run_multi_turn_cycle()
    └── scripts/
        ├── __init__.py
        ├── run_live_cycle.py                # CLI diagnostic runner
        ├── sample_packets.py                # 3 original scenarios
        ├── scenario_corpus.py               # 12 benchmark scenarios (NEW in 011a)
        ├── benchmark_runner.py              # run_benchmark() (NEW in 011a)
        └── benchmark_report.py              # generate_report() (NEW in 011a)
```

---

## Session 011b Goal

Run the full 12-scenario benchmark against the live LLM, compare against the rule-based baseline, identify prompt weaknesses from the data, iterate on `prompts.py`, and validate improvements — all within a single session.

### What This Session Produces

1. **`run_llm_benchmark.py`** — Script that executes the full benchmark with live LLM, saves results, and generates the comparison report
2. **Revised `prompts.py`** — Improved system prompt templates based on benchmark findings
3. **`benchmark_results/`** — Directory with saved benchmark outputs (rule-based baseline, LLM run v1, LLM run v2 post-optimization)
4. **Tests** — For the benchmark script and any prompt validation logic
5. **`SESSION_011B_BENCHMARK_ANALYSIS.md`** — Written analysis of findings

### What This Session Does NOT Do
- No structural changes to existing agent, coordinator, or orchestration code
- No new dataclass types in the core engine
- No modifications to benchmark_runner.py or scenario_corpus.py
- No changes to the OracleJudge (remains deterministic)

---

## The Nature of This Session

This session is **fundamentally different** from all previous sessions. Every prior session was deterministic — write code, run tests, verify behavior. Session 011b is **empirical and iterative**:

1. Run → observe → analyze → modify prompts → re-run → compare
2. The LLM's behavior is non-deterministic — same scenario may produce different results
3. Cost is real ($0.03 per scenario × 12 = ~$0.36 per full run, but could be more with larger packets)
4. Latency is real (~5-17 seconds per scenario)

This means the CC prompt must give Claude Code clear **decision-making authority** on when to iterate vs when to accept results. It can't be purely mechanical.

---

## Key Architectural Decisions

### Decision 1: What Can CC Modify?

**Option A: Only `prompts.py`**
- Safest. The prompt templates are the only tuning knob.
- System prompt changes affect all three strategies (Architect, Skeptic, Narrator).
- No risk of breaking existing tests.
- Limitation: If the issue is in JSON parsing or validation logic in `llm_strategy.py`, prompts alone can't fix it.

**Option B: `prompts.py` + `llm_strategy.py`**
- More flexibility. Can adjust validation tolerance, parsing logic, confidence calibration.
- Higher risk — `llm_strategy.py` has existing tests from Session 009.
- Any changes must be backward-compatible.

**Option C: `prompts.py` only for this session, flag `llm_strategy.py` issues for 011c**
- Best of both worlds. Tune what's safe, document what needs structural changes.

**Recommendation: Option C.** Prompts are the intended tuning surface. If CC discovers validation or parsing issues during the benchmark, it should document them clearly but not attempt structural fixes in the same session that's doing empirical prompt tuning. Mixing code refactoring and empirical optimization in one session is asking for trouble.

### Decision 2: How Many Iterations?

Running the full 12-scenario benchmark costs ~$0.36 and takes ~2-3 minutes. That's affordable for 3-4 full runs. But we need to be disciplined:

**Proposed Protocol:**
1. **Run 0: Rule-based baseline** (free, instant) — capture via `run_benchmark(strategy_type="rule_based")`
2. **Run 1: LLM v1** (current prompts) — first live data across all 12 scenarios
3. **Analysis:** Identify prompt weaknesses from Run 1 vs Run 0 delta
4. **Prompt revision:** CC modifies `prompts.py` based on findings
5. **Run 2: LLM v2** (revised prompts) — validate improvements
6. **Final analysis:** Run 2 vs Run 1 delta (improvement), Run 2 vs Run 0 delta (total LLM improvement over rule-based)

**Budget cap: 4 full LLM runs max** (~$1.50). If prompts aren't converging after 4 runs, stop and document the remaining issues for a future session.

### Decision 3: What Metrics Drive Prompt Changes?

Not all metrics are equally important. Priority order:

1. **Validation errors and fallbacks** — These are schema violations. If the LLM is producing invalid fact_ids or malformed JSON, that's a prompt clarity issue. Fix first.
2. **Verdict accuracy vs expected** — Does the LLM reach the right conclusion? Tier 1 scenarios should be near-100% correct. Tier 2-3 have more latitude.
3. **Fact coverage ratio** — Are agents citing evidence or hallucinating arguments? Low coverage (< 30%) suggests the prompt isn't directing attention to the evidence packet.
4. **Architect/Skeptic balance** — Is one agent consistently dominating? On BALANCED scenarios (SC-005, SC-006, SC-007, SC-011, SC-012), both agents should have comparable confidence.
5. **Confidence calibration** — Are confidence scores meaningful? 0.90 on an ambiguous scenario is worse than 0.60.

### Decision 4: The Benchmark Script Design

The script needs to be both **automated** (for CC to run programmatically) and **inspectable** (for Dan to review results). Two approaches:

**Option A: Single monolithic script**
- `run_llm_benchmark.py` does everything: baseline, LLM run, analysis, prompt modification, re-run
- Simpler for CC to execute
- Harder to debug if something goes wrong mid-run

**Option B: Composable scripts**
- `run_llm_benchmark.py` — Runs benchmark and saves results to JSON/text files
- Analysis and prompt iteration happens in CC's reasoning, not automated in script
- More flexible, easier to re-run specific parts

**Recommendation: Option B.** The script handles execution and output. CC handles analysis and prompt editing as separate cognitive steps. This matches how empirical science works — you don't automate the hypothesis revision.

### Decision 5: Result Persistence

Benchmark results should be saveable for comparison across sessions. But we don't want to add heavyweight serialization infrastructure.

**Simple approach:** Save `BenchmarkRun` as JSON (custom serializer for frozen dataclasses) to `ares/dialectic/scripts/benchmark_results/`. Each file gets a descriptive name: `rule_based_baseline_011b.json`, `llm_v1_011b.json`, `llm_v2_011b.json`.

Also save the text report alongside: `rule_based_baseline_011b_report.txt`, etc.

---

## Prompt Optimization Strategy

### What We Know From Session 010

The single live run (privilege escalation) showed:
- LLM Architect understood *relationships* between facts — confidence jumped from 0.49 to 0.90
- LLM Skeptic produced *narrative counterarguments*, not just pattern inversions — confidence 0.30 to 0.80
- Narrator cited specific fact_ids and explained the genuine ambiguity
- Zero validation errors — closed-world constraint held
- Three API calls total (~$0.03)

### What We Don't Know (011b Will Reveal)

- **How do the prompts handle diverse attack types?** Session 010 only tested privilege escalation.
- **How does the Skeptic perform on Tier 3 (false positive) scenarios?** SC-008 and SC-009 require the Skeptic to correctly defend benign activity. If the Architect prompt is too aggressive, it may overwhelm legitimate skepticism.
- **How does sparse evidence affect reasoning?** SC-011 has only 3-4 facts. Will the LLM over-interpret or express appropriate uncertainty?
- **How does high evidence density affect token usage?** SC-010 has 15-18 facts. Token/cost scaling matters.
- **Are confidence values calibrated?** On ambiguous scenarios (SC-005, SC-006, SC-007, SC-012), do agents produce moderate confidence, or do they always swing to extremes?

### Likely Prompt Issues to Watch For

Based on common LLM prompting patterns and the current template design:

1. **Architect over-aggression** — The Architect prompt may be biased toward finding threats even in benign scenarios. Watch SC-008, SC-009.
2. **Skeptic under-performance** — The Skeptic prompt may not be assertive enough to counter a strong Architect narrative. Watch BALANCED scenarios.
3. **Confidence inflation** — Both agents may default to high confidence regardless of evidence quality. Watch SC-011 (sparse evidence).
4. **Fact citation gaps** — The prompts may not strongly enough emphasize that ALL reasoning must be grounded in specific fact_ids from the packet. Watch fact coverage ratios.
5. **JSON formatting issues** — The prompts may need more explicit JSON output format instructions to reduce parse failures.

### Prompt Revision Principles

When modifying `prompts.py`, CC should follow these principles:

1. **One change at a time where possible.** If changing both Architect and Skeptic prompts, it's harder to attribute improvement.
2. **Strengthen the closed-world constraint.** Every assertion must cite fact_ids. This is the core architectural invariant.
3. **Add calibration guidance.** "Express confidence proportional to the strength and quantity of evidence."
4. **Role clarity.** The Architect's job is to find threats. The Skeptic's job is to find alternative explanations. Neither should hedge — that's the Oracle's job.
5. **Don't over-specify.** Overly detailed prompts cause the LLM to lose the forest for the trees. Keep prompts focused on *principles* not *procedures*.

---

## Test Plan

### New Tests

Session 011b has minimal new deterministic tests since most of the work is empirical:

```
ares/dialectic/scripts/
├── run_llm_benchmark.py         # NEW: benchmark execution script
└── benchmark_results/           # NEW: directory for saved results
    └── .gitkeep

ares/dialectic/tests/scripts/
└── test_run_llm_benchmark.py    # NEW: ~10 tests for script logic
```

**Test focus:**
- Script correctly invokes `run_benchmark()` with proper parameters
- Results are saved to files in expected format
- Report generation works with saved results
- Script handles missing API key gracefully
- Script handles individual scenario failures without crashing the full run

**Note:** The actual LLM benchmark runs are NOT automated tests. They're executed manually via the script and analyzed by CC. The deterministic tests validate the script's plumbing, not the LLM's reasoning.

### Existing Test Integrity

All 1,164 existing tests must continue to pass. The only file being modified is `prompts.py`, which has no direct tests — it's tested indirectly through `test_llm_strategy.py` (which uses mocked responses, not real prompts). Changing prompt text should not affect any existing tests.

**Risk check:** If CC changes the prompt structure (not just content) — for example, changing the expected JSON output schema — that WOULD break `llm_strategy.py` parsing. This is why Decision 1 recommends Option C: prompts-only changes, flag structural issues separately.

---

## Execution Flow for Claude Code

### Phase 1: Setup & Baseline (deterministic, no API calls)

1. **Read** existing files: `prompts.py`, `llm_strategy.py`, `benchmark_runner.py`, `scenario_corpus.py`, `benchmark_report.py`, `live_cycle.py`, `observability.py`
2. **Create** `run_llm_benchmark.py` — script that:
   - Accepts CLI args: `--strategy rule_based|llm`, `--output-dir`, `--run-name`
   - Runs `run_benchmark()` with specified strategy
   - Saves `BenchmarkRun` results to JSON
   - Generates and saves text report via `generate_report()`
   - Prints summary to console
3. **Create** `benchmark_results/` directory with `.gitkeep`
4. **Write tests** for the script logic
5. **Run** rule-based baseline: `python -m ares.dialectic.scripts.run_llm_benchmark --strategy rule_based --run-name baseline`
6. **Verify** all 1,164+ existing tests still pass

### Phase 2: First LLM Run (requires API key)

7. **Run** full LLM benchmark: `python -m ares.dialectic.scripts.run_llm_benchmark --strategy llm --run-name llm_v1`
8. **Generate** delta report: rule-based baseline vs LLM v1
9. **Analyze** results — identify:
   - Which scenarios had validation errors or fallbacks?
   - Which scenarios got the wrong verdict?
   - Where is fact coverage low?
   - Where is the Architect/Skeptic balance off?
   - Where are confidence values miscalibrated?

### Phase 3: Prompt Optimization (iterative)

10. **Modify** `prompts.py` based on analysis findings
11. **Run** LLM benchmark again: `--run-name llm_v2`
12. **Generate** delta report: LLM v1 vs LLM v2
13. **Assess:** Did the changes improve the target metrics? Did they cause regressions?
14. **If needed:** One more iteration (LLM v3), budget permitting
15. **Verify** all existing tests still pass after prompt changes

### Phase 4: Documentation & Cleanup

16. **Generate** final comprehensive report: rule-based vs best LLM run
17. **Write** `SESSION_011B_BENCHMARK_ANALYSIS.md` — findings, prompt changes, recommendations
18. **Run** full test suite: `pytest ares/ -v`

---

## Cost & Time Budget

| Run | Estimated Cost | Estimated Time | Purpose |
|-----|---------------|---------------|---------|
| Baseline (rule-based) | $0.00 | ~2 seconds | Reference point |
| LLM v1 (current prompts) | ~$0.36 | ~2-3 minutes | First full benchmark |
| LLM v2 (revised prompts) | ~$0.36 | ~2-3 minutes | Validate improvements |
| LLM v3 (if needed) | ~$0.36 | ~2-3 minutes | Second iteration |
| **Total budget** | **~$1.50 max** | **~10-15 minutes API time** | |

Plus CC execution time for analysis, code, and testing.

---

## What Success Looks Like

### Minimum Bar (session is a success if):
- [ ] Full 12-scenario benchmark completes against live LLM without crashes
- [ ] Zero validation errors across all 12 scenarios (closed-world constraint holds)
- [ ] Zero fallbacks to rule-based (LLM produces valid output for all three strategies on all scenarios)
- [ ] Benchmark results saved and delta reports generated
- [ ] `prompts.py` revised with at least one documented improvement
- [ ] All existing tests pass
- [ ] Written analysis of findings

### Stretch Goals (great session if also):
- [ ] LLM matches or exceeds rule-based verdict accuracy on Tier 1 scenarios
- [ ] LLM outperforms rule-based on at least 2 Tier 2 scenarios
- [ ] Tier 3 scenarios correctly dismissed (Skeptic wins on SC-008, SC-009)
- [ ] Average fact coverage > 50% across all scenarios
- [ ] Confidence values show calibration (higher on clear scenarios, moderate on ambiguous)
- [ ] Identified specific prompt improvements with measurable before/after data

---

## Risk Mitigation

| Risk | Mitigation |
|------|-----------|
| API rate limiting | AnthropicClient already has retry with exponential backoff |
| Scenario failure crashes entire run | Script should catch per-scenario errors and continue |
| Prompt changes break JSON parsing | Test with one scenario before full run; keep backup of original prompts.py |
| LLM produces radically different output across runs | Run twice if results seem anomalous; note variance |
| Budget overrun | Hard cap at 4 full runs; abort if issues are structural rather than prompt-level |
| Context rot in CC instance | Self-contained prompt with full file tree; empirical phase has natural breakpoints |

---

## Architecture Relationship

```
                     ┌─────────────────────────┐
                     │   scenario_corpus.py     │
                     │   12 BenchmarkScenarios  │
                     │   (from 011a — FROZEN)   │
                     └────────────┬────────────┘
                                  │
                                  ▼
                     ┌─────────────────────────┐
                     │  benchmark_runner.py     │
                     │  run_benchmark()         │
                     │  (from 011a — FROZEN)    │
                     └────────────┬────────────┘
                                  │
                     ┌────────────┼────────────┐
                     │            │            │
                     ▼            ▼            ▼
              ┌──────────┐ ┌──────────┐ ┌──────────┐
              │ Rule-    │ │ LLM      │ │ LLM      │
              │ Based    │ │ Strategy │ │ Strategy  │
              │ Strategy │ │ v1       │ │ v2        │
              │ (frozen) │ │ (current │ │ (revised  │
              │          │ │ prompts) │ │ prompts)  │
              └──────────┘ └──────────┘ └──────────┘
                     │            │            │
                     ▼            ▼            ▼
                     ┌─────────────────────────┐
                     │  benchmark_report.py     │
                     │  generate_report()       │
                     │  (from 011a — FROZEN)    │
                     │                         │
                     │  Delta: baseline vs v1   │
                     │  Delta: v1 vs v2         │
                     │  Delta: baseline vs v2   │
                     └─────────────────────────┘
                                  │
                                  ▼
                     ┌─────────────────────────┐
                     │  run_llm_benchmark.py    │
                     │  (NEW — orchestrates     │
                     │   execution & saves      │
                     │   results to disk)       │
                     └─────────────────────────┘
```

The benchmark infrastructure from 011a is a **consumer** that CC does not modify. The only production code that changes is `prompts.py`. Everything else is new scripts and analysis.

---

## File Modification Summary

| File | Action | Notes |
|------|--------|-------|
| `prompts.py` | MODIFY | System prompt templates — the tuning target |
| `run_llm_benchmark.py` | CREATE | Benchmark execution script |
| `test_run_llm_benchmark.py` | CREATE | Tests for script logic |
| `benchmark_results/` | CREATE | Output directory for saved runs |
| `SESSION_011B_BENCHMARK_ANALYSIS.md` | CREATE | Written analysis document |
| Everything else | DO NOT MODIFY | |

---

## Session History Reference

| Session | Component | Tests | Cumulative | Key Insight |
|---------|-----------|-------|------------|-------------|
| 001 | Graph Schema | 110 | 110 | Node/edge types for security data |
| 002 | Dialectical Foundation | 292 | 402 | "Hallucinations = schema violations" |
| 003 | Agent Foundation | 144 | 546 | Packet binding, phase enforcement, evidence tracking |
| 004 | Concrete Agents | 134 | 570 | Rule-based Architect/Skeptic/Oracle, end-to-end cycle |
| 005 | Evidence Extractors | 130 | 700 | "Sensors don't get opinions" |
| 006 | Coordinator Orchestration | 58 | 758 | Facade pattern, single-call entry point |
| 007 | Memory Stream | 103 | 861 | Tamper-evident hash-chained audit trail |
| 008 | Multi-Turn Cycles | 65 | 926 | Iterative refinement before verdict |
| 009 | LLM Infrastructure | 114 | 1040 | Strategy Pattern — extract then inject |
| 010 | Live LLM Harness | 64 | 1104 | Zero validation errors on first live run |
| 011a | Scenario Corpus + Benchmark | 60 | 1164 | Measure before you tune |
| **011b** | **Live LLM Benchmark + Prompt Optimization** | **~10** | **~1174** | **Data-driven prompt engineering** |

---

## Commands

```powershell
# Activate venv
.\venv\Scripts\Activate.ps1

# Run all tests
pytest ares/ -v

# Run just 011b tests
pytest ares/dialectic/tests/scripts/test_run_llm_benchmark.py -v

# Run rule-based baseline
python -m ares.dialectic.scripts.run_llm_benchmark --strategy rule_based --run-name baseline

# Run LLM benchmark (requires ANTHROPIC_API_KEY)
python -m ares.dialectic.scripts.run_llm_benchmark --strategy llm --run-name llm_v1

# Run with coverage
pytest ares/ --cov=ares --cov-report=term-missing
```

---

*"Twelve scenarios. Three prompts. One question: does the immune system reason well enough to earn its name?"*
