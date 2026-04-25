# SESSION 024: Combined Gate Evaluation + Calibration Metrics
## Claude Code Execution Prompt

## Context

Continuing ARES build. Phase 3 (Selective Escalation Architecture), Session 3 of 4.

Session 023 accomplished: MiscalibrationDetector with 4 detection patterns (40 tests), ClaimAuditor with per-claim evidence assessment (28 tests), combined gate analysis script (17 tests). 1,825 tests total, zero regressions.

ARES now has a two-gate selective escalation architecture:
- **EscalationGate** (Session 022): Detects uncertainty — confidence in [0.35, 0.70] band
- **MiscalibrationDetector** (Session 023): Detects overconfidence — 4 rule-based pattern checks
- **ClaimAuditor** (Session 023): Decomposes flagged verdicts into per-claim evidence support

Session 024 goal: This is the measurement and integration session. Three objectives:
1. **Measure** combined gate error capture rate against the full 33-scenario corpus (live benchmark)
2. **Build** calibration metrics (Brier score, Expected Calibration Error) to quantify confidence quality
3. **Build** the selective escalation pipeline — single-turn → gate check → multi-turn debate on flagged cases only — and measure whether it beats pure single-turn accuracy

This session DOES use live LLM calls for the selective escalation benchmark. Budget accordingly.

**Project location:** C:\ares-phase-zero
**Run tests:** python -m pytest ares/ -v
**Git branch:** session/024-calibration-metrics

---

## CRITICAL CONSTRAINTS

1. **DO NOT MODIFY ANY EXISTING FILES.** Every file listed below with "DO NOT MODIFY" must not be touched. All 1,825 existing tests must pass unchanged.
2. **All new dataclasses must be frozen.** `@dataclass(frozen=True)` everywhere.
3. **Type hints on everything. Docstrings on all public methods.**
4. **Test naming convention:** `test_<what>_<condition>_<expected>`
5. **New files only.** Zero modifications to existing code.
6. **Live LLM calls are permitted** in the benchmark runner script only. All unit tests must be deterministic (rule-based only).

---

## FIRST ACTION: Run Combined Gate Benchmark

Before writing ANY code, run the existing combined gate analysis to establish the baseline. This is critical — we need to know what the two-gate system catches before building on top of it.

```powershell
# Step 1: Run the full benchmark to get results
python -m ares.dialectic.scripts.run_full_benchmark

# Step 2: If run_combined_gate_analysis has a CLI entry point, run it
# Otherwise, run a quick Python snippet:
python -c "
from ares.dialectic.scripts.miscalibration_analysis import run_combined_gate_analysis, format_combined_report
from ares.dialectic.scripts.run_full_benchmark import <whatever function returns results>
# Adapt as needed based on actual function signatures
"
```

**Capture the output.** Report: how many of the 7 known errors does each gate catch? How many does the combination catch? What's the combined error capture rate?

If the existing analysis script doesn't have a direct CLI runner, note this — we'll build one in this session.

---

## Existing File Tree (ALL marked DO NOT MODIFY)

```
ares/
├── graph/schema.py                                  # Session 001 — DO NOT MODIFY
└── dialectic/
    ├── evidence/
    │   ├── provenance.py                            # DO NOT MODIFY
    │   ├── fact.py                                  # DO NOT MODIFY
    │   ├── packet.py                                # DO NOT MODIFY
    │   └── extractors/
    │       ├── protocol.py                          # DO NOT MODIFY
    │       ├── windows.py                           # DO NOT MODIFY
    │       ├── syslog.py                            # DO NOT MODIFY
    │       └── netflow.py                           # DO NOT MODIFY
    ├── messages/
    │   ├── assertions.py                            # DO NOT MODIFY
    │   └── protocol.py                              # DO NOT MODIFY
    ├── coordinator/
    │   ├── validator.py                             # DO NOT MODIFY
    │   ├── cycle.py                                 # DO NOT MODIFY
    │   ├── coordinator.py                           # DO NOT MODIFY
    │   ├── orchestrator.py                          # DO NOT MODIFY
    │   ├── escalation.py                            # Session 022 — DO NOT MODIFY
    │   ├── miscalibration.py                        # Session 023 — DO NOT MODIFY
    │   └── claim_audit.py                           # Session 023 — DO NOT MODIFY
    ├── agents/
    │   ├── context.py                               # DO NOT MODIFY
    │   ├── base.py                                  # DO NOT MODIFY
    │   ├── patterns.py                              # DO NOT MODIFY
    │   ├── architect.py                             # DO NOT MODIFY
    │   ├── skeptic.py                               # DO NOT MODIFY
    │   ├── oracle.py                                # DO NOT MODIFY
    │   └── strategies/                              # ALL files DO NOT MODIFY
    ├── memory/                                      # ALL files DO NOT MODIFY
    └── scripts/
        ├── scenarios.py                             # DO NOT MODIFY
        ├── expanded_scenarios.py                    # Session 021 — DO NOT MODIFY
        ├── benchmark_analysis.py                    # Session 021 — DO NOT MODIFY
        ├── run_anchored_benchmark.py                # DO NOT MODIFY
        ├── run_full_benchmark.py                    # Session 022 — DO NOT MODIFY
        ├── escalation_analysis.py                   # Session 022 — DO NOT MODIFY
        └── miscalibration_analysis.py               # Session 023 — DO NOT MODIFY
```

---

## Files to Create

### File 1: `ares/dialectic/coordinator/calibration.py`

Calibration metrics for quantifying confidence quality.

**Required types (all frozen dataclasses):**

**CalibrationResult** — Frozen dataclass with fields:
- `brier_score` (float) — Mean squared error between confidence and binary correctness. Range [0, 1]. Lower is better. 0.0 = perfect calibration.
- `expected_calibration_error` (float) — Weighted average of |accuracy - confidence| across bins. Range [0, 1]. Lower is better.
- `bin_count` (int) — Number of bins used for ECE calculation.
- `bin_details` (tuple of BinDetail) — Per-bin breakdown.
- `overconfidence_ratio` (float) — Proportion of predictions where confidence > accuracy-in-bin. Measures systematic overconfidence.
- `underconfidence_ratio` (float) — Proportion where confidence < accuracy-in-bin.
- `n_samples` (int) — Total predictions evaluated.

**BinDetail** — Frozen dataclass with fields:
- `bin_lower` (float)
- `bin_upper` (float)
- `count` (int) — Number of predictions in this bin
- `avg_confidence` (float) — Mean confidence of predictions in bin
- `accuracy` (float) — Fraction correct in bin
- `calibration_gap` (float) — |accuracy - avg_confidence|

**CalibrationEvaluator** — Class that computes calibration metrics.

Constructor accepts:
- `n_bins` (int, default 10) — Number of equal-width bins for ECE

Methods:
```python
def evaluate(
    self,
    predictions: Sequence[tuple[float, bool]]  # (confidence, was_correct) pairs
) -> CalibrationResult
```

**Brier score calculation:** `sum((confidence - correct)^2) / n` where correct is 1.0 if verdict matched expected, 0.0 otherwise.

**ECE calculation:** Divide [0, 1] into `n_bins` equal-width bins. For each bin: compute average confidence and accuracy (fraction correct). ECE = weighted average of |accuracy - avg_confidence| where weight = bin_count / total_count. Skip empty bins.

**Overconfidence/underconfidence ratio:** Count bins where avg_confidence > accuracy (overconfident) vs avg_confidence < accuracy (underconfident). Weight by bin count.

---

### File 2: `ares/dialectic/scripts/selective_escalation.py`

The selective escalation pipeline — the core deliverable of Phase 3.

**Pipeline logic:**

```
For each scenario in corpus:
    1. Run single-turn verdict
    2. Run EscalationGate on single-turn result
    3. Run MiscalibrationDetector on single-turn result
    4. If EITHER gate flags the scenario:
         → Run multi-turn debate on this scenario
         → Use multi-turn verdict as final answer
    5. Else:
         → Accept single-turn verdict as final answer
    6. Record: scenario_id, single_turn_verdict, gate_decisions, final_verdict, expected, correct, cost
```

**Required types (all frozen dataclasses):**

**SelectiveResult** — Frozen dataclass with fields:
- `scenario_id` (str)
- `scenario_name` (str)
- `expected_verdict` (VerdictOutcome)
- `single_turn_verdict` (VerdictOutcome)
- `single_turn_confidence` (float)
- `escalated` (bool)
- `escalation_reason` (str — "uncertainty", "miscalibration", "both", or "none")
- `final_verdict` (VerdictOutcome)
- `final_correct` (bool)
- `cost` (float)

**SelectiveSummary** — Frozen dataclass with fields:
- `total_scenarios` (int)
- `escalated_count` (int)
- `escalation_rate` (float)
- `single_turn_accuracy` (float) — Baseline: what single-turn alone would have gotten
- `selective_accuracy` (float) — What selective escalation actually got
- `accuracy_delta` (float) — selective - single_turn (positive = improvement)
- `total_cost` (float)
- `single_turn_cost` (float) — What single-turn alone would have cost
- `cost_ratio` (float) — selective_cost / single_turn_cost
- `results` (tuple[SelectiveResult, ...])

**Functions:**

`run_selective_escalation(scenarios, escalation_gate, miscalibration_detector)` — Runs the full pipeline. Uses existing `run_cycle_with_strategies()` or `run_multi_turn_with_strategies()` from `live_cycle.py` for LLM calls. Returns SelectiveSummary.

`format_selective_report(summary)` — Formatted string report showing per-scenario decisions, accuracy comparison, cost comparison, and the key question: did selective escalation beat pure single-turn?

**IMPORTANT:** This script makes live LLM calls. It should:
- Use the existing AnthropicClient and LLM strategies
- Track cost via LLMCallLogger
- Handle API errors gracefully (retry logic already exists in AnthropicClient)
- Print progress as it runs (this will take time)

---

### File 3: `ares/dialectic/scripts/run_selective_benchmark.py`

CLI runner for the selective escalation pipeline.

```powershell
python -m ares.dialectic.scripts.run_selective_benchmark
```

Should:
1. Load full 33-scenario corpus
2. Configure EscalationGate with [0.35, 0.70] thresholds
3. Configure MiscalibrationDetector with defaults
4. Run selective escalation pipeline
5. Compute calibration metrics on results
6. Print comprehensive report: accuracy comparison, cost comparison, per-scenario breakdown, calibration metrics, gate performance

---

### File 4: `ares/dialectic/tests/coordinator/test_calibration.py`

Comprehensive tests for CalibrationEvaluator. **Target: 30+ tests.**

Test categories:
- Perfect calibration (Brier = 0, ECE = 0)
- Perfect miscalibration (always confident, always wrong)
- Known Brier score calculations (hand-computed)
- ECE with different bin counts
- Overconfidence vs underconfidence detection
- Edge cases: single prediction, all same confidence, empty bins
- Bin boundary behavior
- Immutability of all output types
- BinDetail correctness

---

### File 5: `ares/dialectic/tests/scripts/test_selective_escalation.py`

Tests for the selective escalation pipeline logic. **Target: 20+ tests.** All tests are deterministic — mock the LLM calls.

Test categories:
- Pipeline routing: scenarios that should escalate vs pass through
- SelectiveResult construction and immutability
- SelectiveSummary computation (accuracy, cost, delta)
- Escalation reason classification (uncertainty, miscalibration, both)
- Cost tracking accuracy
- Edge cases: zero escalations, all escalated
- format_selective_report output structure

---

## Execution Order

1. **FIRST: Run existing combined gate benchmark.** Capture and report the combined error capture rate before writing any code.
2. **Read existing files:** `escalation.py`, `miscalibration.py`, `claim_audit.py`, `patterns.py`, `live_cycle.py`, `run_full_benchmark.py`, `miscalibration_analysis.py`.
3. **Create** `calibration.py` with CalibrationEvaluator.
4. **Create** `test_calibration.py`. Run tests. Fix until all pass.
5. **Create** `selective_escalation.py` with pipeline logic.
6. **Create** `test_selective_escalation.py`. Run tests (deterministic/mocked). Fix until all pass.
7. **Create** `run_selective_benchmark.py` CLI runner.
8. **Run full test suite:** `python -m pytest ares/ -v`. Confirm zero regressions.
9. **Run the selective benchmark:** `python -m ares.dialectic.scripts.run_selective_benchmark`. This is the live LLM run. Capture full output.
10. **Report:** Combined gate capture rate, selective escalation accuracy vs single-turn baseline, cost comparison, calibration metrics, total new tests, cumulative test count.

---

## Key Interfaces to Use (Do Not Reinvent)

- **From `escalation.py`:** `EscalationGate.evaluate()` returns `EscalationResult` with `decision` (RESOLVED or ESCALATE).
- **From `miscalibration.py`:** `MiscalibrationDetector.detect()` returns `MiscalibrationResult` with `recommendation` (PASS or INSPECT).
- **From `claim_audit.py`:** `ClaimAuditor.audit()` returns `ClaimAuditResult` with `audit_verdict` (CONFIRMED or MISCALIBRATED).
- **From `live_cycle.py`:** `run_cycle_with_strategies()` for single-turn, `run_multi_turn_with_strategies()` for multi-turn. These handle LLM calls.
- **From `patterns.py`:** `Verdict`, `VerdictOutcome` for verdict types.
- **From `scenarios.py` + `expanded_scenarios.py`:** Scenario definitions with `expected_verdict`.
- **From `benchmark_analysis.py`:** `get_full_corpus()` returns all 33 scenarios.
- **From `strategies/observability.py`:** `LLMCallLogger` for cost tracking.

**IMPORTANT:** Read these files before writing any code. The exact function signatures, return types, and field names matter. The selective escalation script must compose existing components — do not reimplement LLM call logic, benchmark running, or gate evaluation.

---

## What Success Looks Like

When you're done:
1. `python -m pytest ares/ -v` shows **1,875+ tests passing with 0 failures**
2. The selective escalation benchmark has run against all 33 scenarios
3. You can answer: **Does selective escalation beat pure single-turn accuracy?**
4. You can answer: **What does it cost relative to pure single-turn?**
5. Calibration metrics (Brier score, ECE) quantify confidence quality across modes

The selective escalation accuracy number is the Phase 3 verdict. If selective > single-turn, the two-gate architecture works. If not, we have precise data on why.

---

**End of Session 024 execution prompt.**
