# SESSION 011B: Live LLM Benchmark & Prompt Optimization
# Claude Code Execution Prompt

## Context

Continuing ARES build. Phase 1 complete (1,104 tests across 10 sessions). Session 011a added scenario corpus and benchmark infrastructure (60 tests, 1,164 total).

Session 011a accomplished:
- 12 benchmark scenarios (ScenarioMetadata, BenchmarkScenario) across 4 difficulty tiers
- Benchmark runner (run_benchmark()) with ScenarioResult, BenchmarkRun frozen dataclasses
- Benchmark report generator (generate_report()) with delta comparison support
- All 12 scenarios pass through rule-based cycle without errors

Session 011b goal: Run the full 12-scenario benchmark against the live Anthropic LLM, compare against rule-based baseline, identify prompt weaknesses from the data, revise `prompts.py`, validate improvements, and document findings. This session uses LIVE LLM CALLS and requires the ANTHROPIC_API_KEY environment variable.

Project location: C:\ares-phase-zero
Run tests: python -m pytest ares/ -v
Git branch: session/011b-prompt-optimization

---

## CRITICAL CONSTRAINTS

1. **The ONLY existing file you may modify is `ares/dialectic/agents/strategies/prompts.py`.** All other existing files are frozen. All 1,164 existing tests must pass unchanged.
2. **Do NOT modify `llm_strategy.py`, `benchmark_runner.py`, `scenario_corpus.py`, `benchmark_report.py`, or any agent/coordinator/evidence/memory file.** If you discover issues in these files, document them in the analysis but do not fix them.
3. **Budget: 3 full LLM benchmark runs maximum.** Each run costs ~$0.36 and takes ~2-3 minutes. Do not exceed this.
4. **All new dataclasses must be frozen.** `@dataclass(frozen=True)` everywhere.
5. **Type hints on everything. Docstrings on all public methods.**
6. **Test naming convention:** `test_<what>_<condition>_<expected>`
7. **Back up `prompts.py` before modifying it.** Copy to `prompts_v1_original.py` so changes can be compared.

---

## Existing File Tree

```
ares/
├── graph/schema.py                          # Session 001 — DO NOT MODIFY
└── dialectic/
    ├── evidence/
    │   ├── provenance.py                    # DO NOT MODIFY
    │   ├── fact.py                          # DO NOT MODIFY
    │   ├── packet.py                        # DO NOT MODIFY
    │   └── extractors/
    │       ├── protocol.py                  # DO NOT MODIFY
    │       └── windows.py                   # DO NOT MODIFY
    ├── messages/
    │   ├── assertions.py                    # DO NOT MODIFY
    │   └── protocol.py                      # DO NOT MODIFY
    ├── coordinator/
    │   ├── validator.py                     # DO NOT MODIFY
    │   ├── cycle.py                         # DO NOT MODIFY
    │   ├── coordinator.py                   # DO NOT MODIFY
    │   └── orchestrator.py                  # DO NOT MODIFY
    ├── agents/
    │   ├── context.py                       # DO NOT MODIFY
    │   ├── base.py                          # DO NOT MODIFY
    │   ├── patterns.py                      # DO NOT MODIFY
    │   ├── architect.py                     # DO NOT MODIFY
    │   ├── skeptic.py                       # DO NOT MODIFY
    │   ├── oracle.py                        # DO NOT MODIFY
    │   └── strategies/
    │       ├── __init__.py                  # DO NOT MODIFY
    │       ├── protocol.py                  # DO NOT MODIFY
    │       ├── rule_based.py                # DO NOT MODIFY
    │       ├── llm_strategy.py              # DO NOT MODIFY (document issues if found)
    │       ├── client.py                    # DO NOT MODIFY
    │       ├── prompts.py                   # ★ THE ONLY FILE YOU MAY MODIFY ★
    │       ├── observability.py             # DO NOT MODIFY
    │       └── live_cycle.py                # DO NOT MODIFY
    ├── memory/
    │   ├── __init__.py                      # DO NOT MODIFY
    │   ├── errors.py                        # DO NOT MODIFY
    │   ├── entry.py                         # DO NOT MODIFY
    │   ├── protocol.py                      # DO NOT MODIFY
    │   ├── chain.py                         # DO NOT MODIFY
    │   ├── stream.py                        # DO NOT MODIFY
    │   └── backends/
    │       ├── __init__.py                  # DO NOT MODIFY
    │       └── in_memory.py                 # DO NOT MODIFY
    ├── multi_turn/
    │   └── cycle.py                         # DO NOT MODIFY
    └── scripts/
        ├── __init__.py                      # DO NOT MODIFY
        ├── run_live_cycle.py                # DO NOT MODIFY
        ├── sample_packets.py                # DO NOT MODIFY
        ├── scenario_corpus.py               # DO NOT MODIFY
        ├── benchmark_runner.py              # DO NOT MODIFY
        └── benchmark_report.py              # DO NOT MODIFY
```

---

## Step 1 — Review Before Writing

Read these files to understand what you're working with:

1. `ares/dialectic/agents/strategies/prompts.py` — Current system prompt templates. THIS IS YOUR TUNING TARGET. Understand the current Architect, Skeptic, and Narrator prompts completely.
2. `ares/dialectic/agents/strategies/llm_strategy.py` — How prompts are used: `_build_user_prompt()`, `_parse_json_response()`, `_validate_patterns()`. Understand the expected JSON output format.
3. `ares/dialectic/scripts/benchmark_runner.py` — `run_benchmark()` signature, `ScenarioResult` and `BenchmarkRun` types.
4. `ares/dialectic/scripts/scenario_corpus.py` — `get_all_scenarios()`, `ScenarioMetadata`, `BenchmarkScenario`. Understand the 12 scenarios and their expected verdicts.
5. `ares/dialectic/scripts/benchmark_report.py` — `generate_report()` signature and output format.
6. `ares/dialectic/agents/strategies/live_cycle.py` — `run_cycle_with_strategies()` to understand how strategies wire to the cycle.
7. `ares/dialectic/agents/strategies/observability.py` — `LLMCallRecord`, `LLMCallLogger` for inspecting LLM behavior.
8. `ares/dialectic/agents/strategies/client.py` — `AnthropicClient` constructor and retry configuration.
9. `ares/dialectic/agents/patterns.py` — `AnomalyPattern`, `BenignExplanation`, `Verdict`, `VerdictOutcome` types.

**Do NOT write any code until you have read all nine files.** You need to understand the JSON output schemas expected by `llm_strategy.py` before you can write effective prompts.

---

## Step 2 — Create File Structure

```
ares/dialectic/scripts/
├── run_llm_benchmark.py         # NEW: benchmark execution script
├── prompts_v1_original.py       # NEW: backup of original prompts.py (created by copying)
└── benchmark_results/           # NEW: directory for saved results
    └── .gitkeep

ares/dialectic/tests/scripts/
└── test_run_llm_benchmark.py    # NEW: ~10 tests for script logic
```

---

## Step 3 — Back Up Original Prompts

Before ANY modifications to `prompts.py`, copy it:

```python
# Copy prompts.py to prompts_v1_original.py in the same directory
# This preserves the original for comparison
```

This is a safety net. If prompt changes cause issues, the original is always available.

---

## Step 4 — Implement `run_llm_benchmark.py`

A script (runnable via `python -m ares.dialectic.scripts.run_llm_benchmark`) that executes the benchmark and saves results.

### 4.1 CLI Interface

```python
"""
ARES Benchmark Runner Script

Usage:
    python -m ares.dialectic.scripts.run_llm_benchmark --strategy rule_based --run-name baseline
    python -m ares.dialectic.scripts.run_llm_benchmark --strategy llm --run-name llm_v1
    python -m ares.dialectic.scripts.run_llm_benchmark --strategy llm --run-name llm_v2 --baseline baseline

Arguments:
    --strategy    : "rule_based" or "llm"
    --run-name    : Descriptive name for this run (used in filenames)
    --output-dir  : Directory for results (default: ares/dialectic/scripts/benchmark_results/)
    --baseline    : Optional run-name of a previous run to generate delta report against
    --no-narration: Skip narrator output (faster, cheaper)
"""
```

### 4.2 Core Logic

```python
import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

def main():
    parser = argparse.ArgumentParser(description="ARES Benchmark Runner")
    parser.add_argument("--strategy", required=True, choices=["rule_based", "llm"])
    parser.add_argument("--run-name", required=True, help="Descriptive name for this run")
    parser.add_argument("--output-dir", default=None, help="Output directory for results")
    parser.add_argument("--baseline", default=None, help="Run-name of baseline for delta report")
    parser.add_argument("--no-narration", action="store_true", help="Skip narrator output")
    args = parser.parse_args()

    # Determine output directory
    if args.output_dir:
        output_dir = Path(args.output_dir)
    else:
        output_dir = Path(__file__).parent / "benchmark_results"
    output_dir.mkdir(parents=True, exist_ok=True)

    # Import after argument parsing (faster startup for --help)
    from ares.dialectic.scripts.scenario_corpus import get_all_scenarios
    from ares.dialectic.scripts.benchmark_runner import run_benchmark
    from ares.dialectic.scripts.benchmark_report import generate_report

    scenarios = get_all_scenarios()
    print(f"ARES Benchmark: {len(scenarios)} scenarios, strategy={args.strategy}")
    print(f"Output: {output_dir}")

    # Set up client and logger for LLM runs
    client = None
    call_logger = None
    if args.strategy == "llm":
        from ares.dialectic.agents.strategies.client import AnthropicClient
        from ares.dialectic.agents.strategies.observability import LLMCallLogger
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            print("ERROR: ANTHROPIC_API_KEY environment variable not set.")
            sys.exit(1)
        client = AnthropicClient(api_key=api_key)
        call_logger = LLMCallLogger()

    # Run benchmark
    print(f"\nRunning {args.strategy} benchmark...")
    run = run_benchmark(
        scenarios=scenarios,
        strategy_type=args.strategy,
        include_narration=not args.no_narration,
        client=client,
        call_logger=call_logger,
    )

    # Save results as JSON
    results_json = serialize_benchmark_run(run)
    json_path = output_dir / f"{args.run_name}.json"
    with open(json_path, "w") as f:
        json.dump(results_json, f, indent=2, default=str)
    print(f"Results saved: {json_path}")

    # Generate and save report
    report = generate_report(run, scenarios)
    report_path = output_dir / f"{args.run_name}_report.txt"
    with open(report_path, "w") as f:
        f.write(report)
    print(f"Report saved: {report_path}")

    # Generate delta report if baseline specified
    if args.baseline:
        baseline_json_path = output_dir / f"{args.baseline}.json"
        if baseline_json_path.exists():
            baseline_run = deserialize_benchmark_run(baseline_json_path)
            delta_report = generate_report(run, scenarios, baseline_run=baseline_run)
            delta_path = output_dir / f"{args.run_name}_vs_{args.baseline}_report.txt"
            with open(delta_path, "w") as f:
                f.write(delta_report)
            print(f"Delta report saved: {delta_path}")
        else:
            print(f"WARNING: Baseline file not found: {baseline_json_path}")

    # Print LLM observability summary
    if call_logger and call_logger.records:
        print(f"\n--- LLM Observability ---")
        total_calls = len(call_logger.records)
        total_input = sum(r.input_tokens for r in call_logger.records)
        total_output = sum(r.output_tokens for r in call_logger.records)
        fallbacks = sum(1 for r in call_logger.records if r.fallback_used)
        val_errors = sum(len(r.validation_errors) for r in call_logger.records)
        print(f"API calls: {total_calls}")
        print(f"Tokens: {total_input} input + {total_output} output = {total_input + total_output} total")
        print(f"Fallbacks: {fallbacks}")
        print(f"Validation errors: {val_errors}")

    # Print summary to console
    print(f"\n--- Summary ---")
    print(report)

    return run


def serialize_benchmark_run(run) -> dict:
    """Serialize BenchmarkRun to a JSON-compatible dict."""
    return {
        "run_id": run.run_id,
        "timestamp": run.timestamp.isoformat(),
        "strategy_type": run.strategy_type,
        "scenario_count": run.scenario_count,
        "total_duration_ms": run.total_duration_ms,
        "total_cost_usd": run.total_cost_usd,
        "results": [
            {
                "scenario_id": r.scenario_id,
                "strategy_type": r.strategy_type,
                "verdict_outcome": r.verdict_outcome,
                "verdict_confidence": r.verdict_confidence,
                "architect_confidence": r.architect_confidence,
                "skeptic_confidence": r.skeptic_confidence,
                "architect_assertion_count": r.architect_assertion_count,
                "skeptic_assertion_count": r.skeptic_assertion_count,
                "architect_fact_ids_cited": sorted(r.architect_fact_ids_cited),
                "skeptic_fact_ids_cited": sorted(r.skeptic_fact_ids_cited),
                "total_facts_available": r.total_facts_available,
                "fact_coverage_ratio": r.fact_coverage_ratio,
                "validation_errors": r.validation_errors,
                "fallback_triggers": r.fallback_triggers,
                "duration_ms": r.duration_ms,
                "token_usage": r.token_usage,
                "cost_usd": r.cost_usd,
                "narrator_output": r.narrator_output,
            }
            for r in run.results
        ],
    }


def deserialize_benchmark_run(json_path) -> "BenchmarkRun":
    """Deserialize BenchmarkRun from a JSON file."""
    import json
    from datetime import datetime
    from ares.dialectic.scripts.benchmark_runner import BenchmarkRun, ScenarioResult

    with open(json_path, "r") as f:
        data = json.load(f)

    results = tuple(
        ScenarioResult(
            scenario_id=r["scenario_id"],
            strategy_type=r["strategy_type"],
            verdict_outcome=r["verdict_outcome"],
            verdict_confidence=r["verdict_confidence"],
            architect_confidence=r["architect_confidence"],
            skeptic_confidence=r["skeptic_confidence"],
            architect_assertion_count=r["architect_assertion_count"],
            skeptic_assertion_count=r["skeptic_assertion_count"],
            architect_fact_ids_cited=frozenset(r["architect_fact_ids_cited"]),
            skeptic_fact_ids_cited=frozenset(r["skeptic_fact_ids_cited"]),
            total_facts_available=r["total_facts_available"],
            fact_coverage_ratio=r["fact_coverage_ratio"],
            validation_errors=r["validation_errors"],
            fallback_triggers=r["fallback_triggers"],
            duration_ms=r["duration_ms"],
            token_usage=r["token_usage"],
            cost_usd=r["cost_usd"],
            narrator_output=r["narrator_output"],
        )
        for r in data["results"]
    )

    return BenchmarkRun(
        run_id=data["run_id"],
        timestamp=datetime.fromisoformat(data["timestamp"]),
        strategy_type=data["strategy_type"],
        scenario_count=data["scenario_count"],
        results=results,
        total_duration_ms=data["total_duration_ms"],
        total_cost_usd=data["total_cost_usd"],
    )


if __name__ == "__main__":
    main()
```

**IMPORTANT implementation notes:**

- The `serialize_benchmark_run` and `deserialize_benchmark_run` functions handle the frozen dataclass ↔ JSON conversion. They must correctly handle `frozenset` (serialize as sorted list, deserialize back to frozenset) and `datetime` (ISO format).
- The script should **catch per-scenario exceptions** within `run_benchmark()` if possible. If a single scenario fails, print the error and continue with remaining scenarios rather than crashing the entire run. However, since `run_benchmark()` is frozen (DO NOT MODIFY), this error handling depends on how the runner is implemented. If it doesn't handle individual failures, document this as a limitation.
- The `--baseline` flag loads a previous run's JSON and passes it to `generate_report()` for delta comparison.

---

## Step 5 — Write Tests for `run_llm_benchmark.py`

### `test_run_llm_benchmark.py` (~10 tests)

```python
import pytest
import json
import tempfile
from pathlib import Path
from datetime import datetime, timezone
from ares.dialectic.scripts.run_llm_benchmark import (
    serialize_benchmark_run,
    deserialize_benchmark_run,
)
from ares.dialectic.scripts.benchmark_runner import run_benchmark, BenchmarkRun, ScenarioResult
from ares.dialectic.scripts.scenario_corpus import get_all_scenarios

ALL_SCENARIOS = get_all_scenarios()


def test_serialize_benchmark_run_returns_dict():
    run = run_benchmark(ALL_SCENARIOS, strategy_type="rule_based")
    result = serialize_benchmark_run(run)
    assert isinstance(result, dict)
    assert "run_id" in result
    assert "results" in result
    assert len(result["results"]) == 12


def test_serialize_preserves_scenario_ids():
    run = run_benchmark(ALL_SCENARIOS, strategy_type="rule_based")
    result = serialize_benchmark_run(run)
    ids = {r["scenario_id"] for r in result["results"]}
    expected_ids = {s.metadata.scenario_id for s in ALL_SCENARIOS}
    assert ids == expected_ids


def test_serialize_frozenset_as_sorted_list():
    run = run_benchmark(ALL_SCENARIOS, strategy_type="rule_based")
    result = serialize_benchmark_run(run)
    for r in result["results"]:
        assert isinstance(r["architect_fact_ids_cited"], list)
        assert isinstance(r["skeptic_fact_ids_cited"], list)


def test_serialize_is_json_compatible():
    run = run_benchmark(ALL_SCENARIOS, strategy_type="rule_based")
    result = serialize_benchmark_run(run)
    # Should not raise
    json_str = json.dumps(result, default=str)
    assert len(json_str) > 0


def test_round_trip_serialize_deserialize():
    run = run_benchmark(ALL_SCENARIOS, strategy_type="rule_based")
    serialized = serialize_benchmark_run(run)
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(serialized, f, default=str)
        tmp_path = Path(f.name)
    try:
        restored = deserialize_benchmark_run(tmp_path)
        assert restored.run_id == run.run_id
        assert restored.scenario_count == run.scenario_count
        assert len(restored.results) == len(run.results)
        for orig, rest in zip(run.results, restored.results):
            assert orig.scenario_id == rest.scenario_id
            assert orig.verdict_outcome == rest.verdict_outcome
    finally:
        tmp_path.unlink()


def test_deserialize_restores_frozensets():
    run = run_benchmark(ALL_SCENARIOS, strategy_type="rule_based")
    serialized = serialize_benchmark_run(run)
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(serialized, f, default=str)
        tmp_path = Path(f.name)
    try:
        restored = deserialize_benchmark_run(tmp_path)
        for r in restored.results:
            assert isinstance(r.architect_fact_ids_cited, frozenset)
            assert isinstance(r.skeptic_fact_ids_cited, frozenset)
    finally:
        tmp_path.unlink()


def test_deserialize_restores_frozen_dataclass():
    run = run_benchmark(ALL_SCENARIOS, strategy_type="rule_based")
    serialized = serialize_benchmark_run(run)
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(serialized, f, default=str)
        tmp_path = Path(f.name)
    try:
        restored = deserialize_benchmark_run(tmp_path)
        assert isinstance(restored, BenchmarkRun)
        with pytest.raises(AttributeError):
            restored.run_id = "tampered"
    finally:
        tmp_path.unlink()


def test_deserialize_nonexistent_file_raises():
    with pytest.raises(FileNotFoundError):
        deserialize_benchmark_run(Path("/nonexistent/path.json"))


def test_serialize_includes_strategy_type():
    run = run_benchmark(ALL_SCENARIOS, strategy_type="rule_based")
    result = serialize_benchmark_run(run)
    assert result["strategy_type"] == "rule_based"
    for r in result["results"]:
        assert r["strategy_type"] == "rule_based"


def test_serialize_includes_cost_fields():
    run = run_benchmark(ALL_SCENARIOS, strategy_type="rule_based")
    result = serialize_benchmark_run(run)
    assert result["total_cost_usd"] is None  # rule_based has no cost
    for r in result["results"]:
        assert r["cost_usd"] is None
        assert r["token_usage"] is None
```

---

## Step 6 — Run Rule-Based Baseline & Verify Tests

Before any LLM calls:

```powershell
# 1. Run ALL tests — existing + new
pytest ares/ -v
# Expected: 1164 existing + ~10 new = ~1174 total, ALL PASSING

# 2. Run rule-based baseline
python -m ares.dialectic.scripts.run_llm_benchmark --strategy rule_based --run-name baseline
# Expected: Completes successfully, saves baseline.json and baseline_report.txt
```

**STOP if any test fails.** Fix before proceeding to LLM runs.

---

## Step 7 — Run LLM Benchmark v1 (Current Prompts)

```powershell
python -m ares.dialectic.scripts.run_llm_benchmark --strategy llm --run-name llm_v1 --baseline baseline
```

This will:
1. Run all 12 scenarios through LLM strategies (Architect, Skeptic, Narrator)
2. Save `llm_v1.json` and `llm_v1_report.txt`
3. Generate `llm_v1_vs_baseline_report.txt` (delta analysis)
4. Print observability summary (API calls, tokens, fallbacks, validation errors)

### After Run 1: Analyze Results

Examine the delta report and observability output. Answer these questions IN ORDER:

**Priority 1 — Schema Compliance:**
- How many validation errors occurred? Which scenarios?
- How many fallbacks to rule-based? Which strategies?
- If there are validation errors or fallbacks, the prompts need to more clearly specify the expected JSON output format and fact_id citation requirements.

**Priority 2 — Verdict Accuracy:**
- Which scenarios got the wrong verdict vs expected?
- Did all Tier 1 (baseline) scenarios get the right verdict?
- Did Tier 3 (false positive) scenarios get dismissed (SC-008, SC-009)?

**Priority 3 — Fact Coverage:**
- What's the average fact_coverage_ratio across scenarios?
- Are any scenarios below 30% coverage? (Agents ignoring evidence)
- Are Architect and Skeptic citing different facts? (Good — they should see different things)

**Priority 4 — Agent Balance:**
- On BALANCED scenarios (SC-005, SC-006, SC-007, SC-011, SC-012), are both agents' confidence values comparable? Or is one dominating?
- On ARCHITECT-favored scenarios, does the Architect have materially higher confidence?
- On SKEPTIC-favored scenarios (SC-008, SC-009), does the Skeptic win convincingly?

**Priority 5 — Confidence Calibration:**
- Are confidence values on ambiguous scenarios (INCONCLUSIVE expected) moderate (0.4-0.7)?
- Are confidence values on clear scenarios (THREAT_CONFIRMED, THREAT_DISMISSED expected) high (0.7+)?
- Is the Architect always at 0.9+? (Bad — means confidence is inflated and meaningless)

---

## Step 8 — Revise Prompts

Based on the analysis in Step 7, modify `ares/dialectic/agents/strategies/prompts.py`.

### Prompt Revision Principles

1. **DO NOT change the JSON output schema.** The parsing logic in `llm_strategy.py` expects specific fields. Changing the schema would break parsing. Only change the instructional text.

2. **Strengthen the closed-world constraint.** Every fact_id cited must exist in the evidence packet. Add explicit language: "You may ONLY cite fact_ids that appear in the evidence packet below. Citing any fact_id not in the packet is a critical error."

3. **Add confidence calibration guidance.** "Your confidence should reflect the strength and quantity of evidence. With sparse evidence (fewer than 5 facts), confidence above 0.7 is rarely appropriate. With ambiguous evidence, confidence between 0.4-0.6 is expected."

4. **Sharpen role differentiation:**
   - Architect: "Your role is to find the strongest possible threat hypothesis. Build a coherent attack narrative from the evidence. Cite every fact that supports your case."
   - Skeptic: "Your role is to find the most credible benign explanation. Assume innocence and look for legitimate reasons for every suspicious indicator. Cite facts that support alternative explanations."

5. **Address specific weaknesses found in Step 7.** If the Skeptic is weak on false-positive scenarios, add guidance about recognizing maintenance patterns, authorized activity, and update behavior. If the Architect over-interprets sparse evidence, add caution about evidence density.

6. **Keep prompts concise.** Overly long prompts cause the LLM to lose focus. Aim for clear principles, not exhaustive checklists.

### After Modifying Prompts

```powershell
# Verify no tests broke
pytest ares/ -v
# Expected: All ~1174 tests pass
```

---

## Step 9 — Run LLM Benchmark v2 (Revised Prompts)

```powershell
python -m ares.dialectic.scripts.run_llm_benchmark --strategy llm --run-name llm_v2 --baseline llm_v1
```

This generates:
- `llm_v2.json` and `llm_v2_report.txt`
- `llm_v2_vs_llm_v1_report.txt` (improvement delta)

### After Run 2: Assess Improvement

Compare v2 to v1:
- Did validation errors decrease? (Should be zero)
- Did verdict accuracy improve?
- Did fact coverage increase?
- Did agent balance improve on BALANCED scenarios?
- Did any regressions occur? (Scenarios that were correct in v1 but wrong in v2)

**If significant regressions occurred:** Revert the specific prompt change that caused them and try a different approach.

**If results are satisfactory:** Proceed to Step 10.

**If results need further improvement AND budget allows:** Make targeted prompt changes and run one more benchmark (llm_v3). Maximum 3 total LLM runs.

---

## Step 10 — Generate Final Analysis

Generate the comprehensive comparison report:

```powershell
# Final comparison: best LLM run vs rule-based baseline
python -m ares.dialectic.scripts.run_llm_benchmark --strategy rule_based --run-name final_baseline
# (re-run baseline to get fresh comparison, or use existing baseline)
```

### Write `SESSION_011B_BENCHMARK_ANALYSIS.md`

Create this file in the project root (or scripts directory) with the following sections:

```markdown
# Session 011B: Benchmark Analysis

## Executive Summary
- [One paragraph: what was tested, what improved, what remains]

## Methodology
- 12 scenarios, 4 difficulty tiers
- Rule-based baseline vs LLM v1 (original prompts) vs LLM v2 (revised prompts)
- Metrics: verdict accuracy, confidence calibration, fact coverage, agent balance

## Results: Rule-Based Baseline
- [Table: scenario_id | verdict | confidence | fact_coverage]

## Results: LLM v1 (Original Prompts)
- [Table: same format]
- Validation errors: [count]
- Fallbacks: [count]
- Total cost: [amount]
- Key observations: [what worked, what didn't]

## Results: LLM v2 (Revised Prompts)
- [Table: same format]
- Validation errors: [count]
- Fallbacks: [count]
- Total cost: [amount]
- Improvements vs v1: [specific]

## Prompt Changes Made
- [Describe each change and the rationale]
- [Before/after examples if useful]

## Tier-by-Tier Analysis
### Tier 1 (Baseline): [Did LLM match/exceed rule-based?]
### Tier 2 (Requires Reasoning): [Where did LLM outperform?]
### Tier 3 (Stress Skeptic): [Did false positives get dismissed?]
### Tier 4 (Find Limits): [Where did the system struggle?]

## Known Issues
- [Any llm_strategy.py issues discovered but not fixed]
- [Scenarios that remain problematic]
- [Structural limitations that prompts alone can't address]

## Recommendations for Future Sessions
- [Priority list of what to work on next]
```

---

## Step 11 — Final Test Run

```powershell
# Final verification: ALL tests pass
pytest ares/ -v

# Expected: ~1174 total, ALL PASSING
```

---

## Success Criteria

- [ ] All 1,164 existing tests pass (zero regressions)
- [ ] ~10 new tests pass (serialization, script logic)
- [ ] Full 12-scenario benchmark completed against live LLM (at least 2 runs)
- [ ] Zero validation errors across all 12 scenarios on best LLM run
- [ ] Zero fallbacks on best LLM run
- [ ] `prompts.py` revised with documented improvements
- [ ] `prompts_v1_original.py` backup exists for comparison
- [ ] Benchmark results saved (JSON + text reports)
- [ ] Delta reports generated (baseline vs LLM, v1 vs v2)
- [ ] `SESSION_011B_BENCHMARK_ANALYSIS.md` written with findings
- [ ] All tests pass after prompt modifications

---

## Style Notes

- Frozen dataclasses everywhere (immutability)
- Type hints on everything
- Docstrings for public methods and classes
- Test naming: `test_<what>_<condition>_<expected>`
- Keep benchmark script clean — it's a consumer of existing infrastructure, not new infrastructure
- Import paths follow existing patterns: `from ares.dialectic.scripts.run_llm_benchmark import ...`

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

# Run LLM benchmark v1 (current prompts)
python -m ares.dialectic.scripts.run_llm_benchmark --strategy llm --run-name llm_v1 --baseline baseline

# Run LLM benchmark v2 (after prompt revision)
python -m ares.dialectic.scripts.run_llm_benchmark --strategy llm --run-name llm_v2 --baseline llm_v1

# Run full test suite
pytest ares/ -v

# Run with coverage
pytest ares/ --cov=ares --cov-report=term-missing
```

---

## Key Reminders for Empirical Phase

This session is different from all previous sessions. You are doing **data-driven prompt engineering**, not deterministic code construction. Key principles:

1. **Observe before you change.** Run v1 first. Understand what the prompts currently produce before modifying them.
2. **Change prompts, not structure.** The JSON schema, parsing logic, and validation logic are frozen. Only the instructional text in the prompts can change.
3. **One priority at a time.** Fix validation errors before optimizing verdicts. Fix verdicts before tuning confidence.
4. **Document everything.** Every finding, every prompt change, every before/after comparison goes in the analysis document.
5. **Respect the budget.** 3 full LLM runs maximum. If the prompts aren't converging, stop and document what needs structural changes.
6. **The closed-world constraint is sacred.** Zero validation errors is the minimum bar. If the LLM cites fact_ids that don't exist in the packet, the prompt has failed its most important job.
