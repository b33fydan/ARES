# SESSION 031: Benchmark Regeneration & Misclassification Diagnosis
# Claude Code Execution Prompt

## Context

Continuing ARES build. 2,001 tests (1,927 passed + 74 new from Session 030, 65 skipped live LLM, 0 failures).

Session 030 accomplished:
- Visual pipeline stress-tested: 33/33 scenarios produce valid event sequences
- Diagnostics module: event sequence validation with anomaly detection
- Corpus replay runner: full corpus stress test infrastructure
- Zero CRITICAL, zero WARNING anomalies across entire corpus

Session 031 goal: Re-run the full 33-scenario benchmark against live LLM (single-turn), save results, then build a misclassification diagnosis tool that classifies WHY each failed scenario got the wrong verdict. This session makes live API calls.

Project location: C:\ares-phase-zero
Run tests: python -m pytest ares/ -v
Git branch: session/031-benchmark-diagnosis

---

## CRITICAL CONSTRAINTS

1. **DO NOT MODIFY ANY EXISTING FILES.** All existing files are off-limits.
2. **All new dataclasses must be frozen.** `@dataclass(frozen=True)` everywhere.
3. **This session DOES make live LLM API calls.** The Anthropic API key is configured.
4. **Save all benchmark results to files.** API calls cost money — never require re-running to access results.
5. **Type hints on everything. Docstrings on all public methods.**

---

## Step 1 — Review Existing Files (READ FIRST, CODE SECOND)

Read these files to understand the existing benchmark infrastructure:

1. `ares/dialectic/scripts/benchmark_runner.py` — `run_benchmark()`, `ScenarioResult`, `BenchmarkRun`
2. `ares/dialectic/scripts/benchmark_report.py` — `generate_report()`
3. `ares/dialectic/scripts/scenario_corpus.py` — `get_all_scenarios()`, `get_scenario_by_id()`, `BenchmarkScenario`, `ScenarioMetadata`
4. `ares/dialectic/scripts/run_llm_benchmark.py` — Existing CLI benchmark script (if present)
5. `ares/dialectic/agents/strategies/live_cycle.py` — `run_cycle_with_strategies()`
6. `ares/dialectic/agents/strategies/observability.py` — `LLMCallRecord`, `LLMCallLogger`
7. `ares/dialectic/agents/strategies/client.py` — `AnthropicClient`
8. `ares/dialectic/agents/patterns.py` — `VerdictOutcome`
9. `ares/visual/replayer.py` — `ScenarioReplayer` (for evidence graph analysis)
10. `ares/visual/diagnostics.py` — `validate_sequence()` (from Session 030)

**Understand how `run_benchmark()` works, what `ScenarioResult` contains, and how the visual replayer generates event sequences before writing any code.**

---

## Step 2 — Create New File Structure

```
ares/dialectic/scripts/
├── run_full_benchmark.py            # NEW: CLI — runs 33-scenario LLM benchmark, saves results
├── misclassification_diagnosis.py   # NEW: Diagnosis engine — failure mode classification  
└── run_diagnosis.py                 # NEW: CLI — reads saved results, produces diagnosis report
```

Ensure `ares/dialectic/scripts/benchmark_results/` directory exists for output files.

---

## Step 3 — Implement `run_full_benchmark.py`

CLI script that runs the full benchmark and saves everything.

```python
"""
Run the full 33-scenario benchmark against live LLM and save results.

Usage:
    python -m ares.dialectic.scripts.run_full_benchmark
    python -m ares.dialectic.scripts.run_full_benchmark --output-dir results/
    python -m ares.dialectic.scripts.run_full_benchmark --include-rule-based
"""

import argparse
import json
import os
from datetime import datetime

def main():
    parser = argparse.ArgumentParser(description="Run full ARES benchmark")
    parser.add_argument("--output-dir", default="ares/dialectic/scripts/benchmark_results",
                        help="Directory to save results")
    parser.add_argument("--include-rule-based", action="store_true",
                        help="Also run rule-based baseline for delta comparison")
    parser.add_argument("--include-narration", action="store_true", default=True,
                        help="Include OracleNarrator output")
    args = parser.parse_args()

    # 1. Load all 33 scenarios from corpus
    # 2. Create output directory if needed
    # 3. Run rule-based baseline (if --include-rule-based)
    # 4. Run LLM benchmark (single-turn, v2 prompts)
    # 5. Generate formatted report (with delta if baseline exists)
    # 6. Save:
    #    - Raw BenchmarkRun as JSON (serialize ScenarioResult fields)
    #    - Formatted report as .txt
    #    - Summary: accuracy, cost, duration, misclassified scenario IDs
    # 7. Print summary to stdout
```

**Implementation details:**

- Use `run_benchmark(scenarios, strategy_type="llm", client=client, call_logger=logger)` from existing `benchmark_runner.py`
- Create `AnthropicClient()` and `LLMCallLogger()` as in previous benchmark sessions
- Timestamp all output files: `benchmark_llm_YYYYMMDD_HHMMSS.json`, `benchmark_report_YYYYMMDD_HHMMSS.txt`
- JSON serialization: convert frozen dataclasses to dicts. For each `ScenarioResult`, serialize all fields. `frozenset` → sorted list. `datetime` → ISO string. `Optional` fields → null.
- Print to stdout during execution: scenario-by-scenario progress with verdict + match status
- At the end, print accuracy summary and list of misclassified scenario IDs

**Expected stdout example:**
```
Running ARES benchmark: 33 scenarios, single-turn LLM v2
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SC-001: THREAT_CONFIRMED (expected: THREAT_CONFIRMED) ✓  $0.008
SC-002: THREAT_CONFIRMED (expected: THREAT_DISMISSED) ✗  $0.009
...
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Accuracy: 27/33 (81.8%)
Total cost: $0.19
Duration: 47.2s
Misclassified: SC-002, SC-006, SC-011, SC-015, SC-023, SC-029

Results saved to: benchmark_results/benchmark_llm_20260327_143022.json
Report saved to:  benchmark_results/benchmark_report_20260327_143022.txt
```

---

## Step 4 — Implement `misclassification_diagnosis.py`

The diagnosis engine. Pure functions, no CLI — this is the analytical core.

### 4.1 Failure Mode Enum

```python
from dataclasses import dataclass
from enum import Enum, auto

class FailureMode(Enum):
    SKEPTIC_OVERWEIGHT = auto()      # Skeptic confidence too high on weak benign evidence
    ARCHITECT_UNDERWEIGHT = auto()   # Architect missed or underweighted threat indicators
    EVIDENCE_GAP = auto()            # Insufficient facts to make correct determination
    CONFIDENCE_CALIBRATION = auto()  # Right direction, wrong magnitude flipped verdict
    AMBIGUITY_MISMATCH = auto()      # System reasonable, expected verdict arguably wrong
    VERDICT_INVERSION = auto()       # Complete reversal — THREAT expected, DISMISSED produced (or vice versa)
    ERROR_DURING_ANALYSIS = auto()   # Scenario threw an exception during benchmark
```

### 4.2 Scenario Diagnosis

```python
@dataclass(frozen=True)
class ScenarioDiagnosis:
    """Diagnosis of a single misclassified scenario."""
    scenario_id: str
    scenario_name: str
    expected_verdict: str
    actual_verdict: str
    failure_mode: FailureMode
    architect_confidence: float
    skeptic_confidence: float
    verdict_confidence: float
    fact_coverage: float
    total_facts: int
    evidence_summary: str           # Human-readable summary of what evidence existed
    failure_explanation: str         # Why this failure mode was classified
    recommendation: str             # Concrete suggestion for fixing this miss
```

### 4.3 Diagnosis Report

```python
@dataclass(frozen=True)
class DiagnosisReport:
    """Complete diagnosis of all misclassifications in a benchmark run."""
    benchmark_timestamp: str
    total_scenarios: int
    correct: int
    misclassified: int
    error_count: int
    diagnoses: tuple                # tuple[ScenarioDiagnosis, ...]
    failure_mode_distribution: dict # {FailureMode: count}
    
    @property
    def accuracy(self) -> float:
        return self.correct / self.total_scenarios if self.total_scenarios > 0 else 0.0
```

### 4.4 Core Diagnosis Functions

```python
def classify_failure_mode(result, scenario) -> FailureMode:
    """
    Classify why a scenario was misclassified based on metrics.
    
    Logic:
    1. If result.verdict_outcome == "ERROR" → ERROR_DURING_ANALYSIS
    2. If expected THREAT_CONFIRMED but got THREAT_DISMISSED (or vice versa) → VERDICT_INVERSION
    3. If expected INCONCLUSIVE → check if either agent was reasonable → AMBIGUITY_MISMATCH
    4. If skeptic_confidence > 0.7 and actual verdict is THREAT_DISMISSED 
       but expected THREAT_CONFIRMED → SKEPTIC_OVERWEIGHT
    5. If architect_confidence < 0.5 and expected THREAT_CONFIRMED → ARCHITECT_UNDERWEIGHT
    6. If fact_coverage < 0.6 → EVIDENCE_GAP
    7. If abs(architect_confidence - skeptic_confidence) < 0.15 → CONFIDENCE_CALIBRATION
    8. Default to CONFIDENCE_CALIBRATION
    
    Args:
        result: ScenarioResult from benchmark
        scenario: BenchmarkScenario with metadata and packet
    
    Returns:
        FailureMode classification
    """

def build_evidence_summary(scenario) -> str:
    """
    Build a human-readable summary of the evidence in a scenario.
    
    Reads the EvidencePacket and summarizes:
    - Total fact count
    - Entity types present
    - Source types present
    - Key facts that could indicate threat vs benign
    
    Keep it concise — 3-5 sentences max.
    """

def build_recommendation(failure_mode, result, scenario) -> str:
    """
    Generate a concrete recommendation for fixing this misclassification.
    
    Maps failure modes to actionable prompt engineering suggestions:
    - SKEPTIC_OVERWEIGHT: "Tighten Skeptic plausibility gating — require explicit 
      authorization evidence before confidence > 0.6"
    - ARCHITECT_UNDERWEIGHT: "Add emphasis on [specific indicator type] in Architect prompt"
    - EVIDENCE_GAP: "No prompt fix — scenario may need additional facts or expected verdict review"
    - CONFIDENCE_CALIBRATION: "Adjust Oracle scoring weights — architect/skeptic confidence 
      delta was only X"
    - AMBIGUITY_MISMATCH: "Review expected verdict — system behavior is defensible"
    - VERDICT_INVERSION: "Critical miss — investigate whether agent prompt fundamentally 
      mishandles this attack type"
    - ERROR_DURING_ANALYSIS: "Fix runtime error before addressing accuracy"
    """

def diagnose_benchmark(results_json_path: str) -> DiagnosisReport:
    """
    Load saved benchmark results and produce a complete diagnosis.
    
    1. Load JSON results file
    2. Load scenario corpus for metadata/packet access
    3. Identify misclassified scenarios (actual != expected)
    4. For each miss: classify failure mode, build evidence summary, build recommendation
    5. Aggregate into DiagnosisReport
    
    Args:
        results_json_path: Path to saved benchmark JSON from run_full_benchmark.py
    
    Returns:
        DiagnosisReport with all diagnoses
    """

def format_diagnosis_report(report: DiagnosisReport) -> str:
    """
    Format DiagnosisReport as readable ASCII text.
    
    Sections:
    1. Header: benchmark timestamp, accuracy summary
    2. Failure mode distribution: count per FailureMode
    3. Per-scenario diagnosis: scenario_id, name, expected/actual, failure_mode,
       confidence values, evidence summary, failure explanation, recommendation
    4. Aggregate recommendations: grouped by failure mode, prioritized by count
    """
```

---

## Step 5 — Implement `run_diagnosis.py`

CLI wrapper for the diagnosis engine.

```python
"""
Run misclassification diagnosis on saved benchmark results.

Usage:
    python -m ares.dialectic.scripts.run_diagnosis --results path/to/benchmark.json
    python -m ares.dialectic.scripts.run_diagnosis --results path/to/benchmark.json --output diagnosis.txt
"""

import argparse

def main():
    parser = argparse.ArgumentParser(description="Diagnose ARES benchmark misclassifications")
    parser.add_argument("--results", required=True, help="Path to benchmark results JSON")
    parser.add_argument("--output", help="Path to save diagnosis report (default: stdout + auto-named file)")
    args = parser.parse_args()

    # 1. Call diagnose_benchmark(args.results)
    # 2. Format the report
    # 3. Print to stdout
    # 4. Save to file (auto-named if --output not specified)
```

---

## Step 6 — Execute the Benchmark

After implementing the scripts, run them in sequence:

### 6.1 Run the Full Benchmark
```powershell
python -m ares.dialectic.scripts.run_full_benchmark --include-rule-based
```

This will:
- Run all 33 scenarios against rule-based baseline (~instant)
- Run all 33 scenarios against live LLM (~30-60 seconds, ~$0.15-0.25)
- Save results JSON and formatted report with delta analysis
- Print accuracy summary and misclassified scenario IDs

**Capture the full stdout output.**

### 6.2 Run the Diagnosis
```powershell
python -m ares.dialectic.scripts.run_diagnosis --results ares/dialectic/scripts/benchmark_results/<latest_json_file>
```

This will:
- Load the saved results
- Classify each misclassification
- Produce the diagnosis report
- Save the diagnosis to file

**Capture the full stdout output.**

---

## Step 7 — Run Full Test Suite

```powershell
python -m pytest ares/ -v
```

**Expected result:**
- All 2,001 previously collected tests maintain their pass/skip/fail status
- 0 new test files this session (scripts are CLIs, not library code requiring unit tests)
- 0 failures

---

## Existing File Tree (ALL marked DO NOT MODIFY)

The rule is simple: **if a file exists, DO NOT MODIFY IT.**

Key files for this session:
```
ares/dialectic/scripts/
├── scenario_corpus.py                # get_all_scenarios(), BenchmarkScenario — DO NOT MODIFY
├── benchmark_runner.py               # run_benchmark(), ScenarioResult, BenchmarkRun — DO NOT MODIFY
├── benchmark_report.py               # generate_report() — DO NOT MODIFY
├── run_llm_benchmark.py              # Existing CLI (if present) — DO NOT MODIFY
└── benchmark_results/                # May contain old results — DO NOT MODIFY existing files

ares/dialectic/agents/strategies/
├── client.py                         # AnthropicClient — DO NOT MODIFY
├── prompts.py                        # v2 prompt templates — DO NOT MODIFY (this session)
├── observability.py                  # LLMCallRecord, LLMCallLogger — DO NOT MODIFY
├── live_cycle.py                     # run_cycle_with_strategies() — DO NOT MODIFY
└── rule_based.py                     # RuleBasedThreatAnalyzer etc. — DO NOT MODIFY

ares/visual/
├── replayer.py                       # ScenarioReplayer — DO NOT MODIFY
├── diagnostics.py                    # validate_sequence() — DO NOT MODIFY
└── corpus_replay.py                  # replay_scenario() — DO NOT MODIFY
```

**Read the full `ares/` directory tree before starting to ensure no files are missed.**

---

## Summary

This session regenerates the accuracy baseline on the full 33-scenario corpus and builds the diagnostic tooling to understand exactly why each misclassification happens. The output is a diagnosis report that maps directly to prompt engineering work in Session 032.

Two concrete outputs to bring back to the strategy window:
1. **Benchmark results JSON + report** — the current accuracy number and per-scenario data
2. **Diagnosis report** — per-scenario failure mode, evidence summary, and concrete recommendations

Git: commit to `session/031-benchmark-diagnosis`, squash merge to main only after all tests pass.
