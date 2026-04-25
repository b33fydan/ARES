# SESSION 030: Visual Pipeline Corpus Stress Test
# Claude Code Execution Prompt

## Context

Continuing ARES build. 1,992 tests collected (1,927 passed, 65 skipped live LLM), zero failures.

Session 029 accomplished:
- 7 frozen event dataclasses representing scenario analysis lifecycle
- ScenarioReplayer: scenario → timed event sequence
- WebSocket emitter for nw_wrld 3D visualization
- SC-019 smoke test passed: clean event sequence through full pipeline
- nw_wrld modules: AresEvidenceGraph.js, AresConfidenceHeat.js

Session 030 goal: Stress-test the visual pipeline against ALL 33 scenarios in the corpus. Build event sequence diagnostics and a corpus-wide replay runner that validates every scenario produces a correct, complete event sequence. Catalog any anomalies as a concrete bug list for Session 031.

Project location: C:\ares-phase-zero
Run tests: python -m pytest ares/ -v
Git branch: session/030-visual-stress-test

---

## CRITICAL CONSTRAINTS

1. **DO NOT MODIFY ANY EXISTING FILES.** Every file listed below with "DO NOT MODIFY" must not be touched. All 1,927 existing passing tests must pass unchanged. All 65 skipped tests must remain skipped.
2. **All new dataclasses must be frozen.** `@dataclass(frozen=True)` everywhere.
3. **No live LLM calls.** This session is fully deterministic.
4. **No WebSocket/network calls.** Test the data, not the transport.
5. **Type hints on everything. Docstrings on all public methods.**
6. **Test naming convention:** `test_<what>_<condition>_<expected>`

---

## Step 1 — Review Existing Files (READ FIRST, CODE SECOND)

Read these files to understand existing types and patterns:

1. `ares/visual/events.py` — The 7 frozen event dataclasses and their serialization
2. `ares/visual/replayer.py` — ScenarioReplayer: how scenarios become event sequences
3. `ares/visual/tests/test_events.py` — Existing event tests (24 tests)
4. `ares/visual/tests/test_replayer.py` — Existing replayer tests (22 tests)
5. `ares/dialectic/scripts/scenario_corpus.py` — `get_all_scenarios()`, `BenchmarkScenario`, `ScenarioMetadata`
6. `ares/dialectic/evidence/packet.py` — `EvidencePacket` (frozen container, `fact_count`, `facts`)
7. `ares/dialectic/agents/patterns.py` — `VerdictOutcome`

**Understand the event types, their fields, and the ScenarioReplayer's output format before writing any code.**

---

## Step 2 — Create New File Structure

```
ares/visual/
├── diagnostics.py                  # NEW: Event sequence validation + anomaly detection
├── corpus_replay.py                # NEW: Full corpus stress test runner
└── tests/
    ├── test_diagnostics.py         # NEW: ~25 tests
    └── test_corpus_replay.py       # NEW: ~25 tests
```

---

## Step 3 — Implement `diagnostics.py`

### 3.1 Anomaly Types

```python
from dataclasses import dataclass
from enum import Enum, auto

class AnomalySeverity(Enum):
    CRITICAL = auto()  # Sequence is broken, rendering would fail
    WARNING = auto()   # Unexpected but renderable

class AnomalyType(Enum):
    # CRITICAL
    MISSING_SCENARIO_START = auto()
    MISSING_SCENARIO_END = auto()
    MISSING_VERDICT = auto()
    FACT_COUNT_MISMATCH = auto()
    WRONG_EVENT_ORDER = auto()
    
    # WARNING
    ZERO_ASSERTIONS = auto()
    DUPLICATE_FACT_EVENT = auto()
    HIGH_EVENT_COUNT = auto()  # > 50 events for a single scenario
    ORPHANED_ASSERTION = auto()  # assertion references fact not yet ingested

@dataclass(frozen=True)
class SequenceAnomaly:
    """A single anomaly detected in an event sequence."""
    anomaly_type: AnomalyType
    severity: AnomalySeverity
    description: str
    event_index: int | None  # Index in the event list where anomaly was detected, None if structural
```

### 3.2 Diagnostic Result

```python
@dataclass(frozen=True)
class DiagnosticResult:
    """Result of validating an event sequence."""
    scenario_id: str
    total_events: int
    fact_events: int
    assertion_events: int
    anomalies: tuple  # tuple[SequenceAnomaly, ...]
    
    @property
    def is_valid(self) -> bool:
        """True if zero CRITICAL anomalies."""
        return not any(a.severity == AnomalySeverity.CRITICAL for a in self.anomalies)
    
    @property
    def critical_count(self) -> int:
        return sum(1 for a in self.anomalies if a.severity == AnomalySeverity.CRITICAL)
    
    @property
    def warning_count(self) -> int:
        return sum(1 for a in self.anomalies if a.severity == AnomalySeverity.WARNING)
```

### 3.3 Validation Function

```python
def validate_sequence(events: list | tuple, packet, scenario_id: str = "unknown") -> DiagnosticResult:
    """
    Validate an event sequence against expected invariants.
    
    Checks:
    1. Starts with scenario_start
    2. Ends with scenario_end
    3. Contains exactly one verdict_rendered
    4. fact_ingested count matches packet.fact_count
    5. Events follow lifecycle ordering (no verdict before facts, no facts after verdict)
    6. No duplicate fact_ingested events for the same fact_id
    7. assertion_formed events reference previously ingested facts (if fact references are available)
    
    Args:
        events: The event sequence to validate (list of event dataclass instances)
        packet: The EvidencePacket that generated these events (for fact count comparison)
        scenario_id: Identifier for reporting
    
    Returns:
        DiagnosticResult with any detected anomalies
    """
```

**Implementation notes:**
- Extract event type from each event object (check the `events.py` type field or class name — read the file first)
- Track which facts have been ingested (by fact_id if available in the event)
- Detect ordering violations: no `fact_ingested` after `verdict_rendered`, no `assertion_formed` before any `fact_ingested`
- Flag `HIGH_EVENT_COUNT` as WARNING if total events exceed 50

---

## Step 4 — Implement `corpus_replay.py`

### 4.1 Replay Result

```python
@dataclass(frozen=True)
class ReplayResult:
    """Result of replaying a single scenario through the visual pipeline."""
    scenario_id: str
    scenario_name: str
    event_count: int
    fact_events: int
    assertion_events: int
    diagnostic: DiagnosticResult  # From diagnostics.validate_sequence()
    
    @property
    def passed(self) -> bool:
        return self.diagnostic.is_valid
```

### 4.2 Corpus Replay Report

```python
@dataclass(frozen=True)
class CorpusReplayReport:
    """Aggregate report from replaying all scenarios."""
    total_scenarios: int
    passed: int
    failed: int
    warning_scenarios: int  # Passed but had WARNING anomalies
    results: tuple  # tuple[ReplayResult, ...]
    
    @property
    def all_passed(self) -> bool:
        return self.failed == 0
    
    @property
    def failed_scenarios(self) -> tuple:
        return tuple(r for r in self.results if not r.passed)
    
    @property
    def warning_list(self) -> tuple:
        return tuple(r for r in self.results if r.passed and r.diagnostic.warning_count > 0)
```

### 4.3 Replay Functions

```python
def replay_scenario(scenario) -> ReplayResult:
    """
    Replay a single BenchmarkScenario through ScenarioReplayer and validate.
    
    1. Create ScenarioReplayer for the scenario
    2. Generate the event sequence
    3. Run validate_sequence() from diagnostics
    4. Package into ReplayResult
    
    No network, no WebSocket, no LLM. Pure data transformation + validation.
    """

def replay_corpus() -> CorpusReplayReport:
    """
    Replay ALL scenarios from get_all_scenarios() and produce aggregate report.
    
    Iterates through every scenario in the corpus, replays each one,
    collects results, and produces the summary report.
    """

def format_report(report: CorpusReplayReport) -> str:
    """
    Format the corpus replay report as readable ASCII text.
    
    Sections:
    1. Header: timestamp, total scenarios, pass/fail summary
    2. Per-scenario table: scenario_id | name | events | facts | assertions | status
    3. Failed scenarios detail: scenario_id + list of CRITICAL anomalies
    4. Warning scenarios detail: scenario_id + list of WARNING anomalies
    5. Summary metrics: total events across corpus, average events per scenario, fact coverage
    """
```

---

## Step 5 — Implement `test_diagnostics.py` (~25 tests)

```python
import pytest
from ares.visual.diagnostics import (
    validate_sequence, DiagnosticResult, SequenceAnomaly,
    AnomalyType, AnomalySeverity,
)

# --- Valid Sequences ---

def test_valid_sequence_returns_no_critical_anomalies():
    """A well-formed event sequence should have zero CRITICAL anomalies."""

def test_valid_sequence_is_valid_true():
    """DiagnosticResult.is_valid should be True for clean sequences."""

def test_valid_sequence_counts_fact_events():
    """fact_events should match the number of fact_ingested events."""

def test_valid_sequence_counts_assertion_events():
    """assertion_events should match the number of assertion_formed events."""

# --- Missing Bookends ---

def test_missing_scenario_start_is_critical():
    """Sequence without scenario_start should produce CRITICAL anomaly."""

def test_missing_scenario_end_is_critical():
    """Sequence without scenario_end should produce CRITICAL anomaly."""

# --- Missing Verdict ---

def test_missing_verdict_is_critical():
    """Sequence without verdict_rendered should produce CRITICAL anomaly."""

def test_multiple_verdicts_detected():
    """More than one verdict_rendered should be flagged."""

# --- Fact Count Mismatch ---

def test_fewer_fact_events_than_packet_is_critical():
    """If fact_ingested count < packet.fact_count, CRITICAL."""

def test_more_fact_events_than_packet_is_critical():
    """If fact_ingested count > packet.fact_count, CRITICAL."""

def test_exact_fact_match_no_anomaly():
    """If fact_ingested count == packet.fact_count, no fact-related anomaly."""

# --- Ordering Violations ---

def test_fact_after_verdict_is_critical():
    """fact_ingested occurring after verdict_rendered is a CRITICAL ordering violation."""

def test_assertion_before_any_fact_is_warning():
    """assertion_formed before any fact_ingested should be flagged."""

# --- Warnings ---

def test_zero_assertions_is_warning():
    """A sequence with no assertion_formed events should produce WARNING."""

def test_high_event_count_is_warning():
    """Sequence with >50 events should produce HIGH_EVENT_COUNT warning."""

def test_duplicate_fact_event_is_warning():
    """Two fact_ingested events for the same fact should produce WARNING."""

# --- Edge Cases ---

def test_empty_event_list_all_critical():
    """Empty event list should produce multiple CRITICAL anomalies."""

def test_single_event_only_scenario_start():
    """Just scenario_start should flag missing end, verdict, fact mismatch."""

# --- Property Tests ---

def test_critical_count_property():
    """critical_count should return count of CRITICAL anomalies."""

def test_warning_count_property():
    """warning_count should return count of WARNING anomalies."""

def test_diagnostic_result_is_frozen():
    """DiagnosticResult should be immutable."""

def test_sequence_anomaly_is_frozen():
    """SequenceAnomaly should be immutable."""
```

**Build these tests using mock/synthetic event sequences.** Construct event lists by hand to test each condition. Reference `events.py` for how to instantiate each event type.

---

## Step 6 — Implement `test_corpus_replay.py` (~25 tests)

```python
import pytest
from ares.visual.corpus_replay import (
    replay_scenario, replay_corpus, format_report,
    ReplayResult, CorpusReplayReport,
)
from ares.dialectic.scripts.scenario_corpus import get_all_scenarios, get_scenario_by_id

ALL_SCENARIOS = get_all_scenarios()

# --- Single Scenario Replay ---

def test_replay_single_scenario_returns_replay_result():
    """replay_scenario should return a ReplayResult."""

def test_replay_sc019_smoke_test():
    """SC-019 (the original smoke test) should replay cleanly."""

def test_replay_result_has_scenario_id():
    """ReplayResult.scenario_id should match the input scenario."""

def test_replay_result_event_count_positive():
    """Every scenario should produce at least 4 events (start, fact, verdict, end)."""

def test_replay_result_fact_events_match_packet():
    """fact_events should equal the scenario's packet.fact_count."""

# --- Full Corpus Replay ---

def test_corpus_replay_covers_all_scenarios():
    """replay_corpus should produce results for all 33 scenarios."""

def test_corpus_replay_total_equals_len():
    """total_scenarios should match len(results)."""

def test_corpus_replay_pass_fail_sum():
    """passed + failed should equal total_scenarios."""

def test_all_scenarios_produce_valid_sequences():
    """THIS IS THE KEY TEST. Every scenario in the corpus should produce
    a valid event sequence (zero CRITICAL anomalies)."""

# --- Cross-Source Scenarios (SC-025+) ---

def test_cross_source_scenarios_replay_cleanly():
    """SC-025 through SC-033 are the complex multi-source scenarios.
    They should all produce valid event sequences."""

def test_cross_source_higher_event_counts():
    """Cross-source scenarios should generally have higher event counts
    than single-source scenarios (more facts = more events)."""

# --- Report Formatting ---

def test_format_report_contains_header():
    """Formatted report should include header with timestamp and summary."""

def test_format_report_contains_per_scenario_table():
    """Formatted report should list each scenario with status."""

def test_format_report_lists_failures():
    """If any scenarios failed, they should appear in the failure detail section."""

def test_format_report_lists_warnings():
    """Warning scenarios should appear in the warning detail section."""

# --- Edge Cases ---

def test_replay_result_is_frozen():
    """ReplayResult should be immutable."""

def test_corpus_replay_report_is_frozen():
    """CorpusReplayReport should be immutable."""

def test_failed_scenarios_property():
    """failed_scenarios should return only results where passed is False."""

def test_warning_list_property():
    """warning_list should return results that passed but had warnings."""

# --- Metrics ---

def test_corpus_total_event_count_reasonable():
    """Total events across all 33 scenarios should be > 100 (sanity check)."""

def test_every_scenario_has_at_least_one_fact_event():
    """Every scenario has at least one fact, so every replay should have >= 1 fact event."""
```

---

## Step 7 — Run Full Test Suite

```powershell
python -m pytest ares/ -v
```

**Expected result:**
- All 1,927 previously passing tests still pass
- All 65 skipped tests remain skipped
- ~50 new tests pass
- 0 failures

---

## Existing File Tree (ALL marked DO NOT MODIFY)

```
ares/
├── graph/schema.py                                    # Session 001 — DO NOT MODIFY
├── visual/
│   ├── __init__.py                                    # Session 029 — DO NOT MODIFY
│   ├── events.py                                      # Session 029 — DO NOT MODIFY
│   ├── replayer.py                                    # Session 029 — DO NOT MODIFY
│   ├── emitter.py                                     # Session 029 — DO NOT MODIFY
│   ├── scripts/
│   │   └── run_visual.py                              # Session 029 — DO NOT MODIFY
│   ├── tests/
│   │   ├── test_events.py                             # Session 029 (24 tests) — DO NOT MODIFY
│   │   └── test_replayer.py                           # Session 029 (22 tests) — DO NOT MODIFY
│   └── nw_wrld_modules/
│       ├── AresEvidenceGraph.js                       # Session 029 — DO NOT MODIFY
│       ├── AresConfidenceHeat.js                      # Session 029 — DO NOT MODIFY
│       └── README.md                                  # Session 029 — DO NOT MODIFY
└── dialectic/
    ├── evidence/                                      # Sessions 002-005 — DO NOT MODIFY
    ├── messages/                                      # Session 002 — DO NOT MODIFY
    ├── coordinator/                                   # Sessions 002-006 — DO NOT MODIFY
    ├── agents/                                        # Sessions 003-004, 009-010 — DO NOT MODIFY
    ├── memory/                                        # Session 007 — DO NOT MODIFY
    ├── escalation/                                    # Sessions 022-024 — DO NOT MODIFY
    └── scripts/
        ├── scenario_corpus.py                         # Sessions 011A, 021 — DO NOT MODIFY
        ├── benchmark_runner.py                        # Session 011A — DO NOT MODIFY
        └── benchmark_report.py                        # Session 011A — DO NOT MODIFY
```

**Note:** The file tree above may not be exhaustive. Read `ares/` directory structure before starting. The rule is simple: if a file exists, DO NOT MODIFY IT.

---

## Summary

This session builds the validation infrastructure that proves the visual pipeline works for ALL 33 scenarios, not just SC-019. The output is a concrete pass/fail report for every scenario plus a cataloged list of any anomalies. No new features, no architecture changes — just proving what we built actually works at scale.

After this session:
- If all 33 pass: visual layer is production-ready for content
- If some fail: the anomaly list becomes the Session 031 bug fix scope

Git: commit to `session/030-visual-stress-test`, squash merge to main only after all tests pass.
