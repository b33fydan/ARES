# SESSION 030: Strategy Brief — Visual Pipeline Corpus Stress Test

**Purpose:** Strategy document for Dan and Claude (strategy window) to design the Session 030 Claude Code prompt. This is NOT the prompt itself — it's the context, options, and architectural considerations needed to build one.

**Date:** March 27, 2026
**Phase:** Phase 4 — Visualization & Content Infrastructure

---

## Where We Are

### System State After Session 029
- **1,992 tests collected** (1,927 passed, 65 skipped live LLM tests), zero failures, zero regressions
- **Phase 3 CONCLUDED:** Selective Escalation Architecture built, benchmarked, formally closed
- **Multi-turn thesis dead:** Every configuration degraded accuracy vs single-turn (91.7% → 83.3% on 12-scenario pilot; 81.8% single-turn ceiling on 33-scenario corpus)
- **Visual layer shipped (Session 029):** 7 frozen event dataclasses, ScenarioReplayer, WebSocket emitter, nw_wrld 3D modules (AresEvidenceGraph, AresConfidenceHeat)
- **Smoke test passed:** SC-019 produced clean event sequence through the full pipeline
- **Single-turn production pipeline:** The reasoning path that actually works — visualization renders THIS path

### What Session 029 Built (DO NOT MODIFY)
```
ares/visual/
├── __init__.py                           # Package init
├── events.py                             # 7 frozen event dataclasses + serialization
├── replayer.py                           # ScenarioReplayer — scenario to event sequence
├── emitter.py                            # WebSocket server for nw_wrld
├── scripts/
│   └── run_visual.py                     # CLI runner
├── tests/
│   ├── test_events.py                    # 24 tests
│   └── test_replayer.py                  # 22 tests
└── nw_wrld_modules/
    ├── AresEvidenceGraph.js              # 3D evidence graph module
    ├── AresConfidenceHeat.js             # Confidence particle system
    └── README.md                         # Setup instructions
```

### Key Architecture Facts
1. **Event types:** `scenario_start`, `fact_ingested`, `assertion_formed`, `verdict_rendered`, `miscalibration_check`, `scenario_end`, plus confidence events
2. **ScenarioReplayer** bridges benchmark corpus → visual layer without coupling them
3. **Event ordering invariant:** `scenario_start` → N × `fact_ingested` → M × `assertion_formed` → `verdict_rendered` → `miscalibration_check` → `scenario_end`
4. **SC-019 smoke test result:** `scenario_start` → 8 `fact_ingested` → 1 `assertion_formed` → `verdict_rendered` → `miscalibration_check` → `scenario_end`

---

## The Problem

Session 029 proved the visual pipeline works for **one scenario** (SC-019). The pipeline has NOT been tested against:

1. **All 33 scenarios** — event volume, fact counts, and complexity vary significantly across the corpus
2. **Cross-source scenarios (SC-025 through SC-033)** — multiple evidence types, higher fact counts, more complex graph topology
3. **Edge cases** — scenarios with many facts, scenarios with few facts, scenarios with INCONCLUSIVE verdicts, scenarios with high/low confidence
4. **Event sequence integrity** — does every fact in every EvidencePacket produce exactly one `fact_ingested` event? Do assertion counts match what the pipeline actually produces?

Until this is proven, the visual layer is a demo, not infrastructure.

---

## What Session 030 Must Build

### 1. Corpus Replay Runner (`corpus_replay.py`)

A deterministic stress test harness that:
- Replays ALL 33 scenarios through ScenarioReplayer
- Validates event sequence integrity for each scenario
- Captures per-scenario metrics (event count, fact count, assertion count, timing)
- Produces a summary report identifying any failures or anomalies
- Does NOT require WebSocket/network — operates on the event sequence data directly

**Key types:**
- `ReplayResult` (frozen) — per-scenario: scenario_id, event_count, fact_events, assertion_events, has_verdict, has_miscalibration, sequence_valid, anomalies list
- `CorpusReplayReport` (frozen) — aggregate: total_scenarios, passed, failed, anomaly_list, per-scenario results
- `replay_scenario(scenario) → ReplayResult`
- `replay_corpus() → CorpusReplayReport`

### 2. Event Sequence Diagnostics (`diagnostics.py`)

A validator that checks invariants on any event sequence:
- **Ordering:** Events follow the required lifecycle ordering
- **Completeness:** Every fact in the EvidencePacket has a corresponding `fact_ingested` event
- **Fact coverage:** `fact_ingested` count matches `packet.fact_count`
- **Bookend check:** Sequence starts with `scenario_start` and ends with `scenario_end`
- **Verdict present:** Exactly one `verdict_rendered` event exists
- **No orphans:** Every `assertion_formed` references facts that were previously ingested

**Key types:**
- `SequenceAnomaly` (frozen) — anomaly_type (enum), description, event_index, severity
- `DiagnosticResult` (frozen) — scenario_id, anomalies list, is_valid (True if zero CRITICAL anomalies)
- `validate_sequence(events, packet) → DiagnosticResult`

### 3. Tests

- `test_corpus_replay.py` — ~25 tests validating the replay runner against known scenarios, edge cases, metric correctness
- `test_diagnostics.py` — ~25 tests validating sequence anomaly detection: missing facts, wrong ordering, duplicate events, orphaned assertions

---

## What Session 030 Must NOT Build

- No WebSocket integration testing (that's a manual/integration concern)
- No modifications to existing visual layer files
- No nw_wrld module changes
- No live LLM calls
- No benchmark re-runs

---

## Architectural Decisions

### Why Separate Diagnostics from Replay?

The diagnostics module (`validate_sequence`) is a pure function: events in, anomalies out. It can be used by the corpus replay runner but also independently — for example, validating a live WebSocket stream, or debugging a single scenario's event output. Keeping it separate follows the ARES pattern of composable, testable components.

### Why Not Test WebSocket Directly?

WebSocket testing introduces network dependencies, async complexity, and flaky test potential. The ScenarioReplayer → event sequence path is deterministic and testable without any I/O. If the event sequences are valid for all 33 scenarios, the WebSocket layer (which just serializes and sends them) will work. Test the data, not the transport.

### Anomaly Severity Levels

- **CRITICAL:** Sequence is fundamentally broken (missing verdict, missing scenario_start/end, fact count mismatch). Visual rendering would fail or be misleading.
- **WARNING:** Sequence has unexpected characteristics but would still render (e.g., zero assertions, unusually high event count). Worth logging for investigation.

---

## New Files Created This Session

```
ares/visual/
├── diagnostics.py                        # Event sequence validation + anomaly detection
├── corpus_replay.py                      # Full corpus stress test runner + reporting
└── tests/
    ├── test_diagnostics.py               # ~25 tests
    └── test_corpus_replay.py             # ~25 tests
```

**Files Modified: NONE.** All existing 1,992 tests must remain collectible with 1,927 passing and 65 skipped.

---

## Success Criteria

- [ ] All 1,927 existing passing tests still pass (zero regressions)
- [ ] All 65 skipped tests remain skipped (not broken)
- [ ] ~50 new tests pass
- [ ] All 33 scenarios replay through ScenarioReplayer without errors
- [ ] Event sequence diagnostics validate all 33 scenarios as VALID (zero CRITICAL anomalies)
- [ ] Per-scenario metrics captured: event count, fact coverage, assertion count
- [ ] Any WARNING-level anomalies cataloged in the CorpusReplayReport (these become the 031 bug list)
- [ ] All new dataclasses are frozen
- [ ] No modifications to existing files

---

## What Comes After (Session 031 Preview)

Session 030 produces a concrete list of what works and what doesn't across all 33 scenarios. Session 031 addresses whatever 030 surfaces:

- Fix any WARNING-level anomalies in event generation
- If complex scenarios expose nw_wrld rendering issues, update the JS modules
- If event volume for cross-source scenarios is problematic, add event batching/throttling to the emitter
- With a validated visual pipeline, begin Episode 5/6 content production with live ARES renders

---

## Session History Reference

| Session | What | Tests | Key Insight |
|---------|------|-------|-------------|
| 001–010 | Core dialectic (Phase 1) | 1,104 | "Hallucinations = schema violations" |
| 011A/B | Scenario corpus + benchmark | ~120 | Measurement before optimization |
| 013–014 | Multi-turn thesis test | — | Debate degrades accuracy (75% vs 91.7%) |
| 016 | Syslog extractor | ~50 | Expanding evidence diversity |
| 021 | Phase 3 prep | — | 81.8% single-turn ceiling on 33 scenarios |
| 022–024 | Selective escalation (Phase 3) | ~145 | Multi-turn thesis formally dead |
| 029 | Visual emitter + nw_wrld | 46 | ARES has eyes (SC-019 smoke test) |
| **030** | **Visual corpus stress test** | **~50** | **Prove the eyes work on everything** |

---

*The system can see. Session 030 proves it can see everything.*
