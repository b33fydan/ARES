# SESSION 023: Miscalibration Detector + Per-Claim Evidence Audit
## Claude Code Execution Prompt

## Context

Continuing ARES build. Phase 3 (Selective Escalation Architecture), Session 2 of 4.

Session 022 accomplished: EscalationGate built and tested (50 tests), full 33-scenario benchmark runner, escalation threshold sweep analysis (23 tests). 1,736 tests total, zero regressions.

Critical finding from Session 022: The EscalationGate at [0.35, 0.70] captures only 14% of errors. All 7 errors are MISCALIBRATED (confidently wrong), not uncertain. The gate solves a different problem than the one we have.

Session 023 goal: Build a miscalibration detection layer that catches overconfident wrong answers. Two components: (1) a deterministic rule-based pre-screen that flags suspicious confidence patterns, and (2) a per-claim evidence auditor that decomposes flagged verdicts and checks evidence support per claim.

This session is FULLY DETERMINISTIC — no live LLM calls. All testing uses rule-based strategies and existing benchmark data structures.

**Project location:** C:\ares-phase-zero
**Run tests:** python -m pytest ares/ -v
**Git branch:** session/023-miscalibration-detector

---

## CRITICAL CONSTRAINTS

1. **DO NOT MODIFY ANY EXISTING FILES.** Every file listed below with "DO NOT MODIFY" must not be touched. All 1,736 existing tests must pass unchanged.
2. **All new dataclasses must be frozen.** `@dataclass(frozen=True)` everywhere.
3. **No live LLM calls.** This session uses only rule-based strategies and existing data structures.
4. **Type hints on everything. Docstrings on all public methods.**
5. **Test naming convention:** `test_<what>_<condition>_<expected>`
6. **New files only.** Zero modifications to existing code.

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
    │   └── escalation.py                            # Session 022 — DO NOT MODIFY
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
        └── escalation_analysis.py                   # Session 022 — DO NOT MODIFY
```

---

## Files to Create

### File 1: `ares/dialectic/coordinator/miscalibration.py`

The MiscalibrationDetector and its output types.

**Required types (all frozen dataclasses):**

**MiscalibrationPattern** — Enum or frozen dataclass identifying which pattern triggered: `EVIDENCE_STARVATION`, `EVIDENCE_CONFLICT`, `CONFIDENCE_COMPLEXITY_MISMATCH`, `NARROW_SPREAD`.

**MiscalibrationResult** — Frozen dataclass with fields:
- `flagged` (bool)
- `patterns_triggered` (tuple[MiscalibrationPattern, ...])
- `risk_score` (float, 0.0–1.0)
- `recommendation` (PASS or INSPECT)
- `details` (tuple of human-readable strings explaining each triggered pattern)

**MiscalibrationDetector** — Class that takes configuration thresholds and exposes a single `detect()` method.

Constructor accepts:
- `min_facts_for_confidence` (int, default 3)
- `confidence_threshold` (float, default 0.70)
- `conflict_indicators` (tuple of entity-type pairs that constitute conflicts)
- `complexity_entity_threshold` (int, default 4)
- `complexity_source_threshold` (int, default 3)
- `spread_threshold` (float, default 0.15)
- `spread_minimum` (float, default 0.60)

The `detect()` method signature:
```python
def detect(
    self,
    verdict: Verdict,
    architect_message: DialecticalMessage,
    skeptic_message: DialecticalMessage,
    packet: EvidencePacket
) -> MiscalibrationResult
```

**Detection logic for each pattern:**

- **EVIDENCE_STARVATION:** `verdict.confidence >= confidence_threshold` AND `len(architect_message.assertions) > 0` AND total cited facts across all assertions < `min_facts_for_confidence`.

- **EVIDENCE_CONFLICT:** `verdict.confidence >= confidence_threshold` AND packet contains facts with conflicting entity types (e.g., both `authentication_success` and `authentication_failure` for overlapping entities). Use the fact's `entity_type` and `entity_id` fields. Define a default set of conflict pairs.

- **CONFIDENCE_COMPLEXITY_MISMATCH:** `verdict.confidence >= confidence_threshold` AND (number of distinct `entity_types` in packet >= `complexity_entity_threshold` OR number of distinct `source_types` in packet provenance >= `complexity_source_threshold`).

- **NARROW_SPREAD:** `abs(architect_confidence - skeptic_confidence) <= spread_threshold` AND both >= `spread_minimum`. Extract confidences from the message confidence fields.

**risk_score calculation:** count of triggered patterns / 4.0 (simple, can be refined later).

---

### File 2: `ares/dialectic/coordinator/claim_audit.py`

The ClaimAuditor and its output types.

**Required types (all frozen dataclasses):**

**ClaimSupport** — Enum: `SUPPORTED` (2+ facts), `WEAK` (1 fact), `UNSUPPORTED` (0 facts).

**ClaimAuditDetail** — Frozen dataclass with fields:
- `assertion_type` (AssertionType from existing assertions.py)
- `claim_text` (str, the assertion content)
- `cited_fact_ids` (tuple[str, ...])
- `support_level` (ClaimSupport)
- `fact_count` (int)

**ClaimAuditResult** — Frozen dataclass with fields:
- `claims_total` (int)
- `claims_supported` (int)
- `claims_weak` (int)
- `claims_unsupported` (int)
- `audit_verdict` (CONFIRMED or MISCALIBRATED)
- `claim_details` (tuple[ClaimAuditDetail, ...])
- `miscalibration_ratio` (float, proportion of WEAK + UNSUPPORTED claims)

**ClaimAuditor** — Class with configurable `miscalibration_threshold` (float, default 0.5 — if more than half of claims are weak or unsupported, verdict is MISCALIBRATED).

Single method:
```python
def audit(
    self,
    architect_message: DialecticalMessage,
    packet: EvidencePacket
) -> ClaimAuditResult
```

**Audit logic:** Iterate over `architect_message.assertions`. For each assertion, check how many of its cited fact_ids exist in the packet (using packet's lookup methods). Classify each assertion's support level. Compute aggregate metrics. Set `audit_verdict` based on `miscalibration_ratio` vs threshold.

---

### File 3: `ares/dialectic/scripts/miscalibration_analysis.py`

Analysis script for evaluating combined gate performance across the full corpus.

**Functions to implement:**

- `run_combined_gate_analysis(results)` — Takes benchmark results, runs both EscalationGate and MiscalibrationDetector on each, reports: total errors caught by EscalationGate only, by MiscalibrationDetector only, by both, by neither. Computes combined error capture rate.

- `format_combined_report(analysis)` — Produces a formatted string report showing per-scenario gate decisions and combined capture statistics.

- `get_miscalibration_patterns_summary(results)` — Aggregates which patterns trigger most frequently across the corpus.

---

### File 4: `ares/dialectic/tests/coordinator/test_miscalibration.py`

Comprehensive tests for MiscalibrationDetector. **Target: 35+ tests.**

Test categories:
- Construction and defaults
- Each detection pattern in isolation
- Pattern combinations
- Boundary conditions (exactly at thresholds)
- Risk score calculation
- Recommendation logic (PASS vs INSPECT)
- Immutability of all output types
- Empty/minimal inputs
- Integration with existing Verdict/DialecticalMessage/EvidencePacket types

---

### File 5: `ares/dialectic/tests/coordinator/test_claim_audit.py`

Comprehensive tests for ClaimAuditor. **Target: 25+ tests.**

Test categories:
- Construction and defaults
- Support level classification (SUPPORTED/WEAK/UNSUPPORTED)
- Audit verdict logic (threshold behavior)
- Edge cases (zero assertions, all supported, all unsupported)
- miscalibration_ratio calculation
- Immutability of all output types
- Integration with existing Assertion/EvidencePacket types

---

### File 6: `ares/dialectic/tests/scripts/test_miscalibration_analysis.py`

Tests for the analysis script. **Target: 10+ tests.**

Test categories:
- Combined gate analysis logic
- Report formatting
- Pattern summary aggregation
- Edge cases (no errors, all errors caught)

---

## Execution Order

1. **Read existing files:** `escalation.py` (Session 022 gate for interface reference), `assertions.py` (Assertion type), `patterns.py` (Verdict type), `protocol.py` (DialecticalMessage type), `packet.py` (EvidencePacket), `fact.py` (Fact, EntityType), `provenance.py` (SourceType).
2. **Create** `miscalibration.py` with MiscalibrationDetector.
3. **Create** `test_miscalibration.py`. Run tests. Fix until all pass.
4. **Create** `claim_audit.py` with ClaimAuditor.
5. **Create** `test_claim_audit.py`. Run tests. Fix until all pass.
6. **Create** `miscalibration_analysis.py`.
7. **Create** `test_miscalibration_analysis.py`. Run tests. Fix until all pass.
8. **Run full test suite:** `python -m pytest ares/ -v`. Confirm zero regressions.
9. **Report:** total new tests, cumulative test count, any observations about the existing data structures that affected implementation.

---

## Key Interfaces to Use (Do Not Reinvent)

- **From `patterns.py`:** `Verdict` has `outcome` (VerdictOutcome enum) and `confidence` (float). Use these directly.
- **From `protocol.py`:** `DialecticalMessage` has `assertions` (tuple of Assertion), `confidence` (float), `phase` (Phase).
- **From `assertions.py`:** `Assertion` has `assertion_type` (AssertionType), `content` (str), `evidence` (tuple of fact IDs as strings), `confidence` (float).
- **From `packet.py`:** `EvidencePacket` has `facts` (tuple of Fact), and lookup methods. Use `packet_id`, `snapshot_id`.
- **From `fact.py`:** `Fact` has `fact_id` (str), `entity_type` (EntityType), `entity_id` (str).
- **From `provenance.py`:** Each Fact has `provenance` with `source_type` (SourceType).
- **From `escalation.py`:** `EscalationGate`, `EscalationDecision`, `EscalationResult` — reference for interface consistency.

**IMPORTANT:** Read these files before writing any code. The exact field names and types matter. Do not assume — verify against the actual frozen dataclass definitions.

---

## What Success Looks Like

When you're done, running `python -m pytest ares/ -v` should show **1,800+ tests passing with 0 failures**. The MiscalibrationDetector should correctly flag scenarios with evidence starvation, conflicting evidence, confidence-complexity mismatch, and narrow agent spread. The ClaimAuditor should decompose verdicts into per-claim support assessments. The analysis script should be ready to evaluate combined gate performance once live benchmark data is available.

---

**End of Session 023 execution prompt.**
