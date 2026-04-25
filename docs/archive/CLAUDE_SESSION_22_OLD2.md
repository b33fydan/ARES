**ARES SESSION 023**

Miscalibration Detector + Per-Claim Evidence Audit

Strategy Brief + Claude Code Execution Prompt

|Date|March 26, 2026|
|-|-|
|**Phase**|Phase 3 — Selective Escalation Architecture (Session 2 of 4)|
|**Tests (pre)**|1,736 passed, 65 skipped, 0 failed|
|**Branch**|session/023-miscalibration-detector|

# **Where We Are**

## **Session 022 Results**

Session 022 built the EscalationGate and ran the first full benchmark on the expanded 33-scenario corpus. Key numbers:

|Mode|Accuracy (N=33)|Cost|
|-|-|-|
|**Single-Turn**|78.8%|$0.50|
|MT Original|75.8%|$1.10|
|MT Anchored|75.8%|$1.47|

## **The Critical Finding**

The EscalationGate at \[0.35, 0.70] achieves the target 18.2% escalation rate. But it captures only 1 of 7 errors (14%). All 7 errors are MISCALIBRATED — the system is confidently wrong, not uncertainly wrong.

The gate detects uncertainty. The actual failure mode is overconfidence. Two different diseases requiring two different treatments.

This changes the Session 023 plan. The original design assumed errors would cluster in the uncertainty band and per-claim debate on escalated cases would catch them. They don’t. Session 023 must address the actual failure mode: how do you catch a system that is confidently wrong?

## **The Accuracy Gap Shift**

On N=18, single-turn led multi-turn by 17 points (83.3% vs 66.7%). On N=33, that gap shrank to 3 points (78.8% vs 75.8%). The new scenarios — heavily weighted toward AMBIGUOUS and MIXED\_SIGNALS — favor multi-turn. This is the first empirical signal that evidence complexity affects the debate mechanism’s relative performance.

# **What Session 023 Builds**

Two complementary components that form the overconfidence detection layer:

## **Component 1: MiscalibrationDetector (Deterministic Pre-Screen)**

A rule-based, zero-LLM-cost detector that flags verdicts exhibiting known miscalibration patterns. This is the cheap trigger — it runs on every single-turn output and identifies candidates for deeper inspection.

### **Detection Patterns**

Pattern 1 — Evidence Starvation: High confidence (≥0.70) with fewer than 3 supporting facts cited. A verdict built on thin evidence shouldn’t be confident.

Pattern 2 — Evidence Conflict: High confidence with conflicting evidence types present in the packet (e.g., both login-success and login-failure facts for the same entity). Confident verdicts should not exist alongside contradictory signals.

Pattern 3 — Confidence-Complexity Mismatch: High confidence on a scenario with 4+ distinct entity types or 3+ evidence source types. Complex scenarios with simple answers deserve scrutiny.

Pattern 4 — Narrow Spread: Architect and Skeptic final confidences within 0.15 of each other AND both above 0.60. When both agents strongly agree, it may indicate groupthink rather than genuine convergence.

### **Output**

MiscalibrationResult frozen dataclass containing: flagged (bool), patterns\_triggered (tuple of pattern names), risk\_score (float 0.0–1.0 based on pattern count and severity), recommendation (PASS or INSPECT).

## **Component 2: ClaimAuditor (Per-Claim Evidence Audit)**

When the MiscalibrationDetector flags a verdict for INSPECT, the ClaimAuditor decomposes the verdict into individual claims and checks each claim’s evidence support. This is the structural decomposition that reveals whether a confident verdict is justified or hollow.

### **Audit Process**

Step 1 — Claim Extraction: Parse the Architect’s assertions from the DialecticalMessage into individual claims (each Assertion already exists as a frozen dataclass).

Step 2 — Evidence Linking: For each claim, count the supporting facts from the EvidencePacket that are cited in the assertion’s evidence. Cross-reference against the packet’s fact IDs.

Step 3 — Support Scoring: Each claim gets a support score. Claims with zero cited evidence are UNSUPPORTED. Claims with 1 fact are WEAK. Claims with 2+ facts are SUPPORTED.

Step 4 — Verdict Assessment: If more than half the claims are UNSUPPORTED or WEAK, the verdict is MISCALIBRATED regardless of the overall confidence number.

### **Output**

ClaimAuditResult frozen dataclass containing: claims\_total (int), claims\_supported (int), claims\_weak (int), claims\_unsupported (int), audit\_verdict (CONFIRMED or MISCALIBRATED), claim\_details (tuple of per-claim results).

# **Architecture Integration**

The two components slot into the existing pipeline as a post-processing layer after single-turn runs:

Single-Turn Verdict → MiscalibrationDetector → \[PASS: accept verdict] or \[INSPECT: ClaimAuditor] → \[CONFIRMED: accept] or \[MISCALIBRATED: flag for escalation]

This creates a two-gate selective escalation architecture:

|Gate|Detects|Cost|From Session|
|-|-|-|-|
|**EscalationGate**|Uncertainty|Zero (rule-based)|022|
|**MiscalibrationDetector**|Overconfidence|Zero (rule-based)|023|
|**ClaimAuditor**|Hollow confidence|Low (no LLM)|023|

Combined, these gates address both failure modes: the EscalationGate catches scenarios where the system doesn’t know, and the MiscalibrationDetector + ClaimAuditor catch scenarios where the system thinks it knows but doesn’t.

# **Session 023 Success Criteria**

|Metric|Target|
|-|-|
|MiscalibrationDetector built|4 detection patterns implemented|
|ClaimAuditor built|Full audit pipeline operational|
|New tests|60+ (target 1,800+ cumulative)|
|Regressions|Zero|
|Existing tests|1,736 pass unchanged|
|Error capture rate (combined gates)|Measured (target: >50% of 7 errors)|
|No existing files modified|Strict|

# **Claude Code Execution Prompt**

*The following is the prompt to paste into Claude Code for Session 023 execution.*

## **SESSION 023: Miscalibration Detector + Per-Claim Evidence Audit**

### **Claude Code Execution Prompt**

## **Context**

Continuing ARES build. Phase 3 (Selective Escalation Architecture), Session 2 of 4.

Session 022 accomplished: EscalationGate built and tested (50 tests), full 33-scenario benchmark runner, escalation threshold sweep analysis (23 tests). 1,736 tests total, zero regressions.

Critical finding from Session 022: The EscalationGate at \[0.35, 0.70] captures only 14% of errors. All 7 errors are MISCALIBRATED (confidently wrong), not uncertain. The gate solves a different problem than the one we have.

Session 023 goal: Build a miscalibration detection layer that catches overconfident wrong answers. Two components: (1) a deterministic rule-based pre-screen that flags suspicious confidence patterns, and (2) a per-claim evidence auditor that decomposes flagged verdicts and checks evidence support per claim.

This session is FULLY DETERMINISTIC — no live LLM calls. All testing uses rule-based strategies and existing benchmark data structures.

**Project location:** C:\\ares-phase-zero

**Run tests:** python -m pytest ares/ -v

**Git branch:** session/023-miscalibration-detector

## **CRITICAL CONSTRAINTS**

1\. DO NOT MODIFY ANY EXISTING FILES. Every file listed below with “DO NOT MODIFY” must not be touched. All 1,736 existing tests must pass unchanged.

2\. All new dataclasses must be frozen. @dataclass(frozen=True) everywhere.

3\. No live LLM calls. This session uses only rule-based strategies and existing data structures.

4\. Type hints on everything. Docstrings on all public methods.

5\. Test naming convention: test\_<what>\_<condition>\_<expected>

6\. New files only. Zero modifications to existing code.

## **Existing File Tree (ALL marked DO NOT MODIFY)**

ares/

├── graph/schema.py                                  # Session 001 — DO NOT MODIFY

└── dialectic/

&#x20;   ├── evidence/

    │   ├── provenance.py                            \\# DO NOT MODIFY

    │   ├── fact.py                                  \\# DO NOT MODIFY

    │   ├── packet.py                                \\# DO NOT MODIFY

    │   └── extractors/

    │       ├── protocol.py                          \\# DO NOT MODIFY

    │       ├── windows.py                           \\# DO NOT MODIFY

    │       ├── syslog.py                            \\# DO NOT MODIFY

    │       └── netflow.py                           \\# DO NOT MODIFY

    ├── messages/

    │   ├── assertions.py                            \\# DO NOT MODIFY

    │   └── protocol.py                              \\# DO NOT MODIFY

    ├── coordinator/

    │   ├── validator.py                             \\# DO NOT MODIFY

    │   ├── cycle.py                                 \\# DO NOT MODIFY

    │   ├── coordinator.py                           \\# DO NOT MODIFY

    │   ├── orchestrator.py                          \\# DO NOT MODIFY

    │   └── escalation.py                            \\# Session 022 — DO NOT MODIFY

    ├── agents/

    │   ├── context.py                               \\# DO NOT MODIFY

    │   ├── base.py                                  \\# DO NOT MODIFY

    │   ├── patterns.py                              \\# DO NOT MODIFY

    │   ├── architect.py                             \\# DO NOT MODIFY

    │   ├── skeptic.py                               \\# DO NOT MODIFY

    │   ├── oracle.py                                \\# DO NOT MODIFY

    │   └── strategies/                              \\# ALL files DO NOT MODIFY

    ├── memory/                                          \\# ALL files DO NOT MODIFY

    └── scripts/

        ├── scenarios.py                             \\# DO NOT MODIFY

        ├── expanded\\\_scenarios.py                    \\# Session 021 — DO NOT MODIFY

        ├── benchmark\\\_analysis.py                    \\# Session 021 — DO NOT MODIFY

        ├── run\\\_anchored\\\_benchmark.py                \\# DO NOT MODIFY

        ├── run\\\_full\\\_benchmark.py                    \\# Session 022 — DO NOT MODIFY

        └── escalation\\\_analysis.py                   \\# Session 022 — DO NOT MODIFY


## **Files to Create**

### **File 1: ares/dialectic/coordinator/miscalibration.py**

The MiscalibrationDetector and its output types.

Required types (all frozen dataclasses):

MiscalibrationPattern — Enum or frozen dataclass identifying which pattern triggered: EVIDENCE\_STARVATION, EVIDENCE\_CONFLICT, CONFIDENCE\_COMPLEXITY\_MISMATCH, NARROW\_SPREAD.

MiscalibrationResult — Frozen dataclass with fields: flagged (bool), patterns\_triggered (tuple\[MiscalibrationPattern, ...]), risk\_score (float, 0.0–1.0), recommendation (PASS or INSPECT), details (tuple of human-readable strings explaining each triggered pattern).

MiscalibrationDetector — Class that takes configuration thresholds and exposes a single detect() method. Constructor accepts: min\_facts\_for\_confidence (int, default 3), confidence\_threshold (float, default 0.70), conflict\_indicators (tuple of entity-type pairs that constitute conflicts), complexity\_entity\_threshold (int, default 4), complexity\_source\_threshold (int, default 3), spread\_threshold (float, default 0.15), spread\_minimum (float, default 0.60).

The detect() method signature: detect(verdict: Verdict, architect\_message: DialecticalMessage, skeptic\_message: DialecticalMessage, packet: EvidencePacket) -> MiscalibrationResult

Detection logic for each pattern:

EVIDENCE\_STARVATION: verdict.confidence >= confidence\_threshold AND len(architect\_message.assertions) > 0 AND total cited facts across all assertions < min\_facts\_for\_confidence.

EVIDENCE\_CONFLICT: verdict.confidence >= confidence\_threshold AND packet contains facts with conflicting entity types (e.g., both authentication\_success and authentication\_failure for overlapping entities). Use the fact’s entity\_type and entity\_id fields. Define a default set of conflict pairs.

CONFIDENCE\_COMPLEXITY\_MISMATCH: verdict.confidence >= confidence\_threshold AND (number of distinct entity\_types in packet >= complexity\_entity\_threshold OR number of distinct source\_types in packet provenance >= complexity\_source\_threshold).

NARROW\_SPREAD: abs(architect\_confidence - skeptic\_confidence) <= spread\_threshold AND both >= spread\_minimum. Extract confidences from the message confidence fields.

risk\_score calculation: count of triggered patterns / 4.0 (simple, can be refined later).

### **File 2: ares/dialectic/coordinator/claim\_audit.py**

The ClaimAuditor and its output types.

Required types (all frozen dataclasses):

ClaimSupport — Enum: SUPPORTED (2+ facts), WEAK (1 fact), UNSUPPORTED (0 facts).

ClaimAuditDetail — Frozen dataclass with fields: assertion\_type (AssertionType from existing assertions.py), claim\_text (str, the assertion content), cited\_fact\_ids (tuple\[str, ...]), support\_level (ClaimSupport), fact\_count (int).

ClaimAuditResult — Frozen dataclass with fields: claims\_total (int), claims\_supported (int), claims\_weak (int), claims\_unsupported (int), audit\_verdict (CONFIRMED or MISCALIBRATED), claim\_details (tuple\[ClaimAuditDetail, ...]), miscalibration\_ratio (float, proportion of WEAK + UNSUPPORTED claims).

ClaimAuditor — Class with configurable miscalibration\_threshold (float, default 0.5 — if more than half of claims are weak or unsupported, verdict is MISCALIBRATED). Single method: audit(architect\_message: DialecticalMessage, packet: EvidencePacket) -> ClaimAuditResult.

Audit logic: iterate over architect\_message.assertions. For each assertion, check how many of its cited fact\_ids exist in the packet (using packet.get\_fact() or similar lookup). Classify each assertion’s support level. Compute aggregate metrics. Set audit\_verdict based on miscalibration\_ratio vs threshold.

### **File 3: ares/dialectic/scripts/miscalibration\_analysis.py**

Analysis script for evaluating combined gate performance across the full corpus.

Functions to implement:

run\_combined\_gate\_analysis(results) — Takes benchmark results, runs both EscalationGate and MiscalibrationDetector on each, reports: total errors caught by EscalationGate only, by MiscalibrationDetector only, by both, by neither. Computes combined error capture rate.

format\_combined\_report(analysis) — Produces a formatted string report showing per-scenario gate decisions and combined capture statistics.

get\_miscalibration\_patterns\_summary(results) — Aggregates which patterns trigger most frequently across the corpus.

### **File 4: ares/dialectic/tests/coordinator/test\_miscalibration.py**

Comprehensive tests for MiscalibrationDetector. Target: 35+ tests.

Test categories: construction and defaults, each detection pattern in isolation, pattern combinations, boundary conditions (exactly at thresholds), risk score calculation, recommendation logic (PASS vs INSPECT), immutability of all output types, empty/minimal inputs, integration with existing Verdict/DialecticalMessage/EvidencePacket types.

### **File 5: ares/dialectic/tests/coordinator/test\_claim\_audit.py**

Comprehensive tests for ClaimAuditor. Target: 25+ tests.

Test categories: construction and defaults, support level classification (SUPPORTED/WEAK/UNSUPPORTED), audit verdict logic (threshold behavior), edge cases (zero assertions, all supported, all unsupported), miscalibration\_ratio calculation, immutability of all output types, integration with existing Assertion/EvidencePacket types.

### **File 6: ares/dialectic/tests/scripts/test\_miscalibration\_analysis.py**

Tests for the analysis script. Target: 10+ tests.

Test categories: combined gate analysis logic, report formatting, pattern summary aggregation, edge cases (no errors, all errors caught).

## **Execution Order**

1\. Read existing files: escalation.py (Session 022 gate for interface reference), assertions.py (Assertion type), patterns.py (Verdict type), protocol.py (DialecticalMessage type), packet.py (EvidencePacket), fact.py (Fact, EntityType), provenance.py (SourceType).

2\. Create miscalibration.py with MiscalibrationDetector.

3\. Create test\_miscalibration.py. Run tests. Fix until all pass.

4\. Create claim\_audit.py with ClaimAuditor.

5\. Create test\_claim\_audit.py. Run tests. Fix until all pass.

6\. Create miscalibration\_analysis.py.

7\. Create test\_miscalibration\_analysis.py. Run tests. Fix until all pass.

8\. Run full test suite: python -m pytest ares/ -v. Confirm zero regressions.

9\. Report: total new tests, cumulative test count, any observations about the existing data structures that affected implementation.

## **Key Interfaces to Use (Do Not Reinvent)**

From patterns.py: Verdict has outcome (VerdictOutcome enum) and confidence (float). Use these directly.

From protocol.py: DialecticalMessage has assertions (tuple of Assertion), confidence (float), phase (Phase).

From assertions.py: Assertion has assertion\_type (AssertionType), content (str), evidence (tuple of fact IDs as strings), confidence (float).

From packet.py: EvidencePacket has facts (tuple of Fact), and lookup methods. Use packet\_id, snapshot\_id.

From fact.py: Fact has fact\_id (str), entity\_type (EntityType), entity\_id (str).

From provenance.py: Each Fact has provenance with source\_type (SourceType).

From escalation.py: EscalationGate, EscalationDecision, EscalationResult — reference for interface consistency.

IMPORTANT: Read these files before writing any code. The exact field names and types matter. Do not assume — verify against the actual frozen dataclass definitions.

## **What Success Looks Like**

When you’re done, running python -m pytest ares/ -v should show 1,800+ tests passing with 0 failures. The MiscalibrationDetector should correctly flag scenarios with evidence starvation, conflicting evidence, confidence-complexity mismatch, and narrow agent spread. The ClaimAuditor should decompose verdicts into per-claim support assessments. The analysis script should be ready to evaluate combined gate performance once live benchmark data is available.

**End of Session 023 execution prompt.**

# **CLAUDE\_SESSION\_023.md**

*Updated project brief for Claude Code. Copy this content into CLAUDE.md before starting the session.*

## **ARES Development Project**

### **Context**

Building ARES (Adversarial Reasoning Engine System) — a dialectical AI framework for cybersecurity defense. Phase 3: Selective Escalation Architecture.

### **Current Status**

Phase 3, Session 023. 1,736 tests passing across 22 sessions, zero regressions. Escalation gate built (Session 022). Expanded corpus of 33 scenarios operational. Single-turn accuracy: 78.8%. Multi-turn: 75.8%. Critical finding: errors are MISCALIBRATED (confidently wrong), not uncertain.

### **Tech Stack**

Python 3.11, Windows + PowerShell + venv. Anthropic API (Claude Sonnet) for LLM strategies. Redis for Memory Stream.

### **Code Location**

C:\\ares-phase-zero

### **Architecture Principles**

1\. Closed-world assumption — Only frozen EvidencePackets as truth

2\. Hallucinations = Schema violations — Not mysterious AI behavior

3\. All dataclasses frozen — Immutability enforced at the type level

4\. New files only — Never modify existing files

5\. Zero regressions — Non-negotiable across all sessions

6\. Measurement before optimization — Every change is benchmarked

### **Session 022 Key Result**

EscalationGate at \[0.35, 0.70] captures uncertainty but not overconfidence. 14% error capture rate. All 7 errors are MISCALIBRATED. Session 023 builds the complementary overconfidence detection layer.

### **Development Commands**

\# Activate venv

.\\venv\\Scripts\\Activate.ps1

\# Run tests

python -m pytest ares/ -v

\# Run specific test file

python -m pytest ares/dialectic/tests/coordinator/test\_miscalibration.py -v

### **Session Progress**

|Session|Component|Tests|Cumulative|
|-|-|-|-|
|001–010|Phase 1: Core Architecture|1,104|1,104|
|011–014|Phase 2: Scenarios, Benchmarks, Prompts|304|1,408|
|016–020|Extractors + Anchored Debate|187|1,595|
|021|Corpus Expansion (18→33 scenarios)|68|1,663|
|022|EscalationGate + Full Benchmark|73|1,736|
|**023**|**MiscalibrationDetector + ClaimAuditor**|TBD|TBD|



