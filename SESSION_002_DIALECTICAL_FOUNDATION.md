# SESSION 002: Dialectical Foundation
**Date:** January 16, 2025
**Duration:** ~2 hours
**Status:** MILESTONE ACHIEVED

---

## Session Summary

Built the complete foundation for the hallucination-resistant dialectical reasoning engine. This session transformed theoretical architecture into tested, enforceable code.

---

## What We Accomplished

### 1. Architecture Hardening (Pre-Code)

Received and adopted critical external feedback that upgraded our design:

**Original Plan:**
- Freeform message content between agents
- Simple entity ID references
- No enforcement mechanism

**Hardened Architecture:**
- `assertions[]` - Machine-checkable claims (ASSERT, LINK, ALT types)
- `narrative` - Optional, LOW TRUST (never rely on it for logic)
- `unknowns[]` - Explicit uncertainty declaration
- `fact_ids` - Reference specific facts, not just entities
- **Closed-World Principle**: Agents can ONLY cite facts from EvidencePacket

Key insight adopted: *"This turns hallucinations into schema violations, not mysterious model moods."*

### 2. EvidencePacket System (98 tests)

The frozen reality that all agents must argue within.

**Files Created:**
```
ares/dialectic/evidence/
    __init__.py
    provenance.py    # SourceType enum + Provenance frozen dataclass
    fact.py          # EntityType enum + Fact frozen dataclass  
    packet.py        # EvidencePacket, TimeWindow, exceptions
```

**Key Features:**
- Immutable facts with SHA256 value hashes
- Full provenance tracking (source, parser version, raw reference)
- O(1) lookup by fact_id
- Indexed queries by entity, field, time range
- Snapshot ID for replay verification
- Once frozen, cannot be modified

### 3. DialecticalMessage Protocol (85 tests)

Structured communication that agents use to debate.

**Files Created:**
```
ares/dialectic/messages/
    __init__.py
    assertions.py    # AssertionType enum + Assertion frozen dataclass
    protocol.py      # MessageType, Phase, Priority, DialecticalMessage, MessageBuilder
```

**Key Features:**
- Three assertion types: ASSERT (condition), LINK (causal chain), ALT (alternative)
- MessageBuilder fluent API for constructing valid messages
- ValidationResult for detailed error reporting
- Confidence must be earned (0.0-1.0, validated)
- All assertions must reference existing fact_ids

### 4. Coordinator - The Bouncer (109 tests)

Central authority that enforces all rules.

**Files Created:**
```
ares/dialectic/coordinator/
    __init__.py
    validator.py     # MessageValidator, ValidationError, ErrorCode
    cycle.py         # CycleState, TerminationReason, CycleConfig, DialecticalCycle
    coordinator.py   # Coordinator, SubmissionResult, exceptions
```

**Key Features:**
- Validates every message against EvidencePacket
- Rejects messages with non-existent fact_ids
- Manages cycle state machine (THESIS → ANTITHESIS → SYNTHESIS)
- Enforces termination conditions:
  - Max turns exceeded
  - No new evidence introduced
  - Confidence stabilized
  - Insufficient data coverage
- Complete message logging for audit/replay

---

## Test Results

```
┌─────────────────────────────────┬───────┐
│           Component             │ Tests │
├─────────────────────────────────┼───────┤
│ Graph Schema (Session 001)      │ 110   │
├─────────────────────────────────┼───────┤
│ evidence/provenance             │  22   │
├─────────────────────────────────┼───────┤
│ evidence/fact                   │  31   │
├─────────────────────────────────┼───────┤
│ evidence/packet                 │  45   │
├─────────────────────────────────┼───────┤
│ messages/assertions             │  33   │
├─────────────────────────────────┼───────┤
│ messages/protocol               │  52   │
├─────────────────────────────────┼───────┤
│ coordinator/validator           │  26   │
├─────────────────────────────────┼───────┤
│ coordinator/cycle               │  50   │
├─────────────────────────────────┼───────┤
│ coordinator/coordinator         │  33   │
├─────────────────────────────────┼───────┤
│ TOTAL                           │ 402   │
└─────────────────────────────────┴───────┘
```

---

## Architecture Diagram (Current State)

```
┌─────────────────────────────────────────────────────────────────┐
│                    ARES DIALECTICAL ENGINE                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────────┐                                           │
│  │ SECURITY GRAPH  │ (Session 001 - 110 tests)                 │
│  │  Nodes, Edges   │                                           │
│  └────────┬────────┘                                           │
│           │                                                     │
│           ▼                                                     │
│  ┌─────────────────┐                                           │
│  │ EVIDENCE PACKET │ (Session 002 - 98 tests)                  │
│  │  Frozen Facts   │                                           │
│  │  Provenance     │                                           │
│  │  Immutable      │                                           │
│  └────────┬────────┘                                           │
│           │                                                     │
│           ▼                                                     │
│  ┌─────────────────┐    ┌──────────────────────┐               │
│  │   COORDINATOR   │◄──►│ DIALECTICAL MESSAGE  │               │
│  │    (Bouncer)    │    │  - assertions[]      │               │
│  │                 │    │  - unknowns[]        │               │
│  │  - Validates    │    │  - confidence        │               │
│  │  - Routes       │    │  - narrative (low    │               │
│  │  - Enforces     │    │    trust)            │               │
│  │  - Terminates   │    └──────────────────────┘               │
│  └────────┬────────┘    (Session 002 - 85 tests)               │
│           │             (Coordinator - 109 tests)              │
│           │                                                     │
│           ▼                                                     │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                    AGENTS (Tomorrow)                    │   │
│  │                                                         │   │
│  │   ┌──────────┐    ┌──────────┐    ┌───────────────┐   │   │
│  │   │ARCHITECT │───►│ SKEPTIC  │───►│    ORACLE     │   │   │
│  │   │ (Thesis) │    │(Antithe.)│    │ ┌───────────┐ │   │   │
│  │   │          │    │          │    │ │   JUDGE   │ │   │   │
│  │   │ Proposes │    │Challenges│    │ │(determin.)│ │   │   │
│  │   │ threats  │    │ claims   │    │ ├───────────┤ │   │   │
│  │   │          │    │          │    │ │ NARRATOR  │ │   │   │
│  │   │          │    │          │    │ │(explains) │ │   │   │
│  │   └──────────┘    └──────────┘    │ └───────────┘ │   │   │
│  │                                    └───────────────┘   │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Key Design Decisions Made

### 1. Closed-World Debate
Agents cannot invent facts. They can only:
- CITE facts from EvidencePacket
- COMBINE facts into hypotheses
- REQUEST additional facts
- ADMIT uncertainty

### 2. Oracle Split Architecture
- **Judge** (deterministic): Computes verdict from assertions + scoring rules
- **Narrator** (LLM): Writes explanation AFTER verdict is locked, must cite fact_ids

### 3. Multi-Turn Rules
- Default: single turn (Architect → Skeptic → Oracle)
- Extra rounds allowed ONLY if new evidence introduced
- Terminates if confidence stabilizes or max turns hit
- Prevents "self-hypnosis" where agents agree on wrong answer

### 4. Evidence Granularity
- In messages: `fact_id` references with entity, field, value_hash
- Full values stored in EvidencePacket, referenced in-band
- Prevents context bloat while maintaining verifiability

---

## Tomorrow's Continuation: SESSION 003

### Primary Goal: Build the Agents

**Implementation Order:**

1. **Agent Base Class** (`ares/dialectic/agents/base.py`)
   - Context management (bounded working memory)
   - Message composition via MessageBuilder
   - Self-validation before submission
   - Consolidation hooks for memory stream
   - Health monitoring (context_pressure, should_consolidate)

2. **Architect Agent** (`ares/dialectic/agents/architect.py`)
   - Observes EvidencePacket
   - Identifies anomalies/patterns
   - Composes HYPOTHESIS messages with assertions
   - Role: THESIS

3. **Skeptic Agent** (`ares/dialectic/agents/skeptic.py`)
   - Receives Architect's claims
   - Challenges with REBUTTAL messages
   - Proposes ALT (alternative) explanations
   - Role: ANTITHESIS

4. **Oracle Agent** (`ares/dialectic/agents/oracle.py`)
   - Split into Judge + Narrator
   - Judge: Deterministic scoring of assertions
   - Narrator: Human explanation (constrained to cite facts)
   - Role: SYNTHESIS

### Secondary Goal: Integration Testing

Create end-to-end test that:
1. Builds graph with simulated threat
2. Extracts EvidencePacket
3. Coordinator starts cycle
4. Architect observes and proposes
5. Skeptic challenges
6. Oracle resolves
7. Verdict is produced

### Stretch Goal: Extractor

`ares/dialectic/evidence/extractor.py`
- Pulls facts from existing graph schema
- Bridges Session 001 (graph) with Session 002 (dialectic)

---

## Claude Code Prompt for Session 003 Start

```
Continuing ARES build. Coordinator complete (292 tests passing in dialectic/).

Session 002 accomplished:
- EvidencePacket (frozen facts, closed world)
- DialecticalMessage (structured assertions)
- Coordinator (validates, routes, enforces)

Now building: Agents that use this infrastructure to reason about threats.

Project location: C:\ares-phase-zero
Run tests: python -m pytest ares/dialectic/tests/ -v

Ready to implement Agent Base Class. Awaiting specifications.
```

---

## Files Modified/Created This Session

```
ares/dialectic/
├── __init__.py
├── evidence/
│   ├── __init__.py
│   ├── provenance.py
│   ├── fact.py
│   └── packet.py
├── messages/
│   ├── __init__.py
│   ├── assertions.py
│   └── protocol.py
├── coordinator/
│   ├── __init__.py
│   ├── validator.py
│   ├── cycle.py
│   └── coordinator.py
└── tests/
    ├── __init__.py
    ├── evidence/
    │   ├── __init__.py
    │   ├── test_provenance.py
    │   ├── test_fact.py
    │   └── test_packet.py
    ├── messages/
    │   ├── __init__.py
    │   ├── test_assertions.py
    │   └── test_protocol.py
    └── coordinator/
        ├── __init__.py
        ├── test_validator.py
        ├── test_cycle.py
        └── test_coordinator.py
```

---

## Reflections

The external feedback we received and adopted was invaluable. The original "agents pass messages" design would have worked, but it would have been vulnerable to the same hallucination problems that plague naive LLM systems. By forcing structured assertions with fact references and implementing the Coordinator as an enforcement layer, we've created something genuinely different.

The immune system metaphor continues to guide well:
- **Facts** are like antigens - specific, identifiable, verifiable
- **Assertions** are like antibody bindings - claims that reference specific evidence
- **Coordinator** is like the thymus - filters out self-reactive (hallucinated) responses
- **Agents** are like immune cells - specialized roles working in concert

Tomorrow we give these cells their behavior.

---

## End of Session 002

**Tests passing:** 402
**Code written:** ~1,500 lines
**Architecture:** Hardened and tested
**Next session:** Agents come alive
