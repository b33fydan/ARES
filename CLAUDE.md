# ARES Development Project

## Context
Building ARES (Adversarial Reasoning Engine System) - a dialectical AI framework 
for cybersecurity defense using graph neural networks and multi-agent reasoning.

## Current Status
- Phase 0: Architecture Crystallization ✅ COMPLETE
- Phase 1: Minimal Viable Dialectic 🔄 IN PROGRESS
- Session 006: Coordinator Orchestration ✅ COMPLETE
- **Active: Session 007 - Memory Stream**

## Test Count: 758 passing

## Tech Stack
- Python 3.11, PyTorch, PyTorch Geometric
- NetworkX (Phase 0/1), Neo4j (Phase 2+)
- Redis for Memory Stream (planned)
- Windows + PowerShell + venv

## Code Location
C:\ares-phase-zero

## Architecture Principles
1. **Closed-world assumption** - Only frozen EvidencePackets as truth
2. **Hallucinations = Schema violations** - Not mysterious AI behavior
3. **Deterministic first, neural later** - Rule-based agents before LLM injection
4. **Autoimmune metaphor** - Self/non-self discrimination guides design
5. **Five invariants as bedrock** - Schema violations, not runtime checks

## Key Components

### Completed (Sessions 001-006)
```
ares/
├── graph/schema.py                    # Graph structure (Session 001, 110 tests)
└── dialectic/
    ├── evidence/
    │   ├── provenance.py              # Source tracking (Session 002)
    │   ├── fact.py                    # Immutable facts (Session 002)
    │   ├── packet.py                  # Frozen evidence container (Session 002)
    │   └── extractors/                # Telemetry parsing (Session 005)
    │       ├── protocol.py            # ExtractionResult, ExtractorProtocol
    │       └── windows.py             # 4624/4672/4688 event parsing
    ├── messages/
    │   ├── assertions.py              # ASSERT, LINK, ALT (Session 002)
    │   └── protocol.py                # DialecticalMessage, Phase (Session 002)
    ├── coordinator/
    │   ├── validator.py               # MessageValidator, ValidationError (Session 002, 26 tests)
    │   ├── cycle.py                   # CycleState, TerminationReason, DialecticalCycle (Session 002, 50 tests)
    │   ├── coordinator.py             # Coordinator (the Bouncer), SubmissionResult (Session 002, 33 tests)
    │   └── orchestrator.py            # DialecticalOrchestrator, CycleResult, CycleError (Session 006, 58 tests)
    └── agents/
        ├── context.py                 # TurnContext, DataRequest (Session 003)
        ├── base.py                    # AgentBase with invariants (Session 003)
        ├── patterns.py                # AnomalyPattern, BenignExplanation, Verdict, VerdictOutcome (Session 004)
        ├── architect.py               # ArchitectAgent - THESIS phase (Session 004)
        ├── skeptic.py                 # SkepticAgent - ANTITHESIS phase (Session 004)
        └── oracle.py                  # OracleJudge (deterministic) + OracleNarrator (constrained) (Session 004)
```

### Session Progress
| Session | Component | Tests | Cumulative |
|---------|-----------|-------|------------|
| 001 | Graph Schema | 110 | 110 |
| 002 | Evidence + Messages + Coordinator | 292 | 402 |
| 003 | Agent Foundation (TurnContext, AgentBase) | 144 | 546 |
| 004 | Concrete Agents (Architect, Skeptic, Oracle) + Integration | 134 | 570 |
| 005 | Evidence Extractors (Windows Event Log) | 130 | 700 |
| 006 | Coordinator Orchestration (DialecticalOrchestrator) | 58 | 758 |

## Current Entry Point

```python
from ares.dialectic.coordinator.orchestrator import DialecticalOrchestrator

orchestrator = DialecticalOrchestrator()
result = orchestrator.run_cycle(packet)  # packet must be frozen

result.verdict.outcome     # THREAT_CONFIRMED / THREAT_DISMISSED / INCONCLUSIVE
result.verdict.confidence  # 0.0 - 1.0
result.cycle_id            # UUID for audit trail
result.duration_ms         # Performance timing
```

## Session 007: Memory Stream

### Goal
Build tamper-evident persistence layer that stores CycleResults with hash chain 
integrity, enabling audit trails and cross-cycle correlation.

### Key Architectural Decision
The Memory Stream is a **PEER module** to the coordinator — not injected into the 
Orchestrator. The caller composes them. The Orchestrator (58 tests) remains 
untouched.

### Files to Create
```
ares/dialectic/memory/
├── __init__.py                # Public exports
├── errors.py                  # ALL memory exceptions (single source of truth)
├── protocol.py                # MemoryBackend protocol (abstract interface)
├── entry.py                   # MemoryEntry (frozen record with hash chain linkage)
├── chain.py                   # HashChain (tamper-evident audit log)
├── stream.py                  # MemoryStream (main API — composes backend + chain)
└── backends/
    ├── __init__.py
    └── in_memory.py           # InMemoryBackend (dict-based, for testing)

ares/dialectic/tests/memory/
├── __init__.py
├── test_entry.py              # MemoryEntry tests
├── test_chain.py              # HashChain tests
├── test_backend.py            # InMemoryBackend tests
├── test_stream.py             # MemoryStream integration tests
└── conftest.py                # Shared fixtures
```

### Existing Files (DO NOT MODIFY)
- All files under `ares/graph/`, `ares/dialectic/evidence/`, `ares/dialectic/messages/`, 
  `ares/dialectic/coordinator/`, `ares/dialectic/agents/`
- 758 tests must continue passing

## Development Commands
```powershell
# Activate venv
.\venv\Scripts\Activate.ps1

# Run all tests
pytest ares/ -v

# Run just memory tests
pytest ares/dialectic/tests/memory/ -v

# Run with coverage
pytest ares/ --cov=ares --cov-report=term-missing
```

## Git Workflow
- **NEVER commit directly to main**
- Main branch = stable, all tests passing, production-ready
- Create a session branch before each session: `session/{number}-{short-description}`
- Commit frequently to the session branch during work
- All 758+ tests must pass before merging to main
- Squash merge preferred for clean history (one commit per session)

```powershell
# Before session: create branch from main
git checkout main
git pull origin main
git checkout -b session/007-memory-stream

# During session: Claude Code commits to session branch
# (multiple commits fine — it's a working branch)

# After session: all tests green → merge to main
git checkout main
git merge --squash session/007-memory-stream
git commit -m "Session 007: Memory Stream - XX new tests (XXX total)"
git push origin main

# Clean up
git branch -d session/007-memory-stream
```

## Session Workflow
1. Start new chat in Claude.ai ARES project
2. Create session branch (see Git Workflow above)
3. Reference previous session number
4. State today's goal
5. Ask clarifying questions before coding
6. All commits go to session branch, NOT main
7. Merge to main only after all tests pass
8. Document decisions in session logs

## Phase 1 Roadmap
```
Phase One: Minimal Viable Dialectic
├── [✓] Real data integration (Session 005)
├── [✓] Coordinator orchestration (Session 006)
├── [ ] Memory Stream (Session 007) ← ACTIVE
└── [ ] LLM integration (deterministic Judge preserved)
```

## Dan's Preferences
- Direct, technical communication
- Seek disconfirmation, honest feedback
- Document everything in session logs
- Test rigorously before moving forward
- Military-style acknowledgments (WILCO, SOLID, etc.)