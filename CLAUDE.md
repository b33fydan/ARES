# ARES Development Project

## Context
Building ARES (Adversarial Reasoning Engine System) - a dialectical AI framework 
for cybersecurity defense using graph neural networks and multi-agent reasoning.

## Current Status
- Phase 0: Architecture Crystallization ✅ COMPLETE
- Phase 1: Minimal Viable Dialectic 🔄 IN PROGRESS
- Session 007: Memory Stream ✅ COMPLETE
- **Next: Session 008 — Multi-Turn Dialectical Cycles**

## Test Count: 861 passing

## Tech Stack
- Python 3.11, PyTorch, PyTorch Geometric
- NetworkX (Phase 0/1), Neo4j (Phase 2+)
- Redis for Memory Stream (future — currently InMemoryBackend)
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

### Completed (Sessions 001-007)
```
ares/
├── graph/schema.py                    # Graph structure (Session 001)
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
    ├── agents/
    │   ├── context.py                 # TurnContext, DataRequest (Session 003)
    │   ├── base.py                    # AgentBase with invariants (Session 003)
    │   ├── patterns.py                # AnomalyPattern, BenignExplanation, Verdict, VerdictOutcome (Session 004)
    │   ├── architect.py               # ArchitectAgent - THESIS phase (Session 004)
    │   ├── skeptic.py                 # SkepticAgent - ANTITHESIS phase (Session 004)
    │   └── oracle.py                  # OracleJudge (deterministic) + OracleNarrator (constrained) (Session 004)
    └── memory/
        ├── errors.py                  # MemoryStreamError, ChainIntegrityError, DuplicateEntryError
        ├── entry.py                   # MemoryEntry (frozen, hash-chained)
        ├── protocol.py                # MemoryBackend protocol
        ├── chain.py                   # HashChain, ChainLink, GENESIS_HASH
        ├── stream.py                  # MemoryStream (main API)
        └── backends/
            └── in_memory.py           # InMemoryBackend (Session 007, 103 tests)
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
| 007 | Memory Stream (tamper-evident persistence) | 103 | 861 |

## Current Entry Points

```python
# Single-turn (Session 006)
from ares.dialectic.coordinator.orchestrator import DialecticalOrchestrator
orchestrator = DialecticalOrchestrator()
result = orchestrator.run_cycle(packet)  # packet must be frozen

# Memory Stream (Session 007)
from ares.dialectic.memory.stream import MemoryStream
from ares.dialectic.memory.backends.in_memory import InMemoryBackend
stream = MemoryStream(backend=InMemoryBackend())
entry = stream.store(result)
assert stream.verify_chain_integrity()
```

## Development Commands
```powershell
# Activate venv
.\venv\Scripts\Activate.ps1

# Run all tests
pytest ares/ -v

# Run with coverage
pytest ares/ --cov=ares --cov-report=term-missing
```

## Git Workflow
- **NEVER commit directly to main**
- Main branch = stable, all tests passing, production-ready
- Create a session branch before each session: `session/{number}-{short-description}`
- Commit frequently to the session branch during work
- All 861+ tests must pass before merging to main
- Squash merge preferred for clean history (one commit per session)

```powershell
# Before session: create branch from main
git checkout main
git pull origin main
git checkout -b session/008-multi-turn

# During session: Claude Code commits to session branch
# (multiple commits fine — it's a working branch)

# After session: all tests green → merge to main
git checkout main
git merge --squash session/008-multi-turn
git commit -m "Session 008: Multi-Turn Dialectical Cycles - XX new tests (XXX total)"
git push origin main

# Clean up
git branch -d session/008-multi-turn
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
├── [✓] Memory Stream (Session 007)
├── [ ] Multi-Turn Dialectical Cycles (Session 008) ← NEXT
└── [ ] LLM integration (deterministic Judge preserved)
```

## Dan's Preferences
- Direct, technical communication
- Seek disconfirmation, honest feedback
- Document everything in session logs
- Test rigorously before moving forward
- Military-style acknowledgments (WILCO, SOLID, etc.)
