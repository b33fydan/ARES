# ARES Development Project

## Context
Building ARES (Adversarial Reasoning Engine System) - a dialectical AI framework 
for cybersecurity defense using graph neural networks and multi-agent reasoning.

## Current Status
- Phase 0: Architecture Crystallization ✅ COMPLETE
- Phase 1: Minimal Viable Dialectic 🔄 IN PROGRESS
- Session 005: Evidence Extractors ✅ COMPLETE
- **Active: Session 006 - Coordinator Orchestration**

## Test Count: 700 passing

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

### Completed (Sessions 001-005)
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
    │   └── coordinator.py             # Coordinator (the Bouncer), SubmissionResult (Session 002, 33 tests)
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

## Session 006: Coordinator Orchestration

### Goal
Build `DialecticalOrchestrator` - a single entry point that manages the entire 
THESIS → ANTITHESIS → SYNTHESIS cycle automatically.

### Key Architectural Decision
The Orchestrator is a **FACADE** that composes existing components. It does NOT 
replace the existing Coordinator (the Bouncer). The existing `coordinator.py` has 
33 tests for message validation and routing. The new `orchestrator.py` sits above 
it, automating the agent wiring and cycle management.

### Files to Create
```
ares/dialectic/coordinator/
    orchestrator.py            # NEW - DialecticalOrchestrator, CycleResult, CycleError

ares/dialectic/tests/coordinator/
    test_orchestrator.py       # NEW - ~50 orchestrator tests
```

### Existing Coordinator Files (DO NOT recreate)
- `coordinator/validator.py` - MessageValidator (26 tests)
- `coordinator/cycle.py` - DialecticalCycle state machine (50 tests)
- `coordinator/coordinator.py` - Coordinator bouncer (33 tests)

### Agent Wiring Sequence (what the Orchestrator automates)
```python
# This is the manual sequence the Orchestrator must automate:
architect = ArchitectAgent(agent_id="arch-001")
skeptic = SkepticAgent(agent_id="skep-001")

# THESIS
architect.observe(packet)
arch_context = TurnContext(phase=Phase.THESIS, turn_number=1, cycle_id=..., packet_id=..., snapshot_id=...)
arch_result = architect.act(arch_context)

# ANTITHESIS
skeptic.observe(packet)
skeptic.receive(arch_result.message)
skep_context = TurnContext(phase=Phase.ANTITHESIS, turn_number=2, cycle_id=..., packet_id=..., snapshot_id=...)
skep_result = skeptic.act(skep_context)

# SYNTHESIS
verdict = OracleJudge.compute_verdict(arch_result.message, skep_result.message, packet)
narrator = OracleNarrator(agent_id="oracle-001", verdict=verdict)
narrator.observe(packet)
narr_context = TurnContext(phase=Phase.SYNTHESIS, turn_number=3, cycle_id=..., packet_id=..., snapshot_id=...)
narr_result = narrator.act(narr_context)
```

## Development Commands
```powershell
# Activate venv
.\venv\Scripts\Activate.ps1

# Run all tests
pytest ares/ -v

# Run just orchestrator tests
pytest ares/dialectic/tests/coordinator/test_orchestrator.py -v

# Run with coverage
pytest ares/ --cov=ares --cov-report=term-missing
```

## Session Workflow
1. Start new chat in Claude.ai ARES project
2. Reference previous session number
3. State today's goal
4. Ask clarifying questions before coding
5. Document decisions in session logs

## Phase 1 Roadmap
```
Phase One: Minimal Viable Dialectic
├── [✓] Real data integration (Session 005)
├── [ ] Coordinator orchestration (Session 006) ← ACTIVE
├── [ ] Memory Stream (Redis-backed persistence)
└── [ ] LLM integration (deterministic Judge preserved)
```

## Dan's Preferences
- Direct, technical communication
- Seek disconfirmation, honest feedback
- Document everything in session logs
- Test rigorously before moving forward
- Military-style acknowledgments (WILCO, SOLID, etc.)
