# ARES Development Project

## Context
Building ARES (Adversarial Reasoning Engine System) - a dialectical AI framework 
for cybersecurity defense using graph neural networks and multi-agent reasoning.

## Current Status
- Phase 0: Architecture Crystallization ✅ COMPLETE
- Phase 1: Minimal Viable Dialectic 🔄 IN PROGRESS
- Session 005: Evidence Extractors ✅ COMPLETE
- Next: Session 006 - Coordinator Orchestration

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
    │   └── protocol.py                # DialecticalMessage (Session 002)
    ├── coordinator/
    │   ├── validator.py               # Message validation (Session 002)
    │   └── cycle.py                   # Cycle state machine (Session 002)
    └── agents/
        ├── context.py                 # TurnContext (Session 003)
        ├── base.py                    # AgentBase with invariants (Session 003)
        ├── patterns.py                # AnomalyPattern, Verdict (Session 004)
        ├── architect.py               # THESIS phase (Session 004)
        ├── skeptic.py                 # ANTITHESIS phase (Session 004)
        └── oracle.py                  # SYNTHESIS phase (Session 004)
```

### Session Progress
| Session | Component | Tests | Cumulative |
|---------|-----------|-------|------------|
| 001 | Graph Schema | 110 | 110 |
| 002 | Evidence + Messages + Coordinator | 292 | 402 |
| 003 | Agent Foundation | 144 | 546 |
| 004 | Concrete Agents | 134 | 570 |
| 005 | Evidence Extractors | 130 | 700 |

## Development Commands
```powershell
# Activate venv
.\venv\Scripts\Activate.ps1

# Run all tests
pytest ares/ -v

# Run specific test file
pytest ares/dialectic/tests/evidence/extractors/ -v

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
├── [ ] Coordinator orchestration (Session 006) ← NEXT
├── [ ] Memory Stream (Redis-backed persistence)
└── [ ] LLM integration (deterministic Judge preserved)
```

## Dan's Preferences
- Direct, technical communication
- Seek disconfirmation, honest feedback
- Document everything in session logs
- Test rigorously before moving forward
- Military-style acknowledgments (WILCO, SOLID, etc.)
