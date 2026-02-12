# ARES Development Project

## Context
Building ARES (Adversarial Reasoning Engine System) - a dialectical AI framework 
for cybersecurity defense using graph neural networks and multi-agent reasoning.

## Current Status
- Phase 0: Architecture Crystallization ✅ COMPLETE
- Phase 1: Minimal Viable Dialectic 🔄 IN PROGRESS
- Session 009: LLM Infrastructure Layer ✅ COMPLETE
- **Next: Session 010 — Live LLM Integration Harness + Observability**

## Test Count: 1040 passing

## Tech Stack
- Python 3.11, PyTorch, PyTorch Geometric
- NetworkX (Phase 0/1), Neo4j (Phase 2+)
- Redis for Memory Stream (future — currently InMemoryBackend)
- Anthropic API (Claude) for LLM integration — `anthropic` SDK installed
- Windows + PowerShell + venv

## Code Location
C:\ares-phase-zero

## Architecture Principles
1. **Closed-world assumption** - Only frozen EvidencePackets as truth
2. **Hallucinations = Schema violations** - Not mysterious AI behavior
3. **Deterministic first, neural later** - Rule-based agents before LLM injection
4. **Autoimmune metaphor** - Self/non-self discrimination guides design
5. **Five invariants as bedrock** - Schema violations, not runtime checks
6. **Strategy Pattern for reasoning** - Pluggable backends (rule-based default, LLM optional)

## Key Components

### Completed (Sessions 001-009)
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
    │   ├── orchestrator.py            # DialecticalOrchestrator, CycleResult, CycleError (Session 006, 58 tests)
    │   └── multi_turn.py              # run_multi_turn_cycle(), MultiTurnCycleResult (Session 008, 65 tests)
    ├── agents/
    │   ├── context.py                 # TurnContext, DataRequest (Session 003)
    │   ├── base.py                    # AgentBase with invariants (Session 003)
    │   ├── patterns.py                # AnomalyPattern, BenignExplanation, Verdict, VerdictOutcome (Session 004)
    │   ├── architect.py               # ArchitectAgent - THESIS phase (Session 004, strategy-enabled Session 009)
    │   ├── skeptic.py                 # SkepticAgent - ANTITHESIS phase (Session 004, strategy-enabled Session 009)
    │   ├── oracle.py                  # OracleJudge (deterministic) + OracleNarrator (Session 004, strategy-enabled Session 009)
    │   └── strategies/                # Pluggable reasoning backends (Session 009)
    │       ├── protocol.py            # ThreatAnalyzer, ExplanationFinder, NarrativeGenerator
    │       ├── rule_based.py          # RuleBasedThreatAnalyzer, RuleBasedExplanationFinder, RuleBasedNarrativeGenerator
    │       ├── llm_strategy.py        # LLMThreatAnalyzer, LLMExplanationFinder, LLMNarrativeGenerator
    │       ├── client.py              # AnthropicClient, LLMResponse
    │       └── prompts.py             # System prompt templates (closed-world enforced)
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
| 008 | Multi-Turn Dialectical Cycles | 65 | 926 |
| 009 | LLM Infrastructure Layer (Strategy Pattern + Anthropic API) | 114 | 1040 |

## Current Entry Points

```python
# Single-turn (Session 006)
from ares.dialectic.coordinator.orchestrator import DialecticalOrchestrator
orchestrator = DialecticalOrchestrator()
result = orchestrator.run_cycle(packet)  # packet must be frozen

# Multi-turn (Session 008)
from ares.dialectic.coordinator.multi_turn import run_multi_turn_cycle
mt_result = run_multi_turn_cycle(packet)  # returns MultiTurnCycleResult
cr = mt_result.to_cycle_result()          # bridge to Memory Stream

# Memory Stream (Session 007)
from ares.dialectic.memory.stream import MemoryStream
from ares.dialectic.memory.backends.in_memory import InMemoryBackend
stream = MemoryStream(backend=InMemoryBackend())
entry = stream.store(cr)
assert stream.verify_chain_integrity()

# LLM-powered agents (Session 009)
from ares.dialectic.agents.strategies.client import AnthropicClient
from ares.dialectic.agents.strategies.llm_strategy import LLMThreatAnalyzer, LLMExplanationFinder
from ares.dialectic.agents.architect import ArchitectAgent
from ares.dialectic.agents.skeptic import SkepticAgent

client = AnthropicClient(api_key="sk-...")  # or set ANTHROPIC_API_KEY env var
architect = ArchitectAgent(agent_id="arch-001", threat_analyzer=LLMThreatAnalyzer(client))
skeptic = SkepticAgent(agent_id="skep-001", explanation_finder=LLMExplanationFinder(client))
# Agents now use LLM reasoning with automatic rule-based fallback
```

## Development Commands
```powershell
# Activate venv
.\venv\Scripts\Activate.ps1

# Run all tests (excludes live LLM tests)
pytest ares/ -v

# Run with coverage
pytest ares/ --cov=ares --cov-report=term-missing

# Run live LLM tests (requires ANTHROPIC_API_KEY)
pytest ares/ -m live_llm --run-live-llm -v

# Run everything including live LLM
pytest ares/ --run-live-llm -v
```

## Git Workflow
- **NEVER commit directly to main**
- Main branch = stable, all tests passing, production-ready
- Create a session branch before each session: `session/{number}-{short-description}`
- Commit frequently to the session branch during work
- All 1040+ tests must pass before merging to main
- Squash merge preferred for clean history (one commit per session)
- Use `git branch -D` (capital D) after squash merge to delete branch

```powershell
# Before session: create branch from main
git checkout main
git pull origin main
git checkout -b session/010-live-llm-integration

# During session: Claude Code commits to session branch
# (multiple commits fine — it's a working branch)

# After session: all tests green → merge to main
git checkout main
git merge --squash session/010-live-llm-integration
git commit -m "Session 010: Live LLM Integration Harness - XX new tests (XXX total)"
git push origin main

# Clean up (capital -D required after squash merge)
git branch -D session/010-live-llm-integration
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
├── [✓] Multi-Turn Dialectical Cycles (Session 008)
├── [✓] LLM Infrastructure Layer (Session 009)
└── [ ] Live LLM Integration Harness + Observability (Session 010) ← NEXT
```

## LLM Integration Architecture (Session 009)
- **Strategy Pattern**: ThreatAnalyzer, ExplanationFinder, NarrativeGenerator protocols
- **RuleBasedStrategy**: Extracted current logic, zero behavior change, default for all agents
- **LLMStrategy**: Anthropic API (Claude), validates output against EvidencePacket, closed-world fact_id enforcement
- **Fallback**: LLM failure → automatic rule-based fallback (graceful degradation)
- **OracleJudge stays deterministic** — no LLM touches verdict computation
- **AnthropicClient**: Thin wrapper, model default claude-sonnet-4-20250514

## Dan's Preferences
- Direct, technical communication
- Seek disconfirmation, honest feedback
- Document everything in session logs
- Test rigorously before moving forward
- Military-style acknowledgments (WILCO, SOLID, etc.)
