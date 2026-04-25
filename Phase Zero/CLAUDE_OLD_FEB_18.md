# ARES — Adversarial Reasoning Engine System
# CLAUDE.md — Claude Code Context File

## Project Overview
Dialectical AI framework for hallucination-resistant cybersecurity threat detection. Three specialized agents (Architect, Skeptic, Oracle) debate within a closed-world evidence system where hallucinations become schema violations.

## Project Location
C:\ares-phase-zero

## Current Status
- **Phase 1: COMPLETE** (Sessions 001-010)
- **Phase 2: IN PROGRESS** — Starting Session 011a
- **1,104 tests passing**, zero failures, zero regressions
- **Live LLM cycle proven** — zero validation errors on first run

## File Tree

ares/
├── graph/schema.py                          # Session 001 (110 tests)
└── dialectic/
    ├── evidence/
    │   ├── provenance.py                    # Provenance, SourceType
    │   ├── fact.py                          # Fact, EntityType
    │   ├── packet.py                        # EvidencePacket (frozen container)
    │   └── extractors/
    │       ├── protocol.py                  # ExtractionResult, ExtractorProtocol
    │       └── windows.py                   # WindowsEventExtractor (4624/4672/4688)
    ├── messages/
    │   ├── assertions.py                    # Assertion, AssertionType
    │   └── protocol.py                      # DialecticalMessage, Phase, MessageBuilder
    ├── coordinator/
    │   ├── validator.py                     # MessageValidator, ValidationError, ErrorCode
    │   ├── cycle.py                         # CycleState, TerminationReason, CycleConfig, DialecticalCycle
    │   ├── coordinator.py                   # Coordinator (the Bouncer), SubmissionResult
    │   └── orchestrator.py                  # DialecticalOrchestrator, CycleResult, CycleError
    ├── agents/
    │   ├── context.py                       # TurnContext, DataRequest, RequestKind, RequestPriority
    │   ├── base.py                          # AgentBase (packet binding, phase enforcement, evidence tracking)
    │   ├── patterns.py                      # AnomalyPattern, BenignExplanation, Verdict, VerdictOutcome
    │   ├── architect.py                     # ArchitectAgent (THESIS)
    │   ├── skeptic.py                       # SkepticAgent (ANTITHESIS)
    │   ├── oracle.py                        # OracleJudge (deterministic) + OracleNarrator (constrained)
    │   └── strategies/
    │       ├── __init__.py                  # Public exports
    │       ├── protocol.py                  # ThreatAnalyzer, ExplanationFinder, NarrativeGenerator (typing.Protocol)
    │       ├── rule_based.py                # RuleBasedThreatAnalyzer, RuleBasedExplanationFinder, RuleBasedNarrativeGenerator
    │       ├── llm_strategy.py              # LLMThreatAnalyzer, LLMExplanationFinder, LLMNarrativeGenerator
    │       ├── client.py                    # AnthropicClient, LLMResponse, retry with exponential backoff
    │       ├── prompts.py                   # System prompt templates (closed-world enforced)
    │       ├── observability.py             # LLMCallRecord (frozen), LLMCallLogger (token/cost aggregation)
    │       └── live_cycle.py                # run_cycle_with_strategies(), run_multi_turn_with_strategies()
    ├── memory/
    │   ├── __init__.py                      # Public exports
    │   ├── errors.py                        # MemoryStreamError, ChainIntegrityError, DuplicateEntryError
    │   ├── entry.py                         # MemoryEntry (frozen, hash-chained)
    │   ├── protocol.py                      # MemoryBackend protocol
    │   ├── chain.py                         # HashChain, ChainLink, GENESIS_HASH, canonical serialization
    │   ├── stream.py                        # MemoryStream (main API)
    │   └── backends/
    │       ├── __init__.py
    │       └── in_memory.py                 # InMemoryBackend
    ├── multi_turn/
    │   └── cycle.py                         # run_multi_turn_cycle(), MultiTurnCycleResult, DebateRound
    └── scripts/
        ├── __init__.py
        ├── run_live_cycle.py                # CLI diagnostic runner
        └── sample_packets.py                # 3 realistic attack scenario packets


## Session Progress
| Session | Component | Tests | Cumulative | Key Insight |
|---------|-----------|-------|------------|-------------|
| 001 | Graph Schema | 110 | 110 | Node/edge types for security data |
| 002 | Dialectical Foundation | 292 | 402 | "Hallucinations = schema violations" |
| 003 | Agent Foundation | 144 | 546 | Packet binding, phase enforcement, evidence tracking |
| 004 | Concrete Agents | 134 | 570 | Rule-based Architect/Skeptic/Oracle, end-to-end cycle |
| 005 | Evidence Extractors | 130 | 700 | "Sensors don't get opinions" |
| 006 | Coordinator Orchestration | 58 | 758 | Facade pattern, single-call entry point |
| 007 | Memory Stream | 103 | 861 | Tamper-evident hash-chained audit trail |
| 008 | Multi-Turn Cycles | 65 | 926 | Iterative refinement before verdict |
| 009 | LLM Infrastructure | 114 | 1040 | Strategy Pattern — extract then inject |
| 010 | Live LLM Harness | 64 | 1104 | Zero validation errors on first live run |

## Current Entry Points

python
# Single-turn cycle (deterministic)
from ares.dialectic.coordinator.orchestrator import DialecticalOrchestrator
orchestrator = DialecticalOrchestrator()
result = orchestrator.run_cycle(packet)  # packet must be frozen

# Single-turn with pluggable strategies (rule-based or LLM)
from ares.dialectic.agents.strategies.live_cycle import run_cycle_with_strategies
result = run_cycle_with_strategies(
    packet=packet,
    threat_analyzer=RuleBasedThreatAnalyzer(),
    explanation_finder=RuleBasedExplanationFinder(),
    narrative_generator=RuleBasedNarrativeGenerator(),
)

# Multi-turn cycle (deterministic)
from ares.dialectic.multi_turn.cycle import run_multi_turn_cycle
result = run_multi_turn_cycle(packet, config=MultiTurnConfig(max_rounds=3))

# Memory Stream
from ares.dialectic.memory.stream import MemoryStream
from ares.dialectic.memory.backends.in_memory import InMemoryBackend
stream = MemoryStream(backend=InMemoryBackend())
entry = stream.store(cycle_result)


## Key Architecture Principles
- **Closed-world constraint:** Agents can only cite fact_ids that exist in the EvidencePacket
- **Frozen dataclasses everywhere:** All output types are immutable
- **Strategy Pattern:** Separates *how agents reason* from *what agents do*
- **Fallback always available:** LLM strategies wrap rule-based fallbacks
- **Hallucinations = schema violations:** Invalid fact_ids are caught, not mysterious
- **Agent isolation per cycle:** Fresh agents for each cycle, no state leakage
- **Hash-chained audit trail:** Memory Stream entries are tamper-evident

## Development Commands
powershell
# Activate venv
.\venv\Scripts\Activate.ps1

# Run all tests
pytest ares/ -v

# Run with coverage
pytest ares/ --cov=ares --cov-report=term-missing

# Run live LLM tests (requires API key)
pytest -m live_llm --run-live-llm -v


## Git Workflow
- **NEVER commit directly to main**
- Create session branch: `git checkout -b session/011a-scenario-corpus`
- Commit frequently to session branch during work
- All 1,104+ tests must pass before merging to main
- Squash merge: `git merge --squash session/011a-scenario-corpus`
- Commit message: `"Session 011a: Scenario Corpus + Benchmark - XX new tests (XXXX total)"`

## Session Workflow
1. Create session branch (see Git Workflow above)
2. Reference previous session number
3. State today's goal
4. Read existing files before writing new code
5. All commits go to session branch, NOT main
6. Merge to main only after all tests pass
7. Document decisions in session logs

## Dan's Preferences
- Direct, technical communication
- Seek disconfirmation, honest feedback
- Document everything in session logs
- Test rigorously before moving forward
- Military-style acknowledgments (WILCO, SOLID, etc.)
- Frozen dataclasses, type hints, docstrings everywhere
- Rule-based first, neural later
- The autoimmune metaphor guides architecture

## Phase 2 Roadmap

Phase Two: Prompt Optimization & Hardening
├── [ ] Session 011a: Scenario Corpus + Benchmark Infrastructure ← CURRENT
├── [ ] Session 011b: Live LLM Benchmark + Prompt Tuning
├── [ ] Session 012: Memory Stream v2 (full debate transcript storage)
├── [ ] Session 013: Additional Extractors (Syslog, NetFlow)
├── [ ] Session 014: Redis Backend
└── [ ] Session 015+: GNN Foundation
