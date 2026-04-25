# ARES — Adversarial Reasoning Engine System
# CLAUDE.md — Claude Code Context File

## Project Overview
Dialectical AI framework for hallucination-resistant cybersecurity threat detection. Three specialized agents (Architect, Skeptic, Oracle) debate within a closed-world evidence system where hallucinations become schema violations.

## Project Location
C:\ares-phase-zero

## Current Status
- **Phase 1: COMPLETE** (Sessions 001-010)
- **Phase 2: IN PROGRESS** — Starting Session 012
- **1,176 tests passing**, 8 skipped (live LLM), zero failures, zero regressions
- **Live LLM cycle proven** — zero validation errors on first run
- **LLM verdict accuracy: 91.7%** across 12 benchmark scenarios (up from 50% pre-tuning)
- **Last commit:** `5908b1c Session 011b: Live LLM benchmark & prompt optimization`

## File Tree

```
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
    │       ├── prompts.py                   # System prompt templates v2 (calibrated confidence + plausibility-gated)
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
        ├── sample_packets.py                # 3 realistic attack scenario packets
        ├── scenario_corpus.py               # ScenarioMetadata, BenchmarkScenario, 12 scenarios (Session 011a)
        ├── benchmark_runner.py              # ScenarioResult, BenchmarkRun, run_benchmark() (Session 011a)
        ├── benchmark_report.py              # generate_report() with delta analysis (Session 011a)
        ├── run_llm_benchmark.py             # CLI benchmark execution script (Session 011b)
        ├── prompts_v1_original.py           # Backup of original prompts pre-tuning (Session 011b)
        └── benchmark_results/               # JSON + report outputs from benchmark runs (Session 011b)
            ├── baseline.json
            ├── baseline_report.txt
            ├── llm_v1.json
            ├── llm_v1_report.txt
            ├── llm_v1_vs_baseline_report.txt
            ├── llm_v2.json
            ├── llm_v2_report.txt
            └── llm_v2_vs_llm_v1_report.txt
```

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
| 011a | Scenario Corpus + Benchmark | 60 | 1164 | Measure before you tune |
| 011b | Live LLM Benchmark + Prompt Optimization | 12 | 1176 | Data-driven prompt engineering: 50% → 91.7% |

## Benchmark Results (Session 011b)
| Run | Match Rate | Avg Confidence | Avg Coverage |
|-----|-----------|---------------|-------------|
| Rule-based baseline | 9/12 (75.0%) | 0.570 | 0.652 |
| LLM v1 (original prompts) | 6/12 (50.0%) | 0.846 | 0.917 |
| LLM v2 (revised prompts) | 11/12 (91.7%) | 0.822 | 0.946 |

**Known issue:** `benchmark_runner.py` doesn't pass `call_logger` to LLM strategies — cost tracking shows $0.00. Session 012 fixes this.

## Current Entry Points

```python
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

# Benchmark (rule-based)
from ares.dialectic.scripts.benchmark_runner import run_benchmark
from ares.dialectic.scripts.scenario_corpus import ALL_SCENARIOS
run = run_benchmark(ALL_SCENARIOS, strategy_type="rule_based")

# Benchmark (LLM)
from ares.dialectic.agents.strategies.client import AnthropicClient
from ares.dialectic.agents.strategies.observability import LLMCallLogger
client = AnthropicClient()
logger = LLMCallLogger()
run = run_benchmark(ALL_SCENARIOS, strategy_type="llm", client=client, call_logger=logger)
```

## Key Architecture Principles
- **Closed-world constraint:** Agents can only cite fact_ids that exist in the EvidencePacket
- **Frozen dataclasses everywhere:** All output types are immutable
- **Strategy Pattern:** Separates *how agents reason* from *what agents do*
- **Fallback always available:** LLM strategies wrap rule-based fallbacks
- **Hallucinations = schema violations:** Invalid fact_ids are caught, not mysterious
- **Agent isolation per cycle:** Fresh agents for each cycle, no state leakage
- **Hash-chained audit trail:** Memory Stream entries are tamper-evident
- **Measure before you tune:** Build benchmark infrastructure before optimizing

## Development Commands
```powershell
# Activate venv
.\venv\Scripts\Activate.ps1

# Run all tests
pytest ares/ -v

# Run with coverage
pytest ares/ --cov=ares --cov-report=term-missing

# Run live LLM tests (requires API key)
pytest -m live_llm --run-live-llm -v

# Run benchmark (rule-based baseline)
python -m ares.dialectic.scripts.run_llm_benchmark --strategy rule_based

# Run benchmark (LLM, requires ANTHROPIC_API_KEY)
python -m ares.dialectic.scripts.run_llm_benchmark --strategy llm
```

## Git Workflow
- **NEVER commit directly to main**
- Create session branch: `git checkout -b session/012-benchmark-hardening`
- Commit frequently to session branch during work
- All 1,176+ tests must pass before merging to main
- Squash merge: `git merge --squash session/012-benchmark-hardening`
- Commit message: `"Session 012: Benchmark runner hardening — XX new tests (XXXX total)"`

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

```
Phase Two: Optimization & Hardening
├── [✓] Session 011a: Scenario Corpus + Benchmark Infrastructure
├── [✓] Session 011b: Live LLM Benchmark + Prompt Tuning (91.7% accuracy)
├── [ ] Session 012: Benchmark Runner Hardening (call_logger wiring, error handling) ← CURRENT
├── [ ] Session 013: Multi-Turn LLM Benchmark OR Content Launch
├── [ ] Session 014: Additional Extractors (Syslog, NetFlow)
├── [ ] Session 015: Redis Backend
└── [ ] Session 016+: GNN Foundation
```
