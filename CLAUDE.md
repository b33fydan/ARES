# ARES Development Project — CLAUDE.md
# Last updated: Session 016 (March 2026)

## Context
Building ARES (Adversarial Reasoning Engine System) — a dialectical AI framework
for cybersecurity defense. Three agents (Architect, Skeptic, Oracle) debate whether
security events are threats within a closed-world evidence system where hallucinations
become schema violations rather than silent failures.

## Current Status
- Phase 1: COMPLETE (Sessions 001–012)
- Multi-turn experiment: COMPLETE (Sessions 013–014b)
- Episode 4 content: COMPLETE (Session 015)
- **Next: Session 016 — Syslog Evidence Extractor**
- Total tests: 1,282 (zero regressions across all sessions)

## Key Findings (Sessions 013–014)
- Single-turn LLM accuracy: 91.7% (11/12 scenarios)
- Multi-turn peak accuracy: 75.0% (9/12 scenarios)
- **Debate amplifies commitment bias** unless explicitly calibrated for uncertainty
- INCONCLUSIVE calibration fixed SC-011 (first time ever) but overcorrected clear threats
- Multi-turn iteration parked until richer evidence distribution available (new extractors)

## Tech Stack
- Python 3.11, Anthropic API (Claude) for LLM reasoning
- Frozen dataclasses throughout (immutability enforced at type level)
- Windows + PowerShell + venv
- Future: Redis backend, PyTorch/GNN components

## Code Location
C:\ares-phase-zero

## Architecture Principles
1. **Closed-world assumption** — Only frozen EvidencePackets as truth
2. **Hallucinations = Schema violations** — Catchable errors, not silent bugs
3. **Deterministic first, neural later** — Rule-based agents validated before LLM injection
4. **Autoimmune metaphor** — Self/non-self discrimination guides design
5. **Sensors don't get opinions** — Extractors parse and stamp provenance, reasoning happens downstream
6. **New files over modifications** — Strict discipline of creating new files per session
7. **Infrastructure before capability** — Measurement before optimization, always

## File Tree (Complete)

```
ares/
├── graph/schema.py                              # Session 001 (110 tests)
└── dialectic/
    ├── evidence/
    │   ├── provenance.py                        # Provenance, SourceType
    │   ├── fact.py                              # Fact, EntityType
    │   ├── packet.py                            # EvidencePacket
    │   └── extractors/
    │       ├── __init__.py
    │       ├── protocol.py                      # ExtractionResult, ExtractorProtocol
    │       └── windows.py                       # WindowsEventExtractor (4624/4672/4688)
    ├── messages/
    │   ├── assertions.py                        # Assertion, AssertionType
    │   └── protocol.py                          # DialecticalMessage, Phase, MessageBuilder
    ├── coordinator/
    │   ├── validator.py                         # MessageValidator
    │   ├── cycle.py                             # CycleState, TerminationReason
    │   ├── coordinator.py                       # Coordinator
    │   └── orchestrator.py                      # DialecticalOrchestrator, CycleResult
    ├── agents/
    │   ├── context.py                           # TurnContext, DataRequest
    │   ├── base.py                              # AgentBase
    │   ├── patterns.py                          # AnomalyPattern, BenignExplanation, Verdict
    │   ├── architect.py                         # ArchitectAgent
    │   ├── skeptic.py                           # SkepticAgent
    │   ├── oracle.py                            # OracleJudge, OracleNarrator
    │   └── strategies/
    │       ├── __init__.py                      # Public exports
    │       ├── protocol.py                      # ThreatAnalyzer, ExplanationFinder, NarrativeGenerator
    │       ├── rule_based.py                    # Rule-based strategies
    │       ├── llm_strategy.py                  # LLM strategies
    │       ├── client.py                        # AnthropicClient
    │       ├── prompts.py                       # System prompt templates
    │       ├── observability.py                 # LLMCallRecord, LLMCallLogger
    │       ├── live_cycle.py                    # run_cycle_with_strategies()
    │       ├── multi_turn_prompts.py            # Session 014 (modified 014b)
    │       └── multi_turn_strategies.py         # Session 014
    ├── memory/
    │   ├── __init__.py
    │   ├── errors.py
    │   ├── entry.py                             # MemoryEntry
    │   ├── protocol.py                          # MemoryBackend protocol
    │   ├── chain.py                             # HashChain
    │   ├── stream.py                            # MemoryStream
    │   └── backends/
    │       ├── __init__.py
    │       └── in_memory.py                     # InMemoryBackend
    ├── multi_turn/
    │   └── cycle.py                             # run_multi_turn_cycle()
    └── scripts/
        ├── __init__.py
        ├── run_live_cycle.py
        ├── sample_packets.py                    # 3 original scenarios
        ├── scenario_corpus.py                   # 12 benchmark scenarios (SC-001 to SC-012)
        ├── benchmark_runner.py                  # ScenarioResult, BenchmarkRun, run_benchmark()
        ├── benchmark_report.py                  # generate_report()
        ├── multi_turn_benchmark.py              # Session 013 (modified 014)
        ├── multi_turn_benchmark_report.py       # Session 013
        └── run_multi_turn_llm_benchmark.py      # Session 013 (modified 014)
```

## Session History

| Session | Component | Tests | Cumulative | Key Insight |
|---------|-----------|-------|------------|-------------|
| 001 | Graph Schema | 110 | 110 | Node/edge types for security data |
| 002 | Dialectical Foundation | 292 | 402 | "Hallucinations = schema violations" |
| 003 | Agent Foundation | 144 | 546 | Packet binding, phase enforcement |
| 004 | Concrete Agents | 134 | 570 | Rule-based Architect/Skeptic/Oracle |
| 005 | Evidence Extractors | 130 | 700 | "Sensors don't get opinions" |
| 006 | Coordinator Orchestration | 58 | 758 | Facade pattern, single-call entry |
| 007 | Memory Stream | 103 | 861 | Hash-chained audit trail |
| 008 | Multi-Turn Cycles | 65 | 926 | Iterative refinement before verdict |
| 009 | LLM Infrastructure | 114 | 1040 | Strategy Pattern — extract then inject |
| 010 | Live LLM Harness | 64 | 1104 | Zero validation errors on first live run |
| 011a | Scenario Corpus + Benchmark | 60 | 1164 | Measure before you tune |
| 011b | Prompt Optimization | 12 | 1176 | 50% → 91.7% via data-driven engineering |
| 012 | Benchmark Hardening | 14 | 1190 | You can't optimize what you can't measure |
| 013 | Multi-Turn Benchmark | 51 | 1241 | Debate without engagement is repetition |
| 014/b | Round-Aware Strategies | 41 | 1282 | Debate amplifies commitment bias |
| 015 | Episode 4 Content | — | 1282 | Content creation session |

## Development Commands
```powershell
# Activate venv
.\venv\Scripts\Activate.ps1

# Run all tests
python -m pytest ares/ -v

# Run specific test file
python -m pytest ares/dialectic/tests/evidence/extractors/test_windows.py -v
```

## Roadmap (Sessions 016–020)
- **016: Syslog Extractor** — Second telemetry source (network-layer evidence)
- **017: NetFlow Extractor** — Third telemetry source (traffic metadata)
- **018: Mixed-Source Benchmark** — Cross-source scenarios, re-test single-turn AND multi-turn
- **019: Redis Backend** — Persistent Memory Stream
- **020: Checkpoint** — Binary pass/fail against expanded corpus

## Dan's Preferences
- Direct, military-style communication (WILCO, SOLID, GO)
- New files over modifications — always
- Frozen dataclasses everywhere
- Test naming: `test_<what>_<condition>_<expected>`
- Zero regressions is a hard requirement
- Empirical rigor over aspirational framing