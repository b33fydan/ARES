# ARES Development Project — CLAUDE.md
# Last updated: Session 018 (March 24, 2026)

## Context
Building ARES (Adversarial Reasoning Engine System) — a dialectical AI framework
for cybersecurity defense. Three agents (Architect, Skeptic, Oracle) debate whether
security events are threats within a closed-world evidence system where hallucinations
become schema violations rather than silent failures.

## Current Status
- Phase 1: COMPLETE (Sessions 001–012)
- Multi-turn experiment round 1: COMPLETE (Sessions 013–014b)
- Evidence expansion: COMPLETE (Sessions 016–017)
- Mixed-source re-test: COMPLETE (Session 018)
- **Next: Session 019 — Redis Backend**
- Total tests: 1,576 (zero regressions across all sessions)

## Key Findings

### Single-Turn LLM (Production Path)
- 83–92% accuracy across 18 scenarios, three evidence sources
- Cross-source evidence synthesis works in a single pass
- $0.31 per full corpus run (~$0.017/scenario)
- Run-to-run variance: ±8%

### Multi-Turn Debate (Research Finding)
- 61.1% accuracy on 18-scenario corpus (vs 83–89% single-turn)
- **Architect systematically retreats under Skeptic pressure** (avg -30 points per round)
- Skeptic rarely moves regardless of Architect arguments
- Evidence diversity does NOT fix the debate asymmetry
- One genuine win: SC-017 — debate corrected an over-confident single-turn verdict
- Fix requires protocol-level changes (conviction anchoring, Skeptic obligation to move)

## Tech Stack
- Python 3.11, Anthropic API (Claude Sonnet) for LLM reasoning
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

## Evidence Sources (3 Extractors)

| Source | File | Events/Records |
|--------|------|----------------|
| Windows Event Log | `extractors/windows.py` | 4624 (logon), 4672 (privilege), 4688 (process) |
| Syslog (RFC 3164) | `extractors/syslog.py` | SSH auth, UFW firewall, sudo, systemd |
| NetFlow (CSV) | `extractors/netflow.py` | Flow records with timing, volume, direction |

## Benchmark Corpus (18 Scenarios)

| Range | Source | File |
|-------|--------|------|
| SC-001 to SC-012 | Single-source (Windows) | `scripts/scenario_corpus.py` |
| SC-013 to SC-018 | Mixed-source (2-3 sources) | `scripts/mixed_source_scenarios.py` |

Combined API: `get_combined_corpus()` returns all 18.

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
    │       ├── windows.py                       # WindowsEventExtractor (Session 005)
    │       ├── syslog.py                        # SyslogExtractor (Session 016)
    │       └── netflow.py                       # NetFlowExtractor (Session 017)
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
        ├── run_multi_turn_llm_benchmark.py      # Session 013 (modified 014)
        ├── mixed_source_scenarios.py            # Session 018: SC-013 to SC-018
        └── run_combined_benchmark.py            # Session 018: combined CLI
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
| 009 | LLM Infrastructure | 114 | 1,040 | Strategy Pattern — extract then inject |
| 010 | Live LLM Harness | 64 | 1,104 | Zero validation errors on first live run |
| 011a | Scenario Corpus + Benchmark | 60 | 1,164 | Measure before you tune |
| 011b | Prompt Optimization | 12 | 1,176 | 50% → 91.7% via data-driven engineering |
| 012 | Benchmark Hardening | 14 | 1,190 | You can't optimize what you can't measure |
| 013 | Multi-Turn Benchmark | 51 | 1,241 | Debate without engagement is repetition |
| 014/b | Round-Aware Strategies | 41 | 1,282 | Debate amplifies commitment bias |
| 015 | Episode 4 Content | — | 1,282 | Content creation session |
| 016 | Syslog Extractor | 126 | 1,408 | Second telemetry source (network layer) |
| 017 | NetFlow Extractor | 95 | 1,503 | Third telemetry source (traffic metadata) |
| 018 | Mixed-Source Scenarios | 73 | 1,576 | Evidence diversity doesn't fix debate asymmetry |

## Development Commands
```powershell
# Activate venv
.\venv\Scripts\Activate.ps1

# Run all tests
python -m pytest ares/ -v

# Run combined benchmark (rule-based)
python -m ares.dialectic.scripts.run_combined_benchmark --strategy rule_based

# Run combined benchmark (LLM single-turn)
python -m ares.dialectic.scripts.run_combined_benchmark --strategy llm

# Run combined benchmark (LLM single + multi-turn comparison)
python -m ares.dialectic.scripts.run_combined_benchmark --strategy llm --compare-multi-turn --max-rounds 3
```

## Roadmap (Sessions 019–020)
- **019: Redis Backend** — Persistent Memory Stream (second backend implementation)
- **020: Checkpoint** — Binary pass/fail assessment, production path declaration

## Dan's Preferences
- Direct, military-style communication (WILCO, SOLID, GO)
- New files over modifications — always
- Frozen dataclasses everywhere
- Test naming: `test_<what>_<condition>_<expected>`
- Zero regressions is a hard requirement
- Empirical rigor over aspirational framing