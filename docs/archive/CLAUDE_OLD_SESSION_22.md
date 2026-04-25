# ARES Development Project

## Context
Building ARES (Adversarial Reasoning Engine System) - a dialectical AI framework 
for cybersecurity defense using graph neural networks and multi-agent reasoning.

## Current Status
- Phase 0: Architecture Crystallization ✅ COMPLETE
- Phase 1: Minimal Viable Dialectic ✅ COMPLETE
- Phase 2: Evidence Expansion + Benchmarking ✅ COMPLETE (Sessions 011A–020)
- **Phase 3: Selective Escalation Architecture — IN PROGRESS**
  - Session 021: Corpus Expansion ✅ COMPLETE
  - Session 022: Escalation Gate — NEXT
  - Session 023: Per-Claim Evidence Extraction
  - Session 024: Integration + Benchmark (FORCING FUNCTION)

## Test Count: 1,663 passing (+ 65 skipped), 0 failed, zero regressions

## Key Findings (Sessions 013–020)
- **Single-turn accuracy: 83.3% (15/18)** — production path
- **Multi-turn accuracy: 66.7% (12/18)** — both original and anchored variants
- **Diagnosed failure mechanism:** Architect retreat (-30pts/round), Skeptic rigidity, asymmetric calibration
- **Conviction anchoring fix:** Traded one failure mode for another. Zero net improvement.
- **Debate wins:** SC-011 (corrected over-dismissal) and SC-016 (reinforced justified conviction) — both original multi-turn only
- **SC-017 CORRECTED:** Previously cited as flagship debate win. Verified wrong in all three modes across two independent runs. Removed from narrative.
- **ETH Zurich convergence:** Independent study (arXiv:2603.01213v2) found same consensus failure in abstract game setting

## Phase 3 Architecture: Selective Escalation with Per-Claim Audit
Designed from Tribunal synthesis (GPT 5.4 Pro, Gemini 3.1 Pro, Perplexity — unanimous on direction):
1. **Single-turn pass** — standard pipeline, Oracle renders verdict with confidence
2. **Escalation gate** — if Oracle confidence is 0.35–0.65, escalate. Deterministic threshold.
3. **Claim extraction** — Oracle identifies 3–5 contested claims tied to frozen EvidencePackets
4. **Per-claim debate** — Architect/Skeptic argue each claim individually with specific evidence citations
5. **Deterministic aggregation** — claim-level confidences weighted by evidence support count

Reserve hypotheses if Phase 3 fails:
- **Reserve A:** Adversarial Oracle (active stress-tester, not passive judge)
- **Reserve B:** Deterministic Skeptic (replace LLM Skeptic with Python graph query function)

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
7. **New files over modifications** - Never modify existing files, always create new ones
8. **Measurement before optimization** - Build instrumentation first, then tune

## Key Components

### Completed (Sessions 001–021)
```
ares/
├── graph/schema.py                    # Graph structure (Session 001)
└── dialectic/
    ├── evidence/
    │   ├── provenance.py              # Source tracking (Session 002)
    │   ├── fact.py                    # Immutable facts (Session 002)
    │   ├── packet.py                  # Frozen evidence container (Session 002)
    │   └── extractors/                # Telemetry parsing (Sessions 005, 011A/B, 016, 017)
    │       ├── protocol.py            # ExtractionResult, ExtractorProtocol
    │       ├── windows.py             # 4624/4672/4688 event parsing
    │       ├── syslog.py              # SSH/firewall/sudo/systemd parsing
    │       └── netflow.py             # Traffic metadata extraction
    ├── messages/
    │   ├── assertions.py              # ASSERT, LINK, ALT (Session 002)
    │   └── protocol.py                # DialecticalMessage, Phase (Session 002)
    ├── coordinator/
    │   ├── validator.py               # MessageValidator (Session 002)
    │   ├── cycle.py                   # CycleState, TerminationReason (Session 002)
    │   ├── coordinator.py             # Coordinator "the Bouncer" (Session 002)
    │   ├── orchestrator.py            # DialecticalOrchestrator (Session 006)
    │   └── multi_turn.py              # run_multi_turn_cycle() (Session 008)
    ├── agents/
    │   ├── context.py                 # TurnContext, DataRequest (Session 003)
    │   ├── base.py                    # AgentBase with invariants (Session 003)
    │   ├── patterns.py                # AnomalyPattern, BenignExplanation, Verdict (Session 004)
    │   ├── architect.py               # ArchitectAgent - THESIS (Session 004, strategy Session 009)
    │   ├── skeptic.py                 # SkepticAgent - ANTITHESIS (Session 004, strategy Session 009)
    │   ├── oracle.py                  # OracleJudge (deterministic) + OracleNarrator (Session 004)
    │   └── strategies/                # Pluggable reasoning backends (Sessions 009–010)
    │       ├── protocol.py            # ThreatAnalyzer, ExplanationFinder, NarrativeGenerator
    │       ├── rule_based.py          # RuleBasedThreatAnalyzer, etc.
    │       ├── llm_strategy.py        # LLMThreatAnalyzer, etc.
    │       ├── client.py              # AnthropicClient with retry logic
    │       ├── prompts.py             # System prompt templates
    │       ├── observability.py       # LLMCallRecord, LLMCallLogger
    │       └── live_cycle.py          # run_cycle_with_strategies(), run_multi_turn_with_strategies()
    ├── memory/
    │   ├── errors.py                  # MemoryStreamError, ChainIntegrityError
    │   ├── entry.py                   # MemoryEntry (frozen, hash-chained)
    │   ├── protocol.py                # MemoryBackend protocol
    │   ├── chain.py                   # HashChain, ChainLink, GENESIS_HASH
    │   ├── stream.py                  # MemoryStream (main API)
    │   └── backends/
    │       └── in_memory.py           # InMemoryBackend (Session 007)
    └── scripts/
        ├── run_live_cycle.py          # CLI diagnostic runner
        ├── sample_packets.py          # Realistic attack scenario packets
        ├── scenario_corpus.py         # Original 12 scenarios (Session 011A)
        ├── expanded_scenarios.py      # 15 new scenarios SC-019–SC-033 (Session 021)
        ├── benchmark_runner.py        # ScenarioResult, BenchmarkRun (Session 011A)
        ├── benchmark_report.py        # generate_report() with delta analysis
        ├── benchmark_analysis.py      # FP/FN/Miscalibrated classification + per-tier accuracy (Session 021)
        └── run_anchored_benchmark.py  # compare-all mode: single/original-MT/anchored-MT
```

### Session Progress
| Session | Component | Tests Added | Cumulative |
|---------|-----------|-------------|------------|
| 001 | Graph Schema | 110 | 110 |
| 002 | Evidence + Messages + Coordinator | 292 | 402 |
| 003 | Agent Foundation | 144 | 546 |
| 004 | Concrete Agents + Integration | 134 | 570 |
| 005 | Evidence Extractors (Windows Event Log) | 130 | 700 |
| 006 | Coordinator Orchestration | 58 | 758 |
| 007 | Memory Stream | 103 | 861 |
| 008 | Multi-Turn Dialectical Cycles | 65 | 926 |
| 009 | LLM Infrastructure Layer | 114 | 1,040 |
| 010 | Live LLM Integration + Observability | 64 | 1,104 |
| 011A | Scenario Corpus + Benchmark Infrastructure | 60 | 1,164 |
| 011B | Prompt Optimization (50% → 91.7%) | 12 | 1,176 |
| 012 | Benchmark Hardening | 14 | 1,190 |
| 013 | Multi-Turn Benchmark (first negative result) | ~40 | ~1,230 |
| 014 | Diagnosis + Analysis | ~30 | ~1,260 |
| 015 | Mixed-Source Scenarios | ~50 | ~1,310 |
| 016 | Syslog Extractor | ~40 | ~1,350 |
| 017 | NetFlow Extractor | ~40 | ~1,390 |
| 018–019 | Cross-Source Integration + Benchmarking | ~70 | ~1,460 |
| 020 | Conviction Anchoring Protocol | ~68 | ~1,528 |
| **021** | **Corpus Expansion (18→33) + Benchmark Analysis** | **68** | **1,663** |

## Scenario Corpus (33 Scenarios)

### Original Corpus (SC-001 through SC-018)
| Tier | Count | Scenarios |
|------|-------|-----------|
| CLEAR_THREAT | 5 | SC-002, SC-003, SC-004, SC-010, SC-013, SC-014, SC-016 |
| CLEAR_BENIGN | 3 | SC-008, SC-009, SC-015, SC-018 |
| AMBIGUOUS | 6 | SC-001, SC-005, SC-006, SC-007, SC-011, SC-012 |
| MIXED_SIGNALS | 4 | SC-017 |

### Expanded Corpus (SC-019 through SC-033, Session 021)
| Tier | Count | Scenarios |
|------|-------|-----------|
| CLEAR_THREAT | 2 | SC-019 (Ransomware Deployment), SC-020 (C2 Beaconing) |
| CLEAR_BENIGN | 3 | SC-021 (Scheduled Backup), SC-022 (Admin PsExec Patching), SC-023 (Vulnerability Scanner Noise) |
| AMBIGUOUS | 6 | SC-024 (Dual-Use PowerShell), SC-025 (Cloud Upload Ambiguity), SC-026 (Failed Logins Then Success), SC-027 (After-Hours Foreign VPN), SC-028 (WMI Remote Execution), SC-029 (Internal Port Scan) |
| MIXED_SIGNALS | 4 | SC-030 (DGA DNS Minimal Traffic), SC-031 (Sudo Abuse No Exfil), SC-032 (Impossible Travel Normal Processes), SC-033 (Suspicious Binary Ansible Deploy) |

## Benchmark Results (Session 020, N=18)
| Mode | Accuracy | Cost |
|------|----------|------|
| Single-Turn LLM | 15/18 (83.3%) | $0.31 |
| Multi-Turn Original | 12/18 (66.7%) | $0.67 |
| Multi-Turn Anchored | 12/18 (66.7%) | $0.83 |

**Session 021 expanded corpus benchmark (N=33): PENDING — run on next build day**

## Current Entry Points

```python
# Single-turn with LLM strategies (production path)
from ares.dialectic.agents.strategies.client import AnthropicClient
from ares.dialectic.agents.strategies.llm_strategy import LLMThreatAnalyzer, LLMExplanationFinder, LLMNarrativeGenerator
from ares.dialectic.agents.strategies.observability import LLMCallLogger
from ares.dialectic.agents.strategies.live_cycle import run_cycle_with_strategies

client = AnthropicClient()
logger = LLMCallLogger()
result = run_cycle_with_strategies(
    packet,
    threat_analyzer=LLMThreatAnalyzer(client, call_logger=logger),
    explanation_finder=LLMExplanationFinder(client, call_logger=logger),
    narrative_generator=LLMNarrativeGenerator(client, call_logger=logger),
)

# Benchmark (compare all modes)
python -m ares.dialectic.scripts.run_anchored_benchmark --mode compare-all

# Full corpus API
from ares.dialectic.scripts.expanded_scenarios import get_full_corpus, get_expanded_scenarios
all_33 = get_full_corpus()       # all scenarios
new_15 = get_expanded_scenarios() # SC-019 through SC-033 only

# Benchmark analysis (FP/FN/tier breakdown)
from ares.dialectic.scripts.benchmark_analysis import classify_errors, format_analysis_report
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

# Benchmark (all modes, full corpus)
python -m ares.dialectic.scripts.run_anchored_benchmark --mode compare-all
```

## Git Workflow
- **NEVER commit directly to main**
- Create session branch: `session/{number}-{short-description}`
- All 1,663+ tests must pass before merging
- Squash merge to main for clean history

```powershell
# Before session
git checkout main && git pull origin main
git checkout -b session/022-escalation-gate

# After session (all tests green)
git checkout main
git merge --squash session/022-escalation-gate
git commit -m "Session 022: Escalation Gate - XX new tests (XXXX total)"
git push origin main
git branch -D session/022-escalation-gate
```

## Next Session: 022 — Escalation Gate
**Goal:** Implement the confidence-based escalation detector
**Deliverables:**
- EscalationGate frozen dataclass (takes Oracle output, returns RESOLVED or ESCALATE)
- Configurable threshold band (defaults 0.35/0.65)
- Gate accuracy test against expanded corpus
- Escalation rate metrics (target: 15–25% of scenarios trigger)
**Prerequisite:** Run compare-all on full 33-scenario corpus FIRST to establish expanded baseline

## Session 024 Forcing Function
Binary checkpoint: selective escalation accuracy on N=33 corpus ≥ 83.3% (single-turn baseline) with improved calibration on ambiguous-tier scenarios. Pass or fail. Documented either way.

## Dan's Preferences
- Direct, technical communication
- Seek disconfirmation, honest feedback
- Document everything in session logs
- Test rigorously before moving forward
- Military-style acknowledgments (WILCO, SOLID, etc.)
- New files over modifications — strict discipline
- Zero regressions — non-negotiable