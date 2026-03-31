# ARES — Adversarial Reasoning Engine System

**A dialectical AI framework for hallucination-resistant cybersecurity threat detection.**

ARES uses structured debate between AI agents to analyze security threats. Instead of trusting a single model's output, three specialized agents argue within a closed-world evidence system where hallucinations become schema violations — not mysterious AI behavior.

> *2,246 tests | 39 development sessions | Zero regressions*

---

## The Core Idea

Traditional AI security tools have a fatal flaw: they can confidently fabricate evidence. ARES solves this through **dialectical reasoning**:

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   ARCHITECT     │────►│    SKEPTIC      │────►│     ORACLE      │
│    (Thesis)     │     │  (Antithesis)   │     │   (Synthesis)   │
│                 │     │                 │     │                 │
│ "This is a      │     │ "Could be       │     │ "Verdict:       │
│  privilege      │     │  scheduled      │     │  THREAT_        │
│  escalation     │     │  maintenance"   │     │  CONFIRMED"     │
│  attack!"       │     │                 │     │                 │
└─────────────────┘     └─────────────────┘     └─────────────────┘
        │                       │                       │
        └───────────────────────┴───────────────────────┘
                                │
                    ┌───────────▼───────────┐
                    │   EVIDENCE PACKET     │
                    │   (Frozen Facts)      │
                    │                       │
                    │ All claims must cite  │
                    │ facts that exist here │
                    └───────────────────────┘
```

**Key Innovation:** Agents cannot invent facts. Every assertion must reference a `fact_id` from the immutable EvidencePacket. The Coordinator rejects any message containing non-existent references. This transforms potential hallucinations into catchable validation errors.

---

## Architecture

```
ares/
├── graph/                        # Security graph schema
│   ├── schema.py                 # Node/Edge definitions for security data
│   ├── store.py                  # Graph storage
│   └── validators.py             # Graph validation
│
├── dialectic/                    # Dialectical reasoning engine
│   ├── evidence/                 # Evidence system
│   │   ├── provenance.py         # Source tracking
│   │   ├── fact.py               # Immutable fact representation
│   │   ├── packet.py             # Frozen evidence container
│   │   └── extractors/           # Log-to-evidence converters
│   │       ├── protocol.py       # Extractor protocol
│   │       ├── windows.py        # Windows Event Log extractor
│   │       ├── syslog.py         # Syslog extractor
│   │       └── netflow.py        # NetFlow extractor
│   │
│   ├── messages/                 # Communication protocol
│   │   ├── assertions.py         # ASSERT, LINK, ALT assertion types
│   │   └── protocol.py           # DialecticalMessage, MessageBuilder
│   │
│   ├── coordinator/              # Enforcement layer
│   │   ├── validator.py          # Message validation against evidence
│   │   ├── cycle.py              # Dialectical cycle state machine
│   │   ├── coordinator.py        # Central authority (the "Bouncer")
│   │   ├── orchestrator.py       # Single-turn production pipeline
│   │   └── multi_turn.py         # Multi-turn debate orchestration
│   │
│   ├── agents/                   # Reasoning agents
│   │   ├── base.py               # AgentBase with critical invariants
│   │   ├── context.py            # TurnContext, DataRequest
│   │   ├── patterns.py           # AnomalyPattern, BenignExplanation, Verdict
│   │   ├── architect.py          # THESIS phase — threat hypothesis
│   │   ├── skeptic.py            # ANTITHESIS phase — benign alternatives
│   │   ├── oracle.py             # SYNTHESIS phase — Judge + Narrator
│   │   └── strategies/           # LLM and rule-based agent strategies
│   │       ├── protocol.py       # Strategy protocol
│   │       ├── rule_based.py     # Deterministic strategy
│   │       ├── llm_strategy.py   # Claude-powered strategy
│   │       ├── client.py         # Anthropic API client
│   │       ├── prompts.py        # Agent prompt templates
│   │       ├── live_cycle.py     # Live LLM cycle runner
│   │       └── observability.py  # Cycle metrics and logging
│   │
│   ├── memory/                   # Memory stream
│   │   ├── entry.py              # Memory entry representation
│   │   ├── stream.py             # Stream interface
│   │   ├── chain.py              # Evidence chain tracking
│   │   └── backends/             # Storage backends
│   │       └── in_memory.py      # In-memory backend
│   │
│   └── scripts/                  # Benchmark and corpus tools
│       ├── scenario_corpus.py    # 33-scenario test corpus
│       ├── run_llm_benchmark.py  # Live LLM benchmark runner
│       ├── benchmark_report.py   # Report generation
│       ├── run_live_cycle.py     # Single-scenario live runner
│       └── sample_packets.py     # Example evidence packets
│
└── visual/                       # ARES-VISION visualization system
    ├── events.py                 # Dialectical event model
    ├── emitter.py                # Event emitter for cycles
    ├── live_emitter.py           # Real-time WebSocket emitter
    ├── replayer.py               # Session replay engine
    ├── diagnostics.py            # Visual diagnostics
    ├── visualizer/               # Three.js particle physics visualizer
    │   └── index_v5.html         # Standalone visualizer (latest)
    └── tests/                    # Visual pipeline tests
```

---

## Quick Start

### Requirements

- Python 3.11+
- An [Anthropic API key](https://console.anthropic.com/) (for live LLM analysis)

### Installation

```bash
# Clone the repository
git clone https://github.com/b33fydan/ARES.git
cd ARES

# Create virtual environment
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # Linux/Mac

# Install dependencies
pip install -r requirements.txt
```

### Run Tests

```bash
# Run all tests (2,246 tests)
python -m pytest ares/ -v

# Run by component
python -m pytest ares/dialectic/tests/agents/ -v
python -m pytest ares/dialectic/tests/coordinator/ -v
python -m pytest ares/visual/tests/ -v

# Run live LLM tests (requires ANTHROPIC_API_KEY)
python -m pytest ares/ -v --run-live-llm

# Run with coverage
python -m pytest ares/ --cov=ares --cov-report=term-missing
```

### Basic Usage

```python
from ares.dialectic.evidence import EvidencePacket, Fact, Provenance, SourceType, EntityType
from ares.dialectic.agents import ArchitectAgent, SkepticAgent, OracleJudge, OracleNarrator
from ares.dialectic.agents.context import TurnContext, AgentRole
from ares.dialectic.messages.protocol import Phase

# 1. Build an evidence packet with security facts
packet = EvidencePacket(packet_id="packet-001")
packet.add_fact(Fact(
    fact_id="fact-001",
    entity_type=EntityType.USER,
    entity_id="user-jsmith",
    field="privilege_level",
    value="SYSTEM",
    provenance=Provenance(source_type=SourceType.WINDOWS_EVENT_LOG, ...)
))
packet.freeze()

# 2. Create agents and bind to evidence
architect = ArchitectAgent(agent_id="arch-001")
skeptic = SkepticAgent(agent_id="skep-001")
architect.observe(packet)
skeptic.observe(packet)

# 3. Run dialectical cycle
arch_context = TurnContext(
    phase=Phase.THESIS,
    packet_id=packet.packet_id,
    snapshot_id=packet.snapshot_id,
    cycle_id="cycle-001",
    turn_number=1,
    seen_fact_ids=frozenset()
)
arch_result = architect.act(arch_context)

skeptic.receive(arch_result.message)
skep_context = TurnContext(
    phase=Phase.ANTITHESIS,
    packet_id=packet.packet_id,
    snapshot_id=packet.snapshot_id,
    cycle_id="cycle-001",
    turn_number=2,
    seen_fact_ids=arch_result.message.fact_ids
)
skep_result = skeptic.act(skep_context)

# 4. Get verdict
verdict = OracleJudge.compute_verdict(
    architect_msg=arch_result.message,
    skeptic_msg=skep_result.message,
    packet=packet
)

print(f"Verdict: {verdict.outcome}")     # THREAT_CONFIRMED, THREAT_DISMISSED, or INCONCLUSIVE
print(f"Confidence: {verdict.confidence}")
print(f"Evidence: {verdict.supporting_fact_ids}")
```

---

## Critical Invariants

ARES enforces five architectural rules as **schema violations**, not runtime checks:

### 1. Packet Binding
Agents are bound to a specific EvidencePacket. They cannot use facts from a different packet.
```python
agent.observe(packet_a)
agent.act(context_for_packet_b)  # raises PacketMismatchError
```

### 2. Phase Enforcement
Each agent can only operate in its designated phase.
```python
# Architect = THESIS only | Skeptic = ANTITHESIS only | Oracle = SYNTHESIS only
architect.act(antithesis_context)  # raises PhaseViolationError
```

### 3. Evidence Grounding
All assertions must cite `fact_ids` that exist in the bound packet.
```python
coordinator.submit(message_with_fake_facts)  # raises ValidationError
```

### 4. Oracle Split
The Oracle is split into Judge (deterministic) and Narrator (constrained):
- **OracleJudge** — Pure function, no LLM, computes verdict from evidence
- **OracleNarrator** — Explains verdict, cannot modify it

### 5. Verdict Locking
Once OracleJudge computes a verdict, it cannot be changed. OracleNarrator receives a locked verdict at construction.

---

## The Immune System Metaphor

ARES is modeled after the biological immune system:

| Immune System | ARES Component |
|---------------|----------------|
| Antigens | Facts in EvidencePacket |
| T-Helper cells | ArchitectAgent (identifies threats) |
| Regulatory T-cells | SkepticAgent (prevents overreaction) |
| T-Killer cells | Coordinator (enforces, terminates) |
| MHC restriction | Packet binding (respond only to bound evidence) |
| Clonal selection | Evidence tracking (only productive responses survive) |
| Autoimmune prevention | Closed-world principle (can't attack self/hallucinate) |

---

## Development Status

ARES has been developed across 39 sessions with a zero-regression policy.

### Phase 1: Architecture Crystallization — COMPLETE
Core graph schema, evidence system, message protocol, coordinator, and agent foundation.

### Phase 2: LLM Integration & Benchmarking — COMPLETE
Live Anthropic integration, strategy pattern, prompt engineering, 33-scenario benchmark corpus, multi-turn debate infrastructure.

### Phase 3: Selective Escalation — COMPLETE (Negative Result)
Investigated whether multi-turn debate improves accuracy. Finding: single-turn pipelines outperform multi-turn debate. This is a valid research outcome that informed the single-turn production architecture.

### Phase 4: Accuracy Improvement & Visualization — COMPLETE
Evidence extractors (Windows, Syslog, NetFlow), accuracy hardening, ARES-VISION particle physics visualizer with real-time WebSocket streaming and session replay.

| Component | Tests |
|-----------|-------|
| Evidence System | 449 |
| Agents & Strategies | 505 |
| Coordinator & Orchestration | 389 |
| Benchmark & Scripts | 367 |
| Visual Pipeline | 213 |
| Memory Stream | 158 |
| Messages | 85 |
| **Total** | **2,246** |

---

## Tech Stack

- **Language:** Python 3.11
- **LLM:** Anthropic Claude (via `anthropic` SDK)
- **Testing:** pytest (2,246 tests, 65 skipped for live LLM)
- **Graph:** NetworkX
- **Visualization:** Three.js, WebSocket, particle physics engine
- **Data:** Frozen dataclasses (immutability as architectural constraint)

---

## Contributing

This project is in active development. Contributions, issues, and discussions are welcome.

---

## License

[MIT](LICENSE)

---

## Author

Built by [Daniel Gmys-Casiano](https://github.com/b33fydan) with structured paranoia and adversarial thinking.

*"Hallucinations are schema violations, not mysterious AI behavior."*