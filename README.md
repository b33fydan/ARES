# 🔱 ARES - Adversarial Reasoning Engine System

**A dialectical AI framework for hallucination-resistant cybersecurity threat detection.**

ARES uses structured debate between AI agents to analyze security threats. Instead of trusting a single model's output, three specialized agents argue within a closed-world evidence system where hallucinations become schema violations—not mysterious AI behavior.

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
├── graph/                    # Security graph schema (Session 001)
│   └── schema.py             # Node/Edge definitions for security data
│
└── dialectic/                # Dialectical reasoning engine
    ├── evidence/             # Evidence system (Session 002)
    │   ├── provenance.py     # Source tracking
    │   ├── fact.py           # Immutable fact representation
    │   └── packet.py         # Frozen evidence container
    │
    ├── messages/             # Communication protocol (Session 002)
    │   ├── assertions.py     # ASSERT, LINK, ALT assertion types
    │   └── protocol.py       # DialecticalMessage, MessageBuilder
    │
    ├── coordinator/          # Enforcement layer (Session 002)
    │   ├── validator.py      # Message validation against evidence
    │   ├── cycle.py          # Dialectical cycle state machine
    │   └── coordinator.py    # Central authority (the "Bouncer")
    │
    └── agents/               # Reasoning agents (Sessions 003-004)
        ├── context.py        # TurnContext, DataRequest
        ├── base.py           # AgentBase with critical invariants
        ├── patterns.py       # AnomalyPattern, BenignExplanation, Verdict
        ├── architect.py      # THESIS phase - threat hypothesis
        ├── skeptic.py        # ANTITHESIS phase - benign alternatives
        └── oracle.py         # SYNTHESIS phase - Judge + Narrator
```

---

## Quick Start

### Requirements

- Python 3.11+
- pytest

### Installation

```bash
# Clone the repository
git clone https://github.com/b33fydan/ARES.git
cd ARES

# Create virtual environment
python -m venv venv
venv\Scripts\activate  # Windows
# source venv/bin/activate  # Linux/Mac

# Install dependencies
pip install -r requirements.txt
```

### Run Tests

```bash
# Run all tests
python -m pytest ares/ -v

# Run specific component tests
python -m pytest ares/dialectic/tests/agents/ -v
python -m pytest ares/dialectic/tests/test_integration.py -v

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

# 2. Create agents
architect = ArchitectAgent(agent_id="arch-001")
skeptic = SkepticAgent(agent_id="skep-001")

# 3. Bind agents to evidence
architect.observe(packet)
skeptic.observe(packet)

# 4. Run dialectical cycle
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

# 5. Get verdict
verdict = OracleJudge.compute_verdict(
    architect_msg=arch_result.message,
    skeptic_msg=skep_result.message,
    packet=packet
)

print(f"Verdict: {verdict.outcome}")  # THREAT_CONFIRMED, THREAT_DISMISSED, or INCONCLUSIVE
print(f"Confidence: {verdict.confidence}")
print(f"Supporting evidence: {verdict.supporting_fact_ids}")
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
# Architect = THESIS only
# Skeptic = ANTITHESIS only  
# Oracle = SYNTHESIS only
architect.act(antithesis_context)  # raises PhaseViolationError
```

### 3. Evidence Grounding
All assertions must cite `fact_ids` that exist in the bound packet.
```python
# Coordinator rejects messages with non-existent fact references
coordinator.submit(message_with_fake_facts)  # raises ValidationError
```

### 4. Oracle Split
The Oracle is split into Judge (deterministic) and Narrator (constrained):
- **OracleJudge**: Pure function, no LLM, computes verdict from evidence
- **OracleNarrator**: Explains verdict, cannot modify it

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

### Phase Zero: Architecture Crystallization ✓ COMPLETE

| Component | Tests | Status |
|-----------|-------|--------|
| Graph Schema | 110 | ✓ |
| Evidence System | 98 | ✓ |
| Message Protocol | 85 | ✓ |
| Coordinator | 109 | ✓ |
| Agent Foundation | 144 | ✓ |
| Concrete Agents | 134 | ✓ |
| **Total** | **570** | ✓ |

### Phase One: Minimal Viable Dialectic (Planned)
- [ ] Real data integration (Windows Event Logs, Sysmon)
- [ ] Memory Stream (Redis-backed persistence)
- [ ] LLM integration (with deterministic Judge preserved)
- [ ] Full Coordinator orchestration

### Future Phases
- Phase Two: Chaos Engineering & Adversarial Testing
- Phase Three: Model Security & Adversarial ML Defense
- Phase Four: Regulatory Compliance Layer
- Phase Five: Autonomous Defense Protocols

---

## Session Logs

Detailed development history is maintained in session logs:

- `SESSION_001_GRAPH_SCHEMA.md` - Security graph node/edge definitions
- `SESSION_002_DIALECTICAL_FOUNDATION.md` - Evidence, messages, coordinator
- `SESSION_003_AGENT_FOUNDATION.md` - AgentBase, TurnContext, invariants
- `SESSION_004_CONCRETE_AGENTS.md` - Architect, Skeptic, Oracle implementation

---

## Tech Stack

- **Language:** Python 3.11
- **Testing:** pytest
- **Graph (Phase 0):** NetworkX
- **Graph (Phase 2+):** Neo4j (planned)
- **Memory Stream:** Redis (planned)
- **ML Framework:** PyTorch, PyTorch Geometric (Phase 1+)

---

## Contributing

This project is in active development. The architecture is stabilizing but not yet ready for external contributions. Watch this space.

---

## License

[MIT](LICENSE)

---

## Author

Built with structured paranoia and adversarial thinking.

*"Hallucinations are schema violations, not mysterious AI behavior."*