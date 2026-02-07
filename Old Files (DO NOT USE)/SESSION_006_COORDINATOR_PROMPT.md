# SESSION 006: Coordinator Orchestration

## Context
You're working on ARES (Adversarial Reasoning Engine System) - a dialectical AI framework for cybersecurity defense. 

**Current State:**
- Phase 0: COMPLETE (570 tests)
- Session 005: Evidence Extractors COMPLETE (130 new tests, 700 total)
- Golden pipeline proven: Raw XML → Facts → EvidencePacket → Dialectical cycle → Verdict

Session 006 builds the **orchestration layer** - a single entry point that manages the entire dialectical cycle automatically.

## Project Location
C:\ares-phase-zero

## What Exists (Don't Recreate)
```
ares/
├── graph/schema.py                    # Graph structure
└── dialectic/
    ├── evidence/
    │   ├── provenance.py              # Provenance, SourceType
    │   ├── fact.py                    # Fact, EntityType
    │   ├── packet.py                  # EvidencePacket
    │   └── extractors/
    │       ├── protocol.py            # ExtractionResult, ExtractorProtocol
    │       └── windows.py             # WindowsEventExtractor (4624/4672/4688)
    ├── messages/
    │   ├── assertions.py              # Assertion, AssertionType
    │   └── protocol.py                # DialecticalMessage, Phase
    ├── coordinator/
    │   ├── validator.py               # Message validation
    │   └── cycle.py                   # DialecticalCycle state machine (exists but may need enhancement)
    └── agents/
        ├── context.py                 # TurnContext, DataRequest
        ├── base.py                    # AgentBase
        ├── patterns.py                # AnomalyPattern, BenignExplanation, Verdict, VerdictOutcome
        ├── architect.py               # ArchitectAgent (THESIS)
        ├── skeptic.py                 # SkepticAgent (ANTITHESIS)
        └── oracle.py                  # OracleJudge, OracleNarrator (SYNTHESIS)
```

## The Problem

Currently, running a dialectical cycle requires manual wiring:

```python
# Current (manual) approach
architect = ArchitectAgent(agent_id="arch-001")
skeptic = SkepticAgent(agent_id="skep-001")

architect.observe(packet)
skeptic.observe(packet)

arch_context = TurnContext(phase=Phase.THESIS, ...)
arch_result = architect.act(arch_context)

skeptic.receive(arch_result.message)
skep_context = TurnContext(phase=Phase.ANTITHESIS, ...)
skep_result = skeptic.act(skep_context)

verdict = OracleJudge.compute_verdict(arch_result.message, skep_result.message, packet)
narrator = OracleNarrator(agent_id="oracle-001", verdict=verdict)
# ... etc
```

This is error-prone, verbose, and doesn't enforce the cycle invariants automatically.

## Your Mission: Build the Orchestrator

Create a `DialecticalOrchestrator` that provides:

```python
# Desired (orchestrated) approach
orchestrator = DialecticalOrchestrator()
result = orchestrator.run_cycle(packet)

print(result.verdict.outcome)        # THREAT_CONFIRMED / THREAT_DISMISSED / INCONCLUSIVE
print(result.verdict.confidence)     # 0.0 - 1.0
print(result.architect_message)      # The THESIS
print(result.skeptic_message)        # The ANTITHESIS
print(result.narrator_message)       # The SYNTHESIS explanation
print(result.cycle_id)               # Unique identifier
print(result.duration_ms)            # Timing
```

## Files to Create/Modify

```
ares/dialectic/coordinator/
├── __init__.py                # Update exports
├── validator.py               # Existing
├── cycle.py                   # Existing (may need enhancement)
└── orchestrator.py            # NEW - DialecticalOrchestrator

ares/dialectic/tests/coordinator/
├── __init__.py
├── test_validator.py          # Existing
├── test_cycle.py              # Existing
└── test_orchestrator.py       # NEW - orchestrator tests
```

## Key Types (orchestrator.py)

```python
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

@dataclass(frozen=True)
class CycleResult:
    """Complete output of a dialectical cycle."""
    cycle_id: str
    packet_id: str
    verdict: Verdict
    architect_message: DialecticalMessage
    skeptic_message: DialecticalMessage
    narrator_message: Optional[DialecticalMessage]  # May be None if skipped
    started_at: datetime
    completed_at: datetime
    duration_ms: int

class DialecticalOrchestrator:
    """
    Manages the complete THESIS → ANTITHESIS → SYNTHESIS cycle.
    
    Single entry point for dialectical reasoning. Handles:
    - Agent instantiation and lifecycle
    - Turn context creation
    - Phase transitions
    - Message passing between agents
    - Verdict computation
    - Cycle timing and identification
    """
    
    def __init__(
        self,
        *,
        agent_id_prefix: str = "ares",
        include_narration: bool = True,
    ):
        """
        Args:
            agent_id_prefix: Prefix for generated agent IDs
            include_narration: If True, run OracleNarrator for human explanation
        """
        ...
    
    def run_cycle(self, packet: EvidencePacket) -> CycleResult:
        """
        Execute a complete dialectical cycle on the given evidence.
        
        Args:
            packet: Frozen EvidencePacket containing facts to analyze
            
        Returns:
            CycleResult with verdict and all messages
            
        Raises:
            ValueError: If packet is not frozen
            CycleError: If any phase fails validation
        """
        ...
```

## Critical Constraints

1. **Packet must be frozen**: Orchestrator rejects unfrozen packets immediately
2. **Phase order enforced**: THESIS → ANTITHESIS → SYNTHESIS, no skipping
3. **Agent isolation**: Each cycle gets fresh agent instances (no state leakage)
4. **Timing captured**: Start/end timestamps for performance analysis
5. **Cycle IDs unique**: UUID or similar for audit trail
6. **Narration optional**: Can skip OracleNarrator for performance

## Existing Types to Import

```python
from ares.dialectic.evidence.packet import EvidencePacket
from ares.dialectic.messages.protocol import DialecticalMessage, Phase
from ares.dialectic.agents.context import TurnContext
from ares.dialectic.agents.architect import ArchitectAgent
from ares.dialectic.agents.skeptic import SkepticAgent
from ares.dialectic.agents.oracle import OracleJudge, OracleNarrator
from ares.dialectic.agents.patterns import Verdict, VerdictOutcome
```

## Test Scenarios

### 1. Basic Cycle Execution
```python
def test_run_cycle_returns_complete_result():
    packet = build_test_packet_with_privilege_escalation()
    packet.freeze()
    
    orchestrator = DialecticalOrchestrator()
    result = orchestrator.run_cycle(packet)
    
    assert result.cycle_id is not None
    assert result.verdict is not None
    assert result.architect_message.phase == Phase.THESIS
    assert result.skeptic_message.phase == Phase.ANTITHESIS
    assert result.duration_ms >= 0
```

### 2. Unfrozen Packet Rejection
```python
def test_run_cycle_rejects_unfrozen_packet():
    packet = EvidencePacket(packet_id="test")
    # NOT frozen
    
    orchestrator = DialecticalOrchestrator()
    
    with pytest.raises(ValueError, match="frozen"):
        orchestrator.run_cycle(packet)
```

### 3. Cycle Isolation
```python
def test_cycles_are_isolated():
    """Each cycle gets fresh agents - no state leakage."""
    orchestrator = DialecticalOrchestrator()
    
    result1 = orchestrator.run_cycle(packet1)
    result2 = orchestrator.run_cycle(packet2)
    
    assert result1.cycle_id != result2.cycle_id
    # Agent IDs should be unique per cycle
```

### 4. Narration Skip
```python
def test_can_skip_narration():
    orchestrator = DialecticalOrchestrator(include_narration=False)
    result = orchestrator.run_cycle(packet)
    
    assert result.narrator_message is None
    assert result.verdict is not None  # Verdict still computed
```

### 5. Integration with Extractors
```python
def test_full_pipeline_with_orchestrator():
    """Raw XML → Extractor → Packet → Orchestrator → Verdict"""
    extractor = WindowsEventExtractor()
    result = extractor.extract(raw_xml, source_ref="test")
    
    packet = EvidencePacket(packet_id="test")
    for fact in result.facts:
        packet.add_fact(fact)
    packet.freeze()
    
    orchestrator = DialecticalOrchestrator()
    cycle_result = orchestrator.run_cycle(packet)
    
    assert cycle_result.verdict.outcome in VerdictOutcome
```

## Error Handling

Create a custom exception for cycle failures:

```python
class CycleError(Exception):
    """Raised when a dialectical cycle fails."""
    
    def __init__(
        self,
        message: str,
        phase: Phase,
        cycle_id: str,
        cause: Optional[Exception] = None
    ):
        super().__init__(message)
        self.phase = phase
        self.cycle_id = cycle_id
        self.cause = cause
```

## Execution Order

1. First: Review existing `cycle.py` to understand current state machine
2. Second: Create `orchestrator.py` with `CycleResult` and `DialecticalOrchestrator`
3. Third: Create `test_orchestrator.py` with comprehensive tests
4. Fourth: Add integration test with extractor pipeline
5. Fifth: Run full test suite to verify 700+ tests still pass

## Success Criteria

- [ ] All existing 700 tests still pass
- [ ] ~50 new tests for orchestrator
- [ ] `orchestrator.run_cycle(packet)` works end-to-end
- [ ] Unfrozen packet rejection tested
- [ ] Cycle isolation verified
- [ ] Integration with extractors tested
- [ ] Timing and cycle IDs captured

## Commands

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

## Style Notes
- Frozen dataclasses everywhere (immutability)
- Type hints on everything
- Docstrings for public methods
- Test naming: `test_<what>_<condition>_<expected>`
- Keep tests focused and fast

## Stretch Goals (If Time Permits)

1. **Multi-turn cycles**: Support THESIS → ANTITHESIS → THESIS (Architect responds to Skeptic) → ANTITHESIS → SYNTHESIS
2. **Cycle hooks**: Callbacks for observability (on_phase_start, on_phase_end, on_verdict)
3. **Batch processing**: `orchestrator.run_cycles(packets: List[EvidencePacket]) -> List[CycleResult]`
