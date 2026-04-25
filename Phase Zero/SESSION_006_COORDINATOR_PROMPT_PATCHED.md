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
    │   ├── validator.py               # MessageValidator, ValidationError, ErrorCode (26 tests)
    │   ├── cycle.py                   # CycleState, TerminationReason, CycleConfig, DialecticalCycle (50 tests)
    │   └── coordinator.py             # Coordinator (the Bouncer), SubmissionResult, exceptions (33 tests)
    └── agents/
        ├── context.py                 # TurnContext, DataRequest
        ├── base.py                    # AgentBase
        ├── patterns.py                # AnomalyPattern, BenignExplanation, Verdict, VerdictOutcome
        ├── architect.py               # ArchitectAgent (THESIS)
        ├── skeptic.py                 # SkepticAgent (ANTITHESIS)
        └── oracle.py                  # OracleJudge, OracleNarrator (SYNTHESIS)
```

## Architectural Note

The new `DialecticalOrchestrator` is a **FACADE** that composes existing components. It does NOT replace the existing `Coordinator` (the Bouncer, 33 tests). The orchestrator instantiates fresh agents, drives them through the cycle, and may optionally use the existing Coordinator for message validation. The existing Coordinator handles message validation and cycle state — the Orchestrator automates the agent wiring and lifecycle management that currently requires manual code.

## The Problem

Currently, running a dialectical cycle requires manual wiring:

```python
# Current (manual) approach
architect = ArchitectAgent(agent_id="arch-001")
skeptic = SkepticAgent(agent_id="skep-001")

# THESIS
architect.observe(packet)
arch_context = TurnContext(phase=Phase.THESIS, turn_number=1, cycle_id="cycle-001",
                           packet_id=packet.packet_id, snapshot_id=packet.snapshot_id)
arch_result = architect.act(arch_context)

# ANTITHESIS
skeptic.observe(packet)
skeptic.receive(arch_result.message)
skep_context = TurnContext(phase=Phase.ANTITHESIS, turn_number=2, cycle_id="cycle-001",
                            packet_id=packet.packet_id, snapshot_id=packet.snapshot_id)
skep_result = skeptic.act(skep_context)

# SYNTHESIS
verdict = OracleJudge.compute_verdict(arch_result.message, skep_result.message, packet)
narrator = OracleNarrator(agent_id="oracle-001", verdict=verdict)
narrator.observe(packet)
narr_context = TurnContext(phase=Phase.SYNTHESIS, turn_number=3, cycle_id="cycle-001",
                            packet_id=packet.packet_id, snapshot_id=packet.snapshot_id)
narr_result = narrator.act(narr_context)
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
├── validator.py               # Existing (DO NOT modify)
├── cycle.py                   # Existing (may need enhancement)
├── coordinator.py             # Existing (DO NOT modify) - the Bouncer
└── orchestrator.py            # NEW - DialecticalOrchestrator

ares/dialectic/tests/coordinator/
├── __init__.py
├── test_validator.py          # Existing (DO NOT modify)
├── test_cycle.py              # Existing (DO NOT modify)
├── test_coordinator.py        # Existing (DO NOT modify)
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
    - Turn context creation (with proper packet_id, snapshot_id, cycle_id)
    - Phase transitions
    - Message passing between agents
    - Verdict computation
    - Cycle timing and identification
    
    This is a FACADE over existing components. It does NOT replace the
    Coordinator (bouncer) or any existing validation.
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

## Agent ID Format

Agent IDs should use the format: `{prefix}-{role}-{cycle_uuid_short}`
Example: `"ares-arch-a1b2c3d4"`, `"ares-skep-a1b2c3d4"`, `"ares-oracle-a1b2c3d4"`

Same UUID suffix per cycle ensures traceability in audit logs.

## Critical Constraints

1. **Packet must be frozen**: Orchestrator rejects unfrozen packets immediately
2. **Phase order enforced**: THESIS → ANTITHESIS → SYNTHESIS, no skipping
3. **Agent isolation**: Each cycle gets fresh agent instances (no state leakage)
4. **Timing captured**: Start/end timestamps for performance analysis
5. **Cycle IDs unique**: UUID or similar for audit trail
6. **Narration optional**: Can skip OracleNarrator for performance
7. **TurnContext fully populated**: Every TurnContext must include phase, turn_number, cycle_id, packet_id, and snapshot_id (review context.py for required fields)

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
    assert result.verdict.outcome in VerdictOutcome  # Valid outcome
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

### 6. Empty Packet Handling
```python
def test_run_cycle_with_empty_packet():
    """Packet with no facts - Architect has nothing to detect."""
    packet = EvidencePacket(packet_id="empty")
    packet.freeze()
    
    orchestrator = DialecticalOrchestrator()
    result = orchestrator.run_cycle(packet)
    
    # Empty evidence should produce INCONCLUSIVE verdict
    assert result.verdict.outcome == VerdictOutcome.INCONCLUSIVE
```

### 7. CycleResult Immutability
```python
def test_cycle_result_is_frozen():
    """CycleResult should be immutable."""
    result = orchestrator.run_cycle(packet)
    
    with pytest.raises(AttributeError):
        result.verdict = None  # Cannot modify frozen dataclass
```

### 8. Agent ID Uniqueness
```python
def test_agent_ids_contain_cycle_uuid():
    """Agent IDs should include cycle UUID for traceability."""
    orchestrator = DialecticalOrchestrator(agent_id_prefix="test")
    result = orchestrator.run_cycle(packet)
    
    # All agents in same cycle share UUID suffix
    # Format: {prefix}-{role}-{uuid_short}
    assert result.cycle_id is not None
    assert len(result.cycle_id) > 0
```

## Error Handling

Create a custom exception for cycle failures:

```python
class CycleError(Exception):
    """Raised when a dialectical cycle fails.
    
    Use 'raise CycleError(...) from original_exception' to preserve
    the exception chain for debugging.
    """
    
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

1. **First**: Review existing `cycle.py` AND `coordinator.py` to understand the current state machine and validation logic
2. **Second**: Review `context.py` to understand TurnContext required fields
3. **Third**: Create `orchestrator.py` with `CycleResult`, `CycleError`, and `DialecticalOrchestrator`
4. **Fourth**: Create `test_orchestrator.py` with comprehensive tests
5. **Fifth**: Add integration test with extractor pipeline
6. **Sixth**: Update `coordinator/__init__.py` exports
7. **Seventh**: Run full test suite to verify 700+ tests still pass

## Success Criteria

- [ ] All existing 700 tests still pass
- [ ] ~50 new tests for orchestrator
- [ ] `orchestrator.run_cycle(packet)` works end-to-end
- [ ] Unfrozen packet rejection tested
- [ ] Cycle isolation verified (no state leakage between runs)
- [ ] Integration with extractors tested
- [ ] Empty packet handling tested
- [ ] Timing and cycle IDs captured
- [ ] CycleResult immutability verified
- [ ] Agent IDs unique per cycle with traceable format

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
- Use `raise ... from ...` for exception chaining

## Stretch Goals (If Time Permits)

1. **Multi-turn cycles**: Support THESIS → ANTITHESIS → THESIS (Architect responds to Skeptic) → ANTITHESIS → SYNTHESIS
2. **Cycle hooks**: Callbacks for observability (on_phase_start, on_phase_end, on_verdict) - these will be critical for Memory Stream integration in a future session
3. **Batch processing**: `orchestrator.run_cycles(packets: List[EvidencePacket]) -> List[CycleResult]`
