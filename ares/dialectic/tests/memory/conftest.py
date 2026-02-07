"""Shared test helpers for Memory Stream tests.

Follows the established ARES pattern: module-level helper functions
with sensible defaults, not pytest fixtures.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from ares.dialectic.agents.patterns import Verdict, VerdictOutcome
from ares.dialectic.coordinator.orchestrator import CycleResult
from ares.dialectic.evidence.fact import EntityType, Fact
from ares.dialectic.evidence.packet import EvidencePacket, TimeWindow
from ares.dialectic.evidence.provenance import Provenance, SourceType
from ares.dialectic.memory.chain import GENESIS_HASH, HashChain
from ares.dialectic.memory.entry import MemoryEntry
from ares.dialectic.messages.assertions import Assertion, AssertionType
from ares.dialectic.messages.protocol import (
    DialecticalMessage,
    MessageType,
    Phase,
    Priority,
)


def make_provenance() -> Provenance:
    """Build a test provenance."""
    return Provenance(
        source_type=SourceType.MANUAL,
        source_id="memory-test",
        extracted_at=datetime(2024, 1, 15, 12, 0, 0),
    )


def make_fact(
    fact_id: str = "fact-001",
    entity_id: str = "node-001",
    field: str = "data",
    value: object = "test_value",
    timestamp: Optional[datetime] = None,
) -> Fact:
    """Build a test fact."""
    if timestamp is None:
        timestamp = datetime(2024, 1, 15, 12, 0, 0)
    return Fact(
        fact_id=fact_id,
        entity_id=entity_id,
        entity_type=EntityType.NODE,
        field=field,
        value=value,
        timestamp=timestamp,
        provenance=make_provenance(),
    )


def make_time_window() -> TimeWindow:
    """Build a test time window."""
    return TimeWindow(
        start=datetime(2024, 1, 1, 0, 0, 0),
        end=datetime(2024, 1, 31, 23, 59, 59),
    )


def make_assertion(
    assertion_id: str = "assert-001",
    fact_ids: tuple = ("fact-001",),
    interpretation: str = "Test assertion",
) -> Assertion:
    """Build a test assertion."""
    return Assertion(
        assertion_id=assertion_id,
        assertion_type=AssertionType.ASSERT,
        fact_ids=fact_ids,
        interpretation=interpretation,
        operator=">",
        threshold=0,
    )


def make_message(
    source_agent: str = "test-architect",
    phase: Phase = Phase.THESIS,
    confidence: float = 0.8,
    assertions: Optional[list] = None,
    narrative: Optional[str] = None,
    fact_ids: tuple = ("fact-001",),
) -> DialecticalMessage:
    """Build a test DialecticalMessage."""
    if assertions is None:
        assertions = [make_assertion(fact_ids=fact_ids)]
    return DialecticalMessage(
        message_id=str(uuid.uuid4()),
        timestamp=datetime(2024, 1, 15, 12, 0, 0),
        source_agent=source_agent,
        target_agent="broadcast",
        packet_id="test-packet-001",
        cycle_id="cycle-test001",
        phase=phase,
        turn_number=1,
        message_type=MessageType.HYPOTHESIS,
        assertions=assertions,
        confidence=confidence,
        narrative=narrative,
    )


def make_verdict(
    outcome: VerdictOutcome = VerdictOutcome.THREAT_CONFIRMED,
    confidence: float = 0.85,
    reasoning: str = "Test threat confirmed by evidence analysis",
    architect_confidence: float = 0.9,
    skeptic_confidence: float = 0.3,
) -> Verdict:
    """Build a test Verdict."""
    return Verdict(
        outcome=outcome,
        confidence=confidence,
        supporting_fact_ids=frozenset({"fact-001"}),
        architect_confidence=architect_confidence,
        skeptic_confidence=skeptic_confidence,
        reasoning=reasoning,
    )


def build_test_cycle_result(
    cycle_id: Optional[str] = None,
    packet_id: str = "test-packet-001",
    outcome: VerdictOutcome = VerdictOutcome.THREAT_CONFIRMED,
    confidence: float = 0.85,
    reasoning: str = "Test threat confirmed by evidence analysis",
    include_narrator: bool = True,
    architect_confidence: float = 0.9,
    skeptic_confidence: float = 0.3,
) -> CycleResult:
    """Build a test CycleResult with deterministic content.

    Args:
        cycle_id: Unique cycle ID. Auto-generated if None.
        packet_id: Packet ID.
        outcome: Verdict outcome.
        confidence: Verdict confidence.
        reasoning: Verdict reasoning.
        include_narrator: Whether to include a narrator message.
        architect_confidence: Architect's confidence.
        skeptic_confidence: Skeptic's confidence.

    Returns:
        A frozen CycleResult.
    """
    if cycle_id is None:
        cycle_id = f"cycle-{uuid.uuid4().hex[:8]}"

    verdict = make_verdict(
        outcome=outcome,
        confidence=confidence,
        reasoning=reasoning,
        architect_confidence=architect_confidence,
        skeptic_confidence=skeptic_confidence,
    )

    architect_msg = make_message(
        source_agent="test-architect",
        phase=Phase.THESIS,
        confidence=architect_confidence,
    )

    skeptic_msg = make_message(
        source_agent="test-skeptic",
        phase=Phase.ANTITHESIS,
        confidence=skeptic_confidence,
    )

    narrator_msg = None
    if include_narrator:
        narrator_msg = make_message(
            source_agent="test-narrator",
            phase=Phase.SYNTHESIS,
            confidence=confidence,
            narrative="Synthesized explanation of the verdict",
        )

    started = datetime(2024, 1, 15, 12, 0, 0)
    completed = datetime(2024, 1, 15, 12, 0, 0, 50000)  # 50ms later

    return CycleResult(
        cycle_id=cycle_id,
        packet_id=packet_id,
        verdict=verdict,
        architect_message=architect_msg,
        skeptic_message=skeptic_msg,
        narrator_message=narrator_msg,
        started_at=started,
        completed_at=completed,
        duration_ms=50,
    )


def build_test_entry(
    entry_id: Optional[str] = None,
    cycle_id: Optional[str] = None,
    sequence_number: int = 0,
    prev_chain_hash: str = GENESIS_HASH,
    cycle_result: Optional[CycleResult] = None,
) -> MemoryEntry:
    """Build a test MemoryEntry with valid hash chain linkage.

    Args:
        entry_id: Entry ID. Auto-generated if None.
        cycle_id: Cycle ID. Auto-generated if None.
        sequence_number: Position in the chain.
        prev_chain_hash: Previous chain hash.
        cycle_result: Full CycleResult. Auto-built if None.

    Returns:
        A frozen MemoryEntry.
    """
    if entry_id is None:
        entry_id = uuid.uuid4().hex
    if cycle_id is None:
        cycle_id = f"cycle-{uuid.uuid4().hex[:8]}"

    if cycle_result is None:
        cycle_result = build_test_cycle_result(cycle_id=cycle_id)
    else:
        cycle_id = cycle_result.cycle_id

    content_hash = HashChain.compute_content_hash(cycle_result)
    chain_hash = HashChain.compute_chain_hash(prev_chain_hash, content_hash)

    return MemoryEntry(
        entry_id=entry_id,
        cycle_id=cycle_id,
        packet_id=cycle_result.packet_id,
        verdict_outcome=cycle_result.verdict.outcome,
        verdict_confidence=cycle_result.verdict.confidence,
        cycle_result=cycle_result,
        stored_at=datetime(2024, 1, 15, 12, 1, 0),
        content_hash=content_hash,
        chain_hash=chain_hash,
        sequence_number=sequence_number,
        prev_chain_hash=prev_chain_hash,
    )


def build_privilege_escalation_packet() -> EvidencePacket:
    """Build a frozen packet with privilege escalation indicators.

    Used for full pipeline integration tests.
    """
    packet = EvidencePacket(
        packet_id="threat-scenario-001",
        time_window=make_time_window(),
    )
    prov = make_provenance()

    # User login fact
    packet.add_fact(Fact(
        fact_id="fact-login-001",
        entity_id="user-admin",
        entity_type=EntityType.NODE,
        field="logon_type",
        value=10,
        timestamp=datetime(2024, 1, 15, 2, 30, 0),
        provenance=prov,
    ))

    # Privilege assignment
    packet.add_fact(Fact(
        fact_id="fact-priv-001",
        entity_id="user-admin",
        entity_type=EntityType.NODE,
        field="privilege",
        value="SeDebugPrivilege",
        timestamp=datetime(2024, 1, 15, 2, 30, 1),
        provenance=prov,
    ))

    # Suspicious process
    packet.add_fact(Fact(
        fact_id="fact-proc-001",
        entity_id="proc-cmd",
        entity_type=EntityType.NODE,
        field="process_name",
        value="cmd.exe",
        timestamp=datetime(2024, 1, 15, 2, 31, 0),
        provenance=prov,
    ))

    packet.freeze()
    return packet
