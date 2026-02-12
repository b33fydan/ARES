"""Shared test fixtures for strategy tests."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional
from unittest.mock import MagicMock

import pytest

from ares.dialectic.agents.patterns import Verdict, VerdictOutcome
from ares.dialectic.agents.strategies.client import LLMResponse
from ares.dialectic.evidence.fact import EntityType, Fact
from ares.dialectic.evidence.packet import EvidencePacket, TimeWindow
from ares.dialectic.evidence.provenance import Provenance, SourceType
from ares.dialectic.messages.assertions import Assertion, AssertionType
from ares.dialectic.messages.protocol import (
    DialecticalMessage,
    MessageType,
    Phase,
    Priority,
)


# =============================================================================
# Helper Functions
# =============================================================================


def make_provenance() -> Provenance:
    """Create a test provenance instance."""
    return Provenance(
        source_type=SourceType.MANUAL,
        source_id="strategy-test",
        extracted_at=datetime(2024, 1, 15, 12, 0, 0),
    )


def make_fact(
    fact_id: str = "fact-001",
    entity_id: str = "node-001",
    field: str = "data",
    value: object = "test_value",
    timestamp: Optional[datetime] = None,
) -> Fact:
    """Create a test fact instance."""
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
    """Create a test time window."""
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
        operator="detected",
        threshold="privilege_escalation",
    )


def make_message(
    source_agent: str = "test-architect",
    phase: Phase = Phase.THESIS,
    confidence: float = 0.8,
    assertions: Optional[list] = None,
    fact_ids: tuple = ("fact-001",),
    packet_id: str = "test-packet",
    cycle_id: str = "cycle-test",
) -> DialecticalMessage:
    """Build a test DialecticalMessage."""
    if assertions is None:
        assertions = [make_assertion(fact_ids=fact_ids)]
    return DialecticalMessage(
        message_id=str(uuid.uuid4()),
        timestamp=datetime(2024, 1, 15, 12, 0, 0),
        source_agent=source_agent,
        target_agent="broadcast",
        packet_id=packet_id,
        cycle_id=cycle_id,
        phase=phase,
        turn_number=1,
        message_type=MessageType.HYPOTHESIS,
        assertions=assertions,
        confidence=confidence,
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


# =============================================================================
# Packet Fixtures
# =============================================================================


@pytest.fixture
def sample_packet() -> EvidencePacket:
    """Frozen EvidencePacket with known facts for testing."""
    packet = EvidencePacket(
        packet_id="test-packet",
        time_window=make_time_window(),
    )
    prov = make_provenance()

    # Privilege escalation evidence
    packet.add_fact(Fact(
        fact_id="fact-001",
        entity_id="user-admin",
        entity_type=EntityType.NODE,
        field="privilege",
        value="SeDebugPrivilege",
        timestamp=datetime(2024, 1, 15, 2, 30, 0),
        provenance=prov,
    ))

    # Suspicious process
    packet.add_fact(Fact(
        fact_id="fact-002",
        entity_id="proc-cmd",
        entity_type=EntityType.NODE,
        field="process_name",
        value="cmd.exe",
        timestamp=datetime(2024, 1, 15, 2, 31, 0),
        provenance=prov,
    ))

    # Admin activity
    packet.add_fact(Fact(
        fact_id="fact-003",
        entity_id="user-admin",
        entity_type=EntityType.NODE,
        field="account_type",
        value="administrator",
        timestamp=datetime(2024, 1, 15, 2, 30, 0),
        provenance=prov,
    ))

    # Maintenance indicator
    packet.add_fact(Fact(
        fact_id="fact-004",
        entity_id="session-001",
        entity_type=EntityType.NODE,
        field="maintenance_window",
        value="scheduled",
        timestamp=datetime(2024, 1, 15, 2, 30, 0),
        provenance=prov,
    ))

    # Generic data fact
    packet.add_fact(Fact(
        fact_id="fact-005",
        entity_id="node-001",
        entity_type=EntityType.NODE,
        field="data",
        value="test_value",
        timestamp=datetime(2024, 1, 15, 12, 0, 0),
        provenance=prov,
    ))

    packet.freeze()
    return packet


@pytest.fixture
def valid_fact_ids(sample_packet) -> set:
    """Set of fact_ids that exist in the sample packet."""
    return {f.fact_id for f in sample_packet.get_all_facts()}


@pytest.fixture
def empty_packet() -> EvidencePacket:
    """Frozen EvidencePacket with a single benign fact."""
    packet = EvidencePacket(
        packet_id="empty-packet",
        time_window=make_time_window(),
    )
    packet.add_fact(make_fact(
        fact_id="fact-benign-001",
        field="status",
        value="normal",
    ))
    packet.freeze()
    return packet


@pytest.fixture
def architect_msg() -> DialecticalMessage:
    """A test Architect hypothesis message."""
    return make_message(
        source_agent="test-architect",
        phase=Phase.THESIS,
        confidence=0.8,
        fact_ids=("fact-001", "fact-002"),
    )


@pytest.fixture
def skeptic_msg() -> DialecticalMessage:
    """A test Skeptic rebuttal message."""
    return make_message(
        source_agent="test-skeptic",
        phase=Phase.ANTITHESIS,
        confidence=0.5,
        fact_ids=("fact-003",),
    )


@pytest.fixture
def threat_verdict() -> Verdict:
    """A THREAT_CONFIRMED verdict."""
    return make_verdict(outcome=VerdictOutcome.THREAT_CONFIRMED)


@pytest.fixture
def dismissed_verdict() -> Verdict:
    """A THREAT_DISMISSED verdict."""
    return make_verdict(
        outcome=VerdictOutcome.THREAT_DISMISSED,
        confidence=0.75,
        reasoning="Benign explanation accepted",
        architect_confidence=0.3,
        skeptic_confidence=0.8,
    )


@pytest.fixture
def inconclusive_verdict() -> Verdict:
    """An INCONCLUSIVE verdict."""
    return make_verdict(
        outcome=VerdictOutcome.INCONCLUSIVE,
        confidence=0.5,
        reasoning="Neither side conclusive",
        architect_confidence=0.5,
        skeptic_confidence=0.5,
    )


# =============================================================================
# Mock Client Fixtures
# =============================================================================


@pytest.fixture
def mock_client():
    """AnthropicClient mock that returns configurable responses."""
    client = MagicMock()
    client.model = "claude-sonnet-4-20250514"
    client.max_tokens = 4096
    return client


@pytest.fixture
def mock_llm_response_valid():
    """Valid JSON response matching AnomalyPattern schema."""
    return LLMResponse(
        content='[{"pattern_type": "privilege_escalation", "fact_ids": ["fact-001", "fact-002"], "confidence": 0.85, "description": "Privilege escalation detected"}]',
        model="claude-sonnet-4-20250514",
        usage_input_tokens=100,
        usage_output_tokens=50,
    )


@pytest.fixture
def mock_llm_response_explanations():
    """Valid JSON response matching BenignExplanation schema."""
    return LLMResponse(
        content='[{"explanation_type": "known_admin", "fact_ids": ["fact-003"], "confidence": 0.7, "description": "Known admin account"}]',
        model="claude-sonnet-4-20250514",
        usage_input_tokens=100,
        usage_output_tokens=50,
    )


@pytest.fixture
def mock_llm_response_narrative():
    """Valid narrative response."""
    return LLMResponse(
        content="The evidence strongly suggests privilege escalation by fact-001 and fact-002.",
        model="claude-sonnet-4-20250514",
        usage_input_tokens=100,
        usage_output_tokens=30,
    )
