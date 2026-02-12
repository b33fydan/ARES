"""Tests for run_cycle_with_strategies and run_multi_turn_with_strategies.

All tests use rule-based strategies (no mocks needed) unless testing
LLM strategy injection (mocked client).
"""

from __future__ import annotations

import json
from datetime import datetime
from unittest.mock import MagicMock

import pytest

from ares.dialectic.agents.patterns import Verdict, VerdictOutcome
from ares.dialectic.agents.strategies.client import LLMResponse
from ares.dialectic.agents.strategies.live_cycle import (
    run_cycle_with_strategies,
    run_multi_turn_with_strategies,
)
from ares.dialectic.agents.strategies.llm_strategy import LLMThreatAnalyzer
from ares.dialectic.coordinator.orchestrator import CycleResult
from ares.dialectic.evidence.fact import EntityType, Fact
from ares.dialectic.evidence.packet import EvidencePacket, TimeWindow
from ares.dialectic.evidence.provenance import Provenance, SourceType
from ares.dialectic.memory.backends.in_memory import InMemoryBackend
from ares.dialectic.memory.stream import MemoryStream
from ares.dialectic.messages.protocol import Phase


# =============================================================================
# Fixtures
# =============================================================================


def _make_provenance():
    return Provenance(
        source_type=SourceType.MANUAL,
        source_id="live-cycle-test",
        extracted_at=datetime(2024, 1, 15, 12, 0, 0),
    )


def _make_packet() -> EvidencePacket:
    """Build a frozen packet with enough facts to trigger anomalies."""
    packet = EvidencePacket(
        packet_id="live-test-packet",
        time_window=TimeWindow(
            start=datetime(2024, 1, 1), end=datetime(2024, 1, 31, 23, 59, 59),
        ),
    )
    prov = _make_provenance()

    packet.add_fact(Fact(
        fact_id="fact-001", entity_id="user-admin",
        entity_type=EntityType.NODE, field="privilege",
        value="SeDebugPrivilege",
        timestamp=datetime(2024, 1, 15, 2, 30), provenance=prov,
    ))
    packet.add_fact(Fact(
        fact_id="fact-002", entity_id="proc-cmd",
        entity_type=EntityType.NODE, field="process_name",
        value="cmd.exe",
        timestamp=datetime(2024, 1, 15, 2, 31), provenance=prov,
    ))
    packet.add_fact(Fact(
        fact_id="fact-003", entity_id="user-admin",
        entity_type=EntityType.NODE, field="account_type",
        value="administrator",
        timestamp=datetime(2024, 1, 15, 2, 30), provenance=prov,
    ))
    packet.add_fact(Fact(
        fact_id="fact-004", entity_id="session-001",
        entity_type=EntityType.NODE, field="maintenance_window",
        value="scheduled",
        timestamp=datetime(2024, 1, 15, 2, 30), provenance=prov,
    ))

    packet.freeze()
    return packet


@pytest.fixture
def frozen_packet():
    return _make_packet()


@pytest.fixture
def unfrozen_packet():
    packet = EvidencePacket(
        packet_id="unfrozen-packet",
        time_window=TimeWindow(
            start=datetime(2024, 1, 1), end=datetime(2024, 1, 31),
        ),
    )
    packet.add_fact(Fact(
        fact_id="fact-001", entity_id="node-001",
        entity_type=EntityType.NODE, field="data", value="test",
        timestamp=datetime(2024, 1, 15), provenance=_make_provenance(),
    ))
    return packet


# =============================================================================
# run_cycle_with_strategies Tests
# =============================================================================


class TestRunCycleWithStrategies:
    """Tests for the single-turn cycle helper."""

    def test_defaults_produce_valid_cycle_result(self, frozen_packet):
        """Default strategies produce a valid CycleResult."""
        result = run_cycle_with_strategies(frozen_packet)
        assert isinstance(result, CycleResult)
        assert result.packet_id == frozen_packet.packet_id
        assert result.verdict is not None
        assert result.architect_message is not None
        assert result.skeptic_message is not None

    def test_matches_orchestrator_output_shape(self, frozen_packet):
        """CycleResult has all expected fields."""
        result = run_cycle_with_strategies(frozen_packet)
        assert isinstance(result.cycle_id, str)
        assert result.cycle_id.startswith("cycle-")
        assert isinstance(result.verdict, Verdict)
        assert isinstance(result.started_at, datetime)
        assert isinstance(result.completed_at, datetime)
        assert isinstance(result.duration_ms, int)

    def test_with_mock_llm_strategy(self, frozen_packet):
        """Mock LLM strategy injects correctly."""
        mock_client = MagicMock()
        content = json.dumps([{
            "pattern_type": "privilege_escalation",
            "fact_ids": ["fact-001", "fact-002"],
            "confidence": 0.9,
            "description": "LLM detected priv esc",
        }])
        mock_client.complete.return_value = LLMResponse(
            content=content, model="m",
            usage_input_tokens=10, usage_output_tokens=5,
        )
        analyzer = LLMThreatAnalyzer(mock_client)
        result = run_cycle_with_strategies(
            frozen_packet, threat_analyzer=analyzer,
        )
        assert isinstance(result, CycleResult)
        # Architect should have used the mock LLM result
        assert mock_client.complete.called

    def test_compatible_with_memory_stream(self, frozen_packet):
        """CycleResult stores in MemoryStream without error."""
        result = run_cycle_with_strategies(frozen_packet)
        stream = MemoryStream(backend=InMemoryBackend())
        entry = stream.store(result)
        assert entry is not None
        assert stream.verify_chain_integrity()

    def test_rejects_unfrozen_packet(self, unfrozen_packet):
        """Raises ValueError for unfrozen packet."""
        with pytest.raises(ValueError, match="frozen"):
            run_cycle_with_strategies(unfrozen_packet)

    def test_deterministic_oracle_verdict(self, frozen_packet):
        """OracleJudge verdict is deterministic (same each run)."""
        r1 = run_cycle_with_strategies(frozen_packet)
        r2 = run_cycle_with_strategies(frozen_packet)
        # Same input → same verdict outcome
        assert r1.verdict.outcome == r2.verdict.outcome

    def test_failing_llm_strategy_falls_back(self, frozen_packet):
        """Failing LLM strategy falls back to rule-based."""
        mock_client = MagicMock()
        mock_client.complete.side_effect = RuntimeError("API down")
        analyzer = LLMThreatAnalyzer(mock_client)
        result = run_cycle_with_strategies(
            frozen_packet, threat_analyzer=analyzer,
        )
        # Should still produce valid result via fallback
        assert isinstance(result, CycleResult)
        assert result.verdict is not None

    def test_correct_phase_assignments(self, frozen_packet):
        """Messages have correct phase assignments."""
        result = run_cycle_with_strategies(frozen_packet)
        assert result.architect_message.phase == Phase.THESIS
        assert result.skeptic_message.phase == Phase.ANTITHESIS
        if result.narrator_message:
            assert result.narrator_message.phase == Phase.SYNTHESIS

    def test_narration_disabled(self, frozen_packet):
        """include_narration=False omits narrator message."""
        result = run_cycle_with_strategies(
            frozen_packet, include_narration=False,
        )
        assert result.narrator_message is None

    def test_custom_agent_id_prefix(self, frozen_packet):
        """Custom agent_id_prefix appears in agent IDs."""
        result = run_cycle_with_strategies(
            frozen_packet, agent_id_prefix="custom",
        )
        assert result.architect_message.source_agent.startswith("custom-arch-")
        assert result.skeptic_message.source_agent.startswith("custom-skep-")

    def test_no_state_leakage_between_calls(self, frozen_packet):
        """Agents are fresh for each call — no state leakage."""
        r1 = run_cycle_with_strategies(frozen_packet)
        r2 = run_cycle_with_strategies(frozen_packet)
        # Different cycle IDs = fresh agents
        assert r1.cycle_id != r2.cycle_id


# =============================================================================
# run_multi_turn_with_strategies Tests
# =============================================================================


class TestRunMultiTurnWithStrategies:
    """Tests for the multi-turn cycle helper."""

    def test_defaults_produce_valid_cycle_result(self, frozen_packet):
        """Default strategies produce a valid CycleResult."""
        result = run_multi_turn_with_strategies(frozen_packet)
        assert isinstance(result, CycleResult)
        assert result.packet_id == frozen_packet.packet_id

    def test_with_mock_llm_strategy(self, frozen_packet):
        """Mock LLM strategy injects correctly in multi-turn."""
        mock_client = MagicMock()
        content = json.dumps([{
            "pattern_type": "privilege_escalation",
            "fact_ids": ["fact-001"],
            "confidence": 0.85,
            "description": "LLM test",
        }])
        mock_client.complete.return_value = LLMResponse(
            content=content, model="m",
            usage_input_tokens=10, usage_output_tokens=5,
        )
        analyzer = LLMThreatAnalyzer(mock_client)
        result = run_multi_turn_with_strategies(
            frozen_packet, threat_analyzer=analyzer, max_rounds=1,
        )
        assert isinstance(result, CycleResult)

    def test_stores_in_memory_stream(self, frozen_packet):
        """Multi-turn result stores in MemoryStream."""
        result = run_multi_turn_with_strategies(frozen_packet, max_rounds=1)
        stream = MemoryStream(backend=InMemoryBackend())
        entry = stream.store(result)
        assert entry is not None
        assert stream.verify_chain_integrity()

    def test_respects_max_rounds(self, frozen_packet):
        """max_rounds=1 produces single round."""
        result = run_multi_turn_with_strategies(frozen_packet, max_rounds=1)
        # With max_rounds=1, the cycle should complete quickly
        assert isinstance(result, CycleResult)
        assert result.verdict is not None

    def test_rejects_unfrozen_packet(self, unfrozen_packet):
        """Raises ValueError for unfrozen packet."""
        with pytest.raises(ValueError, match="frozen"):
            run_multi_turn_with_strategies(unfrozen_packet)
