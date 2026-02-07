"""Tests for InMemoryBackend — dict-based storage."""

from datetime import datetime

import pytest

from ares.dialectic.agents.patterns import VerdictOutcome
from ares.dialectic.memory.backends.in_memory import InMemoryBackend
from ares.dialectic.memory.errors import DuplicateEntryError
from ares.dialectic.memory.protocol import MemoryBackend

from .conftest import build_test_entry, build_test_cycle_result


# ------------------------------------------------------------------
# Protocol compliance
# ------------------------------------------------------------------


class TestProtocolCompliance:
    """InMemoryBackend satisfies the MemoryBackend protocol."""

    def test_implements_memory_backend_protocol(self):
        backend = InMemoryBackend()
        assert isinstance(backend, MemoryBackend)


# ------------------------------------------------------------------
# Store and retrieve
# ------------------------------------------------------------------


class TestStoreAndRetrieve:
    """Basic store and retrieval operations."""

    def test_store_and_get_by_entry_id(self):
        backend = InMemoryBackend()
        entry = build_test_entry()
        backend.store(entry)
        assert backend.get_by_entry_id(entry.entry_id) == entry

    def test_store_and_get_by_cycle_id(self):
        backend = InMemoryBackend()
        entry = build_test_entry()
        backend.store(entry)
        assert backend.get_by_cycle_id(entry.cycle_id) == entry

    def test_get_nonexistent_entry_id_returns_none(self):
        backend = InMemoryBackend()
        assert backend.get_by_entry_id("nope") is None

    def test_get_nonexistent_cycle_id_returns_none(self):
        backend = InMemoryBackend()
        assert backend.get_by_cycle_id("nope") is None

    def test_store_multiple_entries(self):
        backend = InMemoryBackend()
        e1 = build_test_entry(entry_id="e1", cycle_id="c1", sequence_number=0)
        e2 = build_test_entry(entry_id="e2", cycle_id="c2", sequence_number=1)
        backend.store(e1)
        backend.store(e2)
        assert backend.get_by_entry_id("e1") == e1
        assert backend.get_by_entry_id("e2") == e2


# ------------------------------------------------------------------
# Duplicate rejection
# ------------------------------------------------------------------


class TestDuplicateRejection:
    """Duplicate entry_id or cycle_id must be rejected."""

    def test_duplicate_entry_id_raises(self):
        backend = InMemoryBackend()
        entry = build_test_entry(entry_id="e1", cycle_id="c1")
        backend.store(entry)
        with pytest.raises(DuplicateEntryError) as exc_info:
            backend.store(entry)
        assert exc_info.value.field == "entry_id"

    def test_duplicate_cycle_id_raises(self):
        backend = InMemoryBackend()
        e1 = build_test_entry(entry_id="e1", cycle_id="c1")
        e2 = build_test_entry(entry_id="e2", cycle_id="c1")
        backend.store(e1)
        with pytest.raises(DuplicateEntryError) as exc_info:
            backend.store(e2)
        assert exc_info.value.field == "cycle_id"


# ------------------------------------------------------------------
# Query by verdict
# ------------------------------------------------------------------


class TestQueryByVerdict:
    """Verdict-based filtering."""

    def test_query_by_verdict_filters_correctly(self):
        backend = InMemoryBackend()
        threat = build_test_entry(
            entry_id="e1",
            cycle_id="c1",
            cycle_result=build_test_cycle_result(
                cycle_id="c1", outcome=VerdictOutcome.THREAT_CONFIRMED
            ),
        )
        dismissed = build_test_entry(
            entry_id="e2",
            cycle_id="c2",
            cycle_result=build_test_cycle_result(
                cycle_id="c2", outcome=VerdictOutcome.THREAT_DISMISSED
            ),
        )
        backend.store(threat)
        backend.store(dismissed)

        threats = backend.query_by_verdict(VerdictOutcome.THREAT_CONFIRMED)
        assert len(threats) == 1
        assert threats[0].verdict_outcome == VerdictOutcome.THREAT_CONFIRMED

    def test_query_by_verdict_returns_empty_for_no_match(self):
        backend = InMemoryBackend()
        entry = build_test_entry(
            cycle_result=build_test_cycle_result(
                outcome=VerdictOutcome.THREAT_CONFIRMED
            ),
        )
        backend.store(entry)
        result = backend.query_by_verdict(VerdictOutcome.INCONCLUSIVE)
        assert result == []


# ------------------------------------------------------------------
# Query by packet_id
# ------------------------------------------------------------------


class TestQueryByPacketId:
    """Packet-based filtering."""

    def test_query_by_packet_id_returns_matching(self):
        backend = InMemoryBackend()
        e1 = build_test_entry(
            entry_id="e1",
            cycle_id="c1",
            cycle_result=build_test_cycle_result(
                cycle_id="c1", packet_id="pkt-001"
            ),
        )
        e2 = build_test_entry(
            entry_id="e2",
            cycle_id="c2",
            cycle_result=build_test_cycle_result(
                cycle_id="c2", packet_id="pkt-001"
            ),
        )
        e3 = build_test_entry(
            entry_id="e3",
            cycle_id="c3",
            cycle_result=build_test_cycle_result(
                cycle_id="c3", packet_id="pkt-002"
            ),
        )
        backend.store(e1)
        backend.store(e2)
        backend.store(e3)

        results = backend.query_by_packet_id("pkt-001")
        assert len(results) == 2
        assert all(e.packet_id == "pkt-001" for e in results)

    def test_query_by_packet_id_returns_empty_for_no_match(self):
        backend = InMemoryBackend()
        result = backend.query_by_packet_id("nonexistent")
        assert result == []


# ------------------------------------------------------------------
# Query by time range
# ------------------------------------------------------------------


class TestQueryByTimeRange:
    """Time-range queries."""

    def test_query_by_time_range_inclusive(self):
        backend = InMemoryBackend()
        from ares.dialectic.memory.chain import GENESIS_HASH, HashChain

        result = build_test_cycle_result(cycle_id="c1")
        content_hash = HashChain.compute_content_hash(result)
        chain_hash = HashChain.compute_chain_hash(GENESIS_HASH, content_hash)

        from ares.dialectic.memory.entry import MemoryEntry

        entry = MemoryEntry(
            entry_id="e1",
            cycle_id="c1",
            packet_id=result.packet_id,
            verdict_outcome=result.verdict.outcome,
            verdict_confidence=result.verdict.confidence,
            cycle_result=result,
            stored_at=datetime(2024, 1, 15, 12, 0, 0),
            content_hash=content_hash,
            chain_hash=chain_hash,
            sequence_number=0,
            prev_chain_hash=GENESIS_HASH,
        )
        backend.store(entry)

        # Query range that includes the entry
        results = backend.query_by_time_range(
            datetime(2024, 1, 15, 0, 0, 0),
            datetime(2024, 1, 15, 23, 59, 59),
        )
        assert len(results) == 1

    def test_query_by_time_range_excludes_outside(self):
        backend = InMemoryBackend()
        from ares.dialectic.memory.chain import GENESIS_HASH, HashChain
        from ares.dialectic.memory.entry import MemoryEntry

        result = build_test_cycle_result(cycle_id="c1")
        content_hash = HashChain.compute_content_hash(result)
        chain_hash = HashChain.compute_chain_hash(GENESIS_HASH, content_hash)

        entry = MemoryEntry(
            entry_id="e1",
            cycle_id="c1",
            packet_id=result.packet_id,
            verdict_outcome=result.verdict.outcome,
            verdict_confidence=result.verdict.confidence,
            cycle_result=result,
            stored_at=datetime(2024, 1, 15, 12, 0, 0),
            content_hash=content_hash,
            chain_hash=chain_hash,
            sequence_number=0,
            prev_chain_hash=GENESIS_HASH,
        )
        backend.store(entry)

        # Query range that excludes the entry
        results = backend.query_by_time_range(
            datetime(2024, 1, 16, 0, 0, 0),
            datetime(2024, 1, 16, 23, 59, 59),
        )
        assert len(results) == 0


# ------------------------------------------------------------------
# Edge cases
# ------------------------------------------------------------------


class TestEdgeCases:
    """Empty backend and edge case behavior."""

    def test_empty_backend_count_is_zero(self):
        backend = InMemoryBackend()
        assert backend.count() == 0

    def test_get_latest_empty_returns_none(self):
        backend = InMemoryBackend()
        assert backend.get_latest() is None

    def test_get_chain_head_empty_returns_none(self):
        backend = InMemoryBackend()
        assert backend.get_chain_head() is None

    def test_count_after_store(self):
        backend = InMemoryBackend()
        backend.store(build_test_entry(entry_id="e1", cycle_id="c1"))
        assert backend.count() == 1

    def test_get_latest_returns_last_stored(self):
        backend = InMemoryBackend()
        e1 = build_test_entry(entry_id="e1", cycle_id="c1", sequence_number=0)
        e2 = build_test_entry(entry_id="e2", cycle_id="c2", sequence_number=1)
        backend.store(e1)
        backend.store(e2)
        assert backend.get_latest() == e2

    def test_get_chain_head_returns_latest_chain_hash(self):
        backend = InMemoryBackend()
        e1 = build_test_entry(entry_id="e1", cycle_id="c1")
        backend.store(e1)
        assert backend.get_chain_head() == e1.chain_hash

    def test_get_all_ordered_returns_insertion_order(self):
        backend = InMemoryBackend()
        e1 = build_test_entry(entry_id="e1", cycle_id="c1", sequence_number=0)
        e2 = build_test_entry(entry_id="e2", cycle_id="c2", sequence_number=1)
        backend.store(e1)
        backend.store(e2)
        ordered = backend.get_all_ordered()
        assert ordered == [e1, e2]

    def test_get_all_ordered_empty_returns_empty(self):
        backend = InMemoryBackend()
        assert backend.get_all_ordered() == []
