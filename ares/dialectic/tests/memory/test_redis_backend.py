"""Tests for RedisBackend — Redis-backed persistent storage.

Mirrors test_backend.py structure. All tests skip if Redis is unavailable.
"""

from datetime import datetime

import pytest

redis = pytest.importorskip("redis")

from ares.dialectic.agents.patterns import VerdictOutcome
from ares.dialectic.memory.chain import GENESIS_HASH, HashChain
from ares.dialectic.memory.entry import MemoryEntry
from ares.dialectic.memory.errors import DuplicateEntryError
from ares.dialectic.memory.protocol import MemoryBackend

from .conftest import build_test_entry, build_test_cycle_result


# ------------------------------------------------------------------
# Fixtures
# ------------------------------------------------------------------


@pytest.fixture
def redis_client():
    """Provide a Redis client, skip if no server available."""
    try:
        client = redis.Redis(host="localhost", port=6379, db=15)
        client.ping()
    except (redis.ConnectionError, redis.exceptions.ConnectionError, OSError):
        pytest.skip("Redis server not available")
    yield client
    client.flushdb()


@pytest.fixture
def backend(redis_client):
    """RedisBackend with unique prefix per test."""
    import uuid

    prefix = f"ares_test_{uuid.uuid4().hex[:8]}"
    from ares.dialectic.memory.backends.redis_backend import RedisBackend

    backend = RedisBackend(redis_client, key_prefix=prefix)
    yield backend
    # Cleanup keys with this prefix
    for key in redis_client.scan_iter(f"{prefix}:*"):
        redis_client.delete(key)


# ------------------------------------------------------------------
# Protocol compliance
# ------------------------------------------------------------------


class TestProtocolCompliance:
    """RedisBackend satisfies the MemoryBackend protocol."""

    def test_implements_memory_backend_protocol(self, backend):
        assert isinstance(backend, MemoryBackend)


# ------------------------------------------------------------------
# Store and retrieve
# ------------------------------------------------------------------


class TestStoreAndRetrieve:
    """Basic store and retrieval operations."""

    def test_store_and_get_by_entry_id(self, backend):
        entry = build_test_entry()
        backend.store(entry)
        assert backend.get_by_entry_id(entry.entry_id) == entry

    def test_store_and_get_by_cycle_id(self, backend):
        entry = build_test_entry()
        backend.store(entry)
        assert backend.get_by_cycle_id(entry.cycle_id) == entry

    def test_get_nonexistent_entry_id_returns_none(self, backend):
        assert backend.get_by_entry_id("nope") is None

    def test_get_nonexistent_cycle_id_returns_none(self, backend):
        assert backend.get_by_cycle_id("nope") is None

    def test_store_multiple_entries(self, backend):
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

    def test_duplicate_entry_id_raises(self, backend):
        entry = build_test_entry(entry_id="e1", cycle_id="c1")
        backend.store(entry)
        with pytest.raises(DuplicateEntryError) as exc_info:
            backend.store(entry)
        assert exc_info.value.field == "entry_id"

    def test_duplicate_cycle_id_raises(self, backend):
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

    def test_query_by_verdict_filters_correctly(self, backend):
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

    def test_query_by_verdict_returns_empty_for_no_match(self, backend):
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

    def test_query_by_packet_id_returns_matching(self, backend):
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

    def test_query_by_packet_id_returns_empty_for_no_match(self, backend):
        result = backend.query_by_packet_id("nonexistent")
        assert result == []


# ------------------------------------------------------------------
# Query by time range
# ------------------------------------------------------------------


class TestQueryByTimeRange:
    """Time-range queries."""

    def test_query_by_time_range_inclusive(self, backend):
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

        results = backend.query_by_time_range(
            datetime(2024, 1, 15, 0, 0, 0),
            datetime(2024, 1, 15, 23, 59, 59),
        )
        assert len(results) == 1

    def test_query_by_time_range_excludes_outside(self, backend):
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

    def test_empty_backend_count_is_zero(self, backend):
        assert backend.count() == 0

    def test_get_latest_empty_returns_none(self, backend):
        assert backend.get_latest() is None

    def test_get_chain_head_empty_returns_none(self, backend):
        assert backend.get_chain_head() is None

    def test_count_after_store(self, backend):
        backend.store(build_test_entry(entry_id="e1", cycle_id="c1"))
        assert backend.count() == 1

    def test_get_latest_returns_last_stored(self, backend):
        e1 = build_test_entry(entry_id="e1", cycle_id="c1", sequence_number=0)
        e2 = build_test_entry(entry_id="e2", cycle_id="c2", sequence_number=1)
        backend.store(e1)
        backend.store(e2)
        assert backend.get_latest() == e2

    def test_get_chain_head_returns_latest_chain_hash(self, backend):
        e1 = build_test_entry(entry_id="e1", cycle_id="c1")
        backend.store(e1)
        assert backend.get_chain_head() == e1.chain_hash

    def test_get_all_ordered_returns_sequence_order(self, backend):
        e1 = build_test_entry(entry_id="e1", cycle_id="c1", sequence_number=0)
        e2 = build_test_entry(entry_id="e2", cycle_id="c2", sequence_number=1)
        backend.store(e1)
        backend.store(e2)
        ordered = backend.get_all_ordered()
        assert ordered == [e1, e2]

    def test_get_all_ordered_empty_returns_empty(self, backend):
        assert backend.get_all_ordered() == []


# ------------------------------------------------------------------
# Ordering guarantee
# ------------------------------------------------------------------


class TestOrdering:
    """All queries return entries ordered by sequence_number ascending."""

    def test_ordering_by_sequence_number(self, backend):
        """Store entries out of order, verify queries return in sequence order."""
        # Build entries with explicit sequence numbers
        cr1 = build_test_cycle_result(cycle_id="c1", packet_id="pkt-001")
        cr2 = build_test_cycle_result(cycle_id="c2", packet_id="pkt-001")
        cr3 = build_test_cycle_result(cycle_id="c3", packet_id="pkt-001")

        e1 = build_test_entry(
            entry_id="e1", cycle_result=cr1, sequence_number=0
        )
        e2 = build_test_entry(
            entry_id="e2", cycle_result=cr2, sequence_number=1
        )
        e3 = build_test_entry(
            entry_id="e3", cycle_result=cr3, sequence_number=2
        )

        # Store in reverse order
        backend.store(e3)
        backend.store(e1)
        backend.store(e2)

        # All ordered should be by sequence_number
        ordered = backend.get_all_ordered()
        assert [e.entry_id for e in ordered] == ["e1", "e2", "e3"]

        # query_by_packet_id should also be ordered
        by_packet = backend.query_by_packet_id("pkt-001")
        assert [e.entry_id for e in by_packet] == ["e1", "e2", "e3"]

        # query_by_verdict should also be ordered
        by_verdict = backend.query_by_verdict(VerdictOutcome.THREAT_CONFIRMED)
        assert [e.entry_id for e in by_verdict] == ["e1", "e2", "e3"]


# ------------------------------------------------------------------
# Serialization round-trip
# ------------------------------------------------------------------


class TestSerializationRoundTrip:
    """Serialize then deserialize a MemoryEntry, assert equality on every field."""

    def test_serialization_round_trip(self, backend):
        """Store and retrieve must produce an identical MemoryEntry."""
        entry = build_test_entry(entry_id="e1", cycle_id="c1")
        backend.store(entry)
        retrieved = backend.get_by_entry_id("e1")

        assert retrieved is not None
        assert retrieved.entry_id == entry.entry_id
        assert retrieved.cycle_id == entry.cycle_id
        assert retrieved.packet_id == entry.packet_id
        assert retrieved.verdict_outcome == entry.verdict_outcome
        assert retrieved.verdict_confidence == entry.verdict_confidence
        assert retrieved.stored_at == entry.stored_at
        assert retrieved.content_hash == entry.content_hash
        assert retrieved.chain_hash == entry.chain_hash
        assert retrieved.sequence_number == entry.sequence_number
        assert retrieved.prev_chain_hash == entry.prev_chain_hash

        # Deep CycleResult comparison
        cr = retrieved.cycle_result
        orig_cr = entry.cycle_result
        assert cr.cycle_id == orig_cr.cycle_id
        assert cr.packet_id == orig_cr.packet_id
        assert cr.duration_ms == orig_cr.duration_ms
        assert cr.started_at == orig_cr.started_at
        assert cr.completed_at == orig_cr.completed_at

        # Verdict fields
        assert cr.verdict.outcome == orig_cr.verdict.outcome
        assert cr.verdict.confidence == orig_cr.verdict.confidence
        assert cr.verdict.supporting_fact_ids == orig_cr.verdict.supporting_fact_ids
        assert cr.verdict.architect_confidence == orig_cr.verdict.architect_confidence
        assert cr.verdict.skeptic_confidence == orig_cr.verdict.skeptic_confidence
        assert cr.verdict.reasoning == orig_cr.verdict.reasoning

        # Message fields
        for attr in ("architect_message", "skeptic_message"):
            msg = getattr(cr, attr)
            orig_msg = getattr(orig_cr, attr)
            assert msg.message_id == orig_msg.message_id
            assert msg.source_agent == orig_msg.source_agent
            assert msg.phase == orig_msg.phase
            assert msg.confidence == orig_msg.confidence
            assert len(msg.assertions) == len(orig_msg.assertions)
            for a, orig_a in zip(msg.assertions, orig_msg.assertions):
                assert a.assertion_id == orig_a.assertion_id
                assert a.assertion_type == orig_a.assertion_type
                assert a.fact_ids == orig_a.fact_ids

        # Narrator message
        if orig_cr.narrator_message is not None:
            assert cr.narrator_message is not None
            assert cr.narrator_message.narrative == orig_cr.narrator_message.narrative
        else:
            assert cr.narrator_message is None

    def test_serialization_round_trip_no_narrator(self, backend):
        """Round-trip with narrator_message=None."""
        cr = build_test_cycle_result(cycle_id="c1", include_narrator=False)
        entry = build_test_entry(entry_id="e1", cycle_result=cr)
        backend.store(entry)
        retrieved = backend.get_by_entry_id("e1")
        assert retrieved is not None
        assert retrieved.cycle_result.narrator_message is None
        assert retrieved == entry
