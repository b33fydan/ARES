"""Integration tests for MemoryStream + RedisBackend.

Wires MemoryStream(backend=RedisBackend(...)) and verifies identical
behavior to the InMemoryBackend integration tests in test_stream.py.

All tests skip if Redis is unavailable.
"""

from datetime import datetime

import pytest

redis = pytest.importorskip("redis")

from ares.dialectic.agents.patterns import VerdictOutcome
from ares.dialectic.memory.chain import GENESIS_HASH, HashChain
from ares.dialectic.memory.errors import (
    ChainIntegrityError,
    DuplicateEntryError,
)
from ares.dialectic.memory.stream import MemoryStream

from .conftest import (
    build_privilege_escalation_packet,
    build_test_cycle_result,
)


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
def redis_backend(redis_client):
    """RedisBackend with unique prefix per test."""
    import uuid

    prefix = f"ares_test_{uuid.uuid4().hex[:8]}"
    from ares.dialectic.memory.backends.redis_backend import RedisBackend

    backend = RedisBackend(redis_client, key_prefix=prefix)
    yield backend
    for key in redis_client.scan_iter(f"{prefix}:*"):
        redis_client.delete(key)


@pytest.fixture
def stream(redis_backend):
    """MemoryStream backed by Redis."""
    return MemoryStream(backend=redis_backend)


# ------------------------------------------------------------------
# Store and retrieve
# ------------------------------------------------------------------


class TestStoreAndRetrieve:
    """Storing CycleResults and retrieving MemoryEntries via Redis."""

    def test_store_cycle_result_returns_entry(self, stream):
        result = build_test_cycle_result()
        entry = stream.store(result)
        assert entry.cycle_id == result.cycle_id
        assert entry.verdict_outcome == result.verdict.outcome

    def test_store_populates_all_fields(self, stream):
        result = build_test_cycle_result()
        entry = stream.store(result)
        assert entry.entry_id
        assert entry.cycle_id == result.cycle_id
        assert entry.packet_id == result.packet_id
        assert entry.verdict_outcome == result.verdict.outcome
        assert entry.verdict_confidence == result.verdict.confidence
        assert entry.stored_at is not None
        assert entry.content_hash
        assert entry.chain_hash
        assert entry.sequence_number == 0
        assert entry.prev_chain_hash == GENESIS_HASH

    def test_get_by_cycle_id_returns_stored_entry(self, stream):
        result = build_test_cycle_result()
        entry = stream.store(result)
        retrieved = stream.get_by_cycle_id(result.cycle_id)
        assert retrieved == entry

    def test_get_by_cycle_id_returns_none_for_missing(self, stream):
        assert stream.get_by_cycle_id("nonexistent") is None


# ------------------------------------------------------------------
# Hash chain built automatically
# ------------------------------------------------------------------


class TestHashChainBuilding:
    """The hash chain is built automatically during store."""

    def test_first_entry_links_to_genesis(self, stream):
        entry = stream.store(build_test_cycle_result(cycle_id="c1"))
        assert entry.prev_chain_hash == GENESIS_HASH
        assert entry.sequence_number == 0

    def test_second_entry_links_to_first(self, stream):
        entry1 = stream.store(build_test_cycle_result(cycle_id="c1"))
        entry2 = stream.store(build_test_cycle_result(cycle_id="c2"))
        assert entry2.prev_chain_hash == entry1.chain_hash
        assert entry2.sequence_number == 1

    def test_three_entry_chain(self, stream):
        e1 = stream.store(build_test_cycle_result(cycle_id="c1"))
        e2 = stream.store(build_test_cycle_result(cycle_id="c2"))
        e3 = stream.store(build_test_cycle_result(cycle_id="c3"))

        assert e1.prev_chain_hash == GENESIS_HASH
        assert e2.prev_chain_hash == e1.chain_hash
        assert e3.prev_chain_hash == e2.chain_hash

    def test_chain_hashes_are_unique(self, stream):
        e1 = stream.store(build_test_cycle_result(cycle_id="c1"))
        e2 = stream.store(build_test_cycle_result(cycle_id="c2"))
        e3 = stream.store(build_test_cycle_result(cycle_id="c3"))
        hashes = {e1.chain_hash, e2.chain_hash, e3.chain_hash}
        assert len(hashes) == 3


# ------------------------------------------------------------------
# Chain integrity verification
# ------------------------------------------------------------------


class TestChainIntegrity:
    """Chain integrity verification through Redis."""

    def test_verify_empty_chain_passes(self, stream):
        assert stream.verify_chain_integrity() is True

    def test_verify_single_entry_chain_passes(self, stream):
        stream.store(build_test_cycle_result(cycle_id="c1"))
        assert stream.verify_chain_integrity() is True

    def test_verify_multi_entry_chain_passes(self, stream):
        stream.store(build_test_cycle_result(cycle_id="c1"))
        stream.store(build_test_cycle_result(cycle_id="c2"))
        stream.store(build_test_cycle_result(cycle_id="c3"))
        assert stream.verify_chain_integrity() is True


# ------------------------------------------------------------------
# Duplicate rejection
# ------------------------------------------------------------------


class TestDuplicateRejection:
    """Duplicate cycle_id must be rejected at the stream level."""

    def test_store_duplicate_cycle_id_raises(self, stream):
        result = build_test_cycle_result(cycle_id="c1")
        stream.store(result)
        with pytest.raises(DuplicateEntryError):
            stream.store(result)

    def test_duplicate_does_not_corrupt_chain(self, stream):
        r1 = build_test_cycle_result(cycle_id="c1")
        stream.store(r1)

        r_dup = build_test_cycle_result(cycle_id="c1")
        with pytest.raises(DuplicateEntryError):
            stream.store(r_dup)

        assert stream.count == 1
        assert stream.verify_chain_integrity() is True


# ------------------------------------------------------------------
# Query delegation
# ------------------------------------------------------------------


class TestQueryDelegation:
    """Stream delegates queries to the RedisBackend."""

    def test_query_by_verdict(self, stream):
        stream.store(
            build_test_cycle_result(
                cycle_id="c1", outcome=VerdictOutcome.THREAT_CONFIRMED
            )
        )
        stream.store(
            build_test_cycle_result(
                cycle_id="c2", outcome=VerdictOutcome.THREAT_DISMISSED
            )
        )
        stream.store(
            build_test_cycle_result(
                cycle_id="c3", outcome=VerdictOutcome.THREAT_CONFIRMED
            )
        )

        threats = stream.query_by_verdict(VerdictOutcome.THREAT_CONFIRMED)
        assert len(threats) == 2
        assert all(
            e.verdict_outcome == VerdictOutcome.THREAT_CONFIRMED
            for e in threats
        )

    def test_query_by_packet_id(self, stream):
        stream.store(
            build_test_cycle_result(cycle_id="c1", packet_id="pkt-001")
        )
        stream.store(
            build_test_cycle_result(cycle_id="c2", packet_id="pkt-001")
        )
        stream.store(
            build_test_cycle_result(cycle_id="c3", packet_id="pkt-002")
        )

        results = stream.query_by_packet_id("pkt-001")
        assert len(results) == 2
        assert all(e.packet_id == "pkt-001" for e in results)

    def test_query_by_time_range(self, stream):
        stream.store(build_test_cycle_result(cycle_id="c1"))

        results = stream.query_by_time_range(
            datetime(2020, 1, 1), datetime(2030, 1, 1)
        )
        assert len(results) == 1

    def test_query_by_verdict_empty_result(self, stream):
        stream.store(
            build_test_cycle_result(
                cycle_id="c1", outcome=VerdictOutcome.THREAT_CONFIRMED
            )
        )
        results = stream.query_by_verdict(VerdictOutcome.INCONCLUSIVE)
        assert results == []


# ------------------------------------------------------------------
# Count and properties
# ------------------------------------------------------------------


class TestCountAndProperties:
    """Count and chain_head properties."""

    def test_count_starts_at_zero(self, stream):
        assert stream.count == 0

    def test_count_tracks_entries(self, stream):
        stream.store(build_test_cycle_result(cycle_id="c1"))
        assert stream.count == 1
        stream.store(build_test_cycle_result(cycle_id="c2"))
        assert stream.count == 2

    def test_chain_head_starts_at_genesis(self, stream):
        assert stream.chain_head == GENESIS_HASH

    def test_chain_head_updates_after_store(self, stream):
        entry = stream.store(build_test_cycle_result())
        assert stream.chain_head == entry.chain_hash

    def test_get_latest_empty_stream(self, stream):
        assert stream.get_latest() is None

    def test_get_latest_returns_most_recent(self, stream):
        stream.store(build_test_cycle_result(cycle_id="c1"))
        entry2 = stream.store(build_test_cycle_result(cycle_id="c2"))
        assert stream.get_latest() == entry2


# ------------------------------------------------------------------
# Chain continuity across restart (CRITICAL for Redis backend)
# ------------------------------------------------------------------


class TestChainContinuityAcrossRestart:
    """MemoryStream must hydrate chain state from existing RedisBackend entries.

    This is THE critical test for persistence — a new MemoryStream with the
    same RedisBackend must continue the chain, not restart from GENESIS_HASH.
    """

    def test_stream_resumes_from_prepopulated_backend(self, redis_backend):
        stream1 = MemoryStream(backend=redis_backend)
        stream1.store(build_test_cycle_result(cycle_id="c1"))
        stream1.store(build_test_cycle_result(cycle_id="c2"))
        entry3 = stream1.store(build_test_cycle_result(cycle_id="c3"))

        # New stream picks up from the same Redis backend
        stream2 = MemoryStream(backend=redis_backend)
        assert stream2.count == 3
        assert stream2.chain_head == entry3.chain_hash

    def test_resumed_stream_continues_chain(self, redis_backend):
        stream1 = MemoryStream(backend=redis_backend)
        stream1.store(build_test_cycle_result(cycle_id="c1"))
        stream1.store(build_test_cycle_result(cycle_id="c2"))
        entry3 = stream1.store(build_test_cycle_result(cycle_id="c3"))

        # New stream continues from where stream1 left off
        stream2 = MemoryStream(backend=redis_backend)
        entry4 = stream2.store(build_test_cycle_result(cycle_id="c4"))

        assert entry4.prev_chain_hash == entry3.chain_hash
        assert entry4.sequence_number == 3  # 0-indexed: 0, 1, 2, 3

    def test_resumed_stream_verifies_full_chain(self, redis_backend):
        stream1 = MemoryStream(backend=redis_backend)
        stream1.store(build_test_cycle_result(cycle_id="c1"))
        stream1.store(build_test_cycle_result(cycle_id="c2"))
        stream1.store(build_test_cycle_result(cycle_id="c3"))

        stream2 = MemoryStream(backend=redis_backend)
        stream2.store(build_test_cycle_result(cycle_id="c4"))
        assert stream2.verify_chain_integrity() is True


# ------------------------------------------------------------------
# Content hash integrity
# ------------------------------------------------------------------


class TestContentHashIntegrity:
    """Content hash correctly represents the CycleResult through Redis."""

    def test_content_hash_matches_recomputation(self, stream):
        result = build_test_cycle_result()
        entry = stream.store(result)

        recomputed = HashChain.compute_content_hash(entry.cycle_result)
        assert entry.content_hash == recomputed

    def test_different_results_produce_different_entries(self, stream):
        e1 = stream.store(build_test_cycle_result(cycle_id="c1"))
        e2 = stream.store(build_test_cycle_result(cycle_id="c2"))
        assert e1.content_hash != e2.content_hash
        assert e1.chain_hash != e2.chain_hash
        assert e1.entry_id != e2.entry_id


# ------------------------------------------------------------------
# Full pipeline integration
# ------------------------------------------------------------------


class TestFullPipelineIntegration:
    """Raw evidence → Orchestrator → MemoryStream(Redis) → Query."""

    def test_full_pipeline_orchestrator_to_redis_memory(self, stream):
        from ares.dialectic.coordinator.orchestrator import DialecticalOrchestrator

        packet = build_privilege_escalation_packet()
        orchestrator = DialecticalOrchestrator()
        result = orchestrator.run_cycle(packet)

        entry = stream.store(result)

        retrieved = stream.get_by_cycle_id(result.cycle_id)
        assert retrieved == entry
        assert retrieved.verdict_outcome == result.verdict.outcome
        assert retrieved.verdict_confidence == result.verdict.confidence
        assert stream.verify_chain_integrity() is True

    def test_multiple_cycles_stored_and_queried(self, stream):
        from ares.dialectic.coordinator.orchestrator import DialecticalOrchestrator

        packet = build_privilege_escalation_packet()
        orchestrator = DialecticalOrchestrator()

        results = []
        for _ in range(3):
            result = orchestrator.run_cycle(packet)
            stream.store(result)
            results.append(result)

        assert stream.count == 3
        assert stream.verify_chain_integrity() is True

        for r in results:
            retrieved = stream.get_by_cycle_id(r.cycle_id)
            assert retrieved is not None
            assert retrieved.cycle_id == r.cycle_id
