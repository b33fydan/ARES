"""Tests for MemoryEntry — immutable record with hash chain linkage."""

import pytest

from ares.dialectic.agents.patterns import VerdictOutcome
from ares.dialectic.memory.chain import GENESIS_HASH, HashChain
from ares.dialectic.memory.entry import MemoryEntry

from .conftest import build_test_cycle_result, build_test_entry


# ------------------------------------------------------------------
# Immutability
# ------------------------------------------------------------------


class TestMemoryEntryImmutability:
    """MemoryEntry is frozen — no field can be modified after creation."""

    def test_memory_entry_is_frozen(self):
        entry = build_test_entry()
        with pytest.raises(AttributeError):
            entry.cycle_id = "tampered"

    def test_cannot_modify_entry_id(self):
        entry = build_test_entry()
        with pytest.raises(AttributeError):
            entry.entry_id = "tampered"

    def test_cannot_modify_content_hash(self):
        entry = build_test_entry()
        with pytest.raises(AttributeError):
            entry.content_hash = "tampered"

    def test_cannot_modify_chain_hash(self):
        entry = build_test_entry()
        with pytest.raises(AttributeError):
            entry.chain_hash = "tampered"

    def test_cannot_modify_sequence_number(self):
        entry = build_test_entry()
        with pytest.raises(AttributeError):
            entry.sequence_number = 999

    def test_cannot_modify_verdict_outcome(self):
        entry = build_test_entry()
        with pytest.raises(AttributeError):
            entry.verdict_outcome = VerdictOutcome.INCONCLUSIVE


# ------------------------------------------------------------------
# Content hash determinism
# ------------------------------------------------------------------


class TestContentHashDeterminism:
    """Same CycleResult must produce the same content hash every time."""

    def test_same_cycle_result_produces_same_content_hash(self):
        result = build_test_cycle_result(cycle_id="c1")
        hash1 = HashChain.compute_content_hash(result)
        hash2 = HashChain.compute_content_hash(result)
        assert hash1 == hash2

    def test_content_hash_is_64_char_hex(self):
        result = build_test_cycle_result()
        h = HashChain.compute_content_hash(result)
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)

    def test_different_cycle_ids_produce_different_hashes(self):
        r1 = build_test_cycle_result(cycle_id="cycle-aaa")
        r2 = build_test_cycle_result(cycle_id="cycle-bbb")
        assert HashChain.compute_content_hash(r1) != HashChain.compute_content_hash(r2)

    def test_content_hash_changes_when_verdict_reasoning_differs(self):
        """Altering verdict.reasoning must change the content_hash."""
        r1 = build_test_cycle_result(
            cycle_id="c1", reasoning="Threat detected via priv escalation"
        )
        r2 = build_test_cycle_result(
            cycle_id="c1", reasoning="Threat detected via lateral movement"
        )
        assert HashChain.compute_content_hash(r1) != HashChain.compute_content_hash(r2)

    def test_content_hash_changes_when_confidence_differs(self):
        r1 = build_test_cycle_result(cycle_id="c1", confidence=0.85)
        r2 = build_test_cycle_result(cycle_id="c1", confidence=0.90)
        assert HashChain.compute_content_hash(r1) != HashChain.compute_content_hash(r2)

    def test_content_hash_changes_when_outcome_differs(self):
        r1 = build_test_cycle_result(
            cycle_id="c1", outcome=VerdictOutcome.THREAT_CONFIRMED
        )
        r2 = build_test_cycle_result(
            cycle_id="c1", outcome=VerdictOutcome.THREAT_DISMISSED
        )
        assert HashChain.compute_content_hash(r1) != HashChain.compute_content_hash(r2)

    def test_content_hash_changes_with_vs_without_narrator(self):
        r1 = build_test_cycle_result(cycle_id="c1", include_narrator=True)
        r2 = build_test_cycle_result(cycle_id="c1", include_narrator=False)
        assert HashChain.compute_content_hash(r1) != HashChain.compute_content_hash(r2)

    def test_content_hash_changes_when_packet_id_differs(self):
        r1 = build_test_cycle_result(cycle_id="c1", packet_id="packet-aaa")
        r2 = build_test_cycle_result(cycle_id="c1", packet_id="packet-bbb")
        assert HashChain.compute_content_hash(r1) != HashChain.compute_content_hash(r2)


# ------------------------------------------------------------------
# Denormalized fields
# ------------------------------------------------------------------


class TestDenormalizedFields:
    """Denormalized fields must match the source CycleResult."""

    def test_denormalized_verdict_outcome_matches_cycle_result(self):
        entry = build_test_entry()
        assert entry.verdict_outcome == entry.cycle_result.verdict.outcome

    def test_denormalized_verdict_confidence_matches_cycle_result(self):
        entry = build_test_entry()
        assert entry.verdict_confidence == entry.cycle_result.verdict.confidence

    def test_denormalized_packet_id_matches_cycle_result(self):
        entry = build_test_entry()
        assert entry.packet_id == entry.cycle_result.packet_id

    def test_denormalized_cycle_id_matches_cycle_result(self):
        entry = build_test_entry()
        assert entry.cycle_id == entry.cycle_result.cycle_id


# ------------------------------------------------------------------
# Hash chain linkage
# ------------------------------------------------------------------


class TestHashChainLinkage:
    """Entry's hash fields must be consistent with its chain position."""

    def test_first_entry_uses_genesis_hash(self):
        entry = build_test_entry(sequence_number=0, prev_chain_hash=GENESIS_HASH)
        assert entry.prev_chain_hash == GENESIS_HASH

    def test_content_hash_matches_cycle_result(self):
        result = build_test_cycle_result(cycle_id="c1")
        entry = build_test_entry(cycle_result=result)
        assert entry.content_hash == HashChain.compute_content_hash(result)

    def test_chain_hash_computed_correctly(self):
        entry = build_test_entry(prev_chain_hash=GENESIS_HASH)
        expected = HashChain.compute_chain_hash(GENESIS_HASH, entry.content_hash)
        assert entry.chain_hash == expected

    def test_entry_has_all_required_fields(self):
        entry = build_test_entry()
        assert entry.entry_id
        assert entry.cycle_id
        assert entry.packet_id
        assert entry.content_hash
        assert entry.chain_hash
        assert entry.stored_at is not None
        assert entry.sequence_number >= 0
        assert entry.prev_chain_hash
