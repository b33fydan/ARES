"""Tests for HashChain — tamper-evident audit log."""

import pytest

from ares.dialectic.memory.chain import GENESIS_HASH, ChainLink, HashChain

from .conftest import build_test_cycle_result


# ------------------------------------------------------------------
# Genesis
# ------------------------------------------------------------------


class TestGenesisHash:
    """The genesis hash is a 64-char zero string."""

    def test_genesis_hash_is_64_zeros(self):
        assert GENESIS_HASH == "0" * 64

    def test_genesis_hash_length(self):
        assert len(GENESIS_HASH) == 64


# ------------------------------------------------------------------
# Chain initialization
# ------------------------------------------------------------------


class TestChainInitialization:
    """A new HashChain starts at genesis."""

    def test_new_chain_head_is_genesis(self):
        chain = HashChain()
        assert chain.head_hash == GENESIS_HASH

    def test_new_chain_sequence_is_zero(self):
        chain = HashChain()
        assert chain.sequence == 0


# ------------------------------------------------------------------
# Adding links
# ------------------------------------------------------------------


class TestChainAdd:
    """Adding links to the chain."""

    def test_first_link_uses_genesis_hash(self):
        chain = HashChain()
        link = chain.add("abc123")
        assert link.prev_chain_hash == GENESIS_HASH
        assert link.sequence_number == 0

    def test_chain_links_use_previous_hash(self):
        chain = HashChain()
        link1 = chain.add("hash1")
        link2 = chain.add("hash2")
        assert link2.prev_chain_hash == link1.chain_hash
        assert link2.sequence_number == 1

    def test_head_hash_updates_after_add(self):
        chain = HashChain()
        link = chain.add("content")
        assert chain.head_hash == link.chain_hash

    def test_sequence_increments_after_add(self):
        chain = HashChain()
        chain.add("a")
        chain.add("b")
        chain.add("c")
        assert chain.sequence == 3

    def test_chain_link_is_frozen(self):
        chain = HashChain()
        link = chain.add("content")
        with pytest.raises(AttributeError):
            link.chain_hash = "tampered"

    def test_three_link_chain_integrity(self):
        chain = HashChain()
        link1 = chain.add("first")
        link2 = chain.add("second")
        link3 = chain.add("third")

        assert link1.prev_chain_hash == GENESIS_HASH
        assert link2.prev_chain_hash == link1.chain_hash
        assert link3.prev_chain_hash == link2.chain_hash
        assert link3.sequence_number == 2


# ------------------------------------------------------------------
# compute_chain_hash
# ------------------------------------------------------------------


class TestComputeChainHash:
    """The static chain hash computation."""

    def test_compute_chain_hash_is_deterministic(self):
        h1 = HashChain.compute_chain_hash("prev", "content")
        h2 = HashChain.compute_chain_hash("prev", "content")
        assert h1 == h2

    def test_compute_chain_hash_is_64_char_hex(self):
        h = HashChain.compute_chain_hash("prev", "content")
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)

    def test_different_prev_produces_different_hash(self):
        h1 = HashChain.compute_chain_hash("prev1", "content")
        h2 = HashChain.compute_chain_hash("prev2", "content")
        assert h1 != h2

    def test_different_content_produces_different_hash(self):
        h1 = HashChain.compute_chain_hash("prev", "content1")
        h2 = HashChain.compute_chain_hash("prev", "content2")
        assert h1 != h2

    def test_order_matters(self):
        h1 = HashChain.compute_chain_hash("A", "B")
        h2 = HashChain.compute_chain_hash("B", "A")
        assert h1 != h2


# ------------------------------------------------------------------
# verify_link
# ------------------------------------------------------------------


class TestVerifyLink:
    """Link verification detects tampering."""

    def test_verify_valid_link(self):
        chain = HashChain()
        link = chain.add("content")
        assert HashChain.verify_link(link, GENESIS_HASH) is True

    def test_verify_valid_second_link(self):
        chain = HashChain()
        link1 = chain.add("first")
        link2 = chain.add("second")
        assert HashChain.verify_link(link2, link1.chain_hash) is True

    def test_verify_detects_tampered_content(self):
        chain = HashChain()
        link = chain.add("content")
        tampered = ChainLink(
            content_hash="tampered",
            prev_chain_hash=link.prev_chain_hash,
            chain_hash=link.chain_hash,
            sequence_number=link.sequence_number,
        )
        assert HashChain.verify_link(tampered, GENESIS_HASH) is False

    def test_verify_detects_wrong_prev_hash(self):
        chain = HashChain()
        link = chain.add("content")
        assert HashChain.verify_link(link, "wrong_prev_hash") is False

    def test_verify_detects_tampered_chain_hash(self):
        chain = HashChain()
        link = chain.add("content")
        tampered = ChainLink(
            content_hash=link.content_hash,
            prev_chain_hash=link.prev_chain_hash,
            chain_hash="tampered_chain_hash",
            sequence_number=link.sequence_number,
        )
        assert HashChain.verify_link(tampered, GENESIS_HASH) is False


# ------------------------------------------------------------------
# compute_content_hash
# ------------------------------------------------------------------


class TestComputeContentHash:
    """Content hash from CycleResult."""

    def test_compute_content_hash_deterministic(self):
        result = build_test_cycle_result(cycle_id="c1")
        h1 = HashChain.compute_content_hash(result)
        h2 = HashChain.compute_content_hash(result)
        assert h1 == h2

    def test_compute_content_hash_is_64_char_hex(self):
        result = build_test_cycle_result()
        h = HashChain.compute_content_hash(result)
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)

    def test_different_results_produce_different_hashes(self):
        r1 = build_test_cycle_result(cycle_id="cycle-001")
        r2 = build_test_cycle_result(cycle_id="cycle-002")
        assert HashChain.compute_content_hash(r1) != HashChain.compute_content_hash(r2)

    def test_content_hash_covers_verdict(self):
        r1 = build_test_cycle_result(
            cycle_id="c1", outcome=VerdictOutcome.THREAT_CONFIRMED
        )
        r2 = build_test_cycle_result(
            cycle_id="c1", outcome=VerdictOutcome.THREAT_DISMISSED
        )
        assert HashChain.compute_content_hash(r1) != HashChain.compute_content_hash(r2)


# ------------------------------------------------------------------
# Chain restore
# ------------------------------------------------------------------


class TestChainRestore:
    """Chain state can be restored for backend resumption."""

    def test_restore_sets_head_hash(self):
        chain = HashChain()
        chain.restore("abc123", 5)
        assert chain.head_hash == "abc123"

    def test_restore_sets_sequence(self):
        chain = HashChain()
        chain.restore("abc123", 5)
        assert chain.sequence == 5

    def test_restore_then_add_continues_chain(self):
        chain = HashChain()
        chain.restore("prev_head", 3)
        link = chain.add("new_content")
        assert link.prev_chain_hash == "prev_head"
        assert link.sequence_number == 3
        assert chain.sequence == 4


# Need this import for the parameterized test
from ares.dialectic.agents.patterns import VerdictOutcome
