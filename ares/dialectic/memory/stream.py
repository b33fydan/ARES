"""MemoryStream — the immune system's memory.

Stores and queries dialectical cycle results with tamper-evident
hash chain integrity. Composes a MemoryBackend (storage) with a
HashChain (integrity).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import List, Optional

from ares.dialectic.agents.patterns import VerdictOutcome
from ares.dialectic.coordinator.orchestrator import CycleResult
from ares.dialectic.memory.chain import GENESIS_HASH, HashChain
from ares.dialectic.memory.entry import MemoryEntry
from ares.dialectic.memory.errors import (
    ChainIntegrityError,
    DuplicateEntryError,
    MemoryStreamError,
)
from ares.dialectic.memory.protocol import MemoryBackend


class MemoryStream:
    """The immune system's memory — stores and queries dialectical cycle results
    with tamper-evident hash chain integrity.

    Composes a MemoryBackend (storage) with a HashChain (integrity).
    Write-only from the Orchestrator's perspective.
    """

    def __init__(self, *, backend: MemoryBackend) -> None:
        """Initialize the MemoryStream.

        Args:
            backend: Storage backend implementing MemoryBackend protocol.

        Initializes HashChain state from the backend, ensuring chain
        continuity across restarts (critical for future Redis backend).
        If backend is empty, HashChain starts at GENESIS_HASH with sequence 0.
        """
        self._backend = backend
        self._chain = HashChain()

        # Hydrate chain state from pre-populated backend
        chain_head = backend.get_chain_head()
        entry_count = backend.count()
        if chain_head is not None and entry_count > 0:
            self._chain.restore(chain_head, entry_count)

    def store(self, cycle_result: CycleResult) -> MemoryEntry:
        """Store a CycleResult as a MemoryEntry with hash chain linkage.

        Args:
            cycle_result: Frozen CycleResult from DialecticalOrchestrator.

        Returns:
            The created MemoryEntry.

        Raises:
            DuplicateEntryError: If cycle_id already stored.
            MemoryStreamError: On storage failure.
        """
        # Check for duplicate cycle_id before computing hashes
        existing = self._backend.get_by_cycle_id(cycle_result.cycle_id)
        if existing is not None:
            raise DuplicateEntryError(
                f"CycleResult with cycle_id '{cycle_result.cycle_id}' already stored",
                entry_id=cycle_result.cycle_id,
                field="cycle_id",
            )

        # Compute content hash and chain link
        content_hash = HashChain.compute_content_hash(cycle_result)
        link = self._chain.add(content_hash)

        # Build the MemoryEntry
        entry = MemoryEntry(
            entry_id=uuid.uuid4().hex,
            cycle_id=cycle_result.cycle_id,
            packet_id=cycle_result.packet_id,
            verdict_outcome=cycle_result.verdict.outcome,
            verdict_confidence=cycle_result.verdict.confidence,
            cycle_result=cycle_result,
            stored_at=datetime.utcnow(),
            content_hash=content_hash,
            chain_hash=link.chain_hash,
            sequence_number=link.sequence_number,
            prev_chain_hash=link.prev_chain_hash,
        )

        # Persist
        try:
            self._backend.store(entry)
        except DuplicateEntryError:
            raise
        except Exception as e:
            raise MemoryStreamError(
                f"Failed to store entry: {e}"
            ) from e

        return entry

    def get_by_cycle_id(self, cycle_id: str) -> Optional[MemoryEntry]:
        """Retrieve entry by cycle_id."""
        return self._backend.get_by_cycle_id(cycle_id)

    def query_by_verdict(self, outcome: VerdictOutcome) -> List[MemoryEntry]:
        """All entries with matching verdict outcome."""
        return self._backend.query_by_verdict(outcome)

    def query_by_packet_id(self, packet_id: str) -> List[MemoryEntry]:
        """All entries for a given packet_id."""
        return self._backend.query_by_packet_id(packet_id)

    def query_by_time_range(
        self, start: datetime, end: datetime
    ) -> List[MemoryEntry]:
        """Entries stored within time range."""
        return self._backend.query_by_time_range(start, end)

    def verify_chain_integrity(self) -> bool:
        """Walk the full chain and verify every link.

        Returns:
            True if intact.

        Raises:
            ChainIntegrityError: On first failure.
        """
        entries = self._backend.get_all_ordered()
        if not entries:
            return True

        expected_prev = GENESIS_HASH
        for entry in entries:
            # Verify the chain linkage
            expected_chain = HashChain.compute_chain_hash(
                expected_prev, entry.content_hash
            )
            if entry.chain_hash != expected_chain:
                raise ChainIntegrityError(
                    f"Chain integrity broken at entry {entry.entry_id} "
                    f"(sequence {entry.sequence_number})",
                    entry_id=entry.entry_id,
                    expected_hash=expected_chain,
                    actual_hash=entry.chain_hash,
                )
            if entry.prev_chain_hash != expected_prev:
                raise ChainIntegrityError(
                    f"Previous hash mismatch at entry {entry.entry_id} "
                    f"(sequence {entry.sequence_number})",
                    entry_id=entry.entry_id,
                    expected_hash=expected_prev,
                    actual_hash=entry.prev_chain_hash,
                )
            expected_prev = entry.chain_hash

        return True

    def get_latest(self) -> Optional[MemoryEntry]:
        """Most recent entry."""
        return self._backend.get_latest()

    @property
    def count(self) -> int:
        """Number of entries stored."""
        return self._backend.count()

    @property
    def chain_head(self) -> str:
        """Current hash chain head."""
        return self._chain.head_hash
