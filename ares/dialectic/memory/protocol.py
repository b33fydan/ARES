"""MemoryBackend protocol — abstract storage interface.

Defines the contract that all storage backends must satisfy.
Implementations: InMemoryBackend (testing), RedisBackend (future).
"""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional, Protocol, runtime_checkable

from ares.dialectic.agents.patterns import VerdictOutcome
from ares.dialectic.memory.entry import MemoryEntry


@runtime_checkable
class MemoryBackend(Protocol):
    """Abstract storage interface for MemoryEntries.

    All query methods returning lists order results by sequence_number.
    """

    def store(self, entry: MemoryEntry) -> None:
        """Persist a MemoryEntry.

        Raises:
            DuplicateEntryError: If entry_id or cycle_id already exists.
        """
        ...

    def get_by_entry_id(self, entry_id: str) -> Optional[MemoryEntry]:
        """Retrieve by entry_id. Returns None if not found."""
        ...

    def get_by_cycle_id(self, cycle_id: str) -> Optional[MemoryEntry]:
        """Retrieve by cycle_id. Returns None if not found."""
        ...

    def query_by_packet_id(self, packet_id: str) -> List[MemoryEntry]:
        """All entries for a given packet_id, ordered by sequence_number."""
        ...

    def query_by_verdict(self, outcome: VerdictOutcome) -> List[MemoryEntry]:
        """All entries with matching verdict outcome, ordered by sequence_number."""
        ...

    def query_by_time_range(
        self, start: datetime, end: datetime
    ) -> List[MemoryEntry]:
        """Entries where stored_at is within [start, end], ordered by sequence_number."""
        ...

    def get_latest(self) -> Optional[MemoryEntry]:
        """Most recent entry by sequence_number. None if empty."""
        ...

    def count(self) -> int:
        """Total number of stored entries."""
        ...

    def get_chain_head(self) -> Optional[str]:
        """Return the chain_hash of the latest entry. None if empty."""
        ...

    def get_all_ordered(self) -> List[MemoryEntry]:
        """All entries ordered by sequence_number. Used for chain verification."""
        ...
