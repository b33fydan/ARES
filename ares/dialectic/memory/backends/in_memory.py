"""InMemoryBackend — dict-based MemoryBackend for testing.

NOT thread-safe. NOT persistent across restarts.
Implements MemoryBackend protocol.
"""

from __future__ import annotations

from datetime import datetime
from typing import Dict, List, Optional

from ares.dialectic.agents.patterns import VerdictOutcome
from ares.dialectic.memory.entry import MemoryEntry
from ares.dialectic.memory.errors import DuplicateEntryError


class InMemoryBackend:
    """Dict-based MemoryBackend for testing and development.

    Stores entries in memory using dicts and a sorted list.
    All query methods return results ordered by sequence_number.
    """

    def __init__(self) -> None:
        self._entries_by_id: Dict[str, MemoryEntry] = {}
        self._entries_by_cycle: Dict[str, MemoryEntry] = {}
        self._entries_ordered: List[MemoryEntry] = []

    def store(self, entry: MemoryEntry) -> None:
        """Persist a MemoryEntry.

        Args:
            entry: The entry to store.

        Raises:
            DuplicateEntryError: If entry_id or cycle_id already exists.
        """
        if entry.entry_id in self._entries_by_id:
            raise DuplicateEntryError(
                f"Entry with entry_id '{entry.entry_id}' already exists",
                entry_id=entry.entry_id,
                field="entry_id",
            )
        if entry.cycle_id in self._entries_by_cycle:
            raise DuplicateEntryError(
                f"Entry with cycle_id '{entry.cycle_id}' already exists",
                entry_id=entry.cycle_id,
                field="cycle_id",
            )

        self._entries_by_id[entry.entry_id] = entry
        self._entries_by_cycle[entry.cycle_id] = entry
        self._entries_ordered.append(entry)

    def get_by_entry_id(self, entry_id: str) -> Optional[MemoryEntry]:
        """Retrieve by entry_id. Returns None if not found."""
        return self._entries_by_id.get(entry_id)

    def get_by_cycle_id(self, cycle_id: str) -> Optional[MemoryEntry]:
        """Retrieve by cycle_id. Returns None if not found."""
        return self._entries_by_cycle.get(cycle_id)

    def query_by_packet_id(self, packet_id: str) -> List[MemoryEntry]:
        """All entries for a given packet_id, ordered by sequence_number."""
        return [
            e for e in self._entries_ordered if e.packet_id == packet_id
        ]

    def query_by_verdict(self, outcome: VerdictOutcome) -> List[MemoryEntry]:
        """All entries with matching verdict outcome, ordered by sequence_number."""
        return [
            e for e in self._entries_ordered if e.verdict_outcome == outcome
        ]

    def query_by_time_range(
        self, start: datetime, end: datetime
    ) -> List[MemoryEntry]:
        """Entries where stored_at is within [start, end], ordered by sequence_number."""
        return [
            e
            for e in self._entries_ordered
            if start <= e.stored_at <= end
        ]

    def get_latest(self) -> Optional[MemoryEntry]:
        """Most recent entry by sequence_number. None if empty."""
        if not self._entries_ordered:
            return None
        return self._entries_ordered[-1]

    def count(self) -> int:
        """Total number of stored entries."""
        return len(self._entries_ordered)

    def get_chain_head(self) -> Optional[str]:
        """Return the chain_hash of the latest entry. None if empty."""
        if not self._entries_ordered:
            return None
        return self._entries_ordered[-1].chain_hash

    def get_all_ordered(self) -> List[MemoryEntry]:
        """All entries ordered by sequence_number."""
        return list(self._entries_ordered)
