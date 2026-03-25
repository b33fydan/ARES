"""RedisBackend — Redis-backed MemoryBackend for persistent storage.

Implements MemoryBackend protocol using Redis sorted sets for ordered
queries and JSON serialization for MemoryEntry storage.

Thread-safe via Redis atomic pipelines. Persistent across restarts.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Dict, List, Optional

import redis as _redis_lib

from ares.dialectic.agents.patterns import Verdict, VerdictOutcome
from ares.dialectic.coordinator.orchestrator import CycleResult
from ares.dialectic.memory.entry import MemoryEntry
from ares.dialectic.memory.errors import DuplicateEntryError
from ares.dialectic.messages.assertions import Assertion, AssertionType
from ares.dialectic.messages.protocol import (
    DialecticalMessage,
    MessageType,
    Phase,
    Priority,
)


class RedisBackend:
    """Redis-backed MemoryBackend for persistent storage.

    Stores MemoryEntries as JSON with sorted-set indices for ordered queries.
    All query methods return results ordered by sequence_number ascending.

    Key schema (prefix defaults to "ares"):
        {prefix}:entry:{entry_id}          → JSON-serialized MemoryEntry
        {prefix}:idx:cycle:{cycle_id}      → entry_id string
        {prefix}:idx:packet:{packet_id}    → sorted set (score=seq, member=entry_id)
        {prefix}:idx:verdict:{outcome}     → sorted set (score=seq, member=entry_id)
        {prefix}:idx:time                  → sorted set (score=stored_at ts, member=entry_id)
        {prefix}:ordered                   → sorted set (score=seq, member=entry_id)
        {prefix}:meta:chain_head           → chain hash string
        {prefix}:meta:count                → integer
    """

    def __init__(
        self, client: _redis_lib.Redis, *, key_prefix: str = "ares"
    ) -> None:
        """Initialize with an injected Redis client.

        Args:
            client: A redis.Redis instance (caller manages connection).
            key_prefix: Namespace prefix for all keys. Enables test isolation.
        """
        self._client = client
        self._prefix = key_prefix

    # ------------------------------------------------------------------
    # Key helpers
    # ------------------------------------------------------------------

    def _key(self, *parts: str) -> str:
        """Build a namespaced Redis key."""
        return ":".join([self._prefix] + list(parts))

    # ------------------------------------------------------------------
    # Store
    # ------------------------------------------------------------------

    def store(self, entry: MemoryEntry) -> None:
        """Persist a MemoryEntry atomically via pipeline.

        Raises:
            DuplicateEntryError: If entry_id or cycle_id already exists.
        """
        entry_key = self._key("entry", entry.entry_id)
        cycle_key = self._key("idx", "cycle", entry.cycle_id)

        # Check duplicates before pipeline
        if self._client.exists(entry_key):
            raise DuplicateEntryError(
                f"Entry with entry_id '{entry.entry_id}' already exists",
                entry_id=entry.entry_id,
                field="entry_id",
            )
        if self._client.exists(cycle_key):
            raise DuplicateEntryError(
                f"Entry with cycle_id '{entry.cycle_id}' already exists",
                entry_id=entry.cycle_id,
                field="cycle_id",
            )

        # Atomic pipeline write
        pipe = self._client.pipeline(transaction=True)
        pipe.set(entry_key, _serialize_entry(entry))
        pipe.set(cycle_key, entry.entry_id)
        pipe.zadd(
            self._key("idx", "packet", entry.packet_id),
            {entry.entry_id: entry.sequence_number},
        )
        pipe.zadd(
            self._key("idx", "verdict", entry.verdict_outcome.value),
            {entry.entry_id: entry.sequence_number},
        )
        pipe.zadd(
            self._key("idx", "time"),
            {entry.entry_id: entry.stored_at.timestamp()},
        )
        pipe.zadd(
            self._key("ordered"),
            {entry.entry_id: entry.sequence_number},
        )
        pipe.set(self._key("meta", "chain_head"), entry.chain_hash)
        pipe.incr(self._key("meta", "count"))
        pipe.execute()

    # ------------------------------------------------------------------
    # Single-entry retrieval
    # ------------------------------------------------------------------

    def get_by_entry_id(self, entry_id: str) -> Optional[MemoryEntry]:
        """Retrieve by entry_id. Returns None if not found."""
        raw = self._client.get(self._key("entry", entry_id))
        if raw is None:
            return None
        return _deserialize_entry(raw)

    def get_by_cycle_id(self, cycle_id: str) -> Optional[MemoryEntry]:
        """Retrieve by cycle_id. Returns None if not found."""
        entry_id = self._client.get(self._key("idx", "cycle", cycle_id))
        if entry_id is None:
            return None
        if isinstance(entry_id, bytes):
            entry_id = entry_id.decode("utf-8")
        return self.get_by_entry_id(entry_id)

    # ------------------------------------------------------------------
    # Query methods (all return ordered by sequence_number)
    # ------------------------------------------------------------------

    def query_by_packet_id(self, packet_id: str) -> List[MemoryEntry]:
        """All entries for a given packet_id, ordered by sequence_number."""
        return self._fetch_by_sorted_set(
            self._key("idx", "packet", packet_id)
        )

    def query_by_verdict(self, outcome: VerdictOutcome) -> List[MemoryEntry]:
        """All entries with matching verdict outcome, ordered by sequence_number."""
        return self._fetch_by_sorted_set(
            self._key("idx", "verdict", outcome.value)
        )

    def query_by_time_range(
        self, start: datetime, end: datetime
    ) -> List[MemoryEntry]:
        """Entries where stored_at is within [start, end], ordered by sequence_number."""
        # Get entry_ids in the time range from the time index
        entry_ids = self._client.zrangebyscore(
            self._key("idx", "time"),
            min=start.timestamp(),
            max=end.timestamp(),
        )
        if not entry_ids:
            return []

        # Fetch entries and sort by sequence_number
        entries = self._fetch_entries_by_ids(entry_ids)
        entries.sort(key=lambda e: e.sequence_number)
        return entries

    def get_all_ordered(self) -> List[MemoryEntry]:
        """All entries ordered by sequence_number. Used for chain verification."""
        return self._fetch_by_sorted_set(self._key("ordered"))

    # ------------------------------------------------------------------
    # Metadata
    # ------------------------------------------------------------------

    def get_latest(self) -> Optional[MemoryEntry]:
        """Most recent entry by sequence_number. None if empty."""
        # Get the highest-scored entry from the ordered set
        result = self._client.zrange(
            self._key("ordered"), -1, -1
        )
        if not result:
            return None
        entry_id = result[0]
        if isinstance(entry_id, bytes):
            entry_id = entry_id.decode("utf-8")
        return self.get_by_entry_id(entry_id)

    def count(self) -> int:
        """Total number of stored entries."""
        raw = self._client.get(self._key("meta", "count"))
        if raw is None:
            return 0
        return int(raw)

    def get_chain_head(self) -> Optional[str]:
        """Return the chain_hash of the latest entry. None if empty."""
        raw = self._client.get(self._key("meta", "chain_head"))
        if raw is None:
            return None
        if isinstance(raw, bytes):
            return raw.decode("utf-8")
        return raw

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _fetch_by_sorted_set(self, key: str) -> List[MemoryEntry]:
        """Fetch entries from a sorted set, ordered by score (sequence_number)."""
        entry_ids = self._client.zrange(key, 0, -1)
        if not entry_ids:
            return []
        return self._fetch_entries_by_ids(entry_ids)

    def _fetch_entries_by_ids(
        self, entry_ids: List[bytes | str]
    ) -> List[MemoryEntry]:
        """Batch-fetch entries by ID using pipeline."""
        if not entry_ids:
            return []

        decoded_ids = [
            eid.decode("utf-8") if isinstance(eid, bytes) else eid
            for eid in entry_ids
        ]

        pipe = self._client.pipeline(transaction=False)
        for eid in decoded_ids:
            pipe.get(self._key("entry", eid))
        raw_entries = pipe.execute()

        entries: List[MemoryEntry] = []
        for raw in raw_entries:
            if raw is not None:
                entries.append(_deserialize_entry(raw))
        return entries


# ------------------------------------------------------------------
# Serialization (module-level, stateless)
# ------------------------------------------------------------------


def _serialize_entry(entry: MemoryEntry) -> str:
    """Serialize a MemoryEntry to JSON string."""
    data: Dict[str, Any] = {
        "entry_id": entry.entry_id,
        "cycle_id": entry.cycle_id,
        "packet_id": entry.packet_id,
        "verdict_outcome": entry.verdict_outcome.value,
        "verdict_confidence": entry.verdict_confidence,
        "cycle_result": _serialize_cycle_result(entry.cycle_result),
        "stored_at": entry.stored_at.isoformat(),
        "content_hash": entry.content_hash,
        "chain_hash": entry.chain_hash,
        "sequence_number": entry.sequence_number,
        "prev_chain_hash": entry.prev_chain_hash,
    }
    return json.dumps(data, separators=(",", ":"))


def _deserialize_entry(raw: bytes | str) -> MemoryEntry:
    """Deserialize a JSON string back to a MemoryEntry."""
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8")
    data = json.loads(raw)

    return MemoryEntry(
        entry_id=data["entry_id"],
        cycle_id=data["cycle_id"],
        packet_id=data["packet_id"],
        verdict_outcome=VerdictOutcome(data["verdict_outcome"]),
        verdict_confidence=data["verdict_confidence"],
        cycle_result=_deserialize_cycle_result(data["cycle_result"]),
        stored_at=datetime.fromisoformat(data["stored_at"]),
        content_hash=data["content_hash"],
        chain_hash=data["chain_hash"],
        sequence_number=data["sequence_number"],
        prev_chain_hash=data["prev_chain_hash"],
    )


# ------------------------------------------------------------------
# CycleResult serialization
# ------------------------------------------------------------------


def _serialize_cycle_result(cr: CycleResult) -> Dict[str, Any]:
    """Serialize CycleResult to a JSON-safe dict."""
    return {
        "cycle_id": cr.cycle_id,
        "packet_id": cr.packet_id,
        "verdict": _serialize_verdict(cr.verdict),
        "architect_message": cr.architect_message.to_dict(),
        "skeptic_message": cr.skeptic_message.to_dict(),
        "narrator_message": (
            cr.narrator_message.to_dict()
            if cr.narrator_message is not None
            else None
        ),
        "started_at": cr.started_at.isoformat(),
        "completed_at": cr.completed_at.isoformat(),
        "duration_ms": cr.duration_ms,
    }


def _deserialize_cycle_result(data: Dict[str, Any]) -> CycleResult:
    """Deserialize a dict back to CycleResult."""
    narrator_data = data["narrator_message"]
    return CycleResult(
        cycle_id=data["cycle_id"],
        packet_id=data["packet_id"],
        verdict=_deserialize_verdict(data["verdict"]),
        architect_message=DialecticalMessage.from_dict(
            data["architect_message"]
        ),
        skeptic_message=DialecticalMessage.from_dict(
            data["skeptic_message"]
        ),
        narrator_message=(
            DialecticalMessage.from_dict(narrator_data)
            if narrator_data is not None
            else None
        ),
        started_at=datetime.fromisoformat(data["started_at"]),
        completed_at=datetime.fromisoformat(data["completed_at"]),
        duration_ms=data["duration_ms"],
    )


# ------------------------------------------------------------------
# Verdict serialization
# ------------------------------------------------------------------


def _serialize_verdict(v: Verdict) -> Dict[str, Any]:
    """Serialize Verdict to a JSON-safe dict."""
    return {
        "outcome": v.outcome.value,
        "confidence": v.confidence,
        "supporting_fact_ids": sorted(v.supporting_fact_ids),
        "architect_confidence": v.architect_confidence,
        "skeptic_confidence": v.skeptic_confidence,
        "reasoning": v.reasoning,
    }


def _deserialize_verdict(data: Dict[str, Any]) -> Verdict:
    """Deserialize a dict back to Verdict."""
    return Verdict(
        outcome=VerdictOutcome(data["outcome"]),
        confidence=data["confidence"],
        supporting_fact_ids=frozenset(data["supporting_fact_ids"]),
        architect_confidence=data["architect_confidence"],
        skeptic_confidence=data["skeptic_confidence"],
        reasoning=data["reasoning"],
    )
