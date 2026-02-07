"""MemoryEntry — immutable record of a completed dialectical cycle.

Each MemoryEntry captures a CycleResult with hash chain linkage,
enabling tamper-evident audit trails.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from ares.dialectic.agents.patterns import VerdictOutcome
from ares.dialectic.coordinator.orchestrator import CycleResult


@dataclass(frozen=True)
class MemoryEntry:
    """An immutable record of a completed dialectical cycle.

    Stored by the MemoryStream with hash chain integrity.

    Attributes:
        entry_id: UUID, unique per entry.
        cycle_id: From CycleResult.cycle_id.
        packet_id: From CycleResult.packet_id.
        verdict_outcome: Denormalized for fast queries.
        verdict_confidence: Denormalized for fast queries.
        cycle_result: Full frozen CycleResult (the source of truth).
        stored_at: When this entry was stored.
        content_hash: SHA256 of canonical serialization of CycleResult.
        chain_hash: SHA256(prev_chain_hash + content_hash).
        sequence_number: Monotonic position in the chain.
        prev_chain_hash: GENESIS_HASH ("0"*64) for the first entry.
    """

    entry_id: str
    cycle_id: str
    packet_id: str
    verdict_outcome: VerdictOutcome
    verdict_confidence: float
    cycle_result: CycleResult
    stored_at: datetime
    content_hash: str
    chain_hash: str
    sequence_number: int
    prev_chain_hash: str
