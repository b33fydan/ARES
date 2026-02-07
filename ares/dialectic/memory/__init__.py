"""Memory Stream — tamper-evident persistence for dialectical cycles.

Public API:
    MemoryStream: Main API for storing and querying CycleResults.
    MemoryEntry: Immutable record with hash chain linkage.
    MemoryBackend: Abstract storage interface (protocol).
    InMemoryBackend: Dict-based backend for testing.
    HashChain: Tamper-evident audit log.
    ChainLink: A single link in the hash chain.
    GENESIS_HASH: The chain anchor constant.

Exceptions:
    MemoryStreamError: Base exception.
    ChainIntegrityError: Hash chain verification failure.
    DuplicateEntryError: Duplicate entry_id or cycle_id.
"""

from ares.dialectic.memory.backends.in_memory import InMemoryBackend
from ares.dialectic.memory.chain import GENESIS_HASH, ChainLink, HashChain
from ares.dialectic.memory.entry import MemoryEntry
from ares.dialectic.memory.errors import (
    ChainIntegrityError,
    DuplicateEntryError,
    MemoryStreamError,
)
from ares.dialectic.memory.protocol import MemoryBackend
from ares.dialectic.memory.stream import MemoryStream

__all__ = [
    "MemoryStream",
    "MemoryEntry",
    "MemoryBackend",
    "InMemoryBackend",
    "HashChain",
    "ChainLink",
    "GENESIS_HASH",
    "MemoryStreamError",
    "ChainIntegrityError",
    "DuplicateEntryError",
]
