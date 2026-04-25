# SESSION 007: Memory Stream

## Context
You're working on ARES (Adversarial Reasoning Engine System) — a dialectical AI framework for cybersecurity defense.

**Current State:**
- Phase 0: Sessions 001–006 COMPLETE (758 tests)
- Session 006: Coordinator Orchestration COMPLETE (58 new tests, 758 total)
- Golden pipeline proven: Raw XML → WindowsEventExtractor → Facts → EvidencePacket → DialecticalOrchestrator.run_cycle() → CycleResult with Verdict
- All components are deterministic — zero LLM calls, pure rule-based logic

Session 007 builds the **Memory Stream** — a persistence layer that stores CycleResults, enabling audit trails, cross-cycle correlation, and hash chain integrity verification.

## Project Location
C:\ares-phase-zero

## Git Branch
**Create and work on branch:** `session/007-memory-stream`
```powershell
git checkout main
git pull origin main
git checkout -b session/007-memory-stream
```
**All commits go to this branch. NEVER commit to main.**

---

## What Exists — DO NOT MODIFY

These files are production code with 758 passing tests. Do not modify, rename, move, or delete any of them.

```
ares/
├── graph/schema.py                        # Graph structure (Session 001, 110 tests) — DO NOT MODIFY
└── dialectic/
    ├── evidence/
    │   ├── provenance.py                  # Provenance, SourceType — DO NOT MODIFY
    │   ├── fact.py                        # Fact, EntityType — DO NOT MODIFY
    │   ├── packet.py                      # EvidencePacket (frozen container, SHA256, O(1) lookup) — DO NOT MODIFY
    │   └── extractors/
    │       ├── protocol.py                # ExtractionResult, ExtractorProtocol — DO NOT MODIFY
    │       └── windows.py                 # WindowsEventExtractor (4624/4672/4688) — DO NOT MODIFY
    ├── messages/
    │   ├── assertions.py                  # Assertion, AssertionType — DO NOT MODIFY
    │   └── protocol.py                    # DialecticalMessage, Phase, MessageBuilder — DO NOT MODIFY
    ├── coordinator/
    │   ├── validator.py                   # MessageValidator, ValidationError, ErrorCode (26 tests) — DO NOT MODIFY
    │   ├── cycle.py                       # CycleState, TerminationReason, CycleConfig, DialecticalCycle (50 tests) — DO NOT MODIFY
    │   ├── coordinator.py                 # Coordinator (the Bouncer), SubmissionResult (33 tests) — DO NOT MODIFY
    │   └── orchestrator.py                # DialecticalOrchestrator, CycleResult, CycleError (58 tests) — DO NOT MODIFY
    └── agents/
        ├── context.py                     # TurnContext, DataRequest, RequestKind, RequestPriority — DO NOT MODIFY
        ├── base.py                        # AgentBase (packet binding, phase enforcement, evidence tracking) — DO NOT MODIFY
        ├── patterns.py                    # AnomalyPattern, BenignExplanation, Verdict, VerdictOutcome — DO NOT MODIFY
        ├── architect.py                   # ArchitectAgent (THESIS) — DO NOT MODIFY
        ├── skeptic.py                     # SkepticAgent (ANTITHESIS) — DO NOT MODIFY
        └── oracle.py                      # OracleJudge (deterministic) + OracleNarrator (constrained) — DO NOT MODIFY
```

### Key Types You Will Consume (read-only)

```python
# From ares.dialectic.coordinator.orchestrator
@dataclass(frozen=True)
class CycleResult:
    cycle_id: str                              # UUID string
    packet_id: str                             # Source packet identifier
    verdict: Verdict                           # From ares.dialectic.agents.patterns
    architect_message: DialecticalMessage       # THESIS phase message
    skeptic_message: DialecticalMessage         # ANTITHESIS phase message
    narrator_message: Optional[DialecticalMessage]  # SYNTHESIS (None if skipped)
    started_at: datetime                       # Cycle start timestamp
    completed_at: datetime                     # Cycle end timestamp
    duration_ms: int                           # Execution duration

# From ares.dialectic.agents.patterns
@dataclass(frozen=True)
class Verdict:
    outcome: VerdictOutcome    # THREAT_CONFIRMED / THREAT_DISMISSED / INCONCLUSIVE
    confidence: float          # 0.0 – 1.0
    reasoning: str
    architect_confidence: float
    skeptic_confidence: float

class VerdictOutcome(Enum):
    THREAT_CONFIRMED = "THREAT_CONFIRMED"
    THREAT_DISMISSED = "THREAT_DISMISSED"
    INCONCLUSIVE = "INCONCLUSIVE"
```

---

## Execution Order

**CRITICAL: Follow this order exactly.**

### Step 1 — Review Before Writing
Read these files to understand the types you'll be consuming:
1. `ares/dialectic/coordinator/orchestrator.py` — CycleResult structure, how cycles are produced
2. `ares/dialectic/agents/patterns.py` — Verdict, VerdictOutcome
3. `ares/dialectic/evidence/packet.py` — EvidencePacket (snapshot_id, packet_id)
4. `ares/dialectic/evidence/fact.py` — Fact, EntityType (for entity extraction from verdicts)

### Step 2 — Create Memory Module Structure
```
ares/dialectic/memory/
├── __init__.py                # Public exports
├── errors.py                  # ALL memory exceptions (single source of truth)
├── protocol.py                # MemoryBackend protocol (abstract interface)
├── entry.py                   # MemoryEntry (the stored record)
├── chain.py                   # HashChain (tamper-evident audit log)
├── stream.py                  # MemoryStream (main API — composes backend + chain)
└── backends/
    ├── __init__.py
    └── in_memory.py           # InMemoryBackend (dict-based, for testing)
```

### Step 3 — Create Test Structure
```
ares/dialectic/tests/memory/
├── __init__.py
├── test_entry.py              # MemoryEntry tests
├── test_chain.py              # HashChain tests
├── test_backend.py            # InMemoryBackend tests
├── test_stream.py             # MemoryStream integration tests
└── conftest.py                # Shared fixtures (sample CycleResults, packets)
```

### Step 4 — Implement (bottom-up)
1. `errors.py` → 2. `entry.py` → 3. `protocol.py` → 4. `chain.py` → 5. `backends/in_memory.py` → 6. `stream.py`

### Step 5 — Run Full Test Suite
```powershell
pytest ares/ -v
```
All 758 existing tests MUST still pass. Target ~70 new tests.

---

## Your Mission: Build the Memory Stream

### Architecture Relationship
The Memory Stream is a **PEER module** to the coordinator — not a wrapper, not a subcomponent. It sits alongside the orchestrator and consumes its output:

```
Orchestrator.run_cycle(packet) → CycleResult
                                      ↓
                              MemoryStream.store(result)
                                      ↓
                              MemoryEntry (frozen, hashed, chained)
                                      ↓
                              MemoryBackend (persistence)
```

The Orchestrator does NOT know about the Memory Stream. The caller wires them together:

```python
# Usage pattern — caller composes
orchestrator = DialecticalOrchestrator()
stream = MemoryStream(backend=InMemoryBackend())

result = orchestrator.run_cycle(packet)
entry = stream.store(result)

# Query later
entries = stream.query_by_verdict(VerdictOutcome.THREAT_CONFIRMED)
entries = stream.query_by_time_range(start, end)
entry = stream.get_by_cycle_id(result.cycle_id)
```

### Why NOT inject into Orchestrator
The Orchestrator is a proven facade (Session 006). Injecting a MemoryStream dependency would violate the single-responsibility principle and require modifying a component with 58 passing tests. The caller — which will eventually be a higher-level pipeline or API — composes the pieces.

---

## Key Types to Build

### 1. MemoryEntry (`entry.py`)

```python
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

@dataclass(frozen=True)
class MemoryEntry:
    """
    An immutable record of a completed dialectical cycle.
    
    Stored by the MemoryStream with hash chain integrity.
    """
    entry_id: str                  # UUID, unique per entry
    cycle_id: str                  # From CycleResult.cycle_id
    packet_id: str                 # From CycleResult.packet_id
    verdict_outcome: VerdictOutcome  # Denormalized for fast queries
    verdict_confidence: float      # Denormalized for fast queries
    cycle_result: CycleResult      # Full frozen CycleResult (the source of truth)
    stored_at: datetime            # When this entry was stored
    content_hash: str              # SHA256 of canonical serialization of CycleResult
    chain_hash: str                # SHA256(prev_chain_hash + content_hash)
    sequence_number: int           # Monotonic position in the chain
    prev_chain_hash: str           # GENESIS_HASH ("0"*64) for the first entry, always a string — never None
```

**Design Notes:**
- `verdict_outcome` and `verdict_confidence` are denormalized from `cycle_result.verdict` for O(1) filtering without deserializing the full CycleResult
- `content_hash` is computed from a **canonical serialization of the ENTIRE CycleResult** — see `compute_content_hash()` below. This covers all messages, verdict reasoning, timestamps, and duration. If any field is altered, the hash breaks.
- `chain_hash` links each entry to its predecessor — tamper-evident
- `prev_chain_hash` is ALWAYS a string — `GENESIS_HASH` for the first entry (no Optional, no branching)
- `frozen=True` because entries are immutable once stored

### 2. MemoryBackend Protocol (`protocol.py`)

```python
from typing import Protocol, Optional, List, runtime_checkable

@runtime_checkable
class MemoryBackend(Protocol):
    """
    Abstract storage interface for MemoryEntries.
    
    Implementations: InMemoryBackend (testing), RedisBackend (production, future).
    """
    
    def store(self, entry: MemoryEntry) -> None:
        """Persist a MemoryEntry. Raises DuplicateEntryError if entry_id exists."""
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
```

### 3. HashChain (`chain.py`)

```python
import hashlib
from dataclasses import dataclass
from typing import Optional

GENESIS_HASH = "0" * 64  # SHA256 of "nothing" — the chain anchor

@dataclass(frozen=True)
class ChainLink:
    """A single link in the hash chain."""
    content_hash: str
    prev_chain_hash: str
    chain_hash: str          # SHA256(prev_chain_hash + content_hash)
    sequence_number: int

class HashChain:
    """
    Tamper-evident hash chain for audit integrity.
    
    Each link hashes its content together with the previous link's hash,
    creating an append-only chain where any modification invalidates all
    subsequent entries.
    """
    
    def __init__(self) -> None:
        self._head_hash: str = GENESIS_HASH
        self._sequence: int = 0
    
    def add(self, content_hash: str) -> ChainLink:
        """
        Add a new link to the chain.
        
        Returns a ChainLink with the computed chain_hash.
        """
        ...
    
    @staticmethod
    def compute_chain_hash(prev_hash: str, content_hash: str) -> str:
        """SHA256(prev_hash + content_hash). Deterministic, pure function."""
        ...
    
    @staticmethod
    def verify_link(link: ChainLink, expected_prev_hash: str) -> bool:
        """Verify that a ChainLink is valid given its expected predecessor."""
        ...
    
    @staticmethod
    def compute_content_hash(cycle_result: CycleResult) -> str:
        """
        Canonical SHA256 of the FULL CycleResult.
        
        CRITICAL: This must cover ALL stored fields to prevent partial tampering.
        
        Algorithm:
        1. Build a primitive-only dict from CycleResult:
           - cycle_id, packet_id, duration_ms
           - started_at.isoformat(), completed_at.isoformat()
           - verdict: outcome.value, confidence (formatted to 10 decimal places),
             reasoning, architect_confidence, skeptic_confidence
           - architect_message: phase.value, confidence, list of assertion dicts,
             list of cited fact_ids (sorted)
           - skeptic_message: same structure as architect_message
           - narrator_message: same structure or null
        2. Sort all dict keys recursively
        3. json.dumps(dict, sort_keys=True, separators=(',', ':'))
        4. SHA256 the UTF-8 bytes
        
        Float formatting: use f"{value:.10f}" for deterministic representation.
        None handling: use JSON null for missing narrator_message.
        """
        ...
    
    @property
    def head_hash(self) -> str:
        """Current head of the chain."""
        ...
    
    @property
    def sequence(self) -> int:
        """Current sequence number (number of links added)."""
        ...
```

### 4. InMemoryBackend (`backends/in_memory.py`)

```python
from ares.dialectic.memory.errors import DuplicateEntryError  # Import, do NOT redefine

class InMemoryBackend:
    """
    Dict-based MemoryBackend for testing and development.
    
    NOT thread-safe. NOT persistent across restarts.
    Implements MemoryBackend protocol.
    """
    
    def __init__(self) -> None:
        self._entries_by_id: Dict[str, MemoryEntry] = {}
        self._entries_by_cycle: Dict[str, MemoryEntry] = {}
        self._entries_ordered: List[MemoryEntry] = []  # By sequence_number
    
    # ... implement all MemoryBackend methods
```

### 5. MemoryStream (`stream.py`)

```python
class MemoryStreamError(Exception):
    """Base exception for MemoryStream operations."""
    pass

class ChainIntegrityError(MemoryStreamError):
    """Raised when hash chain verification fails."""
    
    def __init__(self, message: str, entry_id: str, expected_hash: str, actual_hash: str):
        super().__init__(message)
        self.entry_id = entry_id
        self.expected_hash = expected_hash
        self.actual_hash = actual_hash

class MemoryStream:
    """
    The immune system's memory — stores and queries dialectical cycle results
    with tamper-evident hash chain integrity.
    
    Composes a MemoryBackend (storage) with a HashChain (integrity).
    Write-only from the Orchestrator's perspective.
    """
    
    def __init__(self, *, backend: MemoryBackend) -> None:
        """
        Args:
            backend: Storage backend implementing MemoryBackend protocol
            
        CRITICAL: Constructor must initialize HashChain state from the backend.
        Read backend.get_chain_head() and backend.count() to set the chain's
        head_hash and sequence number. This ensures:
        - A MemoryStream can resume from a pre-populated backend (future Redis)
        - Chain continuity is maintained across restarts
        - The in-memory HashChain starts where the backend left off
        
        If backend is empty, HashChain starts at GENESIS_HASH with sequence 0.
        """
        ...
    
    def store(self, cycle_result: CycleResult) -> MemoryEntry:
        """
        Store a CycleResult as a MemoryEntry with hash chain linkage.
        
        Args:
            cycle_result: Frozen CycleResult from DialecticalOrchestrator
            
        Returns:
            The created MemoryEntry
            
        Raises:
            DuplicateEntryError: If cycle_id already stored
            MemoryStreamError: On storage failure
        """
        ...
    
    def get_by_cycle_id(self, cycle_id: str) -> Optional[MemoryEntry]:
        """Retrieve entry by cycle_id."""
        ...
    
    def query_by_verdict(self, outcome: VerdictOutcome) -> List[MemoryEntry]:
        """All entries with matching verdict outcome."""
        ...
    
    def query_by_packet_id(self, packet_id: str) -> List[MemoryEntry]:
        """All entries for a given packet_id."""
        ...
    
    def query_by_time_range(self, start: datetime, end: datetime) -> List[MemoryEntry]:
        """Entries stored within time range."""
        ...
    
    def verify_chain_integrity(self) -> bool:
        """
        Walk the full chain and verify every link.
        
        Returns True if intact, raises ChainIntegrityError on first failure.
        """
        ...
    
    def get_latest(self) -> Optional[MemoryEntry]:
        """Most recent entry."""
        ...
    
    @property
    def count(self) -> int:
        """Number of entries stored."""
        ...
    
    @property
    def chain_head(self) -> str:
        """Current hash chain head."""
        ...
```

---

## Test Scenarios

### MemoryEntry Tests (`test_entry.py`)

```python
# Immutability
def test_memory_entry_is_frozen():
    entry = build_test_entry()
    with pytest.raises(AttributeError):
        entry.cycle_id = "tampered"

# Content hash determinism
def test_same_cycle_result_produces_same_content_hash():
    result = build_test_cycle_result()
    hash1 = HashChain.compute_content_hash(result)
    hash2 = HashChain.compute_content_hash(result)
    assert hash1 == hash2

# Content hash covers full CycleResult (Fix 1 — prevents partial tampering)
def test_content_hash_changes_when_messages_differ():
    """Two CycleResults with same metadata but different messages must produce different hashes."""
    result1 = build_test_cycle_result(cycle_id="c1")
    result2 = build_test_cycle_result(cycle_id="c1")  # Same ID but different message content
    # Note: test fixture must produce results with different architect/skeptic messages
    # to verify the hash covers message payloads, not just metadata

def test_content_hash_covers_verdict_reasoning():
    """Altering verdict.reasoning must change the content_hash."""
    # Build two CycleResults with identical outcomes but different reasoning strings
    # Assert their content_hashes differ

# Denormalized fields match
def test_denormalized_verdict_matches_cycle_result():
    entry = build_test_entry()
    assert entry.verdict_outcome == entry.cycle_result.verdict.outcome
    assert entry.verdict_confidence == entry.cycle_result.verdict.confidence
```

### HashChain Tests (`test_chain.py`)

```python
# Genesis
def test_first_link_uses_genesis_hash():
    chain = HashChain()
    link = chain.add("abc123")
    assert link.prev_chain_hash == GENESIS_HASH
    assert link.sequence_number == 0

# Chain growth
def test_chain_links_use_previous_hash():
    chain = HashChain()
    link1 = chain.add("hash1")
    link2 = chain.add("hash2")
    assert link2.prev_chain_hash == link1.chain_hash
    assert link2.sequence_number == 1

# Verification
def test_verify_valid_link():
    chain = HashChain()
    link = chain.add("content")
    assert HashChain.verify_link(link, GENESIS_HASH) is True

def test_verify_detects_tampered_content():
    chain = HashChain()
    link = chain.add("content")
    # Manually create a tampered link
    tampered = ChainLink(
        content_hash="tampered",
        prev_chain_hash=link.prev_chain_hash,
        chain_hash=link.chain_hash,  # Hash won't match tampered content
        sequence_number=link.sequence_number,
    )
    assert HashChain.verify_link(tampered, GENESIS_HASH) is False

# Determinism
def test_compute_chain_hash_is_deterministic():
    h1 = HashChain.compute_chain_hash("prev", "content")
    h2 = HashChain.compute_chain_hash("prev", "content")
    assert h1 == h2

# Content hash from CycleResult
def test_compute_content_hash_deterministic():
    result = build_test_cycle_result()
    assert HashChain.compute_content_hash(result) == HashChain.compute_content_hash(result)
```

### InMemoryBackend Tests (`test_backend.py`)

```python
# Store and retrieve
def test_store_and_get_by_entry_id():
    backend = InMemoryBackend()
    entry = build_test_entry()
    backend.store(entry)
    assert backend.get_by_entry_id(entry.entry_id) == entry

def test_store_and_get_by_cycle_id():
    backend = InMemoryBackend()
    entry = build_test_entry()
    backend.store(entry)
    assert backend.get_by_cycle_id(entry.cycle_id) == entry

# Duplicate rejection
def test_duplicate_entry_id_raises():
    backend = InMemoryBackend()
    entry = build_test_entry()
    backend.store(entry)
    with pytest.raises(DuplicateEntryError):
        backend.store(entry)

def test_duplicate_cycle_id_raises():
    backend = InMemoryBackend()
    entry1 = build_test_entry(entry_id="e1", cycle_id="c1")
    entry2 = build_test_entry(entry_id="e2", cycle_id="c1")  # Same cycle_id
    backend.store(entry1)
    with pytest.raises(DuplicateEntryError):
        backend.store(entry2)

# Queries
def test_query_by_verdict_filters_correctly():
    backend = InMemoryBackend()
    # Store entries with different verdicts
    # Assert filtering works

def test_query_by_time_range():
    # Store entries at different times
    # Assert range filtering works

def test_query_by_packet_id():
    # Multiple entries for same packet
    # Assert all returned, ordered by sequence_number

# Edge cases
def test_get_nonexistent_returns_none():
    backend = InMemoryBackend()
    assert backend.get_by_entry_id("nope") is None

def test_empty_backend_count_is_zero():
    backend = InMemoryBackend()
    assert backend.count() == 0

def test_get_latest_empty_returns_none():
    backend = InMemoryBackend()
    assert backend.get_latest() is None

def test_get_chain_head_empty_returns_none():
    backend = InMemoryBackend()
    assert backend.get_chain_head() is None

def test_results_ordered_by_sequence_number():
    # Store entries in various orders
    # Assert queries return in sequence_number order
```

### MemoryStream Integration Tests (`test_stream.py`)

```python
# Store and retrieve
def test_store_cycle_result_returns_entry():
    stream = MemoryStream(backend=InMemoryBackend())
    result = build_test_cycle_result()
    entry = stream.store(result)
    assert entry.cycle_id == result.cycle_id
    assert entry.verdict_outcome == result.verdict.outcome

# Hash chain built automatically
def test_store_builds_hash_chain():
    stream = MemoryStream(backend=InMemoryBackend())
    entry1 = stream.store(build_test_cycle_result(cycle_id="c1"))
    entry2 = stream.store(build_test_cycle_result(cycle_id="c2"))
    assert entry1.prev_chain_hash == GENESIS_HASH  # Always a string, never None
    assert entry2.prev_chain_hash == entry1.chain_hash

# Chain integrity verification
def test_verify_chain_integrity_passes_for_valid_chain():
    stream = MemoryStream(backend=InMemoryBackend())
    stream.store(build_test_cycle_result(cycle_id="c1"))
    stream.store(build_test_cycle_result(cycle_id="c2"))
    stream.store(build_test_cycle_result(cycle_id="c3"))
    assert stream.verify_chain_integrity() is True

# Duplicate rejection
def test_store_duplicate_cycle_id_raises():
    stream = MemoryStream(backend=InMemoryBackend())
    result = build_test_cycle_result()
    stream.store(result)
    with pytest.raises(DuplicateEntryError):
        stream.store(result)

# Query delegation
def test_query_by_verdict():
    stream = MemoryStream(backend=InMemoryBackend())
    # Store THREAT_CONFIRMED and THREAT_DISMISSED
    threats = stream.query_by_verdict(VerdictOutcome.THREAT_CONFIRMED)
    assert all(e.verdict_outcome == VerdictOutcome.THREAT_CONFIRMED for e in threats)

def test_query_by_time_range():
    # Test time-bounded queries

def test_query_by_packet_id():
    # Multiple cycles for same packet

# Count and properties
def test_count_tracks_entries():
    stream = MemoryStream(backend=InMemoryBackend())
    assert stream.count == 0
    stream.store(build_test_cycle_result(cycle_id="c1"))
    assert stream.count == 1

def test_chain_head_updates():
    stream = MemoryStream(backend=InMemoryBackend())
    entry = stream.store(build_test_cycle_result())
    assert stream.chain_head == entry.chain_hash

# Full pipeline integration
def test_full_pipeline_orchestrator_to_memory():
    """Raw XML → Extractor → Packet → Orchestrator → MemoryStream → Query"""
    from ares.dialectic.coordinator.orchestrator import DialecticalOrchestrator
    from ares.dialectic.evidence.extractors.windows import WindowsEventExtractor
    
    # Build packet from XML
    extractor = WindowsEventExtractor()
    # ... extract, build packet, freeze
    
    orchestrator = DialecticalOrchestrator()
    result = orchestrator.run_cycle(packet)
    
    stream = MemoryStream(backend=InMemoryBackend())
    entry = stream.store(result)
    
    # Query back
    retrieved = stream.get_by_cycle_id(result.cycle_id)
    assert retrieved == entry
    assert retrieved.verdict_outcome == result.verdict.outcome
    assert stream.verify_chain_integrity() is True

# Empty stream edge cases
def test_get_latest_empty_stream():
    stream = MemoryStream(backend=InMemoryBackend())
    assert stream.get_latest() is None

def test_verify_empty_chain_passes():
    stream = MemoryStream(backend=InMemoryBackend())
    assert stream.verify_chain_integrity() is True

# Chain resumption from pre-populated backend (Fix 4 — critical for future Redis)
def test_stream_resumes_from_prepopulated_backend():
    """MemoryStream must hydrate chain state from existing backend entries."""
    backend = InMemoryBackend()
    
    # First stream writes 3 entries
    stream1 = MemoryStream(backend=backend)
    stream1.store(build_test_cycle_result(cycle_id="c1"))
    stream1.store(build_test_cycle_result(cycle_id="c2"))
    entry3 = stream1.store(build_test_cycle_result(cycle_id="c3"))
    
    # Second stream picks up from the same backend
    stream2 = MemoryStream(backend=backend)
    assert stream2.count == 3
    assert stream2.chain_head == entry3.chain_hash
    
    # New entry continues the chain, not a new genesis
    entry4 = stream2.store(build_test_cycle_result(cycle_id="c4"))
    assert entry4.prev_chain_hash == entry3.chain_hash
    assert entry4.sequence_number == 3  # 0-indexed: 0, 1, 2, 3
    assert stream2.verify_chain_integrity() is True
```

---

## Established Patterns (Follow These)

1. **Frozen dataclasses** for all output types (`@dataclass(frozen=True)`)
2. **`raise ... from ...`** for exception chaining
3. **Type hints** on everything
4. **Docstrings** for all public methods
5. **Test naming:** `test_<what>_<condition>_<expected>`
6. **Focused, fast tests** — no I/O, no sleep, no external dependencies
7. **`__init__.py`** exports for clean public API
8. **`conftest.py`** with shared fixtures
9. **No LLM calls** — everything is deterministic

## Error Handling — ALL in `errors.py` (Single Source of Truth)

**CRITICAL: All memory exceptions live in `ares/dialectic/memory/errors.py`. Import from there everywhere — stream.py, backends/in_memory.py, tests. Do NOT redefine exceptions in multiple files.**

```python
# ares/dialectic/memory/errors.py

class MemoryStreamError(Exception):
    """Base exception for all Memory Stream operations."""
    pass

class ChainIntegrityError(MemoryStreamError):
    """Raised when hash chain verification fails."""
    
    def __init__(self, message: str, entry_id: str, expected_hash: str, actual_hash: str):
        super().__init__(message)
        self.entry_id = entry_id
        self.expected_hash = expected_hash
        self.actual_hash = actual_hash

class DuplicateEntryError(MemoryStreamError):
    """Raised when attempting to store an entry with a duplicate entry_id or cycle_id."""
    
    def __init__(self, message: str, entry_id: str, field: str = "entry_id"):
        super().__init__(message)
        self.entry_id = entry_id
        self.field = field
```

**Usage in other files:**
```python
# In backends/in_memory.py, stream.py, and all test files:
from ares.dialectic.memory.errors import DuplicateEntryError, ChainIntegrityError, MemoryStreamError
```

---

## Success Criteria

- [ ] All existing 758 tests still pass
- [ ] ~70 new tests for the memory module
- [ ] `MemoryStream.store(cycle_result)` creates a hashed, chained MemoryEntry
- [ ] Hash chain integrity verification works (valid chain passes, tampered chain fails)
- [ ] Query by cycle_id, packet_id, verdict outcome, time range all functional
- [ ] Duplicate cycle_id rejection tested
- [ ] MemoryEntry immutability tested
- [ ] Genesis entry (first in chain) handled correctly
- [ ] Empty stream edge cases handled
- [ ] Full pipeline integration test (Orchestrator → MemoryStream → Query)
- [ ] InMemoryBackend satisfies MemoryBackend protocol
- [ ] No modifications to any existing files

## Commands

```powershell
# Activate venv
.\venv\Scripts\Activate.ps1

# Run all tests
pytest ares/ -v

# Run just memory tests
pytest ares/dialectic/tests/memory/ -v

# Run with coverage
pytest ares/ --cov=ares --cov-report=term-missing
```

## Style Notes
- Frozen dataclasses everywhere (immutability)
- Type hints on everything
- Docstrings for public methods
- Test naming: `test_<what>_<condition>_<expected>`
- Keep tests focused and fast
- Use `hashlib.sha256` for all hashing (standard library, no dependencies)
- `uuid.uuid4()` for entry_id generation

## Stretch Goals (If Time Permits)

1. **Entity extraction index:** Extract entity_ids from CycleResult facts, build a secondary index for "find all cycles involving IP 192.168.1.100"
2. **Chain export/import:** Serialize the full chain to JSON for external audit tools
3. **Statistics:** `stream.summary()` → dict with counts by verdict outcome, average confidence, time range
