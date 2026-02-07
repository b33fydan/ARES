"""Memory Stream exceptions — single source of truth.

All memory-related exceptions live here. Import from this module everywhere.
Do NOT redefine exceptions in other files.
"""


class MemoryStreamError(Exception):
    """Base exception for all Memory Stream operations."""

    pass


class ChainIntegrityError(MemoryStreamError):
    """Raised when hash chain verification fails.

    Attributes:
        entry_id: The entry where integrity broke.
        expected_hash: What the chain hash should have been.
        actual_hash: What the chain hash actually was.
    """

    def __init__(
        self, message: str, entry_id: str, expected_hash: str, actual_hash: str
    ) -> None:
        super().__init__(message)
        self.entry_id = entry_id
        self.expected_hash = expected_hash
        self.actual_hash = actual_hash


class DuplicateEntryError(MemoryStreamError):
    """Raised when attempting to store an entry with a duplicate entry_id or cycle_id.

    Attributes:
        entry_id: The conflicting entry or cycle ID value.
        field: Which field caused the conflict ('entry_id' or 'cycle_id').
    """

    def __init__(
        self, message: str, entry_id: str, field: str = "entry_id"
    ) -> None:
        super().__init__(message)
        self.entry_id = entry_id
        self.field = field
