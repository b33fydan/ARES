"""Protocol and types for evidence extractors.

Extractors parse raw telemetry into Facts with full provenance tracking.
This module defines the contract all extractors must implement.
"""

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from ..fact import Fact


@dataclass(frozen=True)
class ExtractionError:
    """A parse failure that didn't produce a Fact.

    Errors are collected during extraction to enable debugging
    and partial results in permissive mode.

    Attributes:
        line_number: Line number where error occurred (None if unknown).
        raw_snippet: First 200 chars of problematic input for debugging.
        error_type: Category of error (MALFORMED_XML, MISSING_FIELD, etc.).
        message: Human-readable description of the error.
    """

    line_number: int | None
    raw_snippet: str
    error_type: str
    message: str

    # Error type constants
    MALFORMED_XML = "MALFORMED_XML"
    MISSING_FIELD = "MISSING_FIELD"
    INVALID_TIMESTAMP = "INVALID_TIMESTAMP"
    INVALID_EVENT_ID = "INVALID_EVENT_ID"
    UNSUPPORTED_EVENT = "UNSUPPORTED_EVENT"
    FIELD_TOO_LARGE = "FIELD_TOO_LARGE"
    PARSE_ERROR = "PARSE_ERROR"

    def __post_init__(self) -> None:
        """Validate and truncate raw_snippet to 200 chars."""
        if len(self.raw_snippet) > 200:
            object.__setattr__(self, "raw_snippet", self.raw_snippet[:200])


@dataclass(frozen=True)
class ExtractionStats:
    """Telemetry about the extraction run.

    Provides metrics for monitoring extraction quality and throughput.

    Attributes:
        events_seen: Total events encountered in input.
        events_parsed: Events successfully parsed.
        events_dropped: Events skipped due to errors or unsupported types.
        facts_emitted: Total Facts generated (may be > events_parsed).
    """

    events_seen: int
    events_parsed: int
    events_dropped: int
    facts_emitted: int

    def __post_init__(self) -> None:
        """Validate stats invariants."""
        if self.events_seen < 0:
            raise ValueError("events_seen must be non-negative")
        if self.events_parsed < 0:
            raise ValueError("events_parsed must be non-negative")
        if self.events_dropped < 0:
            raise ValueError("events_dropped must be non-negative")
        if self.facts_emitted < 0:
            raise ValueError("facts_emitted must be non-negative")
        if self.events_parsed + self.events_dropped > self.events_seen:
            raise ValueError("parsed + dropped cannot exceed seen")


@dataclass(frozen=True)
class ExtractionResult:
    """The complete output of an extraction run.

    Contains all extracted Facts, any errors encountered, and
    statistics about the extraction process.

    Attributes:
        facts: Tuple of extracted Facts (immutable).
        errors: Tuple of extraction errors (immutable).
        stats: Statistics about the extraction run.
        source_ref: Reference to the data source (file path, stream ID, etc.).
        extractor_version: Version of the extractor that produced this result.
    """

    facts: tuple[Fact, ...]
    errors: tuple[ExtractionError, ...]
    stats: ExtractionStats
    source_ref: str
    extractor_version: str

    def __post_init__(self) -> None:
        """Validate result invariants."""
        # Ensure tuples are actually tuples (not lists)
        if not isinstance(self.facts, tuple):
            raise TypeError("facts must be a tuple")
        if not isinstance(self.errors, tuple):
            raise TypeError("errors must be a tuple")

        # Validate stats consistency
        if self.stats.facts_emitted != len(self.facts):
            raise ValueError(
                f"stats.facts_emitted ({self.stats.facts_emitted}) "
                f"must equal len(facts) ({len(self.facts)})"
            )

    @property
    def success(self) -> bool:
        """Check if extraction had no errors.

        Returns:
            True if no errors occurred during extraction.
        """
        return len(self.errors) == 0

    @property
    def partial(self) -> bool:
        """Check if extraction produced partial results with errors.

        Returns:
            True if both facts and errors exist.
        """
        return len(self.facts) > 0 and len(self.errors) > 0


@runtime_checkable
class ExtractorProtocol(Protocol):
    """Protocol defining what every extractor must implement.

    Extractors parse raw telemetry bytes/strings into typed Facts
    with full provenance tracking. They support two modes:

    - Strict mode (default): Raises on first parse error
    - Permissive mode: Collects errors and returns partial results

    Class Attributes:
        VERSION: Semantic version of the extractor (e.g., "1.0.0").
    """

    VERSION: str

    def extract(
        self,
        raw: bytes | str,
        *,
        source_ref: str,
        strict: bool = True,
    ) -> ExtractionResult:
        """Parse raw telemetry into Facts.

        Args:
            raw: Raw telemetry data (bytes or string).
            source_ref: Reference to data source for provenance tracking.
            strict: If True, raise on first error. If False, collect errors
                   and return partial results.

        Returns:
            ExtractionResult containing Facts, errors, and stats.

        Raises:
            ExtractionError: In strict mode, on first parse error.
            ValueError: If raw input is invalid type.
        """
        ...
