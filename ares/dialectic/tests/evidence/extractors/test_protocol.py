"""Tests for extractor protocol types.

Tests validate:
1. ExtractionError - immutability, snippet truncation
2. ExtractionStats - invariant validation
3. ExtractionResult - tuple enforcement, stats consistency
4. ExtractorProtocol - runtime checkable protocol
"""

import pytest
from dataclasses import FrozenInstanceError
from datetime import datetime

from ares.dialectic.evidence.extractors.protocol import (
    ExtractionError,
    ExtractionStats,
    ExtractionResult,
    ExtractorProtocol,
)
from ares.dialectic.evidence.fact import Fact, EntityType
from ares.dialectic.evidence.provenance import Provenance, SourceType


# =============================================================================
# Helper Functions
# =============================================================================


def make_provenance(source_ref: str = "test-source") -> Provenance:
    """Create a test provenance instance."""
    return Provenance(
        source_type=SourceType.AUTH_LOG,
        source_id=source_ref,
        parser_version="1.0.0",
        raw_reference="line:1",
        extracted_at=datetime(2024, 1, 15, 12, 0, 0),
    )


def make_fact(
    fact_id: str = "fact-001",
    entity_id: str = "user:jsmith",
    field: str = "logon_type",
    value: any = "interactive",
) -> Fact:
    """Create a test fact instance."""
    return Fact(
        fact_id=fact_id,
        entity_id=entity_id,
        entity_type=EntityType.NODE,
        field=field,
        value=value,
        timestamp=datetime(2024, 1, 15, 12, 0, 0),
        provenance=make_provenance(),
    )


def make_error(
    line_number: int = 1,
    raw_snippet: str = "<Event>broken",
    error_type: str = ExtractionError.MALFORMED_XML,
    message: str = "Invalid XML structure",
) -> ExtractionError:
    """Create a test extraction error."""
    return ExtractionError(
        line_number=line_number,
        raw_snippet=raw_snippet,
        error_type=error_type,
        message=message,
    )


def make_stats(
    events_seen: int = 10,
    events_parsed: int = 8,
    events_dropped: int = 2,
    facts_emitted: int = 24,
) -> ExtractionStats:
    """Create test extraction stats."""
    return ExtractionStats(
        events_seen=events_seen,
        events_parsed=events_parsed,
        events_dropped=events_dropped,
        facts_emitted=facts_emitted,
    )


def make_result(
    facts: tuple = None,
    errors: tuple = None,
    stats: ExtractionStats = None,
    source_ref: str = "test.xml",
    extractor_version: str = "1.0.0",
) -> ExtractionResult:
    """Create a test extraction result."""
    if facts is None:
        facts = (make_fact("fact-001"), make_fact("fact-002"))
    if errors is None:
        errors = ()
    if stats is None:
        stats = ExtractionStats(
            events_seen=1,
            events_parsed=1,
            events_dropped=0,
            facts_emitted=len(facts),
        )
    return ExtractionResult(
        facts=facts,
        errors=errors,
        stats=stats,
        source_ref=source_ref,
        extractor_version=extractor_version,
    )


# =============================================================================
# ExtractionError Tests
# =============================================================================


class TestExtractionErrorImmutability:
    """Tests for ExtractionError immutability."""

    def test_cannot_modify_line_number(self) -> None:
        """ExtractionError line_number cannot be modified."""
        error = make_error(line_number=42)
        with pytest.raises(FrozenInstanceError):
            error.line_number = 99

    def test_cannot_modify_raw_snippet(self) -> None:
        """ExtractionError raw_snippet cannot be modified."""
        error = make_error(raw_snippet="original")
        with pytest.raises(FrozenInstanceError):
            error.raw_snippet = "modified"

    def test_cannot_modify_error_type(self) -> None:
        """ExtractionError error_type cannot be modified."""
        error = make_error(error_type=ExtractionError.MALFORMED_XML)
        with pytest.raises(FrozenInstanceError):
            error.error_type = ExtractionError.MISSING_FIELD

    def test_cannot_modify_message(self) -> None:
        """ExtractionError message cannot be modified."""
        error = make_error(message="original")
        with pytest.raises(FrozenInstanceError):
            error.message = "modified"


class TestExtractionErrorSnippetTruncation:
    """Tests for raw_snippet truncation behavior."""

    def test_short_snippet_unchanged(self) -> None:
        """Snippets under 200 chars are not truncated."""
        snippet = "x" * 100
        error = make_error(raw_snippet=snippet)
        assert len(error.raw_snippet) == 100
        assert error.raw_snippet == snippet

    def test_snippet_at_limit_unchanged(self) -> None:
        """Snippets at exactly 200 chars are not truncated."""
        snippet = "x" * 200
        error = make_error(raw_snippet=snippet)
        assert len(error.raw_snippet) == 200
        assert error.raw_snippet == snippet

    def test_long_snippet_truncated(self) -> None:
        """Snippets over 200 chars are truncated."""
        snippet = "x" * 500
        error = make_error(raw_snippet=snippet)
        assert len(error.raw_snippet) == 200
        assert error.raw_snippet == "x" * 200

    def test_truncation_preserves_start(self) -> None:
        """Truncation preserves the beginning of the snippet."""
        snippet = "START" + "x" * 500 + "END"
        error = make_error(raw_snippet=snippet)
        assert error.raw_snippet.startswith("START")
        assert not error.raw_snippet.endswith("END")


class TestExtractionErrorTypes:
    """Tests for error type constants."""

    def test_error_type_constants_exist(self) -> None:
        """All error type constants are defined."""
        assert ExtractionError.MALFORMED_XML == "MALFORMED_XML"
        assert ExtractionError.MISSING_FIELD == "MISSING_FIELD"
        assert ExtractionError.INVALID_TIMESTAMP == "INVALID_TIMESTAMP"
        assert ExtractionError.INVALID_EVENT_ID == "INVALID_EVENT_ID"
        assert ExtractionError.UNSUPPORTED_EVENT == "UNSUPPORTED_EVENT"
        assert ExtractionError.FIELD_TOO_LARGE == "FIELD_TOO_LARGE"
        assert ExtractionError.PARSE_ERROR == "PARSE_ERROR"

    def test_error_with_none_line_number(self) -> None:
        """Error can have None line_number."""
        error = make_error(line_number=None)
        assert error.line_number is None


class TestExtractionErrorEquality:
    """Tests for ExtractionError equality."""

    def test_equal_errors_are_equal(self) -> None:
        """Identical errors compare equal."""
        error1 = ExtractionError(
            line_number=10,
            raw_snippet="test",
            error_type=ExtractionError.MALFORMED_XML,
            message="test error",
        )
        error2 = ExtractionError(
            line_number=10,
            raw_snippet="test",
            error_type=ExtractionError.MALFORMED_XML,
            message="test error",
        )
        assert error1 == error2

    def test_different_errors_not_equal(self) -> None:
        """Different errors are not equal."""
        error1 = make_error(line_number=10)
        error2 = make_error(line_number=20)
        assert error1 != error2


# =============================================================================
# ExtractionStats Tests
# =============================================================================


class TestExtractionStatsImmutability:
    """Tests for ExtractionStats immutability."""

    def test_cannot_modify_events_seen(self) -> None:
        """ExtractionStats events_seen cannot be modified."""
        stats = make_stats()
        with pytest.raises(FrozenInstanceError):
            stats.events_seen = 999

    def test_cannot_modify_events_parsed(self) -> None:
        """ExtractionStats events_parsed cannot be modified."""
        stats = make_stats()
        with pytest.raises(FrozenInstanceError):
            stats.events_parsed = 999

    def test_cannot_modify_events_dropped(self) -> None:
        """ExtractionStats events_dropped cannot be modified."""
        stats = make_stats()
        with pytest.raises(FrozenInstanceError):
            stats.events_dropped = 999

    def test_cannot_modify_facts_emitted(self) -> None:
        """ExtractionStats facts_emitted cannot be modified."""
        stats = make_stats()
        with pytest.raises(FrozenInstanceError):
            stats.facts_emitted = 999


class TestExtractionStatsValidation:
    """Tests for ExtractionStats validation."""

    def test_valid_stats_accepted(self) -> None:
        """Valid stats are accepted."""
        stats = ExtractionStats(
            events_seen=100,
            events_parsed=90,
            events_dropped=10,
            facts_emitted=270,
        )
        assert stats.events_seen == 100
        assert stats.events_parsed == 90
        assert stats.events_dropped == 10
        assert stats.facts_emitted == 270

    def test_zero_stats_valid(self) -> None:
        """Zero values are valid."""
        stats = ExtractionStats(
            events_seen=0,
            events_parsed=0,
            events_dropped=0,
            facts_emitted=0,
        )
        assert stats.events_seen == 0

    def test_negative_events_seen_rejected(self) -> None:
        """Negative events_seen is rejected."""
        with pytest.raises(ValueError, match="events_seen must be non-negative"):
            ExtractionStats(
                events_seen=-1,
                events_parsed=0,
                events_dropped=0,
                facts_emitted=0,
            )

    def test_negative_events_parsed_rejected(self) -> None:
        """Negative events_parsed is rejected."""
        with pytest.raises(ValueError, match="events_parsed must be non-negative"):
            ExtractionStats(
                events_seen=10,
                events_parsed=-1,
                events_dropped=0,
                facts_emitted=0,
            )

    def test_negative_events_dropped_rejected(self) -> None:
        """Negative events_dropped is rejected."""
        with pytest.raises(ValueError, match="events_dropped must be non-negative"):
            ExtractionStats(
                events_seen=10,
                events_parsed=5,
                events_dropped=-1,
                facts_emitted=0,
            )

    def test_negative_facts_emitted_rejected(self) -> None:
        """Negative facts_emitted is rejected."""
        with pytest.raises(ValueError, match="facts_emitted must be non-negative"):
            ExtractionStats(
                events_seen=10,
                events_parsed=5,
                events_dropped=5,
                facts_emitted=-1,
            )

    def test_parsed_plus_dropped_exceeds_seen_rejected(self) -> None:
        """parsed + dropped cannot exceed seen."""
        with pytest.raises(ValueError, match="parsed \\+ dropped cannot exceed seen"):
            ExtractionStats(
                events_seen=10,
                events_parsed=8,
                events_dropped=5,  # 8 + 5 = 13 > 10
                facts_emitted=24,
            )

    def test_parsed_plus_dropped_equals_seen_valid(self) -> None:
        """parsed + dropped == seen is valid."""
        stats = ExtractionStats(
            events_seen=10,
            events_parsed=7,
            events_dropped=3,  # 7 + 3 = 10
            facts_emitted=21,
        )
        assert stats.events_seen == 10


class TestExtractionStatsEquality:
    """Tests for ExtractionStats equality."""

    def test_equal_stats_are_equal(self) -> None:
        """Identical stats compare equal."""
        stats1 = ExtractionStats(10, 8, 2, 24)
        stats2 = ExtractionStats(10, 8, 2, 24)
        assert stats1 == stats2

    def test_different_stats_not_equal(self) -> None:
        """Different stats are not equal."""
        stats1 = make_stats(events_seen=10)
        stats2 = make_stats(events_seen=20)
        assert stats1 != stats2


# =============================================================================
# ExtractionResult Tests
# =============================================================================


class TestExtractionResultImmutability:
    """Tests for ExtractionResult immutability."""

    def test_cannot_modify_facts(self) -> None:
        """ExtractionResult facts cannot be modified."""
        result = make_result()
        with pytest.raises(FrozenInstanceError):
            result.facts = ()

    def test_cannot_modify_errors(self) -> None:
        """ExtractionResult errors cannot be modified."""
        result = make_result()
        with pytest.raises(FrozenInstanceError):
            result.errors = ()

    def test_cannot_modify_stats(self) -> None:
        """ExtractionResult stats cannot be modified."""
        result = make_result()
        with pytest.raises(FrozenInstanceError):
            result.stats = make_stats()

    def test_cannot_modify_source_ref(self) -> None:
        """ExtractionResult source_ref cannot be modified."""
        result = make_result()
        with pytest.raises(FrozenInstanceError):
            result.source_ref = "modified.xml"

    def test_cannot_modify_extractor_version(self) -> None:
        """ExtractionResult extractor_version cannot be modified."""
        result = make_result()
        with pytest.raises(FrozenInstanceError):
            result.extractor_version = "2.0.0"


class TestExtractionResultValidation:
    """Tests for ExtractionResult validation."""

    def test_facts_must_be_tuple(self) -> None:
        """Facts must be a tuple, not a list."""
        with pytest.raises(TypeError, match="facts must be a tuple"):
            ExtractionResult(
                facts=[make_fact()],  # list, not tuple
                errors=(),
                stats=ExtractionStats(1, 1, 0, 1),
                source_ref="test.xml",
                extractor_version="1.0.0",
            )

    def test_errors_must_be_tuple(self) -> None:
        """Errors must be a tuple, not a list."""
        with pytest.raises(TypeError, match="errors must be a tuple"):
            ExtractionResult(
                facts=(make_fact(),),
                errors=[make_error()],  # list, not tuple
                stats=ExtractionStats(1, 1, 0, 1),
                source_ref="test.xml",
                extractor_version="1.0.0",
            )

    def test_stats_facts_count_must_match(self) -> None:
        """stats.facts_emitted must equal len(facts)."""
        with pytest.raises(ValueError, match="stats.facts_emitted"):
            ExtractionResult(
                facts=(make_fact("f1"), make_fact("f2")),  # 2 facts
                errors=(),
                stats=ExtractionStats(1, 1, 0, 5),  # says 5 facts
                source_ref="test.xml",
                extractor_version="1.0.0",
            )

    def test_empty_facts_with_zero_stats_valid(self) -> None:
        """Empty facts with zero stats is valid."""
        result = ExtractionResult(
            facts=(),
            errors=(),
            stats=ExtractionStats(0, 0, 0, 0),
            source_ref="empty.xml",
            extractor_version="1.0.0",
        )
        assert len(result.facts) == 0


class TestExtractionResultProperties:
    """Tests for ExtractionResult properties."""

    def test_success_true_when_no_errors(self) -> None:
        """success is True when there are no errors."""
        result = make_result(errors=())
        assert result.success is True

    def test_success_false_when_errors_exist(self) -> None:
        """success is False when errors exist."""
        facts = (make_fact(),)
        result = ExtractionResult(
            facts=facts,
            errors=(make_error(),),
            stats=ExtractionStats(2, 1, 1, 1),
            source_ref="test.xml",
            extractor_version="1.0.0",
        )
        assert result.success is False

    def test_partial_true_with_facts_and_errors(self) -> None:
        """partial is True when both facts and errors exist."""
        facts = (make_fact(),)
        result = ExtractionResult(
            facts=facts,
            errors=(make_error(),),
            stats=ExtractionStats(2, 1, 1, 1),
            source_ref="test.xml",
            extractor_version="1.0.0",
        )
        assert result.partial is True

    def test_partial_false_with_only_facts(self) -> None:
        """partial is False when only facts exist."""
        result = make_result(errors=())
        assert result.partial is False

    def test_partial_false_with_only_errors(self) -> None:
        """partial is False when only errors exist (no facts)."""
        result = ExtractionResult(
            facts=(),
            errors=(make_error(),),
            stats=ExtractionStats(1, 0, 1, 0),
            source_ref="test.xml",
            extractor_version="1.0.0",
        )
        assert result.partial is False


class TestExtractionResultContents:
    """Tests for ExtractionResult contents."""

    def test_facts_accessible(self) -> None:
        """Facts are accessible from result."""
        fact1 = make_fact("f1")
        fact2 = make_fact("f2")
        result = make_result(facts=(fact1, fact2))
        assert len(result.facts) == 2
        assert result.facts[0] == fact1
        assert result.facts[1] == fact2

    def test_errors_accessible(self) -> None:
        """Errors are accessible from result."""
        error = make_error()
        facts = (make_fact(),)
        result = ExtractionResult(
            facts=facts,
            errors=(error,),
            stats=ExtractionStats(2, 1, 1, 1),
            source_ref="test.xml",
            extractor_version="1.0.0",
        )
        assert len(result.errors) == 1
        assert result.errors[0] == error

    def test_stats_accessible(self) -> None:
        """Stats are accessible from result."""
        stats = ExtractionStats(10, 8, 2, 24)
        facts = tuple(make_fact(f"f{i}") for i in range(24))
        result = ExtractionResult(
            facts=facts,
            errors=(),
            stats=stats,
            source_ref="test.xml",
            extractor_version="1.0.0",
        )
        assert result.stats == stats

    def test_source_ref_accessible(self) -> None:
        """source_ref is accessible from result."""
        result = make_result(source_ref="events/2024-01-15.xml")
        assert result.source_ref == "events/2024-01-15.xml"

    def test_extractor_version_accessible(self) -> None:
        """extractor_version is accessible from result."""
        result = make_result(extractor_version="2.0.0")
        assert result.extractor_version == "2.0.0"


# =============================================================================
# ExtractorProtocol Tests
# =============================================================================


class TestExtractorProtocolDefinition:
    """Tests for ExtractorProtocol definition."""

    def test_protocol_is_runtime_checkable(self) -> None:
        """ExtractorProtocol is runtime checkable."""
        # Create a class that implements the protocol
        class DummyExtractor:
            VERSION = "1.0.0"

            def extract(
                self,
                raw: bytes | str,
                *,
                source_ref: str,
                strict: bool = True,
            ) -> ExtractionResult:
                return ExtractionResult(
                    facts=(),
                    errors=(),
                    stats=ExtractionStats(0, 0, 0, 0),
                    source_ref=source_ref,
                    extractor_version=self.VERSION,
                )

        extractor = DummyExtractor()
        assert isinstance(extractor, ExtractorProtocol)

    def test_incomplete_implementation_fails_check(self) -> None:
        """Incomplete implementation fails isinstance check."""
        class IncompleteExtractor:
            VERSION = "1.0.0"
            # Missing extract method

        extractor = IncompleteExtractor()
        assert not isinstance(extractor, ExtractorProtocol)

    def test_missing_version_fails_check(self) -> None:
        """Missing VERSION class attribute fails isinstance check."""
        class NoVersionExtractor:
            def extract(
                self,
                raw: bytes | str,
                *,
                source_ref: str,
                strict: bool = True,
            ) -> ExtractionResult:
                pass

        extractor = NoVersionExtractor()
        assert not isinstance(extractor, ExtractorProtocol)


class TestExtractorProtocolSignature:
    """Tests for ExtractorProtocol method signatures."""

    def test_extract_accepts_bytes(self) -> None:
        """Extract method should accept bytes input."""
        class BytesExtractor:
            VERSION = "1.0.0"

            def extract(
                self,
                raw: bytes | str,
                *,
                source_ref: str,
                strict: bool = True,
            ) -> ExtractionResult:
                assert isinstance(raw, bytes)
                return ExtractionResult(
                    facts=(),
                    errors=(),
                    stats=ExtractionStats(0, 0, 0, 0),
                    source_ref=source_ref,
                    extractor_version=self.VERSION,
                )

        extractor = BytesExtractor()
        result = extractor.extract(b"<Event/>", source_ref="test")
        assert result.success

    def test_extract_accepts_string(self) -> None:
        """Extract method should accept string input."""
        class StringExtractor:
            VERSION = "1.0.0"

            def extract(
                self,
                raw: bytes | str,
                *,
                source_ref: str,
                strict: bool = True,
            ) -> ExtractionResult:
                assert isinstance(raw, str)
                return ExtractionResult(
                    facts=(),
                    errors=(),
                    stats=ExtractionStats(0, 0, 0, 0),
                    source_ref=source_ref,
                    extractor_version=self.VERSION,
                )

        extractor = StringExtractor()
        result = extractor.extract("<Event/>", source_ref="test")
        assert result.success

    def test_extract_requires_source_ref_kwarg(self) -> None:
        """Extract method requires source_ref as keyword argument."""
        class KwargExtractor:
            VERSION = "1.0.0"

            def extract(
                self,
                raw: bytes | str,
                *,
                source_ref: str,
                strict: bool = True,
            ) -> ExtractionResult:
                return ExtractionResult(
                    facts=(),
                    errors=(),
                    stats=ExtractionStats(0, 0, 0, 0),
                    source_ref=source_ref,
                    extractor_version=self.VERSION,
                )

        extractor = KwargExtractor()
        # Must use keyword argument
        result = extractor.extract("<Event/>", source_ref="test.xml")
        assert result.source_ref == "test.xml"

    def test_extract_strict_defaults_to_true(self) -> None:
        """Extract method strict parameter defaults to True."""
        class DefaultStrictExtractor:
            VERSION = "1.0.0"

            def extract(
                self,
                raw: bytes | str,
                *,
                source_ref: str,
                strict: bool = True,
            ) -> ExtractionResult:
                assert strict is True
                return ExtractionResult(
                    facts=(),
                    errors=(),
                    stats=ExtractionStats(0, 0, 0, 0),
                    source_ref=source_ref,
                    extractor_version=self.VERSION,
                )

        extractor = DefaultStrictExtractor()
        # strict should default to True
        result = extractor.extract("<Event/>", source_ref="test")
        assert result.success
