"""Tests for Provenance class."""

import pytest
from datetime import datetime
from dataclasses import FrozenInstanceError

from ares.dialectic.evidence.provenance import Provenance, SourceType


class TestSourceType:
    """Tests for SourceType enum."""

    def test_all_source_types_exist(self) -> None:
        """Verify all expected source types are defined."""
        expected = {
            "NETFLOW",
            "SYSLOG",
            "PROCESS_LIST",
            "DNS_LOG",
            "AUTH_LOG",
            "GRAPH_COMPUTATION",
            "MANUAL",
            "UNKNOWN",
        }
        actual = {member.name for member in SourceType}
        assert actual == expected

    def test_source_type_values(self) -> None:
        """Verify source type values are lowercase."""
        assert SourceType.NETFLOW.value == "netflow"
        assert SourceType.PROCESS_LIST.value == "process_list"


class TestProvenanceImmutability:
    """Tests for Provenance immutability."""

    def test_cannot_modify_source_type(self) -> None:
        """Provenance source_type cannot be modified after creation."""
        prov = Provenance(
            source_type=SourceType.SYSLOG,
            source_id="syslog-001",
        )
        with pytest.raises(FrozenInstanceError):
            prov.source_type = SourceType.NETFLOW

    def test_cannot_modify_source_id(self) -> None:
        """Provenance source_id cannot be modified after creation."""
        prov = Provenance(
            source_type=SourceType.SYSLOG,
            source_id="syslog-001",
        )
        with pytest.raises(FrozenInstanceError):
            prov.source_id = "different-id"

    def test_cannot_modify_parser_version(self) -> None:
        """Provenance parser_version cannot be modified after creation."""
        prov = Provenance(
            source_type=SourceType.SYSLOG,
            source_id="syslog-001",
        )
        with pytest.raises(FrozenInstanceError):
            prov.parser_version = "2.0.0"

    def test_cannot_modify_raw_reference(self) -> None:
        """Provenance raw_reference cannot be modified after creation."""
        prov = Provenance(
            source_type=SourceType.SYSLOG,
            source_id="syslog-001",
            raw_reference="line:42",
        )
        with pytest.raises(FrozenInstanceError):
            prov.raw_reference = "line:100"

    def test_cannot_modify_extracted_at(self) -> None:
        """Provenance extracted_at cannot be modified after creation."""
        prov = Provenance(
            source_type=SourceType.SYSLOG,
            source_id="syslog-001",
        )
        with pytest.raises(FrozenInstanceError):
            prov.extracted_at = datetime.utcnow()


class TestProvenanceSerialization:
    """Tests for Provenance serialization."""

    def test_to_dict_contains_all_fields(self) -> None:
        """to_dict includes all provenance fields."""
        timestamp = datetime(2024, 1, 15, 10, 30, 0)
        prov = Provenance(
            source_type=SourceType.DNS_LOG,
            source_id="dns-server-01",
            parser_version="2.1.0",
            raw_reference="offset:1024",
            extracted_at=timestamp,
        )
        result = prov.to_dict()

        assert result["source_type"] == "dns_log"
        assert result["source_id"] == "dns-server-01"
        assert result["parser_version"] == "2.1.0"
        assert result["raw_reference"] == "offset:1024"
        assert result["extracted_at"] == "2024-01-15T10:30:00"

    def test_serialization_roundtrip(self) -> None:
        """Provenance survives serialization roundtrip."""
        timestamp = datetime(2024, 1, 15, 10, 30, 0)
        original = Provenance(
            source_type=SourceType.AUTH_LOG,
            source_id="auth-001",
            parser_version="1.5.0",
            raw_reference="entry:999",
            extracted_at=timestamp,
        )

        serialized = original.to_dict()
        restored = Provenance.from_dict(serialized)

        assert restored.source_type == original.source_type
        assert restored.source_id == original.source_id
        assert restored.parser_version == original.parser_version
        assert restored.raw_reference == original.raw_reference
        assert restored.extracted_at == original.extracted_at

    def test_roundtrip_with_none_raw_reference(self) -> None:
        """Serialization handles None raw_reference."""
        original = Provenance(
            source_type=SourceType.NETFLOW,
            source_id="netflow-001",
            extracted_at=datetime(2024, 1, 1, 0, 0, 0),
        )

        serialized = original.to_dict()
        assert serialized["raw_reference"] is None

        restored = Provenance.from_dict(serialized)
        assert restored.raw_reference is None


class TestProvenanceManualFactory:
    """Tests for manual factory method."""

    def test_manual_creates_manual_source_type(self) -> None:
        """manual() creates provenance with MANUAL source type."""
        prov = Provenance.manual()
        assert prov.source_type == SourceType.MANUAL

    def test_manual_uses_default_source_id(self) -> None:
        """manual() uses 'test' as default source_id."""
        prov = Provenance.manual()
        assert prov.source_id == "test"

    def test_manual_accepts_custom_source_id(self) -> None:
        """manual() accepts custom source_id."""
        prov = Provenance.manual(source_id="custom-test")
        assert prov.source_id == "custom-test"

    def test_manual_accepts_raw_reference(self) -> None:
        """manual() accepts raw_reference parameter."""
        prov = Provenance.manual(raw_reference="test-ref:123")
        assert prov.raw_reference == "test-ref:123"

    def test_manual_sets_extracted_at(self) -> None:
        """manual() sets extracted_at to current time."""
        before = datetime.utcnow()
        prov = Provenance.manual()
        after = datetime.utcnow()

        assert before <= prov.extracted_at <= after


class TestProvenanceEquality:
    """Tests for Provenance equality and hashability."""

    def test_equal_provenances_are_equal(self) -> None:
        """Identical provenances compare equal."""
        timestamp = datetime(2024, 1, 15, 12, 0, 0)
        prov1 = Provenance(
            source_type=SourceType.SYSLOG,
            source_id="syslog-001",
            parser_version="1.0.0",
            raw_reference="line:10",
            extracted_at=timestamp,
        )
        prov2 = Provenance(
            source_type=SourceType.SYSLOG,
            source_id="syslog-001",
            parser_version="1.0.0",
            raw_reference="line:10",
            extracted_at=timestamp,
        )
        assert prov1 == prov2

    def test_different_provenances_not_equal(self) -> None:
        """Different provenances do not compare equal."""
        timestamp = datetime(2024, 1, 15, 12, 0, 0)
        prov1 = Provenance(
            source_type=SourceType.SYSLOG,
            source_id="syslog-001",
            extracted_at=timestamp,
        )
        prov2 = Provenance(
            source_type=SourceType.SYSLOG,
            source_id="syslog-002",
            extracted_at=timestamp,
        )
        assert prov1 != prov2

    def test_provenance_is_hashable(self) -> None:
        """Provenance can be used in sets and as dict keys."""
        timestamp = datetime(2024, 1, 15, 12, 0, 0)
        prov = Provenance(
            source_type=SourceType.NETFLOW,
            source_id="netflow-001",
            extracted_at=timestamp,
        )

        # Can be added to set
        prov_set = {prov}
        assert prov in prov_set

        # Can be used as dict key
        prov_dict = {prov: "value"}
        assert prov_dict[prov] == "value"

    def test_equal_provenances_have_same_hash(self) -> None:
        """Equal provenances have the same hash."""
        timestamp = datetime(2024, 1, 15, 12, 0, 0)
        prov1 = Provenance(
            source_type=SourceType.GRAPH_COMPUTATION,
            source_id="pagerank-v1",
            extracted_at=timestamp,
        )
        prov2 = Provenance(
            source_type=SourceType.GRAPH_COMPUTATION,
            source_id="pagerank-v1",
            extracted_at=timestamp,
        )
        assert hash(prov1) == hash(prov2)


class TestProvenanceDefaults:
    """Tests for Provenance default values."""

    def test_default_parser_version(self) -> None:
        """Default parser_version is 1.0.0."""
        prov = Provenance(
            source_type=SourceType.UNKNOWN,
            source_id="unknown-001",
        )
        assert prov.parser_version == "1.0.0"

    def test_default_raw_reference_is_none(self) -> None:
        """Default raw_reference is None."""
        prov = Provenance(
            source_type=SourceType.UNKNOWN,
            source_id="unknown-001",
        )
        assert prov.raw_reference is None

    def test_default_extracted_at_is_set(self) -> None:
        """Default extracted_at is set to current time."""
        before = datetime.utcnow()
        prov = Provenance(
            source_type=SourceType.UNKNOWN,
            source_id="unknown-001",
        )
        after = datetime.utcnow()

        assert prov.extracted_at is not None
        assert before <= prov.extracted_at <= after
