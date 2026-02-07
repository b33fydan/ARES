"""Tests for Windows Event Log extractor.

Tests validate:
1. Event 4624 (logon) extraction
2. Event 4672 (privilege) extraction
3. Event 4688 (process) extraction
4. Strict vs permissive mode
5. Error handling
6. Size limits
7. Protocol compliance
"""

import pytest
from datetime import datetime
from pathlib import Path

from ares.dialectic.evidence.extractors import (
    WindowsEventExtractor,
    ExtractorProtocol,
    ExtractionError,
)
from ares.dialectic.evidence.fact import EntityType
from ares.dialectic.evidence.provenance import SourceType


# =============================================================================
# Fixtures
# =============================================================================

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def load_fixture(name: str) -> str:
    """Load a test fixture file."""
    return (FIXTURES_DIR / name).read_text(encoding="utf-8")


# Sample event XMLs for inline tests
SAMPLE_4624_XML = """<?xml version="1.0" encoding="UTF-8"?>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4624</EventID>
    <TimeCreated SystemTime="2025-02-04T14:30:00.000Z"/>
    <Computer>DC01.internal.local</Computer>
  </System>
  <EventData>
    <Data Name="TargetUserName">jsmith</Data>
    <Data Name="TargetDomainName">INTERNAL</Data>
    <Data Name="LogonType">10</Data>
    <Data Name="IpAddress">192.168.1.100</Data>
    <Data Name="WorkstationName">WS001</Data>
  </EventData>
</Event>"""

SAMPLE_4672_XML = """<?xml version="1.0" encoding="UTF-8"?>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4672</EventID>
    <TimeCreated SystemTime="2025-02-04T14:30:00.000Z"/>
    <Computer>DC01.internal.local</Computer>
  </System>
  <EventData>
    <Data Name="SubjectUserName">jsmith</Data>
    <Data Name="SubjectDomainName">INTERNAL</Data>
    <Data Name="PrivilegeList">SeDebugPrivilege
		SeBackupPrivilege</Data>
  </EventData>
</Event>"""

SAMPLE_4688_XML = """<?xml version="1.0" encoding="UTF-8"?>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4688</EventID>
    <TimeCreated SystemTime="2025-02-04T14:35:00.000Z"/>
    <Computer>DC01.internal.local</Computer>
  </System>
  <EventData>
    <Data Name="SubjectUserName">jsmith</Data>
    <Data Name="SubjectDomainName">INTERNAL</Data>
    <Data Name="NewProcessId">0x1234</Data>
    <Data Name="NewProcessName">C:\\Windows\\System32\\cmd.exe</Data>
    <Data Name="CommandLine">cmd.exe /c whoami</Data>
    <Data Name="ParentProcessName">C:\\Windows\\explorer.exe</Data>
  </EventData>
</Event>"""

# XML without declaration for wrapper tests (XML declarations must be at start of doc)
SAMPLE_4624_XML_NO_DECL = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4624</EventID>
    <TimeCreated SystemTime="2025-02-04T14:30:00.000Z"/>
    <Computer>DC01.internal.local</Computer>
  </System>
  <EventData>
    <Data Name="TargetUserName">jsmith</Data>
    <Data Name="TargetDomainName">INTERNAL</Data>
    <Data Name="LogonType">10</Data>
    <Data Name="IpAddress">192.168.1.100</Data>
    <Data Name="WorkstationName">WS001</Data>
  </EventData>
</Event>"""

SAMPLE_4672_XML_NO_DECL = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4672</EventID>
    <TimeCreated SystemTime="2025-02-04T14:30:00.000Z"/>
    <Computer>DC01.internal.local</Computer>
  </System>
  <EventData>
    <Data Name="SubjectUserName">jsmith</Data>
    <Data Name="SubjectDomainName">INTERNAL</Data>
    <Data Name="PrivilegeList">SeDebugPrivilege
		SeBackupPrivilege</Data>
  </EventData>
</Event>"""

SAMPLE_4688_XML_NO_DECL = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4688</EventID>
    <TimeCreated SystemTime="2025-02-04T14:35:00.000Z"/>
    <Computer>DC01.internal.local</Computer>
  </System>
  <EventData>
    <Data Name="SubjectUserName">jsmith</Data>
    <Data Name="SubjectDomainName">INTERNAL</Data>
    <Data Name="NewProcessId">0x1234</Data>
    <Data Name="NewProcessName">C:\\Windows\\System32\\cmd.exe</Data>
    <Data Name="CommandLine">cmd.exe /c whoami</Data>
    <Data Name="ParentProcessName">C:\\Windows\\explorer.exe</Data>
  </EventData>
</Event>"""

UNSUPPORTED_EVENT_XML_NO_DECL = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>9999</EventID>
    <TimeCreated SystemTime="2025-02-04T14:30:00.000Z"/>
    <Computer>DC01.internal.local</Computer>
  </System>
  <EventData>
    <Data Name="SomeField">SomeValue</Data>
  </EventData>
</Event>"""

MALFORMED_XML = "<Event><broken"

UNSUPPORTED_EVENT_XML = """<?xml version="1.0" encoding="UTF-8"?>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>9999</EventID>
    <TimeCreated SystemTime="2025-02-04T14:30:00.000Z"/>
    <Computer>DC01.internal.local</Computer>
  </System>
  <EventData>
    <Data Name="SomeField">SomeValue</Data>
  </EventData>
</Event>"""


# =============================================================================
# Protocol Compliance Tests
# =============================================================================


class TestWindowsExtractorProtocolCompliance:
    """Tests for ExtractorProtocol compliance."""

    def test_implements_extractor_protocol(self) -> None:
        """WindowsEventExtractor implements ExtractorProtocol."""
        extractor = WindowsEventExtractor()
        assert isinstance(extractor, ExtractorProtocol)

    def test_has_version_attribute(self) -> None:
        """Extractor has VERSION class attribute."""
        assert hasattr(WindowsEventExtractor, "VERSION")
        assert isinstance(WindowsEventExtractor.VERSION, str)

    def test_version_is_semantic(self) -> None:
        """VERSION follows semantic versioning."""
        parts = WindowsEventExtractor.VERSION.split(".")
        assert len(parts) == 3
        for part in parts:
            assert part.isdigit()

    def test_extract_returns_extraction_result(self) -> None:
        """extract() returns ExtractionResult."""
        extractor = WindowsEventExtractor()
        result = extractor.extract(SAMPLE_4624_XML, source_ref="test.xml")
        assert hasattr(result, "facts")
        assert hasattr(result, "errors")
        assert hasattr(result, "stats")
        assert hasattr(result, "source_ref")
        assert hasattr(result, "extractor_version")

    def test_extractor_version_in_result(self) -> None:
        """Result contains correct extractor version."""
        extractor = WindowsEventExtractor()
        result = extractor.extract(SAMPLE_4624_XML, source_ref="test.xml")
        assert result.extractor_version == WindowsEventExtractor.VERSION


# =============================================================================
# Event 4624 (Logon) Tests
# =============================================================================


class TestEvent4624Extraction:
    """Tests for 4624 logon event extraction."""

    def test_extracts_logon_facts(self) -> None:
        """4624 event produces expected facts."""
        extractor = WindowsEventExtractor()
        result = extractor.extract(SAMPLE_4624_XML, source_ref="test.xml")

        assert result.success
        assert len(result.facts) >= 5  # logon_type, logon_time, source_ip, workstation, target_username

    def test_entity_id_format(self) -> None:
        """Entity ID follows user:name@domain format."""
        extractor = WindowsEventExtractor()
        result = extractor.extract(SAMPLE_4624_XML, source_ref="test.xml")

        entity_ids = {f.entity_id for f in result.facts}
        assert "user:jsmith@INTERNAL" in entity_ids

    def test_logon_type_extracted(self) -> None:
        """Logon type is extracted and translated."""
        extractor = WindowsEventExtractor()
        result = extractor.extract(SAMPLE_4624_XML, source_ref="test.xml")

        logon_type_fact = next(f for f in result.facts if f.field == "logon_type")
        assert logon_type_fact.value == "remote_interactive"  # Type 10

    def test_logon_time_extracted(self) -> None:
        """Logon time is extracted in ISO format."""
        extractor = WindowsEventExtractor()
        result = extractor.extract(SAMPLE_4624_XML, source_ref="test.xml")

        logon_time_fact = next(f for f in result.facts if f.field == "logon_time")
        assert "2025-02-04T14:30:00" in logon_time_fact.value

    def test_source_ip_extracted(self) -> None:
        """Source IP is extracted."""
        extractor = WindowsEventExtractor()
        result = extractor.extract(SAMPLE_4624_XML, source_ref="test.xml")

        ip_fact = next(f for f in result.facts if f.field == "source_ip")
        assert ip_fact.value == "192.168.1.100"

    def test_workstation_extracted(self) -> None:
        """Workstation name is extracted."""
        extractor = WindowsEventExtractor()
        result = extractor.extract(SAMPLE_4624_XML, source_ref="test.xml")

        ws_fact = next(f for f in result.facts if f.field == "workstation")
        assert ws_fact.value == "WS001"

    def test_target_username_extracted(self) -> None:
        """Target username is extracted."""
        extractor = WindowsEventExtractor()
        result = extractor.extract(SAMPLE_4624_XML, source_ref="test.xml")

        user_fact = next(f for f in result.facts if f.field == "target_username")
        assert user_fact.value == "jsmith"

    def test_domain_extracted(self) -> None:
        """Domain is extracted."""
        extractor = WindowsEventExtractor()
        result = extractor.extract(SAMPLE_4624_XML, source_ref="test.xml")

        domain_fact = next(f for f in result.facts if f.field == "domain")
        assert domain_fact.value == "INTERNAL"

    def test_provenance_set_correctly(self) -> None:
        """Provenance is set with AUTH_LOG source type."""
        extractor = WindowsEventExtractor()
        result = extractor.extract(SAMPLE_4624_XML, source_ref="test.xml")

        for fact in result.facts:
            assert fact.provenance.source_type == SourceType.AUTH_LOG
            assert fact.provenance.source_id == "test.xml"
            assert fact.provenance.parser_version == extractor.VERSION

    def test_entity_type_is_node(self) -> None:
        """All facts have NODE entity type."""
        extractor = WindowsEventExtractor()
        result = extractor.extract(SAMPLE_4624_XML, source_ref="test.xml")

        for fact in result.facts:
            assert fact.entity_type == EntityType.NODE

    def test_fixture_4624_extraction(self) -> None:
        """4624 fixture file extracts correctly."""
        extractor = WindowsEventExtractor()
        xml = load_fixture("event_4624_logon.xml")
        result = extractor.extract(xml, source_ref="event_4624_logon.xml")

        assert result.success
        assert len(result.facts) >= 5

        # Check specific fields from fixture
        ip_fact = next(f for f in result.facts if f.field == "source_ip")
        assert ip_fact.value == "192.168.1.100"


# =============================================================================
# Event 4672 (Privileges) Tests
# =============================================================================


class TestEvent4672Extraction:
    """Tests for 4672 privilege event extraction."""

    def test_extracts_privilege_facts(self) -> None:
        """4672 event produces expected facts."""
        extractor = WindowsEventExtractor()
        result = extractor.extract(SAMPLE_4672_XML, source_ref="test.xml")

        assert result.success
        assert len(result.facts) == 2  # privilege_level, privileges_assigned

    def test_entity_id_format(self) -> None:
        """Entity ID follows user:name@domain format."""
        extractor = WindowsEventExtractor()
        result = extractor.extract(SAMPLE_4672_XML, source_ref="test.xml")

        entity_ids = {f.entity_id for f in result.facts}
        assert "user:jsmith@INTERNAL" in entity_ids

    def test_admin_privilege_detected(self) -> None:
        """Admin privileges are detected."""
        extractor = WindowsEventExtractor()
        result = extractor.extract(SAMPLE_4672_XML, source_ref="test.xml")

        level_fact = next(f for f in result.facts if f.field == "privilege_level")
        assert level_fact.value == "ADMIN"

    def test_privileges_list_extracted(self) -> None:
        """Privilege list is extracted as list."""
        extractor = WindowsEventExtractor()
        result = extractor.extract(SAMPLE_4672_XML, source_ref="test.xml")

        privs_fact = next(f for f in result.facts if f.field == "privileges_assigned")
        assert isinstance(privs_fact.value, list)
        assert "SeDebugPrivilege" in privs_fact.value
        assert "SeBackupPrivilege" in privs_fact.value

    def test_non_admin_privilege(self) -> None:
        """Non-admin privileges result in STANDARD level."""
        xml = """<?xml version="1.0" encoding="UTF-8"?>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4672</EventID>
    <TimeCreated SystemTime="2025-02-04T14:30:00.000Z"/>
    <Computer>DC01.internal.local</Computer>
  </System>
  <EventData>
    <Data Name="SubjectUserName">jsmith</Data>
    <Data Name="SubjectDomainName">INTERNAL</Data>
    <Data Name="PrivilegeList">SeChangeNotifyPrivilege</Data>
  </EventData>
</Event>"""
        extractor = WindowsEventExtractor()
        result = extractor.extract(xml, source_ref="test.xml")

        level_fact = next(f for f in result.facts if f.field == "privilege_level")
        assert level_fact.value == "STANDARD"

    def test_fixture_4672_extraction(self) -> None:
        """4672 fixture file extracts correctly."""
        extractor = WindowsEventExtractor()
        xml = load_fixture("event_4672_privileges.xml")
        result = extractor.extract(xml, source_ref="event_4672_privileges.xml")

        assert result.success

        level_fact = next(f for f in result.facts if f.field == "privilege_level")
        assert level_fact.value == "ADMIN"


# =============================================================================
# Event 4688 (Process Creation) Tests
# =============================================================================


class TestEvent4688Extraction:
    """Tests for 4688 process creation event extraction."""

    def test_extracts_process_facts(self) -> None:
        """4688 event produces expected facts."""
        extractor = WindowsEventExtractor()
        result = extractor.extract(SAMPLE_4688_XML, source_ref="test.xml")

        assert result.success
        assert len(result.facts) >= 5  # name, path, parent_name, parent_path, command_line, user

    def test_entity_id_format(self) -> None:
        """Entity ID follows process:pid format."""
        extractor = WindowsEventExtractor()
        result = extractor.extract(SAMPLE_4688_XML, source_ref="test.xml")

        entity_ids = {f.entity_id for f in result.facts}
        assert "process:0x1234" in entity_ids

    def test_process_name_extracted(self) -> None:
        """Process name is extracted (just filename)."""
        extractor = WindowsEventExtractor()
        result = extractor.extract(SAMPLE_4688_XML, source_ref="test.xml")

        name_fact = next(f for f in result.facts if f.field == "process_name")
        assert name_fact.value == "cmd.exe"

    def test_process_path_extracted(self) -> None:
        """Full process path is extracted."""
        extractor = WindowsEventExtractor()
        result = extractor.extract(SAMPLE_4688_XML, source_ref="test.xml")

        path_fact = next(f for f in result.facts if f.field == "process_path")
        assert path_fact.value == "C:\\Windows\\System32\\cmd.exe"

    def test_parent_name_extracted(self) -> None:
        """Parent process name is extracted."""
        extractor = WindowsEventExtractor()
        result = extractor.extract(SAMPLE_4688_XML, source_ref="test.xml")

        parent_fact = next(f for f in result.facts if f.field == "parent_name")
        assert parent_fact.value == "explorer.exe"

    def test_command_line_extracted(self) -> None:
        """Command line is extracted."""
        extractor = WindowsEventExtractor()
        result = extractor.extract(SAMPLE_4688_XML, source_ref="test.xml")

        cmd_fact = next(f for f in result.facts if f.field == "command_line")
        assert cmd_fact.value == "cmd.exe /c whoami"

    def test_user_extracted(self) -> None:
        """User who started process is extracted."""
        extractor = WindowsEventExtractor()
        result = extractor.extract(SAMPLE_4688_XML, source_ref="test.xml")

        user_fact = next(f for f in result.facts if f.field == "user")
        assert user_fact.value == "INTERNAL\\jsmith"

    def test_provenance_is_process_list(self) -> None:
        """4688 facts have PROCESS_LIST source type."""
        extractor = WindowsEventExtractor()
        result = extractor.extract(SAMPLE_4688_XML, source_ref="test.xml")

        for fact in result.facts:
            assert fact.provenance.source_type == SourceType.PROCESS_LIST

    def test_fixture_4688_extraction(self) -> None:
        """4688 fixture file extracts correctly."""
        extractor = WindowsEventExtractor()
        xml = load_fixture("event_4688_process.xml")
        result = extractor.extract(xml, source_ref="event_4688_process.xml")

        assert result.success

        # Check suspicious parent process from fixture
        parent_fact = next(f for f in result.facts if f.field == "parent_name")
        assert parent_fact.value == "EXCEL.EXE"


# =============================================================================
# Strict Mode Tests
# =============================================================================


class TestStrictMode:
    """Tests for strict mode behavior."""

    def test_strict_raises_on_malformed_xml(self) -> None:
        """Strict mode raises on malformed XML."""
        extractor = WindowsEventExtractor()
        with pytest.raises(ValueError, match="XML parse error"):
            extractor.extract(MALFORMED_XML, source_ref="test.xml", strict=True)

    def test_strict_raises_on_unsupported_event(self) -> None:
        """Strict mode raises on unsupported event."""
        extractor = WindowsEventExtractor()
        with pytest.raises(ValueError, match="Unsupported event ID"):
            extractor.extract(UNSUPPORTED_EVENT_XML, source_ref="test.xml", strict=True)

    def test_strict_raises_on_missing_field(self) -> None:
        """Strict mode raises on missing required field."""
        xml = """<?xml version="1.0" encoding="UTF-8"?>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4624</EventID>
    <TimeCreated SystemTime="2025-02-04T14:30:00.000Z"/>
    <Computer>DC01.internal.local</Computer>
  </System>
  <EventData>
    <Data Name="TargetDomainName">INTERNAL</Data>
  </EventData>
</Event>"""
        extractor = WindowsEventExtractor()
        with pytest.raises(ValueError, match="Missing TargetUserName"):
            extractor.extract(xml, source_ref="test.xml", strict=True)

    def test_strict_is_default(self) -> None:
        """Strict mode is the default."""
        extractor = WindowsEventExtractor()
        with pytest.raises(ValueError):
            extractor.extract(MALFORMED_XML, source_ref="test.xml")


# =============================================================================
# Permissive Mode Tests
# =============================================================================


class TestPermissiveMode:
    """Tests for permissive mode behavior."""

    def test_permissive_collects_errors(self) -> None:
        """Permissive mode collects errors without raising."""
        extractor = WindowsEventExtractor()
        result = extractor.extract(
            MALFORMED_XML, source_ref="test.xml", strict=False
        )

        assert not result.success
        assert len(result.errors) > 0

    def test_permissive_returns_partial_results(self) -> None:
        """Permissive mode returns partial results."""
        # Multiple events, one bad (use NO_DECL versions to avoid XML declaration conflicts)
        xml = f"""<Events>
{SAMPLE_4624_XML_NO_DECL}
{UNSUPPORTED_EVENT_XML_NO_DECL}
</Events>"""
        extractor = WindowsEventExtractor()
        result = extractor.extract(xml, source_ref="test.xml", strict=False)

        # Should have facts from valid event and errors from invalid
        assert len(result.facts) > 0
        assert len(result.errors) > 0
        assert result.partial

    def test_permissive_error_contains_snippet(self) -> None:
        """Errors contain raw snippet for debugging."""
        extractor = WindowsEventExtractor()
        result = extractor.extract(
            UNSUPPORTED_EVENT_XML, source_ref="test.xml", strict=False
        )

        assert len(result.errors) > 0
        error = result.errors[0]
        assert len(error.raw_snippet) > 0
        assert len(error.raw_snippet) <= 200

    def test_permissive_error_type_set(self) -> None:
        """Error type is set appropriately."""
        extractor = WindowsEventExtractor()
        result = extractor.extract(
            UNSUPPORTED_EVENT_XML, source_ref="test.xml", strict=False
        )

        error = result.errors[0]
        assert error.error_type == ExtractionError.UNSUPPORTED_EVENT


# =============================================================================
# Statistics Tests
# =============================================================================


class TestExtractionStats:
    """Tests for extraction statistics."""

    def test_stats_events_seen(self) -> None:
        """events_seen counts all events."""
        extractor = WindowsEventExtractor()
        result = extractor.extract(SAMPLE_4624_XML, source_ref="test.xml")
        assert result.stats.events_seen == 1

    def test_stats_events_parsed(self) -> None:
        """events_parsed counts successful parses."""
        extractor = WindowsEventExtractor()
        result = extractor.extract(SAMPLE_4624_XML, source_ref="test.xml")
        assert result.stats.events_parsed == 1

    def test_stats_events_dropped_on_error(self) -> None:
        """events_dropped counts errors."""
        extractor = WindowsEventExtractor()
        result = extractor.extract(
            UNSUPPORTED_EVENT_XML, source_ref="test.xml", strict=False
        )
        assert result.stats.events_dropped == 1
        assert result.stats.events_parsed == 0

    def test_stats_facts_emitted(self) -> None:
        """facts_emitted counts generated facts."""
        extractor = WindowsEventExtractor()
        result = extractor.extract(SAMPLE_4624_XML, source_ref="test.xml")
        assert result.stats.facts_emitted == len(result.facts)

    def test_stats_consistency(self) -> None:
        """Stats are internally consistent."""
        extractor = WindowsEventExtractor()
        result = extractor.extract(SAMPLE_4624_XML, source_ref="test.xml")

        assert result.stats.events_parsed + result.stats.events_dropped <= result.stats.events_seen


# =============================================================================
# Input Format Tests
# =============================================================================


class TestInputFormats:
    """Tests for different input formats."""

    def test_accepts_bytes_input(self) -> None:
        """Extractor accepts bytes input."""
        extractor = WindowsEventExtractor()
        result = extractor.extract(
            SAMPLE_4624_XML.encode("utf-8"), source_ref="test.xml"
        )
        assert result.success

    def test_accepts_string_input(self) -> None:
        """Extractor accepts string input."""
        extractor = WindowsEventExtractor()
        result = extractor.extract(SAMPLE_4624_XML, source_ref="test.xml")
        assert result.success

    def test_multiple_events_in_wrapper(self) -> None:
        """Extractor handles Events wrapper with multiple events."""
        # Use NO_DECL versions to avoid XML declaration conflicts in wrapper
        xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<Events>
{SAMPLE_4624_XML_NO_DECL}
{SAMPLE_4672_XML_NO_DECL}
</Events>"""
        extractor = WindowsEventExtractor()
        result = extractor.extract(xml, source_ref="test.xml")

        assert result.success
        assert result.stats.events_seen == 2
        assert result.stats.events_parsed == 2


# =============================================================================
# Size Limit Tests
# =============================================================================


class TestSizeLimits:
    """Tests for field size limits."""

    def test_command_line_truncated_at_10kb(self) -> None:
        """Command line is truncated at 10KB."""
        long_cmd = "x" * 20000  # 20KB
        xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4688</EventID>
    <TimeCreated SystemTime="2025-02-04T14:35:00.000Z"/>
    <Computer>DC01.internal.local</Computer>
  </System>
  <EventData>
    <Data Name="SubjectUserName">jsmith</Data>
    <Data Name="SubjectDomainName">INTERNAL</Data>
    <Data Name="NewProcessId">0x1234</Data>
    <Data Name="NewProcessName">C:\\Windows\\cmd.exe</Data>
    <Data Name="CommandLine">{long_cmd}</Data>
  </EventData>
</Event>"""
        extractor = WindowsEventExtractor()
        result = extractor.extract(xml, source_ref="test.xml")

        cmd_fact = next(f for f in result.facts if f.field == "command_line")
        assert len(cmd_fact.value.encode("utf-8")) <= 10240

    def test_other_fields_truncated_at_1kb(self) -> None:
        """Other fields are truncated at 1KB."""
        long_user = "u" * 2000  # 2KB
        xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4624</EventID>
    <TimeCreated SystemTime="2025-02-04T14:30:00.000Z"/>
    <Computer>DC01.internal.local</Computer>
  </System>
  <EventData>
    <Data Name="TargetUserName">{long_user}</Data>
    <Data Name="TargetDomainName">INTERNAL</Data>
    <Data Name="LogonType">10</Data>
  </EventData>
</Event>"""
        extractor = WindowsEventExtractor()
        result = extractor.extract(xml, source_ref="test.xml")

        user_fact = next(f for f in result.facts if f.field == "target_username")
        assert len(user_fact.value.encode("utf-8")) <= 1024


# =============================================================================
# Timestamp Tests
# =============================================================================


class TestTimestampParsing:
    """Tests for timestamp parsing."""

    def test_utc_timestamp_parsed(self) -> None:
        """UTC timestamp is parsed correctly."""
        extractor = WindowsEventExtractor()
        result = extractor.extract(SAMPLE_4624_XML, source_ref="test.xml")

        for fact in result.facts:
            assert fact.timestamp == datetime(2025, 2, 4, 14, 30, 0)

    def test_timestamp_without_milliseconds(self) -> None:
        """Timestamp without milliseconds is parsed."""
        xml = """<?xml version="1.0" encoding="UTF-8"?>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4624</EventID>
    <TimeCreated SystemTime="2025-02-04T14:30:00Z"/>
    <Computer>DC01.internal.local</Computer>
  </System>
  <EventData>
    <Data Name="TargetUserName">jsmith</Data>
    <Data Name="TargetDomainName">INTERNAL</Data>
    <Data Name="LogonType">10</Data>
  </EventData>
</Event>"""
        extractor = WindowsEventExtractor()
        result = extractor.extract(xml, source_ref="test.xml")
        assert result.success


# =============================================================================
# Fact ID Uniqueness Tests
# =============================================================================


class TestFactIdUniqueness:
    """Tests for fact ID uniqueness."""

    def test_fact_ids_unique_within_event(self) -> None:
        """All fact IDs within an event are unique."""
        extractor = WindowsEventExtractor()
        result = extractor.extract(SAMPLE_4624_XML, source_ref="test.xml")

        fact_ids = [f.fact_id for f in result.facts]
        assert len(fact_ids) == len(set(fact_ids))

    def test_fact_ids_unique_across_events(self) -> None:
        """Fact IDs are unique across multiple events."""
        # Use NO_DECL versions to avoid XML declaration conflicts in wrapper
        xml = f"""<Events>
{SAMPLE_4624_XML_NO_DECL}
{SAMPLE_4672_XML_NO_DECL}
{SAMPLE_4688_XML_NO_DECL}
</Events>"""
        extractor = WindowsEventExtractor()
        result = extractor.extract(xml, source_ref="test.xml")

        fact_ids = [f.fact_id for f in result.facts]
        assert len(fact_ids) == len(set(fact_ids))

    def test_fact_id_contains_event_type(self) -> None:
        """Fact IDs contain event type for traceability."""
        extractor = WindowsEventExtractor()

        result_4624 = extractor.extract(SAMPLE_4624_XML, source_ref="test.xml")
        assert all("4624" in f.fact_id for f in result_4624.facts)

        result_4672 = extractor.extract(SAMPLE_4672_XML, source_ref="test.xml")
        assert all("4672" in f.fact_id for f in result_4672.facts)

        result_4688 = extractor.extract(SAMPLE_4688_XML, source_ref="test.xml")
        assert all("4688" in f.fact_id for f in result_4688.facts)


# =============================================================================
# Logon Type Tests
# =============================================================================


class TestLogonTypeMapping:
    """Tests for logon type mapping."""

    def test_type_2_interactive(self) -> None:
        """Logon type 2 maps to interactive."""
        xml = SAMPLE_4624_XML.replace("LogonType\">10", "LogonType\">2")
        extractor = WindowsEventExtractor()
        result = extractor.extract(xml, source_ref="test.xml")

        logon_fact = next(f for f in result.facts if f.field == "logon_type")
        assert logon_fact.value == "interactive"

    def test_type_3_network(self) -> None:
        """Logon type 3 maps to network."""
        xml = SAMPLE_4624_XML.replace("LogonType\">10", "LogonType\">3")
        extractor = WindowsEventExtractor()
        result = extractor.extract(xml, source_ref="test.xml")

        logon_fact = next(f for f in result.facts if f.field == "logon_type")
        assert logon_fact.value == "network"

    def test_unknown_type_preserved(self) -> None:
        """Unknown logon types are preserved as type_N."""
        xml = SAMPLE_4624_XML.replace("LogonType\">10", "LogonType\">99")
        extractor = WindowsEventExtractor()
        result = extractor.extract(xml, source_ref="test.xml")

        logon_fact = next(f for f in result.facts if f.field == "logon_type")
        assert logon_fact.value == "type_99"


# =============================================================================
# Edge Case Tests
# =============================================================================


class TestEdgeCases:
    """Tests for edge cases."""

    def test_empty_optional_fields_excluded(self) -> None:
        """Empty optional fields are excluded from facts."""
        xml = """<?xml version="1.0" encoding="UTF-8"?>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4624</EventID>
    <TimeCreated SystemTime="2025-02-04T14:30:00.000Z"/>
    <Computer>DC01.internal.local</Computer>
  </System>
  <EventData>
    <Data Name="TargetUserName">jsmith</Data>
    <Data Name="TargetDomainName">INTERNAL</Data>
    <Data Name="LogonType">10</Data>
    <Data Name="IpAddress">-</Data>
    <Data Name="WorkstationName">-</Data>
  </EventData>
</Event>"""
        extractor = WindowsEventExtractor()
        result = extractor.extract(xml, source_ref="test.xml")

        fields = {f.field for f in result.facts}
        assert "source_ip" not in fields  # "-" is excluded
        assert "workstation" not in fields  # "-" is excluded

    def test_handles_missing_event_data(self) -> None:
        """Handles events with missing EventData section."""
        xml = """<?xml version="1.0" encoding="UTF-8"?>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4624</EventID>
    <TimeCreated SystemTime="2025-02-04T14:30:00.000Z"/>
    <Computer>DC01.internal.local</Computer>
  </System>
</Event>"""
        extractor = WindowsEventExtractor()
        with pytest.raises(ValueError):
            extractor.extract(xml, source_ref="test.xml", strict=True)

    def test_empty_input_no_crash(self) -> None:
        """Empty input doesn't crash."""
        extractor = WindowsEventExtractor()
        with pytest.raises(ValueError):
            extractor.extract("", source_ref="test.xml")
