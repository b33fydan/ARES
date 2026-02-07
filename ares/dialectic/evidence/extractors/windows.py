"""Windows Security Event Log extractor.

Parses Windows Security Event XML into Facts for dialectical reasoning.
Supports events: 4624 (logon), 4672 (special privileges), 4688 (process creation).
"""

import re
import uuid
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime
from typing import Iterator

from ..provenance import Provenance, SourceType
from ..fact import Fact, EntityType
from .protocol import (
    ExtractionError,
    ExtractionStats,
    ExtractionResult,
)


# Windows Event Log XML namespace
EVTX_NS = {"evt": "http://schemas.microsoft.com/win/2004/08/events/event"}

# Supported event IDs
SUPPORTED_EVENTS = frozenset({4624, 4672, 4688})

# Size limits
MAX_FIELD_SIZE = 1024  # 1KB for most fields
MAX_COMMAND_LINE_SIZE = 10240  # 10KB for command_line

# Logon type descriptions (for 4624)
LOGON_TYPES = {
    "2": "interactive",
    "3": "network",
    "4": "batch",
    "5": "service",
    "7": "unlock",
    "8": "network_cleartext",
    "9": "new_credentials",
    "10": "remote_interactive",
    "11": "cached_interactive",
}


@dataclass(frozen=True)
class ParsedEvent:
    """Intermediate parsed event before conversion to Facts."""

    event_id: int
    timestamp: datetime
    computer: str
    event_data: dict[str, str]
    raw_xml: str
    line_number: int | None = None


class WindowsEventExtractor:
    """Extractor for Windows Security Event Log XML.

    Parses Windows Security Event XML and extracts Facts with provenance.
    Supports strict mode (raise on first error) and permissive mode
    (collect errors, return partial results).

    Supported events:
        - 4624: Successful logon (user facts)
        - 4672: Special privileges assigned (privilege facts)
        - 4688: Process creation (process facts)

    Attributes:
        VERSION: Semantic version of this extractor.
    """

    VERSION = "1.0.0"

    def extract(
        self,
        raw: bytes | str,
        *,
        source_ref: str,
        strict: bool = True,
    ) -> ExtractionResult:
        """Parse Windows Event XML into Facts.

        Args:
            raw: Raw XML data (single event or Events wrapper).
            source_ref: Reference to data source for provenance.
            strict: If True, raise on first error. If False, collect errors.

        Returns:
            ExtractionResult with extracted Facts and any errors.

        Raises:
            ValueError: In strict mode, on parse errors.
        """
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8")

        facts: list[Fact] = []
        errors: list[ExtractionError] = []
        events_seen = 0
        events_parsed = 0
        events_dropped = 0

        # Parse XML and iterate events
        try:
            for parsed in self._iterate_events(raw):
                events_seen += 1

                if parsed.event_id not in SUPPORTED_EVENTS:
                    events_dropped += 1
                    error = ExtractionError(
                        line_number=parsed.line_number,
                        raw_snippet=parsed.raw_xml[:200],
                        error_type=ExtractionError.UNSUPPORTED_EVENT,
                        message=f"Unsupported event ID: {parsed.event_id}",
                    )
                    if strict:
                        raise ValueError(error.message)
                    errors.append(error)
                    continue

                try:
                    event_facts = self._extract_facts(parsed, source_ref)
                    facts.extend(event_facts)
                    events_parsed += 1
                except Exception as e:
                    events_dropped += 1
                    error = ExtractionError(
                        line_number=parsed.line_number,
                        raw_snippet=parsed.raw_xml[:200],
                        error_type=ExtractionError.PARSE_ERROR,
                        message=str(e),
                    )
                    if strict:
                        raise ValueError(error.message) from e
                    errors.append(error)

        except ET.ParseError as e:
            error = ExtractionError(
                line_number=getattr(e, "position", (None,))[0],
                raw_snippet=raw[:200],
                error_type=ExtractionError.MALFORMED_XML,
                message=f"XML parse error: {e}",
            )
            if strict:
                raise ValueError(error.message) from e
            errors.append(error)

        stats = ExtractionStats(
            events_seen=events_seen,
            events_parsed=events_parsed,
            events_dropped=events_dropped,
            facts_emitted=len(facts),
        )

        return ExtractionResult(
            facts=tuple(facts),
            errors=tuple(errors),
            stats=stats,
            source_ref=source_ref,
            extractor_version=self.VERSION,
        )

    def _iterate_events(self, raw: str) -> Iterator[ParsedEvent]:
        """Iterate over events in XML input.

        Handles both single Event elements and Events wrappers.

        Args:
            raw: Raw XML string.

        Yields:
            ParsedEvent for each event found.
        """
        # Try to parse as XML
        root = ET.fromstring(raw)

        # Check if this is a single Event or wrapper
        if root.tag == "{http://schemas.microsoft.com/win/2004/08/events/event}Event":
            # Single event
            yield self._parse_event_element(root, raw)
        elif root.tag == "Events":
            # Wrapper with multiple events
            for event_elem in root.findall("evt:Event", EVTX_NS):
                event_xml = ET.tostring(event_elem, encoding="unicode")
                yield self._parse_event_element(event_elem, event_xml)
        else:
            # Try finding Event elements anywhere
            events = root.findall(".//evt:Event", EVTX_NS)
            if not events:
                # Maybe no namespace
                events = root.findall(".//Event")
            for event_elem in events:
                event_xml = ET.tostring(event_elem, encoding="unicode")
                yield self._parse_event_element(event_elem, event_xml)

    def _parse_event_element(self, elem: ET.Element, raw_xml: str) -> ParsedEvent:
        """Parse an Event element into ParsedEvent.

        Args:
            elem: Event XML element.
            raw_xml: Raw XML string for this event.

        Returns:
            ParsedEvent with extracted fields.
        """
        # Extract System info
        system = elem.find("evt:System", EVTX_NS)
        if system is None:
            system = elem.find("System")

        event_id_elem = system.find("evt:EventID", EVTX_NS)
        if event_id_elem is None:
            event_id_elem = system.find("EventID")
        event_id = int(event_id_elem.text)

        time_created = system.find("evt:TimeCreated", EVTX_NS)
        if time_created is None:
            time_created = system.find("TimeCreated")
        timestamp_str = time_created.get("SystemTime")
        timestamp = self._parse_timestamp(timestamp_str)

        computer_elem = system.find("evt:Computer", EVTX_NS)
        if computer_elem is None:
            computer_elem = system.find("Computer")
        computer = computer_elem.text if computer_elem is not None else ""

        # Extract EventData
        event_data = {}
        event_data_elem = elem.find("evt:EventData", EVTX_NS)
        if event_data_elem is None:
            event_data_elem = elem.find("EventData")

        if event_data_elem is not None:
            for data in event_data_elem.findall("evt:Data", EVTX_NS):
                name = data.get("Name")
                value = data.text or ""
                if name:
                    event_data[name] = value
            # Also check without namespace
            for data in event_data_elem.findall("Data"):
                name = data.get("Name")
                value = data.text or ""
                if name:
                    event_data[name] = value

        return ParsedEvent(
            event_id=event_id,
            timestamp=timestamp,
            computer=computer,
            event_data=event_data,
            raw_xml=raw_xml,
        )

    def _parse_timestamp(self, timestamp_str: str) -> datetime:
        """Parse Windows timestamp to UTC datetime.

        Args:
            timestamp_str: ISO format timestamp string.

        Returns:
            datetime in UTC.

        Raises:
            ValueError: If timestamp cannot be parsed.
        """
        if not timestamp_str:
            raise ValueError("Empty timestamp")

        # Handle various timestamp formats
        # Format: 2025-02-04T14:30:00.000Z or 2025-02-04T14:30:00Z
        timestamp_str = timestamp_str.rstrip("Z")

        # Try with microseconds
        try:
            return datetime.fromisoformat(timestamp_str)
        except ValueError:
            pass

        # Try without microseconds
        try:
            return datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S")
        except ValueError:
            pass

        # Try with milliseconds
        try:
            return datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S.%f")
        except ValueError:
            pass

        raise ValueError(f"Cannot parse timestamp: {timestamp_str}")

    def _extract_facts(
        self, parsed: ParsedEvent, source_ref: str
    ) -> list[Fact]:
        """Extract Facts from parsed event.

        Args:
            parsed: Parsed event data.
            source_ref: Source reference for provenance.

        Returns:
            List of Facts extracted from the event.
        """
        if parsed.event_id == 4624:
            return self._extract_4624_facts(parsed, source_ref)
        elif parsed.event_id == 4672:
            return self._extract_4672_facts(parsed, source_ref)
        elif parsed.event_id == 4688:
            return self._extract_4688_facts(parsed, source_ref)
        else:
            return []

    def _make_provenance(
        self, source_ref: str, raw_reference: str
    ) -> Provenance:
        """Create provenance for a fact.

        Args:
            source_ref: Data source reference.
            raw_reference: Reference within the source (event ID, line, etc.).

        Returns:
            Provenance instance.
        """
        return Provenance(
            source_type=SourceType.AUTH_LOG,
            source_id=source_ref,
            parser_version=self.VERSION,
            raw_reference=raw_reference,
        )

    def _truncate_field(self, value: str, max_size: int = MAX_FIELD_SIZE) -> str:
        """Truncate field value to max size.

        Args:
            value: Field value.
            max_size: Maximum size in bytes.

        Returns:
            Truncated value.
        """
        if len(value.encode("utf-8")) <= max_size:
            return value
        # Truncate by characters, checking byte size
        while len(value.encode("utf-8")) > max_size:
            value = value[:-1]
        return value

    def _make_fact(
        self,
        fact_id: str,
        entity_id: str,
        field: str,
        value: any,
        timestamp: datetime,
        provenance: Provenance,
    ) -> Fact:
        """Create a fact with size validation.

        Args:
            fact_id: Unique fact identifier.
            entity_id: Entity this fact describes.
            field: Field name.
            value: Field value.
            timestamp: When fact was observed.
            provenance: Source provenance.

        Returns:
            Fact instance.

        Raises:
            ValueError: If value exceeds size limits.
        """
        # Truncate string values
        if isinstance(value, str):
            max_size = MAX_COMMAND_LINE_SIZE if field == "command_line" else MAX_FIELD_SIZE
            if len(value.encode("utf-8")) > max_size:
                value = self._truncate_field(value, max_size)

        return Fact(
            fact_id=fact_id,
            entity_id=entity_id,
            entity_type=EntityType.NODE,
            field=field,
            value=value,
            timestamp=timestamp,
            provenance=provenance,
        )

    def _extract_4624_facts(
        self, parsed: ParsedEvent, source_ref: str
    ) -> list[Fact]:
        """Extract facts from 4624 (logon) event.

        Facts emitted:
            - logon_type: Type of logon (interactive, network, etc.)
            - logon_time: When the logon occurred
            - source_ip: Remote IP address (if applicable)
            - workstation: Source workstation name
            - target_username: User who logged on
            - domain: User's domain

        Args:
            parsed: Parsed 4624 event.
            source_ref: Source reference.

        Returns:
            List of Facts for this logon event.
        """
        facts = []
        data = parsed.event_data

        # Get required fields
        username = data.get("TargetUserName", "")
        domain = data.get("TargetDomainName", "")

        if not username:
            raise ValueError("Missing TargetUserName in 4624 event")

        # Build entity ID
        entity_id = f"user:{username}@{domain}"
        base_fact_id = f"4624-{parsed.timestamp.isoformat()}-{username}"
        provenance = self._make_provenance(source_ref, f"event_id=4624")

        # Logon type
        logon_type_raw = data.get("LogonType", "")
        logon_type = LOGON_TYPES.get(logon_type_raw, f"type_{logon_type_raw}")
        facts.append(self._make_fact(
            fact_id=f"{base_fact_id}-logon_type",
            entity_id=entity_id,
            field="logon_type",
            value=logon_type,
            timestamp=parsed.timestamp,
            provenance=provenance,
        ))

        # Logon time
        facts.append(self._make_fact(
            fact_id=f"{base_fact_id}-logon_time",
            entity_id=entity_id,
            field="logon_time",
            value=parsed.timestamp.isoformat() + "Z",
            timestamp=parsed.timestamp,
            provenance=provenance,
        ))

        # Source IP (if present and not empty/dash)
        source_ip = data.get("IpAddress", "")
        if source_ip and source_ip != "-":
            facts.append(self._make_fact(
                fact_id=f"{base_fact_id}-source_ip",
                entity_id=entity_id,
                field="source_ip",
                value=source_ip,
                timestamp=parsed.timestamp,
                provenance=provenance,
            ))

        # Workstation (if present)
        workstation = data.get("WorkstationName", "")
        if workstation and workstation != "-":
            facts.append(self._make_fact(
                fact_id=f"{base_fact_id}-workstation",
                entity_id=entity_id,
                field="workstation",
                value=workstation,
                timestamp=parsed.timestamp,
                provenance=provenance,
            ))

        # Target username (denormalized for easier querying)
        facts.append(self._make_fact(
            fact_id=f"{base_fact_id}-target_username",
            entity_id=entity_id,
            field="target_username",
            value=username,
            timestamp=parsed.timestamp,
            provenance=provenance,
        ))

        # Domain
        if domain:
            facts.append(self._make_fact(
                fact_id=f"{base_fact_id}-domain",
                entity_id=entity_id,
                field="domain",
                value=domain,
                timestamp=parsed.timestamp,
                provenance=provenance,
            ))

        return facts

    def _extract_4672_facts(
        self, parsed: ParsedEvent, source_ref: str
    ) -> list[Fact]:
        """Extract facts from 4672 (special privileges assigned) event.

        Facts emitted:
            - privilege_level: "ADMIN" if sensitive privileges assigned
            - privileges_assigned: List of privileges

        Args:
            parsed: Parsed 4672 event.
            source_ref: Source reference.

        Returns:
            List of Facts for this privilege event.
        """
        facts = []
        data = parsed.event_data

        username = data.get("SubjectUserName", "")
        domain = data.get("SubjectDomainName", "")

        if not username:
            raise ValueError("Missing SubjectUserName in 4672 event")

        entity_id = f"user:{username}@{domain}"
        base_fact_id = f"4672-{parsed.timestamp.isoformat()}-{username}"
        provenance = self._make_provenance(source_ref, f"event_id=4672")

        # Parse privilege list
        privilege_list_raw = data.get("PrivilegeList", "")
        privileges = [
            p.strip() for p in re.split(r"[\n\t]+", privilege_list_raw) if p.strip()
        ]

        # Determine if admin-level privileges
        admin_privileges = {
            "SeDebugPrivilege",
            "SeBackupPrivilege",
            "SeRestorePrivilege",
            "SeTakeOwnershipPrivilege",
            "SeLoadDriverPrivilege",
            "SeImpersonatePrivilege",
            "SeAssignPrimaryTokenPrivilege",
            "SeTcbPrivilege",
        }
        has_admin = bool(set(privileges) & admin_privileges)

        # Privilege level
        facts.append(self._make_fact(
            fact_id=f"{base_fact_id}-privilege_level",
            entity_id=entity_id,
            field="privilege_level",
            value="ADMIN" if has_admin else "STANDARD",
            timestamp=parsed.timestamp,
            provenance=provenance,
        ))

        # Privileges assigned
        facts.append(self._make_fact(
            fact_id=f"{base_fact_id}-privileges_assigned",
            entity_id=entity_id,
            field="privileges_assigned",
            value=privileges,
            timestamp=parsed.timestamp,
            provenance=provenance,
        ))

        return facts

    def _extract_4688_facts(
        self, parsed: ParsedEvent, source_ref: str
    ) -> list[Fact]:
        """Extract facts from 4688 (process creation) event.

        Facts emitted:
            - process_name: Name of the new process
            - parent_name: Name of the parent process
            - command_line: Full command line
            - user: User who started the process

        Args:
            parsed: Parsed 4688 event.
            source_ref: Source reference.

        Returns:
            List of Facts for this process event.
        """
        facts = []
        data = parsed.event_data

        # Get process ID for entity
        new_process_id = data.get("NewProcessId", "")
        process_name_full = data.get("NewProcessName", "")

        if not process_name_full:
            raise ValueError("Missing NewProcessName in 4688 event")

        # Extract just the executable name
        process_name = process_name_full.split("\\")[-1]

        entity_id = f"process:{new_process_id}"
        base_fact_id = f"4688-{parsed.timestamp.isoformat()}-{new_process_id}"

        # Use PROCESS_LIST source type for process events
        provenance = Provenance(
            source_type=SourceType.PROCESS_LIST,
            source_id=source_ref,
            parser_version=self.VERSION,
            raw_reference=f"event_id=4688",
        )

        # Process name
        facts.append(self._make_fact(
            fact_id=f"{base_fact_id}-name",
            entity_id=entity_id,
            field="process_name",
            value=process_name,
            timestamp=parsed.timestamp,
            provenance=provenance,
        ))

        # Full path
        facts.append(self._make_fact(
            fact_id=f"{base_fact_id}-path",
            entity_id=entity_id,
            field="process_path",
            value=process_name_full,
            timestamp=parsed.timestamp,
            provenance=provenance,
        ))

        # Parent process
        parent_name_full = data.get("ParentProcessName", "")
        if parent_name_full:
            parent_name = parent_name_full.split("\\")[-1]
            facts.append(self._make_fact(
                fact_id=f"{base_fact_id}-parent_name",
                entity_id=entity_id,
                field="parent_name",
                value=parent_name,
                timestamp=parsed.timestamp,
                provenance=provenance,
            ))
            facts.append(self._make_fact(
                fact_id=f"{base_fact_id}-parent_path",
                entity_id=entity_id,
                field="parent_path",
                value=parent_name_full,
                timestamp=parsed.timestamp,
                provenance=provenance,
            ))

        # Command line
        command_line = data.get("CommandLine", "")
        if command_line:
            facts.append(self._make_fact(
                fact_id=f"{base_fact_id}-command_line",
                entity_id=entity_id,
                field="command_line",
                value=command_line,
                timestamp=parsed.timestamp,
                provenance=provenance,
            ))

        # User who started the process
        username = data.get("SubjectUserName", "")
        domain = data.get("SubjectDomainName", "")
        if username:
            facts.append(self._make_fact(
                fact_id=f"{base_fact_id}-user",
                entity_id=entity_id,
                field="user",
                value=f"{domain}\\{username}" if domain else username,
                timestamp=parsed.timestamp,
                provenance=provenance,
            ))

        return facts
