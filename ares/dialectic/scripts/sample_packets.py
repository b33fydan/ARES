"""Sample EvidencePackets for live testing and diagnostics.

Each function returns a frozen EvidencePacket representing a specific
attack scenario with Windows security event telemetry.
"""

from __future__ import annotations

from datetime import datetime

from ares.dialectic.evidence.extractors.windows import WindowsEventExtractor
from ares.dialectic.evidence.fact import EntityType, Fact
from ares.dialectic.evidence.packet import EvidencePacket, TimeWindow
from ares.dialectic.evidence.provenance import Provenance, SourceType


# =============================================================================
# XML Event Templates
# =============================================================================

_4624_TEMPLATE = """\
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>4624</EventID>
    <TimeCreated SystemTime="{timestamp}"/>
    <Computer>{computer}</Computer>
  </System>
  <EventData>
    <Data Name="TargetUserName">{username}</Data>
    <Data Name="TargetDomainName">{domain}</Data>
    <Data Name="LogonType">{logon_type}</Data>
    <Data Name="IpAddress">{ip_address}</Data>
    <Data Name="WorkstationName">{workstation}</Data>
  </EventData>
</Event>"""

_4672_TEMPLATE = """\
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>4672</EventID>
    <TimeCreated SystemTime="{timestamp}"/>
    <Computer>{computer}</Computer>
  </System>
  <EventData>
    <Data Name="SubjectUserName">{username}</Data>
    <Data Name="SubjectDomainName">{domain}</Data>
    <Data Name="PrivilegeList">{privileges}</Data>
  </EventData>
</Event>"""

_4688_TEMPLATE = """\
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>4688</EventID>
    <TimeCreated SystemTime="{timestamp}"/>
    <Computer>{computer}</Computer>
  </System>
  <EventData>
    <Data Name="NewProcessId">0x{pid}</Data>
    <Data Name="NewProcessName">{process_path}</Data>
    <Data Name="ParentProcessName">{parent_path}</Data>
    <Data Name="CommandLine">{command_line}</Data>
    <Data Name="SubjectUserName">{username}</Data>
    <Data Name="SubjectDomainName">{domain}</Data>
  </EventData>
</Event>"""


def _extract_facts_from_xml(xml: str, source_ref: str) -> tuple:
    """Extract facts from a single XML event."""
    extractor = WindowsEventExtractor()
    result = extractor.extract(xml, source_ref=source_ref)
    return result.facts


def build_privilege_escalation_packet() -> EvidencePacket:
    """Scenario: User escalates from standard to admin privileges.

    Events:
    - 4624: Type 10 (RemoteInteractive) logon from unusual workstation
    - 4672: Special privileges (SeDebugPrivilege, SeTcbPrivilege) assigned
    - 4688: cmd.exe spawned by unexpected parent process

    Expected: Architect should detect PRIVILEGE_ESCALATION + SUSPICIOUS_PROCESS
    Expected: Skeptic might counter with KNOWN_ADMIN or MAINTENANCE_WINDOW
    """
    packet = EvidencePacket(
        packet_id="priv-esc-001",
        time_window=TimeWindow(
            start=datetime(2024, 3, 15, 2, 0, 0),
            end=datetime(2024, 3, 15, 3, 0, 0),
        ),
    )

    # Event 4624: RemoteInteractive logon from unusual workstation
    xml_4624 = _4624_TEMPLATE.format(
        timestamp="2024-03-15T02:15:00.000Z",
        computer="WORKSTATION-42",
        username="jdoe",
        domain="CORP",
        logon_type="10",
        ip_address="10.0.99.13",
        workstation="UNKNOWN-PC",
    )
    for fact in _extract_facts_from_xml(xml_4624, "security-log-001"):
        packet.add_fact(fact)

    # Event 4672: Admin privileges assigned
    xml_4672 = _4672_TEMPLATE.format(
        timestamp="2024-03-15T02:15:01.000Z",
        computer="WORKSTATION-42",
        username="jdoe",
        domain="CORP",
        privileges="SeDebugPrivilege\n\t\tSeTcbPrivilege\n\t\tSeBackupPrivilege",
    )
    for fact in _extract_facts_from_xml(xml_4672, "security-log-001"):
        packet.add_fact(fact)

    # Event 4688: cmd.exe spawned from explorer.exe
    xml_4688 = _4688_TEMPLATE.format(
        timestamp="2024-03-15T02:16:00.000Z",
        computer="WORKSTATION-42",
        pid="1a2b",
        process_path="C:\\Windows\\System32\\cmd.exe",
        parent_path="C:\\Windows\\explorer.exe",
        command_line="cmd.exe /c whoami /priv",
        username="jdoe",
        domain="CORP",
    )
    for fact in _extract_facts_from_xml(xml_4688, "security-log-001"):
        packet.add_fact(fact)

    packet.freeze()
    return packet


def build_lateral_movement_packet() -> EvidencePacket:
    """Scenario: Attacker moves between workstations using stolen credentials.

    Events:
    - 4624: Type 3 (Network) logon from workstation not in usual pattern
    - 4624: Same user, different workstation, within short time window
    - 4672: Admin privileges on target workstation

    Expected: Architect should detect LATERAL_MOVEMENT
    Expected: Skeptic might counter with LEGITIMATE_REMOTE
    """
    packet = EvidencePacket(
        packet_id="lateral-001",
        time_window=TimeWindow(
            start=datetime(2024, 3, 15, 14, 0, 0),
            end=datetime(2024, 3, 15, 15, 0, 0),
        ),
    )

    # First logon: network logon from workstation A
    xml_4624_a = _4624_TEMPLATE.format(
        timestamp="2024-03-15T14:10:00.000Z",
        computer="SERVER-DB01",
        username="svc_admin",
        domain="CORP",
        logon_type="3",
        ip_address="10.0.1.50",
        workstation="WORKSTATION-A",
    )
    for fact in _extract_facts_from_xml(xml_4624_a, "security-log-db01"):
        packet.add_fact(fact)

    # Second logon: network logon from workstation B, 2 minutes later
    xml_4624_b = _4624_TEMPLATE.format(
        timestamp="2024-03-15T14:12:00.000Z",
        computer="SERVER-FILE01",
        username="svc_admin",
        domain="CORP",
        logon_type="3",
        ip_address="10.0.1.51",
        workstation="WORKSTATION-B",
    )
    for fact in _extract_facts_from_xml(xml_4624_b, "security-log-file01"):
        packet.add_fact(fact)

    # Admin privileges on target
    xml_4672 = _4672_TEMPLATE.format(
        timestamp="2024-03-15T14:12:01.000Z",
        computer="SERVER-FILE01",
        username="svc_admin",
        domain="CORP",
        privileges="SeBackupPrivilege\n\t\tSeRestorePrivilege",
    )
    for fact in _extract_facts_from_xml(xml_4672, "security-log-file01"):
        packet.add_fact(fact)

    packet.freeze()
    return packet


def build_benign_admin_packet() -> EvidencePacket:
    """Scenario: Legitimate admin performs routine maintenance.

    Events:
    - 4624: Type 2 (Interactive) logon at known admin workstation
    - 4672: Standard admin privileges
    - 4688: Known maintenance tool execution

    Expected: Architect may detect patterns but low confidence
    Expected: Skeptic should counter with KNOWN_ADMIN + SCHEDULED_TASK
    Expected: Verdict should be THREAT_DISMISSED or INCONCLUSIVE
    """
    packet = EvidencePacket(
        packet_id="benign-admin-001",
        time_window=TimeWindow(
            start=datetime(2024, 3, 15, 9, 0, 0),
            end=datetime(2024, 3, 15, 10, 0, 0),
        ),
    )

    # Interactive logon at admin workstation
    xml_4624 = _4624_TEMPLATE.format(
        timestamp="2024-03-15T09:00:00.000Z",
        computer="ADMIN-WS-01",
        username="administrator",
        domain="CORP",
        logon_type="2",
        ip_address="-",
        workstation="ADMIN-WS-01",
    )
    for fact in _extract_facts_from_xml(xml_4624, "security-log-admin"):
        packet.add_fact(fact)

    # Standard admin privileges
    xml_4672 = _4672_TEMPLATE.format(
        timestamp="2024-03-15T09:00:01.000Z",
        computer="ADMIN-WS-01",
        username="administrator",
        domain="CORP",
        privileges="SeBackupPrivilege\n\t\tSeRestorePrivilege",
    )
    for fact in _extract_facts_from_xml(xml_4672, "security-log-admin"):
        packet.add_fact(fact)

    # Known maintenance tool
    xml_4688 = _4688_TEMPLATE.format(
        timestamp="2024-03-15T09:05:00.000Z",
        computer="ADMIN-WS-01",
        pid="2c3d",
        process_path="C:\\ProgramData\\Maintenance\\update_tool.exe",
        parent_path="C:\\Windows\\System32\\svchost.exe",
        command_line="update_tool.exe --scheduled --maintenance",
        username="administrator",
        domain="CORP",
    )
    for fact in _extract_facts_from_xml(xml_4688, "security-log-admin"):
        packet.add_fact(fact)

    packet.freeze()
    return packet
