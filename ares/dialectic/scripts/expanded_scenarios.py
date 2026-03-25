"""Expanded benchmark corpus — SC-019 through SC-033.

Session 021: 15 new scenarios expanding the corpus from 18 to 33 total.
Weighted toward AMBIGUOUS tier (6 scenarios) since that is where selective
escalation will be tested. All five ambiguity categories covered:
dual-use tools, exfiltration ambiguity, credential patterns, timing
anomalies, and network scanning.

Tier distribution:
    CLEAR_THREAT (tier 1):  2 new  (SC-019, SC-020)
    CLEAR_BENIGN (tier 3):  3 new  (SC-021, SC-022, SC-023)
    AMBIGUOUS (tier 2):     6 new  (SC-024, SC-025, SC-026, SC-027, SC-028, SC-029)
    MIXED_SIGNALS (tier 4): 4 new  (SC-030, SC-031, SC-032, SC-033)

Public API:
    get_expanded_scenarios()  -> tuple of 15 BenchmarkScenarios
    get_full_corpus()         -> tuple of all 33 BenchmarkScenarios
    get_expanded_scenario_by_id() -> single scenario by ID
"""

from __future__ import annotations

from datetime import datetime

from ares.dialectic.evidence.fact import EntityType, Fact
from ares.dialectic.evidence.packet import EvidencePacket, TimeWindow
from ares.dialectic.evidence.provenance import Provenance, SourceType
from ares.dialectic.scripts.mixed_source_scenarios import (
    get_combined_corpus as _get_18_corpus,
)
from ares.dialectic.scripts.scenario_corpus import (
    BenchmarkScenario,
    ScenarioMetadata,
)


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


def _build_packet(prefix: str, label: str, start: datetime, end: datetime,
                  facts: list) -> EvidencePacket:
    """Build and freeze a packet from a list of facts."""
    packet = EvidencePacket(
        packet_id=f"{prefix}-{label}",
        time_window=TimeWindow(start=start, end=end),
    )
    for f in facts:
        packet.add_fact(f)
    packet.freeze()
    return packet


# =============================================================================
# CLEAR_THREAT — Tier 1 (2 scenarios)
# =============================================================================


def build_sc019_ransomware_indicators() -> BenchmarkScenario:
    """SC-019: Ransomware deployment indicators.

    vssadmin delete shadows → bcdedit /set recovery disabled → mass file
    rename with .encrypted extension. Textbook ransomware preparation.
    """
    ts = datetime(2026, 3, 20, 3, 10, 0)
    p = "sc019"
    src = "fileserver01:Security:2026-03-20"

    facts = [
        _make_fact(p, 1, "proc-vss", EntityType.NODE, "process_name",
                   "vssadmin.exe", ts, SourceType.PROCESS_LIST, src),
        _make_fact(p, 2, "proc-vss", EntityType.NODE, "command_line",
                   "vssadmin delete shadows /all /quiet", ts,
                   SourceType.PROCESS_LIST, src),
        _make_fact(p, 3, "proc-bcdedit", EntityType.NODE, "process_name",
                   "bcdedit.exe", datetime(2026, 3, 20, 3, 10, 5),
                   SourceType.PROCESS_LIST, src),
        _make_fact(p, 4, "proc-bcdedit", EntityType.NODE, "command_line",
                   "bcdedit /set {default} recoveryenabled No",
                   datetime(2026, 3, 20, 3, 10, 5),
                   SourceType.PROCESS_LIST, src),
        _make_fact(p, 5, "file-rename-1", EntityType.NODE, "file_operation",
                   "rename: quarterly_report.xlsx -> quarterly_report.xlsx.encrypted",
                   datetime(2026, 3, 20, 3, 10, 10),
                   SourceType.PROCESS_LIST, src),
        _make_fact(p, 6, "file-rename-2", EntityType.NODE, "file_operation",
                   "rename: customer_db.sql -> customer_db.sql.encrypted",
                   datetime(2026, 3, 20, 3, 10, 11),
                   SourceType.PROCESS_LIST, src),
        _make_fact(p, 7, "ransom-note", EntityType.NODE, "file_operation",
                   "create: README_DECRYPT.txt in 47 directories",
                   datetime(2026, 3, 20, 3, 10, 15),
                   SourceType.PROCESS_LIST, src),
        _make_fact(p, 8, "user-context", EntityType.NODE, "logon_account",
                   "NT AUTHORITY\\SYSTEM", ts, SourceType.AUTH_LOG, src),
    ]

    packet = _build_packet(p, "ransomware", datetime(2026, 3, 20, 3, 0, 0),
                           datetime(2026, 3, 20, 4, 0, 0), facts)

    return BenchmarkScenario(
        metadata=ScenarioMetadata(
            scenario_id="SC-019",
            name="Ransomware Deployment",
            description="Shadow copy deletion, recovery disabled, mass file encryption",
            mitre_attack_ids=("T1490", "T1486"),
            mitre_tactic="Impact",
            difficulty_tier=1,
            expected_verdict="THREAT_CONFIRMED",
            expected_winner="ARCHITECT",
            fact_count=len(facts),
            notes="Clear threat — textbook ransomware preparation chain",
        ),
        packet=packet,
    )


def build_sc020_c2_beaconing() -> BenchmarkScenario:
    """SC-020: C2 beaconing pattern via NetFlow.

    Regular periodic outbound connections (60s intervals) to a single
    external IP with consistent small packet sizes — classic beacon behavior.
    """
    ts = datetime(2026, 3, 20, 8, 0, 0)
    p = "sc020"
    net_src = "router01:netflow:2026-03-20"
    proc_src = "ws-dev-05:Security:2026-03-20"

    facts = [
        _make_fact(p, 1, "flow-beacon-1", EntityType.EDGE, "network_connection",
                   "10.0.2.15:49152 -> 198.51.100.77:443/TCP (4 pkts, 256 bytes)",
                   ts, SourceType.NETFLOW, net_src),
        _make_fact(p, 2, "flow-beacon-2", EntityType.EDGE, "network_connection",
                   "10.0.2.15:49153 -> 198.51.100.77:443/TCP (4 pkts, 260 bytes)",
                   datetime(2026, 3, 20, 8, 1, 0), SourceType.NETFLOW, net_src),
        _make_fact(p, 3, "flow-beacon-3", EntityType.EDGE, "network_connection",
                   "10.0.2.15:49154 -> 198.51.100.77:443/TCP (4 pkts, 252 bytes)",
                   datetime(2026, 3, 20, 8, 2, 0), SourceType.NETFLOW, net_src),
        _make_fact(p, 4, "flow-beacon-4", EntityType.EDGE, "network_connection",
                   "10.0.2.15:49155 -> 198.51.100.77:443/TCP (4 pkts, 264 bytes)",
                   datetime(2026, 3, 20, 8, 3, 0), SourceType.NETFLOW, net_src),
        _make_fact(p, 5, "flow-beacon-5", EntityType.EDGE, "network_connection",
                   "10.0.2.15:49156 -> 198.51.100.77:443/TCP (4 pkts, 248 bytes)",
                   datetime(2026, 3, 20, 8, 4, 0), SourceType.NETFLOW, net_src),
        _make_fact(p, 6, "proc-rundll32", EntityType.NODE, "process_name",
                   "rundll32.exe", ts, SourceType.PROCESS_LIST, proc_src),
        _make_fact(p, 7, "proc-rundll32", EntityType.NODE, "command_line",
                   "rundll32.exe C:\\Users\\dev\\AppData\\Local\\Temp\\update.dll,Start",
                   ts, SourceType.PROCESS_LIST, proc_src),
        _make_fact(p, 8, "proc-rundll32", EntityType.NODE, "parent_process",
                   "explorer.exe", ts, SourceType.PROCESS_LIST, proc_src),
    ]

    packet = _build_packet(p, "c2-beacon", datetime(2026, 3, 20, 7, 55, 0),
                           datetime(2026, 3, 20, 8, 30, 0), facts)

    return BenchmarkScenario(
        metadata=ScenarioMetadata(
            scenario_id="SC-020",
            name="C2 Beaconing Pattern",
            description="Periodic outbound connections with consistent size, rundll32 loading temp DLL",
            mitre_attack_ids=("T1071", "T1573"),
            mitre_tactic="Command and Control",
            difficulty_tier=1,
            expected_verdict="THREAT_CONFIRMED",
            expected_winner="ARCHITECT",
            fact_count=len(facts),
            notes="Clear threat — regular beacon interval + suspicious rundll32 invocation",
        ),
        packet=packet,
    )


# =============================================================================
# CLEAR_BENIGN — Tier 3 (3 scenarios)
# =============================================================================


def build_sc021_scheduled_backup_transfer() -> BenchmarkScenario:
    """SC-021: Scheduled backup transfer that looks like exfiltration.

    Large outbound transfer at 2 AM to a known backup provider IP.
    The volume is high (2 GB) but the process is a signed backup agent.
    """
    ts = datetime(2026, 3, 20, 2, 0, 0)
    p = "sc021"
    net_src = "router01:netflow:2026-03-20"
    proc_src = "fileserver01:Security:2026-03-20"

    facts = [
        _make_fact(p, 1, "flow-backup-1", EntityType.EDGE, "network_connection",
                   "10.0.1.50:8443 -> 34.120.55.10:443/TCP (15000 pkts, 2147483648 bytes)",
                   ts, SourceType.NETFLOW, net_src),
        _make_fact(p, 2, "proc-backup", EntityType.NODE, "process_name",
                   "C:\\Program Files\\Veeam\\Backup\\VeeamAgent.exe",
                   ts, SourceType.PROCESS_LIST, proc_src),
        _make_fact(p, 3, "proc-backup", EntityType.NODE, "executable_signer",
                   "Veeam Software Group GmbH (verified)", ts,
                   SourceType.PROCESS_LIST, proc_src),
        _make_fact(p, 4, "sched-task", EntityType.NODE, "scheduled_task",
                   "VeeamNightlyBackup: runs daily at 02:00", ts,
                   SourceType.PROCESS_LIST, proc_src),
        _make_fact(p, 5, "flow-backup-2", EntityType.EDGE, "network_connection",
                   "10.0.1.50:8444 -> 34.120.55.10:443/TCP (500 pkts, 65536 bytes)",
                   datetime(2026, 3, 20, 2, 45, 0), SourceType.NETFLOW, net_src),
        _make_fact(p, 6, "log-success", EntityType.NODE, "backup_status",
                   "Backup job 'NightlyFull' completed successfully",
                   datetime(2026, 3, 20, 2, 50, 0), SourceType.SYSLOG, proc_src),
    ]

    packet = _build_packet(p, "backup-transfer", datetime(2026, 3, 20, 1, 55, 0),
                           datetime(2026, 3, 20, 3, 0, 0), facts)

    return BenchmarkScenario(
        metadata=ScenarioMetadata(
            scenario_id="SC-021",
            name="Scheduled Backup Transfer",
            description="Large 2AM outbound transfer by signed Veeam agent on schedule",
            mitre_attack_ids=("T1048",),
            mitre_tactic="Exfiltration",
            difficulty_tier=3,
            expected_verdict="THREAT_DISMISSED",
            expected_winner="SKEPTIC",
            fact_count=len(facts),
            notes="Clear benign — signed backup agent, scheduled task, known destination",
        ),
        packet=packet,
    )


def build_sc022_admin_psexec_patching() -> BenchmarkScenario:
    """SC-022: IT admin using PsExec for remote patching.

    PsExec from IT admin workstation to multiple servers during
    a documented change window. Looks like lateral movement but
    is authorized maintenance.
    """
    ts = datetime(2026, 3, 20, 22, 0, 0)
    p = "sc022"
    src = "ws-itadmin-01:Security:2026-03-20"
    syslog_src = "ticketsystem:syslog:2026-03-20"

    facts = [
        _make_fact(p, 1, "proc-psexec", EntityType.NODE, "process_name",
                   "PsExec.exe", ts, SourceType.PROCESS_LIST, src),
        _make_fact(p, 2, "proc-psexec", EntityType.NODE, "command_line",
                   "psexec \\\\srv-web-01 -u CORP\\svc-patch -p *** cmd /c wusa KB5034441.msu /quiet",
                   ts, SourceType.PROCESS_LIST, src),
        _make_fact(p, 3, "user-admin", EntityType.NODE, "logon_account",
                   "CORP\\j.martinez", ts, SourceType.AUTH_LOG, src),
        _make_fact(p, 4, "user-admin", EntityType.NODE, "group_membership",
                   "Domain Admins, IT-PatchManagement", ts,
                   SourceType.AUTH_LOG, src),
        _make_fact(p, 5, "change-ticket", EntityType.NODE, "change_request",
                   "CHG-2026-0342: Emergency patch KB5034441 deployment, window 22:00-02:00",
                   ts, SourceType.SYSLOG, syslog_src),
        _make_fact(p, 6, "proc-psexec-2", EntityType.NODE, "process_name",
                   "PsExec.exe", datetime(2026, 3, 20, 22, 5, 0),
                   SourceType.PROCESS_LIST, src),
        _make_fact(p, 7, "proc-psexec-2", EntityType.NODE, "command_line",
                   "psexec \\\\srv-db-01 -u CORP\\svc-patch -p *** cmd /c wusa KB5034441.msu /quiet",
                   datetime(2026, 3, 20, 22, 5, 0), SourceType.PROCESS_LIST, src),
    ]

    packet = _build_packet(p, "admin-psexec", datetime(2026, 3, 20, 21, 55, 0),
                           datetime(2026, 3, 20, 23, 0, 0), facts)

    return BenchmarkScenario(
        metadata=ScenarioMetadata(
            scenario_id="SC-022",
            name="Admin PsExec Patching",
            description="IT admin PsExec to multiple servers during change window with ticket",
            mitre_attack_ids=("T1570",),
            mitre_tactic="Lateral Movement",
            difficulty_tier=3,
            expected_verdict="THREAT_DISMISSED",
            expected_winner="SKEPTIC",
            fact_count=len(facts),
            notes="Clear benign — PsExec with change ticket, Domain Admin, patch deployment",
        ),
        packet=packet,
    )


def build_sc023_security_scanner_noise() -> BenchmarkScenario:
    """SC-023: Vulnerability scanner generating alert-like traffic.

    Nessus scanner running scheduled monthly scan. Generates port scans,
    failed auth attempts, and exploit probes — all from a known scanner IP.
    """
    ts = datetime(2026, 3, 20, 1, 0, 0)
    p = "sc023"
    net_src = "router01:netflow:2026-03-20"
    syslog_src = "nessus01:syslog:2026-03-20"

    facts = [
        _make_fact(p, 1, "flow-scan-1", EntityType.EDGE, "network_connection",
                   "10.0.0.200:44100 -> 10.0.1.0/24:22/TCP (SYN-only, 254 targets)",
                   ts, SourceType.NETFLOW, net_src),
        _make_fact(p, 2, "flow-scan-2", EntityType.EDGE, "network_connection",
                   "10.0.0.200:44200 -> 10.0.1.0/24:445/TCP (SYN-only, 254 targets)",
                   datetime(2026, 3, 20, 1, 2, 0), SourceType.NETFLOW, net_src),
        _make_fact(p, 3, "flow-scan-3", EntityType.EDGE, "network_connection",
                   "10.0.0.200:44300 -> 10.0.1.0/24:3389/TCP (SYN-only, 254 targets)",
                   datetime(2026, 3, 20, 1, 4, 0), SourceType.NETFLOW, net_src),
        _make_fact(p, 4, "scanner-identity", EntityType.NODE, "asset_tag",
                   "10.0.0.200 = nessus01.corp.local (Tenable Nessus Professional)",
                   ts, SourceType.SYSLOG, syslog_src),
        _make_fact(p, 5, "scan-schedule", EntityType.NODE, "scheduled_task",
                   "MonthlyVulnScan: first Sunday of month at 01:00",
                   ts, SourceType.SYSLOG, syslog_src),
        _make_fact(p, 6, "scan-auth-fail", EntityType.NODE, "event_type",
                   "ssh_failed", datetime(2026, 3, 20, 1, 5, 0),
                   SourceType.SYSLOG, syslog_src),
        _make_fact(p, 7, "scan-auth-fail", EntityType.NODE, "source_ip",
                   "10.0.0.200", datetime(2026, 3, 20, 1, 5, 0),
                   SourceType.SYSLOG, syslog_src),
    ]

    packet = _build_packet(p, "scanner-noise", datetime(2026, 3, 20, 0, 55, 0),
                           datetime(2026, 3, 20, 2, 0, 0), facts)

    return BenchmarkScenario(
        metadata=ScenarioMetadata(
            scenario_id="SC-023",
            name="Vulnerability Scanner Noise",
            description="Nessus monthly scan generating port scans and auth failures from known scanner",
            mitre_attack_ids=("T1046",),
            mitre_tactic="Discovery",
            difficulty_tier=3,
            expected_verdict="THREAT_DISMISSED",
            expected_winner="SKEPTIC",
            fact_count=len(facts),
            notes="Clear benign — all traffic from identified scanner on schedule",
        ),
        packet=packet,
    )


# =============================================================================
# AMBIGUOUS — Tier 2 (6 scenarios)
# =============================================================================


def build_sc024_dual_use_powershell() -> BenchmarkScenario:
    """SC-024: Dual-use PowerShell — admin or attacker?

    PowerShell with encoded command downloading a script from an internal
    server. Could be a sysadmin automation script or a living-off-the-land
    attack. No signed binary, no change ticket.
    """
    ts = datetime(2026, 3, 20, 14, 30, 0)
    p = "sc024"
    src = "ws-finance-07:Security:2026-03-20"

    facts = [
        _make_fact(p, 1, "proc-ps", EntityType.NODE, "process_name",
                   "powershell.exe", ts, SourceType.PROCESS_LIST, src),
        _make_fact(p, 2, "proc-ps", EntityType.NODE, "command_line",
                   "powershell -EncodedCommand SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAAaAB0AHQAcAA6AC8ALwBpAG4AdABlAHIAbgBhAGwALgBjAG8AcgBwAC4AbABvAGMAYQBsAC8AcwBjAHIAaQBwAHQAcwAvAGkAbgB2AGUAbgB0AG8AcgB5AC4AcABzADEA",
                   ts, SourceType.PROCESS_LIST, src),
        _make_fact(p, 3, "proc-ps", EntityType.NODE, "parent_process",
                   "explorer.exe", ts, SourceType.PROCESS_LIST, src),
        _make_fact(p, 4, "user-ctx", EntityType.NODE, "logon_account",
                   "CORP\\a.chen", ts, SourceType.AUTH_LOG, src),
        _make_fact(p, 5, "user-ctx", EntityType.NODE, "group_membership",
                   "Domain Users, Finance-Team", ts, SourceType.AUTH_LOG, src),
        _make_fact(p, 6, "decoded-cmd", EntityType.NODE, "decoded_command",
                   "Invoke-WebRequest http://internal.corp.local/scripts/inventory.ps1",
                   ts, SourceType.PROCESS_LIST, src),
    ]

    packet = _build_packet(p, "dual-use-ps", datetime(2026, 3, 20, 14, 25, 0),
                           datetime(2026, 3, 20, 15, 0, 0), facts)

    return BenchmarkScenario(
        metadata=ScenarioMetadata(
            scenario_id="SC-024",
            name="Dual-Use PowerShell (Encoded)",
            description="Encoded PowerShell downloading from internal server, non-admin user",
            mitre_attack_ids=("T1059.001",),
            mitre_tactic="Execution",
            difficulty_tier=2,
            expected_verdict="INCONCLUSIVE",
            expected_winner="BALANCED",
            fact_count=len(facts),
            notes="Ambiguous — encoded command is suspicious, but target is internal and script name benign",
        ),
        packet=packet,
    )


def build_sc025_exfiltration_ambiguity() -> BenchmarkScenario:
    """SC-025: Large cloud upload — backup or data theft?

    Large upload to a cloud storage endpoint at unusual hours from a
    developer workstation. No scheduled task, but developer accounts
    sometimes work late. Volume is unusually high.
    """
    ts = datetime(2026, 3, 20, 23, 15, 0)
    p = "sc025"
    net_src = "router01:netflow:2026-03-20"
    proc_src = "ws-dev-12:Security:2026-03-20"

    facts = [
        _make_fact(p, 1, "flow-upload", EntityType.EDGE, "network_connection",
                   "10.0.3.12:49200 -> 52.239.184.11:443/TCP (8500 pkts, 524288000 bytes)",
                   ts, SourceType.NETFLOW, net_src),
        _make_fact(p, 2, "proc-rclone", EntityType.NODE, "process_name",
                   "rclone.exe", ts, SourceType.PROCESS_LIST, proc_src),
        _make_fact(p, 3, "proc-rclone", EntityType.NODE, "command_line",
                   "rclone copy C:\\Projects\\client-data remote:backup-bucket",
                   ts, SourceType.PROCESS_LIST, proc_src),
        _make_fact(p, 4, "user-ctx", EntityType.NODE, "logon_account",
                   "CORP\\k.patel", ts, SourceType.AUTH_LOG, proc_src),
        _make_fact(p, 5, "user-ctx", EntityType.NODE, "group_membership",
                   "Domain Users, Dev-Team, Azure-Contributors", ts,
                   SourceType.AUTH_LOG, proc_src),
        _make_fact(p, 6, "dst-info", EntityType.NODE, "dns_resolution",
                   "52.239.184.11 -> blob.core.windows.net (Microsoft Azure)",
                   ts, SourceType.NETFLOW, net_src),
        _make_fact(p, 7, "time-ctx", EntityType.NODE, "logon_time",
                   "23:15 (outside normal hours 08:00-18:00)", ts,
                   SourceType.AUTH_LOG, proc_src),
    ]

    packet = _build_packet(p, "exfil-ambiguity", datetime(2026, 3, 20, 23, 10, 0),
                           datetime(2026, 3, 21, 0, 0, 0), facts)

    return BenchmarkScenario(
        metadata=ScenarioMetadata(
            scenario_id="SC-025",
            name="Cloud Upload Ambiguity",
            description="500MB rclone upload to Azure at 11 PM from developer workstation",
            mitre_attack_ids=("T1567",),
            mitre_tactic="Exfiltration",
            difficulty_tier=2,
            expected_verdict="INCONCLUSIVE",
            expected_winner="BALANCED",
            fact_count=len(facts),
            notes="Ambiguous — rclone to Azure is suspicious, but dev has Azure access and might be working late",
        ),
        packet=packet,
    )


def build_sc026_credential_pattern() -> BenchmarkScenario:
    """SC-026: Failed logins then success — brute force or forgot password?

    Five failed logins over 3 minutes followed by successful login.
    All from the same source IP (user's usual workstation). Pattern
    matches both brute force and legitimate password retry.
    """
    ts = datetime(2026, 3, 20, 9, 0, 0)
    p = "sc026"
    src = "dc01:Security:2026-03-20"

    facts = [
        _make_fact(p, 1, "fail-1", EntityType.NODE, "event_type",
                   "logon_failed (Event 4625)", ts, SourceType.AUTH_LOG, src),
        _make_fact(p, 2, "fail-1", EntityType.NODE, "target_account",
                   "CORP\\r.johnson", ts, SourceType.AUTH_LOG, src),
        _make_fact(p, 3, "fail-1", EntityType.NODE, "source_workstation",
                   "WS-RJOHNSON-01", ts, SourceType.AUTH_LOG, src),
        _make_fact(p, 4, "fail-2", EntityType.NODE, "event_type",
                   "logon_failed (Event 4625)", datetime(2026, 3, 20, 9, 0, 45),
                   SourceType.AUTH_LOG, src),
        _make_fact(p, 5, "fail-3", EntityType.NODE, "event_type",
                   "logon_failed (Event 4625)", datetime(2026, 3, 20, 9, 1, 30),
                   SourceType.AUTH_LOG, src),
        _make_fact(p, 6, "fail-4", EntityType.NODE, "event_type",
                   "logon_failed (Event 4625)", datetime(2026, 3, 20, 9, 2, 15),
                   SourceType.AUTH_LOG, src),
        _make_fact(p, 7, "fail-5", EntityType.NODE, "event_type",
                   "logon_failed (Event 4625)", datetime(2026, 3, 20, 9, 2, 50),
                   SourceType.AUTH_LOG, src),
        _make_fact(p, 8, "success", EntityType.NODE, "event_type",
                   "logon_success (Event 4624)", datetime(2026, 3, 20, 9, 3, 10),
                   SourceType.AUTH_LOG, src),
        _make_fact(p, 9, "success", EntityType.NODE, "logon_type",
                   "Interactive (Type 2)", datetime(2026, 3, 20, 9, 3, 10),
                   SourceType.AUTH_LOG, src),
    ]

    packet = _build_packet(p, "credential-pattern", datetime(2026, 3, 20, 8, 55, 0),
                           datetime(2026, 3, 20, 9, 15, 0), facts)

    return BenchmarkScenario(
        metadata=ScenarioMetadata(
            scenario_id="SC-026",
            name="Failed Logins Then Success",
            description="5 failed logins then success from user's own workstation",
            mitre_attack_ids=("T1110",),
            mitre_tactic="Credential Access",
            difficulty_tier=2,
            expected_verdict="INCONCLUSIVE",
            expected_winner="BALANCED",
            fact_count=len(facts),
            notes="Ambiguous — brute force vs forgotten password. Same source workstation suggests benign.",
        ),
        packet=packet,
    )


def build_sc027_timing_anomaly() -> BenchmarkScenario:
    """SC-027: After-hours VPN access — overseas employee or compromised account?

    VPN login at 3 AM local time from a foreign IP. User is a software
    engineer. No prior access from this geography. Could be travel,
    remote contractor, or account compromise.
    """
    ts = datetime(2026, 3, 20, 3, 0, 0)
    p = "sc027"
    vpn_src = "vpn01:syslog:2026-03-20"
    auth_src = "dc01:Security:2026-03-20"

    facts = [
        _make_fact(p, 1, "vpn-login", EntityType.NODE, "event_type",
                   "vpn_connected", ts, SourceType.SYSLOG, vpn_src),
        _make_fact(p, 2, "vpn-login", EntityType.NODE, "source_ip",
                   "103.245.67.89 (Singapore)", ts, SourceType.SYSLOG, vpn_src),
        _make_fact(p, 3, "vpn-login", EntityType.NODE, "vpn_user",
                   "CORP\\m.rodriguez", ts, SourceType.SYSLOG, vpn_src),
        _make_fact(p, 4, "auth-success", EntityType.NODE, "event_type",
                   "logon_success (Event 4624)", datetime(2026, 3, 20, 3, 0, 5),
                   SourceType.AUTH_LOG, auth_src),
        _make_fact(p, 5, "auth-success", EntityType.NODE, "logon_type",
                   "Network (Type 3)", datetime(2026, 3, 20, 3, 0, 5),
                   SourceType.AUTH_LOG, auth_src),
        _make_fact(p, 6, "user-profile", EntityType.NODE, "employee_location",
                   "Austin, TX (usual login hours: 08:00-18:00 CST)", ts,
                   SourceType.AUTH_LOG, auth_src),
        _make_fact(p, 7, "geo-history", EntityType.NODE, "geo_anomaly",
                   "No prior logins from AS9808 (Singapore) in 90 days", ts,
                   SourceType.SYSLOG, vpn_src),
    ]

    packet = _build_packet(p, "timing-anomaly", datetime(2026, 3, 20, 2, 55, 0),
                           datetime(2026, 3, 20, 4, 0, 0), facts)

    return BenchmarkScenario(
        metadata=ScenarioMetadata(
            scenario_id="SC-027",
            name="After-Hours Foreign VPN",
            description="3 AM VPN login from Singapore for Austin-based employee",
            mitre_attack_ids=("T1133",),
            mitre_tactic="Initial Access",
            difficulty_tier=2,
            expected_verdict="INCONCLUSIVE",
            expected_winner="BALANCED",
            fact_count=len(facts),
            notes="Ambiguous — could be travel, but no prior Singapore access. MFA passed implicitly.",
        ),
        packet=packet,
    )


def build_sc028_wmi_lateral_movement() -> BenchmarkScenario:
    """SC-028: WMI remote execution — admin tool or attacker technique?

    WMI used to execute a process on a remote server. Initiated by a
    service account from a management server. Could be legitimate SCCM
    action or attacker using WMI for lateral movement.
    """
    ts = datetime(2026, 3, 20, 11, 0, 0)
    p = "sc028"
    src = "mgmt-srv-01:Security:2026-03-20"

    facts = [
        _make_fact(p, 1, "wmi-exec", EntityType.NODE, "process_name",
                   "wmiprvse.exe", ts, SourceType.PROCESS_LIST, src),
        _make_fact(p, 2, "wmi-exec", EntityType.NODE, "command_line",
                   "wmic /node:srv-app-03 process call create \"cmd /c systeminfo > C:\\temp\\info.txt\"",
                   ts, SourceType.PROCESS_LIST, src),
        _make_fact(p, 3, "wmi-user", EntityType.NODE, "logon_account",
                   "CORP\\svc-sccm", ts, SourceType.AUTH_LOG, src),
        _make_fact(p, 4, "wmi-user", EntityType.NODE, "logon_type",
                   "Network (Type 3)", ts, SourceType.AUTH_LOG, src),
        _make_fact(p, 5, "target-info", EntityType.NODE, "target_host",
                   "srv-app-03.corp.local (Application Server)", ts,
                   SourceType.PROCESS_LIST, src),
        _make_fact(p, 6, "output-file", EntityType.NODE, "file_operation",
                   "create: C:\\temp\\info.txt on srv-app-03",
                   datetime(2026, 3, 20, 11, 0, 3), SourceType.PROCESS_LIST, src),
    ]

    packet = _build_packet(p, "wmi-lateral", datetime(2026, 3, 20, 10, 55, 0),
                           datetime(2026, 3, 20, 11, 30, 0), facts)

    return BenchmarkScenario(
        metadata=ScenarioMetadata(
            scenario_id="SC-028",
            name="WMI Remote Execution",
            description="WMI process creation on remote server via service account",
            mitre_attack_ids=("T1047",),
            mitre_tactic="Execution",
            difficulty_tier=2,
            expected_verdict="INCONCLUSIVE",
            expected_winner="BALANCED",
            fact_count=len(facts),
            notes="Ambiguous — WMI from SCCM service account is normal, but systeminfo to temp is recon-like",
        ),
        packet=packet,
    )


def build_sc029_port_scan_ambiguity() -> BenchmarkScenario:
    """SC-029: Internal port scanning — asset discovery or recon?

    Sequential port scan from a workstation across an internal subnet.
    The user is in the Network Engineering group. No scanner tool
    identity. Could be nmap for inventory or attacker reconnaissance.
    """
    ts = datetime(2026, 3, 20, 15, 0, 0)
    p = "sc029"
    net_src = "router01:netflow:2026-03-20"
    auth_src = "dc01:Security:2026-03-20"

    facts = [
        _make_fact(p, 1, "scan-1", EntityType.EDGE, "network_connection",
                   "10.0.2.25:51000 -> 10.0.4.1:22/TCP (SYN-only, 1 pkt)",
                   ts, SourceType.NETFLOW, net_src),
        _make_fact(p, 2, "scan-2", EntityType.EDGE, "network_connection",
                   "10.0.2.25:51001 -> 10.0.4.1:80/TCP (SYN-only, 1 pkt)",
                   datetime(2026, 3, 20, 15, 0, 1), SourceType.NETFLOW, net_src),
        _make_fact(p, 3, "scan-3", EntityType.EDGE, "network_connection",
                   "10.0.2.25:51002 -> 10.0.4.1:443/TCP (SYN-only, 1 pkt)",
                   datetime(2026, 3, 20, 15, 0, 2), SourceType.NETFLOW, net_src),
        _make_fact(p, 4, "scan-4", EntityType.EDGE, "network_connection",
                   "10.0.2.25:51003 -> 10.0.4.2:22/TCP (SYN-only, 1 pkt)",
                   datetime(2026, 3, 20, 15, 0, 3), SourceType.NETFLOW, net_src),
        _make_fact(p, 5, "scan-5", EntityType.EDGE, "network_connection",
                   "10.0.2.25:51004 -> 10.0.4.2:445/TCP (SYN-only, 1 pkt)",
                   datetime(2026, 3, 20, 15, 0, 4), SourceType.NETFLOW, net_src),
        _make_fact(p, 6, "user-ctx", EntityType.NODE, "logon_account",
                   "CORP\\t.nguyen", ts, SourceType.AUTH_LOG, auth_src),
        _make_fact(p, 7, "user-ctx", EntityType.NODE, "group_membership",
                   "Domain Users, Network-Engineering", ts,
                   SourceType.AUTH_LOG, auth_src),
        _make_fact(p, 8, "proc-nmap", EntityType.NODE, "process_name",
                   "nmap.exe", ts, SourceType.PROCESS_LIST, auth_src),
    ]

    packet = _build_packet(p, "port-scan-ambig", datetime(2026, 3, 20, 14, 55, 0),
                           datetime(2026, 3, 20, 15, 30, 0), facts)

    return BenchmarkScenario(
        metadata=ScenarioMetadata(
            scenario_id="SC-029",
            name="Internal Port Scan Ambiguity",
            description="nmap scan from Network Engineering workstation, no scanner identity",
            mitre_attack_ids=("T1046",),
            mitre_tactic="Discovery",
            difficulty_tier=2,
            expected_verdict="INCONCLUSIVE",
            expected_winner="BALANCED",
            fact_count=len(facts),
            notes="Ambiguous — Network Engineer may scan legitimately, but no ticket or tool identity",
        ),
        packet=packet,
    )


# =============================================================================
# MIXED_SIGNALS — Tier 4 (4 scenarios)
# =============================================================================


def build_sc030_conflicting_dns_netflow() -> BenchmarkScenario:
    """SC-030: DNS indicates malware, NetFlow shows normal volume.

    DNS queries to a known DGA domain pattern, but NetFlow shows only
    minimal traffic to the resolved IP. Syslog shows the workstation is
    running an up-to-date AV.
    """
    ts = datetime(2026, 3, 20, 10, 0, 0)
    p = "sc030"
    syslog_src = "dns01:syslog:2026-03-20"
    net_src = "router01:netflow:2026-03-20"
    proc_src = "ws-hr-02:Security:2026-03-20"

    facts = [
        _make_fact(p, 1, "dns-query-1", EntityType.NODE, "dns_query",
                   "xk7m2p9q.baddomain.top (A record)", ts,
                   SourceType.SYSLOG, syslog_src),
        _make_fact(p, 2, "dns-query-2", EntityType.NODE, "dns_query",
                   "j3n8r5w1.baddomain.top (A record)",
                   datetime(2026, 3, 20, 10, 5, 0), SourceType.SYSLOG, syslog_src),
        _make_fact(p, 3, "dns-query-3", EntityType.NODE, "dns_query",
                   "v6t4k8y2.baddomain.top (NXDOMAIN response)",
                   datetime(2026, 3, 20, 10, 10, 0), SourceType.SYSLOG, syslog_src),
        _make_fact(p, 4, "flow-minimal", EntityType.EDGE, "network_connection",
                   "10.0.1.22:49300 -> 185.220.101.5:80/TCP (2 pkts, 128 bytes, RST)",
                   datetime(2026, 3, 20, 10, 0, 1), SourceType.NETFLOW, net_src),
        _make_fact(p, 5, "av-status", EntityType.NODE, "endpoint_protection",
                   "CrowdStrike Falcon: running, definitions current, no detections",
                   ts, SourceType.PROCESS_LIST, proc_src),
        _make_fact(p, 6, "dns-source", EntityType.NODE, "source_host",
                   "10.0.1.22 = ws-hr-02.corp.local", ts,
                   SourceType.SYSLOG, syslog_src),
    ]

    packet = _build_packet(p, "dns-netflow-conflict", datetime(2026, 3, 20, 9, 55, 0),
                           datetime(2026, 3, 20, 10, 30, 0), facts)

    return BenchmarkScenario(
        metadata=ScenarioMetadata(
            scenario_id="SC-030",
            name="DGA DNS with Minimal Traffic",
            description="DGA-like DNS queries but minimal NetFlow traffic and clean AV",
            mitre_attack_ids=("T1568.002",),
            mitre_tactic="Command and Control",
            difficulty_tier=4,
            expected_verdict="INCONCLUSIVE",
            expected_winner="BALANCED",
            fact_count=len(facts),
            notes="Mixed signals — DGA patterns are suspicious, but RST + clean AV suggests blocked or false positive",
        ),
        packet=packet,
    )


def build_sc031_syslog_threat_netflow_benign() -> BenchmarkScenario:
    """SC-031: Syslog shows sudo abuse, NetFlow shows no exfiltration.

    Syslog captures unauthorized sudo to root on a web server, but
    NetFlow shows only normal HTTP traffic — no outbound data transfer.
    The sudo user is a web developer with occasional sudo needs.
    """
    ts = datetime(2026, 3, 20, 16, 0, 0)
    p = "sc031"
    syslog_src = "webserver02:syslog:2026-03-20"
    net_src = "router01:netflow:2026-03-20"

    facts = [
        _make_fact(p, 1, "sudo-root", EntityType.NODE, "event_type",
                   "sudo_success", ts, SourceType.SYSLOG, syslog_src),
        _make_fact(p, 2, "sudo-root", EntityType.NODE, "sudo_command",
                   "cat /etc/shadow", ts, SourceType.SYSLOG, syslog_src),
        _make_fact(p, 3, "sudo-root", EntityType.NODE, "sudo_user",
                   "webdev01", ts, SourceType.SYSLOG, syslog_src),
        _make_fact(p, 4, "sudo-root-2", EntityType.NODE, "event_type",
                   "sudo_success", datetime(2026, 3, 20, 16, 1, 0),
                   SourceType.SYSLOG, syslog_src),
        _make_fact(p, 5, "sudo-root-2", EntityType.NODE, "sudo_command",
                   "cat /etc/passwd", datetime(2026, 3, 20, 16, 1, 0),
                   SourceType.SYSLOG, syslog_src),
        _make_fact(p, 6, "flow-normal", EntityType.EDGE, "network_connection",
                   "10.0.5.20:80 -> various:*/TCP (normal HTTP serving, 2000 pkts/min avg)",
                   ts, SourceType.NETFLOW, net_src),
        _make_fact(p, 7, "flow-no-exfil", EntityType.EDGE, "network_connection",
                   "10.0.5.20:* -> external:*/TCP (0 outbound connections outside HTTP)",
                   ts, SourceType.NETFLOW, net_src),
    ]

    packet = _build_packet(p, "sudo-no-exfil", datetime(2026, 3, 20, 15, 55, 0),
                           datetime(2026, 3, 20, 16, 30, 0), facts)

    return BenchmarkScenario(
        metadata=ScenarioMetadata(
            scenario_id="SC-031",
            name="Sudo Abuse Without Exfiltration",
            description="Unauthorized sudo to read /etc/shadow but no outbound data transfer",
            mitre_attack_ids=("T1003.008", "T1548.003"),
            mitre_tactic="Credential Access",
            difficulty_tier=4,
            expected_verdict="THREAT_CONFIRMED",
            expected_winner="ARCHITECT",
            fact_count=len(facts),
            notes="Mixed signals — reading /etc/shadow is credential access regardless of exfiltration",
        ),
        packet=packet,
    )


def build_sc032_auth_threat_process_benign() -> BenchmarkScenario:
    """SC-032: Auth logs show impossible travel, processes look normal.

    User logs in from New York and London within 30 minutes (impossible
    travel). But all processes running on the London session are normal
    Office apps — no recon, no tools, no lateral movement.
    """
    ts = datetime(2026, 3, 20, 14, 0, 0)
    p = "sc032"
    auth_src = "dc01:Security:2026-03-20"
    proc_src = "ws-remote-uk:Security:2026-03-20"

    facts = [
        _make_fact(p, 1, "login-ny", EntityType.NODE, "event_type",
                   "logon_success (Event 4624)", ts, SourceType.AUTH_LOG, auth_src),
        _make_fact(p, 2, "login-ny", EntityType.NODE, "source_ip",
                   "74.125.23.100 (New York, US)", ts, SourceType.AUTH_LOG, auth_src),
        _make_fact(p, 3, "login-ny", EntityType.NODE, "logon_account",
                   "CORP\\s.williams", ts, SourceType.AUTH_LOG, auth_src),
        _make_fact(p, 4, "login-uk", EntityType.NODE, "event_type",
                   "logon_success (Event 4624)", datetime(2026, 3, 20, 14, 25, 0),
                   SourceType.AUTH_LOG, auth_src),
        _make_fact(p, 5, "login-uk", EntityType.NODE, "source_ip",
                   "81.2.69.142 (London, UK)", datetime(2026, 3, 20, 14, 25, 0),
                   SourceType.AUTH_LOG, auth_src),
        _make_fact(p, 6, "proc-office", EntityType.NODE, "process_name",
                   "OUTLOOK.EXE", datetime(2026, 3, 20, 14, 26, 0),
                   SourceType.PROCESS_LIST, proc_src),
        _make_fact(p, 7, "proc-office-2", EntityType.NODE, "process_name",
                   "WINWORD.EXE", datetime(2026, 3, 20, 14, 27, 0),
                   SourceType.PROCESS_LIST, proc_src),
        _make_fact(p, 8, "proc-teams", EntityType.NODE, "process_name",
                   "Teams.exe", datetime(2026, 3, 20, 14, 28, 0),
                   SourceType.PROCESS_LIST, proc_src),
    ]

    packet = _build_packet(p, "impossible-travel", datetime(2026, 3, 20, 13, 55, 0),
                           datetime(2026, 3, 20, 15, 0, 0), facts)

    return BenchmarkScenario(
        metadata=ScenarioMetadata(
            scenario_id="SC-032",
            name="Impossible Travel Normal Processes",
            description="Logins from NY and London 25 min apart, but London session runs only Office apps",
            mitre_attack_ids=("T1078",),
            mitre_tactic="Initial Access",
            difficulty_tier=4,
            expected_verdict="THREAT_CONFIRMED",
            expected_winner="ARCHITECT",
            fact_count=len(facts),
            notes="Mixed signals — impossible travel is strong indicator regardless of benign-looking processes",
        ),
        packet=packet,
    )


def build_sc033_process_threat_syslog_benign() -> BenchmarkScenario:
    """SC-033: Suspicious process but syslog shows authorized deployment.

    A script downloads and executes a binary in /tmp on a Linux server.
    Looks like malware staging. But syslog shows an Ansible deployment
    run from the automation server with a valid job ID.
    """
    ts = datetime(2026, 3, 20, 12, 0, 0)
    p = "sc033"
    syslog_src = "appserver03:syslog:2026-03-20"
    proc_src = "appserver03:process:2026-03-20"

    facts = [
        _make_fact(p, 1, "proc-curl", EntityType.NODE, "process_name",
                   "curl", ts, SourceType.PROCESS_LIST, proc_src),
        _make_fact(p, 2, "proc-curl", EntityType.NODE, "command_line",
                   "curl -o /tmp/deploy-agent http://artifacts.corp.local/releases/agent-v3.2.1",
                   ts, SourceType.PROCESS_LIST, proc_src),
        _make_fact(p, 3, "proc-chmod", EntityType.NODE, "command_line",
                   "chmod +x /tmp/deploy-agent", datetime(2026, 3, 20, 12, 0, 2),
                   SourceType.PROCESS_LIST, proc_src),
        _make_fact(p, 4, "proc-exec", EntityType.NODE, "command_line",
                   "/tmp/deploy-agent --install --config /etc/monitor/agent.conf",
                   datetime(2026, 3, 20, 12, 0, 5), SourceType.PROCESS_LIST, proc_src),
        _make_fact(p, 5, "ansible-log", EntityType.NODE, "event_type",
                   "ansible_task_ok", ts, SourceType.SYSLOG, syslog_src),
        _make_fact(p, 6, "ansible-log", EntityType.NODE, "ansible_job",
                   "Job AWX-2026-1547: Deploy monitoring agent v3.2.1 (initiated by automation@corp)",
                   ts, SourceType.SYSLOG, syslog_src),
        _make_fact(p, 7, "ansible-source", EntityType.NODE, "source_host",
                   "ansible01.corp.local (10.0.0.50)", ts,
                   SourceType.SYSLOG, syslog_src),
    ]

    packet = _build_packet(p, "ansible-deploy", datetime(2026, 3, 20, 11, 55, 0),
                           datetime(2026, 3, 20, 12, 30, 0), facts)

    return BenchmarkScenario(
        metadata=ScenarioMetadata(
            scenario_id="SC-033",
            name="Suspicious Binary with Ansible Deploy",
            description="curl→chmod→exec in /tmp but Ansible job log confirms authorized deployment",
            mitre_attack_ids=("T1105",),
            mitre_tactic="Command and Control",
            difficulty_tier=4,
            expected_verdict="THREAT_DISMISSED",
            expected_winner="SKEPTIC",
            fact_count=len(facts),
            notes="Mixed signals — /tmp execution looks malicious, but Ansible job ID resolves it",
        ),
        packet=packet,
    )


# =============================================================================
# Public API
# =============================================================================


def get_expanded_scenarios() -> tuple[BenchmarkScenario, ...]:
    """Return all 15 expanded scenarios (SC-019 through SC-033)."""
    return (
        build_sc019_ransomware_indicators(),
        build_sc020_c2_beaconing(),
        build_sc021_scheduled_backup_transfer(),
        build_sc022_admin_psexec_patching(),
        build_sc023_security_scanner_noise(),
        build_sc024_dual_use_powershell(),
        build_sc025_exfiltration_ambiguity(),
        build_sc026_credential_pattern(),
        build_sc027_timing_anomaly(),
        build_sc028_wmi_lateral_movement(),
        build_sc029_port_scan_ambiguity(),
        build_sc030_conflicting_dns_netflow(),
        build_sc031_syslog_threat_netflow_benign(),
        build_sc032_auth_threat_process_benign(),
        build_sc033_process_threat_syslog_benign(),
    )


def get_full_corpus() -> tuple[BenchmarkScenario, ...]:
    """Return all 33 scenarios: original 18 + 15 expanded.

    Returns:
        Immutable tuple of all BenchmarkScenario instances, ordered SC-001 to SC-033.
    """
    return _get_18_corpus() + get_expanded_scenarios()


def get_expanded_scenario_by_id(scenario_id: str) -> BenchmarkScenario:
    """Get a single expanded scenario by ID (SC-019 through SC-033).

    Args:
        scenario_id: Scenario ID in "SC-NNN" format.

    Returns:
        The matching BenchmarkScenario.

    Raises:
        ValueError: If the ID is not found in the expanded set.
    """
    for s in get_expanded_scenarios():
        if s.metadata.scenario_id == scenario_id:
            return s
    raise ValueError(
        f"Scenario '{scenario_id}' not found in expanded set (SC-019 to SC-033)"
    )
