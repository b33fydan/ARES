"""PentAGI benchmark scenarios for penetration testing evidence analysis.

Six scenarios derived from PentAGI-style autonomous pentest output.
Each scenario constructs PentAGI action JSON, passes it through the
PentAGIExtractor, and loads the resulting Facts into an EvidencePacket.

This demonstrates the full integration path:
    PentAGI JSON → PentAGIExtractor → EvidencePacket → Dialectical Pipeline → ARES-VISION

Scenario IDs: PT-001 through PT-006 (separate namespace from SC-xxx).

Public API:
    get_pentagi_scenarios()  → tuple of 6 BenchmarkScenarios
    get_pentagi_corpus()     → full 33 + 6 pentagi = 39 scenarios
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from ares.dialectic.evidence.extractors.pentagi import PentAGIExtractor
from ares.dialectic.evidence.packet import EvidencePacket, TimeWindow
from ares.dialectic.scripts.scenario_corpus import (
    BenchmarkScenario,
    ScenarioMetadata,
)
from ares.dialectic.scripts.scenario_corpus_v2 import get_full_corpus_v2


# =============================================================================
# Helpers
# =============================================================================

_extractor = PentAGIExtractor()


def _build_from_actions(
    prefix: str,
    packet_id: str,
    time_start: datetime,
    time_end: datetime,
    actions: list[dict],
    source_ref: str,
) -> tuple[int, "EvidencePacket"]:
    """Build a frozen EvidencePacket from PentAGI action dicts.

    Returns:
        (fact_count, frozen_packet) tuple.
    """
    raw = json.dumps({"actions": actions})
    result = _extractor.extract(raw, source_ref=source_ref, strict=True)

    packet = EvidencePacket(
        packet_id=packet_id,
        time_window=TimeWindow(start=time_start, end=time_end),
    )
    for fact in result.facts:
        packet.add_fact(fact)
    packet.freeze()

    return len(result.facts), packet


# =============================================================================
# PT-001: SQL Injection → Database Compromise (CLEAR THREAT)
# =============================================================================

def build_pt001_sqli_to_rce() -> BenchmarkScenario:
    """PT-001: SQL injection chain leading to database compromise.

    Nmap → open MySQL port, SQLMap → UNION injection confirmed,
    Metasploit → root shell via UDF payload. Classic attack chain
    with clear evidence at every stage.
    """
    ts = "2026-03-15T10:30:00+00:00"

    actions = [
        {
            "action_id": "pt001-recon",
            "tool": "nmap",
            "target": "10.20.30.100",
            "timestamp": ts,
            "parameters": "-sV -sC -p 1-10000",
            "result": {
                "open_ports": [
                    {"port": 22, "service": "ssh", "version": "OpenSSH 8.9p1"},
                    {"port": 80, "service": "http", "version": "Apache 2.4.52"},
                    {"port": 3306, "service": "mysql", "version": "MySQL 5.7.38"},
                    {"port": 8080, "service": "http-proxy", "version": "Tomcat 9.0.65"},
                ],
                "os_detection": "Ubuntu 20.04 LTS",
            },
        },
        {
            "action_id": "pt001-sqli",
            "tool": "sqlmap",
            "target": "http://10.20.30.100:8080/api/users?id=1",
            "timestamp": "2026-03-15T10:35:00+00:00",
            "parameters": "--dbs --risk=3 --level=5 --batch",
            "result": {
                "vulnerable": True,
                "injection_type": "UNION-based blind",
                "parameter": "id",
                "databases": ["webapp_prod", "mysql", "information_schema", "performance_schema"],
                "dbms": "MySQL >= 5.7",
            },
        },
        {
            "action_id": "pt001-exploit",
            "tool": "metasploit",
            "target": "10.20.30.100:3306",
            "timestamp": "2026-03-15T10:42:00+00:00",
            "parameters": "exploit/multi/mysql/mysql_udf_payload",
            "result": {
                "exploited": True,
                "payload": "linux/x64/meterpreter/reverse_tcp",
                "session_type": "meterpreter",
                "access_level": "root",
            },
        },
    ]

    fact_count, packet = _build_from_actions(
        prefix="pt001",
        packet_id="pt001-sqli-rce",
        time_start=datetime(2026, 3, 15, 10, 0, tzinfo=timezone.utc),
        time_end=datetime(2026, 3, 15, 11, 0, tzinfo=timezone.utc),
        actions=actions,
        source_ref="pentagi:flow-pt001",
    )

    metadata = ScenarioMetadata(
        scenario_id="PT-001",
        name="SQL Injection to Root Shell",
        description="Nmap recon → SQLMap UNION injection → Metasploit root via MySQL UDF",
        mitre_attack_ids=("T1190", "T1059"),
        mitre_tactic="Initial Access",
        difficulty_tier=1,
        expected_verdict="THREAT_CONFIRMED",
        expected_winner="ARCHITECT",
        fact_count=fact_count,
        notes="Tier 1 clear threat — full attack chain with exploitation proof at every step",
    )

    return BenchmarkScenario(metadata=metadata, packet=packet)


# =============================================================================
# PT-002: Routine Security Assessment — No Findings (CLEAR BENIGN)
# =============================================================================

def build_pt002_clean_assessment() -> BenchmarkScenario:
    """PT-002: Routine pentest with zero findings on hardened target.

    Nmap shows patched services, Nuclei finds nothing, SQLMap confirms
    no injection. This is a well-maintained server passing its assessment.
    """
    ts = "2026-03-15T14:00:00+00:00"

    actions = [
        {
            "action_id": "pt002-recon",
            "tool": "nmap",
            "target": "10.20.30.200",
            "timestamp": ts,
            "parameters": "-sV -sC -p-",
            "result": {
                "open_ports": [
                    {"port": 443, "service": "https", "version": "nginx 1.24.0"},
                ],
                "os_detection": "Ubuntu 22.04 LTS",
            },
        },
        {
            "action_id": "pt002-vulnscan",
            "tool": "nuclei",
            "target": "https://10.20.30.200",
            "timestamp": "2026-03-15T14:10:00+00:00",
            "parameters": "-t cves/ -severity critical,high,medium",
            "result": {
                "findings": [],
            },
        },
        {
            "action_id": "pt002-sqli-check",
            "tool": "sqlmap",
            "target": "https://10.20.30.200/api/search?q=test",
            "timestamp": "2026-03-15T14:15:00+00:00",
            "parameters": "--batch --level=3",
            "result": {
                "vulnerable": False,
            },
        },
        {
            "action_id": "pt002-dirscan",
            "tool": "gobuster",
            "target": "https://10.20.30.200",
            "timestamp": "2026-03-15T14:20:00+00:00",
            "parameters": "dir -u https://10.20.30.200 -w common.txt",
            "result": {
                "discovered_paths": [
                    {"path": "/api", "status": 401},
                    {"path": "/health", "status": 200},
                ],
            },
        },
    ]

    fact_count, packet = _build_from_actions(
        prefix="pt002",
        packet_id="pt002-clean-assessment",
        time_start=datetime(2026, 3, 15, 14, 0, tzinfo=timezone.utc),
        time_end=datetime(2026, 3, 15, 15, 0, tzinfo=timezone.utc),
        actions=actions,
        source_ref="pentagi:flow-pt002",
    )

    metadata = ScenarioMetadata(
        scenario_id="PT-002",
        name="Hardened Target — Clean Assessment",
        description="Minimal attack surface, no CVEs, no injection, restricted paths",
        mitre_attack_ids=(),
        mitre_tactic="None",
        difficulty_tier=3,
        expected_verdict="THREAT_DISMISSED",
        expected_winner="SKEPTIC",
        fact_count=fact_count,
        notes="Tier 3 clear benign — well-hardened server with zero exploitable findings",
    )

    return BenchmarkScenario(metadata=metadata, packet=packet)


# =============================================================================
# PT-003: Web Vulnerabilities Without Exploitation (AMBIGUOUS)
# =============================================================================

def build_pt003_vulns_no_exploit() -> BenchmarkScenario:
    """PT-003: Web vulnerabilities discovered but no exploitation achieved.

    Nikto finds info leaks and directory listing, Gobuster discovers
    admin panel and backup dir, but SQLMap confirms no injection.
    Vulnerabilities exist but attack chain is incomplete.
    """
    ts = "2026-03-15T16:00:00+00:00"

    actions = [
        {
            "action_id": "pt003-recon",
            "tool": "nmap",
            "target": "10.20.30.50",
            "timestamp": ts,
            "parameters": "-sV -p 80,443,8080",
            "result": {
                "open_ports": [
                    {"port": 80, "service": "http", "version": "Apache 2.4.41"},
                    {"port": 443, "service": "https", "version": "Apache 2.4.41"},
                    {"port": 8080, "service": "http-proxy", "version": "Jetty 9.4.44"},
                ],
            },
        },
        {
            "action_id": "pt003-webscan",
            "tool": "nikto",
            "target": "http://10.20.30.50",
            "timestamp": "2026-03-15T16:05:00+00:00",
            "parameters": "-h 10.20.30.50",
            "result": {
                "vulnerabilities": [
                    {"id": "NIKTO-003301", "description": "Server leaks inodes via ETags", "uri": "/"},
                    {"id": "NIKTO-003268", "description": "Directory indexing found", "uri": "/backup/"},
                    {"id": "NIKTO-006512", "description": "Apache mod_negotiation enabled", "uri": "/"},
                ],
            },
        },
        {
            "action_id": "pt003-dirscan",
            "tool": "gobuster",
            "target": "http://10.20.30.50",
            "timestamp": "2026-03-15T16:10:00+00:00",
            "parameters": "dir -u http://10.20.30.50 -w medium.txt",
            "result": {
                "discovered_paths": [
                    {"path": "/admin", "status": 200},
                    {"path": "/backup", "status": 200},
                    {"path": "/phpmyadmin", "status": 302},
                    {"path": "/server-status", "status": 403},
                    {"path": "/config", "status": 200},
                ],
            },
        },
        {
            "action_id": "pt003-sqli-check",
            "tool": "sqlmap",
            "target": "http://10.20.30.50/admin/login.php?user=admin",
            "timestamp": "2026-03-15T16:15:00+00:00",
            "parameters": "--batch --level=5 --risk=3",
            "result": {
                "vulnerable": False,
            },
        },
    ]

    fact_count, packet = _build_from_actions(
        prefix="pt003",
        packet_id="pt003-vulns-no-exploit",
        time_start=datetime(2026, 3, 15, 16, 0, tzinfo=timezone.utc),
        time_end=datetime(2026, 3, 15, 17, 0, tzinfo=timezone.utc),
        actions=actions,
        source_ref="pentagi:flow-pt003",
    )

    metadata = ScenarioMetadata(
        scenario_id="PT-003",
        name="Web Vulnerabilities — No Exploitation",
        description="Info leaks + exposed admin/backup dirs but no injection or shell",
        mitre_attack_ids=("T1595", "T1190"),
        mitre_tactic="Reconnaissance",
        difficulty_tier=2,
        expected_verdict="INCONCLUSIVE",
        expected_winner="BALANCED",
        fact_count=fact_count,
        notes="Tier 2 ambiguous — real attack surface but no exploitation proof; "
              "Architect sees exposure, Skeptic sees incomplete chain",
    )

    return BenchmarkScenario(metadata=metadata, packet=packet)


# =============================================================================
# PT-004: Credential Brute Force → SSH Compromise (CLEAR THREAT)
# =============================================================================

def build_pt004_credential_compromise() -> BenchmarkScenario:
    """PT-004: Brute force credential attack leading to SSH shell.

    Nmap finds SSH, Hydra cracks admin password, Metasploit gets
    meterpreter session. Full credential-based attack chain.
    """
    ts = "2026-03-16T08:00:00+00:00"

    actions = [
        {
            "action_id": "pt004-recon",
            "tool": "nmap",
            "target": "10.20.30.75",
            "timestamp": ts,
            "parameters": "-sV -p 22,80,443",
            "result": {
                "open_ports": [
                    {"port": 22, "service": "ssh", "version": "OpenSSH 7.6p1"},
                    {"port": 80, "service": "http", "version": "nginx 1.18.0"},
                ],
                "os_detection": "Ubuntu 18.04 LTS",
            },
        },
        {
            "action_id": "pt004-bruteforce",
            "tool": "hydra",
            "target": "10.20.30.75:22",
            "timestamp": "2026-03-16T08:10:00+00:00",
            "parameters": "-l admin -P rockyou.txt -t 4 ssh://10.20.30.75",
            "result": {
                "service": "ssh",
                "credentials_found": [
                    {"username": "admin"},
                ],
            },
        },
        {
            "action_id": "pt004-exploit",
            "tool": "metasploit",
            "target": "10.20.30.75:22",
            "timestamp": "2026-03-16T08:25:00+00:00",
            "parameters": "auxiliary/scanner/ssh/ssh_login",
            "result": {
                "exploited": True,
                "payload": "cmd/unix/interact",
                "session_type": "shell",
                "access_level": "admin",
            },
        },
    ]

    fact_count, packet = _build_from_actions(
        prefix="pt004",
        packet_id="pt004-cred-compromise",
        time_start=datetime(2026, 3, 16, 8, 0, tzinfo=timezone.utc),
        time_end=datetime(2026, 3, 16, 9, 0, tzinfo=timezone.utc),
        actions=actions,
        source_ref="pentagi:flow-pt004",
    )

    metadata = ScenarioMetadata(
        scenario_id="PT-004",
        name="SSH Credential Brute Force to Shell",
        description="Nmap recon → Hydra cracks SSH creds → Metasploit interactive shell",
        mitre_attack_ids=("T1110", "T1021"),
        mitre_tactic="Credential Access",
        difficulty_tier=1,
        expected_verdict="THREAT_CONFIRMED",
        expected_winner="ARCHITECT",
        fact_count=fact_count,
        notes="Tier 1 clear threat — credential compromise with proven shell access",
    )

    return BenchmarkScenario(metadata=metadata, packet=packet)


# =============================================================================
# PT-005: Critical CVEs Found — No Active Exploitation (MIXED SIGNALS)
# =============================================================================

def build_pt005_critical_cves_unpatched() -> BenchmarkScenario:
    """PT-005: Critical CVEs on unpatched server, no exploitation attempted.

    Nmap shows outdated services, Nuclei finds Log4j and Confluence
    auth bypass CVEs. Critically vulnerable but no exploitation was
    performed — assessment only.
    """
    ts = "2026-03-16T11:00:00+00:00"

    actions = [
        {
            "action_id": "pt005-recon",
            "tool": "nmap",
            "target": "10.20.30.150",
            "timestamp": ts,
            "parameters": "-sV -sC -p-",
            "result": {
                "open_ports": [
                    {"port": 22, "service": "ssh", "version": "OpenSSH 7.4"},
                    {"port": 80, "service": "http", "version": "Apache 2.4.29"},
                    {"port": 443, "service": "https", "version": "Apache 2.4.29"},
                    {"port": 8080, "service": "http-proxy", "version": "Tomcat 9.0.31"},
                    {"port": 8090, "service": "http", "version": "Confluence 7.13.6"},
                ],
                "os_detection": "CentOS 7",
            },
        },
        {
            "action_id": "pt005-vulnscan",
            "tool": "nuclei",
            "target": "http://10.20.30.150",
            "timestamp": "2026-03-16T11:15:00+00:00",
            "parameters": "-t cves/ -severity critical,high",
            "result": {
                "findings": [
                    {
                        "template_id": "CVE-2021-44228",
                        "name": "Apache Log4j RCE (Log4Shell)",
                        "severity": "critical",
                        "matched_at": "http://10.20.30.150:8080/",
                    },
                    {
                        "template_id": "CVE-2023-22515",
                        "name": "Atlassian Confluence Broken Access Control",
                        "severity": "critical",
                        "matched_at": "http://10.20.30.150:8090/",
                    },
                    {
                        "template_id": "CVE-2021-41773",
                        "name": "Apache HTTP Server Path Traversal",
                        "severity": "high",
                        "matched_at": "http://10.20.30.150/",
                    },
                ],
            },
        },
        {
            "action_id": "pt005-webscan",
            "tool": "nikto",
            "target": "http://10.20.30.150",
            "timestamp": "2026-03-16T11:20:00+00:00",
            "parameters": "-h 10.20.30.150",
            "result": {
                "vulnerabilities": [
                    {"id": "NIKTO-002795", "description": "Apache/2.4.29 appears to be outdated", "uri": "/"},
                    {"id": "NIKTO-003587", "description": "TRACE method enabled", "uri": "/"},
                ],
            },
        },
    ]

    fact_count, packet = _build_from_actions(
        prefix="pt005",
        packet_id="pt005-critical-cves",
        time_start=datetime(2026, 3, 16, 11, 0, tzinfo=timezone.utc),
        time_end=datetime(2026, 3, 16, 12, 0, tzinfo=timezone.utc),
        actions=actions,
        source_ref="pentagi:flow-pt005",
    )

    metadata = ScenarioMetadata(
        scenario_id="PT-005",
        name="Critical CVEs — Unpatched Server",
        description="Log4Shell + Confluence bypass + path traversal on outdated stack, no exploitation",
        mitre_attack_ids=("T1190", "T1595"),
        mitre_tactic="Initial Access",
        difficulty_tier=4,
        expected_verdict="INCONCLUSIVE",
        expected_winner="BALANCED",
        fact_count=fact_count,
        notes="Tier 4 mixed signals — critical vulns confirmed by scanner but zero exploitation; "
              "under closed-world assumption, vulnerability != compromise; "
              "patched from THREAT_CONFIRMED after Session 040 baseline (same logic as SC-011/SC-017)",
    )

    return BenchmarkScenario(metadata=metadata, packet=packet)


# =============================================================================
# PT-006: Failed Exploitation on Patched Target (CLEAR BENIGN)
# =============================================================================

def build_pt006_failed_exploitation() -> BenchmarkScenario:
    """PT-006: All exploitation attempts fail against patched target.

    Nmap shows services, SQLMap finds no injection, Metasploit exploit
    fails, Nuclei returns nothing. Target is properly defended.
    """
    ts = "2026-03-16T14:00:00+00:00"

    actions = [
        {
            "action_id": "pt006-recon",
            "tool": "nmap",
            "target": "10.20.30.250",
            "timestamp": ts,
            "parameters": "-sV -sC -p 22,80,443,3306",
            "result": {
                "open_ports": [
                    {"port": 22, "service": "ssh", "version": "OpenSSH 9.3p1"},
                    {"port": 443, "service": "https", "version": "nginx 1.25.3"},
                    {"port": 3306, "service": "mysql", "version": "MySQL 8.0.35"},
                ],
                "os_detection": "Ubuntu 24.04 LTS",
            },
        },
        {
            "action_id": "pt006-sqli-check",
            "tool": "sqlmap",
            "target": "https://10.20.30.250/api/v2/users?id=1",
            "timestamp": "2026-03-16T14:10:00+00:00",
            "parameters": "--batch --level=5 --risk=3 --tamper=space2comment",
            "result": {
                "vulnerable": False,
            },
        },
        {
            "action_id": "pt006-exploit-fail",
            "tool": "metasploit",
            "target": "10.20.30.250:3306",
            "timestamp": "2026-03-16T14:20:00+00:00",
            "parameters": "exploit/multi/mysql/mysql_udf_payload",
            "result": {
                "exploited": False,
            },
        },
        {
            "action_id": "pt006-vulnscan",
            "tool": "nuclei",
            "target": "https://10.20.30.250",
            "timestamp": "2026-03-16T14:25:00+00:00",
            "parameters": "-t cves/ -severity critical,high,medium",
            "result": {
                "findings": [],
            },
        },
    ]

    fact_count, packet = _build_from_actions(
        prefix="pt006",
        packet_id="pt006-failed-exploit",
        time_start=datetime(2026, 3, 16, 14, 0, tzinfo=timezone.utc),
        time_end=datetime(2026, 3, 16, 15, 0, tzinfo=timezone.utc),
        actions=actions,
        source_ref="pentagi:flow-pt006",
    )

    metadata = ScenarioMetadata(
        scenario_id="PT-006",
        name="Failed Exploitation — Patched Target",
        description="All exploits fail, no CVEs, no injection — target is well defended",
        mitre_attack_ids=(),
        mitre_tactic="None",
        difficulty_tier=3,
        expected_verdict="THREAT_DISMISSED",
        expected_winner="SKEPTIC",
        fact_count=fact_count,
        notes="Tier 3 clear benign — current software versions, all attacks fail, "
              "no vulnerabilities found; strong dismiss case for Skeptic",
    )

    return BenchmarkScenario(metadata=metadata, packet=packet)


# =============================================================================
# Public API
# =============================================================================

def get_pentagi_scenarios() -> tuple[BenchmarkScenario, ...]:
    """Return all 6 PentAGI benchmark scenarios.

    Returns:
        Tuple of BenchmarkScenario instances (PT-001 through PT-006).
    """
    return (
        build_pt001_sqli_to_rce(),
        build_pt002_clean_assessment(),
        build_pt003_vulns_no_exploit(),
        build_pt004_credential_compromise(),
        build_pt005_critical_cves_unpatched(),
        build_pt006_failed_exploitation(),
    )


def get_pentagi_corpus() -> tuple[BenchmarkScenario, ...]:
    """Return full corpus (33 SC scenarios + 6 PT scenarios).

    Combines the existing v2 corpus with the PentAGI scenarios
    for a total of 39 benchmark scenarios.

    Returns:
        Tuple of 39 BenchmarkScenario instances.
    """
    return get_full_corpus_v2() + get_pentagi_scenarios()
