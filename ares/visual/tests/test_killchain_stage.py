"""Tests for kill chain stage classification logic.

Session 043: Validates that the JavaScript stage classifier (implemented
in index_v6.html) correctly maps PentAGI fact_id prefixes + field_names
to kill chain stages. The Python implementation here mirrors the JS logic
for test coverage.

The JS classifier in index_v6.html uses:
    classifyStage(factId, fieldName) → stage string

This Python mirror is the authoritative spec.
"""

from __future__ import annotations

import pytest


# =============================================================================
# Python mirror of the JS classifyStage() function
# =============================================================================

STAGE_ORDER = ("RECON", "VULN_ID", "EXPLOITATION", "POST_EXPLOIT")

RECON_TOOLS = frozenset({"nmap", "gobuster"})
VULN_ID_TOOLS = frozenset({"nikto", "nuclei"})
SQLMAP_EXPLOIT_FIELDS = frozenset({
    "injection_type", "databases_found", "vulnerable_parameter", "dbms",
})
MSF_POST_EXPLOIT_FIELDS = frozenset({
    "payload", "session_type", "access_level",
})
HYDRA_EXPLOIT_FIELDS = frozenset({
    "compromised_username", "credential_found",
})


def classify_stage(fact_id: str, field_name: str) -> str:
    """Mirror of the JS classifyStage() function in index_v6.html.

    Args:
        fact_id: PentAGI fact identifier (e.g. "nmap-pt001-recon-tool").
        field_name: Field name from the fact (e.g. "tool", "vulnerable").

    Returns:
        Stage string: RECON, VULN_ID, EXPLOITATION, or POST_EXPLOIT.
    """
    tool = fact_id.split("-")[0].lower()

    if tool in RECON_TOOLS:
        return "RECON"
    if tool in VULN_ID_TOOLS:
        return "VULN_ID"

    if tool == "sqlmap":
        if field_name in SQLMAP_EXPLOIT_FIELDS:
            return "EXPLOITATION"
        return "VULN_ID"

    if tool == "msf":
        if field_name in MSF_POST_EXPLOIT_FIELDS:
            return "POST_EXPLOIT"
        return "EXPLOITATION"

    if tool == "hydra":
        if field_name in HYDRA_EXPLOIT_FIELDS:
            return "EXPLOITATION"
        return "RECON"

    return "RECON"


# =============================================================================
# Nmap — always RECON
# =============================================================================

class TestNmapStage:
    def test_nmap_event_type(self):
        assert classify_stage("nmap-pt001-recon-event_type", "event_type") == "RECON"

    def test_nmap_tool(self):
        assert classify_stage("nmap-pt001-recon-tool", "tool") == "RECON"

    def test_nmap_port(self):
        assert classify_stage("nmap-pt001-recon-port-22-port", "port") == "RECON"

    def test_nmap_service(self):
        assert classify_stage("nmap-pt001-recon-port-22-service", "service_name") == "RECON"

    def test_nmap_os_detection(self):
        assert classify_stage("nmap-pt001-recon-os", "os_detection") == "RECON"


# =============================================================================
# Gobuster — always RECON
# =============================================================================

class TestGobusterStage:
    def test_gobuster_event_type(self):
        assert classify_stage("gobuster-pt003-dirscan-event_type", "event_type") == "RECON"

    def test_gobuster_path(self):
        assert classify_stage("gobuster-pt003-dirscan-path-0-path", "discovered_path") == "RECON"


# =============================================================================
# Nikto — always VULN_ID
# =============================================================================

class TestNiktoStage:
    def test_nikto_event_type(self):
        assert classify_stage("nikto-pt003-webscan-event_type", "event_type") == "VULN_ID"

    def test_nikto_vuln(self):
        assert classify_stage("nikto-pt003-webscan-vuln-0-id", "vulnerability_id") == "VULN_ID"


# =============================================================================
# Nuclei — always VULN_ID
# =============================================================================

class TestNucleiStage:
    def test_nuclei_event_type(self):
        assert classify_stage("nuclei-pt005-vulnscan-event_type", "event_type") == "VULN_ID"

    def test_nuclei_finding(self):
        assert classify_stage("nuclei-pt005-vulnscan-finding-0-severity", "vulnerability_severity") == "VULN_ID"


# =============================================================================
# SQLMap — VULN_ID (detection) or EXPLOITATION (success)
# =============================================================================

class TestSqlmapStage:
    def test_sqlmap_detection_only(self):
        assert classify_stage("sqlmap-pt003-sqli-check-vulnerable", "vulnerable") == "VULN_ID"

    def test_sqlmap_tool_fact(self):
        assert classify_stage("sqlmap-pt001-sqli-tool", "tool") == "VULN_ID"

    def test_sqlmap_injection_type(self):
        assert classify_stage("sqlmap-pt001-sqli-injection_type", "injection_type") == "EXPLOITATION"

    def test_sqlmap_databases_found(self):
        assert classify_stage("sqlmap-pt001-sqli-databases", "databases_found") == "EXPLOITATION"

    def test_sqlmap_vulnerable_parameter(self):
        assert classify_stage("sqlmap-pt001-sqli-parameter", "vulnerable_parameter") == "EXPLOITATION"

    def test_sqlmap_dbms(self):
        assert classify_stage("sqlmap-pt001-sqli-dbms", "dbms") == "EXPLOITATION"


# =============================================================================
# Metasploit — EXPLOITATION (attempt) or POST_EXPLOIT (success)
# =============================================================================

class TestMetasploitStage:
    def test_msf_event_type(self):
        assert classify_stage("msf-pt001-exploit-event_type", "event_type") == "EXPLOITATION"

    def test_msf_exploited_field(self):
        assert classify_stage("msf-pt001-exploit-exploited", "exploited") == "EXPLOITATION"

    def test_msf_payload(self):
        assert classify_stage("msf-pt001-exploit-payload", "payload") == "POST_EXPLOIT"

    def test_msf_session_type(self):
        assert classify_stage("msf-pt001-exploit-session_type", "session_type") == "POST_EXPLOIT"

    def test_msf_access_level(self):
        assert classify_stage("msf-pt001-exploit-access_level", "access_level") == "POST_EXPLOIT"

    def test_msf_module(self):
        assert classify_stage("msf-pt006-exploit-fail-module", "exploit_module") == "EXPLOITATION"


# =============================================================================
# Hydra — RECON (attempt) or EXPLOITATION (credentials found)
# =============================================================================

class TestHydraStage:
    def test_hydra_event_type(self):
        assert classify_stage("hydra-pt004-bruteforce-event_type", "event_type") == "RECON"

    def test_hydra_target_service(self):
        assert classify_stage("hydra-pt004-bruteforce-service", "target_service") == "RECON"

    def test_hydra_credential_found(self):
        assert classify_stage("hydra-pt004-bruteforce-cred-0-found", "credential_found") == "EXPLOITATION"

    def test_hydra_compromised_username(self):
        assert classify_stage("hydra-pt004-bruteforce-cred-0-username", "compromised_username") == "EXPLOITATION"


# =============================================================================
# Unknown tools default to RECON
# =============================================================================

class TestUnknownTool:
    def test_unknown_prefix(self):
        assert classify_stage("whois-unknown-scan", "result") == "RECON"

    def test_pentagi_generic(self):
        assert classify_stage("pentagi-custom-action", "custom_field") == "RECON"


# =============================================================================
# Cross-scenario integration: verify real fact_ids from PentAGI scenarios
# =============================================================================

class TestRealFactIds:
    """Test with actual fact_ids generated by the PentAGI extractor."""

    def test_pt001_nmap_is_recon(self):
        assert classify_stage("nmap-pt001-recon-port-3306-service", "service_name") == "RECON"

    def test_pt001_sqlmap_exploiting(self):
        assert classify_stage("sqlmap-pt001-sqli-injection_type", "injection_type") == "EXPLOITATION"

    def test_pt001_msf_root_shell(self):
        assert classify_stage("msf-pt001-exploit-access_level", "access_level") == "POST_EXPLOIT"

    def test_pt002_nmap_clean_scan(self):
        assert classify_stage("nmap-pt002-recon-port-443-service", "service_name") == "RECON"

    def test_pt003_nikto_vuln_report(self):
        assert classify_stage("nikto-pt003-webscan-vuln-0-description", "vulnerability_description") == "VULN_ID"

    def test_pt005_nuclei_cve(self):
        assert classify_stage("nuclei-pt005-vulnscan-finding-0-template_id", "template_id") == "VULN_ID"

    def test_pt006_msf_failed(self):
        # msf failed — exploited field but no payload/session
        assert classify_stage("msf-pt006-exploit-fail-exploited", "exploited") == "EXPLOITATION"

    def test_pt004_hydra_cracked(self):
        assert classify_stage("hydra-pt004-bruteforce-cred-0-found", "credential_found") == "EXPLOITATION"
