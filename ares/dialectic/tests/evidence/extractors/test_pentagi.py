"""Tests for PentAGI evidence extractor.

Tests validate:
1. Nmap scan extraction (ports, services, OS detection)
2. SQLMap injection extraction (vulnerable/not vulnerable)
3. Metasploit exploitation extraction (success/failure)
4. Nuclei vulnerability scan extraction
5. Nikto web scan extraction
6. Gobuster directory enumeration extraction
7. Hydra credential bruteforce extraction
8. Generic tool fallback extraction
9. Strict vs permissive mode
10. Provenance stamping with PENTEST_TOOL source type
11. ExtractionStats accuracy
12. Protocol compliance
13. Edge cases (malformed JSON, missing fields, empty actions)
"""

import json
import pytest

from ares.dialectic.evidence.extractors.protocol import (
    ExtractionError,
    ExtractorProtocol,
)
from ares.dialectic.evidence.extractors.pentagi import (
    PentAGIExtractor,
    PentAGIAction,
    MALFORMED_JSON,
    MISSING_FIELD,
    INVALID_RESULT,
    SUPPORTED_TOOLS,
)
from ares.dialectic.evidence.fact import EntityType
from ares.dialectic.evidence.provenance import SourceType
from ares.dialectic.evidence.packet import EvidencePacket, TimeWindow


# =============================================================================
# Test Data
# =============================================================================

NMAP_ACTION = {
    "action_id": "act-001",
    "tool": "nmap",
    "target": "192.168.1.100",
    "timestamp": "2026-03-15T10:30:00+00:00",
    "parameters": "-sV -sC -p 1-1000",
    "result": {
        "open_ports": [
            {"port": 22, "service": "ssh", "version": "OpenSSH 8.9"},
            {"port": 80, "service": "http", "version": "Apache 2.4.52"},
            {"port": 443, "service": "https", "version": "Apache 2.4.52"},
            {"port": 3306, "service": "mysql", "version": "MySQL 5.7.38"},
        ],
        "os_detection": "Ubuntu 22.04 LTS",
    },
}

SQLMAP_VULNERABLE = {
    "action_id": "act-002",
    "tool": "sqlmap",
    "target": "http://192.168.1.100/api/users",
    "timestamp": "2026-03-15T10:35:00+00:00",
    "parameters": "--dbs --risk=3 --level=5",
    "result": {
        "vulnerable": True,
        "injection_type": "UNION-based blind",
        "parameter": "id",
        "databases": ["webapp_db", "mysql", "information_schema"],
        "dbms": "MySQL 5.7",
    },
}

SQLMAP_NOT_VULNERABLE = {
    "action_id": "act-002b",
    "tool": "sqlmap",
    "target": "http://192.168.1.100/api/health",
    "timestamp": "2026-03-15T10:36:00+00:00",
    "parameters": "--dbs",
    "result": {
        "vulnerable": False,
    },
}

METASPLOIT_SUCCESS = {
    "action_id": "act-003",
    "tool": "metasploit",
    "target": "192.168.1.100:3306",
    "timestamp": "2026-03-15T10:40:00+00:00",
    "parameters": "exploit/multi/mysql/mysql_udf_payload",
    "result": {
        "exploited": True,
        "payload": "linux/x64/meterpreter/reverse_tcp",
        "session_type": "meterpreter",
        "access_level": "root",
    },
}

METASPLOIT_FAILURE = {
    "action_id": "act-003b",
    "tool": "metasploit",
    "target": "192.168.1.100:22",
    "timestamp": "2026-03-15T10:42:00+00:00",
    "parameters": "exploit/linux/ssh/openssh_authbypass",
    "result": {
        "exploited": False,
    },
}

NUCLEI_ACTION = {
    "action_id": "act-004",
    "tool": "nuclei",
    "target": "http://192.168.1.100",
    "timestamp": "2026-03-15T10:45:00+00:00",
    "parameters": "-t cves/ -severity critical,high",
    "result": {
        "findings": [
            {
                "template_id": "CVE-2021-44228",
                "name": "Log4j RCE",
                "severity": "critical",
                "matched_at": "http://192.168.1.100/api/log",
            },
            {
                "template_id": "CVE-2023-22515",
                "name": "Confluence Auth Bypass",
                "severity": "critical",
                "matched_at": "http://192.168.1.100/confluence",
            },
        ],
    },
}

NIKTO_ACTION = {
    "action_id": "act-005",
    "tool": "nikto",
    "target": "http://192.168.1.100",
    "timestamp": "2026-03-15T10:50:00+00:00",
    "parameters": "-h 192.168.1.100",
    "result": {
        "vulnerabilities": [
            {"id": "NIKTO-001", "description": "Server leaks inodes via ETags", "uri": "/"},
            {"id": "NIKTO-002", "description": "Directory indexing found", "uri": "/backup/"},
        ],
    },
}

GOBUSTER_ACTION = {
    "action_id": "act-006",
    "tool": "gobuster",
    "target": "http://192.168.1.100",
    "timestamp": "2026-03-15T10:55:00+00:00",
    "parameters": "dir -u http://192.168.1.100 -w common.txt",
    "result": {
        "discovered_paths": [
            {"path": "/admin", "status": 200},
            {"path": "/backup", "status": 403},
            {"path": "/api", "status": 301},
        ],
    },
}

HYDRA_ACTION = {
    "action_id": "act-007",
    "tool": "hydra",
    "target": "192.168.1.100:22",
    "timestamp": "2026-03-15T11:00:00+00:00",
    "parameters": "-l admin -P rockyou.txt ssh://192.168.1.100",
    "result": {
        "service": "ssh",
        "credentials_found": [
            {"username": "admin"},
        ],
    },
}

GENERIC_TOOL_ACTION = {
    "action_id": "act-008",
    "tool": "custom_scanner",
    "target": "192.168.1.100",
    "timestamp": "2026-03-15T11:05:00+00:00",
    "parameters": "--deep-scan",
    "result": {
        "status": "completed",
        "issues_found": 3,
        "risk_level": "high",
        "details": {"nested": "skipped"},
    },
}

FULL_PENTEST_JSON = json.dumps({
    "actions": [NMAP_ACTION, SQLMAP_VULNERABLE, METASPLOIT_SUCCESS],
})

EMPTY_ACTIONS_JSON = json.dumps({"actions": []})


# =============================================================================
# Helper
# =============================================================================

def extract(raw: str, *, strict: bool = True, source_ref: str = "test:pentagi") -> "ExtractionResult":
    """Shorthand extraction helper for tests."""
    extractor = PentAGIExtractor()
    return extractor.extract(raw, source_ref=source_ref, strict=strict)


def single_action_json(action: dict) -> str:
    """Wrap a single action dict in the expected JSON format."""
    return json.dumps({"actions": [action]})


# =============================================================================
# Protocol Compliance Tests
# =============================================================================


class TestPentAGIProtocolCompliance:
    """Tests for ExtractorProtocol compliance."""

    def test_implements_protocol(self):
        """PentAGIExtractor satisfies ExtractorProtocol."""
        extractor = PentAGIExtractor()
        assert isinstance(extractor, ExtractorProtocol)

    def test_has_version(self):
        """Extractor exposes VERSION string."""
        assert PentAGIExtractor.VERSION == "1.0.0"

    def test_extract_returns_extraction_result(self):
        """extract() returns ExtractionResult."""
        result = extract(FULL_PENTEST_JSON)
        assert result.extractor_version == "1.0.0"
        assert result.source_ref == "test:pentagi"

    def test_facts_are_tuples(self):
        """Facts and errors are tuples, not lists."""
        result = extract(FULL_PENTEST_JSON)
        assert isinstance(result.facts, tuple)
        assert isinstance(result.errors, tuple)


# =============================================================================
# Nmap Tests
# =============================================================================


class TestNmapExtraction:
    """Tests for nmap scan result extraction."""

    def test_nmap_base_facts(self):
        """Nmap action produces event_type, tool, target, parameters facts."""
        result = extract(single_action_json(NMAP_ACTION))
        assert result.success
        fields = {f.field: f.value for f in result.facts if f.entity_id == "target:192.168.1.100"}
        assert fields["event_type"] == "port_scan"
        assert fields["tool"] == "nmap"
        assert fields["target"] == "192.168.1.100"
        assert fields["parameters"] == "-sV -sC -p 1-1000"

    def test_nmap_open_ports(self):
        """Each open port produces port, service_name, service_version facts."""
        result = extract(single_action_json(NMAP_ACTION))
        port_facts = [f for f in result.facts if f.field == "port"]
        assert len(port_facts) == 4
        ports = sorted([f.value for f in port_facts])
        assert ports == [22, 80, 443, 3306]

    def test_nmap_service_names(self):
        """Service names are extracted for each port."""
        result = extract(single_action_json(NMAP_ACTION))
        service_facts = [f for f in result.facts if f.field == "service_name"]
        services = sorted([f.value for f in service_facts])
        assert services == ["http", "https", "mysql", "ssh"]

    def test_nmap_service_versions(self):
        """Service versions are extracted when present."""
        result = extract(single_action_json(NMAP_ACTION))
        version_facts = [f for f in result.facts if f.field == "service_version"]
        assert len(version_facts) == 4
        assert any(f.value == "OpenSSH 8.9" for f in version_facts)

    def test_nmap_os_detection(self):
        """OS detection is extracted when present."""
        result = extract(single_action_json(NMAP_ACTION))
        os_facts = [f for f in result.facts if f.field == "os_detection"]
        assert len(os_facts) == 1
        assert os_facts[0].value == "Ubuntu 22.04 LTS"

    def test_nmap_port_entity_ids(self):
        """Port facts use service-level entity IDs (target:ip:port)."""
        result = extract(single_action_json(NMAP_ACTION))
        port_entities = {f.entity_id for f in result.facts if f.field == "port"}
        assert "service:192.168.1.100:22" in port_entities
        assert "service:192.168.1.100:3306" in port_entities

    def test_nmap_no_os_detection(self):
        """Nmap without OS detection omits os_detection fact."""
        action = {**NMAP_ACTION, "result": {"open_ports": [{"port": 22, "service": "ssh"}]}}
        result = extract(single_action_json(action))
        os_facts = [f for f in result.facts if f.field == "os_detection"]
        assert len(os_facts) == 0

    def test_nmap_empty_ports(self):
        """Nmap with no open ports still produces base facts."""
        action = {**NMAP_ACTION, "result": {"open_ports": []}}
        result = extract(single_action_json(action))
        assert result.success
        fields = {f.field for f in result.facts}
        assert "event_type" in fields
        assert "port" not in fields

    def test_nmap_stats(self):
        """Stats reflect correct counts for nmap extraction."""
        result = extract(single_action_json(NMAP_ACTION))
        assert result.stats.events_seen == 1
        assert result.stats.events_parsed == 1
        assert result.stats.events_dropped == 0
        assert result.stats.facts_emitted == len(result.facts)


# =============================================================================
# SQLMap Tests
# =============================================================================


class TestSQLMapExtraction:
    """Tests for sqlmap injection result extraction."""

    def test_sqlmap_vulnerable(self):
        """Vulnerable sqlmap result includes injection details."""
        result = extract(single_action_json(SQLMAP_VULNERABLE))
        assert result.success
        fields = {f.field: f.value for f in result.facts}
        assert fields["event_type"] == "sql_injection_test"
        assert fields["vulnerable"] is True
        assert fields["injection_type"] == "UNION-based blind"
        assert fields["vulnerable_parameter"] == "id"
        assert fields["dbms"] == "MySQL 5.7"

    def test_sqlmap_databases_found(self):
        """Database list is captured as a fact."""
        result = extract(single_action_json(SQLMAP_VULNERABLE))
        db_facts = [f for f in result.facts if f.field == "databases_found"]
        assert len(db_facts) == 1
        assert "webapp_db" in db_facts[0].value

    def test_sqlmap_not_vulnerable(self):
        """Non-vulnerable sqlmap result has vulnerable=False and no injection details."""
        result = extract(single_action_json(SQLMAP_NOT_VULNERABLE))
        assert result.success
        fields = {f.field: f.value for f in result.facts}
        assert fields["vulnerable"] is False
        assert "injection_type" not in fields
        assert "databases_found" not in fields


# =============================================================================
# Metasploit Tests
# =============================================================================


class TestMetasploitExtraction:
    """Tests for metasploit exploitation result extraction."""

    def test_metasploit_successful_exploitation(self):
        """Successful exploit includes payload, session_type, access_level."""
        result = extract(single_action_json(METASPLOIT_SUCCESS))
        assert result.success
        fields = {f.field: f.value for f in result.facts}
        assert fields["event_type"] == "exploitation_attempt"
        assert fields["exploited"] is True
        assert fields["payload"] == "linux/x64/meterpreter/reverse_tcp"
        assert fields["session_type"] == "meterpreter"
        assert fields["access_level"] == "root"

    def test_metasploit_exploit_module(self):
        """Exploit module (from parameters) is captured."""
        result = extract(single_action_json(METASPLOIT_SUCCESS))
        module_facts = [f for f in result.facts if f.field == "exploit_module"]
        assert len(module_facts) == 1
        assert module_facts[0].value == "exploit/multi/mysql/mysql_udf_payload"

    def test_metasploit_failed_exploitation(self):
        """Failed exploit has exploited=False and no payload details."""
        result = extract(single_action_json(METASPLOIT_FAILURE))
        assert result.success
        fields = {f.field: f.value for f in result.facts}
        assert fields["exploited"] is False
        assert "payload" not in fields
        assert "access_level" not in fields


# =============================================================================
# Nuclei Tests
# =============================================================================


class TestNucleiExtraction:
    """Tests for nuclei vulnerability scan extraction."""

    def test_nuclei_findings(self):
        """Nuclei findings produce template_id, severity, matched_at facts."""
        result = extract(single_action_json(NUCLEI_ACTION))
        assert result.success
        template_facts = [f for f in result.facts if f.field == "template_id"]
        assert len(template_facts) == 2
        templates = sorted([f.value for f in template_facts])
        assert templates == ["CVE-2021-44228", "CVE-2023-22515"]

    def test_nuclei_severity(self):
        """Severity is extracted for each finding."""
        result = extract(single_action_json(NUCLEI_ACTION))
        severity_facts = [f for f in result.facts if f.field == "vulnerability_severity"]
        assert all(f.value == "critical" for f in severity_facts)

    def test_nuclei_finding_count(self):
        """Finding count fact is always present."""
        result = extract(single_action_json(NUCLEI_ACTION))
        count_facts = [f for f in result.facts if f.field == "finding_count"]
        assert len(count_facts) == 1
        assert count_facts[0].value == 2

    def test_nuclei_vulnerability_names(self):
        """Vulnerability names are extracted when present."""
        result = extract(single_action_json(NUCLEI_ACTION))
        name_facts = [f for f in result.facts if f.field == "vulnerability_name"]
        assert len(name_facts) == 2
        names = sorted([f.value for f in name_facts])
        assert names == ["Confluence Auth Bypass", "Log4j RCE"]

    def test_nuclei_empty_findings(self):
        """Nuclei with no findings still produces base facts + count=0."""
        action = {**NUCLEI_ACTION, "result": {"findings": []}}
        result = extract(single_action_json(action))
        assert result.success
        count_facts = [f for f in result.facts if f.field == "finding_count"]
        assert count_facts[0].value == 0


# =============================================================================
# Nikto Tests
# =============================================================================


class TestNiktoExtraction:
    """Tests for nikto web scan extraction."""

    def test_nikto_vulnerabilities(self):
        """Nikto vulnerabilities are extracted with id, description, uri."""
        result = extract(single_action_json(NIKTO_ACTION))
        assert result.success
        vuln_ids = [f for f in result.facts if f.field == "vulnerability_id"]
        assert len(vuln_ids) == 2

    def test_nikto_vuln_count(self):
        """Vulnerability count fact is present."""
        result = extract(single_action_json(NIKTO_ACTION))
        count_facts = [f for f in result.facts if f.field == "vulnerability_count"]
        assert count_facts[0].value == 2

    def test_nikto_uris(self):
        """Vulnerable URIs are extracted."""
        result = extract(single_action_json(NIKTO_ACTION))
        uri_facts = [f for f in result.facts if f.field == "vulnerable_uri"]
        uris = sorted([f.value for f in uri_facts])
        assert uris == ["/", "/backup/"]


# =============================================================================
# Gobuster Tests
# =============================================================================


class TestGobusterExtraction:
    """Tests for gobuster directory enumeration extraction."""

    def test_gobuster_paths(self):
        """Discovered paths are extracted with status codes."""
        result = extract(single_action_json(GOBUSTER_ACTION))
        assert result.success
        path_facts = [f for f in result.facts if f.field == "discovered_path"]
        assert len(path_facts) == 3
        paths = sorted([f.value for f in path_facts])
        assert paths == ["/admin", "/api", "/backup"]

    def test_gobuster_status_codes(self):
        """HTTP status codes are extracted for each path."""
        result = extract(single_action_json(GOBUSTER_ACTION))
        status_facts = [f for f in result.facts if f.field == "http_status"]
        statuses = sorted([f.value for f in status_facts])
        assert statuses == [200, 301, 403]

    def test_gobuster_path_count(self):
        """Path count fact is present."""
        result = extract(single_action_json(GOBUSTER_ACTION))
        count_facts = [f for f in result.facts if f.field == "discovered_path_count"]
        assert count_facts[0].value == 3

    def test_gobuster_string_paths(self):
        """Paths as plain strings (not dicts) are handled."""
        action = {**GOBUSTER_ACTION, "result": {"discovered_paths": ["/secret", "/hidden"]}}
        result = extract(single_action_json(action))
        path_facts = [f for f in result.facts if f.field == "discovered_path"]
        assert len(path_facts) == 2


# =============================================================================
# Hydra Tests
# =============================================================================


class TestHydraExtraction:
    """Tests for hydra credential brute-force extraction."""

    def test_hydra_credentials_found(self):
        """Found credentials produce username facts but NOT password facts."""
        result = extract(single_action_json(HYDRA_ACTION))
        assert result.success
        username_facts = [f for f in result.facts if f.field == "compromised_username"]
        assert len(username_facts) == 1
        assert username_facts[0].value == "admin"
        # No password facts
        password_facts = [f for f in result.facts if "password" in f.field]
        assert len(password_facts) == 0

    def test_hydra_credential_count(self):
        """Credential count is captured."""
        result = extract(single_action_json(HYDRA_ACTION))
        count_facts = [f for f in result.facts if f.field == "credentials_found_count"]
        assert count_facts[0].value == 1

    def test_hydra_target_service(self):
        """Target service is captured."""
        result = extract(single_action_json(HYDRA_ACTION))
        service_facts = [f for f in result.facts if f.field == "target_service"]
        assert service_facts[0].value == "ssh"


# =============================================================================
# Generic Tool Tests
# =============================================================================


class TestGenericToolExtraction:
    """Tests for generic/unknown tool fallback extraction."""

    def test_generic_base_facts(self):
        """Unknown tools produce event_type, tool, target facts."""
        result = extract(single_action_json(GENERIC_TOOL_ACTION))
        assert result.success
        fields = {f.field: f.value for f in result.facts}
        assert fields["event_type"] == "pentest_custom_scanner"
        assert fields["tool"] == "custom_scanner"

    def test_generic_flattens_scalars(self):
        """Scalar result values are captured as facts."""
        result = extract(single_action_json(GENERIC_TOOL_ACTION))
        fields = {f.field: f.value for f in result.facts}
        assert fields["status"] == "completed"
        assert fields["issues_found"] == 3
        assert fields["risk_level"] == "high"

    def test_generic_skips_nested_dicts(self):
        """Nested dict values in result are skipped."""
        result = extract(single_action_json(GENERIC_TOOL_ACTION))
        fields = {f.field for f in result.facts}
        assert "details" not in fields


# =============================================================================
# Provenance Tests
# =============================================================================


class TestPentAGIProvenance:
    """Tests for PENTEST_TOOL provenance stamping."""

    def test_source_type_is_pentest_tool(self):
        """All facts have PENTEST_TOOL source type."""
        result = extract(FULL_PENTEST_JSON)
        for fact in result.facts:
            assert fact.provenance.source_type == SourceType.PENTEST_TOOL

    def test_provenance_includes_tool_and_action_id(self):
        """raw_reference includes action_id and tool name."""
        result = extract(single_action_json(NMAP_ACTION))
        for fact in result.facts:
            assert "action=act-001" in fact.provenance.raw_reference
            assert "tool=nmap" in fact.provenance.raw_reference

    def test_provenance_source_id(self):
        """source_id matches the source_ref passed to extract()."""
        result = extract(FULL_PENTEST_JSON, source_ref="pentagi:flow-123")
        for fact in result.facts:
            assert fact.provenance.source_id == "pentagi:flow-123"

    def test_provenance_parser_version(self):
        """Parser version matches extractor VERSION."""
        result = extract(FULL_PENTEST_JSON)
        for fact in result.facts:
            assert fact.provenance.parser_version == "1.0.0"


# =============================================================================
# Multi-Action Tests
# =============================================================================


class TestMultiActionExtraction:
    """Tests for processing multiple actions in a single JSON."""

    def test_full_pentest_pipeline(self):
        """Three-action pipeline (nmap + sqlmap + msf) processes all actions."""
        result = extract(FULL_PENTEST_JSON)
        assert result.success
        assert result.stats.events_seen == 3
        assert result.stats.events_parsed == 3
        assert result.stats.events_dropped == 0

    def test_full_pentest_fact_diversity(self):
        """Multiple tools produce facts with distinct event types."""
        result = extract(FULL_PENTEST_JSON)
        event_types = {f.value for f in result.facts if f.field == "event_type"}
        assert event_types == {"port_scan", "sql_injection_test", "exploitation_attempt"}

    def test_fact_ids_are_unique(self):
        """All fact IDs across multi-action extraction are unique."""
        result = extract(FULL_PENTEST_JSON)
        ids = [f.fact_id for f in result.facts]
        assert len(ids) == len(set(ids))

    def test_empty_actions(self):
        """Empty actions array produces zero facts, zero errors."""
        result = extract(EMPTY_ACTIONS_JSON)
        assert result.success
        assert len(result.facts) == 0
        assert result.stats.events_seen == 0


# =============================================================================
# Stats Tests
# =============================================================================


class TestExtractionStats:
    """Tests for ExtractionStats accuracy."""

    def test_stats_consistency(self):
        """facts_emitted equals len(facts)."""
        result = extract(FULL_PENTEST_JSON)
        assert result.stats.facts_emitted == len(result.facts)

    def test_stats_parsed_plus_dropped_equals_seen(self):
        """parsed + dropped == seen."""
        # Mix valid and invalid actions
        mixed = json.dumps({
            "actions": [
                NMAP_ACTION,
                {"bad": "action"},
                SQLMAP_VULNERABLE,
            ],
        })
        result = extract(mixed, strict=False)
        assert result.stats.events_parsed + result.stats.events_dropped == result.stats.events_seen


# =============================================================================
# Strict vs Permissive Mode
# =============================================================================


class TestStrictVsPermissive:
    """Tests for strict/permissive extraction modes."""

    def test_strict_raises_on_malformed_json(self):
        """Strict mode raises ValueError on invalid JSON."""
        with pytest.raises(ValueError, match="Invalid JSON"):
            extract("not json at all")

    def test_permissive_returns_error_on_malformed_json(self):
        """Permissive mode returns error instead of raising."""
        result = extract("not json at all", strict=False)
        assert not result.success
        assert len(result.errors) == 1
        assert result.errors[0].error_type == MALFORMED_JSON

    def test_strict_raises_on_missing_fields(self):
        """Strict mode raises on action with missing required fields."""
        bad_json = json.dumps({"actions": [{"tool": "nmap"}]})
        with pytest.raises(ValueError, match="missing required fields"):
            extract(bad_json)

    def test_permissive_skips_bad_actions(self):
        """Permissive mode skips bad actions, processes good ones."""
        mixed = json.dumps({
            "actions": [
                {"bad": "action"},
                NMAP_ACTION,
            ],
        })
        result = extract(mixed, strict=False)
        assert result.partial
        assert result.stats.events_parsed == 1
        assert result.stats.events_dropped == 1
        assert len(result.errors) == 1

    def test_strict_raises_on_non_list_actions(self):
        """Strict mode raises when 'actions' is not a list."""
        bad_json = json.dumps({"actions": "not_a_list"})
        with pytest.raises(ValueError, match="must be a list"):
            extract(bad_json)

    def test_permissive_handles_non_list_actions(self):
        """Permissive mode returns error when 'actions' is not a list."""
        bad_json = json.dumps({"actions": "not_a_list"})
        result = extract(bad_json, strict=False)
        assert not result.success
        assert result.errors[0].error_type == MALFORMED_JSON


# =============================================================================
# Edge Cases
# =============================================================================


class TestEdgeCases:
    """Edge case tests."""

    def test_bytes_input(self):
        """Extractor handles bytes input."""
        result = extract(FULL_PENTEST_JSON.encode("utf-8"))
        assert result.success

    def test_z_suffix_timestamp(self):
        """Timestamps with Z suffix are parsed correctly."""
        action = {**NMAP_ACTION, "timestamp": "2026-03-15T10:30:00Z"}
        result = extract(single_action_json(action))
        assert result.success

    def test_missing_parameters_field(self):
        """Action without 'parameters' field defaults to empty string."""
        action = {
            "action_id": "act-no-params",
            "tool": "nmap",
            "target": "10.0.0.1",
            "timestamp": "2026-03-15T10:30:00+00:00",
            "result": {"open_ports": []},
        }
        result = extract(single_action_json(action))
        assert result.success
        param_facts = [f for f in result.facts if f.field == "parameters"]
        assert param_facts[0].value == ""

    def test_result_not_dict_skipped(self):
        """Action with non-dict result is skipped."""
        action = {
            "action_id": "act-bad-result",
            "tool": "nmap",
            "target": "10.0.0.1",
            "timestamp": "2026-03-15T10:30:00+00:00",
            "result": "string-not-dict",
        }
        result = extract(single_action_json(action), strict=False)
        assert result.stats.events_dropped == 1

    def test_invalid_timestamp_skipped(self):
        """Action with unparseable timestamp is skipped."""
        action = {**NMAP_ACTION, "timestamp": "not-a-date"}
        result = extract(single_action_json(action), strict=False)
        assert result.stats.events_dropped == 1

    def test_nmap_malformed_port_entry_skipped(self):
        """Nmap port entry without 'port' key is silently skipped."""
        action = {**NMAP_ACTION, "result": {"open_ports": [{"service": "http"}]}}
        result = extract(single_action_json(action))
        port_facts = [f for f in result.facts if f.field == "port"]
        assert len(port_facts) == 0

    def test_tool_name_normalized(self):
        """Tool name is lowercased and stripped."""
        action = {**NMAP_ACTION, "tool": "  Nmap  "}
        result = extract(single_action_json(action))
        assert result.success
        tool_facts = [f for f in result.facts if f.field == "tool"]
        assert tool_facts[0].value == "nmap"

    def test_facts_load_into_evidence_packet(self):
        """Extracted facts can be loaded into an EvidencePacket and frozen."""
        result = extract(FULL_PENTEST_JSON)
        from datetime import datetime, timezone
        packet = EvidencePacket(
            packet_id="test-pentagi-packet",
            time_window=TimeWindow(
                start=datetime(2026, 3, 15, 10, 0, tzinfo=timezone.utc),
                end=datetime(2026, 3, 15, 12, 0, tzinfo=timezone.utc),
            ),
        )
        for fact in result.facts:
            packet.add_fact(fact)
        packet.freeze()
        assert packet.is_frozen
        assert packet.fact_count == len(result.facts)

    def test_all_facts_verify_hash(self):
        """All extracted facts pass hash verification."""
        result = extract(FULL_PENTEST_JSON)
        for fact in result.facts:
            assert fact.verify_hash(), f"Hash mismatch for {fact.fact_id}"

    def test_action_not_dict_skipped(self):
        """Non-dict entries in actions array are skipped."""
        bad_json = json.dumps({"actions": ["not_a_dict", NMAP_ACTION]})
        result = extract(bad_json, strict=False)
        assert result.stats.events_parsed == 1
        assert result.stats.events_dropped == 1
