"""Tests for BSD Syslog evidence extractor.

Tests validate:
1. SSH auth event extraction (accepted, failed, invalid user)
2. Firewall event extraction (UFW BLOCK, ALLOW)
3. Sudo event extraction (command, auth failure)
4. Systemd event extraction (started, stopping, stopped)
5. Strict vs permissive mode
6. Provenance stamping
7. ExtractionStats accuracy
8. Protocol compliance
9. Edge cases
"""

import pytest
from datetime import datetime

from ares.dialectic.evidence.extractors.protocol import (
    ExtractionError,
    ExtractorProtocol,
)
from ares.dialectic.evidence.extractors.syslog import (
    SyslogExtractor,
    SyslogHeader,
    MALFORMED_HEADER,
    UNKNOWN_APPLICATION,
    MISSING_FIELD,
    INVALID_PRIORITY,
    SYSLOG_FACILITIES,
    SYSLOG_SEVERITIES,
)
from ares.dialectic.evidence.fact import EntityType
from ares.dialectic.evidence.provenance import SourceType
from ares.dialectic.evidence.packet import EvidencePacket, TimeWindow


# =============================================================================
# Test Fixtures
# =============================================================================

# Fixed year for deterministic tests
TEST_YEAR = 2026

# SSH events
SSH_ACCEPTED = '<38>Mar  4 14:22:01 webserver01 sshd[12345]: Accepted publickey for admin from 10.0.1.50 port 52341 ssh2'
SSH_FAILED = '<38>Mar  4 14:22:02 webserver01 sshd[12345]: Failed password for root from 203.0.113.50 port 44231 ssh2'
SSH_INVALID_USER = '<38>Mar  4 14:22:03 webserver01 sshd[12345]: Invalid user oracle from 198.51.100.23 port 39821'

# Firewall events
UFW_BLOCK = '<4>Mar  4 14:30:00 fw01 kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00:1a:2b:3c:4d:5e SRC=203.0.113.50 DST=10.0.1.100 LEN=52 TTO=128 PROTO=TCP SPT=44231 DPT=22 WINDOW=65535 SYN'
UFW_ALLOW = '<4>Mar  4 14:30:01 fw01 kernel: [UFW ALLOW] IN=eth0 OUT= SRC=10.0.1.50 DST=10.0.1.100 PROTO=TCP SPT=52341 DPT=443'

# Sudo events
SUDO_COMMAND = '<38>Mar  4 14:35:00 webserver01 sudo: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/usr/bin/apt update'
SUDO_AUTH_FAIL = '<38>Mar  4 14:35:01 webserver01 sudo: pam_unix(sudo:auth): authentication failure; logname=admin uid=1000 euid=0 tty=/dev/pts/0 ruser=admin rhost=  user=admin'

# Systemd events
SYSTEMD_START = '<30>Mar  4 14:40:00 webserver01 systemd[1]: Started OpenSSH server daemon.'
SYSTEMD_STOP = '<30>Mar  4 14:40:01 webserver01 systemd[1]: Stopping firewalld - dynamic firewall daemon...'

# Malformed / edge case lines
MALFORMED_LINE = 'This is not a syslog line at all'
UNSUPPORTED_APP = '<38>Mar  4 14:50:00 webserver01 nginx[999]: GET /index.html 200'
EMPTY_INPUT = ''

# Realistic mixed stream
REALISTIC_STREAM = '\n'.join([
    SSH_FAILED,
    SSH_FAILED,
    SSH_FAILED,
    UFW_BLOCK,
    SSH_ACCEPTED,
    SUDO_COMMAND,
])

# Brute-force stream (50+ lines)
BRUTE_FORCE_STREAM = '\n'.join(
    [f'<38>Mar  4 14:{i // 60:02d}:{i % 60:02d} webserver01 sshd[{12345 + i}]: Failed password for root from 203.0.113.50 port {44000 + i} ssh2'
     for i in range(55)]
)


# =============================================================================
# Helper
# =============================================================================

def extract(line: str, *, strict: bool = True, source_ref: str = "test:syslog") -> "ExtractionResult":
    """Shorthand extraction helper for tests."""
    extractor = SyslogExtractor()
    return extractor.extract(line, source_ref=source_ref, strict=strict, year=TEST_YEAR)


# =============================================================================
# Protocol Compliance Tests
# =============================================================================


class TestSyslogProtocolCompliance:
    """Tests for ExtractorProtocol compliance."""

    def test_implements_extractor_protocol(self) -> None:
        """SyslogExtractor implements ExtractorProtocol."""
        extractor = SyslogExtractor()
        assert isinstance(extractor, ExtractorProtocol)

    def test_has_version_attribute(self) -> None:
        """Extractor has VERSION class attribute."""
        assert hasattr(SyslogExtractor, "VERSION")
        assert isinstance(SyslogExtractor.VERSION, str)

    def test_version_is_semantic(self) -> None:
        """VERSION follows semantic versioning."""
        parts = SyslogExtractor.VERSION.split(".")
        assert len(parts) == 3
        for part in parts:
            assert part.isdigit()

    def test_extract_returns_extraction_result(self) -> None:
        """extract() returns ExtractionResult."""
        result = extract(SSH_ACCEPTED)
        assert hasattr(result, "facts")
        assert hasattr(result, "errors")
        assert hasattr(result, "stats")
        assert hasattr(result, "source_ref")
        assert hasattr(result, "extractor_version")

    def test_extractor_version_in_result(self) -> None:
        """Result contains correct extractor version."""
        result = extract(SSH_ACCEPTED)
        assert result.extractor_version == SyslogExtractor.VERSION


# =============================================================================
# SSH Accepted Tests
# =============================================================================


class TestSSHAcceptedExtraction:
    """Tests for SSH accepted auth event extraction."""

    def test_ssh_accepted_produces_facts(self) -> None:
        """SSH accepted event produces expected facts."""
        result = extract(SSH_ACCEPTED)
        assert result.success
        assert len(result.facts) == 7

    def test_ssh_accepted_entity_id_format(self) -> None:
        """Entity ID follows user:name@hostname format."""
        result = extract(SSH_ACCEPTED)
        entity_ids = {f.entity_id for f in result.facts}
        assert "user:admin@webserver01" in entity_ids

    def test_ssh_accepted_event_type(self) -> None:
        """Event type is ssh_accepted."""
        result = extract(SSH_ACCEPTED)
        et = next(f for f in result.facts if f.field == "event_type")
        assert et.value == "ssh_accepted"

    def test_ssh_accepted_auth_method(self) -> None:
        """Auth method is extracted."""
        result = extract(SSH_ACCEPTED)
        am = next(f for f in result.facts if f.field == "auth_method")
        assert am.value == "publickey"

    def test_ssh_accepted_username(self) -> None:
        """Username is extracted."""
        result = extract(SSH_ACCEPTED)
        u = next(f for f in result.facts if f.field == "username")
        assert u.value == "admin"

    def test_ssh_accepted_source_ip(self) -> None:
        """Source IP is extracted."""
        result = extract(SSH_ACCEPTED)
        ip = next(f for f in result.facts if f.field == "source_ip")
        assert ip.value == "10.0.1.50"

    def test_ssh_accepted_source_port(self) -> None:
        """Source port is extracted as integer."""
        result = extract(SSH_ACCEPTED)
        port = next(f for f in result.facts if f.field == "source_port")
        assert port.value == 52341

    def test_ssh_accepted_facility(self) -> None:
        """Facility is extracted."""
        result = extract(SSH_ACCEPTED)
        fac = next(f for f in result.facts if f.field == "facility")
        # Priority 38 = facility 4 (auth) * 8 + severity 6
        assert fac.value == "auth"

    def test_ssh_accepted_severity(self) -> None:
        """Severity is extracted."""
        result = extract(SSH_ACCEPTED)
        sev = next(f for f in result.facts if f.field == "severity")
        assert sev.value == "informational"

    def test_ssh_accepted_timestamp(self) -> None:
        """Timestamp is parsed correctly."""
        result = extract(SSH_ACCEPTED)
        for fact in result.facts:
            assert fact.timestamp == datetime(2026, 3, 4, 14, 22, 1)


# =============================================================================
# SSH Failed Tests
# =============================================================================


class TestSSHFailedExtraction:
    """Tests for SSH failed auth event extraction."""

    def test_ssh_failed_produces_facts(self) -> None:
        """SSH failed event produces expected facts."""
        result = extract(SSH_FAILED)
        assert result.success
        assert len(result.facts) == 8

    def test_ssh_failed_event_type(self) -> None:
        """Event type is ssh_failed."""
        result = extract(SSH_FAILED)
        et = next(f for f in result.facts if f.field == "event_type")
        assert et.value == "ssh_failed"

    def test_ssh_failed_entity_id(self) -> None:
        """Entity ID for failed auth is user:root@hostname."""
        result = extract(SSH_FAILED)
        entity_ids = {f.entity_id for f in result.facts}
        assert "user:root@webserver01" in entity_ids

    def test_ssh_failed_failure_reason(self) -> None:
        """Failure reason is extracted."""
        result = extract(SSH_FAILED)
        fr = next(f for f in result.facts if f.field == "failure_reason")
        assert fr.value == "failed_password"

    def test_ssh_failed_source_ip(self) -> None:
        """Source IP is extracted."""
        result = extract(SSH_FAILED)
        ip = next(f for f in result.facts if f.field == "source_ip")
        assert ip.value == "203.0.113.50"

    def test_ssh_failed_source_port(self) -> None:
        """Source port is extracted."""
        result = extract(SSH_FAILED)
        port = next(f for f in result.facts if f.field == "source_port")
        assert port.value == 44231


# =============================================================================
# SSH Invalid User Tests
# =============================================================================


class TestSSHInvalidUserExtraction:
    """Tests for SSH invalid user event extraction."""

    def test_ssh_invalid_user_produces_facts(self) -> None:
        """SSH invalid user event produces expected facts."""
        result = extract(SSH_INVALID_USER)
        assert result.success
        assert len(result.facts) == 6

    def test_ssh_invalid_user_event_type(self) -> None:
        """Event type is ssh_invalid_user."""
        result = extract(SSH_INVALID_USER)
        et = next(f for f in result.facts if f.field == "event_type")
        assert et.value == "ssh_invalid_user"

    def test_ssh_invalid_user_entity_id(self) -> None:
        """Entity ID contains the invalid username."""
        result = extract(SSH_INVALID_USER)
        entity_ids = {f.entity_id for f in result.facts}
        assert "user:oracle@webserver01" in entity_ids

    def test_ssh_invalid_user_source_ip(self) -> None:
        """Source IP is extracted."""
        result = extract(SSH_INVALID_USER)
        ip = next(f for f in result.facts if f.field == "source_ip")
        assert ip.value == "198.51.100.23"

    def test_ssh_invalid_user_source_port(self) -> None:
        """Source port is extracted."""
        result = extract(SSH_INVALID_USER)
        port = next(f for f in result.facts if f.field == "source_port")
        assert port.value == 39821


# =============================================================================
# Firewall Block Tests
# =============================================================================


class TestFirewallBlockExtraction:
    """Tests for UFW BLOCK event extraction."""

    def test_ufw_block_produces_facts(self) -> None:
        """UFW BLOCK event produces expected facts."""
        result = extract(UFW_BLOCK)
        assert result.success
        assert len(result.facts) >= 8

    def test_ufw_block_event_type(self) -> None:
        """Event type is firewall_block."""
        result = extract(UFW_BLOCK)
        et = next(f for f in result.facts if f.field == "event_type")
        assert et.value == "firewall_block"

    def test_ufw_block_action(self) -> None:
        """Action is BLOCK."""
        result = extract(UFW_BLOCK)
        action = next(f for f in result.facts if f.field == "action")
        assert action.value == "BLOCK"

    def test_ufw_block_entity_id_format(self) -> None:
        """Entity ID follows connection:src:port->dst:port format."""
        result = extract(UFW_BLOCK)
        entity_ids = {f.entity_id for f in result.facts}
        assert "connection:203.0.113.50:44231->10.0.1.100:22" in entity_ids

    def test_ufw_block_src_ip(self) -> None:
        """Source IP is extracted."""
        result = extract(UFW_BLOCK)
        ip = next(f for f in result.facts if f.field == "src_ip")
        assert ip.value == "203.0.113.50"

    def test_ufw_block_dst_ip(self) -> None:
        """Destination IP is extracted."""
        result = extract(UFW_BLOCK)
        ip = next(f for f in result.facts if f.field == "dst_ip")
        assert ip.value == "10.0.1.100"

    def test_ufw_block_protocol(self) -> None:
        """Protocol is extracted."""
        result = extract(UFW_BLOCK)
        proto = next(f for f in result.facts if f.field == "protocol")
        assert proto.value == "TCP"

    def test_ufw_block_ports(self) -> None:
        """Source and destination ports are extracted."""
        result = extract(UFW_BLOCK)
        spt = next(f for f in result.facts if f.field == "src_port")
        dpt = next(f for f in result.facts if f.field == "dst_port")
        assert spt.value == 44231
        assert dpt.value == 22

    def test_ufw_block_interface(self) -> None:
        """Interface is extracted."""
        result = extract(UFW_BLOCK)
        iface = next(f for f in result.facts if f.field == "interface")
        assert iface.value == "eth0"

    def test_ufw_block_facility(self) -> None:
        """Facility is kern (priority 4 = facility 0)."""
        result = extract(UFW_BLOCK)
        fac = next(f for f in result.facts if f.field == "facility")
        assert fac.value == "kern"


# =============================================================================
# Firewall Allow Tests
# =============================================================================


class TestFirewallAllowExtraction:
    """Tests for UFW ALLOW event extraction."""

    def test_ufw_allow_produces_facts(self) -> None:
        """UFW ALLOW event produces expected facts."""
        result = extract(UFW_ALLOW)
        assert result.success

    def test_ufw_allow_event_type(self) -> None:
        """Event type is firewall_allow."""
        result = extract(UFW_ALLOW)
        et = next(f for f in result.facts if f.field == "event_type")
        assert et.value == "firewall_allow"

    def test_ufw_allow_action(self) -> None:
        """Action is ALLOW."""
        result = extract(UFW_ALLOW)
        action = next(f for f in result.facts if f.field == "action")
        assert action.value == "ALLOW"

    def test_ufw_allow_dst_port(self) -> None:
        """Destination port 443 is extracted."""
        result = extract(UFW_ALLOW)
        dpt = next(f for f in result.facts if f.field == "dst_port")
        assert dpt.value == 443


# =============================================================================
# Sudo Command Tests
# =============================================================================


class TestSudoCommandExtraction:
    """Tests for sudo command event extraction."""

    def test_sudo_command_produces_facts(self) -> None:
        """Sudo command event produces expected facts."""
        result = extract(SUDO_COMMAND)
        assert result.success
        assert len(result.facts) == 8

    def test_sudo_command_event_type(self) -> None:
        """Event type is sudo_command."""
        result = extract(SUDO_COMMAND)
        et = next(f for f in result.facts if f.field == "event_type")
        assert et.value == "sudo_command"

    def test_sudo_command_entity_id(self) -> None:
        """Entity ID follows user:name@hostname format."""
        result = extract(SUDO_COMMAND)
        entity_ids = {f.entity_id for f in result.facts}
        assert "user:admin@webserver01" in entity_ids

    def test_sudo_command_invoking_user(self) -> None:
        """Invoking user is extracted."""
        result = extract(SUDO_COMMAND)
        u = next(f for f in result.facts if f.field == "invoking_user")
        assert u.value == "admin"

    def test_sudo_command_target_user(self) -> None:
        """Target user is extracted."""
        result = extract(SUDO_COMMAND)
        u = next(f for f in result.facts if f.field == "target_user")
        assert u.value == "root"

    def test_sudo_command_value(self) -> None:
        """Command is extracted."""
        result = extract(SUDO_COMMAND)
        cmd = next(f for f in result.facts if f.field == "command")
        assert cmd.value == "/usr/bin/apt update"

    def test_sudo_command_tty(self) -> None:
        """TTY is extracted."""
        result = extract(SUDO_COMMAND)
        tty = next(f for f in result.facts if f.field == "tty")
        assert tty.value == "pts/0"

    def test_sudo_command_working_directory(self) -> None:
        """Working directory is extracted."""
        result = extract(SUDO_COMMAND)
        pwd = next(f for f in result.facts if f.field == "working_directory")
        assert pwd.value == "/home/admin"


# =============================================================================
# Sudo Auth Failure Tests
# =============================================================================


class TestSudoAuthFailExtraction:
    """Tests for sudo PAM auth failure event extraction."""

    def test_sudo_auth_fail_produces_facts(self) -> None:
        """Sudo auth failure event produces expected facts."""
        result = extract(SUDO_AUTH_FAIL)
        assert result.success
        assert len(result.facts) == 5

    def test_sudo_auth_fail_event_type(self) -> None:
        """Event type is sudo_auth_failure."""
        result = extract(SUDO_AUTH_FAIL)
        et = next(f for f in result.facts if f.field == "event_type")
        assert et.value == "sudo_auth_failure"

    def test_sudo_auth_fail_username(self) -> None:
        """Username is extracted from PAM detail."""
        result = extract(SUDO_AUTH_FAIL)
        u = next(f for f in result.facts if f.field == "username")
        assert u.value == "admin"

    def test_sudo_auth_fail_failure_reason(self) -> None:
        """Failure reason is authentication_failure."""
        result = extract(SUDO_AUTH_FAIL)
        fr = next(f for f in result.facts if f.field == "failure_reason")
        assert fr.value == "authentication_failure"


# =============================================================================
# Systemd Tests
# =============================================================================


class TestSystemdExtraction:
    """Tests for systemd service event extraction."""

    def test_systemd_start_produces_facts(self) -> None:
        """Systemd started event produces expected facts."""
        result = extract(SYSTEMD_START)
        assert result.success
        assert len(result.facts) == 5

    def test_systemd_start_event_type(self) -> None:
        """Event type is service_started."""
        result = extract(SYSTEMD_START)
        et = next(f for f in result.facts if f.field == "event_type")
        assert et.value == "service_started"

    def test_systemd_start_service_name(self) -> None:
        """Service name is extracted."""
        result = extract(SYSTEMD_START)
        sn = next(f for f in result.facts if f.field == "service_name")
        assert sn.value == "OpenSSH server daemon"

    def test_systemd_start_action(self) -> None:
        """Action is started."""
        result = extract(SYSTEMD_START)
        a = next(f for f in result.facts if f.field == "action")
        assert a.value == "started"

    def test_systemd_start_entity_id(self) -> None:
        """Entity ID follows service:name@hostname format."""
        result = extract(SYSTEMD_START)
        entity_ids = {f.entity_id for f in result.facts}
        assert "service:OpenSSH server daemon@webserver01" in entity_ids

    def test_systemd_stop_event_type(self) -> None:
        """Systemd stopping event has correct event type."""
        result = extract(SYSTEMD_STOP)
        et = next(f for f in result.facts if f.field == "event_type")
        assert et.value == "service_stopping"

    def test_systemd_stop_service_name(self) -> None:
        """Stopping event extracts service name."""
        result = extract(SYSTEMD_STOP)
        sn = next(f for f in result.facts if f.field == "service_name")
        assert sn.value == "firewalld - dynamic firewall daemon"

    def test_systemd_stopped_event(self) -> None:
        """Systemd stopped event parses correctly."""
        line = '<30>Mar  4 14:40:02 webserver01 systemd[1]: Stopped OpenSSH server daemon.'
        result = extract(line)
        et = next(f for f in result.facts if f.field == "event_type")
        assert et.value == "service_stopped"


# =============================================================================
# Provenance Tests
# =============================================================================


class TestProvenanceStamping:
    """Tests for provenance stamping on all facts."""

    def test_source_type_is_syslog(self) -> None:
        """All facts have SYSLOG source type."""
        result = extract(SSH_ACCEPTED)
        for fact in result.facts:
            assert fact.provenance.source_type == SourceType.SYSLOG

    def test_source_id_matches_source_ref(self) -> None:
        """source_id matches the source_ref parameter."""
        result = extract(SSH_ACCEPTED, source_ref="webserver01:auth:2026-03-04")
        for fact in result.facts:
            assert fact.provenance.source_id == "webserver01:auth:2026-03-04"

    def test_parser_version_matches(self) -> None:
        """parser_version matches extractor VERSION."""
        result = extract(SSH_ACCEPTED)
        for fact in result.facts:
            assert fact.provenance.parser_version == SyslogExtractor.VERSION

    def test_raw_reference_contains_line_number(self) -> None:
        """raw_reference contains line number."""
        result = extract(SSH_ACCEPTED)
        for fact in result.facts:
            assert fact.provenance.raw_reference == "line=1"

    def test_extracted_at_is_valid(self) -> None:
        """extracted_at is a valid datetime."""
        result = extract(SSH_ACCEPTED)
        for fact in result.facts:
            assert isinstance(fact.provenance.extracted_at, datetime)

    def test_firewall_provenance_is_syslog(self) -> None:
        """Firewall facts also have SYSLOG source type."""
        result = extract(UFW_BLOCK)
        for fact in result.facts:
            assert fact.provenance.source_type == SourceType.SYSLOG

    def test_sudo_provenance_is_syslog(self) -> None:
        """Sudo facts have SYSLOG source type."""
        result = extract(SUDO_COMMAND)
        for fact in result.facts:
            assert fact.provenance.source_type == SourceType.SYSLOG

    def test_systemd_provenance_is_syslog(self) -> None:
        """Systemd facts have SYSLOG source type."""
        result = extract(SYSTEMD_START)
        for fact in result.facts:
            assert fact.provenance.source_type == SourceType.SYSLOG

    def test_multiline_raw_reference_tracks_lines(self) -> None:
        """Multi-line input provenance tracks correct line numbers."""
        stream = '\n'.join([SSH_ACCEPTED, UFW_BLOCK])
        result = extract(stream)
        # SSH facts should reference line 1, firewall facts line 2
        ssh_facts = [f for f in result.facts if "ssh" in f.fact_id]
        fw_facts = [f for f in result.facts if "fw" in f.fact_id]
        for f in ssh_facts:
            assert f.provenance.raw_reference == "line=1"
        for f in fw_facts:
            assert f.provenance.raw_reference == "line=2"


# =============================================================================
# Strict Mode Tests
# =============================================================================


class TestStrictMode:
    """Tests for strict mode behavior."""

    def test_strict_raises_on_malformed_line(self) -> None:
        """Strict mode raises ValueError on malformed line."""
        with pytest.raises(ValueError, match="does not match BSD syslog format"):
            extract(MALFORMED_LINE, strict=True)

    def test_strict_raises_on_unsupported_application(self) -> None:
        """Strict mode raises on unsupported application."""
        with pytest.raises(ValueError, match="unsupported application"):
            extract(UNSUPPORTED_APP, strict=True)

    def test_strict_is_default(self) -> None:
        """Strict mode is the default."""
        with pytest.raises(ValueError):
            extract(MALFORMED_LINE)

    def test_strict_raises_on_first_bad_line(self) -> None:
        """Strict mode raises on the first bad line in multi-line input."""
        stream = MALFORMED_LINE + '\n' + SSH_ACCEPTED
        with pytest.raises(ValueError):
            extract(stream, strict=True)

    def test_strict_valid_after_valid_succeeds(self) -> None:
        """Strict mode succeeds when all lines are valid."""
        stream = SSH_ACCEPTED + '\n' + SSH_FAILED
        result = extract(stream, strict=True)
        assert result.success

    def test_empty_input_returns_empty_result(self) -> None:
        """Empty input returns empty result (not an error)."""
        result = extract('', strict=True)
        assert result.success
        assert len(result.facts) == 0
        assert result.stats.events_seen == 0

    def test_blank_lines_only_returns_empty_result(self) -> None:
        """Input with only blank lines returns empty result."""
        result = extract('\n\n  \n\n', strict=True)
        assert result.success
        assert result.stats.events_seen == 0

    def test_strict_raises_on_unrecognized_sshd_message(self) -> None:
        """Strict mode raises when sshd message pattern is not recognized."""
        line = '<38>Mar  4 14:22:01 webserver01 sshd[12345]: Connection closed by authenticating user admin 10.0.1.50 port 52341 [preauth]'
        with pytest.raises(ValueError, match="no recognizable pattern"):
            extract(line, strict=True)


# =============================================================================
# Permissive Mode Tests
# =============================================================================


class TestPermissiveMode:
    """Tests for permissive mode behavior."""

    def test_permissive_collects_errors(self) -> None:
        """Permissive mode collects errors without raising."""
        result = extract(MALFORMED_LINE, strict=False)
        assert not result.success
        assert len(result.errors) > 0

    def test_permissive_returns_partial_results(self) -> None:
        """Permissive mode returns partial results."""
        stream = SSH_ACCEPTED + '\n' + MALFORMED_LINE
        result = extract(stream, strict=False)
        assert len(result.facts) > 0
        assert len(result.errors) > 0
        assert result.partial

    def test_permissive_error_type_malformed_header(self) -> None:
        """Malformed lines get MALFORMED_HEADER error type."""
        result = extract(MALFORMED_LINE, strict=False)
        assert result.errors[0].error_type == MALFORMED_HEADER

    def test_permissive_error_type_unknown_application(self) -> None:
        """Unsupported app gets UNKNOWN_APPLICATION error type."""
        result = extract(UNSUPPORTED_APP, strict=False)
        assert result.errors[0].error_type == UNKNOWN_APPLICATION

    def test_permissive_error_snippet_truncated(self) -> None:
        """Error snippets are truncated to 200 chars."""
        long_line = '<38>Mar  4 14:22:01 webserver01 nginx[999]: ' + 'x' * 300
        result = extract(long_line, strict=False)
        assert len(result.errors) > 0
        assert len(result.errors[0].raw_snippet) <= 200

    def test_permissive_error_contains_line_number(self) -> None:
        """Errors contain the correct line number."""
        stream = SSH_ACCEPTED + '\n' + MALFORMED_LINE
        result = extract(stream, strict=False)
        error = result.errors[0]
        assert error.line_number == 2

    def test_permissive_continues_after_error(self) -> None:
        """Permissive mode continues parsing after errors."""
        stream = MALFORMED_LINE + '\n' + SSH_ACCEPTED + '\n' + MALFORMED_LINE
        result = extract(stream, strict=False)
        assert len(result.facts) > 0
        assert len(result.errors) == 2

    def test_permissive_unrecognized_message_is_missing_field(self) -> None:
        """Unrecognized message from supported app gets MISSING_FIELD error."""
        line = '<38>Mar  4 14:22:01 webserver01 sshd[12345]: Connection closed by authenticating user admin 10.0.1.50 port 52341 [preauth]'
        result = extract(line, strict=False)
        assert len(result.errors) == 1
        assert result.errors[0].error_type == MISSING_FIELD


# =============================================================================
# ExtractionStats Tests
# =============================================================================


class TestExtractionStatsAccuracy:
    """Tests for ExtractionStats accuracy."""

    def test_single_event_stats(self) -> None:
        """Single valid event stats are correct."""
        result = extract(SSH_ACCEPTED)
        assert result.stats.events_seen == 1
        assert result.stats.events_parsed == 1
        assert result.stats.events_dropped == 0
        assert result.stats.facts_emitted == len(result.facts)

    def test_mixed_stream_stats(self) -> None:
        """Mixed stream stats are correct."""
        result = extract(REALISTIC_STREAM)
        assert result.stats.events_seen == 6
        assert result.stats.events_parsed == 6
        assert result.stats.events_dropped == 0

    def test_events_dropped_on_malformed(self) -> None:
        """events_dropped counts malformed lines."""
        stream = MALFORMED_LINE + '\n' + SSH_ACCEPTED
        result = extract(stream, strict=False)
        assert result.stats.events_seen == 2
        assert result.stats.events_parsed == 1
        assert result.stats.events_dropped == 1

    def test_facts_emitted_matches_facts_len(self) -> None:
        """facts_emitted always equals len(facts)."""
        result = extract(REALISTIC_STREAM)
        assert result.stats.facts_emitted == len(result.facts)

    def test_stats_consistency(self) -> None:
        """parsed + dropped <= seen."""
        stream = SSH_ACCEPTED + '\n' + MALFORMED_LINE + '\n' + UFW_BLOCK
        result = extract(stream, strict=False)
        assert result.stats.events_parsed + result.stats.events_dropped <= result.stats.events_seen


# =============================================================================
# Input Format Tests
# =============================================================================


class TestInputFormats:
    """Tests for different input formats."""

    def test_accepts_bytes_input(self) -> None:
        """Extractor accepts bytes input."""
        extractor = SyslogExtractor()
        result = extractor.extract(
            SSH_ACCEPTED.encode("utf-8"),
            source_ref="test:syslog",
            year=TEST_YEAR,
        )
        assert result.success

    def test_accepts_string_input(self) -> None:
        """Extractor accepts string input."""
        result = extract(SSH_ACCEPTED)
        assert result.success

    def test_year_parameter(self) -> None:
        """Year parameter overrides default."""
        extractor = SyslogExtractor()
        result = extractor.extract(SSH_ACCEPTED, source_ref="test", year=2025)
        for fact in result.facts:
            assert fact.timestamp.year == 2025

    def test_default_year_is_current(self) -> None:
        """Default year is current year when not specified."""
        extractor = SyslogExtractor()
        result = extractor.extract(SSH_ACCEPTED, source_ref="test")
        current_year = datetime.utcnow().year
        for fact in result.facts:
            assert fact.timestamp.year == current_year


# =============================================================================
# Fact ID Uniqueness Tests
# =============================================================================


class TestFactIdUniqueness:
    """Tests for fact ID uniqueness."""

    def test_fact_ids_unique_within_event(self) -> None:
        """All fact IDs within a single event are unique."""
        result = extract(SSH_ACCEPTED)
        fact_ids = [f.fact_id for f in result.facts]
        assert len(fact_ids) == len(set(fact_ids))

    def test_fact_ids_unique_across_events(self) -> None:
        """Fact IDs are unique across multiple events."""
        stream = '\n'.join([SSH_ACCEPTED, SSH_FAILED, UFW_BLOCK, SUDO_COMMAND, SYSTEMD_START])
        result = extract(stream)
        fact_ids = [f.fact_id for f in result.facts]
        assert len(fact_ids) == len(set(fact_ids))

    def test_fact_id_contains_event_type_indicator(self) -> None:
        """Fact IDs contain event-type indicator for traceability."""
        result = extract(SSH_ACCEPTED)
        assert all("ssh-accepted" in f.fact_id for f in result.facts)

        result = extract(UFW_BLOCK)
        assert all("fw-block" in f.fact_id for f in result.facts)

        result = extract(SUDO_COMMAND)
        assert all("sudo-cmd" in f.fact_id for f in result.facts)

        result = extract(SYSTEMD_START)
        assert all("systemd-started" in f.fact_id for f in result.facts)

    def test_duplicate_timestamps_produce_unique_ids(self) -> None:
        """Multiple events with same timestamp still have unique fact IDs."""
        # Two SSH failed events with same timestamp but different ports
        line1 = '<38>Mar  4 14:22:02 webserver01 sshd[12345]: Failed password for root from 203.0.113.50 port 44231 ssh2'
        line2 = '<38>Mar  4 14:22:02 webserver01 sshd[12346]: Failed password for admin from 203.0.113.51 port 44232 ssh2'
        stream = line1 + '\n' + line2
        result = extract(stream)
        fact_ids = [f.fact_id for f in result.facts]
        assert len(fact_ids) == len(set(fact_ids))


# =============================================================================
# Entity Type Tests
# =============================================================================


class TestEntityTypes:
    """Tests for entity type on all facts."""

    def test_ssh_facts_are_node_type(self) -> None:
        """SSH facts have NODE entity type."""
        result = extract(SSH_ACCEPTED)
        for fact in result.facts:
            assert fact.entity_type == EntityType.NODE

    def test_firewall_facts_are_node_type(self) -> None:
        """Firewall facts have NODE entity type."""
        result = extract(UFW_BLOCK)
        for fact in result.facts:
            assert fact.entity_type == EntityType.NODE

    def test_sudo_facts_are_node_type(self) -> None:
        """Sudo facts have NODE entity type."""
        result = extract(SUDO_COMMAND)
        for fact in result.facts:
            assert fact.entity_type == EntityType.NODE

    def test_systemd_facts_are_node_type(self) -> None:
        """Systemd facts have NODE entity type."""
        result = extract(SYSTEMD_START)
        for fact in result.facts:
            assert fact.entity_type == EntityType.NODE


# =============================================================================
# Priority Parsing Tests
# =============================================================================


class TestPriorityParsing:
    """Tests for syslog priority field parsing."""

    def test_priority_38_is_auth_info(self) -> None:
        """Priority 38 = auth (4) * 8 + informational (6)."""
        result = extract(SSH_ACCEPTED)
        fac = next(f for f in result.facts if f.field == "facility")
        sev = next(f for f in result.facts if f.field == "severity")
        assert fac.value == "auth"
        assert sev.value == "informational"

    def test_priority_4_is_kern_warning(self) -> None:
        """Priority 4 = kern (0) * 8 + warning (4)."""
        result = extract(UFW_BLOCK)
        fac = next(f for f in result.facts if f.field == "facility")
        sev = next(f for f in result.facts if f.field == "severity")
        assert fac.value == "kern"
        assert sev.value == "warning"

    def test_priority_30_is_daemon_info(self) -> None:
        """Priority 30 = daemon (3) * 8 + informational (6)."""
        result = extract(SYSTEMD_START)
        fac = next(f for f in result.facts if f.field == "facility")
        sev = next(f for f in result.facts if f.field == "severity")
        assert fac.value == "daemon"
        assert sev.value == "informational"


# =============================================================================
# Timestamp Parsing Tests
# =============================================================================


class TestTimestampParsing:
    """Tests for syslog timestamp parsing."""

    def test_march_4_parsed(self) -> None:
        """Mar 4 14:22:01 is parsed correctly."""
        result = extract(SSH_ACCEPTED)
        for fact in result.facts:
            assert fact.timestamp == datetime(2026, 3, 4, 14, 22, 1)

    def test_single_digit_day_with_leading_space(self) -> None:
        """Single-digit day with leading space parses correctly."""
        line = '<38>Mar  4 14:22:01 host sshd[1]: Accepted publickey for user from 1.2.3.4 port 22 ssh2'
        result = extract(line)
        assert result.success

    def test_double_digit_day(self) -> None:
        """Double-digit day parses correctly."""
        line = '<38>Mar 14 14:22:01 host sshd[1]: Accepted publickey for user from 1.2.3.4 port 22 ssh2'
        result = extract(line)
        for fact in result.facts:
            assert fact.timestamp.day == 14

    def test_all_months_parse(self) -> None:
        """All 12 months parse correctly."""
        months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
                   "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
        for i, month in enumerate(months, 1):
            line = f'<38>{month}  1 00:00:00 host sshd[1]: Accepted publickey for user from 1.2.3.4 port 22 ssh2'
            result = extract(line)
            assert result.success
            assert result.facts[0].timestamp.month == i


# =============================================================================
# Integration Tests
# =============================================================================


class TestIntegration:
    """Integration tests for realistic scenarios."""

    def test_mixed_message_types(self) -> None:
        """Mixed message types parse correctly in single input."""
        stream = '\n'.join([SSH_ACCEPTED, UFW_BLOCK, SUDO_COMMAND, SYSTEMD_START])
        result = extract(stream)
        assert result.success
        assert result.stats.events_parsed == 4

        event_types = {f.value for f in result.facts if f.field == "event_type"}
        assert "ssh_accepted" in event_types
        assert "firewall_block" in event_types
        assert "sudo_command" in event_types
        assert "service_started" in event_types

    def test_realistic_stream_all_parsed(self) -> None:
        """Realistic stream parses all events."""
        result = extract(REALISTIC_STREAM)
        assert result.success
        assert result.stats.events_parsed == 6

    def test_large_input_performance(self) -> None:
        """Large input (55 lines) completes successfully."""
        result = extract(BRUTE_FORCE_STREAM)
        assert result.success
        assert result.stats.events_parsed == 55
        assert result.stats.facts_emitted == 55 * 8  # 8 facts per SSH failed

    def test_output_facts_addable_to_evidence_packet(self) -> None:
        """Extracted facts can be added to an EvidencePacket."""
        result = extract(SSH_ACCEPTED)
        assert result.success

        # Build a packet with extracted facts
        tw = TimeWindow(
            start=datetime(2026, 3, 4, 14, 0, 0),
            end=datetime(2026, 3, 4, 15, 0, 0),
        )
        packet = EvidencePacket(
            packet_id="test-syslog-001",
            time_window=tw,
        )
        for fact in result.facts:
            packet.add_fact(fact)
        packet.freeze()

        assert packet.fact_count == len(result.facts)
        # Packet should be frozen — adding should raise
        with pytest.raises(Exception):
            packet.add_fact(result.facts[0])

    def test_extraction_result_is_frozen(self) -> None:
        """ExtractionResult is frozen."""
        result = extract(SSH_ACCEPTED)
        with pytest.raises(AttributeError):
            result.source_ref = "modified"

    def test_syslog_header_is_frozen(self) -> None:
        """SyslogHeader dataclass is frozen."""
        header = SyslogHeader(
            priority=38, facility=4, severity=6,
            facility_name="authpriv", severity_name="informational",
            timestamp=datetime(2026, 3, 4, 14, 22, 1),
            hostname="host", application="sshd", pid=123,
            message="test", raw_line="test", line_number=1,
        )
        with pytest.raises(AttributeError):
            header.hostname = "modified"


# =============================================================================
# Edge Case Tests
# =============================================================================


class TestEdgeCases:
    """Tests for edge cases."""

    def test_empty_bytes_input(self) -> None:
        """Empty bytes input returns empty result."""
        extractor = SyslogExtractor()
        result = extractor.extract(b'', source_ref="test", year=TEST_YEAR)
        assert result.success
        assert result.stats.events_seen == 0

    def test_empty_string_input(self) -> None:
        """Empty string input returns empty result."""
        result = extract('', strict=True)
        assert result.success

    def test_only_blank_lines(self) -> None:
        """Input with only blank lines returns empty result."""
        result = extract('\n\n  \n  \n', strict=True)
        assert result.success
        assert result.stats.events_seen == 0

    def test_only_unparseable_lines_strict(self) -> None:
        """All unparseable lines raises in strict mode."""
        with pytest.raises(ValueError):
            extract('garbage\nmore garbage', strict=True)

    def test_only_unparseable_lines_permissive(self) -> None:
        """All unparseable lines collected in permissive mode."""
        result = extract('garbage\nmore garbage', strict=False)
        assert len(result.errors) == 2
        assert result.stats.events_dropped == 2
        assert result.stats.events_parsed == 0

    def test_very_long_line(self) -> None:
        """Very long line (>10000 chars) doesn't crash."""
        long_msg = 'x' * 10000
        line = f'<38>Mar  4 14:22:01 host sshd[1]: {long_msg}'
        # sshd with unrecognized message, permissive mode
        result = extract(line, strict=False)
        assert result.stats.events_seen == 1

    def test_non_ascii_hostname(self) -> None:
        """Non-ASCII characters in hostname don't crash."""
        line = '<38>Mar  4 14:22:01 h\u00f6st sshd[1]: Accepted publickey for user from 1.2.3.4 port 22 ssh2'
        result = extract(line)
        assert result.success

    def test_missing_pid_in_application(self) -> None:
        """Application without PID (e.g., sudo:) still parses."""
        # sudo messages typically don't have a PID
        result = extract(SUDO_COMMAND)
        assert result.success

    def test_application_with_slash(self) -> None:
        """Application name with slash (sshd/something) still matches."""
        # Some syslog daemons append facility info
        line = '<38>Mar  4 14:22:01 host sshd/auth[1]: Accepted publickey for user from 1.2.3.4 port 22 ssh2'
        # sshd/auth should be parsed as app_base=sshd
        result = extract(line)
        assert result.success

    def test_source_ref_propagated(self) -> None:
        """source_ref is propagated to result."""
        result = extract(SSH_ACCEPTED, source_ref="myfile.log")
        assert result.source_ref == "myfile.log"

    def test_hash_verification_on_facts(self) -> None:
        """Extracted facts have valid value hashes."""
        result = extract(SSH_ACCEPTED)
        for fact in result.facts:
            assert fact.verify_hash()
