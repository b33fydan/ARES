"""BSD Syslog (RFC 3164) evidence extractor.

Parses BSD-style syslog messages into Facts for dialectical reasoning.
Supports SSH auth, firewall (UFW/iptables), sudo, and systemd events.

Sensors don't get opinions — this extractor parses and stamps provenance,
reasoning happens downstream.
"""

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from ..provenance import Provenance, SourceType
from ..fact import Fact, EntityType
from .protocol import (
    ExtractionError,
    ExtractionStats,
    ExtractionResult,
)


# =============================================================================
# Constants
# =============================================================================

# Syslog facility codes (RFC 3164)
SYSLOG_FACILITIES = {
    0: "kern",
    1: "user",
    2: "mail",
    3: "daemon",
    4: "auth",
    5: "syslog",
    6: "lpr",
    7: "news",
    8: "uucp",
    9: "cron",
    10: "authpriv",
    11: "ftp",
    16: "local0",
    17: "local1",
    18: "local2",
    19: "local3",
    20: "local4",
    21: "local5",
    22: "local6",
    23: "local7",
}

# Syslog severity levels (RFC 3164)
SYSLOG_SEVERITIES = {
    0: "emergency",
    1: "alert",
    2: "critical",
    3: "error",
    4: "warning",
    5: "notice",
    6: "informational",
    7: "debug",
}

# Month abbreviations for syslog timestamp parsing
MONTH_MAP = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4,
    "May": 5, "Jun": 6, "Jul": 7, "Aug": 8,
    "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

# BSD syslog header pattern: <priority>MMM DD HH:MM:SS hostname app[pid]: message
# Also handles app without PID: <priority>MMM DD HH:MM:SS hostname app: message
SYSLOG_HEADER_RE = re.compile(
    r"^<(\d{1,3})>"                        # priority
    r"(\w{3})\s+(\d{1,2})\s+"             # month day
    r"(\d{2}):(\d{2}):(\d{2})\s+"         # HH:MM:SS
    r"(\S+)\s+"                            # hostname
    r"(\S+?)(?:\[(\d+)\])?:\s+"            # application[pid]:
    r"(.*)"                                # message
)

# SSH message patterns
SSH_ACCEPTED_RE = re.compile(
    r"^Accepted\s+(\S+)\s+for\s+(\S+)\s+from\s+(\S+)\s+port\s+(\d+)"
)
SSH_FAILED_RE = re.compile(
    r"^Failed\s+(\S+)\s+for\s+(?:invalid user\s+)?(\S+)\s+from\s+(\S+)\s+port\s+(\d+)"
)
SSH_INVALID_USER_RE = re.compile(
    r"^Invalid user\s+(\S+)\s+from\s+(\S+)\s+port\s+(\d+)"
)

# UFW/iptables firewall pattern
UFW_RE = re.compile(
    r"^\[UFW\s+(BLOCK|ALLOW|AUDIT|LIMIT)\]"
)

# Sudo command pattern: user : TTY=... ; PWD=... ; USER=... ; COMMAND=...
SUDO_COMMAND_RE = re.compile(
    r"^(\S+)\s+:\s+TTY=(\S+)\s+;\s+PWD=(\S+)\s+;\s+USER=(\S+)\s+;\s+COMMAND=(.*)"
)

# Sudo/PAM auth failure
SUDO_AUTH_FAIL_RE = re.compile(
    r"^pam_unix\(sudo:auth\):\s+authentication failure;(.*)$"
)

# Systemd service events
SYSTEMD_STARTED_RE = re.compile(
    r"^Started\s+(.+)\.$"
)
SYSTEMD_STOPPING_RE = re.compile(
    r"^Stopping\s+(.+)\.\.\.$"
)
SYSTEMD_STOPPED_RE = re.compile(
    r"^Stopped\s+(.+)\.$"
)

# Supported applications
SUPPORTED_APPLICATIONS = frozenset({"sshd", "kernel", "sudo", "systemd"})

# Error type constants for syslog-specific errors
MALFORMED_HEADER = "MALFORMED_HEADER"
UNKNOWN_APPLICATION = "UNKNOWN_APPLICATION"
MISSING_FIELD = "MISSING_FIELD"
INVALID_PRIORITY = "INVALID_PRIORITY"


# =============================================================================
# Intermediate parsed types
# =============================================================================


@dataclass(frozen=True)
class SyslogHeader:
    """Parsed syslog header fields.

    Attributes:
        priority: Raw priority value from <priority> field.
        facility: Decoded facility code (0-23).
        severity: Decoded severity level (0-7).
        facility_name: Human-readable facility name.
        severity_name: Human-readable severity name.
        timestamp: Parsed timestamp as datetime.
        hostname: Source hostname.
        application: Application name (e.g., sshd, kernel).
        pid: Process ID (None if not present).
        message: Message body after the header.
        raw_line: Original raw syslog line.
        line_number: Line number in input (1-based).
    """

    priority: int
    facility: int
    severity: int
    facility_name: str
    severity_name: str
    timestamp: datetime
    hostname: str
    application: str
    pid: Optional[int]
    message: str
    raw_line: str
    line_number: int


# =============================================================================
# Extractor
# =============================================================================


class SyslogExtractor:
    """Parses BSD syslog (RFC 3164) messages into Facts.

    Implements ExtractorProtocol. Handles SSH auth, firewall (UFW/iptables),
    sudo, and systemd service events from syslog streams.

    Each line is treated as an independent message. Lines that don't match
    the BSD syslog format are errors in strict mode, skipped in permissive mode.

    Attributes:
        VERSION: Semantic version of this extractor.
    """

    VERSION: str = "1.0.0"

    def extract(
        self,
        raw: bytes | str,
        *,
        source_ref: str,
        strict: bool = True,
        year: Optional[int] = None,
    ) -> ExtractionResult:
        """Parse syslog messages into Facts.

        Args:
            raw: Raw syslog data (bytes or string), one message per line.
            source_ref: Reference to data source for provenance tracking.
            strict: If True, raise on first error. If False, collect errors
                   and return partial results.
            year: Year to use for timestamps (syslog omits year).
                  Defaults to current year.

        Returns:
            ExtractionResult containing Facts, errors, and stats.

        Raises:
            ValueError: In strict mode, on first parse error.
        """
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8")

        if year is None:
            year = datetime.utcnow().year

        facts: list[Fact] = []
        errors: list[ExtractionError] = []
        events_seen = 0
        events_parsed = 0
        events_dropped = 0

        lines = raw.splitlines()

        for line_idx, line in enumerate(lines):
            # Skip blank lines
            if not line.strip():
                continue

            events_seen += 1
            line_number = line_idx + 1

            # Parse header
            header = self._parse_header(line, line_number, year)
            if header is None:
                events_dropped += 1
                error = ExtractionError(
                    line_number=line_number,
                    raw_snippet=line[:200],
                    error_type=MALFORMED_HEADER,
                    message=f"Line {line_number}: does not match BSD syslog format",
                )
                if strict:
                    raise ValueError(error.message)
                errors.append(error)
                continue

            # Validate priority
            if header.priority < 0 or header.priority > 191:
                events_dropped += 1
                error = ExtractionError(
                    line_number=line_number,
                    raw_snippet=line[:200],
                    error_type=INVALID_PRIORITY,
                    message=f"Line {line_number}: invalid priority {header.priority} (must be 0-191)",
                )
                if strict:
                    raise ValueError(error.message)
                errors.append(error)
                continue

            # Check application is supported
            app_base = header.application.split("/")[0]
            if app_base not in SUPPORTED_APPLICATIONS:
                events_dropped += 1
                error = ExtractionError(
                    line_number=line_number,
                    raw_snippet=line[:200],
                    error_type=UNKNOWN_APPLICATION,
                    message=f"Line {line_number}: unsupported application '{header.application}'",
                )
                if strict:
                    raise ValueError(error.message)
                errors.append(error)
                continue

            # Extract facts from message
            try:
                event_facts = self._extract_facts(header, source_ref)
                if event_facts:
                    facts.extend(event_facts)
                    events_parsed += 1
                else:
                    # Supported app but unrecognized message pattern
                    events_dropped += 1
                    error = ExtractionError(
                        line_number=line_number,
                        raw_snippet=line[:200],
                        error_type=MISSING_FIELD,
                        message=f"Line {line_number}: no recognizable pattern in {app_base} message",
                    )
                    if strict:
                        raise ValueError(error.message)
                    errors.append(error)
            except ValueError as e:
                events_dropped += 1
                error = ExtractionError(
                    line_number=line_number,
                    raw_snippet=line[:200],
                    error_type=MISSING_FIELD,
                    message=str(e),
                )
                if strict:
                    raise
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

    def _parse_header(
        self, line: str, line_number: int, year: int
    ) -> Optional[SyslogHeader]:
        """Parse a BSD syslog line into a SyslogHeader.

        Args:
            line: Raw syslog line.
            line_number: Line number in input (1-based).
            year: Year to use for timestamp.

        Returns:
            SyslogHeader if parsed successfully, None otherwise.
        """
        match = SYSLOG_HEADER_RE.match(line)
        if not match:
            return None

        priority = int(match.group(1))
        month_str = match.group(2)
        day = int(match.group(3))
        hour = int(match.group(4))
        minute = int(match.group(5))
        second = int(match.group(6))
        hostname = match.group(7)
        application = match.group(8)
        pid_str = match.group(9)
        message = match.group(10)

        # Decode priority
        facility = priority // 8
        severity = priority % 8
        facility_name = SYSLOG_FACILITIES.get(facility, f"facility_{facility}")
        severity_name = SYSLOG_SEVERITIES.get(severity, f"severity_{severity}")

        # Parse month
        month = MONTH_MAP.get(month_str)
        if month is None:
            return None

        # Build timestamp
        try:
            timestamp = datetime(year, month, day, hour, minute, second)
        except ValueError:
            return None

        pid = int(pid_str) if pid_str else None

        return SyslogHeader(
            priority=priority,
            facility=facility,
            severity=severity,
            facility_name=facility_name,
            severity_name=severity_name,
            timestamp=timestamp,
            hostname=hostname,
            application=application,
            pid=pid,
            message=message,
            raw_line=line,
            line_number=line_number,
        )

    def _make_provenance(
        self, source_ref: str, raw_reference: str
    ) -> Provenance:
        """Create provenance for a fact.

        Args:
            source_ref: Data source reference.
            raw_reference: Reference within the source.

        Returns:
            Provenance instance with SYSLOG source type.
        """
        return Provenance(
            source_type=SourceType.SYSLOG,
            source_id=source_ref,
            parser_version=self.VERSION,
            raw_reference=raw_reference,
        )

    def _make_fact(
        self,
        fact_id: str,
        entity_id: str,
        field: str,
        value: object,
        timestamp: datetime,
        provenance: Provenance,
    ) -> Fact:
        """Create a Fact with standard entity type.

        Args:
            fact_id: Unique fact identifier.
            entity_id: Entity this fact describes.
            field: Field name.
            value: Field value.
            timestamp: When fact was observed.
            provenance: Source provenance.

        Returns:
            Fact instance.
        """
        return Fact(
            fact_id=fact_id,
            entity_id=entity_id,
            entity_type=EntityType.NODE,
            field=field,
            value=value,
            timestamp=timestamp,
            provenance=provenance,
        )

    def _extract_facts(
        self, header: SyslogHeader, source_ref: str
    ) -> list[Fact]:
        """Extract Facts from a parsed syslog message.

        Dispatches to application-specific handlers.

        Args:
            header: Parsed syslog header and message.
            source_ref: Source reference for provenance.

        Returns:
            List of Facts, or empty list if message not recognized.
        """
        app_base = header.application.split("/")[0]

        if app_base == "sshd":
            return self._extract_ssh_facts(header, source_ref)
        elif app_base == "kernel":
            return self._extract_firewall_facts(header, source_ref)
        elif app_base == "sudo":
            return self._extract_sudo_facts(header, source_ref)
        elif app_base == "systemd":
            return self._extract_systemd_facts(header, source_ref)
        else:
            return []

    # =========================================================================
    # SSH handlers
    # =========================================================================

    def _extract_ssh_facts(
        self, header: SyslogHeader, source_ref: str
    ) -> list[Fact]:
        """Extract facts from SSH (sshd) messages.

        Handles: Accepted auth, Failed auth, Invalid user.

        Args:
            header: Parsed syslog header.
            source_ref: Source reference for provenance.

        Returns:
            List of Facts, or empty list if not recognized.
        """
        msg = header.message

        # SSH Accepted
        match = SSH_ACCEPTED_RE.match(msg)
        if match:
            return self._make_ssh_accepted_facts(header, source_ref, match)

        # SSH Failed
        match = SSH_FAILED_RE.match(msg)
        if match:
            return self._make_ssh_failed_facts(header, source_ref, match)

        # SSH Invalid User
        match = SSH_INVALID_USER_RE.match(msg)
        if match:
            return self._make_ssh_invalid_user_facts(header, source_ref, match)

        return []

    def _make_ssh_accepted_facts(
        self, header: SyslogHeader, source_ref: str, match: re.Match
    ) -> list[Fact]:
        """Build facts for an SSH accepted auth event.

        Args:
            header: Parsed syslog header.
            source_ref: Source reference.
            match: Regex match with groups (auth_method, username, source_ip, port).

        Returns:
            List of Facts.
        """
        auth_method = match.group(1)
        username = match.group(2)
        source_ip = match.group(3)
        source_port = match.group(4)

        entity_id = f"user:{username}@{header.hostname}"
        ts_iso = header.timestamp.isoformat()
        base_id = f"ssh-accepted-{ts_iso}-{username}-{header.hostname}"
        provenance = self._make_provenance(source_ref, f"line={header.line_number}")

        return [
            self._make_fact(f"{base_id}-event_type", entity_id, "event_type", "ssh_accepted", header.timestamp, provenance),
            self._make_fact(f"{base_id}-auth_method", entity_id, "auth_method", auth_method, header.timestamp, provenance),
            self._make_fact(f"{base_id}-username", entity_id, "username", username, header.timestamp, provenance),
            self._make_fact(f"{base_id}-source_ip", entity_id, "source_ip", source_ip, header.timestamp, provenance),
            self._make_fact(f"{base_id}-source_port", entity_id, "source_port", int(source_port), header.timestamp, provenance),
            self._make_fact(f"{base_id}-facility", entity_id, "facility", header.facility_name, header.timestamp, provenance),
            self._make_fact(f"{base_id}-severity", entity_id, "severity", header.severity_name, header.timestamp, provenance),
        ]

    def _make_ssh_failed_facts(
        self, header: SyslogHeader, source_ref: str, match: re.Match
    ) -> list[Fact]:
        """Build facts for an SSH failed auth event.

        Args:
            header: Parsed syslog header.
            source_ref: Source reference.
            match: Regex match with groups (auth_method, username, source_ip, port).

        Returns:
            List of Facts.
        """
        auth_method = match.group(1)
        username = match.group(2)
        source_ip = match.group(3)
        source_port = match.group(4)

        entity_id = f"user:{username}@{header.hostname}"
        ts_iso = header.timestamp.isoformat()
        base_id = f"ssh-failed-{ts_iso}-{username}-{header.hostname}"
        provenance = self._make_provenance(source_ref, f"line={header.line_number}")

        return [
            self._make_fact(f"{base_id}-event_type", entity_id, "event_type", "ssh_failed", header.timestamp, provenance),
            self._make_fact(f"{base_id}-auth_method", entity_id, "auth_method", auth_method, header.timestamp, provenance),
            self._make_fact(f"{base_id}-username", entity_id, "username", username, header.timestamp, provenance),
            self._make_fact(f"{base_id}-source_ip", entity_id, "source_ip", source_ip, header.timestamp, provenance),
            self._make_fact(f"{base_id}-source_port", entity_id, "source_port", int(source_port), header.timestamp, provenance),
            self._make_fact(f"{base_id}-failure_reason", entity_id, "failure_reason", f"failed_{auth_method}", header.timestamp, provenance),
            self._make_fact(f"{base_id}-facility", entity_id, "facility", header.facility_name, header.timestamp, provenance),
            self._make_fact(f"{base_id}-severity", entity_id, "severity", header.severity_name, header.timestamp, provenance),
        ]

    def _make_ssh_invalid_user_facts(
        self, header: SyslogHeader, source_ref: str, match: re.Match
    ) -> list[Fact]:
        """Build facts for an SSH invalid user event.

        Args:
            header: Parsed syslog header.
            source_ref: Source reference.
            match: Regex match with groups (username, source_ip, port).

        Returns:
            List of Facts.
        """
        username = match.group(1)
        source_ip = match.group(2)
        source_port = match.group(3)

        entity_id = f"user:{username}@{header.hostname}"
        ts_iso = header.timestamp.isoformat()
        base_id = f"ssh-invalid-{ts_iso}-{username}-{header.hostname}"
        provenance = self._make_provenance(source_ref, f"line={header.line_number}")

        return [
            self._make_fact(f"{base_id}-event_type", entity_id, "event_type", "ssh_invalid_user", header.timestamp, provenance),
            self._make_fact(f"{base_id}-username", entity_id, "username", username, header.timestamp, provenance),
            self._make_fact(f"{base_id}-source_ip", entity_id, "source_ip", source_ip, header.timestamp, provenance),
            self._make_fact(f"{base_id}-source_port", entity_id, "source_port", int(source_port), header.timestamp, provenance),
            self._make_fact(f"{base_id}-facility", entity_id, "facility", header.facility_name, header.timestamp, provenance),
            self._make_fact(f"{base_id}-severity", entity_id, "severity", header.severity_name, header.timestamp, provenance),
        ]

    # =========================================================================
    # Firewall handlers
    # =========================================================================

    def _extract_firewall_facts(
        self, header: SyslogHeader, source_ref: str
    ) -> list[Fact]:
        """Extract facts from kernel/UFW firewall messages.

        Handles: UFW BLOCK, UFW ALLOW.

        Args:
            header: Parsed syslog header.
            source_ref: Source reference for provenance.

        Returns:
            List of Facts, or empty list if not recognized.
        """
        msg = header.message
        ufw_match = UFW_RE.match(msg)
        if not ufw_match:
            return []

        action = ufw_match.group(1)

        # Parse key=value pairs from the UFW message
        kv_pairs = self._parse_ufw_fields(msg)

        src_ip = kv_pairs.get("SRC", "")
        dst_ip = kv_pairs.get("DST", "")
        proto = kv_pairs.get("PROTO", "")
        src_port = kv_pairs.get("SPT", "")
        dst_port = kv_pairs.get("DPT", "")
        interface = kv_pairs.get("IN", "")

        # Build entity ID for network connection
        entity_id = f"connection:{src_ip}:{src_port}->{dst_ip}:{dst_port}"
        ts_iso = header.timestamp.isoformat()
        base_id = f"fw-{action.lower()}-{ts_iso}-{src_ip}-{dst_port}-{header.hostname}"
        provenance = self._make_provenance(source_ref, f"line={header.line_number}")

        facts = [
            self._make_fact(f"{base_id}-event_type", entity_id, "event_type", f"firewall_{action.lower()}", header.timestamp, provenance),
            self._make_fact(f"{base_id}-action", entity_id, "action", action, header.timestamp, provenance),
            self._make_fact(f"{base_id}-facility", entity_id, "facility", header.facility_name, header.timestamp, provenance),
            self._make_fact(f"{base_id}-severity", entity_id, "severity", header.severity_name, header.timestamp, provenance),
        ]

        if src_ip:
            facts.append(self._make_fact(f"{base_id}-src_ip", entity_id, "src_ip", src_ip, header.timestamp, provenance))
        if dst_ip:
            facts.append(self._make_fact(f"{base_id}-dst_ip", entity_id, "dst_ip", dst_ip, header.timestamp, provenance))
        if proto:
            facts.append(self._make_fact(f"{base_id}-protocol", entity_id, "protocol", proto, header.timestamp, provenance))
        if src_port:
            facts.append(self._make_fact(f"{base_id}-src_port", entity_id, "src_port", int(src_port), header.timestamp, provenance))
        if dst_port:
            facts.append(self._make_fact(f"{base_id}-dst_port", entity_id, "dst_port", int(dst_port), header.timestamp, provenance))
        if interface:
            facts.append(self._make_fact(f"{base_id}-interface", entity_id, "interface", interface, header.timestamp, provenance))

        return facts

    def _parse_ufw_fields(self, message: str) -> dict[str, str]:
        """Parse key=value pairs from a UFW log message.

        Args:
            message: UFW message body.

        Returns:
            Dictionary of parsed key-value pairs.
        """
        result: dict[str, str] = {}
        for match in re.finditer(r"(\w+)=(\S*)", message):
            result[match.group(1)] = match.group(2)
        return result

    # =========================================================================
    # Sudo handlers
    # =========================================================================

    def _extract_sudo_facts(
        self, header: SyslogHeader, source_ref: str
    ) -> list[Fact]:
        """Extract facts from sudo messages.

        Handles: sudo command execution, PAM auth failure.

        Args:
            header: Parsed syslog header.
            source_ref: Source reference for provenance.

        Returns:
            List of Facts, or empty list if not recognized.
        """
        msg = header.message

        # Sudo command execution
        match = SUDO_COMMAND_RE.match(msg)
        if match:
            return self._make_sudo_command_facts(header, source_ref, match)

        # PAM auth failure
        match = SUDO_AUTH_FAIL_RE.match(msg)
        if match:
            return self._make_sudo_auth_fail_facts(header, source_ref, match)

        return []

    def _make_sudo_command_facts(
        self, header: SyslogHeader, source_ref: str, match: re.Match
    ) -> list[Fact]:
        """Build facts for a sudo command execution event.

        Args:
            header: Parsed syslog header.
            source_ref: Source reference.
            match: Regex match with groups (user, tty, pwd, target_user, command).

        Returns:
            List of Facts.
        """
        invoking_user = match.group(1)
        tty = match.group(2)
        pwd = match.group(3)
        target_user = match.group(4)
        command = match.group(5)

        entity_id = f"user:{invoking_user}@{header.hostname}"
        ts_iso = header.timestamp.isoformat()
        base_id = f"sudo-cmd-{ts_iso}-{invoking_user}-{header.hostname}"
        provenance = self._make_provenance(source_ref, f"line={header.line_number}")

        return [
            self._make_fact(f"{base_id}-event_type", entity_id, "event_type", "sudo_command", header.timestamp, provenance),
            self._make_fact(f"{base_id}-invoking_user", entity_id, "invoking_user", invoking_user, header.timestamp, provenance),
            self._make_fact(f"{base_id}-target_user", entity_id, "target_user", target_user, header.timestamp, provenance),
            self._make_fact(f"{base_id}-command", entity_id, "command", command, header.timestamp, provenance),
            self._make_fact(f"{base_id}-tty", entity_id, "tty", tty, header.timestamp, provenance),
            self._make_fact(f"{base_id}-working_directory", entity_id, "working_directory", pwd, header.timestamp, provenance),
            self._make_fact(f"{base_id}-facility", entity_id, "facility", header.facility_name, header.timestamp, provenance),
            self._make_fact(f"{base_id}-severity", entity_id, "severity", header.severity_name, header.timestamp, provenance),
        ]

    def _make_sudo_auth_fail_facts(
        self, header: SyslogHeader, source_ref: str, match: re.Match
    ) -> list[Fact]:
        """Build facts for a sudo PAM auth failure event.

        Args:
            header: Parsed syslog header.
            source_ref: Source reference.
            match: Regex match with group (detail string).

        Returns:
            List of Facts.
        """
        detail = match.group(1).strip()

        # Parse key=value pairs from PAM detail string
        kv_pairs: dict[str, str] = {}
        for kv_match in re.finditer(r"(\w+)=(\S*)", detail):
            kv_pairs[kv_match.group(1)] = kv_match.group(2)

        username = kv_pairs.get("user", kv_pairs.get("ruser", "unknown"))

        entity_id = f"user:{username}@{header.hostname}"
        ts_iso = header.timestamp.isoformat()
        base_id = f"sudo-authfail-{ts_iso}-{username}-{header.hostname}"
        provenance = self._make_provenance(source_ref, f"line={header.line_number}")

        facts = [
            self._make_fact(f"{base_id}-event_type", entity_id, "event_type", "sudo_auth_failure", header.timestamp, provenance),
            self._make_fact(f"{base_id}-username", entity_id, "username", username, header.timestamp, provenance),
            self._make_fact(f"{base_id}-failure_reason", entity_id, "failure_reason", "authentication_failure", header.timestamp, provenance),
            self._make_fact(f"{base_id}-facility", entity_id, "facility", header.facility_name, header.timestamp, provenance),
            self._make_fact(f"{base_id}-severity", entity_id, "severity", header.severity_name, header.timestamp, provenance),
        ]

        return facts

    # =========================================================================
    # Systemd handlers
    # =========================================================================

    def _extract_systemd_facts(
        self, header: SyslogHeader, source_ref: str
    ) -> list[Fact]:
        """Extract facts from systemd messages.

        Handles: Started, Stopping, Stopped.

        Args:
            header: Parsed syslog header.
            source_ref: Source reference for provenance.

        Returns:
            List of Facts, or empty list if not recognized.
        """
        msg = header.message

        # Started
        match = SYSTEMD_STARTED_RE.match(msg)
        if match:
            return self._make_systemd_facts(header, source_ref, match.group(1), "started")

        # Stopping
        match = SYSTEMD_STOPPING_RE.match(msg)
        if match:
            return self._make_systemd_facts(header, source_ref, match.group(1), "stopping")

        # Stopped
        match = SYSTEMD_STOPPED_RE.match(msg)
        if match:
            return self._make_systemd_facts(header, source_ref, match.group(1), "stopped")

        return []

    def _make_systemd_facts(
        self,
        header: SyslogHeader,
        source_ref: str,
        service_name: str,
        action: str,
    ) -> list[Fact]:
        """Build facts for a systemd service event.

        Args:
            header: Parsed syslog header.
            source_ref: Source reference.
            service_name: Name of the service.
            action: Action (started, stopping, stopped).

        Returns:
            List of Facts.
        """
        entity_id = f"service:{service_name}@{header.hostname}"
        ts_iso = header.timestamp.isoformat()
        base_id = f"systemd-{action}-{ts_iso}-{service_name}-{header.hostname}"
        provenance = self._make_provenance(source_ref, f"line={header.line_number}")

        return [
            self._make_fact(f"{base_id}-event_type", entity_id, "event_type", f"service_{action}", header.timestamp, provenance),
            self._make_fact(f"{base_id}-service_name", entity_id, "service_name", service_name, header.timestamp, provenance),
            self._make_fact(f"{base_id}-action", entity_id, "action", action, header.timestamp, provenance),
            self._make_fact(f"{base_id}-facility", entity_id, "facility", header.facility_name, header.timestamp, provenance),
            self._make_fact(f"{base_id}-severity", entity_id, "severity", header.severity_name, header.timestamp, provenance),
        ]
