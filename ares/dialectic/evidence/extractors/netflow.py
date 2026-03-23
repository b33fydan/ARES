"""NetFlow CSV evidence extractor.

Parses CSV-format NetFlow export records (nfdump, SiLK, flow-tools output)
into Facts for dialectical reasoning. Each row represents a completed
unidirectional network flow.

Sensors don't get opinions — this extractor parses and stamps provenance,
reasoning happens downstream.
"""

import ipaddress
from datetime import datetime, timezone
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

# Expected standard column order (used for positional fallback)
STANDARD_COLUMNS = (
    "start_time",
    "end_time",
    "duration_ms",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "packets",
    "bytes",
    "tcp_flags",
    "tos",
)

# Column name aliases → canonical name
COLUMN_ALIASES: dict[str, str] = {
    # start_time
    "start_time": "start_time",
    # end_time
    "end_time": "end_time",
    # duration_ms
    "duration_ms": "duration_ms",
    "duration": "duration_ms",
    "dur": "duration_ms",
    # src_ip
    "src_ip": "src_ip",
    "source_ip": "src_ip",
    "src_addr": "src_ip",
    "source_address": "src_ip",
    # dst_ip
    "dst_ip": "dst_ip",
    "dest_ip": "dst_ip",
    "destination_ip": "dst_ip",
    "dst_addr": "dst_ip",
    "destination_address": "dst_ip",
    # src_port
    "src_port": "src_port",
    "source_port": "src_port",
    # dst_port
    "dst_port": "dst_port",
    "dest_port": "dst_port",
    "destination_port": "dst_port",
    # protocol
    "protocol": "protocol",
    # packets
    "packets": "packets",
    "pkts": "packets",
    "in_packets": "packets",
    # bytes
    "bytes": "bytes",
    "octets": "bytes",
    "in_bytes": "bytes",
    # tcp_flags
    "tcp_flags": "tcp_flags",
    # tos
    "tos": "tos",
}

# Required canonical columns
REQUIRED_COLUMNS = frozenset(STANDARD_COLUMNS)

# RFC 1918 private address ranges
_RFC1918_NETWORKS = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
)

# Error type constants
MALFORMED_ROW = "MALFORMED_ROW"
MISSING_FIELD = "MISSING_FIELD"
INVALID_IP = "INVALID_IP"
INVALID_PORT = "INVALID_PORT"
INVALID_TIMESTAMP = "INVALID_TIMESTAMP"
INVALID_HEADER = "INVALID_HEADER"


# =============================================================================
# Helpers
# =============================================================================


def _is_rfc1918(ip_str: str) -> bool:
    """Check if an IPv4 address is in RFC 1918 private space.

    Args:
        ip_str: IPv4 address string.

    Returns:
        True if the address is private (10/8, 172.16/12, 192.168/16).
    """
    try:
        addr = ipaddress.IPv4Address(ip_str)
    except (ipaddress.AddressValueError, ValueError):
        return False
    return any(addr in net for net in _RFC1918_NETWORKS)


def _classify_direction(src_ip: str, dst_ip: str) -> str:
    """Classify flow direction based on RFC 1918 address ranges.

    Args:
        src_ip: Source IP address.
        dst_ip: Destination IP address.

    Returns:
        One of 'internal', 'outbound', 'inbound', 'external', or 'unknown'.
    """
    src_private = _is_rfc1918(src_ip)
    dst_private = _is_rfc1918(dst_ip)

    if src_private and dst_private:
        return "internal"
    elif src_private and not dst_private:
        return "outbound"
    elif not src_private and dst_private:
        return "inbound"
    else:
        return "external"


def _validate_ipv4(ip_str: str) -> bool:
    """Validate an IPv4 address string.

    Args:
        ip_str: String to validate.

    Returns:
        True if valid IPv4 address.
    """
    try:
        ipaddress.IPv4Address(ip_str)
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


def _looks_like_data_row(fields: list[str]) -> bool:
    """Heuristic: does a row look like flow data rather than a header?

    Checks if the row contains what looks like IP addresses and numeric ports.

    Args:
        fields: Split CSV fields.

    Returns:
        True if the row appears to be data, not a header.
    """
    if len(fields) < len(STANDARD_COLUMNS):
        return False
    # Field index 3 should be src_ip — check if it looks like an IP
    candidate_ip = fields[3].strip()
    if _validate_ipv4(candidate_ip):
        return True
    return False


def _resolve_header(raw_columns: list[str]) -> Optional[dict[str, int]]:
    """Attempt to map raw header names to canonical column names.

    Args:
        raw_columns: List of header column names.

    Returns:
        Dict mapping canonical name → column index, or None if header invalid.
    """
    mapping: dict[str, int] = {}
    for idx, col in enumerate(raw_columns):
        col_lower = col.strip().lower()
        canonical = COLUMN_ALIASES.get(col_lower)
        if canonical is not None:
            mapping[canonical] = idx
    return mapping if mapping else None


# =============================================================================
# Extractor
# =============================================================================


class NetFlowExtractor:
    """Parses CSV-format NetFlow export records into Facts.

    Implements ExtractorProtocol. Handles standard flow fields
    including timing, addressing, volume metrics, and TCP flags.

    Supports three header modes:
    - Standard header with expected column names
    - Alias headers (source_ip, dest_port, etc.)
    - No header (positional mapping to standard column order)

    Attributes:
        VERSION: Semantic version of this extractor.
    """

    VERSION: str = "netflow-extractor-v1.0"

    def extract(
        self,
        raw: bytes | str,
        *,
        source_ref: str,
        strict: bool = True,
    ) -> ExtractionResult:
        """Parse NetFlow CSV records into Facts.

        Args:
            raw: Raw CSV data (bytes or string), one flow per line.
            source_ref: Reference to data source for provenance tracking.
            strict: If True, raise on first error. If False, collect errors
                   and return partial results.

        Returns:
            ExtractionResult containing Facts, errors, and stats.

        Raises:
            ValueError: In strict mode, on first parse error.
        """
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8")

        facts: list[Fact] = []
        errors: list[ExtractionError] = []
        events_seen = 0
        events_parsed = 0
        events_dropped = 0

        lines = raw.splitlines()

        # Filter out blank lines, preserving original line numbers
        data_lines: list[tuple[int, str]] = []
        for idx, line in enumerate(lines):
            if line.strip():
                data_lines.append((idx + 1, line))

        if not data_lines:
            # Empty input — valid, just no data
            stats = ExtractionStats(
                events_seen=0,
                events_parsed=0,
                events_dropped=0,
                facts_emitted=0,
            )
            return ExtractionResult(
                facts=(),
                errors=(),
                stats=stats,
                source_ref=source_ref,
                extractor_version=self.VERSION,
            )

        # Determine header mapping
        first_line_num, first_line = data_lines[0]
        first_fields = first_line.split(",")
        column_map: dict[str, int]
        start_idx: int

        if _looks_like_data_row(first_fields):
            # No header — use positional mapping
            if len(first_fields) < len(STANDARD_COLUMNS):
                error = ExtractionError(
                    line_number=first_line_num,
                    raw_snippet=first_line[:200],
                    error_type=INVALID_HEADER,
                    message=f"Line {first_line_num}: insufficient columns for positional mapping "
                            f"(got {len(first_fields)}, need {len(STANDARD_COLUMNS)})",
                )
                if strict:
                    raise ValueError(error.message)
                errors.append(error)
                stats = ExtractionStats(
                    events_seen=0,
                    events_parsed=0,
                    events_dropped=0,
                    facts_emitted=0,
                )
                return ExtractionResult(
                    facts=(),
                    errors=tuple(errors),
                    stats=stats,
                    source_ref=source_ref,
                    extractor_version=self.VERSION,
                )
            column_map = {col: i for i, col in enumerate(STANDARD_COLUMNS)}
            start_idx = 0
        else:
            # Attempt header resolution
            resolved = _resolve_header(first_fields)
            if resolved is None:
                error = ExtractionError(
                    line_number=first_line_num,
                    raw_snippet=first_line[:200],
                    error_type=INVALID_HEADER,
                    message=f"Line {first_line_num}: unrecognized header columns",
                )
                if strict:
                    raise ValueError(error.message)
                errors.append(error)
                stats = ExtractionStats(
                    events_seen=0,
                    events_parsed=0,
                    events_dropped=0,
                    facts_emitted=0,
                )
                return ExtractionResult(
                    facts=(),
                    errors=tuple(errors),
                    stats=stats,
                    source_ref=source_ref,
                    extractor_version=self.VERSION,
                )

            # Check all required columns present
            missing = REQUIRED_COLUMNS - set(resolved.keys())
            if missing:
                error = ExtractionError(
                    line_number=first_line_num,
                    raw_snippet=first_line[:200],
                    error_type=INVALID_HEADER,
                    message=f"Line {first_line_num}: missing required columns: {sorted(missing)}",
                )
                if strict:
                    raise ValueError(error.message)
                errors.append(error)
                stats = ExtractionStats(
                    events_seen=0,
                    events_parsed=0,
                    events_dropped=0,
                    facts_emitted=0,
                )
                return ExtractionResult(
                    facts=(),
                    errors=tuple(errors),
                    stats=stats,
                    source_ref=source_ref,
                    extractor_version=self.VERSION,
                )

            column_map = resolved
            start_idx = 1  # Skip header line

        # Parse data rows
        for dl_idx in range(start_idx, len(data_lines)):
            line_number, line = data_lines[dl_idx]
            events_seen += 1

            row_facts, row_error = self._parse_row(
                line, line_number, column_map, source_ref
            )

            if row_error is not None:
                events_dropped += 1
                if strict:
                    raise ValueError(row_error.message)
                errors.append(row_error)
            else:
                facts.extend(row_facts)
                events_parsed += 1

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

    def _parse_row(
        self,
        line: str,
        line_number: int,
        column_map: dict[str, int],
        source_ref: str,
    ) -> tuple[list[Fact], Optional[ExtractionError]]:
        """Parse a single CSV data row into Facts.

        Args:
            line: Raw CSV line.
            line_number: Line number in original input (1-based).
            column_map: Mapping of canonical column name → field index.
            source_ref: Source reference for provenance.

        Returns:
            Tuple of (facts_list, error_or_none). Exactly one will be populated.
        """
        fields = line.split(",")

        # Check minimum field count
        max_idx = max(column_map.values())
        if len(fields) <= max_idx:
            return [], ExtractionError(
                line_number=line_number,
                raw_snippet=line[:200],
                error_type=MALFORMED_ROW,
                message=f"Line {line_number}: insufficient fields "
                        f"(got {len(fields)}, need at least {max_idx + 1})",
            )

        # Extract raw values
        try:
            raw = {col: fields[idx].strip() for col, idx in column_map.items()}
        except IndexError:
            return [], ExtractionError(
                line_number=line_number,
                raw_snippet=line[:200],
                error_type=MALFORMED_ROW,
                message=f"Line {line_number}: field index out of range",
            )

        # Validate and parse each field
        # -- Timestamps --
        try:
            start_time = datetime.fromisoformat(raw["start_time"].replace("Z", "+00:00"))
        except (ValueError, KeyError):
            return [], ExtractionError(
                line_number=line_number,
                raw_snippet=line[:200],
                error_type=INVALID_TIMESTAMP,
                message=f"Line {line_number}: invalid start_time '{raw.get('start_time', '')}'",
            )

        try:
            end_time = datetime.fromisoformat(raw["end_time"].replace("Z", "+00:00"))
        except (ValueError, KeyError):
            return [], ExtractionError(
                line_number=line_number,
                raw_snippet=line[:200],
                error_type=INVALID_TIMESTAMP,
                message=f"Line {line_number}: invalid end_time '{raw.get('end_time', '')}'",
            )

        if end_time < start_time:
            return [], ExtractionError(
                line_number=line_number,
                raw_snippet=line[:200],
                error_type=INVALID_TIMESTAMP,
                message=f"Line {line_number}: end_time < start_time",
            )

        # -- Duration --
        try:
            duration_ms = int(raw["duration_ms"])
            if duration_ms < 0:
                raise ValueError("negative")
        except (ValueError, KeyError):
            return [], ExtractionError(
                line_number=line_number,
                raw_snippet=line[:200],
                error_type=MISSING_FIELD,
                message=f"Line {line_number}: invalid duration_ms '{raw.get('duration_ms', '')}'",
            )

        # -- IP addresses --
        src_ip = raw["src_ip"]
        if not _validate_ipv4(src_ip):
            return [], ExtractionError(
                line_number=line_number,
                raw_snippet=line[:200],
                error_type=INVALID_IP,
                message=f"Line {line_number}: invalid src_ip '{src_ip}'",
            )

        dst_ip = raw["dst_ip"]
        if not _validate_ipv4(dst_ip):
            return [], ExtractionError(
                line_number=line_number,
                raw_snippet=line[:200],
                error_type=INVALID_IP,
                message=f"Line {line_number}: invalid dst_ip '{dst_ip}'",
            )

        # -- Ports --
        try:
            src_port = int(raw["src_port"])
            if src_port < 0 or src_port > 65535:
                raise ValueError("out of range")
        except (ValueError, KeyError):
            return [], ExtractionError(
                line_number=line_number,
                raw_snippet=line[:200],
                error_type=INVALID_PORT,
                message=f"Line {line_number}: invalid src_port '{raw.get('src_port', '')}'",
            )

        try:
            dst_port = int(raw["dst_port"])
            if dst_port < 0 or dst_port > 65535:
                raise ValueError("out of range")
        except (ValueError, KeyError):
            return [], ExtractionError(
                line_number=line_number,
                raw_snippet=line[:200],
                error_type=INVALID_PORT,
                message=f"Line {line_number}: invalid dst_port '{raw.get('dst_port', '')}'",
            )

        # -- Protocol --
        protocol = raw["protocol"]
        if not protocol:
            return [], ExtractionError(
                line_number=line_number,
                raw_snippet=line[:200],
                error_type=MISSING_FIELD,
                message=f"Line {line_number}: empty protocol field",
            )

        # -- Packets and bytes --
        try:
            packets = int(raw["packets"])
            if packets < 0:
                raise ValueError("negative")
        except (ValueError, KeyError):
            return [], ExtractionError(
                line_number=line_number,
                raw_snippet=line[:200],
                error_type=MISSING_FIELD,
                message=f"Line {line_number}: invalid packets '{raw.get('packets', '')}'",
            )

        try:
            byte_count = int(raw["bytes"])
            if byte_count < 0:
                raise ValueError("negative")
        except (ValueError, KeyError):
            return [], ExtractionError(
                line_number=line_number,
                raw_snippet=line[:200],
                error_type=MISSING_FIELD,
                message=f"Line {line_number}: invalid bytes '{raw.get('bytes', '')}'",
            )

        tcp_flags = raw["tcp_flags"]
        try:
            tos = int(raw["tos"])
        except (ValueError, KeyError):
            return [], ExtractionError(
                line_number=line_number,
                raw_snippet=line[:200],
                error_type=MISSING_FIELD,
                message=f"Line {line_number}: invalid tos '{raw.get('tos', '')}'",
            )

        # -- Computed fields --
        bytes_per_packet = byte_count / packets if packets > 0 else 0.0
        flow_direction = _classify_direction(src_ip, dst_ip)

        # Build facts
        entity_id = f"flow:{src_ip}:{src_port}->{dst_ip}:{dst_port}/{protocol}"
        start_iso = raw["start_time"]
        base_id = f"netflow-{start_iso}-{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
        provenance = self._make_provenance(source_ref, f"line={line_number}")

        fact_fields = [
            ("start_time", raw["start_time"]),
            ("end_time", raw["end_time"]),
            ("duration_ms", str(duration_ms)),
            ("src_ip", src_ip),
            ("dst_ip", dst_ip),
            ("src_port", str(src_port)),
            ("dst_port", str(dst_port)),
            ("protocol", protocol),
            ("packets", str(packets)),
            ("bytes", str(byte_count)),
            ("tcp_flags", tcp_flags),
            ("tos", str(tos)),
            ("bytes_per_packet", str(bytes_per_packet)),
            ("flow_direction", flow_direction),
        ]

        row_facts = [
            self._make_fact(
                fact_id=f"{base_id}-{field}",
                entity_id=entity_id,
                field=field,
                value=value,
                timestamp=start_time,
                provenance=provenance,
            )
            for field, value in fact_fields
        ]

        return row_facts, None

    def _make_provenance(
        self, source_ref: str, raw_reference: str
    ) -> Provenance:
        """Create provenance for a fact.

        Args:
            source_ref: Data source reference.
            raw_reference: Reference within the source.

        Returns:
            Provenance instance with NETFLOW source type.
        """
        return Provenance(
            source_type=SourceType.NETFLOW,
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
        """Create a Fact with NODE entity type.

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
