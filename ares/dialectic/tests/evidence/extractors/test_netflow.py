"""Tests for NetFlow CSV evidence extractor.

Tests validate:
1. CSV flow record parsing (HTTPS, DNS, SSH, ICMP, C2, lateral movement)
2. 14 fact attributes per flow (including computed fields)
3. Entity ID format: flow:{src}:{sport}->{dst}:{dport}/{proto}
4. Flow direction classification (RFC 1918)
5. Strict vs permissive mode
6. Provenance stamping
7. ExtractionStats accuracy
8. Header handling (standard, alias, no-header, invalid)
9. Protocol compliance
10. Edge cases
"""

import pytest
from datetime import datetime

from ares.dialectic.evidence.extractors.protocol import (
    ExtractionError,
    ExtractionResult,
    ExtractionStats,
    ExtractorProtocol,
)
from ares.dialectic.evidence.extractors.netflow import (
    NetFlowExtractor,
    MALFORMED_ROW,
    MISSING_FIELD,
    INVALID_IP,
    INVALID_PORT,
    INVALID_TIMESTAMP,
    INVALID_HEADER,
    STANDARD_COLUMNS,
    _is_rfc1918,
    _classify_direction,
    _validate_ipv4,
)
from ares.dialectic.evidence.fact import EntityType
from ares.dialectic.evidence.provenance import SourceType
from ares.dialectic.evidence.packet import EvidencePacket, TimeWindow


# =============================================================================
# Test Fixtures
# =============================================================================

HEADER = "start_time,end_time,duration_ms,src_ip,dst_ip,src_port,dst_port,protocol,packets,bytes,tcp_flags,tos"

# Normal HTTPS session (outbound)
HTTPS_FLOW = "2026-03-04T14:00:00Z,2026-03-04T14:00:05Z,5000,10.0.1.50,203.0.113.10,52341,443,TCP,45,32400,SA,0"

# DNS query (internal, UDP)
DNS_FLOW = "2026-03-04T14:00:01Z,2026-03-04T14:00:01Z,50,10.0.1.50,10.0.1.1,61234,53,UDP,2,180,0,0"

# Large SSH session (possible exfiltration, outbound)
LARGE_SSH = "2026-03-04T14:00:02Z,2026-03-04T14:05:02Z,300000,10.0.1.100,198.51.100.50,49152,22,TCP,1200,2450000,SAP,0"

# Port scan signature (SYN-only, inbound)
PORT_SCAN = "2026-03-04T14:00:03Z,2026-03-04T14:00:03Z,20,203.0.113.50,10.0.1.100,44231,22,TCP,3,180,S,0"

# Long-running C2 beacon (outbound)
C2_BEACON = "2026-03-04T14:00:04Z,2026-03-04T14:30:04Z,1800000,10.0.1.100,192.0.2.50,48000,8443,TCP,8500,15000000,SAP,0"

# Internal lateral movement (RDP)
LATERAL_RDP = "2026-03-04T14:01:00Z,2026-03-04T14:10:00Z,540000,10.0.1.100,10.0.1.200,49500,3389,TCP,3200,1800000,SAP,0"

# DNS tunneling signature
DNS_TUNNEL = "2026-03-04T14:02:00Z,2026-03-04T14:02:01Z,1000,10.0.1.100,8.8.8.8,55000,53,UDP,4,2400,0,0"

# ICMP flow (no ports)
ICMP_FLOW = "2026-03-04T14:03:00Z,2026-03-04T14:03:00Z,100,10.0.1.50,10.0.1.1,0,0,ICMP,4,256,0,0"

# Realistic mixed stream
REALISTIC_STREAM = "\n".join([HEADER, HTTPS_FLOW, DNS_FLOW, LARGE_SSH, PORT_SCAN, C2_BEACON, LATERAL_RDP, DNS_TUNNEL, ICMP_FLOW])

# Facts per flow
FACTS_PER_FLOW = 14

SOURCE_REF = "router01:netflow:2026-03-04"


# =============================================================================
# Helper
# =============================================================================


def extract(data: str, *, strict: bool = True, source_ref: str = SOURCE_REF) -> ExtractionResult:
    """Shorthand extraction helper for tests."""
    extractor = NetFlowExtractor()
    return extractor.extract(data, source_ref=source_ref, strict=strict)


# =============================================================================
# Protocol Compliance Tests
# =============================================================================


class TestNetFlowProtocolCompliance:
    """Tests for ExtractorProtocol compliance."""

    def test_protocol_compliance_isinstance(self):
        """NetFlowExtractor satisfies ExtractorProtocol."""
        assert isinstance(NetFlowExtractor(), ExtractorProtocol)

    def test_protocol_compliance_has_version(self):
        """NetFlowExtractor has VERSION attribute."""
        ext = NetFlowExtractor()
        assert hasattr(ext, "VERSION")
        assert isinstance(ext.VERSION, str)
        assert ext.VERSION == "netflow-extractor-v1.0"

    def test_protocol_compliance_extract_returns_result(self):
        """extract() returns ExtractionResult."""
        result = extract(HEADER + "\n" + HTTPS_FLOW)
        assert isinstance(result, ExtractionResult)


# =============================================================================
# Parsing Tests
# =============================================================================


class TestNetFlowParsing:
    """Tests for correct parsing of flow records."""

    def test_parse_https_flow_fact_count(self):
        """HTTPS flow produces exactly 14 facts."""
        result = extract(HEADER + "\n" + HTTPS_FLOW)
        assert len(result.facts) == FACTS_PER_FLOW

    def test_parse_dns_flow_fact_count(self):
        """DNS flow produces exactly 14 facts."""
        result = extract(HEADER + "\n" + DNS_FLOW)
        assert len(result.facts) == FACTS_PER_FLOW

    def test_parse_large_ssh_fact_count(self):
        """Large SSH flow produces exactly 14 facts."""
        result = extract(HEADER + "\n" + LARGE_SSH)
        assert len(result.facts) == FACTS_PER_FLOW

    def test_parse_port_scan_fact_count(self):
        """Port scan flow produces exactly 14 facts."""
        result = extract(HEADER + "\n" + PORT_SCAN)
        assert len(result.facts) == FACTS_PER_FLOW

    def test_parse_c2_beacon_fact_count(self):
        """C2 beacon flow produces exactly 14 facts."""
        result = extract(HEADER + "\n" + C2_BEACON)
        assert len(result.facts) == FACTS_PER_FLOW

    def test_parse_lateral_rdp_fact_count(self):
        """Lateral RDP flow produces exactly 14 facts."""
        result = extract(HEADER + "\n" + LATERAL_RDP)
        assert len(result.facts) == FACTS_PER_FLOW

    def test_parse_icmp_flow_fact_count(self):
        """ICMP flow produces exactly 14 facts."""
        result = extract(HEADER + "\n" + ICMP_FLOW)
        assert len(result.facts) == FACTS_PER_FLOW

    def test_parse_https_entity_id_format(self):
        """Entity ID follows flow:{src}:{sport}->{dst}:{dport}/{proto} format."""
        result = extract(HEADER + "\n" + HTTPS_FLOW)
        entity_ids = {f.entity_id for f in result.facts}
        assert entity_ids == {"flow:10.0.1.50:52341->203.0.113.10:443/TCP"}

    def test_parse_icmp_entity_id_format(self):
        """ICMP entity ID uses port 0."""
        result = extract(HEADER + "\n" + ICMP_FLOW)
        entity_ids = {f.entity_id for f in result.facts}
        assert entity_ids == {"flow:10.0.1.50:0->10.0.1.1:0/ICMP"}

    def test_parse_all_14_attributes_present(self):
        """All 14 fact fields present for a flow."""
        result = extract(HEADER + "\n" + HTTPS_FLOW)
        fields = {f.field for f in result.facts}
        expected = {
            "start_time", "end_time", "duration_ms", "src_ip", "dst_ip",
            "src_port", "dst_port", "protocol", "packets", "bytes",
            "tcp_flags", "tos", "bytes_per_packet", "flow_direction",
        }
        assert fields == expected

    def test_parse_https_attribute_values(self):
        """HTTPS flow attribute values are correct."""
        result = extract(HEADER + "\n" + HTTPS_FLOW)
        fact_map = {f.field: f.value for f in result.facts}
        assert fact_map["start_time"] == "2026-03-04T14:00:00Z"
        assert fact_map["end_time"] == "2026-03-04T14:00:05Z"
        assert fact_map["duration_ms"] == "5000"
        assert fact_map["src_ip"] == "10.0.1.50"
        assert fact_map["dst_ip"] == "203.0.113.10"
        assert fact_map["src_port"] == "52341"
        assert fact_map["dst_port"] == "443"
        assert fact_map["protocol"] == "TCP"
        assert fact_map["packets"] == "45"
        assert fact_map["bytes"] == "32400"
        assert fact_map["tcp_flags"] == "SA"
        assert fact_map["tos"] == "0"

    def test_parse_bytes_per_packet_computed(self):
        """bytes_per_packet is correctly computed."""
        result = extract(HEADER + "\n" + HTTPS_FLOW)
        fact_map = {f.field: f.value for f in result.facts}
        expected_bpp = str(32400 / 45)
        assert fact_map["bytes_per_packet"] == expected_bpp

    def test_parse_bytes_per_packet_zero_packets(self):
        """bytes_per_packet is 0.0 when packets is 0."""
        zero_pkt = "2026-03-04T14:00:00Z,2026-03-04T14:00:00Z,0,10.0.1.50,10.0.1.1,0,0,TCP,0,0,R,0"
        result = extract(HEADER + "\n" + zero_pkt)
        fact_map = {f.field: f.value for f in result.facts}
        assert fact_map["bytes_per_packet"] == "0.0"

    def test_parse_protocol_preserved_tcp(self):
        """TCP protocol string preserved."""
        result = extract(HEADER + "\n" + HTTPS_FLOW)
        fact_map = {f.field: f.value for f in result.facts}
        assert fact_map["protocol"] == "TCP"

    def test_parse_protocol_preserved_udp(self):
        """UDP protocol string preserved."""
        result = extract(HEADER + "\n" + DNS_FLOW)
        fact_map = {f.field: f.value for f in result.facts}
        assert fact_map["protocol"] == "UDP"

    def test_parse_protocol_preserved_icmp(self):
        """ICMP protocol string preserved."""
        result = extract(HEADER + "\n" + ICMP_FLOW)
        fact_map = {f.field: f.value for f in result.facts}
        assert fact_map["protocol"] == "ICMP"

    def test_parse_header_row_not_treated_as_data(self):
        """Header row is not counted as a data event."""
        result = extract(HEADER + "\n" + HTTPS_FLOW)
        assert result.stats.events_seen == 1
        assert result.stats.events_parsed == 1


# =============================================================================
# Flow Direction Tests
# =============================================================================


class TestNetFlowDirection:
    """Tests for RFC 1918 flow direction classification."""

    def test_direction_outbound_https(self):
        """HTTPS to external IP is outbound."""
        result = extract(HEADER + "\n" + HTTPS_FLOW)
        fact_map = {f.field: f.value for f in result.facts}
        assert fact_map["flow_direction"] == "outbound"

    def test_direction_internal_dns(self):
        """DNS to internal resolver is internal."""
        result = extract(HEADER + "\n" + DNS_FLOW)
        fact_map = {f.field: f.value for f in result.facts}
        assert fact_map["flow_direction"] == "internal"

    def test_direction_outbound_ssh(self):
        """SSH to external IP is outbound."""
        result = extract(HEADER + "\n" + LARGE_SSH)
        fact_map = {f.field: f.value for f in result.facts}
        assert fact_map["flow_direction"] == "outbound"

    def test_direction_inbound_port_scan(self):
        """External IP to internal is inbound."""
        result = extract(HEADER + "\n" + PORT_SCAN)
        fact_map = {f.field: f.value for f in result.facts}
        assert fact_map["flow_direction"] == "inbound"

    def test_direction_internal_lateral(self):
        """Internal to internal is internal."""
        result = extract(HEADER + "\n" + LATERAL_RDP)
        fact_map = {f.field: f.value for f in result.facts}
        assert fact_map["flow_direction"] == "internal"

    def test_direction_external_both_public(self):
        """Both public IPs is external."""
        external_flow = "2026-03-04T14:00:00Z,2026-03-04T14:00:01Z,1000,8.8.8.8,1.1.1.1,1234,53,UDP,2,100,0,0"
        result = extract(HEADER + "\n" + external_flow)
        fact_map = {f.field: f.value for f in result.facts}
        assert fact_map["flow_direction"] == "external"

    def test_helper_is_rfc1918_10_range(self):
        """10.x.x.x is RFC 1918."""
        assert _is_rfc1918("10.0.0.1") is True
        assert _is_rfc1918("10.255.255.255") is True

    def test_helper_is_rfc1918_172_range(self):
        """172.16-31.x.x is RFC 1918."""
        assert _is_rfc1918("172.16.0.1") is True
        assert _is_rfc1918("172.31.255.255") is True
        assert _is_rfc1918("172.15.0.1") is False
        assert _is_rfc1918("172.32.0.1") is False

    def test_helper_is_rfc1918_192_range(self):
        """192.168.x.x is RFC 1918."""
        assert _is_rfc1918("192.168.0.1") is True
        assert _is_rfc1918("192.168.255.255") is True
        assert _is_rfc1918("192.167.0.1") is False

    def test_helper_is_rfc1918_public(self):
        """Public IPs are not RFC 1918."""
        assert _is_rfc1918("8.8.8.8") is False
        assert _is_rfc1918("203.0.113.50") is False

    def test_helper_classify_direction(self):
        """_classify_direction returns correct values."""
        assert _classify_direction("10.0.1.1", "10.0.1.2") == "internal"
        assert _classify_direction("10.0.1.1", "8.8.8.8") == "outbound"
        assert _classify_direction("8.8.8.8", "10.0.1.1") == "inbound"
        assert _classify_direction("8.8.8.8", "1.1.1.1") == "external"


# =============================================================================
# Provenance Tests
# =============================================================================


class TestNetFlowProvenance:
    """Tests for provenance stamping."""

    def test_provenance_source_ref_propagated(self):
        """source_ref is propagated to result."""
        ref = "router01:netflow:2026-03-04"
        result = extract(HEADER + "\n" + HTTPS_FLOW, source_ref=ref)
        assert result.source_ref == ref

    def test_provenance_extractor_version(self):
        """extractor_version matches VERSION constant."""
        result = extract(HEADER + "\n" + HTTPS_FLOW)
        assert result.extractor_version == NetFlowExtractor.VERSION

    def test_provenance_fact_source_type_netflow(self):
        """Facts have NETFLOW source type."""
        result = extract(HEADER + "\n" + HTTPS_FLOW)
        for fact in result.facts:
            assert fact.provenance.source_type == SourceType.NETFLOW

    def test_provenance_fact_parser_version(self):
        """Facts have correct parser version."""
        result = extract(HEADER + "\n" + HTTPS_FLOW)
        for fact in result.facts:
            assert fact.provenance.parser_version == NetFlowExtractor.VERSION

    def test_provenance_fact_source_id(self):
        """Facts have correct source_id."""
        result = extract(HEADER + "\n" + HTTPS_FLOW)
        for fact in result.facts:
            assert fact.provenance.source_id == SOURCE_REF

    def test_provenance_extracted_at_valid(self):
        """extracted_at is a valid datetime."""
        result = extract(HEADER + "\n" + HTTPS_FLOW)
        for fact in result.facts:
            assert isinstance(fact.provenance.extracted_at, datetime)

    def test_provenance_raw_reference_has_line(self):
        """raw_reference includes line number."""
        result = extract(HEADER + "\n" + HTTPS_FLOW)
        for fact in result.facts:
            assert fact.provenance.raw_reference == "line=2"

    def test_provenance_entity_type_node(self):
        """All facts have NODE entity type."""
        result = extract(HEADER + "\n" + HTTPS_FLOW)
        for fact in result.facts:
            assert fact.entity_type == EntityType.NODE


# =============================================================================
# Strict Mode Tests
# =============================================================================


class TestNetFlowStrictMode:
    """Tests for strict mode error handling."""

    def test_strict_malformed_row_raises(self):
        """Malformed row raises ValueError in strict mode."""
        with pytest.raises(ValueError, match="insufficient fields"):
            extract(HEADER + "\n" + "not,enough,fields")

    def test_strict_invalid_ip_raises(self):
        """Invalid IP raises ValueError in strict mode."""
        bad_ip = "2026-03-04T14:00:00Z,2026-03-04T14:00:01Z,1000,999.999.999.999,10.0.1.1,1234,53,UDP,2,100,0,0"
        with pytest.raises(ValueError, match="invalid src_ip"):
            extract(HEADER + "\n" + bad_ip)

    def test_strict_invalid_dst_ip_raises(self):
        """Invalid dst_ip raises ValueError in strict mode."""
        bad_ip = "2026-03-04T14:00:00Z,2026-03-04T14:00:01Z,1000,10.0.1.1,not_an_ip,1234,53,UDP,2,100,0,0"
        with pytest.raises(ValueError, match="invalid dst_ip"):
            extract(HEADER + "\n" + bad_ip)

    def test_strict_negative_port_raises(self):
        """Negative port raises ValueError in strict mode."""
        bad_port = "2026-03-04T14:00:00Z,2026-03-04T14:00:01Z,1000,10.0.1.1,10.0.1.2,-1,53,UDP,2,100,0,0"
        with pytest.raises(ValueError, match="invalid src_port"):
            extract(HEADER + "\n" + bad_port)

    def test_strict_port_over_65535_raises(self):
        """Port > 65535 raises ValueError in strict mode."""
        bad_port = "2026-03-04T14:00:00Z,2026-03-04T14:00:01Z,1000,10.0.1.1,10.0.1.2,1234,70000,UDP,2,100,0,0"
        with pytest.raises(ValueError, match="invalid dst_port"):
            extract(HEADER + "\n" + bad_port)

    def test_strict_invalid_timestamp_raises(self):
        """Invalid timestamp raises ValueError in strict mode."""
        bad_ts = "not-a-timestamp,2026-03-04T14:00:01Z,1000,10.0.1.1,10.0.1.2,1234,53,UDP,2,100,0,0"
        with pytest.raises(ValueError, match="invalid start_time"):
            extract(HEADER + "\n" + bad_ts)

    def test_strict_end_before_start_raises(self):
        """end_time < start_time raises ValueError in strict mode."""
        bad_range = "2026-03-04T14:00:05Z,2026-03-04T14:00:00Z,5000,10.0.1.1,10.0.1.2,1234,53,UDP,2,100,0,0"
        with pytest.raises(ValueError, match="end_time < start_time"):
            extract(HEADER + "\n" + bad_range)

    def test_strict_missing_field_raises(self):
        """Missing required field raises ValueError."""
        # Empty protocol
        missing = "2026-03-04T14:00:00Z,2026-03-04T14:00:01Z,1000,10.0.1.1,10.0.1.2,1234,53,,2,100,0,0"
        with pytest.raises(ValueError, match="empty protocol"):
            extract(HEADER + "\n" + missing)

    def test_strict_empty_input_returns_empty(self):
        """Empty input returns empty result, not error."""
        result = extract("")
        assert result.success is True
        assert len(result.facts) == 0
        assert result.stats.events_seen == 0

    def test_strict_header_only_returns_empty(self):
        """Header-only input returns empty result."""
        result = extract(HEADER)
        assert result.success is True
        assert len(result.facts) == 0
        assert result.stats.events_seen == 0

    def test_strict_negative_duration_raises(self):
        """Negative duration_ms raises ValueError."""
        bad_dur = "2026-03-04T14:00:00Z,2026-03-04T14:00:01Z,-100,10.0.1.1,10.0.1.2,1234,53,UDP,2,100,0,0"
        with pytest.raises(ValueError, match="invalid duration_ms"):
            extract(HEADER + "\n" + bad_dur)

    def test_strict_negative_packets_raises(self):
        """Negative packets raises ValueError."""
        bad_pkt = "2026-03-04T14:00:00Z,2026-03-04T14:00:01Z,1000,10.0.1.1,10.0.1.2,1234,53,UDP,-5,100,0,0"
        with pytest.raises(ValueError, match="invalid packets"):
            extract(HEADER + "\n" + bad_pkt)

    def test_strict_negative_bytes_raises(self):
        """Negative bytes raises ValueError."""
        bad_bytes = "2026-03-04T14:00:00Z,2026-03-04T14:00:01Z,1000,10.0.1.1,10.0.1.2,1234,53,UDP,2,-100,0,0"
        with pytest.raises(ValueError, match="invalid bytes"):
            extract(HEADER + "\n" + bad_bytes)


# =============================================================================
# Permissive Mode Tests
# =============================================================================


class TestNetFlowPermissiveMode:
    """Tests for permissive mode error collection."""

    def test_permissive_malformed_collected(self):
        """Malformed rows collected as ExtractionError."""
        data = HEADER + "\n" + HTTPS_FLOW + "\n" + "bad,row" + "\n" + DNS_FLOW
        result = extract(data, strict=False)
        assert len(result.errors) == 1
        assert result.errors[0].error_type == MALFORMED_ROW

    def test_permissive_valid_rows_still_parsed(self):
        """Valid rows still parsed when errors present."""
        data = HEADER + "\n" + HTTPS_FLOW + "\n" + "bad,row" + "\n" + DNS_FLOW
        result = extract(data, strict=False)
        assert result.stats.events_parsed == 2
        assert len(result.facts) == 2 * FACTS_PER_FLOW

    def test_permissive_partial_true_when_errors(self):
        """partial=True when both facts and errors exist."""
        data = HEADER + "\n" + HTTPS_FLOW + "\n" + "bad,row"
        result = extract(data, strict=False)
        assert result.partial is True

    def test_permissive_error_types_categorized(self):
        """Error types correctly categorized."""
        bad_ip = "2026-03-04T14:00:00Z,2026-03-04T14:00:01Z,1000,999.999.999.999,10.0.1.1,1234,53,UDP,2,100,0,0"
        bad_port = "2026-03-04T14:00:00Z,2026-03-04T14:00:01Z,1000,10.0.1.1,10.0.1.2,1234,99999,UDP,2,100,0,0"
        bad_ts = "not-a-ts,2026-03-04T14:00:01Z,1000,10.0.1.1,10.0.1.2,1234,53,UDP,2,100,0,0"
        data = HEADER + "\n" + bad_ip + "\n" + bad_port + "\n" + bad_ts
        result = extract(data, strict=False)
        error_types = {e.error_type for e in result.errors}
        assert INVALID_IP in error_types
        assert INVALID_PORT in error_types
        assert INVALID_TIMESTAMP in error_types

    def test_permissive_stats_reflect_counts(self):
        """Stats accurately reflect parse/drop counts."""
        data = HEADER + "\n" + HTTPS_FLOW + "\n" + "bad,row" + "\n" + DNS_FLOW
        result = extract(data, strict=False)
        assert result.stats.events_seen == 3
        assert result.stats.events_parsed == 2
        assert result.stats.events_dropped == 1
        assert result.stats.facts_emitted == 2 * FACTS_PER_FLOW

    def test_permissive_error_snippet_truncated(self):
        """Error raw_snippet is truncated to 200 chars."""
        long_row = "x" * 300 + ",y,z"
        data = HEADER + "\n" + long_row
        result = extract(data, strict=False)
        assert len(result.errors) == 1
        assert len(result.errors[0].raw_snippet) <= 200

    def test_permissive_error_line_number_correct(self):
        """Error line numbers are correct."""
        data = HEADER + "\n" + HTTPS_FLOW + "\n" + "bad,row"
        result = extract(data, strict=False)
        # Header is line 1, HTTPS is line 2, bad is line 3
        assert result.errors[0].line_number == 3

    def test_permissive_all_bad_rows(self):
        """All bad rows produce errors with no facts."""
        data = HEADER + "\n" + "bad,row" + "\n" + "also,bad"
        result = extract(data, strict=False)
        assert len(result.facts) == 0
        assert len(result.errors) == 2
        assert result.success is False
        assert result.partial is False


# =============================================================================
# ExtractionStats Tests
# =============================================================================


class TestNetFlowStats:
    """Tests for ExtractionStats accuracy."""

    def test_stats_events_seen_counts_data_rows(self):
        """events_seen counts all data rows, not header."""
        result = extract(REALISTIC_STREAM)
        assert result.stats.events_seen == 8  # 8 flow records

    def test_stats_events_parsed_counts_successes(self):
        """events_parsed counts successful parses."""
        result = extract(REALISTIC_STREAM)
        assert result.stats.events_parsed == 8

    def test_stats_events_dropped_zero_on_success(self):
        """events_dropped is 0 when all rows parse."""
        result = extract(REALISTIC_STREAM)
        assert result.stats.events_dropped == 0

    def test_stats_facts_emitted_total(self):
        """facts_emitted counts total facts across all flows."""
        result = extract(REALISTIC_STREAM)
        assert result.stats.facts_emitted == 8 * FACTS_PER_FLOW

    def test_stats_consistency(self):
        """events_parsed + events_dropped <= events_seen."""
        data = HEADER + "\n" + HTTPS_FLOW + "\n" + "bad" + "\n" + DNS_FLOW
        result = extract(data, strict=False)
        s = result.stats
        assert s.events_parsed + s.events_dropped <= s.events_seen


# =============================================================================
# Header Handling Tests
# =============================================================================


class TestNetFlowHeaderHandling:
    """Tests for header detection and alias resolution."""

    def test_header_standard_recognized(self):
        """Standard header parsed correctly."""
        result = extract(HEADER + "\n" + HTTPS_FLOW)
        assert result.success is True
        assert len(result.facts) == FACTS_PER_FLOW

    def test_header_alias_source_ip(self):
        """Alias header 'source_ip' recognized."""
        alias_header = "start_time,end_time,duration_ms,source_ip,dst_ip,src_port,dst_port,protocol,packets,bytes,tcp_flags,tos"
        result = extract(alias_header + "\n" + HTTPS_FLOW)
        assert result.success is True
        fact_map = {f.field: f.value for f in result.facts}
        assert fact_map["src_ip"] == "10.0.1.50"

    def test_header_alias_destination_port(self):
        """Alias header 'destination_port' recognized."""
        alias_header = "start_time,end_time,duration_ms,src_ip,dst_ip,src_port,destination_port,protocol,packets,bytes,tcp_flags,tos"
        result = extract(alias_header + "\n" + HTTPS_FLOW)
        assert result.success is True
        fact_map = {f.field: f.value for f in result.facts}
        assert fact_map["dst_port"] == "443"

    def test_header_alias_dest_ip(self):
        """Alias header 'dest_ip' recognized."""
        alias_header = "start_time,end_time,dur,src_addr,dest_ip,source_port,dest_port,protocol,pkts,octets,tcp_flags,tos"
        result = extract(alias_header + "\n" + HTTPS_FLOW)
        assert result.success is True

    def test_header_no_header_positional(self):
        """No-header input uses positional mapping."""
        # First line looks like data (has IP addresses)
        result = extract(HTTPS_FLOW)
        assert result.success is True
        assert len(result.facts) == FACTS_PER_FLOW

    def test_header_invalid_strict_raises(self):
        """Invalid header in strict mode raises ValueError."""
        bad_header = "col_a,col_b,col_c,col_d"
        with pytest.raises(ValueError, match="unrecognized header"):
            extract(bad_header + "\n" + HTTPS_FLOW)

    def test_header_extra_columns_ignored(self):
        """Extra columns in data rows are ignored."""
        data = HEADER + "\n" + HTTPS_FLOW + ",extra_val_1,extra_val_2"
        result = extract(data)
        assert result.success is True
        assert len(result.facts) == FACTS_PER_FLOW

    def test_header_missing_required_column_strict_raises(self):
        """Missing required column in header raises ValueError."""
        # Missing 'tos' column
        partial_header = "start_time,end_time,duration_ms,src_ip,dst_ip,src_port,dst_port,protocol,packets,bytes,tcp_flags"
        with pytest.raises(ValueError, match="missing required columns"):
            extract(partial_header + "\n" + HTTPS_FLOW)


# =============================================================================
# Integration Tests
# =============================================================================


class TestNetFlowIntegration:
    """Integration tests for realistic scenarios."""

    def test_integration_mixed_flow_types(self):
        """Mixed flow types parse correctly."""
        result = extract(REALISTIC_STREAM)
        assert result.success is True
        assert result.stats.events_parsed == 8
        entity_ids = {f.entity_id for f in result.facts}
        assert len(entity_ids) == 8  # 8 unique flows

    def test_integration_large_input(self):
        """Large input (100+ rows) works correctly."""
        rows = [HEADER]
        for i in range(120):
            port = 10000 + i
            rows.append(
                f"2026-03-04T14:00:00Z,2026-03-04T14:00:01Z,1000,"
                f"10.0.1.{i % 256},10.0.2.{i % 256},{port},443,TCP,10,5000,SA,0"
            )
        data = "\n".join(rows)
        result = extract(data)
        assert result.success is True
        assert result.stats.events_parsed == 120
        assert result.stats.facts_emitted == 120 * FACTS_PER_FLOW

    def test_integration_output_facts_into_evidence_packet(self):
        """Output Facts can be added to EvidencePacket and frozen."""
        result = extract(HEADER + "\n" + HTTPS_FLOW)
        tw = TimeWindow(
            start=datetime(2026, 3, 4, 14, 0, 0),
            end=datetime(2026, 3, 4, 15, 0, 0),
        )
        packet = EvidencePacket(packet_id="test-netflow-001", time_window=tw)
        for fact in result.facts:
            packet.add_fact(fact)
        packet.freeze()
        assert packet.fact_count == FACTS_PER_FLOW
        assert packet.is_frozen

    def test_integration_result_fields_populated(self):
        """ExtractionResult fields all populated."""
        result = extract(REALISTIC_STREAM)
        assert isinstance(result.facts, tuple)
        assert isinstance(result.errors, tuple)
        assert isinstance(result.stats, ExtractionStats)
        assert result.source_ref == SOURCE_REF
        assert result.extractor_version == NetFlowExtractor.VERSION

    def test_integration_realistic_stream_complete(self):
        """Realistic stream parses completely with no errors."""
        result = extract(REALISTIC_STREAM)
        assert result.success is True
        assert len(result.errors) == 0
        assert result.stats.events_dropped == 0

    def test_integration_bytes_input(self):
        """Bytes input is decoded and parsed."""
        data = (HEADER + "\n" + HTTPS_FLOW).encode("utf-8")
        result = extract(data)
        assert result.success is True
        assert len(result.facts) == FACTS_PER_FLOW

    def test_integration_multiple_flows_different_entities(self):
        """Multiple flows produce distinct entity IDs."""
        data = HEADER + "\n" + HTTPS_FLOW + "\n" + DNS_FLOW + "\n" + LARGE_SSH
        result = extract(data)
        entity_ids = {f.entity_id for f in result.facts}
        assert len(entity_ids) == 3

    def test_integration_fact_hashes_valid(self):
        """All facts have valid value hashes."""
        result = extract(REALISTIC_STREAM)
        for fact in result.facts:
            assert fact.verify_hash()


# =============================================================================
# Edge Case Tests
# =============================================================================


class TestNetFlowEdgeCases:
    """Edge case tests."""

    def test_edge_empty_string(self):
        """Empty string returns empty result."""
        result = extract("")
        assert result.stats.events_seen == 0
        assert len(result.facts) == 0

    def test_edge_empty_bytes(self):
        """Empty bytes returns empty result."""
        result = extract(b"")
        assert result.stats.events_seen == 0
        assert len(result.facts) == 0

    def test_edge_header_only(self):
        """Header-only input returns empty result."""
        result = extract(HEADER)
        assert result.stats.events_seen == 0
        assert len(result.facts) == 0

    def test_edge_single_flow_no_header(self):
        """Single flow record without header parses."""
        result = extract(HTTPS_FLOW)
        assert result.success is True
        assert len(result.facts) == FACTS_PER_FLOW

    def test_edge_single_flow_with_header(self):
        """Single flow record with header parses."""
        result = extract(HEADER + "\n" + HTTPS_FLOW)
        assert result.success is True
        assert len(result.facts) == FACTS_PER_FLOW

    def test_edge_zero_duration_flow(self):
        """Zero-duration flow is valid."""
        zero_dur = "2026-03-04T14:00:00Z,2026-03-04T14:00:00Z,0,10.0.1.50,10.0.1.1,1234,53,UDP,2,100,0,0"
        result = extract(HEADER + "\n" + zero_dur)
        assert result.success is True
        fact_map = {f.field: f.value for f in result.facts}
        assert fact_map["duration_ms"] == "0"

    def test_edge_zero_byte_zero_packet_flow(self):
        """Zero-byte, zero-packet flow is valid (RST/timeout)."""
        zero_flow = "2026-03-04T14:00:00Z,2026-03-04T14:00:00Z,0,10.0.1.50,10.0.1.1,0,0,TCP,0,0,R,0"
        result = extract(HEADER + "\n" + zero_flow)
        assert result.success is True
        fact_map = {f.field: f.value for f in result.facts}
        assert fact_map["packets"] == "0"
        assert fact_map["bytes"] == "0"

    def test_edge_icmp_port_zero_valid(self):
        """ICMP with port 0 is valid."""
        result = extract(HEADER + "\n" + ICMP_FLOW)
        assert result.success is True
        fact_map = {f.field: f.value for f in result.facts}
        assert fact_map["src_port"] == "0"
        assert fact_map["dst_port"] == "0"

    def test_edge_duplicate_flows_both_parsed(self):
        """Duplicate flow records are both valid."""
        data = HEADER + "\n" + HTTPS_FLOW + "\n" + HTTPS_FLOW
        result = extract(data)
        # Both parsed — same 5-tuple can appear at different capture points
        assert result.stats.events_parsed == 2
        assert len(result.facts) == 2 * FACTS_PER_FLOW

    def test_edge_blank_lines_skipped(self):
        """Blank lines in input are skipped."""
        data = HEADER + "\n\n" + HTTPS_FLOW + "\n\n" + DNS_FLOW + "\n\n"
        result = extract(data)
        assert result.success is True
        assert result.stats.events_parsed == 2

    def test_edge_very_long_row_truncated_in_error(self):
        """Very long row has snippet truncated in error."""
        long_row = ",".join(["x" * 50] * 20)
        data = HEADER + "\n" + long_row
        result = extract(data, strict=False)
        if result.errors:
            assert len(result.errors[0].raw_snippet) <= 200

    def test_edge_max_port_65535_valid(self):
        """Port 65535 is valid."""
        max_port = "2026-03-04T14:00:00Z,2026-03-04T14:00:01Z,1000,10.0.1.1,10.0.1.2,65535,65535,TCP,1,100,S,0"
        result = extract(HEADER + "\n" + max_port)
        assert result.success is True
        fact_map = {f.field: f.value for f in result.facts}
        assert fact_map["src_port"] == "65535"
        assert fact_map["dst_port"] == "65535"

    def test_edge_port_zero_valid(self):
        """Port 0 is valid."""
        zero_port = "2026-03-04T14:00:00Z,2026-03-04T14:00:01Z,1000,10.0.1.1,10.0.1.2,0,0,ICMP,1,100,0,0"
        result = extract(HEADER + "\n" + zero_port)
        assert result.success is True

    def test_edge_validate_ipv4_helper(self):
        """_validate_ipv4 correctly validates IPs."""
        assert _validate_ipv4("10.0.1.1") is True
        assert _validate_ipv4("255.255.255.255") is True
        assert _validate_ipv4("0.0.0.0") is True
        assert _validate_ipv4("999.999.999.999") is False
        assert _validate_ipv4("not_an_ip") is False
        assert _validate_ipv4("") is False
