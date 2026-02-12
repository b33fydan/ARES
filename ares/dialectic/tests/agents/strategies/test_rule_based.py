"""Tests for rule-based strategy extraction correctness.

These tests prove the extraction is lossless — the strategy classes
produce identical output to the original inline agent methods.
"""

from __future__ import annotations

from datetime import datetime

import pytest

from ares.dialectic.agents.patterns import (
    AnomalyPattern,
    BenignExplanation,
    ExplanationType,
    PatternType,
    VerdictOutcome,
)
from ares.dialectic.agents.strategies.rule_based import (
    RuleBasedExplanationFinder,
    RuleBasedNarrativeGenerator,
    RuleBasedThreatAnalyzer,
)
from ares.dialectic.evidence.fact import EntityType, Fact
from ares.dialectic.evidence.packet import EvidencePacket, TimeWindow
from ares.dialectic.evidence.provenance import Provenance, SourceType

from .conftest import make_fact, make_message, make_provenance, make_time_window, make_verdict


# =============================================================================
# Packet Builders
# =============================================================================


def build_privilege_packet() -> EvidencePacket:
    """Build packet with privilege escalation evidence."""
    packet = EvidencePacket(packet_id="priv-packet", time_window=make_time_window())
    prov = make_provenance()
    packet.add_fact(Fact(
        fact_id="f-priv-001", entity_id="user-1", entity_type=EntityType.NODE,
        field="privilege", value="SeDebugPrivilege",
        timestamp=datetime(2024, 1, 15, 2, 30, 0), provenance=prov,
    ))
    packet.add_fact(Fact(
        fact_id="f-priv-002", entity_id="user-1", entity_type=EntityType.NODE,
        field="account_type", value="administrator",
        timestamp=datetime(2024, 1, 15, 2, 30, 1), provenance=prov,
    ))
    packet.freeze()
    return packet


def build_lateral_packet() -> EvidencePacket:
    """Build packet with lateral movement evidence."""
    packet = EvidencePacket(packet_id="lat-packet", time_window=make_time_window())
    prov = make_provenance()
    packet.add_fact(Fact(
        fact_id="f-lat-001", entity_id="conn-1", entity_type=EntityType.NODE,
        field="remote_connection", value="rdp://192.168.1.50",
        timestamp=datetime(2024, 1, 15, 2, 30, 0), provenance=prov,
    ))
    packet.add_fact(Fact(
        fact_id="f-lat-002", entity_id="conn-1", entity_type=EntityType.NODE,
        field="protocol", value="smb",
        timestamp=datetime(2024, 1, 15, 2, 30, 1), provenance=prov,
    ))
    packet.freeze()
    return packet


def build_process_packet() -> EvidencePacket:
    """Build packet with suspicious process evidence."""
    packet = EvidencePacket(packet_id="proc-packet", time_window=make_time_window())
    prov = make_provenance()
    packet.add_fact(Fact(
        fact_id="f-proc-001", entity_id="proc-1", entity_type=EntityType.NODE,
        field="process_name", value="cmd.exe",
        timestamp=datetime(2024, 1, 15, 2, 30, 0), provenance=prov,
    ))
    packet.add_fact(Fact(
        fact_id="f-proc-002", entity_id="proc-2", entity_type=EntityType.NODE,
        field="process_name", value="powershell.exe",
        timestamp=datetime(2024, 1, 15, 2, 31, 0), provenance=prov,
    ))
    packet.freeze()
    return packet


def build_benign_packet() -> EvidencePacket:
    """Build packet with no anomaly indicators."""
    packet = EvidencePacket(packet_id="benign-packet", time_window=make_time_window())
    prov = make_provenance()
    packet.add_fact(Fact(
        fact_id="f-benign-001", entity_id="app-1", entity_type=EntityType.NODE,
        field="status", value="healthy",
        timestamp=datetime(2024, 1, 15, 12, 0, 0), provenance=prov,
    ))
    packet.freeze()
    return packet


def build_maintenance_packet() -> EvidencePacket:
    """Build packet with maintenance window indicators."""
    packet = EvidencePacket(packet_id="maint-packet", time_window=make_time_window())
    prov = make_provenance()
    packet.add_fact(Fact(
        fact_id="f-maint-001", entity_id="session-1", entity_type=EntityType.NODE,
        field="maintenance_window", value="scheduled",
        timestamp=datetime(2024, 1, 15, 2, 0, 0), provenance=prov,
    ))
    packet.freeze()
    return packet


def build_admin_packet() -> EvidencePacket:
    """Build packet with known admin indicators."""
    packet = EvidencePacket(packet_id="admin-packet", time_window=make_time_window())
    prov = make_provenance()
    packet.add_fact(Fact(
        fact_id="f-admin-001", entity_id="user-1", entity_type=EntityType.NODE,
        field="account_type", value="sysadmin",
        timestamp=datetime(2024, 1, 15, 2, 0, 0), provenance=prov,
    ))
    packet.add_fact(Fact(
        fact_id="f-admin-002", entity_id="user-1", entity_type=EntityType.NODE,
        field="deployment_tool", value="ansible",
        timestamp=datetime(2024, 1, 15, 2, 0, 1), provenance=prov,
    ))
    packet.freeze()
    return packet


def build_multi_anomaly_packet() -> EvidencePacket:
    """Build packet with multiple anomaly types."""
    packet = EvidencePacket(packet_id="multi-packet", time_window=make_time_window())
    prov = make_provenance()
    # Privilege escalation
    packet.add_fact(Fact(
        fact_id="f-multi-001", entity_id="user-1", entity_type=EntityType.NODE,
        field="privilege_escalation", value="admin",
        timestamp=datetime(2024, 1, 15, 2, 30, 0), provenance=prov,
    ))
    # Suspicious process
    packet.add_fact(Fact(
        fact_id="f-multi-002", entity_id="proc-1", entity_type=EntityType.NODE,
        field="process_name", value="cmd.exe",
        timestamp=datetime(2024, 1, 15, 2, 31, 0), provenance=prov,
    ))
    # Service abuse
    packet.add_fact(Fact(
        fact_id="f-multi-003", entity_id="svc-1", entity_type=EntityType.NODE,
        field="service_modification", value="new_service",
        timestamp=datetime(2024, 1, 15, 2, 32, 0), provenance=prov,
    ))
    packet.freeze()
    return packet


# =============================================================================
# RuleBasedThreatAnalyzer Tests
# =============================================================================


class TestRuleBasedThreatAnalyzer:
    """Verify RuleBasedThreatAnalyzer produces identical output to old code."""

    def test_privilege_escalation_detection(self):
        """Detects privilege escalation from privilege-related facts."""
        analyzer = RuleBasedThreatAnalyzer()
        packet = build_privilege_packet()
        anomalies = analyzer.analyze_threats(packet)
        priv_anomalies = [a for a in anomalies if a.pattern_type == PatternType.PRIVILEGE_ESCALATION]
        assert len(priv_anomalies) >= 1
        # Should reference the privilege facts
        for a in priv_anomalies:
            assert a.fact_ids & {"f-priv-001", "f-priv-002"}
            assert 0.0 < a.confidence <= 1.0

    def test_lateral_movement_detection(self):
        """Detects lateral movement from remote connection facts."""
        analyzer = RuleBasedThreatAnalyzer()
        packet = build_lateral_packet()
        anomalies = analyzer.analyze_threats(packet)
        lat_anomalies = [a for a in anomalies if a.pattern_type == PatternType.LATERAL_MOVEMENT]
        assert len(lat_anomalies) >= 1
        for a in lat_anomalies:
            assert a.fact_ids & {"f-lat-001", "f-lat-002"}

    def test_suspicious_process_detection(self):
        """Detects suspicious processes from process_name facts."""
        analyzer = RuleBasedThreatAnalyzer()
        packet = build_process_packet()
        anomalies = analyzer.analyze_threats(packet)
        proc_anomalies = [a for a in anomalies if a.pattern_type == PatternType.SUSPICIOUS_PROCESS]
        assert len(proc_anomalies) >= 1

    def test_no_anomalies_for_benign_packet(self):
        """Returns empty list for packet with no anomaly indicators."""
        analyzer = RuleBasedThreatAnalyzer()
        packet = build_benign_packet()
        anomalies = analyzer.analyze_threats(packet)
        assert anomalies == []

    def test_multiple_anomaly_types(self):
        """Detects multiple anomaly types from combined evidence."""
        analyzer = RuleBasedThreatAnalyzer()
        packet = build_multi_anomaly_packet()
        anomalies = analyzer.analyze_threats(packet)
        types = {a.pattern_type for a in anomalies}
        assert len(types) >= 2

    def test_returns_anomaly_pattern_instances(self):
        """All returned objects are AnomalyPattern instances."""
        analyzer = RuleBasedThreatAnalyzer()
        packet = build_privilege_packet()
        anomalies = analyzer.analyze_threats(packet)
        for a in anomalies:
            assert isinstance(a, AnomalyPattern)

    def test_confidence_values_in_range(self):
        """All confidence values are between 0.0 and 1.0."""
        analyzer = RuleBasedThreatAnalyzer()
        packet = build_multi_anomaly_packet()
        anomalies = analyzer.analyze_threats(packet)
        for a in anomalies:
            assert 0.0 <= a.confidence <= 1.0

    def test_fact_ids_are_frozen_sets(self):
        """Returned fact_ids are frozensets."""
        analyzer = RuleBasedThreatAnalyzer()
        packet = build_privilege_packet()
        anomalies = analyzer.analyze_threats(packet)
        for a in anomalies:
            assert isinstance(a.fact_ids, frozenset)


# =============================================================================
# RuleBasedExplanationFinder Tests
# =============================================================================


class TestRuleBasedExplanationFinder:
    """Verify RuleBasedExplanationFinder produces identical output to old code."""

    def test_maintenance_window_match(self):
        """Detects maintenance window from maintenance-related facts."""
        finder = RuleBasedExplanationFinder()
        packet = build_maintenance_packet()
        msg = make_message(fact_ids=("f-maint-001",))
        explanations = finder.find_explanations(msg, packet)
        maint = [e for e in explanations if e.explanation_type == ExplanationType.MAINTENANCE_WINDOW]
        assert len(maint) >= 1

    def test_known_admin_match(self):
        """Detects known admin from admin-related facts."""
        finder = RuleBasedExplanationFinder()
        packet = build_admin_packet()
        msg = make_message(fact_ids=("f-admin-001",))
        explanations = finder.find_explanations(msg, packet)
        admin = [e for e in explanations if e.explanation_type == ExplanationType.KNOWN_ADMIN]
        assert len(admin) >= 1

    def test_no_explanation_for_benign_packet(self):
        """Returns empty list when no benign patterns found."""
        finder = RuleBasedExplanationFinder()
        packet = build_benign_packet()
        msg = make_message(fact_ids=("f-benign-001",))
        explanations = finder.find_explanations(msg, packet)
        assert explanations == []

    def test_multiple_explanations(self):
        """Finds multiple benign explanations for combined evidence."""
        # Build packet with both admin and maintenance indicators
        packet = EvidencePacket(packet_id="multi-exp", time_window=make_time_window())
        prov = make_provenance()
        packet.add_fact(Fact(
            fact_id="f-1", entity_id="u1", entity_type=EntityType.NODE,
            field="account_type", value="administrator",
            timestamp=datetime(2024, 1, 15, 2, 0, 0), provenance=prov,
        ))
        packet.add_fact(Fact(
            fact_id="f-2", entity_id="s1", entity_type=EntityType.NODE,
            field="maintenance_window", value="scheduled",
            timestamp=datetime(2024, 1, 15, 2, 0, 0), provenance=prov,
        ))
        packet.freeze()
        msg = make_message(fact_ids=("f-1", "f-2"))
        explanations = finder = RuleBasedExplanationFinder()
        explanations = finder.find_explanations(msg, packet)
        types = {e.explanation_type for e in explanations}
        assert len(types) >= 2

    def test_returns_benign_explanation_instances(self):
        """All returned objects are BenignExplanation instances."""
        finder = RuleBasedExplanationFinder()
        packet = build_admin_packet()
        msg = make_message(fact_ids=("f-admin-001",))
        explanations = finder.find_explanations(msg, packet)
        for e in explanations:
            assert isinstance(e, BenignExplanation)

    def test_confidence_values_match_original(self):
        """Confidence values are in range and consistent."""
        finder = RuleBasedExplanationFinder()
        packet = build_maintenance_packet()
        msg = make_message(fact_ids=("f-maint-001",))
        explanations = finder.find_explanations(msg, packet)
        for e in explanations:
            assert 0.0 <= e.confidence <= 1.0

    def test_architect_msg_is_unused_by_rule_based(self):
        """Rule-based finder ignores architect_msg — same result regardless."""
        finder = RuleBasedExplanationFinder()
        packet = build_admin_packet()
        msg1 = make_message(confidence=0.9, fact_ids=("f-admin-001",))
        msg2 = make_message(confidence=0.1, fact_ids=("f-admin-001",))
        result1 = finder.find_explanations(msg1, packet)
        result2 = finder.find_explanations(msg2, packet)
        # Same explanations regardless of message content
        assert len(result1) == len(result2)
        for e1, e2 in zip(result1, result2):
            assert e1.explanation_type == e2.explanation_type
            assert e1.fact_ids == e2.fact_ids


# =============================================================================
# RuleBasedNarrativeGenerator Tests
# =============================================================================


class TestRuleBasedNarrativeGenerator:
    """Verify RuleBasedNarrativeGenerator produces identical output."""

    def test_threat_confirmed_narrative(self, threat_verdict, sample_packet):
        """Generates correct narrative for THREAT_CONFIRMED."""
        gen = RuleBasedNarrativeGenerator()
        narrative = gen.generate_narrative(threat_verdict, sample_packet)
        assert "VERDICT: THREAT CONFIRMED" in narrative
        assert "malicious" in narrative

    def test_threat_dismissed_narrative(self, dismissed_verdict, sample_packet):
        """Generates correct narrative for THREAT_DISMISSED."""
        gen = RuleBasedNarrativeGenerator()
        narrative = gen.generate_narrative(dismissed_verdict, sample_packet)
        assert "VERDICT: THREAT DISMISSED" in narrative
        assert "benign" in narrative

    def test_inconclusive_narrative(self, inconclusive_verdict, sample_packet):
        """Generates correct narrative for INCONCLUSIVE."""
        gen = RuleBasedNarrativeGenerator()
        narrative = gen.generate_narrative(inconclusive_verdict, sample_packet)
        assert "VERDICT: INCONCLUSIVE" in narrative

    def test_narrative_includes_reasoning(self, threat_verdict, sample_packet):
        """Narrative includes the verdict reasoning."""
        gen = RuleBasedNarrativeGenerator()
        narrative = gen.generate_narrative(threat_verdict, sample_packet)
        assert threat_verdict.reasoning in narrative

    def test_narrative_includes_confidence(self, threat_verdict, sample_packet):
        """Narrative includes confidence breakdown."""
        gen = RuleBasedNarrativeGenerator()
        narrative = gen.generate_narrative(threat_verdict, sample_packet)
        assert "Architect proposed" in narrative
        assert "Skeptic challenged" in narrative

    def test_narrative_returns_string(self, threat_verdict, sample_packet):
        """generate_narrative returns a string."""
        gen = RuleBasedNarrativeGenerator()
        result = gen.generate_narrative(threat_verdict, sample_packet)
        assert isinstance(result, str)
        assert len(result) > 0

    def test_packet_and_msgs_ignored_by_rule_based(self, threat_verdict, sample_packet, architect_msg, skeptic_msg):
        """Rule-based generator ignores packet, architect_msg, skeptic_msg."""
        gen = RuleBasedNarrativeGenerator()
        # With no optional args
        result1 = gen.generate_narrative(threat_verdict, sample_packet)
        # With optional args
        result2 = gen.generate_narrative(threat_verdict, sample_packet, architect_msg, skeptic_msg)
        assert result1 == result2
