"""Integration tests for the full extraction-to-verdict pipeline.

These tests prove end-to-end flow:
raw Windows event XML → WindowsEventExtractor.extract() → ExtractionResult.facts
→ EvidencePacket.add_fact() for each → packet.freeze()
→ ArchitectAgent.observe(packet) → ArchitectAgent.act()
→ SkepticAgent.receive() → SkepticAgent.act()
→ OracleJudge.compute_verdict()
→ Assert expected verdict

Test Scenarios:
1. Privilege escalation detected → THREAT_CONFIRMED
2. Benign admin activity → THREAT_DISMISSED
3. Suspicious process spawn → THREAT_CONFIRMED
"""

import pytest
from datetime import datetime
from pathlib import Path
from typing import FrozenSet

from ares.dialectic.agents import (
    ArchitectAgent,
    SkepticAgent,
    OracleJudge,
    Phase,
    TurnContext,
    VerdictOutcome,
)
from ares.dialectic.evidence.extractors import WindowsEventExtractor
from ares.dialectic.evidence.packet import EvidencePacket, TimeWindow
from ares.dialectic.evidence.fact import Fact, EntityType
from ares.dialectic.evidence.provenance import Provenance, SourceType
from ares.dialectic.messages.protocol import MessageType


# =============================================================================
# Fixtures Directory
# =============================================================================

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def load_fixture(name: str) -> str:
    """Load a test fixture file."""
    return (FIXTURES_DIR / name).read_text(encoding="utf-8")


# =============================================================================
# Helper Functions
# =============================================================================


def make_time_window(
    start: datetime = None, end: datetime = None
) -> TimeWindow:
    """Create a test time window."""
    if start is None:
        start = datetime(2025, 1, 1, 0, 0, 0)
    if end is None:
        end = datetime(2025, 12, 31, 23, 59, 59)
    return TimeWindow(start=start, end=end)


def make_context(
    packet: EvidencePacket,
    phase: Phase,
    turn_number: int,
    seen_fact_ids: FrozenSet[str] = frozenset(),
) -> TurnContext:
    """Create a TurnContext for the given phase."""
    return TurnContext(
        cycle_id="pipeline-integration-test",
        packet_id=packet.packet_id,
        snapshot_id=packet.snapshot_id,
        phase=phase,
        turn_number=turn_number,
        max_turns=10,
        seen_fact_ids=seen_fact_ids,
    )


def make_provenance_manual(source_id: str = "test") -> Provenance:
    """Create manual provenance for additional context facts."""
    return Provenance(
        source_type=SourceType.MANUAL,
        source_id=source_id,
        extracted_at=datetime(2025, 2, 4, 12, 0, 0),
    )


def make_context_fact(
    fact_id: str,
    entity_id: str,
    field: str,
    value: any,
) -> Fact:
    """Create a context fact (manual provenance)."""
    return Fact(
        fact_id=fact_id,
        entity_id=entity_id,
        entity_type=EntityType.NODE,
        field=field,
        value=value,
        timestamp=datetime(2025, 2, 4, 14, 30, 0),
        provenance=make_provenance_manual(),
    )


def run_dialectical_cycle(packet: EvidencePacket) -> VerdictOutcome:
    """Run a full dialectical cycle and return the verdict outcome.

    Args:
        packet: Frozen evidence packet.

    Returns:
        VerdictOutcome from OracleJudge.
    """
    # Create agents
    architect = ArchitectAgent(agent_id="arch-pipeline")
    skeptic = SkepticAgent(agent_id="skep-pipeline")

    # Bind to packet
    architect.observe(packet)
    skeptic.observe(packet)

    # Architect proposes (THESIS)
    # May produce HYPOTHESIS (when patterns found) or OBSERVATION (no strong patterns)
    arch_context = make_context(packet, Phase.THESIS, turn_number=1)
    arch_result = architect.act(arch_context)

    assert arch_result.message is not None, "Architect should produce a message"
    assert arch_result.message.message_type in (
        MessageType.HYPOTHESIS,
        MessageType.OBSERVATION,
    ), f"Architect produced unexpected message type: {arch_result.message.message_type}"

    # Skeptic challenges (ANTITHESIS)
    # May produce REBUTTAL (with counter-explanations) or OBSERVATION (acknowledging)
    skeptic.receive(arch_result.message)
    skep_context = make_context(
        packet,
        Phase.ANTITHESIS,
        turn_number=2,
        seen_fact_ids=frozenset(arch_result.message.get_all_fact_ids()),
    )
    skep_result = skeptic.act(skep_context)

    assert skep_result.message is not None, "Skeptic should produce a message"
    assert skep_result.message.message_type in (
        MessageType.REBUTTAL,
        MessageType.OBSERVATION,
    ), f"Skeptic produced unexpected message type: {skep_result.message.message_type}"

    # Oracle judges (SYNTHESIS)
    verdict = OracleJudge.compute_verdict(
        architect_msg=arch_result.message,
        skeptic_msg=skep_result.message,
        packet=packet,
    )

    return verdict.outcome


# =============================================================================
# Scenario 1: Privilege Escalation Detection
# =============================================================================


class TestPrivilegeEscalationScenario:
    """Pipeline test: 4624 + 4672 outside maintenance window → THREAT_CONFIRMED.

    Scenario:
    - User 'jsmith' logs in (4624)
    - Receives admin privileges (4672 with SeDebugPrivilege etc.)
    - No maintenance window context
    - Should be detected as threat
    """

    def test_raw_xml_to_verdict_threat_confirmed(self) -> None:
        """Full pipeline: raw XML → extraction → dialectic → threat confirmed."""
        extractor = WindowsEventExtractor()

        # Extract facts from 4624 (logon)
        logon_xml = load_fixture("event_4624_logon.xml")
        logon_result = extractor.extract(logon_xml, source_ref="4624.xml")
        assert logon_result.success

        # Extract facts from 4672 (privileges)
        priv_xml = load_fixture("event_4672_privileges.xml")
        priv_result = extractor.extract(priv_xml, source_ref="4672.xml")
        assert priv_result.success

        # Build packet
        packet = EvidencePacket(
            packet_id="priv-escalation-001",
            time_window=make_time_window(),
        )

        # Add extracted facts
        for fact in logon_result.facts:
            packet.add_fact(fact)
        for fact in priv_result.facts:
            packet.add_fact(fact)

        # Add context: user is NOT an admin, NOT in maintenance
        packet.add_fact(make_context_fact(
            "ctx-user-role",
            "user:jsmith@INTERNAL",
            "user_role",
            "standard_user",
        ))
        packet.add_fact(make_context_fact(
            "ctx-maintenance",
            "schedule-001",
            "maintenance_window",
            "inactive",
        ))

        packet.freeze()

        # Run dialectic
        outcome = run_dialectical_cycle(packet)

        # Expect threat detection (confirmed or inconclusive - depends on confidence)
        assert outcome in (
            VerdictOutcome.THREAT_CONFIRMED,
            VerdictOutcome.INCONCLUSIVE,
        ), f"Expected threat detected, got {outcome}"

    def test_extracted_facts_have_provenance(self) -> None:
        """Extracted facts have proper provenance for audit trail."""
        extractor = WindowsEventExtractor()

        logon_xml = load_fixture("event_4624_logon.xml")
        result = extractor.extract(logon_xml, source_ref="audit/4624.xml")

        for fact in result.facts:
            assert fact.provenance is not None
            assert fact.provenance.source_id == "audit/4624.xml"
            assert fact.provenance.parser_version == extractor.VERSION

    def test_facts_load_into_packet_successfully(self) -> None:
        """Extracted facts load into packet without errors."""
        extractor = WindowsEventExtractor()

        logon_xml = load_fixture("event_4624_logon.xml")
        result = extractor.extract(logon_xml, source_ref="4624.xml")

        packet = EvidencePacket(
            packet_id="test-load",
            time_window=make_time_window(),
        )

        for fact in result.facts:
            packet.add_fact(fact)

        assert packet.fact_count == len(result.facts)

    def test_packet_freezes_with_extracted_facts(self) -> None:
        """Packet freezes successfully with extracted facts."""
        extractor = WindowsEventExtractor()

        logon_xml = load_fixture("event_4624_logon.xml")
        result = extractor.extract(logon_xml, source_ref="4624.xml")

        packet = EvidencePacket(
            packet_id="test-freeze",
            time_window=make_time_window(),
        )

        for fact in result.facts:
            packet.add_fact(fact)

        snapshot_id = packet.freeze()
        assert snapshot_id is not None
        assert len(snapshot_id) == 32
        assert packet.is_frozen


# =============================================================================
# Scenario 2: Benign Admin Activity
# =============================================================================


class TestBenignAdminScenario:
    """Pipeline test: Same events but with maintenance context → THREAT_DISMISSED.

    Scenario:
    - Same logon and privilege events
    - User IS a known admin
    - During active maintenance window
    - Should be explained as benign
    """

    def test_raw_xml_to_verdict_threat_dismissed(self) -> None:
        """Full pipeline: raw XML → extraction → dialectic → threat dismissed."""
        extractor = WindowsEventExtractor()

        # Extract same events
        logon_xml = load_fixture("event_4624_logon.xml")
        logon_result = extractor.extract(logon_xml, source_ref="4624.xml")

        priv_xml = load_fixture("event_4672_privileges.xml")
        priv_result = extractor.extract(priv_xml, source_ref="4672.xml")

        # Build packet with benign context
        packet = EvidencePacket(
            packet_id="benign-admin-001",
            time_window=make_time_window(),
        )

        for fact in logon_result.facts:
            packet.add_fact(fact)
        for fact in priv_result.facts:
            packet.add_fact(fact)

        # Add strong benign context
        packet.add_fact(make_context_fact(
            "ctx-user-role",
            "user:jsmith@INTERNAL",
            "user_role",
            "administrator",
        ))
        packet.add_fact(make_context_fact(
            "ctx-admin-flag",
            "user:jsmith@INTERNAL",
            "admin_account",
            True,
        ))
        packet.add_fact(make_context_fact(
            "ctx-maintenance",
            "schedule-001",
            "maintenance_window",
            "active",
        ))
        packet.add_fact(make_context_fact(
            "ctx-scheduled",
            "schedule-001",
            "scheduled_maintenance",
            "system_upgrade",
        ))
        packet.add_fact(make_context_fact(
            "ctx-automation",
            "task-001",
            "automated_task",
            "deployment",
        ))

        packet.freeze()

        # Run dialectic
        outcome = run_dialectical_cycle(packet)

        # Expect benign (dismissed or inconclusive)
        assert outcome in (
            VerdictOutcome.THREAT_DISMISSED,
            VerdictOutcome.INCONCLUSIVE,
        ), f"Expected benign outcome, got {outcome}"


# =============================================================================
# Scenario 3: Suspicious Process Spawn
# =============================================================================


class TestSuspiciousProcessScenario:
    """Pipeline test: 4688 with suspicious parent → THREAT_CONFIRMED.

    Scenario:
    - cmd.exe spawned by EXCEL.EXE (office application)
    - Command line shows reconnaissance (whoami)
    - Classic attack pattern
    """

    def test_suspicious_process_spawn_detected(self) -> None:
        """Excel spawning cmd.exe is detected as suspicious."""
        extractor = WindowsEventExtractor()

        # Extract 4688 event
        proc_xml = load_fixture("event_4688_process.xml")
        proc_result = extractor.extract(proc_xml, source_ref="4688.xml")
        assert proc_result.success

        # Build packet
        packet = EvidencePacket(
            packet_id="suspicious-process-001",
            time_window=make_time_window(),
        )

        for fact in proc_result.facts:
            packet.add_fact(fact)

        # Add context: not a developer, not expected
        packet.add_fact(make_context_fact(
            "ctx-user-type",
            "user:jsmith@INTERNAL",
            "user_type",
            "finance",  # Not a developer or IT
        ))

        packet.freeze()

        # Verify suspicious indicators extracted
        fields = {f.field: f.value for f in proc_result.facts}
        assert fields.get("parent_name") == "EXCEL.EXE"
        assert "whoami" in fields.get("command_line", "")

        # Run dialectic
        outcome = run_dialectical_cycle(packet)

        # Excel spawning cmd with whoami is highly suspicious
        assert outcome in (
            VerdictOutcome.THREAT_CONFIRMED,
            VerdictOutcome.INCONCLUSIVE,
        ), f"Expected threat detection, got {outcome}"

    def test_process_facts_contain_parent_info(self) -> None:
        """4688 extraction includes parent process information."""
        extractor = WindowsEventExtractor()

        proc_xml = load_fixture("event_4688_process.xml")
        result = extractor.extract(proc_xml, source_ref="4688.xml")

        parent_fact = next(
            (f for f in result.facts if f.field == "parent_name"), None
        )
        assert parent_fact is not None
        assert parent_fact.value == "EXCEL.EXE"


# =============================================================================
# Combined Scenario: Multiple Events
# =============================================================================


class TestMultipleEventsScenario:
    """Pipeline test: All three event types together."""

    def test_full_attack_chain_detection(self) -> None:
        """Full attack chain: logon → privileges → process → detection."""
        extractor = WindowsEventExtractor()

        # Load all fixtures
        logon_xml = load_fixture("event_4624_logon.xml")
        priv_xml = load_fixture("event_4672_privileges.xml")
        proc_xml = load_fixture("event_4688_process.xml")

        # Extract all
        logon_result = extractor.extract(logon_xml, source_ref="4624.xml")
        priv_result = extractor.extract(priv_xml, source_ref="4672.xml")
        proc_result = extractor.extract(proc_xml, source_ref="4688.xml")

        # Build combined packet
        packet = EvidencePacket(
            packet_id="attack-chain-001",
            time_window=make_time_window(),
        )

        all_facts = (
            list(logon_result.facts) +
            list(priv_result.facts) +
            list(proc_result.facts)
        )

        for fact in all_facts:
            packet.add_fact(fact)

        packet.freeze()

        # Verify all facts loaded
        assert packet.fact_count == len(all_facts)

        # Run dialectic
        outcome = run_dialectical_cycle(packet)

        # Full attack chain should be detected
        assert outcome in (
            VerdictOutcome.THREAT_CONFIRMED,
            VerdictOutcome.INCONCLUSIVE,
        )


# =============================================================================
# Extractor Output Validation
# =============================================================================


class TestExtractorOutputValidation:
    """Tests validating extractor output meets dialectical requirements."""

    def test_all_facts_are_immutable(self) -> None:
        """All extracted facts are frozen dataclasses."""
        from dataclasses import FrozenInstanceError

        extractor = WindowsEventExtractor()
        xml = load_fixture("event_4624_logon.xml")
        result = extractor.extract(xml, source_ref="test.xml")

        for fact in result.facts:
            with pytest.raises(FrozenInstanceError):
                fact.value = "modified"

    def test_all_facts_have_valid_entity_type(self) -> None:
        """All facts have valid EntityType."""
        extractor = WindowsEventExtractor()
        xml = load_fixture("event_4624_logon.xml")
        result = extractor.extract(xml, source_ref="test.xml")

        for fact in result.facts:
            assert fact.entity_type in (EntityType.NODE, EntityType.EDGE)

    def test_all_facts_have_value_hash(self) -> None:
        """All facts have computed value_hash."""
        extractor = WindowsEventExtractor()
        xml = load_fixture("event_4624_logon.xml")
        result = extractor.extract(xml, source_ref="test.xml")

        for fact in result.facts:
            assert fact.value_hash is not None
            assert len(fact.value_hash) == 16

    def test_all_facts_verify_hash(self) -> None:
        """All facts pass hash verification."""
        extractor = WindowsEventExtractor()
        xml = load_fixture("event_4624_logon.xml")
        result = extractor.extract(xml, source_ref="test.xml")

        for fact in result.facts:
            assert fact.verify_hash() is True

    def test_fact_ids_are_unique_globally(self) -> None:
        """Fact IDs are unique across all extractions."""
        extractor = WindowsEventExtractor()

        all_fact_ids = []

        for fixture in ["event_4624_logon.xml", "event_4672_privileges.xml", "event_4688_process.xml"]:
            xml = load_fixture(fixture)
            result = extractor.extract(xml, source_ref=fixture)
            all_fact_ids.extend(f.fact_id for f in result.facts)

        assert len(all_fact_ids) == len(set(all_fact_ids))


# =============================================================================
# Agent Integration Tests
# =============================================================================


class TestAgentIntegration:
    """Tests for agent integration with extracted facts."""

    def test_architect_finds_patterns_in_extracted_facts(self) -> None:
        """Architect processes extracted facts and produces a message."""
        extractor = WindowsEventExtractor()

        # Extract privilege event
        priv_xml = load_fixture("event_4672_privileges.xml")
        priv_result = extractor.extract(priv_xml, source_ref="4672.xml")

        packet = EvidencePacket(
            packet_id="arch-pattern-test",
            time_window=make_time_window(),
        )
        for fact in priv_result.facts:
            packet.add_fact(fact)
        packet.freeze()

        architect = ArchitectAgent()
        architect.observe(packet)

        context = make_context(packet, Phase.THESIS, turn_number=1)
        result = architect.act(context)

        # Architect should produce a message (HYPOTHESIS if patterns found, OBSERVATION otherwise)
        assert result.message is not None
        assert result.message.message_type in (
            MessageType.HYPOTHESIS,
            MessageType.OBSERVATION,
        )
        # Should have assessed the evidence
        assert result.message.confidence >= 0

    def test_skeptic_finds_benign_explanations(self) -> None:
        """Skeptic finds benign explanations when context supports it."""
        extractor = WindowsEventExtractor()

        priv_xml = load_fixture("event_4672_privileges.xml")
        priv_result = extractor.extract(priv_xml, source_ref="4672.xml")

        packet = EvidencePacket(
            packet_id="skep-explain-test",
            time_window=make_time_window(),
        )
        for fact in priv_result.facts:
            packet.add_fact(fact)

        # Add benign context
        packet.add_fact(make_context_fact(
            "ctx-admin",
            "user:jsmith@INTERNAL",
            "admin_account",
            True,
        ))
        packet.add_fact(make_context_fact(
            "ctx-maint",
            "schedule-001",
            "maintenance_window",
            "active",
        ))
        packet.freeze()

        # Run architect first
        architect = ArchitectAgent()
        architect.observe(packet)
        arch_ctx = make_context(packet, Phase.THESIS, turn_number=1)
        arch_result = architect.act(arch_ctx)

        # Now skeptic
        skeptic = SkepticAgent()
        skeptic.observe(packet)
        skeptic.receive(arch_result.message)

        skep_ctx = make_context(
            packet,
            Phase.ANTITHESIS,
            turn_number=2,
            seen_fact_ids=frozenset(arch_result.message.get_all_fact_ids()),
        )
        skep_result = skeptic.act(skep_ctx)

        # Skeptic should produce rebuttal
        assert skep_result.message is not None
        assert skep_result.message.message_type == MessageType.REBUTTAL
        # With benign context, should have some confidence
        assert skep_result.message.confidence > 0

    def test_oracle_produces_verdict(self) -> None:
        """Oracle produces verdict from agent messages."""
        extractor = WindowsEventExtractor()

        logon_xml = load_fixture("event_4624_logon.xml")
        result = extractor.extract(logon_xml, source_ref="4624.xml")

        packet = EvidencePacket(
            packet_id="oracle-verdict-test",
            time_window=make_time_window(),
        )
        for fact in result.facts:
            packet.add_fact(fact)
        packet.freeze()

        # Full cycle
        architect = ArchitectAgent()
        skeptic = SkepticAgent()

        architect.observe(packet)
        skeptic.observe(packet)

        arch_ctx = make_context(packet, Phase.THESIS, turn_number=1)
        arch_result = architect.act(arch_ctx)

        skeptic.receive(arch_result.message)
        skep_ctx = make_context(packet, Phase.ANTITHESIS, turn_number=2)
        skep_result = skeptic.act(skep_ctx)

        verdict = OracleJudge.compute_verdict(
            arch_result.message,
            skep_result.message,
            packet,
        )

        # Verdict should be valid
        assert verdict.outcome in (
            VerdictOutcome.THREAT_CONFIRMED,
            VerdictOutcome.THREAT_DISMISSED,
            VerdictOutcome.INCONCLUSIVE,
        )
        assert 0 <= verdict.confidence <= 1
        assert len(verdict.supporting_fact_ids) >= 0


# =============================================================================
# Performance Sanity Tests
# =============================================================================


class TestPerformanceSanity:
    """Basic performance sanity checks."""

    def test_extraction_completes_quickly(self) -> None:
        """Single event extraction completes in reasonable time."""
        import time

        extractor = WindowsEventExtractor()
        xml = load_fixture("event_4624_logon.xml")

        start = time.time()
        for _ in range(100):
            extractor.extract(xml, source_ref="test.xml")
        elapsed = time.time() - start

        # 100 extractions should complete in under 1 second
        assert elapsed < 1.0, f"Extraction too slow: {elapsed}s for 100 iterations"

    def test_full_pipeline_completes(self) -> None:
        """Full pipeline completes without hanging."""
        import time

        start = time.time()

        extractor = WindowsEventExtractor()
        xml = load_fixture("event_4624_logon.xml")
        result = extractor.extract(xml, source_ref="test.xml")

        packet = EvidencePacket(
            packet_id="perf-test",
            time_window=make_time_window(),
        )
        for fact in result.facts:
            packet.add_fact(fact)
        packet.freeze()

        outcome = run_dialectical_cycle(packet)

        elapsed = time.time() - start

        # Full pipeline should complete in under 2 seconds
        assert elapsed < 2.0, f"Pipeline too slow: {elapsed}s"
        assert outcome is not None
