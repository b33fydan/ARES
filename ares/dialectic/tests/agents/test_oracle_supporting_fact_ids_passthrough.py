"""Anchor tests for the Oracle ``supporting_fact_ids`` passthrough.

These tests lock the Paper 3 (Session 064) Finding 2 architectural
commitment: under outcome ``THREAT_CONFIRMED``, the Verdict's
``supporting_fact_ids`` is sourced verbatim from
``architect_msg.get_all_fact_ids()`` via the assignment

    supporting_facts = frozenset(arch_facts)

at ``oracle.py:102``. The Verdict's *decision* surface (outcome,
confidence) is preserved deterministically by the decision-table call,
but the Verdict's *explanation surface* (the cited-facts set) inherits
whatever the Architect produced. This is the structural source of the
broad-leakage observation in Session 059 run 2.

DO NOT modify this test to make a refactor pass. If a refactor changes
the passthrough behavior, either:

    (a) update this test AND re-run the full leakage harness, OR
    (b) revert the refactor.

The behavior under ``THREAT_DISMISSED`` and ``INCONCLUSIVE`` is also
locked here, because the Paper 3 claim is specifically that the
passthrough is *conditional on outcome* — calling out the other two
branches is what makes the decoupling principle precise.

Source anchors (substring + line-number):
    * line  89: ``arch_facts = architect_msg.get_all_fact_ids()``
    * line 102: ``supporting_facts = frozenset(arch_facts)``  (THREAT_CONFIRMED)
    * line 116: ``supporting_fact_ids=supporting_facts,``  (Verdict construction)
"""

from __future__ import annotations

import inspect
from datetime import datetime
from typing import FrozenSet

import ares.dialectic.agents.oracle as oracle_module
from ares.dialectic.agents import (
    OracleJudge,
    Phase,
    Verdict,
    VerdictOutcome,
)
from ares.dialectic.evidence.fact import Fact, EntityType
from ares.dialectic.evidence.packet import EvidencePacket, TimeWindow
from ares.dialectic.evidence.provenance import Provenance, SourceType
from ares.dialectic.messages.assertions import Assertion, AssertionType
from ares.dialectic.messages.protocol import (
    DialecticalMessage,
    MessageBuilder,
    MessageType,
)


# Lock targets for source-level anchors. EXPECTED_*_LINE constants are
# soft drift detectors — they force a deliberate ADR update if the
# anchor moves, but the substring assertion is the load-bearing one.
EXPECTED_ARCH_FACTS_LINE: str = (
    "arch_facts = architect_msg.get_all_fact_ids()"
)
EXPECTED_ARCH_FACTS_LINE_NUMBER: int = 89
EXPECTED_PASSTHROUGH_LINE: str = "supporting_facts = frozenset(arch_facts)"
EXPECTED_PASSTHROUGH_LINE_NUMBER: int = 102
EXPECTED_VERDICT_ASSIGN_LINE: str = "supporting_fact_ids=supporting_facts,"
EXPECTED_VERDICT_ASSIGN_LINE_NUMBER: int = 116
EXPECTED_FILE_LOCATION: str = "ares/dialectic/agents/oracle.py"


# =============================================================================
# Fixture helpers (inline per project convention: no shared conftest)
# =============================================================================


def _provenance() -> Provenance:
    return Provenance(
        source_type=SourceType.MANUAL,
        source_id="test",
        extracted_at=datetime(2026, 5, 20, 12, 0, 0),
    )


def _fact(fact_id: str, entity_id: str = "node-001") -> Fact:
    return Fact(
        fact_id=fact_id,
        entity_id=entity_id,
        entity_type=EntityType.NODE,
        field="data",
        value="value",
        timestamp=datetime(2026, 5, 20, 12, 0, 0),
        provenance=_provenance(),
    )


def _packet() -> EvidencePacket:
    pkt = EvidencePacket(
        packet_id="passthrough-anchor-packet",
        time_window=TimeWindow(
            start=datetime(2026, 5, 1, 0, 0, 0),
            end=datetime(2026, 5, 31, 23, 59, 59),
        ),
    )
    for fid in ("fact-A1", "fact-A2", "fact-A3", "fact-B1", "fact-B2"):
        pkt.add_fact(_fact(fid, entity_id=f"node-{fid}"))
    pkt.freeze()
    return pkt


def _architect_msg(
    fact_ids: tuple[str, ...],
    confidence: float = 0.8,
) -> DialecticalMessage:
    builder = MessageBuilder(
        source_agent="architect-anchor",
        packet_id="passthrough-anchor-packet",
        cycle_id="passthrough-anchor-cycle",
    )
    builder.set_phase(Phase.THESIS)
    builder.set_turn(1)
    builder.set_type(MessageType.HYPOTHESIS)
    builder.set_confidence(confidence)
    builder.add_assertion(
        Assertion(
            assertion_id="hyp-anchor",
            assertion_type=AssertionType.ASSERT,
            fact_ids=fact_ids,
            interpretation="Threat detected",
            operator="detected",
            threshold="threat",
        )
    )
    return builder.build()


def _skeptic_msg(
    fact_ids: tuple[str, ...],
    confidence: float = 0.3,
) -> DialecticalMessage:
    builder = MessageBuilder(
        source_agent="skeptic-anchor",
        packet_id="passthrough-anchor-packet",
        cycle_id="passthrough-anchor-cycle",
    )
    builder.set_phase(Phase.ANTITHESIS)
    builder.set_turn(2)
    builder.set_type(MessageType.REBUTTAL)
    builder.set_confidence(confidence)
    builder.add_assertion(
        Assertion.alternative(
            assertion_id="alt-anchor",
            fact_ids=list(fact_ids),
            interpretation="Benign explanation",
        )
    )
    return builder.build()


# =============================================================================
# Source-level anchors
# =============================================================================


class TestOracleSourceAnchors:
    """Verbatim source assertions on the load-bearing lines."""

    def _source_lines(self) -> list[str]:
        path = inspect.getfile(oracle_module)
        with open(path, "r", encoding="utf-8") as fh:
            return fh.readlines()

    def test_arch_facts_collection_line_present_verbatim(self) -> None:
        source = inspect.getsource(oracle_module)
        assert EXPECTED_ARCH_FACTS_LINE in source, (
            f"Anchor {EXPECTED_ARCH_FACTS_LINE!r} not found in "
            f"{EXPECTED_FILE_LOCATION}. This is the architect fact-id "
            f"pull that the Paper 3 Finding 2 passthrough depends on."
        )

    def test_arch_facts_line_number_unchanged(self) -> None:
        lines = self._source_lines()
        actual = lines[EXPECTED_ARCH_FACTS_LINE_NUMBER - 1].strip()
        assert EXPECTED_ARCH_FACTS_LINE in actual, (
            f"Line {EXPECTED_ARCH_FACTS_LINE_NUMBER} is {actual!r}; "
            f"expected to contain {EXPECTED_ARCH_FACTS_LINE!r}. Update "
            f"EXPECTED_ARCH_FACTS_LINE_NUMBER only with an explicit ADR."
        )

    def test_passthrough_line_present_verbatim(self) -> None:
        source = inspect.getsource(oracle_module)
        assert EXPECTED_PASSTHROUGH_LINE in source, (
            f"Anchor {EXPECTED_PASSTHROUGH_LINE!r} not found in "
            f"{EXPECTED_FILE_LOCATION}. This is the THREAT_CONFIRMED "
            f"passthrough that makes explanation drift inherit "
            f"Architect drift. Paper 3 Finding 2 load-bearing line."
        )

    def test_passthrough_line_number_unchanged(self) -> None:
        lines = self._source_lines()
        actual = lines[EXPECTED_PASSTHROUGH_LINE_NUMBER - 1].strip()
        assert EXPECTED_PASSTHROUGH_LINE in actual, (
            f"Line {EXPECTED_PASSTHROUGH_LINE_NUMBER} is {actual!r}; "
            f"expected to contain {EXPECTED_PASSTHROUGH_LINE!r}. Update "
            f"EXPECTED_PASSTHROUGH_LINE_NUMBER only with an explicit ADR."
        )

    def test_verdict_assignment_line_present_verbatim(self) -> None:
        source = inspect.getsource(oracle_module)
        assert EXPECTED_VERDICT_ASSIGN_LINE in source, (
            f"Anchor {EXPECTED_VERDICT_ASSIGN_LINE!r} not found in "
            f"{EXPECTED_FILE_LOCATION}. This wires supporting_facts "
            f"into the Verdict object."
        )

    def test_passthrough_line_is_statement_not_comment(self) -> None:
        lines = self._source_lines()
        actual = lines[EXPECTED_PASSTHROUGH_LINE_NUMBER - 1].strip()
        assert not actual.startswith("#"), (
            f"Line {EXPECTED_PASSTHROUGH_LINE_NUMBER} is a comment "
            f"({actual!r}); the anchor must be the executable "
            f"assignment."
        )


# =============================================================================
# Behavioral anchors — THREAT_CONFIRMED branch
# =============================================================================


class TestThreatConfirmedPassthrough:
    """The load-bearing branch: Verdict.supporting_fact_ids inherits
    Architect's get_all_fact_ids() output verbatim."""

    def test_supporting_fact_ids_equals_architect_facts_under_threat_confirmed(
        self,
    ) -> None:
        packet = _packet()
        arch_facts = ("fact-A1", "fact-A2", "fact-A3")
        arch = _architect_msg(arch_facts, confidence=0.85)
        skep = _skeptic_msg(("fact-B1",), confidence=0.3)

        verdict = OracleJudge.compute_verdict(arch, skep, packet)

        assert verdict.outcome == VerdictOutcome.THREAT_CONFIRMED
        assert verdict.supporting_fact_ids == frozenset(
            arch.get_all_fact_ids()
        ), (
            "Under THREAT_CONFIRMED, supporting_fact_ids must equal "
            "frozenset(architect_msg.get_all_fact_ids()) — this is the "
            "passthrough that Paper 3 Finding 2 names."
        )

    def test_architect_drift_propagates_to_supporting_fact_ids(self) -> None:
        """If the Architect cites a different fact set on a sibling
        adversarial trial, the Oracle's explanation surface inherits
        the drift even when the verdict outcome and confidence are
        preserved. This is the Session 059 broad-leakage finding
        captured as an architectural invariant."""
        packet = _packet()
        skep = _skeptic_msg(("fact-B1",), confidence=0.3)

        arch_baseline = _architect_msg(
            ("fact-A1", "fact-A2", "fact-A3"), confidence=0.85,
        )
        arch_mutated = _architect_msg(
            ("fact-A2", "fact-A3"), confidence=0.85,
        )

        v_baseline = OracleJudge.compute_verdict(arch_baseline, skep, packet)
        v_mutated = OracleJudge.compute_verdict(arch_mutated, skep, packet)

        # Decision surface preserved.
        assert v_baseline.outcome == v_mutated.outcome == (
            VerdictOutcome.THREAT_CONFIRMED
        )
        assert v_baseline.confidence == v_mutated.confidence

        # Explanation surface drifts.
        assert v_baseline.supporting_fact_ids != v_mutated.supporting_fact_ids
        assert v_baseline.supporting_fact_ids == frozenset(
            ("fact-A1", "fact-A2", "fact-A3"),
        )
        assert v_mutated.supporting_fact_ids == frozenset(
            ("fact-A2", "fact-A3"),
        )

    def test_skeptic_fact_set_does_not_leak_into_supporting_fact_ids(
        self,
    ) -> None:
        """Under THREAT_CONFIRMED, the Skeptic's cited facts are
        explicitly excluded from supporting_fact_ids — this is the
        symmetric half of the passthrough claim."""
        packet = _packet()
        arch = _architect_msg(("fact-A1",), confidence=0.85)
        skep = _skeptic_msg(("fact-B1", "fact-B2"), confidence=0.3)

        verdict = OracleJudge.compute_verdict(arch, skep, packet)

        assert verdict.outcome == VerdictOutcome.THREAT_CONFIRMED
        skeptic_only = {"fact-B1", "fact-B2"}
        assert not (verdict.supporting_fact_ids & skeptic_only), (
            "Skeptic fact ids must not appear in supporting_fact_ids "
            "under THREAT_CONFIRMED."
        )


# =============================================================================
# Behavioral anchors — other branches (decoupling-precision lock)
# =============================================================================


class TestOtherOutcomeBranches:
    """The Paper 3 claim is that the passthrough is *conditional on
    outcome*. These tests lock the non-passthrough branches so the
    decoupling principle stays precise."""

    def test_threat_dismissed_uses_skeptic_facts_not_architect(
        self,
    ) -> None:
        packet = _packet()
        arch = _architect_msg(
            ("fact-A1", "fact-A2"), confidence=0.3,
        )
        skep = _skeptic_msg(
            ("fact-B1", "fact-B2"), confidence=0.85,
        )

        verdict = OracleJudge.compute_verdict(arch, skep, packet)

        assert verdict.outcome == VerdictOutcome.THREAT_DISMISSED
        assert verdict.supporting_fact_ids == frozenset(
            skep.get_all_fact_ids()
        )
        # And the architect fact set is NOT in supporting_fact_ids.
        arch_only = set(arch.get_all_fact_ids())
        assert not (verdict.supporting_fact_ids & arch_only), (
            "Architect fact ids must not appear in supporting_fact_ids "
            "under THREAT_DISMISSED."
        )

    def test_inconclusive_uses_union_of_both(self) -> None:
        packet = _packet()
        arch = _architect_msg(
            ("fact-A1", "fact-A2"), confidence=0.75,
        )
        skep = _skeptic_msg(
            ("fact-B1", "fact-B2"), confidence=0.75,
        )

        verdict = OracleJudge.compute_verdict(arch, skep, packet)

        assert verdict.outcome == VerdictOutcome.INCONCLUSIVE
        assert verdict.supporting_fact_ids == frozenset(
            arch.get_all_fact_ids()
        ) | frozenset(skep.get_all_fact_ids())
