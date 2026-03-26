"""Claim Auditor — per-claim evidence support assessment.

Session 023: Decomposes flagged verdicts into individual claims and
checks evidence support for each. Complements the MiscalibrationDetector
by providing granular insight into WHY a verdict is miscalibrated.

The auditor iterates over architect assertions, checks how many cited
fact IDs actually exist in the packet, and classifies support level
per claim. Aggregate metrics determine whether the overall verdict
is CONFIRMED or MISCALIBRATED.

Public API:
    ClaimSupport      — enum: SUPPORTED, WEAK, UNSUPPORTED
    ClaimAuditDetail  — frozen dataclass with per-claim assessment
    ClaimAuditResult  — frozen dataclass with aggregate audit outcome
    ClaimAuditor      — the auditor; call .audit() -> ClaimAuditResult
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Tuple

from ares.dialectic.evidence.packet import EvidencePacket
from ares.dialectic.messages.assertions import AssertionType
from ares.dialectic.messages.protocol import DialecticalMessage


class ClaimSupport(Enum):
    """Evidence support level for a single claim.

    SUPPORTED: 2+ facts back this claim.
    WEAK: Exactly 1 fact backs this claim.
    UNSUPPORTED: 0 facts back this claim (all cited IDs missing from packet).
    """

    SUPPORTED = "supported"
    WEAK = "weak"
    UNSUPPORTED = "unsupported"


class AuditVerdict(Enum):
    """Overall audit verdict for the set of claims.

    CONFIRMED: Evidence adequately supports the claims.
    MISCALIBRATED: Too many claims lack evidence support.
    """

    CONFIRMED = "confirmed"
    MISCALIBRATED = "miscalibrated"


@dataclass(frozen=True)
class ClaimAuditDetail:
    """Immutable per-claim evidence assessment.

    Attributes:
        assertion_type: The type of assertion (ASSERT, LINK, ALT).
        claim_text: The assertion's interpretation text.
        cited_fact_ids: Fact IDs the assertion claims to reference.
        support_level: Classification of evidence support.
        fact_count: Number of cited facts that exist in the packet.
    """

    assertion_type: AssertionType
    claim_text: str
    cited_fact_ids: Tuple[str, ...]
    support_level: ClaimSupport
    fact_count: int


@dataclass(frozen=True)
class ClaimAuditResult:
    """Immutable aggregate audit outcome.

    Attributes:
        claims_total: Total number of claims audited.
        claims_supported: Number of claims with SUPPORTED level.
        claims_weak: Number of claims with WEAK level.
        claims_unsupported: Number of claims with UNSUPPORTED level.
        audit_verdict: CONFIRMED or MISCALIBRATED.
        claim_details: Per-claim audit details.
        miscalibration_ratio: Proportion of WEAK + UNSUPPORTED claims.
    """

    claims_total: int
    claims_supported: int
    claims_weak: int
    claims_unsupported: int
    audit_verdict: AuditVerdict
    claim_details: Tuple[ClaimAuditDetail, ...]
    miscalibration_ratio: float


class ClaimAuditor:
    """Per-claim evidence auditor.

    Decomposes architect assertions and checks evidence support for
    each claim individually. Produces an aggregate verdict based on
    the proportion of poorly-supported claims.

    Args:
        miscalibration_threshold: If more than this proportion of claims
            are WEAK or UNSUPPORTED, the audit verdict is MISCALIBRATED.
            Default 0.5 (half).
    """

    def __init__(self, miscalibration_threshold: float = 0.5) -> None:
        if not 0.0 <= miscalibration_threshold <= 1.0:
            raise ValueError(
                f"miscalibration_threshold must be in [0.0, 1.0], "
                f"got {miscalibration_threshold}"
            )
        self._miscalibration_threshold = miscalibration_threshold

    @property
    def miscalibration_threshold(self) -> float:
        """Threshold above which verdict is MISCALIBRATED."""
        return self._miscalibration_threshold

    def audit(
        self,
        architect_message: DialecticalMessage,
        packet: EvidencePacket,
    ) -> ClaimAuditResult:
        """Audit all claims in the architect's message.

        For each assertion, counts how many of its cited fact_ids
        exist in the packet and classifies support level.

        Args:
            architect_message: The Architect's dialectical message.
            packet: The EvidencePacket grounding the debate.

        Returns:
            ClaimAuditResult with per-claim and aggregate assessment.
        """
        details: list[ClaimAuditDetail] = []
        supported = 0
        weak = 0
        unsupported = 0

        for assertion in architect_message.assertions:
            # Count how many cited facts exist in the packet
            valid_count = sum(
                1 for fid in assertion.fact_ids if packet.has_fact(fid)
            )

            # Classify support level
            if valid_count >= 2:
                level = ClaimSupport.SUPPORTED
                supported += 1
            elif valid_count == 1:
                level = ClaimSupport.WEAK
                weak += 1
            else:
                level = ClaimSupport.UNSUPPORTED
                unsupported += 1

            details.append(
                ClaimAuditDetail(
                    assertion_type=assertion.assertion_type,
                    claim_text=assertion.interpretation,
                    cited_fact_ids=assertion.fact_ids,
                    support_level=level,
                    fact_count=valid_count,
                )
            )

        total = len(details)
        if total == 0:
            ratio = 0.0
        else:
            ratio = (weak + unsupported) / total

        audit_verdict = (
            AuditVerdict.MISCALIBRATED
            if ratio > self._miscalibration_threshold
            else AuditVerdict.CONFIRMED
        )

        return ClaimAuditResult(
            claims_total=total,
            claims_supported=supported,
            claims_weak=weak,
            claims_unsupported=unsupported,
            audit_verdict=audit_verdict,
            claim_details=tuple(details),
            miscalibration_ratio=ratio,
        )

    def __repr__(self) -> str:
        return (
            f"ClaimAuditor("
            f"miscalibration_threshold={self._miscalibration_threshold})"
        )
