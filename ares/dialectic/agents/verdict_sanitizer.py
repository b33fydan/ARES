"""Deterministic, framing-invariant sanitizer for Verdict.supporting_fact_ids.

OracleJudge passes the Architect's (LLM-chosen, framing-sensitive) cited
fact-ids verbatim into Verdict.supporting_fact_ids (oracle.py:89/102/116). This
module provides an OPT-IN peer path that re-derives supporting_fact_ids from the
EvidencePacket alone, via a deterministic, outcome-conditioned kill-chain rule.
Because the rule depends only on the packet's fact-id set and per-fact ``field``
(which framing mutations never change), the resulting set is invariant under
framing mutations.

oracle.py and its passthrough anchor test are intentionally UNTOUCHED — this is
a peer, not a modification. Callers opt in by using create_sanitized_oracle_verdict
in place of oracle.create_oracle_verdict.
"""
from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING

from ares.dialectic.agents.light_skeptic import _DEFAULT_STAGE, _STAGE_MAP
from ares.dialectic.agents.oracle import OracleJudge, OracleNarrator
from ares.dialectic.agents.patterns import Verdict, VerdictOutcome
from ares.dialectic.coordinator.firewall import (
    _AUTHORIZATION_FACT_FIELDS,
    _BENIGN_INDICATOR_FIELDS,
)

if TYPE_CHECKING:
    from ares.dialectic.evidence.packet import EvidencePacket
    from ares.dialectic.messages.protocol import DialecticalMessage


_EXCULPATORY_FIELDS = _AUTHORIZATION_FACT_FIELDS | _BENIGN_INDICATOR_FIELDS


def relevant_fact_ids(
    packet: "EvidencePacket", outcome: VerdictOutcome
) -> frozenset[str]:
    """Deterministic, packet-only supporting-fact set, conditioned on outcome.

    - THREAT_CONFIRMED -> fact_ids at the maximum kill-chain stage present
      (per _STAGE_MAP; ties all included).
    - THREAT_DISMISSED -> fact_ids whose field is an authorization/benign
      (exculpatory) field; falls back to the whole packet if none present.
    - INCONCLUSIVE -> all fact_ids.

    Empty packet -> empty frozenset.
    """
    facts = packet.get_all_facts()
    if not facts:
        return frozenset()

    if outcome == VerdictOutcome.THREAT_CONFIRMED:
        stages = {f.fact_id: _STAGE_MAP.get(f.field, _DEFAULT_STAGE) for f in facts}
        top = max(stages.values())
        return frozenset(fid for fid, stage in stages.items() if stage == top)

    if outcome == VerdictOutcome.THREAT_DISMISSED:
        exculpatory = frozenset(
            f.fact_id for f in facts if f.field in _EXCULPATORY_FIELDS
        )
        return exculpatory or frozenset(f.fact_id for f in facts)

    return frozenset(f.fact_id for f in facts)


def sanitize_verdict(verdict: Verdict, packet: "EvidencePacket") -> Verdict:  # noqa: ARG001
    """Placeholder — implemented in Task 2."""
    raise NotImplementedError


def create_sanitized_oracle_verdict(  # noqa: ARG001
    architect_msg: "DialecticalMessage",
    skeptic_msg: "DialecticalMessage",
    packet: "EvidencePacket",
) -> "tuple[Verdict, OracleNarrator]":
    """Placeholder — implemented in Task 3."""
    raise NotImplementedError
