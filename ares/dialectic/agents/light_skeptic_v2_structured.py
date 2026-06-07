# ares/dialectic/agents/light_skeptic_v2_structured.py
"""Light Skeptic v2 — Tier 1 (structural / field-presence). S086 read-depth ladder.

Rung 1. Reads only signals that cannot be paraphrased: which fields are present,
and the kill-chain stage derived from field names. Predicted framing-
susceptibility ~0 (invariant by construction); predicted detection capped,
because real injection scenarios encode malice in fact VALUES (strings), not
field names — which is exactly the frontier's point.

Zero LLM calls. Pure Python. Deterministic.
"""
from __future__ import annotations

from typing import Optional

from ares.dialectic.agents.light_skeptic import _max_kill_chain_stage
from ares.dialectic.agents.light_skeptic_v2_common import (
    MalignHit,
    assemble_judgment,
)
from ares.dialectic.coordinator.firewall import (
    _AUTHORIZATION_FACT_FIELDS,
    _HIGH_THREAT_FIELDS,
)
from ares.dialectic.evidence.packet import EvidencePacket
from ares.dialectic.messages.protocol import DialecticalMessage
from ares.dialectic.schemas.light_skeptic_judgment import LightSkepticJudgment

RULE_HIGH_THREAT_FIELD = "malign_high_threat_field"
RULE_HIGH_STAGE_NO_AUTH = "malign_high_stage_without_authorization"

WEIGHT_HIGH_THREAT_FIELD = 0.4
WEIGHT_HIGH_STAGE_NO_AUTH = 0.3

HIGH_STAGE_THRESHOLD = 2


def _has_authorization(packet: EvidencePacket) -> bool:
    return any(
        f.field in _AUTHORIZATION_FACT_FIELDS for f in packet.get_all_facts()
    )


def _rule_high_threat_field(packet: EvidencePacket) -> Optional[MalignHit]:
    hits = sorted(
        {f.field for f in packet.get_all_facts() if f.field in _HIGH_THREAT_FIELDS}
    )
    if not hits:
        return None
    return MalignHit(
        rule_id=RULE_HIGH_THREAT_FIELD,
        weight=WEIGHT_HIGH_THREAT_FIELD,
        rationale=(
            f"{RULE_HIGH_THREAT_FIELD}: high-threat field(s) present "
            f"({', '.join(hits)})"
        ),
    )


def _rule_high_stage_no_auth(packet: EvidencePacket) -> Optional[MalignHit]:
    stage = _max_kill_chain_stage(packet)
    if stage >= HIGH_STAGE_THRESHOLD and not _has_authorization(packet):
        return MalignHit(
            rule_id=RULE_HIGH_STAGE_NO_AUTH,
            weight=WEIGHT_HIGH_STAGE_NO_AUTH,
            rationale=(
                f"{RULE_HIGH_STAGE_NO_AUTH}: max kill-chain stage {stage} "
                f">= {HIGH_STAGE_THRESHOLD} with no authorization fact"
            ),
        )
    return None


MALIGN_RULES = (_rule_high_threat_field, _rule_high_stage_no_auth)


def evaluate(
    evidence_packet: EvidencePacket,
    architect_output: DialecticalMessage,
) -> LightSkepticJudgment:
    """Tier-1 structural Light Skeptic judgment."""
    return assemble_judgment(evidence_packet, architect_output, MALIGN_RULES)
