# ares/dialectic/agents/light_skeptic_v2_common.py
"""Shared scaffolding for the Light Skeptic v2 read-depth ladder (S086).

Each v2 tier (structured / lexical / canonical) is a deterministic peer of
:mod:`ares.dialectic.agents.light_skeptic`. The tiers share:

  * the v1 BENIGN computation (reused verbatim via ``light_skeptic.evaluate`` so
    every tier's benign channel is byte-identical to v1 — the tiers differ from
    v1 and from each other ONLY in the malign channel),
  * the malign-rule protocol (a rule is a pure function ``packet -> MalignHit|None``),
  * judgment assembly enforcing ``confidence = clamp(0.5 + benign - malign)``.

Zero LLM calls. Pure Python. Deterministic. (The v1 non-negotiables.)
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional, Tuple

from ares.dialectic.agents import light_skeptic
from ares.dialectic.agents.light_skeptic import DEFAULT_CONFIDENCE, RULE_DEFAULT_FLOOR
from ares.dialectic.evidence.packet import EvidencePacket
from ares.dialectic.messages.protocol import DialecticalMessage
from ares.dialectic.schemas.light_skeptic_judgment import LightSkepticJudgment


@dataclass(frozen=True)
class MalignHit:
    """One malign rule firing: its id, weight contribution, and rationale."""

    rule_id: str
    weight: float
    rationale: str


# A malign rule reads a frozen packet and returns a hit or None.
MalignRule = Callable[[EvidencePacket], Optional[MalignHit]]


def _clamp01(x: float) -> float:
    if x < 0.0:
        return 0.0
    if x > 1.0:
        return 1.0
    return x


def assemble_judgment(
    evidence_packet: EvidencePacket,
    architect_output: DialecticalMessage,
    malign_rules: Tuple[MalignRule, ...],
) -> LightSkepticJudgment:
    """Compose v1 benign + tier malign into a LightSkepticJudgment.

    Benign is taken verbatim from ``light_skeptic.evaluate`` (v1); only the
    malign channel varies across tiers.
    """
    base = light_skeptic.evaluate(evidence_packet, architect_output)
    benign_score = base.benign_score

    # Inherit v1's benign audit trail minus the "no signal" floor — a tier that
    # finds malign signal has, by definition, found signal.
    triggered = [r for r in base.triggered_rules if r != RULE_DEFAULT_FLOOR]
    rationale = [r for r in base.rationale if not r.startswith(RULE_DEFAULT_FLOOR)]

    malign_score = 0.0
    for rule in malign_rules:
        hit = rule(evidence_packet)
        if hit is not None:
            malign_score += hit.weight
            triggered.append(hit.rule_id)
            rationale.append(hit.rationale)

    malign_score = _clamp01(malign_score)

    if not triggered:
        # Neither benign nor malign signal → v1's no-signal floor.
        return LightSkepticJudgment(
            confidence=DEFAULT_CONFIDENCE,
            rationale=(f"{RULE_DEFAULT_FLOOR}: no benign or malign signal matched",),
            triggered_rules=(RULE_DEFAULT_FLOOR,),
            benign_score=0.0,
            malign_score=0.0,
        )

    confidence = round(_clamp01(0.5 + benign_score - malign_score), 10)
    return LightSkepticJudgment(
        confidence=confidence,
        rationale=tuple(rationale),
        triggered_rules=tuple(triggered),
        benign_score=_clamp01(benign_score),
        malign_score=malign_score,
    )
