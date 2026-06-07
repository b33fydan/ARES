# ares/dialectic/agents/light_skeptic_v2_ladder.py
"""The read-depth ladder registry (S086 Phase A).

A single ordered handle on the five rungs of the read-depth robustness frontier
for the Phase B/C measurement harness:

    v1_field      -> tier 0, ares.dialectic.agents.light_skeptic.evaluate
    v2_structured -> tier 1
    v2_lexical    -> tier 2
    v2_canonical  -> tier 3
    llm_semantic  -> tier 4 (the LLM anchor; reused from S084, NOT built here)

``DETERMINISTIC_TIERS`` exposes only the four offline tiers; the LLM anchor is
named in ``LADDER_ORDER`` for plotting but is supplied by the harness.
"""
from __future__ import annotations

from typing import Callable, Dict

from ares.dialectic.agents import (
    light_skeptic,
    light_skeptic_v2_canonical,
    light_skeptic_v2_lexical,
    light_skeptic_v2_structured,
)
from ares.dialectic.evidence.packet import EvidencePacket
from ares.dialectic.messages.protocol import DialecticalMessage
from ares.dialectic.schemas.light_skeptic_judgment import LightSkepticJudgment

TierFn = Callable[[EvidencePacket, DialecticalMessage], LightSkepticJudgment]

LADDER_ORDER = (
    "v1_field",
    "v2_structured",
    "v2_lexical",
    "v2_canonical",
    "llm_semantic",
)

DETERMINISTIC_TIERS: Dict[str, TierFn] = {
    "v1_field": light_skeptic.evaluate,
    "v2_structured": light_skeptic_v2_structured.evaluate,
    "v2_lexical": light_skeptic_v2_lexical.evaluate,
    "v2_canonical": light_skeptic_v2_canonical.evaluate,
}
