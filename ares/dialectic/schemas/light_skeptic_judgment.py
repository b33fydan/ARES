"""Session 050 frozen schema for deterministic Light Skeptic judgments.

The :class:`LightSkepticJudgment` is the output of
:mod:`ares.dialectic.agents.light_skeptic` — a pure-Python evidence-graph
rule engine that replaces the LLM Skeptic in the Session 050 "light"
pipeline variant. Zero LLM calls are permitted during evaluation; the
schema carries enough structured context for the OracleJudge to make a
deterministic verdict and for the debrief to explain which rules fired.

The judgment encodes three channels:

    * ``confidence``        -- the final Skeptic confidence in [0, 1], the
                               same semantic value the LLM Skeptic's
                               DialecticalMessage.confidence would have
                               carried. This is what OracleJudge reads.
    * ``benign_score``      -- cumulative contribution from benign-signal
                               rules (evidence indicates benign activity).
    * ``malign_score``      -- cumulative contribution from malign-signal
                               rules (evidence indicates hostile activity).

``confidence = clamp(0.5 + benign_score - malign_score, 0.0, 1.0)`` is
the contract, enforced at construction time in ``__post_init__``.

``triggered_rules`` and ``rationale`` together form a reproducible audit
trail: every rule whose predicate matched must contribute both a rule
identifier and a human-readable rationale entry. A default rule fires
when nothing else matches, so ``rationale`` is never empty.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import Any, Mapping


@dataclass(frozen=True)
class LightSkepticJudgment:
    """Deterministic Light Skeptic evaluation of one evidence packet.

    Attributes:
        confidence: The Skeptic confidence in [0, 1]. Consumed by
            OracleJudge as the ``skeptic_confidence`` field.
        rationale: One human-readable string per contributing decision.
            Must be non-empty; a default-floor rule emits "no_signal"
            when no substantive rule fires.
        triggered_rules: Rule identifiers in the order they fired.
        benign_score: Sum of benign-signal contributions in [0, 1].
        malign_score: Sum of malign-signal contributions in [0, 1].
    """

    confidence: float
    rationale: tuple[str, ...]
    triggered_rules: tuple[str, ...]
    benign_score: float
    malign_score: float

    def __post_init__(self) -> None:
        if not isinstance(self.rationale, tuple):
            raise TypeError(
                "rationale must be a tuple, "
                f"got {type(self.rationale).__name__}"
            )
        if not isinstance(self.triggered_rules, tuple):
            raise TypeError(
                "triggered_rules must be a tuple, "
                f"got {type(self.triggered_rules).__name__}"
            )
        if not self.rationale:
            raise ValueError("rationale must be non-empty")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(
                f"confidence must be in [0.0, 1.0], got {self.confidence}"
            )
        if not 0.0 <= self.benign_score <= 1.0:
            raise ValueError(
                f"benign_score must be in [0.0, 1.0], got {self.benign_score}"
            )
        if not 0.0 <= self.malign_score <= 1.0:
            raise ValueError(
                f"malign_score must be in [0.0, 1.0], got {self.malign_score}"
            )

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["rationale"] = list(self.rationale)
        payload["triggered_rules"] = list(self.triggered_rules)
        return payload

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "LightSkepticJudgment":
        return cls(
            confidence=float(data["confidence"]),
            rationale=tuple(str(x) for x in data["rationale"]),
            triggered_rules=tuple(str(x) for x in data["triggered_rules"]),
            benign_score=float(data["benign_score"]),
            malign_score=float(data["malign_score"]),
        )

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)
