# ares/dialectic/measurement/read_depth_oov_schema.py
"""Frozen schema + verdict rule for the OOV adversarial evasion experiment
(read-depth frontier Phase D). Peer to read_depth_tier4_schema.

The LLM appears only in generation/judging; these types carry the frozen,
reproducible record of what was generated, what survived validation, and the
deterministic flip outcomes that decide the verdict.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from typing import Any, Mapping, Optional, Tuple

READ_DEPTH_OOV_HARD_CEILING_USD = 10.0

# EXPORTED SSOT invariant — intentionally cross-module, NOT dead code.
# Names the pre-registered "any hole" rule: a FALSIFIED verdict requires the
# adversary to evade ZERO scenarios in every arm under test — any meaning-
# preserving rewrite that fools the matcher falsifies the hypothesis.
# Consumed by the Phase D pre-registration guard:
#   tests/paper_4/test_oov_prereg_bands_match_code.py (added in a later task).
# The FALSIFIED branch of classify_oov_verdict below implements exactly this
# rule (reached only when no arm evaded any scenario).
FALSIFIED_REQUIRES_ZERO_EVASIONS = True

ARM_BLACK = "black"
ARM_WHITE = "white"
ARMS: Tuple[str, str] = (ARM_BLACK, ARM_WHITE)

VERDICT_SUPPORTED_STRONG = "SUPPORTED_STRONG"
VERDICT_SUPPORTED_MODERATE = "SUPPORTED_MODERATE"
VERDICT_FALSIFIED = "FALSIFIED"
VERDICT_INSTRUMENT_FAILURE = "INSTRUMENT_FAILURE"


@dataclass(frozen=True)
class OOVCandidate:
    """One LLM-proposed disguise: per-fact value rewrites for a scenario."""

    scenario_id: str
    arm: str
    value_rewrites: Tuple[Tuple[str, str], ...]  # (fact_id, new_value)
    provenance: str = ""

    def rewrites_dict(self) -> dict[str, str]:
        return {fid: val for fid, val in self.value_rewrites}

    def to_dict(self) -> dict[str, Any]:
        return {"scenario_id": self.scenario_id, "arm": self.arm,
                "value_rewrites": [list(p) for p in self.value_rewrites],
                "provenance": self.provenance}

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "OOVCandidate":
        return cls(scenario_id=str(d["scenario_id"]), arm=str(d["arm"]),
                   value_rewrites=tuple((str(a), str(b))
                                        for a, b in d["value_rewrites"]),
                   provenance=str(d.get("provenance", "")))


@dataclass(frozen=True)
class OOVValidationResult:
    """The outcome of running one candidate through the validity gate.

    Transient (not persisted) — this is why it has no ``to_dict``/``from_dict``.
    """

    candidate: OOVCandidate
    skeleton_ok: bool
    novel: bool
    judge_malign: Optional[bool]
    accepted: bool
    reject_reason: str


@dataclass(frozen=True)
class OOVEvasionRecord:
    """Per-accepted-candidate flip outcome on the string-reading tiers."""

    scenario_id: str
    arm: str
    canonical_flipped: bool
    lexical_flipped: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "OOVEvasionRecord":
        return cls(scenario_id=str(d["scenario_id"]), arm=str(d["arm"]),
                   canonical_flipped=bool(d["canonical_flipped"]),
                   lexical_flipped=bool(d["lexical_flipped"]))


@dataclass(frozen=True)
class OOVArmSummary:
    """Aggregate metrics for one threat-model arm."""

    arm: str
    n_candidates: int
    n_accepted: int
    n_rejected_skeleton: int
    n_rejected_novelty: int
    n_rejected_judge: int
    scenarios_evaded: Tuple[str, ...]
    adversarial_x_scenario: float
    per_candidate_flip_rate: float
    n_malign_scenarios: int

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["scenarios_evaded"] = list(self.scenarios_evaded)
        return d

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "OOVArmSummary":
        return cls(arm=str(d["arm"]), n_candidates=int(d["n_candidates"]),
                   n_accepted=int(d["n_accepted"]),
                   n_rejected_skeleton=int(d["n_rejected_skeleton"]),
                   n_rejected_novelty=int(d["n_rejected_novelty"]),
                   n_rejected_judge=int(d["n_rejected_judge"]),
                   scenarios_evaded=tuple(str(s) for s in d["scenarios_evaded"]),
                   adversarial_x_scenario=float(d["adversarial_x_scenario"]),
                   per_candidate_flip_rate=float(d["per_candidate_flip_rate"]),
                   n_malign_scenarios=int(d["n_malign_scenarios"]))


@dataclass(frozen=True)
class OOVFrontierSummary:
    arm_summaries: Tuple[OOVArmSummary, ...]
    records: Tuple[OOVEvasionRecord, ...]
    verdict: str
    corpus_digest: str
    oov_corpus_digest: str
    total_cost_usd: float
    model: str
    provider: str
    k: int

    def to_dict(self) -> dict[str, Any]:
        return {"arm_summaries": [a.to_dict() for a in self.arm_summaries],
                "records": [r.to_dict() for r in self.records],
                "verdict": self.verdict, "corpus_digest": self.corpus_digest,
                "oov_corpus_digest": self.oov_corpus_digest,
                "total_cost_usd": self.total_cost_usd, "model": self.model,
                "provider": self.provider, "k": self.k}

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "OOVFrontierSummary":
        return cls(
            arm_summaries=tuple(OOVArmSummary.from_dict(a)
                                for a in d["arm_summaries"]),
            records=tuple(OOVEvasionRecord.from_dict(r) for r in d["records"]),
            verdict=str(d["verdict"]), corpus_digest=str(d["corpus_digest"]),
            oov_corpus_digest=str(d["oov_corpus_digest"]),
            total_cost_usd=float(d["total_cost_usd"]), model=str(d["model"]),
            provider=str(d["provider"]), k=int(d["k"]))

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, indent=2)


def classify_oov_verdict(arm_summaries: Tuple[OOVArmSummary, ...]) -> str:
    """Apply the pre-registered 3-way rule. Any arm with zero accepted
    candidates is an instrument failure (no fair evasion was produced)."""
    for s in arm_summaries:
        if s.n_accepted == 0:
            return VERDICT_INSTRUMENT_FAILURE
    by_arm = {s.arm: s for s in arm_summaries}
    black = by_arm.get(ARM_BLACK)
    white = by_arm.get(ARM_WHITE)
    if black is not None and black.scenarios_evaded:
        return VERDICT_SUPPORTED_STRONG
    if white is not None and white.scenarios_evaded:
        return VERDICT_SUPPORTED_MODERATE
    # Implements the any-hole rule named by FALSIFIED_REQUIRES_ZERO_EVASIONS.
    return VERDICT_FALSIFIED


def oov_corpus_digest(candidates: Tuple[OOVCandidate, ...]) -> str:
    """Deterministic, order-independent digest over accepted candidates.

    Note: the ``|``-delimited format assumes controlled-vocabulary
    ``scenario_id`` and ``arm`` values (no literal ``|`` in either field).
    """
    parts = sorted(
        f"{c.scenario_id}|{c.arm}|"
        + ";".join(f"{fid}={val}" for fid, val in c.value_rewrites)
        for c in candidates
    )
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:16]
