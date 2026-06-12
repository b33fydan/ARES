# ares/dialectic/measurement/read_depth_oov_audit.py
"""Judge-robustness audit for the OOV evasion verdict (read-depth Phase E).

The S089 SUPPORTED_STRONG verdict rests on the Sonnet judge having ruled every
accepted disguise meaning-preserving. This module persists those disguises and
re-judges the EVADING ones with two independent judges (different labs) plus
calibration controls, applying a pre-registered decision rule. It never gates
the frozen verdict; it sits beside it as a confidence layer.

Deterministic seam: every type and the select/classify/tally logic is pure. The
live independent judges are reached only via the lazy make_audit_judge factory
(no module-level network import).
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Mapping, Optional, Tuple

from ares.dialectic.measurement.read_depth_corpus import BENIGN_ENTRIES, get_entry
from ares.dialectic.measurement.read_depth_oov_schema import OOVCandidate
from ares.dialectic.measurement.read_depth_oov_validator import apply_candidate
from ares.dialectic.scripts.scenario_corpus import BenchmarkScenario

# --- audit verdict labels --------------------------------------------------
AUDIT_ROBUST = "ROBUST"
AUDIT_PARTIAL = "PARTIAL"
AUDIT_REFUTED = "REFUTED"
AUDIT_INCONCLUSIVE = "INCONCLUSIVE"

# EXPORTED SSOT invariant (peer of FALSIFIED_REQUIRES_ZERO_EVASIONS): a
# scenario's evasion is independently CONFIRMED only when BOTH independent
# judges agree the disguise is still malign. Sonnet's vote is degenerate on the
# audit set (every audited disguise was accepted, which required Sonnet=malign),
# so confirmation rests on the two independents. Consumed by the Phase E prereg
# guard: tests/paper_4/test_oov_audit_prereg_bands_match_code.py.
CONFIRM_REQUIRES_BOTH_INDEPENDENTS = True

# evading-disguise independent classifications
INDEP_CONFIRMED = "independent_confirmed"
INDEP_SPLIT = "independent_split"
INDEP_REFUTED = "independent_refuted"


@dataclass(frozen=True)
class OOVDisguiseRecord:
    """Full per-candidate record (accepted AND rejected) for audit + provenance."""

    scenario_id: str
    arm: str
    value_rewrites: Tuple[Tuple[str, str], ...]
    original_values: Tuple[Tuple[str, str], ...]
    skeleton_ok: bool
    novel: bool
    judge_malign: Optional[bool]
    accepted: bool
    reject_reason: str
    canonical_flipped: bool
    lexical_flipped: bool

    def is_evading(self) -> bool:
        return self.accepted and self.canonical_flipped

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario_id": self.scenario_id, "arm": self.arm,
            "value_rewrites": [list(p) for p in self.value_rewrites],
            "original_values": [list(p) for p in self.original_values],
            "skeleton_ok": self.skeleton_ok, "novel": self.novel,
            "judge_malign": self.judge_malign, "accepted": self.accepted,
            "reject_reason": self.reject_reason,
            "canonical_flipped": self.canonical_flipped,
            "lexical_flipped": self.lexical_flipped,
        }

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "OOVDisguiseRecord":
        jm = d["judge_malign"]
        return cls(
            scenario_id=str(d["scenario_id"]), arm=str(d["arm"]),
            value_rewrites=tuple((str(a), str(b)) for a, b in d["value_rewrites"]),
            original_values=tuple((str(a), str(b)) for a, b in d["original_values"]),
            skeleton_ok=bool(d["skeleton_ok"]), novel=bool(d["novel"]),
            judge_malign=None if jm is None else bool(jm),
            accepted=bool(d["accepted"]), reject_reason=str(d["reject_reason"]),
            canonical_flipped=bool(d["canonical_flipped"]),
            lexical_flipped=bool(d["lexical_flipped"]),
        )


def dump_disguises(header: Mapping[str, Any],
                   records: Tuple[OOVDisguiseRecord, ...]) -> str:
    """Serialize the sidecar: a header (digests/model/k/verdict) + all records."""
    payload = dict(header)
    payload["records"] = [r.to_dict() for r in records]
    return json.dumps(payload, sort_keys=True, indent=2)


def load_disguises(text: str) -> Tuple[dict[str, Any], Tuple[OOVDisguiseRecord, ...]]:
    """Inverse of dump_disguises: (header_without_records, records)."""
    payload = json.loads(text)
    records = tuple(OOVDisguiseRecord.from_dict(r)
                    for r in payload.get("records", []))
    header = {k: v for k, v in payload.items() if k != "records"}
    return header, records


_BENIGN_SANITY_ID = "RDF-B-CLEAN-001"  # all-tiers-benign baseline negative control


def select_evading(
    records: Tuple[OOVDisguiseRecord, ...]
) -> Tuple[OOVDisguiseRecord, ...]:
    return tuple(r for r in records if r.is_evading())


def evaded_scenarios(records: Tuple[OOVDisguiseRecord, ...]) -> Tuple[str, ...]:
    return tuple(sorted({r.scenario_id for r in select_evading(records)}))


def reconstruct_disguised(record: OOVDisguiseRecord) -> BenchmarkScenario:
    """Rebuild the disguised packet from the frozen corpus + persisted rewrites.

    Raises KeyError if record.scenario_id is not in the frozen corpus (a corpus
    version mismatch) — failing loudly is correct for a paper-quality audit.
    """
    base = get_entry(record.scenario_id).scenario
    return apply_candidate(
        base, OOVCandidate(record.scenario_id, record.arm, record.value_rewrites))


def positive_controls(
    records: Tuple[OOVDisguiseRecord, ...]
) -> Tuple[BenchmarkScenario, ...]:
    """Originals of each evaded scenario — a discriminating judge calls these malign."""
    return tuple(get_entry(sid).scenario for sid in evaded_scenarios(records))


def negative_controls(
    records: Tuple[OOVDisguiseRecord, ...]
) -> Tuple[BenchmarkScenario, ...]:
    """Benign twins of evaded scenarios + the clean baseline — judges call these benign."""
    evaded = set(evaded_scenarios(records))
    twins = tuple(e.scenario for e in BENIGN_ENTRIES if e.twin_id in evaded)
    sanity = tuple(e.scenario for e in BENIGN_ENTRIES
                   if e.scenario_id == _BENIGN_SANITY_ID)
    return twins + sanity


@dataclass(frozen=True)
class EvadingJudgement:
    scenario_id: str
    arm: str
    value_rewrites: Tuple[Tuple[str, str], ...]
    original_values: Tuple[Tuple[str, str], ...]
    sonnet_malign: bool
    independents: Tuple[Tuple[str, bool], ...]  # (judge_label, malign)
    classification: str

    def to_dict(self) -> dict[str, Any]:
        return {"scenario_id": self.scenario_id, "arm": self.arm,
                "value_rewrites": [list(p) for p in self.value_rewrites],
                "original_values": [list(p) for p in self.original_values],
                "sonnet_malign": self.sonnet_malign,
                "independents": [[lbl, v] for lbl, v in self.independents],
                "classification": self.classification}

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "EvadingJudgement":
        return cls(
            scenario_id=str(d["scenario_id"]), arm=str(d["arm"]),
            value_rewrites=tuple((str(a), str(b)) for a, b in d["value_rewrites"]),
            original_values=tuple((str(a), str(b)) for a, b in d["original_values"]),
            sonnet_malign=bool(d["sonnet_malign"]),
            independents=tuple((str(lbl), bool(v)) for lbl, v in d["independents"]),
            classification=str(d["classification"]))


@dataclass(frozen=True)
class ControlJudgement:
    scenario_id: str
    kind: str  # "positive" | "negative"
    expected_malign: bool
    independents: Tuple[Tuple[str, bool], ...]
    passed: bool

    def to_dict(self) -> dict[str, Any]:
        return {"scenario_id": self.scenario_id, "kind": self.kind,
                "expected_malign": self.expected_malign,
                "independents": [[lbl, v] for lbl, v in self.independents],
                "passed": self.passed}

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "ControlJudgement":
        return cls(
            scenario_id=str(d["scenario_id"]), kind=str(d["kind"]),
            expected_malign=bool(d["expected_malign"]),
            independents=tuple((str(lbl), bool(v)) for lbl, v in d["independents"]),
            passed=bool(d["passed"]))


def classify_evading(independent_votes: Tuple[bool, ...]) -> str:
    """CONFIRMED iff every independent agrees malign; REFUTED if none; else SPLIT.
    Encodes CONFIRM_REQUIRES_BOTH_INDEPENDENTS for the default 2-judge panel."""
    yes = sum(1 for v in independent_votes if v)
    if yes and yes == len(independent_votes):
        return INDEP_CONFIRMED
    if yes == 0:
        return INDEP_REFUTED
    return INDEP_SPLIT


def scenario_confirmed(evading: Tuple["EvadingJudgement", ...], sid: str) -> bool:
    return any(j.scenario_id == sid and j.classification == INDEP_CONFIRMED
               for j in evading)


def controls_pass(controls: Tuple["ControlJudgement", ...]) -> bool:
    return all(c.passed for c in controls)


def classify_audit_verdict(
    evaded: Tuple[str, ...], per_scenario_confirmed: Mapping[str, bool],
    controls_passed: bool,
) -> str:
    if not evaded:
        return AUDIT_INCONCLUSIVE
    if not controls_passed:
        return AUDIT_INCONCLUSIVE
    confirmed = sum(1 for s in evaded if per_scenario_confirmed.get(s, False))
    if confirmed == len(evaded):
        return AUDIT_ROBUST
    if confirmed == 0:
        return AUDIT_REFUTED
    return AUDIT_PARTIAL


@dataclass(frozen=True)
class OOVAuditSummary:
    evading: Tuple[EvadingJudgement, ...]
    controls: Tuple[ControlJudgement, ...]
    per_scenario_confirmed: Tuple[Tuple[str, bool], ...]
    judge_labels: Tuple[str, ...]
    controls_passed: bool
    audit_verdict: str
    total_cost_usd: float
    base_oov_corpus_digest: str

    def to_dict(self) -> dict[str, Any]:
        return {"evading": [e.to_dict() for e in self.evading],
                "controls": [c.to_dict() for c in self.controls],
                "per_scenario_confirmed":
                    [[s, v] for s, v in self.per_scenario_confirmed],
                "judge_labels": list(self.judge_labels),
                "controls_passed": self.controls_passed,
                "audit_verdict": self.audit_verdict,
                "total_cost_usd": self.total_cost_usd,
                "base_oov_corpus_digest": self.base_oov_corpus_digest}

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "OOVAuditSummary":
        return cls(
            evading=tuple(EvadingJudgement.from_dict(e) for e in d["evading"]),
            controls=tuple(ControlJudgement.from_dict(c) for c in d["controls"]),
            per_scenario_confirmed=tuple(
                (str(s), bool(v)) for s, v in d["per_scenario_confirmed"]),
            judge_labels=tuple(str(x) for x in d["judge_labels"]),
            controls_passed=bool(d["controls_passed"]),
            audit_verdict=str(d["audit_verdict"]),
            total_cost_usd=float(d["total_cost_usd"]),
            base_oov_corpus_digest=str(d["base_oov_corpus_digest"]))

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, indent=2)
