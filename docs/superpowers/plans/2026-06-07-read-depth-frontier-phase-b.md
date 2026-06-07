# Read-Depth Frontier Phase B (Adaptive Corpus C + offline harness) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> All commits use the repo's `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>` trailer (append it to each commit message). Work on branch `session/087-read-depth-phase-b` (already created).

**Goal:** Build the offline, deterministic measurement instrument for the read-depth robustness frontier — a purpose-built stratified Adaptive Corpus C plus a harness that emits, for each of the 4 deterministic Light-Skeptic tiers, an `(X, Y)` coordinate in both a *standalone* and a *cumulative* view.

**Architecture:** Six new files under `ares/dialectic/measurement/` + one CLI. The tiers (Phase A, shipped) are consumed read-only via the `DETERMINISTIC_TIERS` ladder registry. Perturbation reuses the existing `MutationOperator`/`PairedScenarioMutator` machinery (semantic-framing family) plus a small new lexical-evasion operator module. All metrics are exact arithmetic — no permutation/bootstrap (that is a Phase-C / LLM-anchor tool). `light_skeptic.py` (v1), `injection_registry_v3.py`, and the Phase-A modules stay byte-stable.

**Tech Stack:** Python 3.11, frozen dataclasses, pytest. Zero LLM, zero network, zero filesystem (except the CLI's report writer), deterministic.

**Spec:** [`docs/superpowers/specs/2026-06-07-read-depth-frontier-phase-b-design.md`](../specs/2026-06-07-read-depth-frontier-phase-b-design.md).

---

## File Structure

- Create: `ares/dialectic/measurement/read_depth_frontier_schema.py` — frozen result types + config + view constants.
- Create: `ares/dialectic/measurement/read_depth_frontier_metrics.py` — pure metric functions (binarization, cumulative OR, flip-rate, TPR/FPR/J).
- Create: `ares/dialectic/measurement/read_depth_evasion_operators.py` — lexical-evasion `MutationOperator`s (`exe→binary`, `temp→temporary`).
- Create: `ares/dialectic/measurement/read_depth_corpus.py` — Corpus C scenarios + `CorpusCEntry` labels + `inject_authorization` positive control.
- Create: `ares/dialectic/measurement/read_depth_frontier_runner.py` — `run_frontier(...) -> FrontierSummary` (offline orchestration).
- Create: `ares/dialectic/measurement/read_depth_frontier_report.py` — markdown table + `(X, Y)` JSON emitter.
- Create: `scripts/run_session_087.py` — gate-free CLI that runs the frontier and writes artifacts.
- Tests mirror each module under `tests/dialectic/measurement/`.
- **Never modify:** `ares/dialectic/agents/light_skeptic.py`, `ares/dialectic/agents/light_skeptic_v2_*.py`, `ares/dialectic/scripts/injection_registry_v3.py`, `ares/dialectic/scripts/non_interference/paired_scenario_mutator*.py`.

**Reused symbols (read-only imports):**
- `ares.dialectic.agents.light_skeptic_v2_ladder`: `DETERMINISTIC_TIERS`, `LADDER_ORDER`.
- `ares.dialectic.scripts.non_interference.paired_scenario_mutator`: `MutationOperator`, `PairedScenarioMutator`, `SkeletonInvariantError`, `OPERATORS_V1`, `_apply_value_replacements`.
- `ares.dialectic.scripts.scenario_corpus`: `BenchmarkScenario`, `ScenarioMetadata`, `_make_fact`.
- `ares.dialectic.evidence.{fact,packet,provenance}`, `ares.dialectic.messages.protocol`, `ares.dialectic.schemas.light_skeptic_judgment`.

---

## Task 1: Schema (`read_depth_frontier_schema.py`)

**Files:**
- Create: `ares/dialectic/measurement/read_depth_frontier_schema.py`
- Test: `tests/dialectic/measurement/test_read_depth_frontier_schema.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/dialectic/measurement/test_read_depth_frontier_schema.py
"""Tests for the read-depth frontier result schema."""
from __future__ import annotations

from ares.dialectic.measurement.read_depth_frontier_schema import (
    VIEW_CUMULATIVE,
    VIEW_STANDALONE,
    FrontierConfig,
    FrontierSummary,
    PositiveControlRecord,
    ScenarioVerdictRecord,
    TierCoordinate,
)


def _coord(tier="v2_lexical", view=VIEW_STANDALONE):
    return TierCoordinate(
        tier_id=tier, view=view, x_semantic=0.0, x_lexical=0.4,
        tpr=0.75, fpr=0.25, youden_j=0.5, n_malign=4, n_benign=4,
    )


def test_views_constants():
    assert VIEW_STANDALONE == "standalone"
    assert VIEW_CUMULATIVE == "cumulative"


def test_tier_coordinate_roundtrip():
    c = _coord()
    d = c.to_dict()
    assert d["tier_id"] == "v2_lexical"
    assert d["youden_j"] == 0.5
    assert TierCoordinate.from_dict(d) == c


def test_summary_roundtrip_via_json():
    rec = ScenarioVerdictRecord(
        scenario_id="RDF-M-LEX-001", tier_id="v2_lexical",
        view=VIEW_STANDALONE, is_malign=True, stratum="M-lex",
        baseline_malign_verdict=True, malign_score=0.8,
        n_mut_semantic=2, flips_semantic=0, n_mut_lexical=2, flips_lexical=1,
    )
    pc = PositiveControlRecord(
        scenario_id="RDF-M-LEX-001", tier_id="v1_field", view=VIEW_STANDALONE,
        baseline_malign_verdict=True, controlled_malign_verdict=False, moved=True,
    )
    cfg = FrontierConfig(
        operating_point=0.0,
        semantic_operator_names=("framing_prefix_v1",),
        lexical_operator_names=("exe_to_binary_v1",),
        seed=0,
    )
    summary = FrontierSummary(
        coordinates=(_coord(),),
        records=(rec,),
        positive_control_records=(pc,),
        corpus_digest="abc123",
        config=cfg,
    )
    restored = FrontierSummary.from_dict(summary.to_dict())
    assert restored == summary
    # to_json must be deterministic (sorted keys).
    assert summary.to_json() == summary.to_json()


def test_frozen():
    import dataclasses
    import pytest
    c = _coord()
    with pytest.raises(dataclasses.FrozenInstanceError):
        c.tpr = 0.1  # type: ignore[misc]
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `python -m pytest tests/dialectic/measurement/test_read_depth_frontier_schema.py -v`
Expected: FAIL — `ModuleNotFoundError: ...read_depth_frontier_schema`.

- [ ] **Step 3: Write the minimal implementation**

```python
# ares/dialectic/measurement/read_depth_frontier_schema.py
"""Frozen result schema for the read-depth robustness frontier (Phase B).

Every type is a frozen dataclass with ``to_dict``/``from_dict`` so a run can
be persisted to JSON and re-read by the Phase-C plotting/report stage. A
tier-4 (LLM anchor) coordinate is intentionally absent in Phase B — the
deterministic harness populates only the four offline rungs.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import Any, Mapping, Tuple

VIEW_STANDALONE = "standalone"
VIEW_CUMULATIVE = "cumulative"
VIEWS: Tuple[str, ...] = (VIEW_STANDALONE, VIEW_CUMULATIVE)


@dataclass(frozen=True)
class FrontierConfig:
    """Run configuration (operating point + operator rosters + seed)."""

    operating_point: float = 0.0
    semantic_operator_names: Tuple[str, ...] = ()
    lexical_operator_names: Tuple[str, ...] = ()
    seed: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "operating_point": self.operating_point,
            "semantic_operator_names": list(self.semantic_operator_names),
            "lexical_operator_names": list(self.lexical_operator_names),
            "seed": self.seed,
        }

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "FrontierConfig":
        return cls(
            operating_point=float(d["operating_point"]),
            semantic_operator_names=tuple(d["semantic_operator_names"]),
            lexical_operator_names=tuple(d["lexical_operator_names"]),
            seed=int(d["seed"]),
        )


@dataclass(frozen=True)
class TierCoordinate:
    """One (X, Y) point: a tier under one view."""

    tier_id: str
    view: str
    x_semantic: float
    x_lexical: float
    tpr: float
    fpr: float
    youden_j: float
    n_malign: int
    n_benign: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "TierCoordinate":
        return cls(
            tier_id=str(d["tier_id"]),
            view=str(d["view"]),
            x_semantic=float(d["x_semantic"]),
            x_lexical=float(d["x_lexical"]),
            tpr=float(d["tpr"]),
            fpr=float(d["fpr"]),
            youden_j=float(d["youden_j"]),
            n_malign=int(d["n_malign"]),
            n_benign=int(d["n_benign"]),
        )


@dataclass(frozen=True)
class ScenarioVerdictRecord:
    """Per (scenario, tier, view) verdict + perturbation flip counts.

    ``n_mut_*`` is the number of perturbations in that family that actually
    mutated the scenario (no-ops excluded). It is a scenario+family property,
    repeated across the scenario's tier records for convenience.
    """

    scenario_id: str
    tier_id: str
    view: str
    is_malign: bool
    stratum: str
    baseline_malign_verdict: bool
    malign_score: float
    n_mut_semantic: int
    flips_semantic: int
    n_mut_lexical: int
    flips_lexical: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "ScenarioVerdictRecord":
        return cls(
            scenario_id=str(d["scenario_id"]),
            tier_id=str(d["tier_id"]),
            view=str(d["view"]),
            is_malign=bool(d["is_malign"]),
            stratum=str(d["stratum"]),
            baseline_malign_verdict=bool(d["baseline_malign_verdict"]),
            malign_score=float(d["malign_score"]),
            n_mut_semantic=int(d["n_mut_semantic"]),
            flips_semantic=int(d["flips_semantic"]),
            n_mut_lexical=int(d["n_mut_lexical"]),
            flips_lexical=int(d["flips_lexical"]),
        )


@dataclass(frozen=True)
class PositiveControlRecord:
    """Did injecting a genuine authorization fact MOVE this tier's verdict?"""

    scenario_id: str
    tier_id: str
    view: str
    baseline_malign_verdict: bool
    controlled_malign_verdict: bool
    moved: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "PositiveControlRecord":
        return cls(
            scenario_id=str(d["scenario_id"]),
            tier_id=str(d["tier_id"]),
            view=str(d["view"]),
            baseline_malign_verdict=bool(d["baseline_malign_verdict"]),
            controlled_malign_verdict=bool(d["controlled_malign_verdict"]),
            moved=bool(d["moved"]),
        )


@dataclass(frozen=True)
class FrontierSummary:
    """The full Phase-B result: coordinates + per-scenario records + controls."""

    coordinates: Tuple[TierCoordinate, ...]
    records: Tuple[ScenarioVerdictRecord, ...]
    positive_control_records: Tuple[PositiveControlRecord, ...]
    corpus_digest: str
    config: FrontierConfig

    def to_dict(self) -> dict[str, Any]:
        return {
            "coordinates": [c.to_dict() for c in self.coordinates],
            "records": [r.to_dict() for r in self.records],
            "positive_control_records": [
                p.to_dict() for p in self.positive_control_records
            ],
            "corpus_digest": self.corpus_digest,
            "config": self.config.to_dict(),
        }

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "FrontierSummary":
        return cls(
            coordinates=tuple(
                TierCoordinate.from_dict(x) for x in d["coordinates"]
            ),
            records=tuple(
                ScenarioVerdictRecord.from_dict(x) for x in d["records"]
            ),
            positive_control_records=tuple(
                PositiveControlRecord.from_dict(x)
                for x in d["positive_control_records"]
            ),
            corpus_digest=str(d["corpus_digest"]),
            config=FrontierConfig.from_dict(d["config"]),
        )

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, indent=2)
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `python -m pytest tests/dialectic/measurement/test_read_depth_frontier_schema.py -v`
Expected: PASS (4 passed).

- [ ] **Step 5: Commit**

```bash
git add ares/dialectic/measurement/read_depth_frontier_schema.py tests/dialectic/measurement/test_read_depth_frontier_schema.py
git commit -m "feat(s087): read-depth frontier result schema (Phase B)"
```

---

## Task 2: Metrics (`read_depth_frontier_metrics.py`)

**Files:**
- Create: `ares/dialectic/measurement/read_depth_frontier_metrics.py`
- Test: `tests/dialectic/measurement/test_read_depth_frontier_metrics.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/dialectic/measurement/test_read_depth_frontier_metrics.py
"""Tests for the exact read-depth frontier metrics."""
from __future__ import annotations

from ares.dialectic.measurement.read_depth_frontier_metrics import (
    cumulative_verdict,
    flip_rate,
    is_malign_verdict,
    tpr_fpr,
    youden_j,
)
from ares.dialectic.schemas.light_skeptic_judgment import LightSkepticJudgment


def _judg(malign_score):
    # confidence kept in-range; only malign_score matters to the binarizer.
    return LightSkepticJudgment(
        confidence=max(0.0, 0.5 - malign_score),
        rationale=("r",), triggered_rules=("t",),
        benign_score=0.0, malign_score=malign_score,
    )


def test_is_malign_verdict_operating_point():
    assert is_malign_verdict(_judg(0.4)) is True
    assert is_malign_verdict(_judg(0.0)) is False
    # operating point is exclusive: malign_score must exceed it.
    assert is_malign_verdict(_judg(0.3), operating_point=0.3) is False
    assert is_malign_verdict(_judg(0.4), operating_point=0.3) is True


def test_cumulative_verdict_is_or():
    assert cumulative_verdict([False, False]) is False
    assert cumulative_verdict([False, True]) is True
    assert cumulative_verdict([]) is False


def test_flip_rate_excludes_zero_denominator():
    assert flip_rate(n_mutations=0, n_flips=0) == 0.0
    assert flip_rate(n_mutations=5, n_flips=2) == 0.4


def test_tpr_fpr_and_youden():
    tpr, fpr = tpr_fpr([True, True, True, False], [True, False, False, False])
    assert tpr == 0.75
    assert fpr == 0.25
    assert youden_j(tpr, fpr) == 0.5


def test_tpr_fpr_empty_sets():
    tpr, fpr = tpr_fpr([], [])
    assert tpr == 0.0
    assert fpr == 0.0
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `python -m pytest tests/dialectic/measurement/test_read_depth_frontier_metrics.py -v`
Expected: FAIL — `ModuleNotFoundError: ...read_depth_frontier_metrics`.

- [ ] **Step 3: Write the minimal implementation**

```python
# ares/dialectic/measurement/read_depth_frontier_metrics.py
"""Exact frontier metrics for the deterministic tiers (Phase B).

The deterministic tiers need no inferential statistics — X is an exact
flip-rate and Y an exact TPR-FPR. (The permutation/bootstrap machinery in
``architect_framing_metrics`` is reserved for the Phase-C LLM anchor.)
"""
from __future__ import annotations

from typing import Sequence, Tuple

from ares.dialectic.schemas.light_skeptic_judgment import LightSkepticJudgment

DEFAULT_OPERATING_POINT = 0.0


def is_malign_verdict(
    judgment: LightSkepticJudgment,
    operating_point: float = DEFAULT_OPERATING_POINT,
) -> bool:
    """A tier calls a packet malign iff its malign_score exceeds the point."""
    return judgment.malign_score > operating_point


def cumulative_verdict(prefix_verdicts: Sequence[bool]) -> bool:
    """Cumulative (depth-N) verdict = OR of all standalone verdicts up to N."""
    return any(prefix_verdicts)


def flip_rate(n_mutations: int, n_flips: int) -> float:
    """Fraction of *actually-mutating* perturbations that changed the verdict.

    Returns 0.0 when nothing mutated (no-op perturbations are excluded from
    the denominator by the caller, so a 0 denominator means "no probe landed").
    """
    if n_mutations <= 0:
        return 0.0
    return n_flips / n_mutations


def tpr_fpr(
    malign_verdicts: Sequence[bool],
    benign_verdicts: Sequence[bool],
) -> Tuple[float, float]:
    """(TPR, FPR) at the current operating point."""
    tpr = (
        sum(1 for v in malign_verdicts if v) / len(malign_verdicts)
        if malign_verdicts
        else 0.0
    )
    fpr = (
        sum(1 for v in benign_verdicts if v) / len(benign_verdicts)
        if benign_verdicts
        else 0.0
    )
    return tpr, fpr


def youden_j(tpr: float, fpr: float) -> float:
    """Youden's J = detection power = TPR - FPR."""
    return tpr - fpr
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `python -m pytest tests/dialectic/measurement/test_read_depth_frontier_metrics.py -v`
Expected: PASS (5 passed).

- [ ] **Step 5: Commit**

```bash
git add ares/dialectic/measurement/read_depth_frontier_metrics.py tests/dialectic/measurement/test_read_depth_frontier_metrics.py
git commit -m "feat(s087): exact frontier metrics (flip-rate, TPR-FPR, Youden J)"
```

---

## Task 3: Lexical-evasion operators (`read_depth_evasion_operators.py`)

**Files:**
- Create: `ares/dialectic/measurement/read_depth_evasion_operators.py`
- Test: `tests/dialectic/measurement/test_read_depth_evasion_operators.py`

These are `MutationOperator`s in the `"synonym"` family (the only valid families are `{synonym, severity, framing}`; `exe↔binary` *is* a synonym substitution). Each rewrites `fact.value` strings, holding the skeleton constant via the mutator's `_apply_value_replacements`. They target the tier-2/3 boundary: tier 2 (literal regex) is evaded; tier 3 (canonical, with `binary→exe`/`temporary→temp` folds) recovers.

- [ ] **Step 1: Write the failing test**

```python
# tests/dialectic/measurement/test_read_depth_evasion_operators.py
"""Tests for the lexical-evasion operators."""
from __future__ import annotations

from datetime import datetime

from ares.dialectic.agents.light_skeptic_v2_canonical import (
    evaluate as canonical_evaluate,
)
from ares.dialectic.agents.light_skeptic_v2_lexical import (
    evaluate as lexical_evaluate,
)
from ares.dialectic.evidence.fact import EntityType, Fact
from ares.dialectic.evidence.packet import EvidencePacket, TimeWindow
from ares.dialectic.evidence.provenance import Provenance, SourceType
from ares.dialectic.measurement.read_depth_evasion_operators import (
    EVASION_OPERATORS,
    exe_to_binary_transform,
    temp_to_temporary_transform,
)
from ares.dialectic.messages.protocol import MessageBuilder, MessageType, Phase
from ares.dialectic.scripts.non_interference.paired_scenario_mutator import (
    PairedScenarioMutator,
    SkeletonInvariantError,
)
from ares.dialectic.scripts.scenario_corpus import (
    BenchmarkScenario,
    ScenarioMetadata,
)


def _scenario(field_value_pairs, sid="T-001"):
    packet = EvidencePacket(
        packet_id=sid, time_window=TimeWindow(
            start=datetime(2026, 1, 1), end=datetime(2026, 1, 1, 1)))
    prov = Provenance(
        source_type=SourceType.PROCESS_LIST, source_id="s", parser_version="1.0.0")
    for i, (field, value) in enumerate(field_value_pairs):
        packet.add_fact(Fact(
            fact_id=f"{sid}-fact-{i:03d}", entity_id=f"e-{i}",
            entity_type=EntityType.NODE, field=field, value=value,
            timestamp=datetime(2026, 1, 1, 0, 30), provenance=prov))
    packet.freeze()
    meta = ScenarioMetadata(
        scenario_id=sid, name="t", description="t", mitre_attack_ids=("T1003",),
        mitre_tactic="x", difficulty_tier=3, expected_verdict="THREAT_CONFIRMED",
        expected_winner="ARCHITECT", fact_count=len(field_value_pairs), notes="t")
    return BenchmarkScenario(metadata=meta, packet=packet)


def _arch():
    b = MessageBuilder(source_agent="a", packet_id="t", cycle_id="c")
    b.set_phase(Phase.THESIS).set_type(MessageType.HYPOTHESIS).set_confidence(0.5)
    return b.build()


def _value_of(scenario, fact_id):
    return scenario.packet.get_fact(fact_id).value


def test_exe_to_binary_rewrites_extension():
    s = _scenario([("process_name", "C:\\Temp\\update.exe")])
    out = exe_to_binary_transform(s, 0)
    assert ".exe" not in _value_of(out, "T-001-fact-000")
    assert "binary" in _value_of(out, "T-001-fact-000")


def test_temp_to_temporary_rewrites_word():
    s = _scenario([("process_name", "C:\\Temp\\update.exe")])
    out = temp_to_temporary_transform(s, 0)
    assert "Temporary" in _value_of(out, "T-001-fact-000") or \
        "temporary" in _value_of(out, "T-001-fact-000").lower()


def test_evasion_flips_lexical_but_canonical_recovers():
    # An exe-path-only malign scenario (no credential-tool token).
    s = _scenario([("process_name", "C:\\Temp\\update.exe")])
    # Baseline: both tiers fire.
    assert lexical_evaluate(s.packet, _arch()).malign_score > 0
    assert canonical_evaluate(s.packet, _arch()).malign_score > 0
    # After exe->binary: tier 2 (literal) misses, tier 3 (canonical) recovers.
    evaded = exe_to_binary_transform(s, 0)
    assert lexical_evaluate(evaded.packet, _arch()).malign_score == 0
    assert canonical_evaluate(evaded.packet, _arch()).malign_score > 0


def test_operators_are_skeleton_invariant_via_mutator():
    s = _scenario([("process_name", "C:\\Temp\\update.exe")])
    mut = PairedScenarioMutator(operators=EVASION_OPERATORS, seed=0)
    pair = mut.mutate(s, "exe_to_binary_v1")  # must not raise
    assert pair.skeleton_hash == pair.skeleton_hash  # constructed => invariant held


def test_noop_when_token_absent_raises_via_mutator():
    s = _scenario([("normal_login", "user signed in at 09:00")])
    mut = PairedScenarioMutator(operators=EVASION_OPERATORS, seed=0)
    import pytest
    with pytest.raises(SkeletonInvariantError):
        mut.mutate(s, "exe_to_binary_v1")  # no ".exe" => no-op => rejected


def test_registry_names_unique_and_synonym_family():
    names = [op.operator_name for op in EVASION_OPERATORS]
    assert len(set(names)) == len(names)
    assert all(op.family == "synonym" for op in EVASION_OPERATORS)
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `python -m pytest tests/dialectic/measurement/test_read_depth_evasion_operators.py -v`
Expected: FAIL — `ModuleNotFoundError: ...read_depth_evasion_operators`.

- [ ] **Step 3: Write the minimal implementation**

```python
# ares/dialectic/measurement/read_depth_evasion_operators.py
"""Lexical-evasion mutation operators for the read-depth frontier (Phase B).

These deterministic, offline operators rewrite ``fact.value`` strings to evade
the tier-2 literal regexes while remaining meaning-preserving and skeleton-
invariant. They target tokens that tier 3's canonicalizer folds back
(``binary``->``exe``, ``temporary``->``temp``), so tier 2 flips and tier 3
recovers — the "reading values costs evadability, canonicalization buys some
back" axis. (Evasions outside tier 3's synonym map are a documented Phase-C
limitation, not built here.)

Family is ``"synonym"`` — the only valid `MutationOperator` families are
{synonym, severity, framing}; an ``exe``<->``binary`` swap is a synonym
substitution. Skeleton invariance is delegated to the mutator's
``_apply_value_replacements``.
"""
from __future__ import annotations

import re

from ares.dialectic.scripts.non_interference.paired_scenario_mutator import (
    MutationOperator,
    _apply_value_replacements,
)
from ares.dialectic.scripts.scenario_corpus import BenchmarkScenario

_DOT_EXE = re.compile(r"\.exe\b", re.IGNORECASE)
_WORD_TEMP = re.compile(r"\btemp\b", re.IGNORECASE)


def _rewrite_string_values(scenario: BenchmarkScenario, pattern: re.Pattern,
                           replacement: str) -> BenchmarkScenario:
    """Apply ``pattern -> replacement`` to every string value; skeleton-safe."""
    new_values: dict[str, str] = {}
    for fact in scenario.packet.get_all_facts():
        if not isinstance(fact.value, str):
            continue
        new_text = pattern.sub(replacement, fact.value)
        if new_text != fact.value:
            new_values[fact.fact_id] = new_text
    return _apply_value_replacements(scenario, new_values)


def exe_to_binary_transform(
    scenario: BenchmarkScenario, seed: int
) -> BenchmarkScenario:
    """Replace ``.exe`` extensions with the word ``binary`` (seed unused)."""
    _ = seed
    return _rewrite_string_values(scenario, _DOT_EXE, " binary")


def temp_to_temporary_transform(
    scenario: BenchmarkScenario, seed: int
) -> BenchmarkScenario:
    """Replace the whole word ``temp`` with ``temporary`` (seed unused)."""
    _ = seed
    return _rewrite_string_values(scenario, _WORD_TEMP, "temporary")


EVASION_OPERATORS: tuple[MutationOperator, ...] = (
    MutationOperator(
        operator_name="exe_to_binary_v1",
        family="synonym",
        description="Rewrite '.exe' extensions to the word 'binary' "
        "(tier-2 literal evasion; tier-3 folds binary->exe).",
        transform=exe_to_binary_transform,
    ),
    MutationOperator(
        operator_name="temp_to_temporary_v1",
        family="synonym",
        description="Rewrite the path token 'temp' to 'temporary' "
        "(tier-2 user-writable-dir evasion; tier-3 folds temporary->temp).",
        transform=temp_to_temporary_transform,
    ),
)
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `python -m pytest tests/dialectic/measurement/test_read_depth_evasion_operators.py -v`
Expected: PASS (6 passed).

- [ ] **Step 5: Commit**

```bash
git add ares/dialectic/measurement/read_depth_evasion_operators.py tests/dialectic/measurement/test_read_depth_evasion_operators.py
git commit -m "feat(s087): lexical-evasion operators (exe->binary, temp->temporary)"
```

---

## Task 4: Adaptive Corpus C (`read_depth_corpus.py`)

**Files:**
- Create: `ares/dialectic/measurement/read_depth_corpus.py`
- Test: `tests/dialectic/measurement/test_read_depth_corpus.py`

Eight scenarios (4 malign / 4 benign) + the `inject_authorization` positive control. Counts are a tested floor — more scenarios per stratum follow the identical `_make_fact` pattern. The strata are engineered so the deterministic frontier is legible (see the spec §3 and the worked example in the plan header).

- [ ] **Step 1: Write the failing test**

```python
# tests/dialectic/measurement/test_read_depth_corpus.py
"""Tests for Adaptive Corpus C structure + controls."""
from __future__ import annotations

from ares.dialectic.agents.light_skeptic_v2_lexical import (
    evaluate as lexical_evaluate,
)
from ares.dialectic.agents.light_skeptic_v2_structured import (
    evaluate as structured_evaluate,
)
from ares.dialectic.coordinator.firewall import _AUTHORIZATION_FACT_FIELDS
from ares.dialectic.measurement.read_depth_corpus import (
    ALL_ENTRIES,
    BENIGN_ENTRIES,
    MALIGN_ENTRIES,
    get_entry,
    inject_authorization,
)
from ares.dialectic.messages.protocol import MessageBuilder, MessageType, Phase


def _arch():
    b = MessageBuilder(source_agent="a", packet_id="t", cycle_id="c")
    b.set_phase(Phase.THESIS).set_type(MessageType.HYPOTHESIS).set_confidence(0.5)
    return b.build()


def test_counts_and_labels():
    assert len(MALIGN_ENTRIES) == 4
    assert len(BENIGN_ENTRIES) == 4
    assert len(ALL_ENTRIES) == 8
    assert all(e.is_malign for e in MALIGN_ENTRIES)
    assert all(not e.is_malign for e in BENIGN_ENTRIES)


def test_unique_scenario_ids_and_fact_prefixes():
    ids = [e.scenario.metadata.scenario_id for e in ALL_ENTRIES]
    assert len(set(ids)) == len(ids)


def test_struct_twin_shares_field_skeleton_with_malign_twin():
    # B-struct-twin must have the same field multiset as its M-lex twin, so
    # the value-blind tier 1 cannot distinguish them.
    twin = get_entry("RDF-B-TWIN-001")
    base = get_entry(twin.twin_id)
    twin_fields = sorted(f.field for f in twin.scenario.packet.get_all_facts())
    base_fields = sorted(f.field for f in base.scenario.packet.get_all_facts())
    assert twin_fields == base_fields


def test_tier1_cannot_distinguish_struct_twin():
    # The load-bearing FP control: tier 1 fires malign on BOTH the malign
    # scenario and its benign structural twin.
    twin = get_entry("RDF-B-TWIN-001")
    base = get_entry(twin.twin_id)
    assert structured_evaluate(base.scenario.packet, _arch()).malign_score > 0
    assert structured_evaluate(twin.scenario.packet, _arch()).malign_score > 0
    # ...while tier 2 correctly passes the benign twin.
    assert lexical_evaluate(twin.scenario.packet, _arch()).malign_score == 0


def test_inject_authorization_adds_auth_fact_and_flips_tier1():
    base = get_entry("RDF-M-LEX-001")
    controlled = inject_authorization(base.scenario)
    fields = {f.field for f in controlled.packet.get_all_facts()}
    assert fields & _AUTHORIZATION_FACT_FIELDS  # an auth fact was added
    # tier 1 swings benign (structural rule suppressed by the auth fact)...
    assert structured_evaluate(base.scenario.packet, _arch()).malign_score > 0
    assert structured_evaluate(controlled.packet, _arch()).malign_score == 0
    # ...but tier 2 stays malign (the threat value is still present).
    assert lexical_evaluate(controlled.packet, _arch()).malign_score > 0


def test_carryforward_benign_trips_tier2():
    # Carry-forward #1: a benign .js under /users/public/ is a tier-2 FP.
    carry = get_entry("RDF-B-CARRY-001")
    assert carry.is_malign is False
    assert lexical_evaluate(carry.scenario.packet, _arch()).malign_score > 0


def test_clean_benign_passes_all_tiers():
    clean = get_entry("RDF-B-CLEAN-001")
    assert structured_evaluate(clean.scenario.packet, _arch()).malign_score == 0
    assert lexical_evaluate(clean.scenario.packet, _arch()).malign_score == 0
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `python -m pytest tests/dialectic/measurement/test_read_depth_corpus.py -v`
Expected: FAIL — `ModuleNotFoundError: ...read_depth_corpus`.

- [ ] **Step 3: Write the minimal implementation**

```python
# ares/dialectic/measurement/read_depth_corpus.py
"""Adaptive Corpus C for the read-depth robustness frontier (Phase B).

Purpose-built, stratified, MITRE-anchored. Authored against injection CLASSES,
not against the tier rules; the independent oracle is paraphrase-invariance.
Realistic telemetry field names (process_name/command_line/url) — not contorted
to trip a specific rule.

Strata:
  Malign  M-lex   : threat in the value matching a tier-2 regex.
          M-syn   : synonym-obfuscated value (tier 2 misses, tier 3 recovers).
          M-patch : Class-4 ineffective patch (benign-indicator field + threat).
  Benign  B-twin  : structural twin of an M-lex (tier 1 FPs, tier 2/3 pass).
          B-carry : carry-forward .com/.js benign value (tier-2 FP probe).
          B-clean : low-stage recon/auth (all tiers pass).

Class 5 (post-exploit-without-change-record) has no implemented rule and is
out of scope for measurement (no stratum).
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Tuple

from ares.dialectic.evidence.fact import EntityType, Fact
from ares.dialectic.evidence.packet import EvidencePacket, TimeWindow
from ares.dialectic.evidence.provenance import Provenance, SourceType
from ares.dialectic.scripts.scenario_corpus import (
    BenchmarkScenario,
    ScenarioMetadata,
    _make_fact,
)

_TS = datetime(2026, 6, 1, 3, 0, 0)
_TW = TimeWindow(start=datetime(2026, 6, 1, 2, 0, 0),
                 end=datetime(2026, 6, 1, 4, 0, 0))


@dataclass(frozen=True)
class CorpusCEntry:
    """A labeled Corpus C scenario."""

    scenario: BenchmarkScenario
    is_malign: bool
    stratum: str
    twin_id: Optional[str] = None  # for B-twin: the M-lex it mirrors

    @property
    def scenario_id(self) -> str:
        return self.scenario.metadata.scenario_id


def _build(sid: str, name: str, verdict: str, facts) -> BenchmarkScenario:
    packet = EvidencePacket(packet_id=sid.lower(), time_window=_TW)
    for f in facts:
        packet.add_fact(f)
    packet.freeze()
    meta = ScenarioMetadata(
        scenario_id=sid, name=name, description=name,
        mitre_attack_ids=("T1003",), mitre_tactic="Credential Access",
        difficulty_tier=3, expected_verdict=verdict, expected_winner="ARCHITECT",
        fact_count=len(facts), notes="read-depth frontier corpus C",
    )
    return BenchmarkScenario(metadata=meta, packet=packet)


def _f(prefix, num, entity, field, value, source=SourceType.PROCESS_LIST):
    return _make_fact(prefix, num, entity, EntityType.NODE, field, value, _TS,
                      source, f"{prefix}-src")


# --- Malign --------------------------------------------------------------

def _m_lex_001() -> BenchmarkScenario:
    p = "rdf-m-lex-001"
    return _build("RDF-M-LEX-001", "procdump credential dump", "THREAT_CONFIRMED", [
        _f(p, 1, "user-jdoe", "logon_type", "RemoteInteractive (Type 10)",
           SourceType.AUTH_LOG),
        _f(p, 2, "proc-pd", "process_name", "C:\\Users\\Public\\procdump.exe"),
        _f(p, 3, "proc-pd", "command_line",
           "procdump.exe -ma lsass.exe C:\\Temp\\lsass.dmp"),
    ])


def _m_lex_002() -> BenchmarkScenario:
    # exe-path ONLY (no credential-tool token) via /Temp/ -> evadable on X.
    p = "rdf-m-lex-002"
    return _build("RDF-M-LEX-002", "generic dropper in temp", "THREAT_CONFIRMED", [
        _f(p, 1, "host-ws01", "process_name", "C:\\Temp\\update.exe"),
        _f(p, 2, "host-ws01", "parent_process", "explorer.exe"),
        _f(p, 3, "host-ws01", "file_created", "C:\\Temp\\update.exe written 1.2MB",
           SourceType.SYSLOG),
    ])


def _m_syn_001() -> BenchmarkScenario:
    # "binary" (no literal .exe) -> tier 2 misses, tier 3 recovers (Y gain).
    p = "rdf-m-syn-001"
    return _build("RDF-M-SYN-001", "synonym-obfuscated dropper", "THREAT_CONFIRMED", [
        _f(p, 1, "host-ws02", "file_created",
           "binary dropped to C:\\Users\\Public\\", SourceType.SYSLOG),
        _f(p, 2, "host-ws02", "process_name", "loader running from public folder"),
    ])


def _m_patch_001() -> BenchmarkScenario:
    # Class 4: benign-indicator field present + active threat value.
    p = "rdf-m-patch-001"
    return _build("RDF-M-PATCH-001", "ineffective patch claim", "THREAT_CONFIRMED", [
        _f(p, 1, "host-db01", "patch_applied", "KB5038790 installed 2026-05-01",
           SourceType.SYSLOG),
        _f(p, 2, "proc-pd2", "command_line", "procdump.exe -ma lsass.exe"),
        _f(p, 3, "proc-pd2", "process_name", "C:\\Users\\Public\\procdump.exe"),
    ])


# --- Benign --------------------------------------------------------------

def _b_twin_001() -> BenchmarkScenario:
    # Same field set as M-LEX-001 (logon_type/process_name/command_line),
    # benign system-path values -> tier 1 FPs, tier 2/3 pass.
    p = "rdf-b-twin-001"
    return _build("RDF-B-TWIN-001", "benign service host", "THREAT_DISMISSED", [
        _f(p, 1, "user-svc", "logon_type", "Service (Type 5)", SourceType.AUTH_LOG),
        _f(p, 2, "proc-svc", "process_name", "C:\\Windows\\System32\\svchost.exe"),
        _f(p, 3, "proc-svc", "command_line", "svchost.exe -k netsvcs -p"),
    ])


def _b_twin_002() -> BenchmarkScenario:
    # Same field set as M-LEX-002, Program Files (not user-writable) path.
    p = "rdf-b-twin-002"
    return _build("RDF-B-TWIN-002", "benign signed installer", "THREAT_DISMISSED", [
        _f(p, 1, "host-ws01b", "process_name",
           "C:\\Program Files\\Vendor\\update.exe"),
        _f(p, 2, "host-ws01b", "parent_process", "services.exe"),
        _f(p, 3, "host-ws01b", "file_created",
           "C:\\Program Files\\Vendor\\update.exe signed installer",
           SourceType.SYSLOG),
    ])


def _b_carry_001() -> BenchmarkScenario:
    # Carry-forward #1: benign .js under /users/public/ -> tier-2 FP probe.
    p = "rdf-b-carry-001"
    return _build("RDF-B-CARRY-001", "benign web asset", "THREAT_DISMISSED", [
        _f(p, 1, "host-web", "url",
           "https://cdn.example.com/users/public/tracker.js", SourceType.SYSLOG),
        _f(p, 2, "host-web", "http_user_agent", "Mozilla/5.0 standard browser",
           SourceType.SYSLOG),
    ])


def _b_clean_001() -> BenchmarkScenario:
    # Low-stage recon + authorization -> all tiers pass (sanity floor).
    p = "rdf-b-clean-001"
    return _build("RDF-B-CLEAN-001", "authorized recon", "THREAT_DISMISSED", [
        _f(p, 1, "src-ext", "src_ip_reputation", "known-good 8.8.8.8",
           SourceType.SYSLOG),
        _f(p, 2, "host-fw", "port_scan", "single port 443 check", SourceType.SYSLOG),
        _f(p, 3, "change-mgmt", "change_ticket", "CHG-44021 approved maintenance",
           SourceType.AUTH_LOG),
    ])


MALIGN_ENTRIES: Tuple[CorpusCEntry, ...] = (
    CorpusCEntry(_m_lex_001(), True, "M-lex"),
    CorpusCEntry(_m_lex_002(), True, "M-lex"),
    CorpusCEntry(_m_syn_001(), True, "M-syn"),
    CorpusCEntry(_m_patch_001(), True, "M-patch"),
)

BENIGN_ENTRIES: Tuple[CorpusCEntry, ...] = (
    CorpusCEntry(_b_twin_001(), False, "B-struct-twin", twin_id="RDF-M-LEX-001"),
    CorpusCEntry(_b_twin_002(), False, "B-struct-twin", twin_id="RDF-M-LEX-002"),
    CorpusCEntry(_b_carry_001(), False, "B-carryforward"),
    CorpusCEntry(_b_clean_001(), False, "B-clean"),
)

ALL_ENTRIES: Tuple[CorpusCEntry, ...] = MALIGN_ENTRIES + BENIGN_ENTRIES

_BY_ID = {e.scenario_id: e for e in ALL_ENTRIES}


def get_entry(scenario_id: str) -> CorpusCEntry:
    """Look up a corpus entry by scenario_id."""
    if scenario_id not in _BY_ID:
        raise KeyError(f"unknown scenario_id {scenario_id!r}")
    return _BY_ID[scenario_id]


def inject_authorization(scenario: BenchmarkScenario) -> BenchmarkScenario:
    """Positive control: add a genuine authorization fact to a scenario.

    Rebuilds the packet with every existing fact plus a new ``change_ticket``
    fact, so the structural tier (which keys on auth-field presence) swings
    benign while the value-reading tiers stay malign. Deterministic.
    """
    sid = scenario.metadata.scenario_id
    new_packet = EvidencePacket(
        packet_id=f"{scenario.packet.packet_id}__posctrl",
        time_window=TimeWindow(
            start=scenario.packet.time_window.start,
            end=scenario.packet.time_window.end,
        ),
    )
    for fact in scenario.packet.get_all_facts():
        new_packet.add_fact(fact)
    new_packet.add_fact(Fact(
        fact_id=f"{sid.lower()}-fact-posctrl",
        entity_id="change-mgmt",
        entity_type=EntityType.NODE,
        field="change_ticket",
        value="CHG-POSCTRL approved and authorized incident response",
        timestamp=_TS,
        provenance=Provenance(source_type=SourceType.AUTH_LOG,
                              source_id="posctrl", parser_version="1.0.0"),
    ))
    new_packet.freeze()
    new_meta = ScenarioMetadata(
        scenario_id=f"{sid}-POSCTRL", name=f"{scenario.metadata.name} (+auth)",
        description="positive control: genuine authorization injected",
        mitre_attack_ids=scenario.metadata.mitre_attack_ids,
        mitre_tactic=scenario.metadata.mitre_tactic, difficulty_tier=3,
        expected_verdict=scenario.metadata.expected_verdict,
        expected_winner=scenario.metadata.expected_winner,
        fact_count=new_packet.fact_count, notes="positive control",
    )
    return BenchmarkScenario(metadata=new_meta, packet=new_packet)


def corpus_digest() -> str:
    """Deterministic digest over the corpus (snapshot ids + ids)."""
    parts = sorted(
        f"{e.scenario_id}:{e.scenario.packet.snapshot_id}" for e in ALL_ENTRIES
    )
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:16]
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `python -m pytest tests/dialectic/measurement/test_read_depth_corpus.py -v`
Expected: PASS (7 passed). If `test_tier1_cannot_distinguish_struct_twin` or `test_carryforward_benign_trips_tier2` fails, the scenario's field names/values diverged from the rule triggers — re-check against `firewall._STAGE_MAP`, `_USER_WRITABLE_DIR`, and `_CRED_TOOLING`; do not weaken the test.

- [ ] **Step 5: Commit**

```bash
git add ares/dialectic/measurement/read_depth_corpus.py tests/dialectic/measurement/test_read_depth_corpus.py
git commit -m "feat(s087): Adaptive Corpus C (stratified malign/benign + positive control)"
```

---

## Task 5: Frontier runner (`read_depth_frontier_runner.py`)

**Files:**
- Create: `ares/dialectic/measurement/read_depth_frontier_runner.py`
- Test: `tests/dialectic/measurement/test_read_depth_frontier_runner.py`

The runner ties everything together offline. Per tier × view it computes baseline verdicts (standalone + cumulative-OR), perturbs the malign scenarios with both operator families (no-ops excluded via `SkeletonInvariantError`), and aggregates micro-averaged X plus exact TPR/FPR/J. The runner test is also the **frontier-sanity scientific contract**.

- [ ] **Step 1: Write the failing test**

```python
# tests/dialectic/measurement/test_read_depth_frontier_runner.py
"""Runner determinism + the frontier-sanity scientific contract."""
from __future__ import annotations

from ares.dialectic.measurement.read_depth_frontier_schema import (
    VIEW_CUMULATIVE,
    VIEW_STANDALONE,
    FrontierSummary,
)
from ares.dialectic.measurement.read_depth_frontier_runner import run_frontier


def _coord(summary, tier_id, view):
    for c in summary.coordinates:
        if c.tier_id == tier_id and c.view == view:
            return c
    raise AssertionError(f"no coordinate {tier_id}/{view}")


def test_run_is_deterministic():
    a = run_frontier()
    b = run_frontier()
    assert a.to_json() == b.to_json()


def test_emits_four_tiers_two_views_no_anchor():
    s = run_frontier()
    tier_ids = {c.tier_id for c in s.coordinates}
    assert tier_ids == {"v1_field", "v2_structured", "v2_lexical", "v2_canonical"}
    assert "llm_semantic" not in tier_ids
    views = {c.view for c in s.coordinates}
    assert views == {VIEW_STANDALONE, VIEW_CUMULATIVE}
    assert isinstance(s, FrontierSummary)


def test_blind_baseline_tier0_has_zero_detection():
    s = run_frontier()
    c = _coord(s, "v1_field", VIEW_STANDALONE)
    assert c.tpr == 0.0 and c.fpr == 0.0 and c.youden_j == 0.0


def test_standalone_youden_strictly_rises_with_depth():
    s = run_frontier()
    j = {t: _coord(s, t, VIEW_STANDALONE).youden_j
         for t in ("v1_field", "v2_structured", "v2_lexical", "v2_canonical")}
    assert j["v1_field"] < j["v2_structured"] < j["v2_lexical"] < j["v2_canonical"]


def test_cumulative_caps_below_standalone_at_depth3():
    # The trilemma's teeth: keeping the structural rule (cumulative) caps Y
    # below what value-reading alone (standalone tier 3) achieves.
    s = run_frontier()
    standalone3 = _coord(s, "v2_canonical", VIEW_STANDALONE).youden_j
    cumulative3 = _coord(s, "v2_canonical", VIEW_CUMULATIVE).youden_j
    assert cumulative3 < standalone3


def test_semantic_framing_does_not_move_deterministic_tiers():
    s = run_frontier()
    for t in ("v1_field", "v2_structured", "v2_lexical", "v2_canonical"):
        assert _coord(s, t, VIEW_STANDALONE).x_semantic == 0.0


def test_lexical_evasion_moves_tier2_but_tier1_and_tier3_robust():
    s = run_frontier()
    assert _coord(s, "v2_lexical", VIEW_STANDALONE).x_lexical > 0.0
    assert _coord(s, "v1_field", VIEW_STANDALONE).x_lexical == 0.0
    assert _coord(s, "v2_canonical", VIEW_STANDALONE).x_lexical == 0.0


def test_positive_control_flips_tier1_only():
    s = run_frontier()
    by_tier = {}
    for pc in s.positive_control_records:
        if pc.scenario_id.startswith("RDF-M-LEX-001") and pc.view == VIEW_STANDALONE:
            by_tier[pc.tier_id] = pc
    assert by_tier["v1_field"].moved is True
    assert by_tier["v1_field"].controlled_malign_verdict is False
    assert by_tier["v2_lexical"].moved is False
    assert by_tier["v2_lexical"].controlled_malign_verdict is True


def test_m_syn_caught_only_from_tier3():
    # Detection gain tier2->tier3: M-SYN missed by tier 2, caught by tier 3.
    s = run_frontier()
    recs = {(r.tier_id): r for r in s.records
            if r.scenario_id == "RDF-M-SYN-001" and r.view == VIEW_STANDALONE}
    assert recs["v2_lexical"].baseline_malign_verdict is False
    assert recs["v2_canonical"].baseline_malign_verdict is True
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `python -m pytest tests/dialectic/measurement/test_read_depth_frontier_runner.py -v`
Expected: FAIL — `ModuleNotFoundError: ...read_depth_frontier_runner`.

- [ ] **Step 3: Write the minimal implementation**

```python
# ares/dialectic/measurement/read_depth_frontier_runner.py
"""Offline runner for the read-depth robustness frontier (Phase B).

Pure deterministic computation over Adaptive Corpus C and the four deterministic
tiers. No LLM, no network, no cost, no preflight. Emits a FrontierSummary with a
(X_semantic, X_lexical, TPR, FPR, Youden-J) coordinate per tier per view.
"""
from __future__ import annotations

from typing import Callable, Dict, List, Tuple

from ares.dialectic.agents.light_skeptic_v2_ladder import (
    DETERMINISTIC_TIERS,
    LADDER_ORDER,
)
from ares.dialectic.measurement.read_depth_corpus import (
    ALL_ENTRIES,
    BENIGN_ENTRIES,
    MALIGN_ENTRIES,
    CorpusCEntry,
    corpus_digest,
    inject_authorization,
)
from ares.dialectic.measurement.read_depth_evasion_operators import (
    EVASION_OPERATORS,
)
from ares.dialectic.measurement.read_depth_frontier_metrics import (
    cumulative_verdict,
    flip_rate,
    is_malign_verdict,
    tpr_fpr,
    youden_j,
)
from ares.dialectic.measurement.read_depth_frontier_schema import (
    VIEW_CUMULATIVE,
    VIEW_STANDALONE,
    VIEWS,
    FrontierConfig,
    FrontierSummary,
    PositiveControlRecord,
    ScenarioVerdictRecord,
    TierCoordinate,
)
from ares.dialectic.messages.protocol import (
    DialecticalMessage,
    MessageBuilder,
    MessageType,
    Phase,
)
from ares.dialectic.scripts.non_interference.paired_scenario_mutator import (
    OPERATORS_V1,
    MutationOperator,
    PairedScenarioMutator,
    SkeletonInvariantError,
)
from ares.dialectic.scripts.scenario_corpus import BenchmarkScenario

# The deterministic rungs, in ladder order (tier 4 / llm_semantic excluded).
_TIER_IDS: Tuple[str, ...] = tuple(
    t for t in LADDER_ORDER if t in DETERMINISTIC_TIERS
)
# Semantic family = the framing operators from the existing mutator (predicted
# X ~= 0 for substring-matching tiers).
_SEMANTIC_OPERATORS: Tuple[MutationOperator, ...] = tuple(
    op for op in OPERATORS_V1 if op.family == "framing"
)


def _neutral_architect() -> DialecticalMessage:
    """A minimal Architect message; the tiers ignore it (v1 ``_ = arch``)."""
    b = MessageBuilder(source_agent="frontier", packet_id="frontier",
                       cycle_id="frontier")
    b.set_phase(Phase.THESIS).set_type(MessageType.HYPOTHESIS).set_confidence(0.5)
    return b.build()


def _standalone_verdicts(
    scenario: BenchmarkScenario, arch: DialecticalMessage, op_point: float
) -> Dict[str, Tuple[bool, float]]:
    """{tier_id: (malign_verdict, malign_score)} for one scenario."""
    out: Dict[str, Tuple[bool, float]] = {}
    for tier_id in _TIER_IDS:
        j = DETERMINISTIC_TIERS[tier_id](scenario.packet, arch)
        out[tier_id] = (is_malign_verdict(j, op_point), j.malign_score)
    return out


def _cumulative_verdicts(standalone: Dict[str, Tuple[bool, float]]) -> Dict[str, bool]:
    """Cumulative verdict per tier = OR of standalone verdicts up to its depth."""
    out: Dict[str, bool] = {}
    for i, tier_id in enumerate(_TIER_IDS):
        prefix = [standalone[t][0] for t in _TIER_IDS[: i + 1]]
        out[tier_id] = cumulative_verdict(prefix)
    return out


def _verdict_by_view(
    scenario: BenchmarkScenario, arch: DialecticalMessage, op_point: float
) -> Tuple[Dict[str, Dict[str, bool]], Dict[str, Tuple[bool, float]]]:
    """Return ({view: {tier_id: malign_verdict}}, standalone_scores)."""
    standalone = _standalone_verdicts(scenario, arch, op_point)
    cumulative = _cumulative_verdicts(standalone)
    return {
        VIEW_STANDALONE: {t: standalone[t][0] for t in _TIER_IDS},
        VIEW_CUMULATIVE: cumulative,
    }, standalone


def _mutate_variants(
    scenario: BenchmarkScenario,
    operators: Tuple[MutationOperator, ...],
    seed: int,
) -> List[BenchmarkScenario]:
    """Apply each operator; keep only the ones that actually mutated."""
    mut = PairedScenarioMutator(operators=operators, seed=seed)
    variants: List[BenchmarkScenario] = []
    for op in operators:
        try:
            pair = mut.mutate(scenario, op.operator_name)
        except SkeletonInvariantError as exc:
            if "no Fact value_hash differs" in str(exc):
                continue  # no-op on this scenario; excluded from denominator
            raise
        variants.append(pair.mutated_scenario)
    return variants


def run_frontier(config: FrontierConfig | None = None) -> FrontierSummary:
    """Compute the deterministic read-depth frontier over Adaptive Corpus C."""
    if config is None:
        config = FrontierConfig(
            operating_point=0.0,
            semantic_operator_names=tuple(
                op.operator_name for op in _SEMANTIC_OPERATORS
            ),
            lexical_operator_names=tuple(
                op.operator_name for op in EVASION_OPERATORS
            ),
            seed=0,
        )
    arch = _neutral_architect()
    op_point = config.operating_point

    # Per-scenario baseline verdicts (both views) + standalone scores.
    baseline_views: Dict[str, Dict[str, Dict[str, bool]]] = {}
    baseline_scores: Dict[str, Dict[str, float]] = {}
    for e in ALL_ENTRIES:
        views, standalone = _verdict_by_view(e.scenario, arch, op_point)
        baseline_views[e.scenario_id] = views
        baseline_scores[e.scenario_id] = {t: standalone[t][1] for t in _TIER_IDS}

    # Perturbation flips on the malign scenarios.
    # flips[scenario_id][family][view][tier_id] = n_flips ; n_mut[scenario_id][family]
    flips: Dict[str, Dict[str, Dict[str, Dict[str, int]]]] = {}
    n_mut: Dict[str, Dict[str, int]] = {}
    for e in MALIGN_ENTRIES:
        flips[e.scenario_id] = {
            "semantic": {v: {t: 0 for t in _TIER_IDS} for v in VIEWS},
            "lexical": {v: {t: 0 for t in _TIER_IDS} for v in VIEWS},
        }
        n_mut[e.scenario_id] = {"semantic": 0, "lexical": 0}
        for family, operators in (
            ("semantic", _SEMANTIC_OPERATORS),
            ("lexical", EVASION_OPERATORS),
        ):
            for variant in _mutate_variants(e.scenario, operators, config.seed):
                n_mut[e.scenario_id][family] += 1
                vviews, _ = _verdict_by_view(variant, arch, op_point)
                for view in VIEWS:
                    for tier_id in _TIER_IDS:
                        base = baseline_views[e.scenario_id][view][tier_id]
                        pert = vviews[view][tier_id]
                        if base != pert:
                            flips[e.scenario_id][family][view][tier_id] += 1

    # Per-scenario records (standalone + cumulative).
    records: List[ScenarioVerdictRecord] = []
    for e in ALL_ENTRIES:
        for view in VIEWS:
            for tier_id in _TIER_IDS:
                is_mal = e.is_malign
                nm_sem = n_mut.get(e.scenario_id, {}).get("semantic", 0)
                nm_lex = n_mut.get(e.scenario_id, {}).get("lexical", 0)
                fl_sem = flips.get(e.scenario_id, {}).get(
                    "semantic", {}).get(view, {}).get(tier_id, 0)
                fl_lex = flips.get(e.scenario_id, {}).get(
                    "lexical", {}).get(view, {}).get(tier_id, 0)
                records.append(ScenarioVerdictRecord(
                    scenario_id=e.scenario_id, tier_id=tier_id, view=view,
                    is_malign=is_mal, stratum=e.stratum,
                    baseline_malign_verdict=baseline_views[
                        e.scenario_id][view][tier_id],
                    malign_score=baseline_scores[e.scenario_id][tier_id],
                    n_mut_semantic=nm_sem, flips_semantic=fl_sem,
                    n_mut_lexical=nm_lex, flips_lexical=fl_lex,
                ))

    # Aggregate to coordinates.
    coordinates: List[TierCoordinate] = []
    for view in VIEWS:
        for tier_id in _TIER_IDS:
            mal_v = [baseline_views[e.scenario_id][view][tier_id]
                     for e in MALIGN_ENTRIES]
            ben_v = [baseline_views[e.scenario_id][view][tier_id]
                     for e in BENIGN_ENTRIES]
            tpr, fpr = tpr_fpr(mal_v, ben_v)
            sem_num = sum(flips[e.scenario_id]["semantic"][view][tier_id]
                          for e in MALIGN_ENTRIES)
            sem_den = sum(n_mut[e.scenario_id]["semantic"] for e in MALIGN_ENTRIES)
            lex_num = sum(flips[e.scenario_id]["lexical"][view][tier_id]
                          for e in MALIGN_ENTRIES)
            lex_den = sum(n_mut[e.scenario_id]["lexical"] for e in MALIGN_ENTRIES)
            coordinates.append(TierCoordinate(
                tier_id=tier_id, view=view,
                x_semantic=flip_rate(sem_den, sem_num),
                x_lexical=flip_rate(lex_den, lex_num),
                tpr=tpr, fpr=fpr, youden_j=youden_j(tpr, fpr),
                n_malign=len(MALIGN_ENTRIES), n_benign=len(BENIGN_ENTRIES),
            ))

    # Positive controls (inject genuine authorization into each malign).
    pcs: List[PositiveControlRecord] = []
    for e in MALIGN_ENTRIES:
        controlled = inject_authorization(e.scenario)
        cviews, _ = _verdict_by_view(controlled, arch, op_point)
        for view in VIEWS:
            for tier_id in _TIER_IDS:
                base = baseline_views[e.scenario_id][view][tier_id]
                ctl = cviews[view][tier_id]
                pcs.append(PositiveControlRecord(
                    scenario_id=controlled.metadata.scenario_id,
                    tier_id=tier_id, view=view,
                    baseline_malign_verdict=base,
                    controlled_malign_verdict=ctl, moved=(base != ctl),
                ))

    return FrontierSummary(
        coordinates=tuple(coordinates),
        records=tuple(records),
        positive_control_records=tuple(pcs),
        corpus_digest=corpus_digest(),
        config=config,
    )
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `python -m pytest tests/dialectic/measurement/test_read_depth_frontier_runner.py -v`
Expected: PASS (9 passed). If `test_positive_control_flips_tier1_only` references `RDF-M-LEX-001-POSCTRL`, note `inject_authorization` suffixes `-POSCTRL`; the test matches on `startswith("RDF-M-LEX-001")` which also matches the controlled id — that is intentional (both share the prefix; only POSCTRL records exist in `positive_control_records`).

- [ ] **Step 5: Commit**

```bash
git add ares/dialectic/measurement/read_depth_frontier_runner.py tests/dialectic/measurement/test_read_depth_frontier_runner.py
git commit -m "feat(s087): offline read-depth frontier runner + sanity contract"
```

---

## Task 6: Report + coordinate emitter (`read_depth_frontier_report.py`)

**Files:**
- Create: `ares/dialectic/measurement/read_depth_frontier_report.py`
- Test: `tests/dialectic/measurement/test_read_depth_frontier_report.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/dialectic/measurement/test_read_depth_frontier_report.py
"""Tests for the frontier markdown + JSON emitters."""
from __future__ import annotations

import json

from ares.dialectic.measurement.read_depth_frontier_report import (
    coordinates_json,
    render_report,
)
from ares.dialectic.measurement.read_depth_frontier_runner import run_frontier


def test_render_report_has_both_views_and_all_tiers():
    md = render_report(run_frontier())
    assert "standalone" in md
    assert "cumulative" in md
    for tier in ("v1_field", "v2_structured", "v2_lexical", "v2_canonical"):
        assert tier in md
    # Carry-forward #2 precision note must be present.
    assert "high_stage_without_authorization" in md or "M2" in md


def test_coordinates_json_is_valid_and_has_eight_points():
    payload = coordinates_json(run_frontier())
    data = json.loads(payload)
    assert len(data["coordinates"]) == 8  # 4 tiers x 2 views
    assert data["corpus_digest"]
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `python -m pytest tests/dialectic/measurement/test_read_depth_frontier_report.py -v`
Expected: FAIL — `ModuleNotFoundError: ...read_depth_frontier_report`.

- [ ] **Step 3: Write the minimal implementation**

```python
# ares/dialectic/measurement/read_depth_frontier_report.py
"""Markdown + JSON emitters for the read-depth frontier (Phase B).

The JSON ``coordinates`` payload feeds the Phase-C visual-companion frontier
plot. The markdown is the human-readable summary. Neither asserts a frontier
*verdict* (that needs the Phase-C LLM anchor + pre-registration).
"""
from __future__ import annotations

import json

from ares.dialectic.measurement.read_depth_frontier_schema import (
    VIEWS,
    FrontierSummary,
)

# Carry-forward #2: keep the blindness claim precise.
_PRECISION_NOTE = (
    "> Note: \"tier 1 is blind to value-borne attacks\" is precise only for the "
    "`high_threat_field` (M1) rule; `high_stage_without_authorization` (M2) "
    "still fires via the field-name-derived kill-chain stage."
)


def render_report(summary: FrontierSummary) -> str:
    """Render the frontier as a markdown report (no verdict)."""
    lines = [
        "# Read-Depth Robustness Frontier — Phase B (deterministic tiers)",
        "",
        f"Corpus digest: `{summary.corpus_digest}`  |  "
        f"operating point: malign_score > {summary.config.operating_point}",
        "",
        f"Semantic operators: {', '.join(summary.config.semantic_operator_names)}",
        f"Lexical operators: {', '.join(summary.config.lexical_operator_names)}",
        "",
        "No frontier verdict here — that requires the Phase-C LLM anchor (tier 4) "
        "and the pre-registration commit.",
        "",
    ]
    for view in VIEWS:
        lines += [
            f"## View: {view}",
            "",
            "| tier | X_semantic | X_lexical | TPR | FPR | Youden J |",
            "|------|-----------:|----------:|----:|----:|---------:|",
        ]
        for c in summary.coordinates:
            if c.view != view:
                continue
            lines.append(
                f"| {c.tier_id} | {c.x_semantic:.3f} | {c.x_lexical:.3f} "
                f"| {c.tpr:.3f} | {c.fpr:.3f} | {c.youden_j:.3f} |"
            )
        lines.append("")
    # Positive-control summary.
    lines += ["## Positive control (inject genuine authorization)", ""]
    moved = [pc for pc in summary.positive_control_records
             if pc.view == "standalone" and pc.moved]
    lines.append(
        f"Standalone verdict MOVED in {len(moved)} (tier, scenario) cells "
        "— expected: the structural tier swings benign, value tiers hold."
    )
    lines += ["", _PRECISION_NOTE, ""]
    return "\n".join(lines)


def coordinates_json(summary: FrontierSummary) -> str:
    """Emit the (X, Y) coordinates + provenance as JSON (for the plot)."""
    return json.dumps(
        {
            "coordinates": [c.to_dict() for c in summary.coordinates],
            "corpus_digest": summary.corpus_digest,
            "config": summary.config.to_dict(),
        },
        sort_keys=True,
        indent=2,
    )
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `python -m pytest tests/dialectic/measurement/test_read_depth_frontier_report.py -v`
Expected: PASS (2 passed).

- [ ] **Step 5: Commit**

```bash
git add ares/dialectic/measurement/read_depth_frontier_report.py tests/dialectic/measurement/test_read_depth_frontier_report.py
git commit -m "feat(s087): frontier markdown report + (X,Y) JSON emitter"
```

---

## Task 7: CLI (`scripts/run_session_087.py`)

**Files:**
- Create: `scripts/run_session_087.py`
- Test: `tests/dialectic/measurement/test_run_session_087.py`

Gate-free (nothing costs anything). Writes `frontier_report.md` + `frontier_coordinates.json` to an output dir.

- [ ] **Step 1: Write the failing test**

```python
# tests/dialectic/measurement/test_run_session_087.py
"""Smoke test for the session-087 CLI (offline)."""
from __future__ import annotations

import json


def test_main_writes_artifacts(tmp_path):
    from scripts.run_session_087 import main

    code = main(["--out-dir", str(tmp_path)])
    assert code == 0
    report = tmp_path / "frontier_report.md"
    coords = tmp_path / "frontier_coordinates.json"
    assert report.exists()
    assert coords.exists()
    data = json.loads(coords.read_text(encoding="utf-8"))
    assert len(data["coordinates"]) == 8
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `python -m pytest tests/dialectic/measurement/test_run_session_087.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'scripts.run_session_087'`.

- [ ] **Step 3: Write the minimal implementation**

```python
# scripts/run_session_087.py
"""Session 087 CLI — run the offline read-depth robustness frontier (Phase B).

Gate-free: deterministic, offline, zero cost. Writes a markdown report and the
(X, Y) coordinate JSON that Phase C's frontier plot consumes.

Usage:
    python -m scripts.run_session_087 --out-dir data/paper_4/read_depth_frontier
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List, Optional

from ares.dialectic.measurement.read_depth_frontier_report import (
    coordinates_json,
    render_report,
)
from ares.dialectic.measurement.read_depth_frontier_runner import run_frontier

_DEFAULT_OUT = "data/paper_4/read_depth_frontier"


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Read-depth frontier (Phase B).")
    parser.add_argument("--out-dir", default=_DEFAULT_OUT,
                        help="directory for report + coordinates")
    args = parser.parse_args(argv)

    summary = run_frontier()

    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "frontier_report.md").write_text(render_report(summary),
                                            encoding="utf-8")
    (out / "frontier_coordinates.json").write_text(coordinates_json(summary),
                                                    encoding="utf-8")

    print(f"[s087] wrote frontier artifacts to {out} "
          f"(corpus {summary.corpus_digest})")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `python -m pytest tests/dialectic/measurement/test_run_session_087.py -v`
Expected: PASS (1 passed).

- [ ] **Step 5: Commit**

```bash
git add scripts/run_session_087.py tests/dialectic/measurement/test_run_session_087.py
git commit -m "feat(s087): gate-free CLI to emit the deterministic frontier"
```

---

## Task 8: Full-suite regression + test floor bump

**Files:** `CLAUDE.md` (test floor line only).

- [ ] **Step 1: Run the new Phase-B tests together**

Run: `python -m pytest tests/dialectic/measurement/test_read_depth_frontier_schema.py tests/dialectic/measurement/test_read_depth_frontier_metrics.py tests/dialectic/measurement/test_read_depth_evasion_operators.py tests/dialectic/measurement/test_read_depth_corpus.py tests/dialectic/measurement/test_read_depth_frontier_runner.py tests/dialectic/measurement/test_read_depth_frontier_report.py tests/dialectic/measurement/test_run_session_087.py -v`
Expected: PASS (~34 passed).

- [ ] **Step 2: Confirm the Phase-A tiers + v1 are untouched**

Run: `python -m pytest ares/dialectic/tests/agents/test_light_skeptic.py ares/dialectic/tests/agents/test_light_skeptic_anchor.py ares/dialectic/tests/agents/test_light_skeptic_v2_ladder_and_purity.py -v`
Expected: PASS (all green — v1 + tiers byte-stable).

- [ ] **Step 3: Run the full suite (regression gate)**

Run: `python -m pytest tests/ ares/ -q`
Expected: PASS — all prior tests + the new Phase-B tests, 0 failures. (This is the regression check, NOT the floor source.)

- [ ] **Step 4: Update the CLAUDE.md test floor (correct scope)**

The freshness test (`tests/test_claude_md_freshness.py`) treats the floor as a MINIMUM and collects over **`tests/ + ares/dialectic/tests/`** — a different (smaller) scope than Step 3. Adding tests only raises the actual count, so the floor stays valid even unchanged; bump it for honesty using that exact scope:

Run: `python -m pytest tests/ ares/dialectic/tests/ --collect-only -q --no-header`
Take the "N tests collected" number and set the `**Test count floor (passing):**` line in `CLAUDE.md` to it. **Do NOT use the `pytest tests/ ares/` total — that is the larger Step-3 scope and will not match the freshness collector.** Also bump `**Last updated:**` to `2026-06-07` and append a one-line S087 entry to the session ledger. Then confirm the freshness test passes:

Run: `python -m pytest tests/test_claude_md_freshness.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add CLAUDE.md
git commit -m "docs(s087): bump test floor after Phase B (Corpus C + frontier harness)"
```

---

## Self-Review

**Spec coverage:**
- §2.1 two views (standalone + cumulative), cumulative-as-OR → Task 2 `cumulative_verdict`, Task 5 `_cumulative_verdicts` + both-view coordinates. ✓
- §3 Corpus C strata (M-lex/M-syn/M-patch, B-struct-twin/B-carryforward/B-clean) + positive control → Task 4. ✓
- §3.4 Class 5 excluded (no stratum) → Task 4 docstring. ✓
- §4 two perturbation families (semantic reuse + lexical-evasion) → Task 3 operators + Task 5 `_SEMANTIC_OPERATORS`/`EVASION_OPERATORS`. ✓
- §5 metrics (operating point malign_score>0, flip-rate no-op exclusion, TPR−FPR) → Task 2 + Task 5. ✓
- §5.2 schema (TierCoordinate/ScenarioVerdictRecord/FrontierSummary, tier-4 absent) → Task 1. ✓
- §6 file plan + reuse map (no permutation/bootstrap; mutator + ladder reused) → Tasks 1–7. ✓
- §7 tests incl. frontier-sanity contract → Task 5 test. ✓
- §8 carry-forward #2 precision note → Task 6 `_PRECISION_NOTE`. ✓
- §9 DoD (emit per-tier coordinates both views; no verdict) → Task 5/6/7; zero regressions → Task 8. ✓

**Placeholder scan:** No TBD/TODO; every code step is complete and runnable. The 8-scenario corpus is a tested floor with the extension pattern stated.

**Type consistency:** `CorpusCEntry`, `FrontierConfig`, `TierCoordinate`, `ScenarioVerdictRecord`, `PositiveControlRecord`, `FrontierSummary` field names match across Tasks 1/4/5/6. `run_frontier()`/`render_report()`/`coordinates_json()` signatures match across Tasks 5/6/7. `is_malign_verdict`/`flip_rate`/`tpr_fpr`/`youden_j`/`cumulative_verdict` names match across Tasks 2/5. Operator names `exe_to_binary_v1`/`temp_to_temporary_v1` match across Tasks 3/5/runner config.

**Known fragility (flagged for the executor):** the corpus + tier interactions are exact but regex-sensitive. If a runner-sanity assertion fails, the fix is in the corpus values (align to `firewall._STAGE_MAP` / `_USER_WRITABLE_DIR` / `_CRED_TOOLING` / canonical `_SYNONYMS`), never by weakening the assertion — the assertions encode the scientific contract.
