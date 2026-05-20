# Prism — Panel 1 (Labyrinth) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the first panel of the Prism (Labyrinth — 6-chamber data-flow topology) as a production page at `skyframe-main/assets/ares/prism.html`, backed by a new TimelineBuilder v2 pipeline (`ares/dialectic/visualization/cycle_trace*`) that emits per-cycle Session 059 traces into `prism-timeline.json`.

**Architecture:** New Python module `cycle_trace.py` (schema) + `cycle_trace_builder.py` (loader/assembler) + `build_cycle_timeline.py` (CLI), parallel to the existing v1 Pinscreen pipeline — no modifications to v1 files (per ARES "new files only" rule). Output JSON is consumed by a standalone HTML page using three.js r128 classic scripts (matching the rest of skyframe-main). Panel 1 ships with full-kit interactivity at single-panel scope: time scrubber, click-to-focus on cycles, adversarial-pressure dial. Cross-panel sync (cycle-focus highlighting across all four panels) is naturally deferred until Panels 2–4 land in follow-on plans.

**Tech Stack:** Python 3.11, frozen dataclasses, pytest, three.js r128 (classic CDN scripts), vanilla JS, deterministic JSON serialization.

**Build-prep reference:** `docs/superpowers/specs/2026-05-13-prism-build-prep.md`
**Mockup reference:** `docs/marketing/prism-mockup.html` (open in browser; uses r160 ESM, this plan converts to r128 classic)
**Pinscreen plan (parallel pattern reference):** `docs/superpowers/plans/2026-05-13-replay-viewer-pinscreen-3d.md`

---

## File Structure

### ARES repo (`C:/ares-phase-zero/`)

**Created:**
- `ares/dialectic/visualization/cycle_trace.py` — frozen dataclasses (`CycleSnapshot`, `PairTrace`, `CycleTimelineV2`)
- `ares/dialectic/visualization/cycle_trace_builder.py` — loads JSONL, assembles `CycleTimelineV2`, reuses `compute_pair_leakage`
- `ares/dialectic/visualization/build_cycle_timeline.py` — CLI: `python -m ares.dialectic.visualization.build_cycle_timeline --traces ... --output ...`
- `ares/dialectic/tests/visualization/test_cycle_trace.py` — schema invariant tests
- `ares/dialectic/tests/visualization/test_cycle_trace_builder.py` — builder tests against synthetic + real Session 059 data
- `ares/dialectic/tests/visualization/test_build_cycle_timeline_cli.py` — CLI invocation tests
- `docs/marketing/prism-timeline.json` — CLI output (source of truth for the JSON)

**Not modified:** v1 pipeline (`data_loader.py`, `pin_mapper.py`, `timeline_builder.py`, `build_timeline.py`) — frozen per ARES architectural constraint.

### skyframe-main repo (`E:/Skyframe Innovations Website/skyframe-main/`)

**Created:**
- `assets/ares/prism.html` — production standalone page (r128 classic scripts, Panel 1 only in v1)
- `assets/ares/prism-timeline.json` — copy of the ARES-generated JSON, served by Netlify

**Modified:**
- `assets/ares/ares.html` — add a second CTA link pointing to `prism.html` next to the existing `pinscreen.html` link

### Branch strategy
Branch `session/062-prism-labyrinth` in the ARES repo. Skyframe-main commits happen on its own `main` (Netlify auto-deploys on push). The two repos commit independently — pinscreen Session 061 set the precedent.

---

## Phase A — TimelineBuilder v2 (Python, schema-first)

### Task A1: Create branch and scaffold empty test files

**Files:**
- Create: `ares/dialectic/tests/visualization/test_cycle_trace.py`
- Create: `ares/dialectic/tests/visualization/test_cycle_trace_builder.py`
- Create: `ares/dialectic/tests/visualization/test_build_cycle_timeline_cli.py`

- [ ] **Step 1: Create the session branch**

```bash
git checkout -b session/062-prism-labyrinth
git status
```

Expected: switched to a new branch, working tree clean except for the Atlas→Prism rename + memory work from the prep turn (those are already committed if you're starting fresh; if not, commit them first as a separate commit).

- [ ] **Step 2: Scaffold three empty test files**

```bash
touch ares/dialectic/tests/visualization/test_cycle_trace.py
touch ares/dialectic/tests/visualization/test_cycle_trace_builder.py
touch ares/dialectic/tests/visualization/test_build_cycle_timeline_cli.py
```

- [ ] **Step 3: Verify pytest discovers them (and collects 0)**

```bash
pytest ares/dialectic/tests/visualization/test_cycle_trace.py ares/dialectic/tests/visualization/test_cycle_trace_builder.py ares/dialectic/tests/visualization/test_build_cycle_timeline_cli.py -v --collect-only
```

Expected: `collected 0 items` for each — confirms pytest sees the files.

- [ ] **Step 4: Commit scaffolding**

```bash
git add ares/dialectic/tests/visualization/test_cycle_trace.py ares/dialectic/tests/visualization/test_cycle_trace_builder.py ares/dialectic/tests/visualization/test_build_cycle_timeline_cli.py
git commit -m "chore(prism): scaffold Phase A test files for cycle trace v2 pipeline"
```

---

### Task A2: CycleSnapshot dataclass + invariants

**Files:**
- Create: `ares/dialectic/visualization/cycle_trace.py`
- Test: `ares/dialectic/tests/visualization/test_cycle_trace.py`

- [ ] **Step 1: Write failing tests for `CycleSnapshot`**

Add to `ares/dialectic/tests/visualization/test_cycle_trace.py`:

```python
import pytest
from ares.dialectic.visualization.cycle_trace import CycleSnapshot


def _valid_snapshot(**overrides):
    base = dict(
        architect_confidence=0.95,
        architect_cited_facts=("inj001-fact-001",),
        architect_message_type="hypothesis",
        skeptic_confidence=0.3,
        skeptic_cited_facts=("inj001-fact-001",),
        skeptic_message_type="rebuttal",
        skeptic_triggered_rules=(),
        oracle_outcome="threat_confirmed",
        oracle_confidence=0.95,
        oracle_supporting_facts=("inj001-fact-001",),
        final_outcome="threat_confirmed",
        final_confidence=0.95,
        pipeline="llm",
    )
    base.update(overrides)
    return CycleSnapshot(**base)


def test_cycle_snapshot_constructs_with_valid_values():
    snap = _valid_snapshot()
    assert snap.architect_confidence == 0.95
    assert snap.pipeline == "llm"


def test_cycle_snapshot_is_frozen():
    snap = _valid_snapshot()
    with pytest.raises((AttributeError, Exception)):
        snap.architect_confidence = 0.5  # type: ignore[misc]


def test_cycle_snapshot_rejects_confidence_below_zero():
    with pytest.raises(ValueError, match="architect_confidence"):
        _valid_snapshot(architect_confidence=-0.1)


def test_cycle_snapshot_rejects_confidence_above_one():
    with pytest.raises(ValueError, match="oracle_confidence"):
        _valid_snapshot(oracle_confidence=1.1)


def test_cycle_snapshot_rejects_invalid_pipeline():
    with pytest.raises(ValueError, match="pipeline"):
        _valid_snapshot(pipeline="bogus")


def test_cycle_snapshot_accepts_light_pipeline():
    snap = _valid_snapshot(pipeline="light")
    assert snap.pipeline == "light"


def test_cycle_snapshot_citations_are_tuples():
    snap = _valid_snapshot()
    assert isinstance(snap.architect_cited_facts, tuple)
    assert isinstance(snap.skeptic_cited_facts, tuple)
    assert isinstance(snap.oracle_supporting_facts, tuple)
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest ares/dialectic/tests/visualization/test_cycle_trace.py -v
```

Expected: ModuleNotFoundError on `from ares.dialectic.visualization.cycle_trace import CycleSnapshot`.

- [ ] **Step 3: Implement `CycleSnapshot`**

Create `ares/dialectic/visualization/cycle_trace.py`:

```python
"""v2 schema for the Prism (Labyrinth panel and beyond).

One CycleSnapshot per (pipeline, baseline-or-mutated) cycle. Four snapshots
per pair (baseline_llm, mutated_llm, baseline_light, mutated_light).
"""

from __future__ import annotations

from dataclasses import dataclass


_VALID_PIPELINES: frozenset[str] = frozenset({"llm", "light"})


@dataclass(frozen=True)
class CycleSnapshot:
    """Per-layer outputs of one pipeline cycle.

    Fields mirror the JSONL trace row (one row from
    ``data/paper_3/leakage_runs/<run_id>/traces.jsonl``).
    """

    architect_confidence: float
    architect_cited_facts: tuple[str, ...]
    architect_message_type: str
    skeptic_confidence: float
    skeptic_cited_facts: tuple[str, ...]
    skeptic_message_type: str
    skeptic_triggered_rules: tuple[str, ...]
    oracle_outcome: str
    oracle_confidence: float
    oracle_supporting_facts: tuple[str, ...]
    final_outcome: str
    final_confidence: float
    pipeline: str  # "llm" or "light"

    def __post_init__(self) -> None:
        for name in (
            "architect_confidence",
            "skeptic_confidence",
            "oracle_confidence",
            "final_confidence",
        ):
            value = getattr(self, name)
            if not 0.0 <= value <= 1.0:
                raise ValueError(
                    f"{name} must be in [0.0, 1.0]; got {value}"
                )
        if self.pipeline not in _VALID_PIPELINES:
            raise ValueError(
                f"pipeline must be one of {sorted(_VALID_PIPELINES)}; "
                f"got {self.pipeline!r}"
            )
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest ares/dialectic/tests/visualization/test_cycle_trace.py -v
```

Expected: 7 passed.

- [ ] **Step 5: Commit**

```bash
git add ares/dialectic/visualization/cycle_trace.py ares/dialectic/tests/visualization/test_cycle_trace.py
git commit -m "feat(prism): CycleSnapshot dataclass with confidence + pipeline invariants"
```

---

### Task A3: PairTrace dataclass + invariants

**Files:**
- Modify: `ares/dialectic/visualization/cycle_trace.py`
- Modify: `ares/dialectic/tests/visualization/test_cycle_trace.py`

- [ ] **Step 1: Write failing tests for `PairTrace`**

Append to `ares/dialectic/tests/visualization/test_cycle_trace.py`:

```python
from ares.dialectic.visualization.cycle_trace import PairTrace


def _valid_pair_trace(**overrides):
    snap_llm_b = _valid_snapshot(pipeline="llm")
    snap_llm_m = _valid_snapshot(pipeline="llm")
    snap_light_b = _valid_snapshot(pipeline="light")
    snap_light_m = _valid_snapshot(pipeline="light")
    base = dict(
        pair_index=0,
        scenario_id="INJ-001",
        operator="framing_prefix_v1",
        baseline_llm=snap_llm_b,
        mutated_llm=snap_llm_m,
        baseline_light=snap_light_b,
        mutated_light=snap_light_m,
        narrow_leakage=False,
        broad_leakage=False,
        first_diverging_layer="None",
        llm_architect_bits=(False, False, False, False),
        llm_skeptic_bits=(False, False, False, False),
        llm_oracle_bits=(False, False, False, False),
        llm_final_bits=(False, False, False, False),
    )
    base.update(overrides)
    return PairTrace(**base)


def test_pair_trace_constructs_with_valid_values():
    pair = _valid_pair_trace()
    assert pair.scenario_id == "INJ-001"
    assert pair.operator == "framing_prefix_v1"


def test_pair_trace_is_frozen():
    pair = _valid_pair_trace()
    with pytest.raises((AttributeError, Exception)):
        pair.pair_index = 99  # type: ignore[misc]


def test_pair_trace_rejects_negative_pair_index():
    with pytest.raises(ValueError, match="pair_index"):
        _valid_pair_trace(pair_index=-1)


def test_pair_trace_rejects_empty_scenario_id():
    with pytest.raises(ValueError, match="scenario_id"):
        _valid_pair_trace(scenario_id="")


def test_pair_trace_rejects_empty_operator():
    with pytest.raises(ValueError, match="operator"):
        _valid_pair_trace(operator="")


def test_pair_trace_rejects_invalid_diverging_layer():
    with pytest.raises(ValueError, match="first_diverging_layer"):
        _valid_pair_trace(first_diverging_layer="bogus")


def test_pair_trace_accepts_all_valid_diverging_layers():
    for layer in ("Architect", "Skeptic", "Oracle", "Final", "None"):
        pair = _valid_pair_trace(first_diverging_layer=layer)
        assert pair.first_diverging_layer == layer


def test_pair_trace_rejects_leakage_bits_wrong_arity():
    with pytest.raises(ValueError, match="llm_architect_bits"):
        _valid_pair_trace(llm_architect_bits=(False, False, False))  # 3 bits


def test_pair_trace_rejects_non_bool_in_leakage_bits():
    with pytest.raises(TypeError, match="llm_oracle_bits"):
        _valid_pair_trace(llm_oracle_bits=(False, False, 1, False))  # int 1, not bool


def test_pair_trace_allows_missing_light_pipeline():
    pair = _valid_pair_trace(baseline_light=None, mutated_light=None)
    assert pair.baseline_light is None
    assert pair.mutated_light is None


def test_pair_trace_requires_at_least_one_complete_pipeline():
    with pytest.raises(ValueError, match="at least one"):
        _valid_pair_trace(
            baseline_llm=None,
            mutated_llm=None,
            baseline_light=None,
            mutated_light=None,
        )


def test_pair_trace_rejects_half_pipeline():
    with pytest.raises(ValueError, match="at least one"):
        _valid_pair_trace(
            baseline_llm=None,  # llm half-set
            baseline_light=None,
            mutated_light=None,
        )
```

- [ ] **Step 2: Run to verify failure**

```bash
pytest ares/dialectic/tests/visualization/test_cycle_trace.py -v
```

Expected: ImportError on `PairTrace`.

- [ ] **Step 3: Implement `PairTrace`**

Append to `ares/dialectic/visualization/cycle_trace.py`:

```python
_VALID_DIVERGING_LAYERS: frozenset[str] = frozenset(
    {"Architect", "Skeptic", "Oracle", "Final", "None"}
)


@dataclass(frozen=True)
class PairTrace:
    """One (scenario, operator) pair, packaged for renderer consumption.

    Both LLM and light pipelines are included when available. At least one
    complete pipeline pair (baseline + mutated) must exist. Per-layer
    leakage bits are populated from the LLM pipeline only (light pipeline
    leakage is reported via narrow_leakage / broad_leakage flags).
    """

    pair_index: int
    scenario_id: str
    operator: str
    baseline_llm: CycleSnapshot | None
    mutated_llm: CycleSnapshot | None
    baseline_light: CycleSnapshot | None
    mutated_light: CycleSnapshot | None
    narrow_leakage: bool
    broad_leakage: bool
    first_diverging_layer: str
    llm_architect_bits: tuple[bool, bool, bool, bool]
    llm_skeptic_bits: tuple[bool, bool, bool, bool]
    llm_oracle_bits: tuple[bool, bool, bool, bool]
    llm_final_bits: tuple[bool, bool, bool, bool]

    def __post_init__(self) -> None:
        if self.pair_index < 0:
            raise ValueError(
                f"pair_index must be >= 0; got {self.pair_index}"
            )
        if not self.scenario_id:
            raise ValueError("scenario_id must be non-empty")
        if not self.operator:
            raise ValueError("operator must be non-empty")
        if self.first_diverging_layer not in _VALID_DIVERGING_LAYERS:
            raise ValueError(
                f"first_diverging_layer must be one of "
                f"{sorted(_VALID_DIVERGING_LAYERS)}; "
                f"got {self.first_diverging_layer!r}"
            )

        has_llm = self.baseline_llm is not None and self.mutated_llm is not None
        has_light = (
            self.baseline_light is not None and self.mutated_light is not None
        )
        if not (has_llm or has_light):
            raise ValueError(
                f"pair {self.pair_index} "
                f"({self.scenario_id}/{self.operator}) must have at least "
                "one complete pipeline pair (both baseline and mutated)"
            )

        for name in (
            "llm_architect_bits",
            "llm_skeptic_bits",
            "llm_oracle_bits",
            "llm_final_bits",
        ):
            bits = getattr(self, name)
            if len(bits) != 4:
                raise ValueError(
                    f"{name} must have exactly 4 bits; got {len(bits)}"
                )
            for b in bits:
                if not isinstance(b, bool):
                    raise TypeError(
                        f"{name} elements must be bool; got "
                        f"{type(b).__name__}"
                    )
```

- [ ] **Step 4: Run tests**

```bash
pytest ares/dialectic/tests/visualization/test_cycle_trace.py -v
```

Expected: 19 passed (7 from A2 + 12 new).

- [ ] **Step 5: Commit**

```bash
git add ares/dialectic/visualization/cycle_trace.py ares/dialectic/tests/visualization/test_cycle_trace.py
git commit -m "feat(prism): PairTrace dataclass with at-least-one-pipeline invariant"
```

---

### Task A4: CycleTimelineV2 wrapper + JSON serializer

**Files:**
- Modify: `ares/dialectic/visualization/cycle_trace.py`
- Modify: `ares/dialectic/tests/visualization/test_cycle_trace.py`

- [ ] **Step 1: Write failing tests for `CycleTimelineV2` + serializer**

Append to `ares/dialectic/tests/visualization/test_cycle_trace.py`:

```python
import json
from ares.dialectic.visualization.cycle_trace import (
    CycleTimelineV2,
    cycle_timeline_to_json,
)


def test_cycle_timeline_v2_constructs():
    pair = _valid_pair_trace()
    timeline = CycleTimelineV2(
        schema_version="v2",
        run_id="20260510-193950-f401a8",
        operators=("framing_prefix_v1",),
        pairs=(pair,),
    )
    assert timeline.schema_version == "v2"
    assert len(timeline.pairs) == 1


def test_cycle_timeline_v2_rejects_wrong_schema_version():
    pair = _valid_pair_trace()
    with pytest.raises(ValueError, match="schema_version"):
        CycleTimelineV2(
            schema_version="v1",
            run_id="run-id",
            operators=("op",),
            pairs=(pair,),
        )


def test_cycle_timeline_v2_rejects_empty_pairs():
    with pytest.raises(ValueError, match="pairs"):
        CycleTimelineV2(
            schema_version="v2",
            run_id="run-id",
            operators=("op",),
            pairs=(),
        )


def test_cycle_timeline_v2_rejects_empty_run_id():
    pair = _valid_pair_trace()
    with pytest.raises(ValueError, match="run_id"):
        CycleTimelineV2(
            schema_version="v2",
            run_id="",
            operators=("op",),
            pairs=(pair,),
        )


def test_cycle_timeline_to_json_round_trip():
    pair = _valid_pair_trace()
    timeline = CycleTimelineV2(
        schema_version="v2",
        run_id="run-id",
        operators=("framing_prefix_v1",),
        pairs=(pair,),
    )
    payload = json.loads(cycle_timeline_to_json(timeline))
    assert payload["schema_version"] == "v2"
    assert payload["run_id"] == "run-id"
    assert payload["operators"] == ["framing_prefix_v1"]
    assert len(payload["pairs"]) == 1
    assert payload["pairs"][0]["scenario_id"] == "INJ-001"
    assert payload["pairs"][0]["baseline_llm"]["architect_confidence"] == 0.95
    assert payload["pairs"][0]["llm_skeptic_bits"] == [False, False, False, False]


def test_cycle_timeline_to_json_is_deterministic():
    pair = _valid_pair_trace()
    timeline = CycleTimelineV2(
        schema_version="v2",
        run_id="run-id",
        operators=("op-a", "op-b"),
        pairs=(pair,),
    )
    a = cycle_timeline_to_json(timeline)
    b = cycle_timeline_to_json(timeline)
    assert a == b


def test_cycle_timeline_to_json_serializes_null_pipelines():
    pair = _valid_pair_trace(baseline_light=None, mutated_light=None)
    timeline = CycleTimelineV2(
        schema_version="v2",
        run_id="run-id",
        operators=("op",),
        pairs=(pair,),
    )
    payload = json.loads(cycle_timeline_to_json(timeline))
    assert payload["pairs"][0]["baseline_light"] is None
    assert payload["pairs"][0]["mutated_light"] is None
```

- [ ] **Step 2: Run to verify failure**

```bash
pytest ares/dialectic/tests/visualization/test_cycle_trace.py -v
```

Expected: ImportError on `CycleTimelineV2` and `cycle_timeline_to_json`.

- [ ] **Step 3: Implement `CycleTimelineV2` + serializer**

Append to `ares/dialectic/visualization/cycle_trace.py`:

```python
import json


@dataclass(frozen=True)
class CycleTimelineV2:
    """Top-level v2 timeline. One document per measurement run."""

    schema_version: str
    run_id: str
    operators: tuple[str, ...]
    pairs: tuple[PairTrace, ...]

    def __post_init__(self) -> None:
        if self.schema_version != "v2":
            raise ValueError(
                f"schema_version must be 'v2'; got {self.schema_version!r}"
            )
        if not self.run_id:
            raise ValueError("run_id must be non-empty")
        if not self.pairs:
            raise ValueError("pairs must be non-empty")


def _snapshot_to_dict(snap: CycleSnapshot | None) -> dict | None:
    if snap is None:
        return None
    return {
        "architect_confidence": snap.architect_confidence,
        "architect_cited_facts": list(snap.architect_cited_facts),
        "architect_message_type": snap.architect_message_type,
        "skeptic_confidence": snap.skeptic_confidence,
        "skeptic_cited_facts": list(snap.skeptic_cited_facts),
        "skeptic_message_type": snap.skeptic_message_type,
        "skeptic_triggered_rules": list(snap.skeptic_triggered_rules),
        "oracle_outcome": snap.oracle_outcome,
        "oracle_confidence": snap.oracle_confidence,
        "oracle_supporting_facts": list(snap.oracle_supporting_facts),
        "final_outcome": snap.final_outcome,
        "final_confidence": snap.final_confidence,
        "pipeline": snap.pipeline,
    }


def _pair_to_dict(pair: PairTrace) -> dict:
    return {
        "pair_index": pair.pair_index,
        "scenario_id": pair.scenario_id,
        "operator": pair.operator,
        "baseline_llm": _snapshot_to_dict(pair.baseline_llm),
        "mutated_llm": _snapshot_to_dict(pair.mutated_llm),
        "baseline_light": _snapshot_to_dict(pair.baseline_light),
        "mutated_light": _snapshot_to_dict(pair.mutated_light),
        "narrow_leakage": pair.narrow_leakage,
        "broad_leakage": pair.broad_leakage,
        "first_diverging_layer": pair.first_diverging_layer,
        "llm_architect_bits": list(pair.llm_architect_bits),
        "llm_skeptic_bits": list(pair.llm_skeptic_bits),
        "llm_oracle_bits": list(pair.llm_oracle_bits),
        "llm_final_bits": list(pair.llm_final_bits),
    }


def cycle_timeline_to_json(timeline: CycleTimelineV2) -> str:
    """Serialize a CycleTimelineV2 to deterministic JSON (sorted keys)."""
    payload = {
        "schema_version": timeline.schema_version,
        "run_id": timeline.run_id,
        "operators": list(timeline.operators),
        "pairs": [_pair_to_dict(p) for p in timeline.pairs],
    }
    return json.dumps(payload, indent=2, sort_keys=True)
```

- [ ] **Step 4: Run tests**

```bash
pytest ares/dialectic/tests/visualization/test_cycle_trace.py -v
```

Expected: 26 passed.

- [ ] **Step 5: Commit**

```bash
git add ares/dialectic/visualization/cycle_trace.py ares/dialectic/tests/visualization/test_cycle_trace.py
git commit -m "feat(prism): CycleTimelineV2 + deterministic JSON serializer"
```

---

### Task A5: Builder — load JSONL and assemble PairTraces

**Files:**
- Create: `ares/dialectic/visualization/cycle_trace_builder.py`
- Test: `ares/dialectic/tests/visualization/test_cycle_trace_builder.py`

- [ ] **Step 1: Write failing tests with synthetic data**

Add to `ares/dialectic/tests/visualization/test_cycle_trace_builder.py`:

```python
import json
from pathlib import Path

import pytest

from ares.dialectic.visualization.cycle_trace_builder import build_cycle_timeline
from ares.dialectic.visualization.cycle_trace import CycleTimelineV2


def _row(
    *,
    scenario_id: str,
    operator: str | None,
    pipeline: str,
    pair_index: int,
    is_baseline: bool,
    architect_facts=("f1", "f2"),
    architect_conf=0.95,
    skeptic_facts=("f1",),
    skeptic_conf=0.3,
    oracle_facts=("f1", "f2"),
    oracle_outcome="threat_confirmed",
    final_outcome="threat_confirmed",
) -> dict:
    cycle_kind = "baseline" if is_baseline else "mutated"
    op_part = "" if operator is None else f"-{operator}"
    return {
        "cycle_id": f"{cycle_kind}-{scenario_id}{op_part}-{pipeline}",
        "scenario_id": scenario_id,
        "operator_name": operator,
        "pair_index": pair_index,
        "is_baseline": is_baseline,
        "pipeline": pipeline,
        "architect_message_type": "hypothesis",
        "architect_confidence": architect_conf,
        "architect_cited_facts": list(architect_facts),
        "skeptic_message_type": "rebuttal",
        "skeptic_confidence": skeptic_conf,
        "skeptic_cited_facts": list(skeptic_facts),
        "skeptic_triggered_rules": [],
        "oracle_outcome": oracle_outcome,
        "oracle_confidence": 0.95,
        "oracle_supporting_facts": list(oracle_facts),
        "final_outcome": final_outcome,
        "final_confidence": 0.95,
        "cost_usd": 0.01,
        "tokens_in": 100,
        "tokens_out": 50,
        "elapsed_ms": 1000.0,
    }


def _write_jsonl(tmp_path: Path, rows: list[dict]) -> Path:
    p = tmp_path / "traces.jsonl"
    p.write_text(
        "\n".join(json.dumps(r, sort_keys=True) for r in rows) + "\n",
        encoding="utf-8",
    )
    return p


def test_build_cycle_timeline_returns_v2(tmp_path):
    rows = [
        _row(scenario_id="INJ-001", operator=None, pipeline="llm", pair_index=0, is_baseline=True),
        _row(scenario_id="INJ-001", operator="op-a", pipeline="llm", pair_index=0, is_baseline=False),
        _row(scenario_id="INJ-001", operator=None, pipeline="light", pair_index=0, is_baseline=True),
        _row(scenario_id="INJ-001", operator="op-a", pipeline="light", pair_index=0, is_baseline=False),
    ]
    timeline = build_cycle_timeline(_write_jsonl(tmp_path, rows), run_id="r1")
    assert isinstance(timeline, CycleTimelineV2)
    assert timeline.schema_version == "v2"
    assert timeline.run_id == "r1"


def test_build_cycle_timeline_emits_one_pair_per_operator(tmp_path):
    rows = [
        _row(scenario_id="INJ-001", operator=None, pipeline="llm", pair_index=0, is_baseline=True),
        _row(scenario_id="INJ-001", operator="op-a", pipeline="llm", pair_index=0, is_baseline=False),
        _row(scenario_id="INJ-001", operator="op-b", pipeline="llm", pair_index=1, is_baseline=False),
        _row(scenario_id="INJ-001", operator=None, pipeline="light", pair_index=0, is_baseline=True),
        _row(scenario_id="INJ-001", operator="op-a", pipeline="light", pair_index=0, is_baseline=False),
        _row(scenario_id="INJ-001", operator="op-b", pipeline="light", pair_index=1, is_baseline=False),
    ]
    timeline = build_cycle_timeline(_write_jsonl(tmp_path, rows), run_id="r1")
    operators = {p.operator for p in timeline.pairs}
    assert operators == {"op-a", "op-b"}
    assert len(timeline.pairs) == 2


def test_build_cycle_timeline_skips_baseline_only_groups(tmp_path):
    rows = [
        _row(scenario_id="INJ-001", operator=None, pipeline="llm", pair_index=0, is_baseline=True),
    ]
    with pytest.raises(ValueError, match="No pairs"):
        build_cycle_timeline(_write_jsonl(tmp_path, rows), run_id="r1")


def test_build_cycle_timeline_detects_citation_drift(tmp_path):
    rows = [
        _row(scenario_id="INJ-001", operator=None, pipeline="llm", pair_index=0, is_baseline=True,
             architect_facts=("f1", "f2", "f3")),
        _row(scenario_id="INJ-001", operator="op-a", pipeline="llm", pair_index=0, is_baseline=False,
             architect_facts=("f1", "f2")),  # f3 dropped
        _row(scenario_id="INJ-001", operator=None, pipeline="light", pair_index=0, is_baseline=True),
        _row(scenario_id="INJ-001", operator="op-a", pipeline="light", pair_index=0, is_baseline=False),
    ]
    timeline = build_cycle_timeline(_write_jsonl(tmp_path, rows), run_id="r1")
    pair = timeline.pairs[0]
    # bit index 2 = cited_facts_changed
    assert pair.llm_architect_bits[2] is True


def test_build_cycle_timeline_no_drift_means_all_bits_false(tmp_path):
    rows = [
        _row(scenario_id="INJ-001", operator=None, pipeline="llm", pair_index=0, is_baseline=True),
        _row(scenario_id="INJ-001", operator="op-a", pipeline="llm", pair_index=0, is_baseline=False),
        _row(scenario_id="INJ-001", operator=None, pipeline="light", pair_index=0, is_baseline=True),
        _row(scenario_id="INJ-001", operator="op-a", pipeline="light", pair_index=0, is_baseline=False),
    ]
    timeline = build_cycle_timeline(_write_jsonl(tmp_path, rows), run_id="r1")
    pair = timeline.pairs[0]
    assert pair.llm_architect_bits == (False, False, False, False)
    assert pair.llm_skeptic_bits == (False, False, False, False)
    assert pair.llm_oracle_bits == (False, False, False, False)
    assert pair.llm_final_bits == (False, False, False, False)


def test_build_cycle_timeline_orders_operators_deterministically(tmp_path):
    # Mix order in input; output should be sorted.
    rows = [
        _row(scenario_id="INJ-001", operator=None, pipeline="llm", pair_index=0, is_baseline=True),
        _row(scenario_id="INJ-001", operator="zeta", pipeline="llm", pair_index=2, is_baseline=False),
        _row(scenario_id="INJ-001", operator="alpha", pipeline="llm", pair_index=0, is_baseline=False),
        _row(scenario_id="INJ-001", operator=None, pipeline="light", pair_index=0, is_baseline=True),
        _row(scenario_id="INJ-001", operator="zeta", pipeline="light", pair_index=2, is_baseline=False),
        _row(scenario_id="INJ-001", operator="alpha", pipeline="light", pair_index=0, is_baseline=False),
    ]
    timeline = build_cycle_timeline(_write_jsonl(tmp_path, rows), run_id="r1")
    assert timeline.operators == ("alpha", "zeta")


def test_build_cycle_timeline_raises_on_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        build_cycle_timeline(tmp_path / "does_not_exist.jsonl", run_id="r1")
```

- [ ] **Step 2: Run to verify failure**

```bash
pytest ares/dialectic/tests/visualization/test_cycle_trace_builder.py -v
```

Expected: ImportError on `build_cycle_timeline`.

- [ ] **Step 3: Implement builder**

Create `ares/dialectic/visualization/cycle_trace_builder.py`:

```python
"""Build CycleTimelineV2 documents from Session 059-style traces.jsonl.

Reuses ``compute_pair_leakage`` from ``ares.dialectic.measurement.leakage_runner``
so per-layer leakage bits agree with the canonical Phase 7 measurement
primitives. JSONL loading is replicated here (small) rather than imported
from v1 ``data_loader.py``, per the ARES "new files only" rule.
"""

from __future__ import annotations

import json
from pathlib import Path

from ares.dialectic.visualization.cycle_trace import (
    CycleSnapshot,
    CycleTimelineV2,
    PairTrace,
)


# Map from leakage_runner layer names to PairTrace's bit field names.
_LLM_LAYER_TO_FIELD: dict[str, str] = {
    "architect": "llm_architect_bits",
    "skeptic_llm": "llm_skeptic_bits",
    "oracle": "llm_oracle_bits",
    "final_verdict": "llm_final_bits",
}

# Title-case the runner's lowercase layer name for first_diverging_layer.
_LAYER_NAME_MAP: dict[str, str] = {
    "architect": "Architect",
    "skeptic_llm": "Skeptic",
    "light_skeptic": "Skeptic",
    "oracle": "Oracle",
    "final_verdict": "Final",
}


def _snapshot_from_row(row: dict) -> CycleSnapshot:
    return CycleSnapshot(
        architect_confidence=float(row["architect_confidence"]),
        architect_cited_facts=tuple(row["architect_cited_facts"]),
        architect_message_type=str(row["architect_message_type"]),
        skeptic_confidence=float(row["skeptic_confidence"]),
        skeptic_cited_facts=tuple(row["skeptic_cited_facts"]),
        skeptic_message_type=str(row["skeptic_message_type"]),
        skeptic_triggered_rules=tuple(row["skeptic_triggered_rules"]),
        oracle_outcome=str(row["oracle_outcome"]),
        oracle_confidence=float(row["oracle_confidence"]),
        oracle_supporting_facts=tuple(row["oracle_supporting_facts"]),
        final_outcome=str(row["final_outcome"]),
        final_confidence=float(row["final_confidence"]),
        pipeline=str(row["pipeline"]),
    )


def _trace_from_row(row: dict):
    """Convert a JSONL row to leakage_runner.CycleTrace for compute_pair_leakage."""
    from ares.dialectic.measurement.leakage_runner import CycleTrace  # noqa: PLC0415
    return CycleTrace(
        cycle_id=row["cycle_id"],
        scenario_id=row["scenario_id"],
        operator_name=row.get("operator_name"),
        pair_index=int(row["pair_index"]),
        is_baseline=bool(row["is_baseline"]),
        pipeline=row["pipeline"],
        architect_message_type=row["architect_message_type"],
        architect_confidence=float(row["architect_confidence"]),
        architect_cited_facts=tuple(row["architect_cited_facts"]),
        skeptic_message_type=row["skeptic_message_type"],
        skeptic_confidence=float(row["skeptic_confidence"]),
        skeptic_cited_facts=tuple(row["skeptic_cited_facts"]),
        skeptic_triggered_rules=tuple(row["skeptic_triggered_rules"]),
        oracle_outcome=row["oracle_outcome"],
        oracle_confidence=float(row["oracle_confidence"]),
        oracle_supporting_facts=tuple(row["oracle_supporting_facts"]),
        final_outcome=row["final_outcome"],
        final_confidence=float(row["final_confidence"]),
        cost_usd=float(row["cost_usd"]),
        tokens_in=int(row["tokens_in"]),
        tokens_out=int(row["tokens_out"]),
        elapsed_ms=float(row["elapsed_ms"]),
    )


def build_cycle_timeline(traces_path: Path, run_id: str) -> CycleTimelineV2:
    """Read traces.jsonl, assemble CycleTimelineV2.

    Raises:
        FileNotFoundError: traces_path missing.
        ValueError: no (scenario, operator) pairs found.
    """
    from ares.dialectic.measurement.leakage_runner import compute_pair_leakage  # noqa: PLC0415

    if not traces_path.exists():
        raise FileNotFoundError(f"Traces file not found: {traces_path}")

    with traces_path.open("r", encoding="utf-8") as fh:
        rows = [json.loads(line) for line in fh if line.strip()]

    # Index: (scenario_id, operator_name|None) -> {pipeline: row}
    index: dict[tuple[str, str | None], dict[str, dict]] = {}
    for row in rows:
        key = (row["scenario_id"], row.get("operator_name"))
        index.setdefault(key, {})[row["pipeline"]] = row

    pair_traces: list[PairTrace] = []
    seen_operators: set[str] = set()

    for (scenario_id, operator_name), pipelines in index.items():
        if operator_name is None:
            continue  # baseline group
        baseline_key = (scenario_id, None)
        if baseline_key not in index:
            continue
        baseline_pipelines = index[baseline_key]
        seen_operators.add(operator_name)

        baseline_llm_row = baseline_pipelines.get("llm")
        mutated_llm_row = pipelines.get("llm")
        baseline_light_row = baseline_pipelines.get("light")
        mutated_light_row = pipelines.get("light")

        baseline_llm = (
            _snapshot_from_row(baseline_llm_row) if baseline_llm_row else None
        )
        mutated_llm = (
            _snapshot_from_row(mutated_llm_row) if mutated_llm_row else None
        )
        baseline_light = (
            _snapshot_from_row(baseline_light_row)
            if baseline_light_row else None
        )
        mutated_light = (
            _snapshot_from_row(mutated_light_row)
            if mutated_light_row else None
        )

        # Compute LLM leakage for per-layer bit fields
        llm_bits_by_field: dict[str, tuple[bool, bool, bool, bool]] = {
            name: (False, False, False, False)
            for name in _LLM_LAYER_TO_FIELD.values()
        }
        llm_first_diverging: str | None = None
        if baseline_llm_row and mutated_llm_row:
            llm_record = compute_pair_leakage(
                baseline=_trace_from_row(baseline_llm_row),
                mutated=_trace_from_row(mutated_llm_row),
                pair_index=int(mutated_llm_row["pair_index"]),
            )
            for leakage in llm_record.leakages:
                field = _LLM_LAYER_TO_FIELD.get(leakage.layer)
                if field:
                    llm_bits_by_field[field] = leakage.bits
            llm_first_diverging = llm_record.first_diverging_layer

        # Compute light pipeline leakage for narrow/broad + first_diverging fallback
        narrow = False
        broad = False
        light_first_diverging: str | None = None
        if baseline_light_row and mutated_light_row:
            light_record = compute_pair_leakage(
                baseline=_trace_from_row(baseline_light_row),
                mutated=_trace_from_row(mutated_light_row),
                pair_index=int(mutated_light_row["pair_index"]),
            )
            narrow = light_record.kill_fires_narrow
            broad = light_record.kill_fires_brief_broad
            light_first_diverging = light_record.first_diverging_layer

        # first_diverging_layer: prefer LLM pipeline, fallback to light
        diverging_raw = llm_first_diverging or light_first_diverging
        first_diverging = (
            _LAYER_NAME_MAP.get(diverging_raw, "None")
            if diverging_raw else "None"
        )

        pair_traces.append(
            PairTrace(
                pair_index=int(mutated_llm_row["pair_index"])
                if mutated_llm_row else int(mutated_light_row["pair_index"]),
                scenario_id=scenario_id,
                operator=operator_name,
                baseline_llm=baseline_llm,
                mutated_llm=mutated_llm,
                baseline_light=baseline_light,
                mutated_light=mutated_light,
                narrow_leakage=narrow,
                broad_leakage=broad,
                first_diverging_layer=first_diverging,
                llm_architect_bits=llm_bits_by_field["llm_architect_bits"],
                llm_skeptic_bits=llm_bits_by_field["llm_skeptic_bits"],
                llm_oracle_bits=llm_bits_by_field["llm_oracle_bits"],
                llm_final_bits=llm_bits_by_field["llm_final_bits"],
            )
        )

    if not pair_traces:
        raise ValueError(
            f"No pairs assembled from {traces_path} — file contains only "
            "baseline rows or no mutated rows reference any baseline."
        )

    # Sort pairs deterministically by (pair_index, scenario_id, operator)
    pair_traces.sort(key=lambda p: (p.pair_index, p.scenario_id, p.operator))

    return CycleTimelineV2(
        schema_version="v2",
        run_id=run_id,
        operators=tuple(sorted(seen_operators)),
        pairs=tuple(pair_traces),
    )
```

- [ ] **Step 4: Run tests**

```bash
pytest ares/dialectic/tests/visualization/test_cycle_trace_builder.py -v
```

Expected: 7 passed.

- [ ] **Step 5: Commit**

```bash
git add ares/dialectic/visualization/cycle_trace_builder.py ares/dialectic/tests/visualization/test_cycle_trace_builder.py
git commit -m "feat(prism): cycle_trace_builder loads JSONL and assembles PairTraces"
```

---

### Task A6: CLI entry point

**Files:**
- Create: `ares/dialectic/visualization/build_cycle_timeline.py`
- Test: `ares/dialectic/tests/visualization/test_build_cycle_timeline_cli.py`

- [ ] **Step 1: Write failing CLI tests**

Add to `ares/dialectic/tests/visualization/test_build_cycle_timeline_cli.py`:

```python
import json
import subprocess
import sys
from pathlib import Path

import pytest


def _row(**overrides) -> dict:
    base = dict(
        cycle_id="cid",
        scenario_id="INJ-001",
        operator_name=None,
        pair_index=0,
        is_baseline=True,
        pipeline="llm",
        architect_message_type="hypothesis",
        architect_confidence=0.95,
        architect_cited_facts=["f1"],
        skeptic_message_type="rebuttal",
        skeptic_confidence=0.3,
        skeptic_cited_facts=["f1"],
        skeptic_triggered_rules=[],
        oracle_outcome="threat_confirmed",
        oracle_confidence=0.95,
        oracle_supporting_facts=["f1"],
        final_outcome="threat_confirmed",
        final_confidence=0.95,
        cost_usd=0.01,
        tokens_in=100,
        tokens_out=50,
        elapsed_ms=1000.0,
    )
    base.update(overrides)
    return base


def _write_min_jsonl(tmp_path: Path) -> Path:
    rows = [
        _row(),  # baseline llm
        _row(operator_name="op-a", is_baseline=False, cycle_id="m-a-llm"),
        _row(pipeline="light", cycle_id="b-light"),
        _row(operator_name="op-a", is_baseline=False, pipeline="light",
             cycle_id="m-a-light"),
    ]
    p = tmp_path / "traces.jsonl"
    p.write_text(
        "\n".join(json.dumps(r, sort_keys=True) for r in rows) + "\n",
        encoding="utf-8",
    )
    return p


def test_cli_writes_json(tmp_path):
    traces = _write_min_jsonl(tmp_path)
    out = tmp_path / "prism-timeline.json"
    result = subprocess.run(
        [
            sys.executable, "-m",
            "ares.dialectic.visualization.build_cycle_timeline",
            "--traces", str(traces),
            "--output", str(out),
            "--run-id", "test-run",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert out.exists()
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "v2"
    assert payload["run_id"] == "test-run"


def test_cli_reports_pair_count(tmp_path):
    traces = _write_min_jsonl(tmp_path)
    out = tmp_path / "prism-timeline.json"
    result = subprocess.run(
        [
            sys.executable, "-m",
            "ares.dialectic.visualization.build_cycle_timeline",
            "--traces", str(traces),
            "--output", str(out),
            "--run-id", "test-run",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert "1 pair" in result.stdout


def test_cli_exits_nonzero_on_missing_file(tmp_path):
    out = tmp_path / "prism-timeline.json"
    result = subprocess.run(
        [
            sys.executable, "-m",
            "ares.dialectic.visualization.build_cycle_timeline",
            "--traces", str(tmp_path / "missing.jsonl"),
            "--output", str(out),
            "--run-id", "test-run",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1
    assert "not found" in result.stderr.lower() or "no such" in result.stderr.lower()


def test_cli_creates_output_parent_dir(tmp_path):
    traces = _write_min_jsonl(tmp_path)
    out = tmp_path / "nested" / "subdir" / "prism-timeline.json"
    result = subprocess.run(
        [
            sys.executable, "-m",
            "ares.dialectic.visualization.build_cycle_timeline",
            "--traces", str(traces),
            "--output", str(out),
            "--run-id", "test-run",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert out.exists()
```

- [ ] **Step 2: Run to verify failure**

```bash
pytest ares/dialectic/tests/visualization/test_build_cycle_timeline_cli.py -v
```

Expected: ImportError / module not found on `build_cycle_timeline`.

- [ ] **Step 3: Implement CLI**

Create `ares/dialectic/visualization/build_cycle_timeline.py`:

```python
"""CLI: read leakage-run traces.jsonl, write prism-timeline.json (v2).

Usage:
    python -m ares.dialectic.visualization.build_cycle_timeline \\
        --traces data/paper_3/leakage_runs/20260510-193950-f401a8/traces.jsonl \\
        --output docs/marketing/prism-timeline.json \\
        --run-id 20260510-193950-f401a8
"""

import argparse
import sys
from pathlib import Path

from ares.dialectic.visualization.cycle_trace import cycle_timeline_to_json
from ares.dialectic.visualization.cycle_trace_builder import build_cycle_timeline


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--traces", required=True, type=Path,
        help="Path to traces.jsonl from a leakage run",
    )
    parser.add_argument(
        "--output", required=True, type=Path,
        help="Where to write the v2 timeline JSON",
    )
    parser.add_argument(
        "--run-id", required=True, type=str,
        help="Run identifier embedded in the JSON",
    )
    args = parser.parse_args()

    try:
        timeline = build_cycle_timeline(args.traces, run_id=args.run_id)
    except FileNotFoundError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(cycle_timeline_to_json(timeline), encoding="utf-8")
    print(
        f"Wrote {len(timeline.pairs)} pair{'s' if len(timeline.pairs) != 1 else ''} "
        f"to {args.output}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 4: Run tests**

```bash
pytest ares/dialectic/tests/visualization/test_build_cycle_timeline_cli.py -v
```

Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
git add ares/dialectic/visualization/build_cycle_timeline.py ares/dialectic/tests/visualization/test_build_cycle_timeline_cli.py
git commit -m "feat(prism): build_cycle_timeline CLI emits prism-timeline.json"
```

---

### Task A7: Generate the real timeline from Session 059 traces

**Files:**
- Create: `docs/marketing/prism-timeline.json` (CLI output, will be tracked in git)

- [ ] **Step 1: Run the CLI against Session 059 data**

```bash
python -m ares.dialectic.visualization.build_cycle_timeline \
    --traces data/paper_3/leakage_runs/20260510-193950-f401a8/traces.jsonl \
    --output docs/marketing/prism-timeline.json \
    --run-id 20260510-193950-f401a8
```

Expected stdout: `Wrote 98 pairs to docs/marketing/prism-timeline.json`

- [ ] **Step 2: Spot-check the JSON structure**

```bash
python -c "
import json
data = json.loads(open('docs/marketing/prism-timeline.json').read())
print('schema_version:', data['schema_version'])
print('run_id:', data['run_id'])
print('operators:', data['operators'])
print('pair count:', len(data['pairs']))
print('first pair keys:', list(data['pairs'][0].keys()))
print('first pair scenario:', data['pairs'][0]['scenario_id'])
print('first pair operator:', data['pairs'][0]['operator'])
print('first pair broad_leakage:', data['pairs'][0]['broad_leakage'])
drift_pairs = [p for p in data['pairs'] if p['broad_leakage']]
print('broad-leakage pair count:', len(drift_pairs))
for p in drift_pairs:
    print('  ', p['scenario_id'], p['operator'], 'diverging:', p['first_diverging_layer'])
"
```

Expected (matching Session 059 documented findings — 97 held / 1 drifted):
```
schema_version: v2
run_id: 20260510-193950-f401a8
operators: ['framing_prefix_v1', 'framing_suffix_v1', 'synonym_substitution_conservative_v2']
pair count: 98
first pair keys: ['baseline_light', 'baseline_llm', 'broad_leakage', 'first_diverging_layer', ...]
broad-leakage pair count: 1
   INJ-001 framing_suffix_v1 diverging: Oracle
```

If the count is anything other than 98 pairs or the drift pair isn't INJ-001 / framing_suffix_v1 / Oracle, STOP. The schema is wrong for the renderer. Investigate before proceeding.

- [ ] **Step 3: Commit the generated JSON**

```bash
git add docs/marketing/prism-timeline.json
git commit -m "feat(prism): generate prism-timeline.json from Session 059 traces (98 pairs)"
```

---

### Task A8: Full Python regression test

- [ ] **Step 1: Run the entire test suite**

```bash
pytest --tb=short
```

Expected: ≥3,647 tests collected (Session 060 floor) + 30 new tests = 3,677 collected, 0 failures.

- [ ] **Step 2: Update CLAUDE.md test-count floor**

Modify `CLAUDE.md` line where it says `**Test count floor (passing):** 3,673` (or current value):

Use Edit tool:
- old_string: `**Test count floor (passing):** 3,673`
- new_string: `**Test count floor (passing):** [actual collected count from Step 1]`

- [ ] **Step 3: Commit**

```bash
git add CLAUDE.md
git commit -m "chore(claude-md): bump test floor for Phase A Prism v2 pipeline"
```

---

## Phase B — Production HTML scaffold + Panel 1 (Labyrinth) renderer

### Task B1: Page chrome (HTML + CSS)

**Files:**
- Create: `E:/Skyframe Innovations Website/skyframe-main/assets/ares/prism.html`

- [ ] **Step 1: Create the scaffold**

Create `E:/Skyframe Innovations Website/skyframe-main/assets/ares/prism.html`:

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>ARES Prism — Session 059 Resilience Interior View</title>
  <link rel="preconnect" href="https://cdnjs.cloudflare.com">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">

  <style>
    :root {
      --bg: #0a0a0a;
      --panel-bg: #050505;
      --border: #1a1a1a;
      --text: #e2e8f0;
      --muted: #94a3b8;
      --subtle: #64748b;
      --accent-red: #ef4444;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font-family: 'Inter', -apple-system, sans-serif;
      min-height: 100vh;
    }
    header {
      padding: 28px 32px 16px;
      border-bottom: 1px solid var(--border);
      text-align: center;
    }
    header .tag {
      display: inline-block;
      font-family: 'JetBrains Mono', monospace;
      font-size: 11px;
      letter-spacing: 2px;
      text-transform: uppercase;
      color: var(--subtle);
      margin-bottom: 8px;
    }
    header h1 {
      margin: 0;
      font-size: 26px;
      font-weight: 500;
    }
    header .subtitle {
      margin: 8px auto 0;
      color: var(--muted);
      font-size: 13px;
      max-width: 600px;
    }
    main {
      display: flex;
      flex-direction: column;
      padding: 24px 28px;
      gap: 22px;
      max-width: 50vw;
      width: 100%;
      margin: 0 auto;
    }
    @media (max-width: 1100px) { main { max-width: 92vw; } }
    .panel {
      background: var(--panel-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      overflow: hidden;
    }
    .panel-header {
      padding: 14px 20px 10px;
      border-bottom: 1px solid #141414;
    }
    .panel-tag {
      font-family: 'JetBrains Mono', monospace;
      font-size: 10px;
      letter-spacing: 1.5px;
      text-transform: uppercase;
      color: var(--subtle);
    }
    .panel-title {
      margin: 2px 0 0;
      font-size: 15px;
      font-weight: 500;
    }
    .panel-subtitle {
      margin: 4px 0 0;
      color: var(--muted);
      font-size: 12px;
      line-height: 1.45;
    }
    .panel-canvas {
      width: 100%;
      height: 620px;
      position: relative;
      cursor: grab;
    }
    .panel-canvas:active { cursor: grabbing; }
    .panel-legend {
      padding: 10px 20px 12px;
      border-top: 1px solid #141414;
      display: flex;
      gap: 16px;
      flex-wrap: wrap;
      font-size: 10px;
      color: var(--muted);
      font-family: 'JetBrains Mono', monospace;
      letter-spacing: 0.5px;
      text-transform: uppercase;
    }
    .legend-item { display: inline-flex; align-items: center; gap: 6px; }
    .legend-dot {
      width: 8px; height: 8px; border-radius: 50%;
      display: inline-block;
    }
    .stats {
      position: absolute;
      top: 10px; right: 14px;
      font-family: 'JetBrains Mono', monospace;
      font-size: 10px;
      color: var(--muted);
      line-height: 1.7;
      letter-spacing: 0.3px;
      text-align: right;
      pointer-events: none;
      mix-blend-mode: difference;
    }
    .stats .value { color: var(--text); }
    .stats .drift { color: var(--accent-red); }
    .controls {
      padding: 14px 20px;
      border-top: 1px solid #141414;
      display: flex;
      align-items: center;
      gap: 16px;
      flex-wrap: wrap;
    }
    .controls label {
      font-family: 'JetBrains Mono', monospace;
      font-size: 10px;
      letter-spacing: 1px;
      text-transform: uppercase;
      color: var(--subtle);
    }
    .controls input[type=range] {
      flex: 1;
      min-width: 200px;
    }
    .controls select {
      background: transparent;
      border: 1px solid #475569;
      color: var(--text);
      padding: 6px 10px;
      font-family: 'JetBrains Mono', monospace;
      font-size: 11px;
      border-radius: 4px;
    }
    footer {
      padding: 18px 32px 24px;
      color: var(--subtle);
      font-size: 11px;
      font-family: 'JetBrains Mono', monospace;
      letter-spacing: 0.5px;
      text-align: center;
      border-top: 1px solid var(--border);
    }
    #loading {
      position: absolute;
      top: 50%; left: 50%;
      transform: translate(-50%, -50%);
      color: var(--subtle);
      font-family: 'JetBrains Mono', monospace;
      font-size: 13px;
      letter-spacing: 1.5px;
    }
  </style>
</head>
<body>
  <header>
    <span class="tag">ARES Prism &middot; Panel 1</span>
    <h1>The Labyrinth</h1>
    <p class="subtitle">98 cycles drop breadcrumbs through the six agent chambers. The drifted cycle deviates at the Oracle layer (red, off-cluster). Session 059 — broad-reading dataset.</p>
  </header>

  <main>
    <div class="panel">
      <div class="panel-header">
        <span class="panel-tag">Panel 1 &middot; chamber chain</span>
        <h2 class="panel-title">The Labyrinth</h2>
        <p class="panel-subtitle">Drag to orbit. Use the scrubber to step through cycles. Click a breadcrumb to focus its path.</p>
      </div>
      <div id="panel1-canvas" class="panel-canvas">
        <div id="loading">LOADING TIMELINE…</div>
        <div class="stats">
          cycles: <span class="value" id="stat-cycles">0/98</span><br>
          held: <span class="value" id="stat-held">0</span><br>
          drifted: <span class="drift" id="stat-drift">0</span>
        </div>
      </div>
      <div class="controls">
        <label for="scrubber">Cycle</label>
        <input type="range" id="scrubber" min="0" max="97" value="97">
        <label for="operator-dial">Operator</label>
        <select id="operator-dial">
          <option value="all">All operators</option>
        </select>
      </div>
      <div class="panel-legend">
        <span class="legend-item"><span class="legend-dot" style="background:#06b6d4"></span>Input</span>
        <span class="legend-item"><span class="legend-dot" style="background:#f59e0b"></span>Architect (LLM)</span>
        <span class="legend-item"><span class="legend-dot" style="background:#22c55e"></span>Firewall</span>
        <span class="legend-item"><span class="legend-dot" style="background:#f59e0b"></span>Skeptic (LLM)</span>
        <span class="legend-item"><span class="legend-dot" style="background:#10b981"></span>Oracle (Python)</span>
        <span class="legend-item"><span class="legend-dot" style="background:#a78bfa"></span>Verdict</span>
        <span class="legend-item"><span class="legend-dot" style="background:#ef4444"></span>Drift moment</span>
      </div>
    </div>
  </main>

  <footer>
    ARES Phase 7 &middot; Session 059 broad-reading dataset &middot; deterministic + reproducible &middot; <a href="pinscreen.html" style="color: var(--muted);">view the Pinscreen</a>
  </footer>

  <script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/three@0.128.0/examples/js/controls/OrbitControls.js"></script>
  <script>
    // Renderer code added in subsequent tasks.
    console.log('Prism Panel 1 scaffold loaded; THREE version:', THREE.REVISION);
  </script>
</body>
</html>
```

- [ ] **Step 2: Manual browser verification**

```bash
# From the skyframe-main repo root:
cd "E:/Skyframe Innovations Website/skyframe-main"
python -m http.server 8000
# In another terminal or browser, navigate to:
# http://localhost:8000/assets/ares/prism.html
```

Expected in browser:
- Dark page with "ARES Prism · Panel 1" header
- Subtitle visible
- Panel header, empty canvas area (with "LOADING TIMELINE…" text), scrubber, operator dial, legend
- Footer with link to pinscreen.html

Open browser DevTools Console — expected: `Prism Panel 1 scaffold loaded; THREE version: 128`. If THREE is undefined, the CDN URL is wrong; re-check.

- [ ] **Step 3: Commit (skyframe-main repo)**

```bash
cd "E:/Skyframe Innovations Website/skyframe-main"
git add assets/ares/prism.html
git commit -m "feat(prism): page scaffold for Panel 1 (Labyrinth) — r128 classic"
```

---

### Task B2: Copy prism-timeline.json to skyframe-main and load it

**Files:**
- Create: `E:/Skyframe Innovations Website/skyframe-main/assets/ares/prism-timeline.json` (copy)
- Modify: `E:/Skyframe Innovations Website/skyframe-main/assets/ares/prism.html`

- [ ] **Step 1: Copy the generated JSON**

```bash
cp "C:/ares-phase-zero/docs/marketing/prism-timeline.json" "E:/Skyframe Innovations Website/skyframe-main/assets/ares/prism-timeline.json"
```

- [ ] **Step 2: Wire up data loading in prism.html**

Replace the placeholder `<script>` block (the one with `console.log('Prism Panel 1 scaffold loaded'...)`) with:

```html
  <script>
    'use strict';

    const STATE = {
      timeline: null,
      pairs: [],
      activeOperator: 'all',
      activeCycleIndex: null,  // null = show all
      visiblePairs: [],
    };

    async function loadTimeline() {
      const res = await fetch('prism-timeline.json');
      if (!res.ok) throw new Error(`Failed to load timeline: ${res.status}`);
      const data = await res.json();
      STATE.timeline = data;
      STATE.pairs = data.pairs;
      return data;
    }

    function populateOperatorDial() {
      const sel = document.getElementById('operator-dial');
      STATE.timeline.operators.forEach((op) => {
        const opt = document.createElement('option');
        opt.value = op;
        opt.textContent = op;
        sel.appendChild(opt);
      });
    }

    function recomputeVisible() {
      STATE.visiblePairs = STATE.pairs.filter((p) =>
        STATE.activeOperator === 'all' || p.operator === STATE.activeOperator
      );
      updateStats();
    }

    function updateStats() {
      const total = STATE.visiblePairs.length;
      const drifted = STATE.visiblePairs.filter((p) => p.broad_leakage).length;
      const held = total - drifted;
      document.getElementById('stat-cycles').textContent = `${total}/${STATE.pairs.length}`;
      document.getElementById('stat-held').textContent = String(held);
      document.getElementById('stat-drift').textContent = String(drifted);
    }

    async function init() {
      try {
        await loadTimeline();
        populateOperatorDial();
        recomputeVisible();
        document.getElementById('loading').style.display = 'none';
        console.log('Prism timeline loaded:', STATE.pairs.length, 'pairs');
      } catch (err) {
        document.getElementById('loading').textContent = 'FAILED TO LOAD: ' + err.message;
        console.error(err);
      }
    }

    init();
  </script>
```

- [ ] **Step 3: Manual browser verification**

Refresh `http://localhost:8000/assets/ares/prism.html`. Expected:
- "LOADING TIMELINE…" message disappears
- Stats overlay shows `cycles: 98/98`, `held: 97`, `drifted: 1`
- Console: `Prism timeline loaded: 98 pairs`
- Operator dial shows 4 options: All operators, framing_prefix_v1, framing_suffix_v1, synonym_substitution_conservative_v2

If stats show `0/0` or load fails, check that prism-timeline.json is in the right directory and the dev server is serving it (open `http://localhost:8000/assets/ares/prism-timeline.json` directly).

- [ ] **Step 4: Commit (skyframe-main repo)**

```bash
cd "E:/Skyframe Innovations Website/skyframe-main"
git add assets/ares/prism.html assets/ares/prism-timeline.json
git commit -m "feat(prism): load prism-timeline.json + populate stats"
```

---

### Task B3: Three.js scene init + 6 chamber geometry

**Files:**
- Modify: `E:/Skyframe Innovations Website/skyframe-main/assets/ares/prism.html`

- [ ] **Step 1: Add scene-init and chamber-geometry code**

Insert this code inside the `<script>` block, AFTER the `STATE` object declaration and BEFORE `loadTimeline()`:

```javascript
    // ---- Scene constants ----
    const CHAMBERS = [
      { id: 'input',     label: 'INPUT',     color: 0x06b6d4 },
      { id: 'architect', label: 'ARCHITECT', color: 0xf59e0b },
      { id: 'firewall',  label: 'FIREWALL',  color: 0x22c55e },
      { id: 'skeptic',   label: 'SKEPTIC',   color: 0xf59e0b },
      { id: 'oracle',    label: 'ORACLE',    color: 0x10b981 },
      { id: 'verdict',   label: 'VERDICT',   color: 0xa78bfa },
    ];
    const CHAMBER_SPACING = 8.0;
    const CHAMBER_RADIUS = 1.6;
    const PIN_RADIUS = 0.10;
    const DRIFT_COLOR = 0xef4444;
    const HELD_COLOR = 0x64748b;

    const SCENE = {
      scene: null,
      camera: null,
      renderer: null,
      controls: null,
      chamberMeshes: [],
      pinGroup: null,
      driftMarkers: [],
      container: null,
    };

    function initScene() {
      SCENE.container = document.getElementById('panel1-canvas');
      const w = SCENE.container.clientWidth;
      const h = SCENE.container.clientHeight;

      SCENE.scene = new THREE.Scene();
      SCENE.scene.background = new THREE.Color(0x0a0a0a);
      SCENE.scene.fog = new THREE.Fog(0x0a0a0a, 30, 80);

      SCENE.camera = new THREE.PerspectiveCamera(40, w / h, 0.1, 200);
      SCENE.camera.position.set(0, 8, 32);
      SCENE.camera.lookAt(0, 0, 0);

      SCENE.renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
      SCENE.renderer.setPixelRatio(window.devicePixelRatio || 1);
      SCENE.renderer.setSize(w, h);
      SCENE.container.appendChild(SCENE.renderer.domElement);

      // Ambient + key light
      SCENE.scene.add(new THREE.AmbientLight(0xffffff, 0.35));
      const keyLight = new THREE.DirectionalLight(0xffffff, 0.7);
      keyLight.position.set(8, 12, 8);
      SCENE.scene.add(keyLight);

      // Orbit controls
      SCENE.controls = new THREE.OrbitControls(SCENE.camera, SCENE.renderer.domElement);
      SCENE.controls.enableDamping = true;
      SCENE.controls.dampingFactor = 0.08;
      SCENE.controls.enableZoom = false;  // we wire custom smooth zoom in B6
      SCENE.controls.autoRotate = true;
      SCENE.controls.autoRotateSpeed = 0.35;

      // Build chambers
      buildChambers();

      // Empty pin group, populated in B4
      SCENE.pinGroup = new THREE.Group();
      SCENE.scene.add(SCENE.pinGroup);

      window.addEventListener('resize', onResize);
      animate();
    }

    function buildChambers() {
      const totalSpan = (CHAMBERS.length - 1) * CHAMBER_SPACING;
      const startX = -totalSpan / 2;

      CHAMBERS.forEach((chamber, i) => {
        const x = startX + i * CHAMBER_SPACING;
        const geo = new THREE.SphereGeometry(CHAMBER_RADIUS, 32, 24);
        const mat = new THREE.MeshStandardMaterial({
          color: chamber.color,
          emissive: chamber.color,
          emissiveIntensity: 0.18,
          roughness: 0.6,
          metalness: 0.1,
          transparent: true,
          opacity: 0.85,
        });
        const mesh = new THREE.Mesh(geo, mat);
        mesh.position.set(x, 0, 0);
        mesh.userData = { chamber: chamber.id };
        SCENE.scene.add(mesh);
        SCENE.chamberMeshes.push(mesh);

        // Connecting tube to the next chamber
        if (i < CHAMBERS.length - 1) {
          const nextX = startX + (i + 1) * CHAMBER_SPACING;
          const tubeLen = nextX - x - 2 * CHAMBER_RADIUS;
          const tubeGeo = new THREE.CylinderGeometry(0.04, 0.04, tubeLen, 12);
          const tubeMat = new THREE.MeshBasicMaterial({ color: 0x1f2937 });
          const tube = new THREE.Mesh(tubeGeo, tubeMat);
          tube.position.set(x + CHAMBER_RADIUS + tubeLen / 2, 0, 0);
          tube.rotation.z = Math.PI / 2;
          SCENE.scene.add(tube);
        }
      });
    }

    function onResize() {
      if (!SCENE.renderer) return;
      const w = SCENE.container.clientWidth;
      const h = SCENE.container.clientHeight;
      SCENE.camera.aspect = w / h;
      SCENE.camera.updateProjectionMatrix();
      SCENE.renderer.setSize(w, h);
    }

    function animate() {
      requestAnimationFrame(animate);
      if (SCENE.controls) SCENE.controls.update();
      if (SCENE.renderer && SCENE.scene && SCENE.camera) {
        SCENE.renderer.render(SCENE.scene, SCENE.camera);
      }
    }
```

Then modify the `init()` function — add `initScene()` call after `recomputeVisible()`:

```javascript
    async function init() {
      try {
        await loadTimeline();
        populateOperatorDial();
        recomputeVisible();
        document.getElementById('loading').style.display = 'none';
        initScene();
        console.log('Prism timeline loaded:', STATE.pairs.length, 'pairs');
      } catch (err) {
        document.getElementById('loading').textContent = 'FAILED TO LOAD: ' + err.message;
        console.error(err);
      }
    }
```

- [ ] **Step 2: Manual browser verification**

Refresh page. Expected:
- Six glowing spheres in a row across the canvas (cyan, amber, green, amber, emerald, purple)
- Dark grey thin tubes connecting them
- Camera slowly rotating around the scene (auto-rotate)
- Drag to orbit works (cursor changes to grabbing)
- Console: no errors

If chambers appear as black dots or are missing colors, check the MeshStandardMaterial parameters — emissiveIntensity should make them visibly luminous.

- [ ] **Step 3: Commit**

```bash
cd "E:/Skyframe Innovations Website/skyframe-main"
git add assets/ares/prism.html
git commit -m "feat(prism): six-chamber Labyrinth geometry with auto-rotate + orbit"
```

---

### Task B4: Render cycle breadcrumbs (one pin per cycle per chamber)

**Files:**
- Modify: `E:/Skyframe Innovations Website/skyframe-main/assets/ares/prism.html`

- [ ] **Step 1: Add breadcrumb rendering**

Add to the script, after `buildChambers()`:

```javascript
    // Vertical stagger for cycles so they don't pile on top of each other.
    function cycleYOffset(pairIndex) {
      // Spiral cycles slightly around each chamber so all 98 are visible.
      const ring = Math.floor(pairIndex / 14);  // 14 cycles per ring
      const slot = pairIndex % 14;
      const angle = (slot / 14) * Math.PI * 2;
      const ringRadius = 0.6 + ring * 0.35;
      return {
        y: Math.sin(angle) * ringRadius,
        z: Math.cos(angle) * ringRadius,
      };
    }

    function renderBreadcrumbs() {
      // Clear previous pins
      while (SCENE.pinGroup.children.length > 0) {
        const child = SCENE.pinGroup.children.pop();
        child.geometry.dispose();
        child.material.dispose();
      }
      SCENE.driftMarkers = [];

      const totalSpan = (CHAMBERS.length - 1) * CHAMBER_SPACING;
      const startX = -totalSpan / 2;

      STATE.visiblePairs.forEach((pair, visibleIdx) => {
        // Use pair_index for spiral position so the same cycle always sits in
        // the same slot regardless of operator filter.
        const offset = cycleYOffset(pair.pair_index);

        CHAMBERS.forEach((chamber, chamberIdx) => {
          const x = startX + chamberIdx * CHAMBER_SPACING + CHAMBER_RADIUS + 0.25;

          // Determine if this chamber is the drift point.
          const isDriftChamber = pair.broad_leakage && (
            (chamber.id === 'architect' && pair.first_diverging_layer === 'Architect') ||
            (chamber.id === 'skeptic'   && pair.first_diverging_layer === 'Skeptic') ||
            (chamber.id === 'oracle'    && pair.first_diverging_layer === 'Oracle') ||
            (chamber.id === 'verdict'   && pair.first_diverging_layer === 'Final')
          );

          const color = isDriftChamber ? DRIFT_COLOR : HELD_COLOR;
          const intensity = isDriftChamber ? 1.5 : 0.4;
          const radius = isDriftChamber ? PIN_RADIUS * 1.8 : PIN_RADIUS;

          const geo = new THREE.SphereGeometry(radius, 12, 8);
          const mat = new THREE.MeshStandardMaterial({
            color: color,
            emissive: color,
            emissiveIntensity: intensity,
            transparent: true,
            opacity: isDriftChamber ? 1.0 : 0.7,
          });
          const pin = new THREE.Mesh(geo, mat);
          pin.position.set(x + offset.z * 0.4, offset.y, offset.z);
          pin.userData = {
            pairIndex: pair.pair_index,
            chamberId: chamber.id,
            isDrift: isDriftChamber,
          };
          SCENE.pinGroup.add(pin);

          if (isDriftChamber) SCENE.driftMarkers.push(pin);
        });
      });
    }
```

Then modify `recomputeVisible()` to call `renderBreadcrumbs()` after updating stats — append this line to the function:

```javascript
    function recomputeVisible() {
      STATE.visiblePairs = STATE.pairs.filter((p) =>
        STATE.activeOperator === 'all' || p.operator === STATE.activeOperator
      );
      updateStats();
      if (SCENE.pinGroup) renderBreadcrumbs();
    }
```

And modify `init()` so the first render happens AFTER `initScene`:

```javascript
    async function init() {
      try {
        await loadTimeline();
        populateOperatorDial();
        document.getElementById('loading').style.display = 'none';
        initScene();
        recomputeVisible();  // calls renderBreadcrumbs() now that SCENE is ready
        console.log('Prism timeline loaded:', STATE.pairs.length, 'pairs');
      } catch (err) {
        document.getElementById('loading').textContent = 'FAILED TO LOAD: ' + err.message;
        console.error(err);
      }
    }
```

- [ ] **Step 2: Manual browser verification**

Refresh page. Expected:
- 6 chambers visible
- Around each chamber, a halo/cloud of small grey pins (~98 pins per chamber)
- At the Oracle chamber, ONE red pin stands out (slightly larger, glowing)
- Stats: `cycles: 98/98`, `held: 97`, `drifted: 1`
- Auto-rotate reveals the structure
- Total pins on screen: 98 cycles × 6 chambers = 588 pins, all positioned around their chamber's vicinity

If the red pin appears at the wrong chamber, check `first_diverging_layer` in the JSON — it should be `"Oracle"` for INJ-001 framing_suffix_v1.

- [ ] **Step 3: Commit**

```bash
cd "E:/Skyframe Innovations Website/skyframe-main"
git add assets/ares/prism.html
git commit -m "feat(prism): cycle breadcrumbs with drift highlight at Oracle chamber"
```

---

### Task B5: Custom smooth zoom

**Files:**
- Modify: `E:/Skyframe Innovations Website/skyframe-main/assets/ares/prism.html`

- [ ] **Step 1: Add zoom logic**

Add this code in the script block, after `animate()`:

```javascript
    // Step-based smooth zoom — ignores deltaY magnitude.
    // Each wheel notch = ~6% step, lerped over ~10 frames.
    const ZOOM_STEP = 0.94;        // 6% closer per notch in
    const ZOOM_FRAMES = 10;
    let zoomTarget = 32.0;          // matches initial camera Z
    let zoomCurrent = 32.0;

    function onWheel(event) {
      event.preventDefault();
      if (event.deltaY > 0) {
        zoomTarget = Math.min(zoomTarget / ZOOM_STEP, 80.0);  // zoom out
      } else if (event.deltaY < 0) {
        zoomTarget = Math.max(zoomTarget * ZOOM_STEP, 12.0);  // zoom in
      }
    }

    function lerpZoom() {
      const alpha = 1.0 / ZOOM_FRAMES;
      zoomCurrent += (zoomTarget - zoomCurrent) * alpha;
      if (SCENE.camera) {
        const dir = new THREE.Vector3();
        SCENE.camera.getWorldDirection(dir);
        dir.multiplyScalar(-1);
        SCENE.camera.position.copy(dir.multiplyScalar(zoomCurrent));
      }
    }
```

Modify `animate()` to call `lerpZoom()`:

```javascript
    function animate() {
      requestAnimationFrame(animate);
      lerpZoom();
      if (SCENE.controls) SCENE.controls.update();
      if (SCENE.renderer && SCENE.scene && SCENE.camera) {
        SCENE.renderer.render(SCENE.scene, SCENE.camera);
      }
    }
```

Wire the wheel listener inside `initScene()`, after `SCENE.controls` is created:

```javascript
      SCENE.renderer.domElement.addEventListener('wheel', onWheel, { passive: false });
```

- [ ] **Step 2: Manual browser verification**

Refresh. Test scroll wheel:
- One scroll notch in → camera glides closer over ~10 frames (~166ms at 60fps), feels smooth
- One scroll notch out → camera glides further, same easing
- No jitter, no deltaY-magnitude sensitivity (laptop trackpad and external mouse both feel the same)
- Trying to zoom past max-in or max-out: camera stops at bound

- [ ] **Step 3: Commit**

```bash
cd "E:/Skyframe Innovations Website/skyframe-main"
git add assets/ares/prism.html
git commit -m "feat(prism): custom step-based smooth zoom"
```

---

## Phase C — Full-kit interactivity at Panel 1 scope

### Task C1: Time scrubber

**Files:**
- Modify: `E:/Skyframe Innovations Website/skyframe-main/assets/ares/prism.html`

- [ ] **Step 1: Wire the scrubber**

The scaffold already has `<input type="range" id="scrubber" min="0" max="97" value="97">`. Add this code after `renderBreadcrumbs()`:

```javascript
    function applyScrubber(maxCycleIndex) {
      // maxCycleIndex = highest pair_index to show; 97 = all.
      STATE.pinGroup_visible_max = maxCycleIndex;
      SCENE.pinGroup.children.forEach((pin) => {
        const visible = pin.userData.pairIndex <= maxCycleIndex;
        pin.visible = visible;
      });
      // Update stats to reflect what's visible.
      const visibleCycles = STATE.visiblePairs.filter(
        (p) => p.pair_index <= maxCycleIndex
      );
      const drifted = visibleCycles.filter((p) => p.broad_leakage).length;
      document.getElementById('stat-cycles').textContent =
        `${visibleCycles.length}/${STATE.pairs.length}`;
      document.getElementById('stat-held').textContent =
        String(visibleCycles.length - drifted);
      document.getElementById('stat-drift').textContent = String(drifted);
    }

    function wireScrubber() {
      const scr = document.getElementById('scrubber');
      scr.max = String(STATE.pairs.length - 1);
      scr.value = String(STATE.pairs.length - 1);
      scr.addEventListener('input', () => {
        applyScrubber(parseInt(scr.value, 10));
      });
    }
```

Modify `init()` to call `wireScrubber()` after `recomputeVisible()`:

```javascript
    async function init() {
      try {
        await loadTimeline();
        populateOperatorDial();
        document.getElementById('loading').style.display = 'none';
        initScene();
        recomputeVisible();
        wireScrubber();
        console.log('Prism timeline loaded:', STATE.pairs.length, 'pairs');
      } catch (err) {
        document.getElementById('loading').textContent = 'FAILED TO LOAD: ' + err.message;
        console.error(err);
      }
    }
```

- [ ] **Step 2: Manual browser verification**

Refresh. Test scrubber:
- Slide all the way left → only `pair_index 0` shows (one cycle worth of pins, ~6 pins, no drift)
- Slide right slowly → more pins appear progressively
- All the way right → 588 pins visible, 1 drift visible
- Stats counter updates live as scrubber moves
- Auto-rotate keeps running while scrubber operates

- [ ] **Step 3: Commit**

```bash
cd "E:/Skyframe Innovations Website/skyframe-main"
git add assets/ares/prism.html
git commit -m "feat(prism): time scrubber reveals cycles progressively"
```

---

### Task C2: Click-to-focus on a cycle

**Files:**
- Modify: `E:/Skyframe Innovations Website/skyframe-main/assets/ares/prism.html`

- [ ] **Step 1: Add raycaster + click handler**

Add after `wireScrubber()`:

```javascript
    const RAYCASTER = new THREE.Raycaster();
    const POINTER = new THREE.Vector2();
    let focusedCycleIndex = null;

    function onCanvasClick(event) {
      const rect = SCENE.renderer.domElement.getBoundingClientRect();
      POINTER.x = ((event.clientX - rect.left) / rect.width) * 2 - 1;
      POINTER.y = -((event.clientY - rect.top) / rect.height) * 2 + 1;

      RAYCASTER.setFromCamera(POINTER, SCENE.camera);
      const intersects = RAYCASTER.intersectObjects(SCENE.pinGroup.children);
      if (intersects.length === 0) {
        clearFocus();
        return;
      }
      const hit = intersects[0].object;
      focusCycle(hit.userData.pairIndex);
    }

    function focusCycle(pairIndex) {
      focusedCycleIndex = pairIndex;
      SCENE.pinGroup.children.forEach((pin) => {
        if (pin.userData.pairIndex === pairIndex) {
          pin.material.opacity = 1.0;
          pin.material.emissiveIntensity = pin.userData.isDrift ? 2.0 : 1.4;
        } else {
          pin.material.opacity = 0.06;
          pin.material.emissiveIntensity = 0.1;
        }
      });
    }

    function clearFocus() {
      focusedCycleIndex = null;
      SCENE.pinGroup.children.forEach((pin) => {
        const isDrift = pin.userData.isDrift;
        pin.material.opacity = isDrift ? 1.0 : 0.7;
        pin.material.emissiveIntensity = isDrift ? 1.5 : 0.4;
      });
    }

    function wireClick() {
      SCENE.renderer.domElement.addEventListener('click', onCanvasClick);
    }
```

Modify `init()` to call `wireClick()`:

```javascript
    async function init() {
      try {
        await loadTimeline();
        populateOperatorDial();
        document.getElementById('loading').style.display = 'none';
        initScene();
        recomputeVisible();
        wireScrubber();
        wireClick();
        console.log('Prism timeline loaded:', STATE.pairs.length, 'pairs');
      } catch (err) {
        document.getElementById('loading').textContent = 'FAILED TO LOAD: ' + err.message;
        console.error(err);
      }
    }
```

- [ ] **Step 2: Manual browser verification**

Refresh. Test click-to-focus:
- Click on any pin → all other cycles fade to ~6% opacity, the clicked cycle's 6-pin chain stays bright
- Click on the red drift pin → the INJ-001 framing_suffix_v1 cycle is highlighted, its 6 pins (5 grey + 1 red at Oracle) bright, the rest faded
- Click on empty space → all pins return to normal opacity (clearFocus)
- Scrubber and operator dial still work while a cycle is focused

If pins don't respond to clicks, check that the canvas is receiving pointer events (the `.stats` overlay has `pointer-events: none` already).

- [ ] **Step 3: Commit**

```bash
cd "E:/Skyframe Innovations Website/skyframe-main"
git add assets/ares/prism.html
git commit -m "feat(prism): click-to-focus highlights one cycle's chamber chain"
```

---

### Task C3: Adversarial-pressure dial (operator filter)

**Files:**
- Modify: `E:/Skyframe Innovations Website/skyframe-main/assets/ares/prism.html`

- [ ] **Step 1: Wire the operator dial**

Add after `wireClick()`:

```javascript
    function wireOperatorDial() {
      const sel = document.getElementById('operator-dial');
      sel.addEventListener('change', () => {
        STATE.activeOperator = sel.value;
        clearFocus();
        recomputeVisible();
        // Re-apply scrubber max in case operator-filtered subset is smaller
        const scr = document.getElementById('scrubber');
        applyScrubber(parseInt(scr.value, 10));
      });
    }
```

Modify `init()` to call `wireOperatorDial()`:

```javascript
    async function init() {
      try {
        await loadTimeline();
        populateOperatorDial();
        document.getElementById('loading').style.display = 'none';
        initScene();
        recomputeVisible();
        wireScrubber();
        wireClick();
        wireOperatorDial();
        console.log('Prism timeline loaded:', STATE.pairs.length, 'pairs');
      } catch (err) {
        document.getElementById('loading').textContent = 'FAILED TO LOAD: ' + err.message;
        console.error(err);
      }
    }
```

- [ ] **Step 2: Manual browser verification**

Refresh. Test the dial:
- Default "All operators" → 98 cycles visible
- Switch to `framing_prefix_v1` → 33 cycles visible (no drift — all grey)
- Switch to `framing_suffix_v1` → 33 cycles visible, 1 red drift at Oracle (the INJ-001 case)
- Switch to `synonym_substitution_conservative_v2` → 32 cycles visible (no-op on 1)
- Stats counter updates: cycles N/98, held = N or N-1, drifted = 0 or 1
- Scrubber range adapts to the visible subset

- [ ] **Step 3: Commit**

```bash
cd "E:/Skyframe Innovations Website/skyframe-main"
git add assets/ares/prism.html
git commit -m "feat(prism): adversarial-pressure dial filters by operator"
```

---

## Phase D — Deployment + CTA

### Task D1: Add CTA link to ares.html

**Files:**
- Modify: `E:/Skyframe Innovations Website/skyframe-main/assets/ares/ares.html`

- [ ] **Step 1: Locate the existing Pinscreen CTA**

```bash
cd "E:/Skyframe Innovations Website/skyframe-main"
grep -n "pinscreen.html" assets/ares/ares.html
```

Expected: one or more lines referencing `pinscreen.html` (likely an `<a href>` in a CTA section).

- [ ] **Step 2: Add a sibling link to prism.html**

Use the Edit tool. Find the surrounding CTA block for `pinscreen.html` (likely something like `<a href="pinscreen.html" class="cta-button">View Pinscreen</a>` or similar — read the file first to confirm exact structure).

Read the file:
```bash
cat assets/ares/ares.html | grep -B 3 -A 3 "pinscreen.html"
```

Then add a second link with parallel styling immediately after the pinscreen link's closing `</a>`. The exact tag and class will depend on what the file shows — copy the structure of the pinscreen link verbatim, change `href="pinscreen.html"` to `href="prism.html"` and the link text to something like `View the Prism` or `Interior View`.

Example (adapt to actual file structure):
```html
<a href="pinscreen.html" class="cta-button">View the Pinscreen</a>
<a href="prism.html" class="cta-button">View the Prism</a>
```

- [ ] **Step 3: Manual browser verification**

```bash
# From skyframe-main, with the dev server still running:
# Navigate to http://localhost:8000/assets/ares/ares.html
```

Expected:
- The ares.html page renders normally
- Both CTAs visible side-by-side (or stacked, depending on layout)
- Clicking "Pinscreen" → loads pinscreen.html
- Clicking "Prism" → loads prism.html
- Both back-links from prism's footer return to ares.html or pinscreen.html as appropriate

- [ ] **Step 4: Commit**

```bash
cd "E:/Skyframe Innovations Website/skyframe-main"
git add assets/ares/ares.html
git commit -m "feat(ares): add second CTA link to the Prism (Panel 1: Labyrinth)"
```

---

### Task D2: End-to-end browser verification

**Files:** (none — verification only)

- [ ] **Step 1: Cold-load prism.html in a fresh tab**

Close the existing tab. Open a new tab, navigate to `http://localhost:8000/assets/ares/prism.html`. Watch carefully:

1. Page chrome loads first (header, panel scaffolding, controls, legend)
2. "LOADING TIMELINE…" placeholder visible briefly
3. Stats populate: `cycles: 98/98`, `held: 97`, `drifted: 1`
4. Six chambers appear with breadcrumbs around them
5. Auto-rotate starts within ~500ms
6. Console: `Prism timeline loaded: 98 pairs`

- [ ] **Step 2: Interactivity smoke test**

Run through all four interactivity surfaces:

1. **Drag-to-orbit:** Click + drag on canvas → camera orbits around the row of chambers smoothly
2. **Smooth zoom:** Scroll in 3 notches → camera glides closer; scroll out 3 notches → returns
3. **Scrubber:** Drag slider from right to left → pins disappear in reverse chronological order; drift pin disappears when scrubber passes its `pair_index`
4. **Operator dial:** Switch to `framing_suffix_v1` → only 33 pins visible, drift pin still red at Oracle
5. **Click-to-focus:** With dial back to "All operators", click on a pin → that cycle's full 6-chamber chain stays bright, others fade; click empty → restores

- [ ] **Step 3: Console hygiene check**

DevTools Console: expected zero red errors. Yellow warnings about deprecated features (rare in r128) are tolerable but note them.

- [ ] **Step 4: Cross-browser smoke (recommend: Chrome + Firefox)**

If Firefox is available: open `http://localhost:8000/assets/ares/prism.html` in Firefox. Same verification as Step 1–3. Three.js r128 should render identically.

- [ ] **Step 5: Manual record**

Take a screenshot of the working page with stats visible (`cycles: 98/98 · held: 97 · drifted: 1`). Save anywhere — the verification artifact is for your own confidence.

---

### Task D3: Push and deploy

**Files:** (none — deployment only)

- [ ] **Step 1: Push the skyframe-main branch**

```bash
cd "E:/Skyframe Innovations Website/skyframe-main"
git status         # confirm everything committed
git log --oneline -5   # confirm the commits are local + on main (or whatever Skyframe uses)
git push origin main
```

Expected: Netlify webhook fires; deployment begins. Auto-deploy typically takes 30–90 seconds.

- [ ] **Step 2: Verify live deployment**

Wait ~90 seconds, then navigate to the live URL:

```
https://[your-skyframe-domain]/assets/ares/prism.html
```

Expected: same behavior as local. Live JSON loads from the same relative path; stats populate; interactivity works.

If the JSON 404s on the live site, confirm `prism-timeline.json` is in the pushed commit (Netlify only serves what's in git):
```bash
git ls-tree HEAD assets/ares/prism-timeline.json
```

- [ ] **Step 3: Push the ARES repo branch**

```bash
cd "C:/ares-phase-zero"
git push -u origin session/062-prism-labyrinth
```

Then open a PR (or merge locally with squash if working solo per CLAUDE.md "squash merge after zero regressions confirmed"):

```bash
git checkout main
git merge --squash session/062-prism-labyrinth
git commit -m "Session 062: Prism Panel 1 (Labyrinth) + TimelineBuilder v2 (squash)"
git push origin main
```

- [ ] **Step 4: Update memory**

Update `C:/Users/danny/.claude/projects/C--ares-phase-zero/memory/project_prism_mockup_validated.md`:
- Change description from "production build is next ARES-VISION session" to "Panel 1 (Labyrinth) live; Panels 2–4 pending"
- Update the "How to apply" paragraph to point at the new plan-of-record (this file)

Update `CLAUDE.md`:
- Add Session 062 entry to the session timeline describing Panel 1 ship
- Add Prism module references to "Key Code Locations" section
- Bump test count floor to actual collected count after Phase A

```bash
cd "C:/ares-phase-zero"
git add CLAUDE.md
git commit -m "docs: CLAUDE.md Session 062 entry — Prism Panel 1 ships"
git push origin main
```

---

## Self-Review (run after writing the plan, before handing off to execution)

**1. Spec coverage:**
- [x] Schema spec-first: Tasks A2–A4
- [x] TimelineBuilder v2 pipeline: Tasks A5–A6
- [x] Generate real JSON: Task A7
- [x] Panel 1 (Labyrinth) renderer: Tasks B1–B5
- [x] Full-kit interactivity at Panel 1 scope (scrubber, click-focus, pressure dial): Tasks C1–C3
- [x] Second CTA in ares.html: Task D1
- [x] Deploy + verify: Tasks D2–D3

**2. Placeholder scan:** No "TBD", "fill in details", or generic "add error handling" patterns. Each Step has concrete code or commands.

**3. Type consistency:**
- `CycleSnapshot.architect_cited_facts` is `tuple[str, ...]` everywhere (schema + builder + JSON serializer uses `list(...)` to JSON-serialize the tuple).
- `PairTrace.llm_*_bits` is `tuple[bool, bool, bool, bool]` everywhere.
- `first_diverging_layer` strings are `"Architect" | "Skeptic" | "Oracle" | "Final" | "None"` — note the title-case mapping in `_LAYER_NAME_MAP` converts runner's lowercase to schema's title-case.

**4. ARES architectural constraints honored:**
- New files only (no v1 module modifications).
- Frozen dataclasses with `__post_init__` invariants throughout.
- Tests-first per task.
- Squash merge to main after zero regressions.

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-05-13-prism-labyrinth.md`. Two execution options:

**1. Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration.

**2. Inline Execution** — Execute tasks in this session using executing-plans, batch execution with checkpoints.

Which approach?
