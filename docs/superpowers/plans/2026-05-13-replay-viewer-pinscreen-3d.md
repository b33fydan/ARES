# ARES Replay Viewer (3D Pinscreen) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the 3D pinscreen replay viewer per the design spec — ship the ARES-VISION extension as the MVP, with a Python pipeline that produces a pre-baked `timeline.json` and a Three.js renderer that animates it.

**Architecture:** Two phases. Phase 1 (Python, `ares-phase-zero`) builds the data pipeline: `DataLoader → PinMapper → TimelineBuilder → pinscreen-timeline.json`. Phase 2 (TypeScript/JS, `skyframe-main`) builds the Three.js renderer and the section component that consumes the JSON. Phases are independent — Phase 1 produces a tested file artifact, Phase 2 consumes that artifact.

**Tech Stack:** Python 3.11 + pytest + frozen dataclasses (Phase 1); Three.js r160 + vanilla ES modules (Phase 2). Phase 2 stays framework-agnostic so it adapts cleanly to whatever skyframe-main uses at integration time.

**Reference:** `docs/superpowers/specs/2026-05-13-replay-viewer-pinscreen-3d-design.md`

---

## Phase 1: Python Pipeline (ares-phase-zero)

### Task 1: Create module skeleton

**Files:**
- Create: `ares/dialectic/visualization/__init__.py`
- Create: `ares/dialectic/tests/visualization/__init__.py`

- [ ] **Step 1: Create the visualization package directory**

```bash
mkdir -p ares/dialectic/visualization
mkdir -p ares/dialectic/tests/visualization
```

- [ ] **Step 2: Create empty `__init__.py` files**

```python
# ares/dialectic/visualization/__init__.py
"""3D Pinscreen replay viewer pipeline (Phase 7 / Paper 3)."""
```

```python
# ares/dialectic/tests/visualization/__init__.py
```

- [ ] **Step 3: Verify the package imports**

Run: `python -c "import ares.dialectic.visualization"`
Expected: no output, no error.

- [ ] **Step 4: Commit**

```bash
git add ares/dialectic/visualization/__init__.py ares/dialectic/tests/visualization/__init__.py
git commit -m "feat: scaffold ares.dialectic.visualization package"
```

---

### Task 2: PairRecord dataclass

**Files:**
- Create: `ares/dialectic/visualization/data_loader.py`
- Test: `ares/dialectic/tests/visualization/test_pair_record.py`

- [ ] **Step 1: Write the failing test**

```python
# ares/dialectic/tests/visualization/test_pair_record.py
import pytest
from ares.dialectic.visualization.data_loader import PairRecord


def test_pair_record_is_frozen():
    record = PairRecord(
        scenario_id="INJ-001",
        operator="framing_prefix_v1",
        narrow_leakage=False,
        broad_leakage=False,
        confidence_baseline=0.95,
        confidence_mutated=0.95,
        first_diverging_layer="None",
    )
    with pytest.raises(Exception):
        record.scenario_id = "INJ-002"


def test_pair_record_fields_required():
    with pytest.raises(TypeError):
        PairRecord()


def test_pair_record_first_diverging_layer_accepts_known_values():
    for layer in ("Architect", "Skeptic", "Oracle", "Final", "None"):
        record = PairRecord(
            scenario_id="INJ-001",
            operator="framing_prefix_v1",
            narrow_leakage=False,
            broad_leakage=False,
            confidence_baseline=0.95,
            confidence_mutated=0.95,
            first_diverging_layer=layer,
        )
        assert record.first_diverging_layer == layer
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest ares/dialectic/tests/visualization/test_pair_record.py -v`
Expected: 3 FAILS with `ImportError: cannot import name 'PairRecord'`.

- [ ] **Step 3: Implement PairRecord**

```python
# ares/dialectic/visualization/data_loader.py
"""Loads Session 059 leakage traces into PairRecord objects."""

from dataclasses import dataclass
from typing import Literal

DivergingLayer = Literal["Architect", "Skeptic", "Oracle", "Final", "None"]


@dataclass(frozen=True)
class PairRecord:
    """One paired-cycle outcome from a Session 059 leakage run."""

    scenario_id: str
    operator: str
    narrow_leakage: bool
    broad_leakage: bool
    confidence_baseline: float
    confidence_mutated: float
    first_diverging_layer: DivergingLayer
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest ares/dialectic/tests/visualization/test_pair_record.py -v`
Expected: 3 PASS.

- [ ] **Step 5: Commit**

```bash
git add ares/dialectic/visualization/data_loader.py ares/dialectic/tests/visualization/test_pair_record.py
git commit -m "feat: PairRecord frozen dataclass for visualization pipeline"
```

---

### Task 3: DataLoader.load_run()

**Files:**
- Modify: `ares/dialectic/visualization/data_loader.py`
- Test: `ares/dialectic/tests/visualization/test_data_loader.py`
- Fixture: `ares/dialectic/tests/visualization/fixtures/mini_traces.jsonl`

- [ ] **Step 1: Examine the real traces format**

Read `data/paper_3/leakage_runs/20260510-193950-f401a8/traces.jsonl` (first 5 lines). The implementer should also read `ares/dialectic/measurement/influence_leakage.py` and `ares/dialectic/measurement/leakage_runner.py` to understand:
- How baseline and mutated traces are paired (by `scenario_id` + `operator_name` + `pair_index`)
- How the 4-bit InfluenceLeakage vector is computed from a baseline/mutated trace pair
- Which pipeline rows (`pipeline: "llm"` vs `"light"`) are needed for narrow vs. broad leakage

Note from spec: **narrow_leakage** = Light Skeptic only; **broad_leakage** = Light + Oracle + Final. Reuse the existing `InfluenceLeakage` helpers — do not re-implement.

- [ ] **Step 2: Create a small fixture (synthetic 2-pair JSONL)**

```jsonl
{"scenario_id":"FIX-001","operator_name":null,"is_baseline":true,"pair_index":0,"pipeline":"llm","architect_confidence":0.9,"architect_cited_facts":["a","b"],"skeptic_confidence":0.3,"skeptic_cited_facts":["a","b"],"oracle_confidence":0.9,"oracle_outcome":"threat_confirmed","oracle_supporting_facts":["a","b"],"final_confidence":0.9,"final_outcome":"threat_confirmed","cycle_id":"baseline-FIX-001-llm","cost_usd":0.01,"elapsed_ms":1000,"tokens_in":100,"tokens_out":50,"architect_message_type":"hypothesis","skeptic_message_type":"rebuttal","skeptic_triggered_rules":[]}
{"scenario_id":"FIX-001","operator_name":"framing_prefix_v1","is_baseline":false,"pair_index":0,"pipeline":"llm","architect_confidence":0.9,"architect_cited_facts":["a","b"],"skeptic_confidence":0.3,"skeptic_cited_facts":["a","b"],"oracle_confidence":0.9,"oracle_outcome":"threat_confirmed","oracle_supporting_facts":["a","b"],"final_confidence":0.9,"final_outcome":"threat_confirmed","cycle_id":"mutated-FIX-001-framing_prefix_v1-llm","cost_usd":0.01,"elapsed_ms":1000,"tokens_in":100,"tokens_out":50,"architect_message_type":"hypothesis","skeptic_message_type":"rebuttal","skeptic_triggered_rules":[]}
{"scenario_id":"FIX-001","operator_name":null,"is_baseline":true,"pair_index":0,"pipeline":"light","architect_confidence":0.9,"architect_cited_facts":["a","b"],"skeptic_confidence":0.3,"skeptic_cited_facts":["a","b"],"oracle_confidence":0.9,"oracle_outcome":"threat_confirmed","oracle_supporting_facts":["a","b"],"final_confidence":0.9,"final_outcome":"threat_confirmed","cycle_id":"baseline-FIX-001-light","cost_usd":0,"elapsed_ms":50,"tokens_in":0,"tokens_out":0,"architect_message_type":"hypothesis","skeptic_message_type":"rebuttal","skeptic_triggered_rules":[]}
{"scenario_id":"FIX-001","operator_name":"framing_prefix_v1","is_baseline":false,"pair_index":0,"pipeline":"light","architect_confidence":0.9,"architect_cited_facts":["a","b"],"skeptic_confidence":0.3,"skeptic_cited_facts":["a","b"],"oracle_confidence":0.9,"oracle_outcome":"threat_confirmed","oracle_supporting_facts":["a","b","c"],"final_confidence":0.9,"final_outcome":"threat_confirmed","cycle_id":"mutated-FIX-001-framing_prefix_v1-light","cost_usd":0,"elapsed_ms":50,"tokens_in":0,"tokens_out":0,"architect_message_type":"hypothesis","skeptic_message_type":"rebuttal","skeptic_triggered_rules":[]}
```

The second mutated pair (light pipeline) has an extra fact in `oracle_supporting_facts` — this triggers a broad-reading leakage at the Oracle layer per the InfluenceLeakage definition.

- [ ] **Step 3: Write the failing test**

```python
# ares/dialectic/tests/visualization/test_data_loader.py
from pathlib import Path
import pytest
from ares.dialectic.visualization.data_loader import PairRecord, load_run

FIXTURE_DIR = Path(__file__).parent / "fixtures"


def test_load_run_returns_one_record_per_pair():
    records = load_run(FIXTURE_DIR / "mini_traces.jsonl")
    assert len(records) == 1
    assert isinstance(records[0], PairRecord)


def test_load_run_extracts_scenario_and_operator():
    records = load_run(FIXTURE_DIR / "mini_traces.jsonl")
    record = records[0]
    assert record.scenario_id == "FIX-001"
    assert record.operator == "framing_prefix_v1"


def test_load_run_detects_broad_leakage_from_oracle_citation_drift():
    records = load_run(FIXTURE_DIR / "mini_traces.jsonl")
    record = records[0]
    assert record.broad_leakage is True
    assert record.narrow_leakage is False


def test_load_run_extracts_confidence_values():
    records = load_run(FIXTURE_DIR / "mini_traces.jsonl")
    record = records[0]
    assert record.confidence_baseline == 0.9
    assert record.confidence_mutated == 0.9


def test_load_run_raises_on_missing_file():
    with pytest.raises(FileNotFoundError):
        load_run(FIXTURE_DIR / "does_not_exist.jsonl")
```

- [ ] **Step 4: Run test to verify it fails**

Run: `pytest ares/dialectic/tests/visualization/test_data_loader.py -v`
Expected: 5 FAILS with `ImportError: cannot import name 'load_run'`.

- [ ] **Step 5: Implement load_run**

```python
# Append to ares/dialectic/visualization/data_loader.py

import json
from pathlib import Path
from typing import List

from ares.dialectic.measurement.influence_leakage import compute_leakage_for_pair


def load_run(traces_path: Path) -> List[PairRecord]:
    """Load Session 059 traces.jsonl and produce one PairRecord per pair.

    Pairs are identified by (scenario_id, operator_name) across pipelines.
    Each pair contributes one PairRecord with narrow + broad leakage flags
    computed via the existing InfluenceLeakage helpers.
    """
    if not traces_path.exists():
        raise FileNotFoundError(f"Traces file not found: {traces_path}")

    with traces_path.open("r", encoding="utf-8") as f:
        all_traces = [json.loads(line) for line in f if line.strip()]

    # Group traces by (scenario_id, operator_name) — None operator is baseline.
    pairs: dict[tuple[str, str | None], dict] = {}
    for trace in all_traces:
        key = (trace["scenario_id"], trace.get("operator_name"))
        pairs.setdefault(key, {})[trace["pipeline"]] = trace

    # Match each mutated key with its baseline (same scenario_id, operator=None).
    records: List[PairRecord] = []
    for (scenario_id, operator), pipelines in pairs.items():
        if operator is None:
            continue
        baseline_key = (scenario_id, None)
        if baseline_key not in pairs:
            continue
        leakage = compute_leakage_for_pair(
            baseline_llm=pairs[baseline_key].get("llm"),
            baseline_light=pairs[baseline_key].get("light"),
            mutated_llm=pipelines.get("llm"),
            mutated_light=pipelines.get("light"),
        )
        records.append(
            PairRecord(
                scenario_id=scenario_id,
                operator=operator,
                narrow_leakage=leakage.narrow_leakage,
                broad_leakage=leakage.broad_leakage,
                confidence_baseline=pairs[baseline_key]["llm"]["architect_confidence"],
                confidence_mutated=pipelines["llm"]["architect_confidence"],
                first_diverging_layer=leakage.first_diverging_layer,
            )
        )
    return records
```

**Note:** `compute_leakage_for_pair` may not exist with that exact signature in `influence_leakage.py`. The implementer should examine the existing module and adapt — the goal is to reuse leakage logic, not duplicate it. If the helper has a different name, rename the import accordingly.

- [ ] **Step 6: Run test to verify it passes**

Run: `pytest ares/dialectic/tests/visualization/test_data_loader.py -v`
Expected: 5 PASS.

- [ ] **Step 7: Commit**

```bash
git add ares/dialectic/visualization/data_loader.py ares/dialectic/tests/visualization/test_data_loader.py ares/dialectic/tests/visualization/fixtures/mini_traces.jsonl
git commit -m "feat: DataLoader.load_run reuses InfluenceLeakage helpers"
```

---

### Task 4: PinState dataclass

**Files:**
- Create: `ares/dialectic/visualization/pin_mapper.py`
- Test: `ares/dialectic/tests/visualization/test_pin_state.py`

- [ ] **Step 1: Write the failing test**

```python
# ares/dialectic/tests/visualization/test_pin_state.py
import pytest
from ares.dialectic.visualization.pin_mapper import PinState


def test_pin_state_is_frozen():
    pin = PinState(
        grid_col=0, grid_row=0,
        depth_target=1.0, brightness_target=0.78,
        activation_order=0, first_diverging_layer="None",
    )
    with pytest.raises(Exception):
        pin.grid_col = 1


def test_pin_state_grid_bounds():
    """grid_col is 0..10 and grid_row is 0..8 for an 11x9 grid."""
    pin = PinState(grid_col=10, grid_row=8,
                   depth_target=0.0, brightness_target=0.0,
                   activation_order=98, first_diverging_layer="Architect")
    assert pin.grid_col == 10
    assert pin.grid_row == 8


def test_pin_state_depth_is_binary_zero_or_one():
    """Per spec, depth_target is 0.0 (drifted) or 1.0 (held)."""
    for depth in (0.0, 1.0):
        pin = PinState(grid_col=0, grid_row=0,
                       depth_target=depth, brightness_target=0.5,
                       activation_order=0, first_diverging_layer="None")
        assert pin.depth_target == depth
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest ares/dialectic/tests/visualization/test_pin_state.py -v`
Expected: 3 FAILS with `ImportError`.

- [ ] **Step 3: Implement PinState**

```python
# ares/dialectic/visualization/pin_mapper.py
"""Maps PairRecord -> PinState for the 11x9 pinscreen grid."""

from dataclasses import dataclass
from ares.dialectic.visualization.data_loader import DivergingLayer


@dataclass(frozen=True)
class PinState:
    """One pin's final-state values, ready for the timeline."""

    grid_col: int          # 0..10
    grid_row: int          # 0..8
    depth_target: float    # 1.0 = held, 0.0 = drifted
    brightness_target: float  # 0.0..1.0, baseline confidence
    activation_order: int  # 0..98
    first_diverging_layer: DivergingLayer
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest ares/dialectic/tests/visualization/test_pin_state.py -v`
Expected: 3 PASS.

- [ ] **Step 5: Commit**

```bash
git add ares/dialectic/visualization/pin_mapper.py ares/dialectic/tests/visualization/test_pin_state.py
git commit -m "feat: PinState frozen dataclass for grid positions"
```

---

### Task 5: PinMapper.map_pairs_to_pins()

**Files:**
- Modify: `ares/dialectic/visualization/pin_mapper.py`
- Test: `ares/dialectic/tests/visualization/test_pin_mapper.py`

- [ ] **Step 1: Write the failing test**

```python
# ares/dialectic/tests/visualization/test_pin_mapper.py
from ares.dialectic.visualization.data_loader import PairRecord
from ares.dialectic.visualization.pin_mapper import PinState, map_pairs_to_pins


def _make_record(scenario_id, operator, broad_leakage=False, confidence=0.9):
    return PairRecord(
        scenario_id=scenario_id, operator=operator,
        narrow_leakage=False, broad_leakage=broad_leakage,
        confidence_baseline=confidence, confidence_mutated=confidence,
        first_diverging_layer="None" if not broad_leakage else "Oracle",
    )


def test_map_produces_one_pin_per_pair():
    pairs = [_make_record(f"INJ-{i:03d}", "framing_prefix_v1") for i in range(33)]
    pins = map_pairs_to_pins(pairs)
    assert len(pins) == 33
    assert all(isinstance(p, PinState) for p in pins)


def test_grid_position_fills_left_to_right_top_to_bottom():
    pairs = [_make_record("INJ-001", op) for op in (
        "framing_prefix_v1", "framing_suffix_v1", "synonym_substitution_conservative_v2",
    )]
    pins = map_pairs_to_pins(pairs)
    assert (pins[0].grid_col, pins[0].grid_row) == (0, 0)
    assert (pins[1].grid_col, pins[1].grid_row) == (1, 0)
    assert (pins[2].grid_col, pins[2].grid_row) == (2, 0)


def test_grid_wraps_at_column_eleven():
    pairs = [_make_record(f"INJ-{i:03d}", "framing_prefix_v1") for i in range(13)]
    pins = map_pairs_to_pins(pairs)
    assert (pins[10].grid_col, pins[10].grid_row) == (10, 0)
    assert (pins[11].grid_col, pins[11].grid_row) == (0, 1)
    assert (pins[12].grid_col, pins[12].grid_row) == (1, 1)


def test_depth_target_is_one_when_held():
    pin = map_pairs_to_pins([_make_record("INJ-001", "op1", broad_leakage=False)])[0]
    assert pin.depth_target == 1.0


def test_depth_target_is_zero_when_drifted():
    pin = map_pairs_to_pins([_make_record("INJ-001", "op1", broad_leakage=True)])[0]
    assert pin.depth_target == 0.0


def test_brightness_is_baseline_confidence_clamped():
    pin = map_pairs_to_pins([_make_record("INJ-001", "op1", confidence=1.5)])[0]
    assert pin.brightness_target == 1.0
    pin2 = map_pairs_to_pins([_make_record("INJ-001", "op1", confidence=-0.3)])[0]
    assert pin2.brightness_target == 0.0


def test_activation_order_matches_input_order():
    pairs = [_make_record(f"INJ-{i:03d}", "op1") for i in range(5)]
    pins = map_pairs_to_pins(pairs)
    assert [p.activation_order for p in pins] == [0, 1, 2, 3, 4]


def test_deterministic_same_input_same_output():
    pairs = [_make_record(f"INJ-{i:03d}", "op1") for i in range(10)]
    pins_a = map_pairs_to_pins(pairs)
    pins_b = map_pairs_to_pins(pairs)
    assert pins_a == pins_b
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest ares/dialectic/tests/visualization/test_pin_mapper.py -v`
Expected: 7 FAILS with `ImportError: cannot import name 'map_pairs_to_pins'`.

- [ ] **Step 3: Implement map_pairs_to_pins**

```python
# Append to ares/dialectic/visualization/pin_mapper.py
from typing import List
from ares.dialectic.visualization.data_loader import PairRecord

GRID_COLS = 11
GRID_ROWS = 9


def map_pairs_to_pins(pairs: List[PairRecord]) -> List[PinState]:
    """Deterministic transform from PairRecords to PinStates.

    Each pair becomes one pin. Grid fills left-to-right, top-to-bottom.
    Depth is binary (1.0 held, 0.0 drifted). Brightness is clamped confidence.
    """
    pins: List[PinState] = []
    for i, pair in enumerate(pairs):
        col = i % GRID_COLS
        row = i // GRID_COLS
        depth = 0.0 if pair.broad_leakage else 1.0
        brightness = max(0.0, min(1.0, pair.confidence_baseline))
        pins.append(
            PinState(
                grid_col=col,
                grid_row=row,
                depth_target=depth,
                brightness_target=brightness,
                activation_order=i,
                first_diverging_layer=pair.first_diverging_layer,
            )
        )
    return pins
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest ares/dialectic/tests/visualization/test_pin_mapper.py -v`
Expected: 7 PASS.

- [ ] **Step 5: Commit**

```bash
git add ares/dialectic/visualization/pin_mapper.py ares/dialectic/tests/visualization/test_pin_mapper.py
git commit -m "feat: PinMapper transforms PairRecords to pin grid coordinates"
```

---

### Task 6: Timeline dataclass

**Files:**
- Create: `ares/dialectic/visualization/timeline_builder.py`
- Test: `ares/dialectic/tests/visualization/test_timeline.py`

- [ ] **Step 1: Write the failing test**

```python
# ares/dialectic/tests/visualization/test_timeline.py
import pytest
from ares.dialectic.visualization.timeline_builder import Timeline, TimelinePin, GridSpec


def test_timeline_is_frozen():
    grid = GridSpec(cols=11, rows=9, spacing_units=5.6)
    timeline = Timeline(version="1", duration_ms=45000, grid=grid, pins=())
    with pytest.raises(Exception):
        timeline.duration_ms = 50000


def test_timeline_pins_is_immutable_tuple():
    grid = GridSpec(cols=11, rows=9, spacing_units=5.6)
    pin = TimelinePin(col=0, row=0, depth_target=1.0,
                     brightness_target=0.8, activation_ms=0,
                     diverging_layer="None")
    timeline = Timeline(version="1", duration_ms=45000, grid=grid, pins=(pin,))
    assert isinstance(timeline.pins, tuple)


def test_grid_spec_is_frozen():
    grid = GridSpec(cols=11, rows=9, spacing_units=5.6)
    with pytest.raises(Exception):
        grid.cols = 10
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest ares/dialectic/tests/visualization/test_timeline.py -v`
Expected: 3 FAILS with `ImportError`.

- [ ] **Step 3: Implement Timeline + GridSpec + TimelinePin**

```python
# ares/dialectic/visualization/timeline_builder.py
"""Builds the timeline.json artifact from PinState objects."""

from dataclasses import dataclass
from typing import Tuple
from ares.dialectic.visualization.data_loader import DivergingLayer


@dataclass(frozen=True)
class GridSpec:
    cols: int
    rows: int
    spacing_units: float


@dataclass(frozen=True)
class TimelinePin:
    col: int
    row: int
    depth_target: float
    brightness_target: float
    activation_ms: int
    diverging_layer: DivergingLayer


@dataclass(frozen=True)
class Timeline:
    version: str
    duration_ms: int
    grid: GridSpec
    pins: Tuple[TimelinePin, ...]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest ares/dialectic/tests/visualization/test_timeline.py -v`
Expected: 3 PASS.

- [ ] **Step 5: Commit**

```bash
git add ares/dialectic/visualization/timeline_builder.py ares/dialectic/tests/visualization/test_timeline.py
git commit -m "feat: Timeline + GridSpec + TimelinePin dataclasses"
```

---

### Task 7: TimelineBuilder.build_timeline()

**Files:**
- Modify: `ares/dialectic/visualization/timeline_builder.py`
- Test: `ares/dialectic/tests/visualization/test_timeline_builder.py`

**Default timing constants per spec:** stagger=400ms, emerge=200ms, pulse=300ms, settle=600ms, final_hold=4000ms.

- [ ] **Step 1: Write the failing test**

```python
# ares/dialectic/tests/visualization/test_timeline_builder.py
import json
from pathlib import Path
from ares.dialectic.visualization.pin_mapper import PinState
from ares.dialectic.visualization.timeline_builder import (
    Timeline, GridSpec, TimelinePin,
    build_timeline, timeline_to_json,
    DEFAULT_STAGGER_MS, DEFAULT_FINAL_HOLD_MS,
)


def _make_pin(i, held=True):
    return PinState(
        grid_col=i % 11, grid_row=i // 11,
        depth_target=1.0 if held else 0.0,
        brightness_target=0.9,
        activation_order=i,
        first_diverging_layer="None" if held else "Oracle",
    )


def test_build_timeline_produces_one_pin_per_state():
    states = [_make_pin(i) for i in range(99)]
    timeline = build_timeline(states)
    assert len(timeline.pins) == 99


def test_activation_ms_uses_stagger():
    states = [_make_pin(i) for i in range(5)]
    timeline = build_timeline(states)
    expected = [0, DEFAULT_STAGGER_MS, 2 * DEFAULT_STAGGER_MS,
                3 * DEFAULT_STAGGER_MS, 4 * DEFAULT_STAGGER_MS]
    assert [p.activation_ms for p in timeline.pins] == expected


def test_duration_ms_accounts_for_full_sweep_plus_hold():
    states = [_make_pin(i) for i in range(99)]
    timeline = build_timeline(states)
    last_activation = 98 * DEFAULT_STAGGER_MS
    per_pin_life = 200 + 300 + 600  # emerge + pulse + settle
    assert timeline.duration_ms == last_activation + per_pin_life + DEFAULT_FINAL_HOLD_MS


def test_grid_spec_matches_spec_values():
    timeline = build_timeline([_make_pin(0)])
    assert timeline.grid.cols == 11
    assert timeline.grid.rows == 9
    assert timeline.grid.spacing_units == 5.6


def test_timeline_to_json_round_trip():
    timeline = build_timeline([_make_pin(0), _make_pin(1, held=False)])
    json_str = timeline_to_json(timeline)
    parsed = json.loads(json_str)
    assert parsed["version"] == "1"
    assert parsed["grid"]["cols"] == 11
    assert len(parsed["pins"]) == 2
    assert parsed["pins"][0]["depth_target"] == 1.0
    assert parsed["pins"][1]["depth_target"] == 0.0


def test_deterministic_same_input_same_json():
    states = [_make_pin(i) for i in range(20)]
    json_a = timeline_to_json(build_timeline(states))
    json_b = timeline_to_json(build_timeline(states))
    assert json_a == json_b
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest ares/dialectic/tests/visualization/test_timeline_builder.py -v`
Expected: 6 FAILS with `ImportError`.

- [ ] **Step 3: Implement build_timeline + timeline_to_json**

```python
# Append to ares/dialectic/visualization/timeline_builder.py
import json
from typing import List
from ares.dialectic.visualization.pin_mapper import PinState

DEFAULT_STAGGER_MS = 400
DEFAULT_EMERGE_MS = 200
DEFAULT_PULSE_MS = 300
DEFAULT_SETTLE_MS = 600
DEFAULT_FINAL_HOLD_MS = 4000
GRID_COLS = 11
GRID_ROWS = 9
GRID_SPACING = 5.6


def build_timeline(
    states: List[PinState],
    stagger_ms: int = DEFAULT_STAGGER_MS,
    emerge_ms: int = DEFAULT_EMERGE_MS,
    pulse_ms: int = DEFAULT_PULSE_MS,
    settle_ms: int = DEFAULT_SETTLE_MS,
    final_hold_ms: int = DEFAULT_FINAL_HOLD_MS,
) -> Timeline:
    """Sequence PinStates into an animation timeline."""
    pins = tuple(
        TimelinePin(
            col=s.grid_col,
            row=s.grid_row,
            depth_target=s.depth_target,
            brightness_target=s.brightness_target,
            activation_ms=s.activation_order * stagger_ms,
            diverging_layer=s.first_diverging_layer,
        )
        for s in states
    )
    if pins:
        last_activation = max(p.activation_ms for p in pins)
    else:
        last_activation = 0
    per_pin_life = emerge_ms + pulse_ms + settle_ms
    duration_ms = last_activation + per_pin_life + final_hold_ms
    return Timeline(
        version="1",
        duration_ms=duration_ms,
        grid=GridSpec(cols=GRID_COLS, rows=GRID_ROWS, spacing_units=GRID_SPACING),
        pins=pins,
    )


def timeline_to_json(timeline: Timeline) -> str:
    """Serialize Timeline to deterministic JSON (sorted keys, 2-space indent)."""
    payload = {
        "version": timeline.version,
        "duration_ms": timeline.duration_ms,
        "grid": {
            "cols": timeline.grid.cols,
            "rows": timeline.grid.rows,
            "spacing_units": timeline.grid.spacing_units,
        },
        "pins": [
            {
                "col": p.col,
                "row": p.row,
                "depth_target": p.depth_target,
                "brightness_target": p.brightness_target,
                "activation_ms": p.activation_ms,
                "diverging_layer": p.diverging_layer,
            }
            for p in timeline.pins
        ],
    }
    return json.dumps(payload, indent=2, sort_keys=True)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest ares/dialectic/tests/visualization/test_timeline_builder.py -v`
Expected: 6 PASS.

- [ ] **Step 5: Commit**

```bash
git add ares/dialectic/visualization/timeline_builder.py ares/dialectic/tests/visualization/test_timeline_builder.py
git commit -m "feat: TimelineBuilder produces deterministic timeline JSON"
```

---

### Task 8: CLI (build_timeline.py)

**Files:**
- Create: `ares/dialectic/visualization/build_timeline.py`
- Test: `ares/dialectic/tests/visualization/test_build_timeline_cli.py`

- [ ] **Step 1: Write the failing test**

```python
# ares/dialectic/tests/visualization/test_build_timeline_cli.py
import json
import sys
from pathlib import Path
from unittest.mock import patch
from ares.dialectic.visualization.build_timeline import main

FIXTURE_DIR = Path(__file__).parent / "fixtures"


def test_cli_writes_json_file(tmp_path):
    output = tmp_path / "out.json"
    args = ["--traces", str(FIXTURE_DIR / "mini_traces.jsonl"),
            "--output", str(output)]
    with patch.object(sys, "argv", ["build_timeline", *args]):
        exit_code = main()
    assert exit_code == 0
    assert output.exists()
    parsed = json.loads(output.read_text())
    assert parsed["version"] == "1"
    assert "pins" in parsed
    assert len(parsed["pins"]) == 1  # mini fixture has one pair


def test_cli_returns_nonzero_when_traces_missing(tmp_path):
    args = ["--traces", str(tmp_path / "missing.jsonl"),
            "--output", str(tmp_path / "out.json")]
    with patch.object(sys, "argv", ["build_timeline", *args]):
        exit_code = main()
    assert exit_code != 0
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest ares/dialectic/tests/visualization/test_build_timeline_cli.py -v`
Expected: 2 FAILS with `ImportError`.

- [ ] **Step 3: Implement the CLI**

```python
# ares/dialectic/visualization/build_timeline.py
"""CLI: read Session 059 traces, write pinscreen-timeline.json.

Usage:
    python -m ares.dialectic.visualization.build_timeline \
        --traces data/paper_3/leakage_runs/20260510-193950-f401a8/traces.jsonl \
        --output docs/marketing/pinscreen-timeline.json
"""

import argparse
import sys
from pathlib import Path

from ares.dialectic.visualization.data_loader import load_run
from ares.dialectic.visualization.pin_mapper import map_pairs_to_pins
from ares.dialectic.visualization.timeline_builder import build_timeline, timeline_to_json


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--traces", required=True, type=Path,
                        help="Path to traces.jsonl from a leakage run")
    parser.add_argument("--output", required=True, type=Path,
                        help="Where to write the timeline JSON")
    args = parser.parse_args()

    try:
        pairs = load_run(args.traces)
    except FileNotFoundError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    states = map_pairs_to_pins(pairs)
    timeline = build_timeline(states)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(timeline_to_json(timeline), encoding="utf-8")
    print(f"Wrote {len(timeline.pins)} pins to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest ares/dialectic/tests/visualization/test_build_timeline_cli.py -v`
Expected: 2 PASS.

- [ ] **Step 5: Commit**

```bash
git add ares/dialectic/visualization/build_timeline.py ares/dialectic/tests/visualization/test_build_timeline_cli.py
git commit -m "feat: build_timeline CLI emits deterministic pinscreen-timeline.json"
```

---

### Task 9: Generate the real pinscreen-timeline.json

**Files:**
- Create: `docs/marketing/pinscreen-timeline.json` (output artifact)

- [ ] **Step 1: Run the CLI against the Session 059 traces**

```bash
python -m ares.dialectic.visualization.build_timeline \
    --traces data/paper_3/leakage_runs/20260510-193950-f401a8/traces.jsonl \
    --output docs/marketing/pinscreen-timeline.json
```

Expected output: `Wrote 99 pins to docs/marketing/pinscreen-timeline.json` (or close to 99 — exact count depends on how many pairs are in the run).

- [ ] **Step 2: Sanity-check the generated JSON**

```bash
python -c "import json; d=json.load(open('docs/marketing/pinscreen-timeline.json')); print(f'pins={len(d[\"pins\"])}, duration={d[\"duration_ms\"]}ms'); held=sum(1 for p in d['pins'] if p['depth_target']==1.0); print(f'held={held}, drifted={len(d[\"pins\"])-held}')"
```

Expected: roughly 80 held / 19 drifted (per spec). If the ratio is dramatically off, the implementer should re-check the `compute_leakage_for_pair` mapping in Task 3.

- [ ] **Step 3: Run the full visualization test suite**

Run: `pytest ares/dialectic/tests/visualization/ -v`
Expected: all green (~23 tests).

- [ ] **Step 4: Run the full project test suite to check for regressions**

Run: `pytest ares/`
Expected: all green; total count rises from 3,647 floor by ~23.

- [ ] **Step 5: Commit the generated artifact**

```bash
git add docs/marketing/pinscreen-timeline.json
git commit -m "data: generate pinscreen-timeline.json from Session 059 traces"
```

---

### Task 10: Update CLAUDE.md with the new module

**Files:**
- Modify: `CLAUDE.md`

- [ ] **Step 1: Add the visualization module to the "Key Code Locations" section**

In `CLAUDE.md`, find the "Key Code Locations" section and add (after the "Measurement" or "Narrow characterization" subsection):

```markdown
### Visualization (Phase 7 / Session 061)
- 3D pinscreen pipeline: `ares/dialectic/visualization/` — `DataLoader`, `PinMapper`, `TimelineBuilder`
- CLI: `python -m ares.dialectic.visualization.build_timeline --traces <path> --output <path>`
- Generated artifact: `docs/marketing/pinscreen-timeline.json` (~99 pins from Session 059)
- Design spec: `docs/superpowers/specs/2026-05-13-replay-viewer-pinscreen-3d-design.md`
- Implementation plan: `docs/superpowers/plans/2026-05-13-replay-viewer-pinscreen-3d.md`
```

- [ ] **Step 2: Update the test floor + last-updated date**

Find the header lines in `CLAUDE.md`:

```markdown
**Last updated:** 2026-05-10
**Test count floor (passing):** 3,647
```

Update to:

```markdown
**Last updated:** 2026-05-13
**Test count floor (passing):** ~3,670 (verify actual count post-implementation)
```

The exact floor depends on test count after Task 9.

- [ ] **Step 3: Run the CLAUDE.md freshness test**

Run: `pytest tests/test_claude_md_freshness.py -v`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: add visualization module to CLAUDE.md key locations"
```

---

## Phase 2: JS Renderer (skyframe-main)

**Note:** Phase 2 lives in the `skyframe-main` repo, not in `ares-phase-zero`. The implementer should `cd` to that repo and follow its existing conventions (module bundling, component structure, deployment). Tasks below assume vanilla ES modules + Three.js r160; adapt to the actual stack at integration time.

### Task 11: Set up the renderer module in skyframe-main

**Files (in skyframe-main):**
- Create: `<components>/pinscreen/PinscreenRenderer.js`
- Create: `<components>/pinscreen/types.js` (or .ts if TypeScript)

The exact `<components>` path follows skyframe-main's existing conventions.

- [ ] **Step 1: Create the directory and module stub**

```javascript
// PinscreenRenderer.js
import * as THREE from 'three';
import { OrbitControls } from 'three/addons/controls/OrbitControls.js';

export function createRenderer(container, timeline) {
  // To be implemented in subsequent tasks.
  return { replay() {}, setView(preset) {}, destroy() {} };
}
```

- [ ] **Step 2: Add a smoke test fixture**

Copy a known-good `pinscreen-timeline.json` (from Phase 1 Task 9) into skyframe-main's test fixtures directory.

- [ ] **Step 3: Commit**

```bash
git add <components>/pinscreen/
git commit -m "feat: scaffold PinscreenRenderer module"
```

---

### Task 12: Scene setup (plate + pins + lighting)

**Files:**
- Modify: `<components>/pinscreen/PinscreenRenderer.js`

- [ ] **Step 1: Write a smoke test**

```javascript
// PinscreenRenderer.test.js (or matching skyframe-main test framework)
import { createRenderer } from './PinscreenRenderer.js';
import fixtureTimeline from './fixtures/pinscreen-timeline.json' assert { type: 'json' };

describe('PinscreenRenderer', () => {
  test('mounts plate + 99 pins + lighting on the scene', () => {
    const container = document.createElement('div');
    container.style.width = '800px';
    container.style.height = '500px';
    document.body.appendChild(container);

    const renderer = createRenderer(container, fixtureTimeline);

    // Scene should have: 1 plate + 99 pin meshes + 2 directional lights + 1 ambient = 103+ children
    const scene = renderer._scene;  // expose for testing
    const meshes = scene.children.filter(c => c.isMesh);
    expect(meshes.length).toBeGreaterThanOrEqual(100);  // plate + 99 pins
    const lights = scene.children.filter(c => c.isLight);
    expect(lights.length).toBeGreaterThanOrEqual(3);

    renderer.destroy();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run via skyframe-main's test runner.
Expected: FAIL — scene is empty.

- [ ] **Step 3: Implement scene setup**

Port the scene-construction code from the brainstorming mockup at `<brainstorm-session>/content/3d-pinscreen-v2.html`. Lock these spec values:

- Background: `0x0a0a0a`, linear fog 90-200
- Plate: 82 × 1 × 62 units, `#1a1a1a` MeshStandardMaterial, metalness 0.4, roughness 0.75
- Pin geometry: CylinderGeometry, radius 1.2, 16 segments
- Pin spacing: 5.6 units (read `timeline.grid.spacing_units`)
- Lighting: AmbientLight 0.28, DirectionalLight key 0.95 at (40,80,30), DirectionalLight fill `#88aacc` 0.35 at (-50,40,-40)
- Camera: PerspectiveCamera 40° FOV, default position (50, 42, 70), target (0, 4, 0)

```javascript
// Inside createRenderer:
const scene = new THREE.Scene();
scene.background = new THREE.Color(0x0a0a0a);
scene.fog = new THREE.Fog(0x0a0a0a, 90, 200);

const camera = new THREE.PerspectiveCamera(40, container.clientWidth / container.clientHeight, 0.1, 500);
camera.position.set(50, 42, 70);

const webglRenderer = new THREE.WebGLRenderer({ antialias: true });
webglRenderer.setSize(container.clientWidth, container.clientHeight);
webglRenderer.setPixelRatio(window.devicePixelRatio);
container.appendChild(webglRenderer.domElement);

const controls = new OrbitControls(camera, webglRenderer.domElement);
controls.enableDamping = true;
controls.dampingFactor = 0.08;
controls.zoomSpeed = 0.4;
controls.rotateSpeed = 0.7;
controls.panSpeed = 0.6;
controls.minDistance = 25;
controls.maxDistance = 180;
controls.target.set(0, 4, 0);

scene.add(new THREE.AmbientLight(0xffffff, 0.28));
const keyLight = new THREE.DirectionalLight(0xffffff, 0.95);
keyLight.position.set(40, 80, 30);
scene.add(keyLight);
const fillLight = new THREE.DirectionalLight(0x88aacc, 0.35);
fillLight.position.set(-50, 40, -40);
scene.add(fillLight);

const plate = new THREE.Mesh(
  new THREE.BoxGeometry(82, 1, 62),
  new THREE.MeshStandardMaterial({ color: 0x1a1a1a, metalness: 0.4, roughness: 0.75 })
);
scene.add(plate);

// Pins from timeline.pins
const pinMeshes = [];
const idleColor = new THREE.Color(0x3a3a3a);
const baseHeight = 0.4;
const spacing = timeline.grid.spacing_units;

for (const pin of timeline.pins) {
  const x = (pin.col - (timeline.grid.cols - 1) / 2) * spacing;
  const z = (pin.row - (timeline.grid.rows - 1) / 2) * spacing;
  const material = new THREE.MeshStandardMaterial({
    color: idleColor.clone(), metalness: 0.55, roughness: 0.4
  });
  const mesh = new THREE.Mesh(
    new THREE.CylinderGeometry(1.2, 1.2, 1, 16),
    material
  );
  mesh.position.set(x, 0.5 + baseHeight / 2, z);
  mesh.scale.y = baseHeight;
  scene.add(mesh);
  pinMeshes.push({ mesh, material, spec: pin });
}

// Expose for testing
const api = {
  _scene: scene,
  _pinMeshes: pinMeshes,
  replay() {},  // implemented in Task 13
  setView(preset) {},  // implemented in Task 14
  destroy() {
    container.removeChild(webglRenderer.domElement);
    webglRenderer.dispose();
  }
};
return api;
```

- [ ] **Step 4: Run test to verify it passes**

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add <components>/pinscreen/PinscreenRenderer.js
git commit -m "feat: PinscreenRenderer scene setup (plate + pins + lighting)"
```

---

### Task 13: Animation loop

**Files:**
- Modify: `<components>/pinscreen/PinscreenRenderer.js`

- [ ] **Step 1: Write a behavior test for replay()**

```javascript
test('replay() resets pin states and starts the activation sweep', async () => {
  const container = document.createElement('div');
  container.style.width = '800px';
  container.style.height = '500px';
  document.body.appendChild(container);

  const renderer = createRenderer(container, fixtureTimeline);

  // Initial pin scale should be base height
  const firstPin = renderer._pinMeshes[0].mesh;
  expect(firstPin.scale.y).toBeCloseTo(0.4, 1);

  renderer.replay();
  await new Promise(r => setTimeout(r, 500));  // let first pin activate

  expect(firstPin.scale.y).toBeGreaterThan(0.4);

  renderer.destroy();
});
```

- [ ] **Step 2: Implement the animation loop**

Per the spec animation language (Section 3): each pin activates at `pin.activation_ms`. Per-pin life: emerge (200ms) → red pulse (300ms) → settle (600ms). Easing: cubic-out on height. Linear color lerp.

```javascript
// Inside createRenderer, after pinMeshes are set up:

const redColor = new THREE.Color(0xef4444);
const baseColor = new THREE.Color(0x3a3a3a);

let startTime = performance.now();
let animationRunning = true;

function targetHeightFor(depthTarget) {
  // depthTarget is 1.0 (held) or 0.0 (drifted)
  return depthTarget === 1.0 ? 7.5 : 1.2;
}

function targetColorFor(brightnessTarget) {
  // brightness 0..1 mapped to color between #4a4a4a (dim) and #cccccc (bright)
  const dim = new THREE.Color(0x4a4a4a);
  const bright = new THREE.Color(0xcccccc);
  return new THREE.Color().lerpColors(dim, bright, brightnessTarget);
}

function animate() {
  if (!animationRunning) return;
  requestAnimationFrame(animate);

  const t = performance.now() - startTime;

  for (const { mesh, material, spec } of pinMeshes) {
    const dt = t - spec.activation_ms;
    const finalHeight = targetHeightFor(spec.depth_target);
    const finalColor = targetColorFor(spec.brightness_target);

    let height, color;
    if (dt < 0) {
      height = baseHeight;
      color = baseColor;
    } else if (dt < 80) {
      // attack pulse
      color = redColor;
      height = baseHeight + (finalHeight - baseHeight) * (dt / 300);
    } else if (dt < 300) {
      const k = (dt - 80) / 220;
      color = new THREE.Color().lerpColors(redColor, finalColor, Math.min(k, 1));
      const heightK = 1 - Math.pow(1 - dt / 300, 3);
      height = baseHeight + (finalHeight - baseHeight) * heightK;
    } else {
      height = finalHeight;
      color = finalColor;
    }

    mesh.scale.y = height;
    mesh.position.y = 0.5 + height / 2;
    material.color.copy(color);
  }

  controls.update();
  webglRenderer.render(scene, camera);
}
animate();

api.replay = function() {
  startTime = performance.now();
};
api.destroy = function() {
  animationRunning = false;
  container.removeChild(webglRenderer.domElement);
  webglRenderer.dispose();
};
```

- [ ] **Step 3: Run test to verify it passes**

Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add <components>/pinscreen/PinscreenRenderer.js
git commit -m "feat: PinscreenRenderer animation loop with red attack pulse"
```

---

### Task 14: Camera presets + public API

**Files:**
- Modify: `<components>/pinscreen/PinscreenRenderer.js`

- [ ] **Step 1: Write a test for setView**

```javascript
test('setView moves camera to named preset positions', () => {
  const container = document.createElement('div');
  container.style.width = '800px';
  container.style.height = '500px';
  document.body.appendChild(container);

  const renderer = createRenderer(container, fixtureTimeline);

  renderer.setView('top-down');
  expect(renderer._camera.position.y).toBeGreaterThan(80);

  renderer.setView('side');
  expect(renderer._camera.position.z).toBeGreaterThan(80);
  expect(renderer._camera.position.y).toBeLessThan(15);

  renderer.setView('three-quarter');
  expect(renderer._camera.position.x).toBeCloseTo(50, 0);

  renderer.destroy();
});
```

- [ ] **Step 2: Implement setView**

```javascript
// Inside createRenderer:
api.setView = function(preset) {
  if (preset === 'top-down') {
    camera.position.set(0, 95, 0.1);
    controls.target.set(0, 0, 0);
  } else if (preset === 'side') {
    camera.position.set(0, 8, 90);
    controls.target.set(0, 4, 0);
  } else if (preset === 'three-quarter') {
    camera.position.set(50, 42, 70);
    controls.target.set(0, 4, 0);
  }
  controls.update();
};
api._camera = camera;  // expose for testing
```

- [ ] **Step 3: Run test to verify it passes**

Expected: PASS.

- [ ] **Step 4: Add viewport resize handling**

```javascript
const resizeHandler = () => {
  camera.aspect = container.clientWidth / container.clientHeight;
  camera.updateProjectionMatrix();
  webglRenderer.setSize(container.clientWidth, container.clientHeight);
};
window.addEventListener('resize', resizeHandler);

// In destroy():
api.destroy = function() {
  animationRunning = false;
  window.removeEventListener('resize', resizeHandler);
  container.removeChild(webglRenderer.domElement);
  webglRenderer.dispose();
};
```

- [ ] **Step 5: Commit**

```bash
git add <components>/pinscreen/PinscreenRenderer.js
git commit -m "feat: PinscreenRenderer camera presets + resize handling"
```

---

### Task 15: ARESVisionSection wrapper

**Files:**
- Create: `<components>/aresVision/PinscreenSection.html` (or framework equivalent)
- Create: `<components>/aresVision/PinscreenSection.js`

The exact paths follow skyframe-main's section conventions. The section MUST:
1. Fetch `/public/data/pinscreen-timeline.json` when it enters the viewport (`IntersectionObserver`).
2. Mount a `PinscreenRenderer` once the JSON is loaded.
3. Show legend, replay button, three camera preset buttons.
4. Honor `prefers-reduced-motion: reduce` by skipping the activation animation (call `replay()` but advance `startTime` so all pins start past their activation window).

- [ ] **Step 1: Write the HTML structure**

```html
<!-- PinscreenSection.html (or template) -->
<section id="ares-pinscreen-section">
  <h2>How ARES holds under attack</h2>
  <p class="caption">99 paired cycles from Session 059. 80 held. 19 drifted. Each pin's height is one cycle's resilience to attacker prose mutation.</p>

  <div id="pinscreen-canvas" style="width:100%;height:520px"></div>

  <div class="controls">
    <button data-action="replay">↻ Replay</button>
    <button data-action="top-down">Top-down</button>
    <button data-action="side">Side view</button>
    <button data-action="three-quarter">3/4 angle</button>
  </div>

  <div class="legend">
    <span class="dot held"></span> Held under attack
    <span class="dot drifted"></span> Drifted
    <span class="dot pulse"></span> Attack pulse (activation moment)
  </div>
</section>
```

- [ ] **Step 2: Wire it up**

```javascript
// PinscreenSection.js
import { createRenderer } from '../pinscreen/PinscreenRenderer.js';

export function initPinscreenSection() {
  const section = document.getElementById('ares-pinscreen-section');
  const canvas = section.querySelector('#pinscreen-canvas');
  let renderer = null;
  let timelineLoaded = false;

  const observer = new IntersectionObserver(async (entries) => {
    if (entries[0].isIntersecting && !timelineLoaded) {
      timelineLoaded = true;
      try {
        const response = await fetch('/public/data/pinscreen-timeline.json');
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const timeline = await response.json();
        renderer = createRenderer(canvas, timeline);
      } catch (err) {
        console.error('Failed to load pinscreen timeline:', err);
        canvas.innerHTML = '<p>Visualization unavailable.</p>';
        return;
      }
      // Wire control buttons.
      section.querySelectorAll('[data-action]').forEach(btn => {
        btn.addEventListener('click', () => {
          const action = btn.dataset.action;
          if (action === 'replay') renderer.replay();
          else renderer.setView(action);
        });
      });
    }
  }, { threshold: 0.3 });

  observer.observe(section);
}
```

- [ ] **Step 3: Handle prefers-reduced-motion**

In `createRenderer`, at the end:

```javascript
if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
  // Skip animation: jump to final state.
  startTime = -Math.max(...timeline.pins.map(p => p.activation_ms)) - 1000;
}
```

- [ ] **Step 4: Smoke test in browser**

Open the page in a browser with the section embedded. Confirm:
- Section renders once it scrolls into view
- Animation plays
- All three preset buttons work
- Replay button restarts the sequence

- [ ] **Step 5: Commit**

```bash
git add <components>/aresVision/PinscreenSection.html <components>/aresVision/PinscreenSection.js
git commit -m "feat: ARESVisionSection wires PinscreenRenderer into skyframe-main"
```

---

### Task 16: Deployment

**Files:**
- Create: `ares-phase-zero/ares/dialectic/visualization/DEPLOYMENT.md`
- Copy: `pinscreen-timeline.json` → `skyframe-main/public/data/`

- [ ] **Step 1: Write the deployment doc**

```markdown
<!-- ares/dialectic/visualization/DEPLOYMENT.md -->
# Pinscreen Timeline Deployment

## To deploy a fresh timeline to skyframe-main:

1. Regenerate the timeline from the current Session 059 run:
   ```bash
   cd /path/to/ares-phase-zero
   python -m ares.dialectic.visualization.build_timeline \
       --traces data/paper_3/leakage_runs/20260510-193950-f401a8/traces.jsonl \
       --output docs/marketing/pinscreen-timeline.json
   ```

2. Copy the JSON to skyframe-main:
   ```bash
   cp docs/marketing/pinscreen-timeline.json /path/to/skyframe-main/public/data/
   ```

3. Commit in skyframe-main:
   ```bash
   cd /path/to/skyframe-main
   git add public/data/pinscreen-timeline.json
   git commit -m "data: refresh pinscreen timeline"
   ```

4. Deploy skyframe-main per its normal process.

## To update the visualization itself:

Changes to PinscreenRenderer live in skyframe-main. Changes to the timeline
schema or data pipeline live in ares-phase-zero. Both repos must stay in sync
on the timeline.json schema version (currently "1").
```

- [ ] **Step 2: Copy the JSON to skyframe-main**

```bash
cp /path/to/ares-phase-zero/docs/marketing/pinscreen-timeline.json /path/to/skyframe-main/public/data/
```

- [ ] **Step 3: Commit DEPLOYMENT.md in ares-phase-zero**

```bash
git add ares/dialectic/visualization/DEPLOYMENT.md
git commit -m "docs: deployment instructions for pinscreen timeline"
```

- [ ] **Step 4: Commit the JSON copy in skyframe-main**

```bash
cd /path/to/skyframe-main
git add public/data/pinscreen-timeline.json
git commit -m "data: initial pinscreen timeline from Session 059"
```

- [ ] **Step 5: Deploy and verify**

Push skyframe-main, deploy via its normal process, and open the page in a browser. Confirm the section renders the 3D pinscreen as expected.

---

## Self-Review (run after writing this plan)

**1. Spec coverage:** Each spec section maps to tasks:
- Architecture / Five Units → Tasks 1–8 (Phase 1) + Tasks 11–14 (Phase 2)
- Data flow & per-pin semantics → Tasks 2, 3, 5
- Animation language → Task 13
- Visual identity (table values) → Tasks 12, 13, 14
- Integration & build pipeline → Tasks 8, 9, 16
- Error handling → Task 15 (Step 3 reduced-motion; renderer try/catch in Step 2)
- Testing → Tasks 2, 3, 5, 7, 8, 12, 13, 14
- Edge cases (resize, reduced-motion, IntersectionObserver autoplay) → Tasks 14, 15

**2. Placeholder scan:** No "TBD" in load-bearing places. `<components>` path placeholder for skyframe-main is intentional and documented as "follows skyframe-main's existing conventions" — a known integration variable, not laziness.

**3. Type consistency:** `PairRecord`, `PinState`, `TimelinePin`, `Timeline`, `GridSpec` used consistently across tasks. Field names (`broad_leakage`, `depth_target`, `activation_ms`, `diverging_layer`) match between Python and JS sides.

**4. Scope check:** 16 tasks; ~80 individual steps; Phase 1 produces a tested file artifact (~3–4 days), Phase 2 builds a renderer that consumes it (~3–4 days). Total within the 5–8 day spec estimate.

---

## Open Items for Implementation

- **`compute_leakage_for_pair` helper name** in `influence_leakage.py` — may need renaming or adapter. Implementer reads the existing module in Task 3 and adapts.
- **skyframe-main component conventions** — exact paths and bundling determined when the repo is opened.
- **Zoom calibration** — empirical. May drop `zoomSpeed` from 0.4 to ~0.25 after touch testing.
- **Caption copy** — working figure is "99 paired cycles from Session 059. 80 held. 19 drifted." Adjust if Paper 3 framing settles differently.
