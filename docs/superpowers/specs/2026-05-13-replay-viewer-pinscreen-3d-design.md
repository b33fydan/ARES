# ARES Replay Viewer — 3D Pinscreen (Design Spec)

**Status:** Approved for implementation planning
**Date:** 2026-05-13
**Author:** Dan Gmys-Casiano (with brainstorming assistance)
**Context:** Phase 7 / Paper 3 visualization layer; first of three planned outputs (ARES-VISION extension → video clip exports → standalone interactive web page)

---

## Overview

A 3D pinscreen that replays Session 059 InfluenceLeakage data as a sequential, draggable, monochrome animation. 99 cylindrical pins on a base plate; each pin's z-axis displacement (height) encodes resilience to attacker prose mutation. Pin emerges, brief red attack pulse, settles to final depth. ~80 pins extend (held), ~19 retract (drifted). Camera is orbital — viewers drag to see the depth pattern from any angle.

Lives as a section inside the existing ARES-VISION layer on `skyframe-main`. Renders client-side from a pre-baked `timeline.json` — no runtime ARES dependency, no LLM calls, no API.

## Goals

1. **Demonstrate (not claim) resilience.** Make the Phase 7 finding visceral — viewers see the topography of stability, they don't just read a number.
2. **Disciplined aesthetic.** Strict monochrome; single red accent during the attack moment only; geometric grid; mechanical motion language. Pinscreen aesthetic locked over Arese and a hybrid merge.
3. **Render in 3D with real depth.** True z-axis displacement, orbital camera. The depth pattern reads from any angle but specifically rewards the side view.
4. **Static, deterministic, deployable.** Build pipeline produces a pre-baked `timeline.json`. Same input → same output. The deployed site never touches Session 059 raw data.
5. **First of three outputs.** This is the ARES-VISION extension (priority 1). Video-clip export (priority 2) and standalone interactive web page (priority 3) reuse the same renderer + timeline format.

## Non-Goals

- **Live LLM-driven replay.** No real-time Architect/Skeptic/Oracle calls. All data is from existing Session 059 run logs.
- **Interactive attack-pressure dial.** Deferred to a future rung (Rung 3 of the original brainstorm).
- **Multiple pinscreens on one page.** Single instance per page in v1.
- **Combined-corpus view across multiple sessions.** Approach C from the brainstorm; deferred. MVP is Session 059 only.
- **Standalone production hosting.** Embedded section within `skyframe-main`, not a standalone deployment target.

## Architecture (Five Units)

The system is five small units with one job each. Units 1–3 run offline in `ares-phase-zero`; units 4–5 run client-side in `skyframe-main`.

### Unit 1: DataLoader (ares-phase-zero)

- **File:** `ares/dialectic/visualization/data_loader.py`
- **Input:** Path to a Session 059 run directory (e.g., `data/paper_3/leakage_runs/20260510-193950-f401a8/`).
- **Output:** `List[PairRecord]` (99 items).
- **Schema (`PairRecord`):**
  - `scenario_id: str` — e.g., `"INJ-001"`
  - `operator: Literal["framing_prefix_v1", "framing_suffix_v1", "synonym_substitution_conservative_v2"]`
  - `narrow_leakage: bool` — Light Skeptic only
  - `broad_leakage: bool` — Light + Oracle + Final
  - `confidence_baseline: float` — 0.0–1.0
  - `confidence_mutated: float` — 0.0–1.0
  - `first_diverging_layer: Literal["Architect", "Skeptic", "Oracle", "Final", "None"]`
- **Frozen dataclass.** Per ARES architecture constraints, no mutable state.

### Unit 2: PinMapper (ares-phase-zero)

- **File:** `ares/dialectic/visualization/pin_mapper.py`
- **Input:** `List[PairRecord]`.
- **Output:** `List[PinState]` (same length).
- **Schema (`PinState`):**
  - `grid_col: int` (0–10)
  - `grid_row: int` (0–8)
  - `depth_target: float` — `1.0` if held (`broad_leakage == False`), `0.0` if drifted
  - `brightness_target: float` — `confidence_baseline`, clamped 0.0–1.0
  - `activation_order: int` (0–98)
  - `first_diverging_layer: str`
- **Pure function.** Same `PairRecord` input ordering → same `PinState` output. Fully unit-testable.
- **Grid ordering:** `index = grid_row * 11 + grid_col`, where `index = scenario_idx * 3 + operator_idx`. The 11×9 grid fills left-to-right, top-to-bottom, with each scenario's three operators in consecutive positions.

### Unit 3: TimelineBuilder (ares-phase-zero)

- **File:** `ares/dialectic/visualization/timeline_builder.py`
- **Input:** `List[PinState]`, timing config (defaults below).
- **Output:** `Timeline` dataclass serialized to JSON at `docs/marketing/pinscreen-timeline.json`.
- **Schema (Timeline JSON):**
  ```json
  {
    "version": "1",
    "duration_ms": 45000,
    "grid": {"cols": 11, "rows": 9, "spacing_units": 5.6},
    "pins": [
      {
        "col": 0, "row": 0,
        "depth_target": 1.0,
        "brightness_target": 0.78,
        "activation_ms": 0,
        "diverging_layer": "None"
      }
    ]
  }
  ```
- **Default timing config:** stagger=400ms per pin, emerge=200ms, pulse=300ms, settle=600ms, final hold=4000ms. Total ≈ 45s.

### Unit 4: PinscreenRenderer (skyframe-main, ES module)

- **Stack:** Three.js (r160 or current stable). Real WebGL.
- **Input:** A parsed `Timeline` JSON.
- **Responsibilities:** Build the scene (plate + 99 pins + lighting), animate the activation sequence per the timeline, expose `OrbitControls` and camera-preset functions.
- **Public API:**
  - `mount(container: HTMLElement, timeline: Timeline) → { replay(), setView(preset), destroy() }`
  - `preset: "top-down" | "side" | "three-quarter"`
- **Knows nothing about ARES.** Consumes timelines; does not know what `broad_leakage` is.

### Unit 5: ARESVisionSection (skyframe-main, component)

- Wraps the renderer in site-styled chrome: section title, copy, legend, replay button row, camera preset button row.
- Loads `/public/data/pinscreen-timeline.json` on viewport entry (`IntersectionObserver`).
- Mounts the renderer once; calls `replay()` from a button click.
- Lives at a path within `skyframe-main` determined during implementation (the existing component conventions of that repo dictate the location).

## Data Flow & Per-Pin Semantics

```
Session 059 run logs (JSONL)
       │
       ▼  Unit 1: extract 6 fields per cycle
List[PairRecord] (99)
       │
       ▼  Unit 2: deterministic per-pin transform
List[PinState] (99)
       │
       ▼  Unit 3: add timing + serialize
docs/marketing/pinscreen-timeline.json (~50KB)
       │
       ▼  Manual copy to skyframe-main
skyframe-main/public/data/pinscreen-timeline.json
       │
       ▼  Fetched at runtime by Unit 5
Unit 4: PinscreenRenderer.mount() → scene rendered
```

**Per-pin state:**
- **Depth:** `1.0` (fully out, tall pin, ~7.5 units of height) if `broad_leakage == False`. `0.0` (retracted, ~1.2 units) if `broad_leakage == True`.
- **Brightness:** baseline confidence (0.0–1.0). Maps to final material color via interpolation between `#4a4a4a` (dim) and `#cccccc` (bright).
- **Attack pulse:** at activation moment, material color flips to `#ef4444` for 80ms, then lerps to target gray over the next 220ms.

**Grid arrangement:** 11×9, scenario × operator ordering. No semantic clustering — pins are just pins; the spatial pattern is meaningful only through aggregate density.

**Why broad-reading (not narrow):** Narrow leakage is 100% stable (Session 060: 98/98), which would render as 99 identical extended pins — visually flat. Broad leakage has ~19% drift, which gives the topographic variety required for "watch this happen." Narrow-reading 100% stability is reserved for a future B-mode (still snapshot for social posts).

## Animation Language

Sequential left-to-right, top-to-bottom playback. Pin `i` activates at `t = i × 400ms`.

**Per-pin life (relative to activation):**

| Phase | Time (ms) | Height | Color |
|---|---|---|---|
| Idle | < 0 | baseHeight (0.4) | idle (`#3a3a3a`) |
| Attack pulse + start emerge | 0–80 | 0.4 → ~27% of target | `#ef4444` (red) |
| Settle + color lerp | 80–300 | 27% → ~100% of target | red → target gray |
| Hold | 300+ | target | target gray |

**Easing:** cubic-out on height (`1 − (1−k)^3`). Color lerp is linear.

**Global timing:** 99 × 400ms ≈ 40s sweep + 5s final hold = ~45s. Replay button restarts the sequence.

**Post-sweep ambient breathing:** deferred to v2.

## Visual Identity

| Element | Value |
|---|---|
| Background | `#0a0a0a` with linear fog (near 90, far 200) |
| Plate dimensions | 82 × 1 × 62 units |
| Plate material | `#1a1a1a`, metalness 0.4, roughness 0.75 |
| Pin geometry | Cylinder, radius 1.2, 16 segments |
| Pin spacing | 5.6 units between centers |
| Pin idle height | 0.4 units |
| Pin held height (target) | 7.5 units |
| Pin drifted height (target) | 1.2 units |
| Pin material | metalness 0.55, roughness 0.4 |
| Idle color | `#3a3a3a` |
| Held final color | `#cccccc` |
| Drifted final color | `#4a4a4a` |
| Attack pulse color | `#ef4444` (only non-monochrome accent) |
| Ambient light | white, intensity 0.28 |
| Key directional light | white, intensity 0.95, position (40, 80, 30) |
| Fill directional light | `#88aacc`, intensity 0.35, position (-50, 40, -40) |
| Camera FOV | 40° perspective |
| Camera default | three-quarter at (50, 42, 70), target (0, 4, 0) |
| Camera preset: top-down | (0, 95, 0.1), target (0, 0, 0) |
| Camera preset: side | (0, 8, 90), target (0, 4, 0) |
| OrbitControls zoom speed | 0.4 (to be calibrated empirically) |
| OrbitControls rotate speed | 0.7 |
| OrbitControls pan speed | 0.6 |
| OrbitControls damping factor | 0.08 |
| Distance bounds | min 25, max 180 |

## Integration

### ares-phase-zero side

New module at `ares/dialectic/visualization/`:
- `__init__.py`
- `data_loader.py` — Unit 1
- `pin_mapper.py` — Unit 2
- `timeline_builder.py` — Unit 3
- `build_timeline.py` — CLI entry point

CLI invocation: `python -m ares.dialectic.visualization.build_timeline --run-id 20260510-193950-f401a8`

Output: `docs/marketing/pinscreen-timeline.json`. Deterministic — same input → same JSON.

### skyframe-main side

New section component (exact path determined by the repo's existing component conventions during implementation). Interface:
- HTML container `<div id="pinscreen-section">`
- ES module script: bundled `PinscreenRenderer` + Three.js + OrbitControls
- Fetches `/public/data/pinscreen-timeline.json` at mount
- Surrounding section copy: title, legend, caption (headline figure: "80 of 99 held under direct prose-mutation attack"), link to Paper 3 placeholder

### Deployment

For MVP: manual copy of `pinscreen-timeline.json` from `ares-phase-zero/docs/marketing/` to `skyframe-main/public/data/`. Documented in a `DEPLOYMENT.md` inside the visualization module.

Automation (git submodule, CI step, or shared bucket) deferred to v2.

## Error Handling

| Condition | Behavior |
|---|---|
| WebGL unavailable | Show a "visualization requires WebGL" notice; section's legend, caption, and headline figure remain visible. Static PNG snapshot fallback deferred to v2 (would otherwise require a separate headless render pipeline). |
| Three.js CDN unreachable | Use bundled local copy in `skyframe-main`. No external runtime network dependency required. |
| `pinscreen-timeline.json` malformed or missing | Renderer logs error to console; section shows the legend + a static "data unavailable" placeholder. Page does not crash. |
| Viewport resize | Camera aspect recalculated, renderer resized. Already handled in the v2 mockup. |
| `prefers-reduced-motion: reduce` user setting | Skip the activation animation, render the final state directly. Replay button still works on explicit click. |

## Testing

### Python (ares-phase-zero)

- `tests/visualization/test_data_loader.py` — load against fixture JSONL, assert `PairRecord` schema, count = 99.
- `tests/visualization/test_pin_mapper.py` — deterministic property test (same input → same output), grid-coordinate correctness, depth/brightness mapping correctness across the broad-leakage boolean.
- `tests/visualization/test_timeline_builder.py` — output JSON schema validation, total `duration_ms` math, `activation_ms` strictly increasing.
- `tests/visualization/test_build_timeline_cli.py` — end-to-end CLI smoke test against a fixture run.

Adds an estimated ~10–15 new tests; raises floor from 3,647 toward ~3,660.

### JavaScript (skyframe-main)

- Smoke test: renderer mounts; scene contains plate + 99 pins; OrbitControls instance present.
- Schema test: `timeline.json` parses correctly.
- Visual regression: deferred to v2.

## Edge Cases

- **Touch devices:** Three.js OrbitControls handles touch (1-finger orbit, 2-finger zoom + pan) out of the box. Reviewed at MVP launch.
- **Autoplay:** Section plays the activation sequence once when it enters the viewport via `IntersectionObserver`. Replay button always visible.
- **`prefers-reduced-motion`:** Honored — skip animation, show final state. (See Error Handling.)
- **Multiple instances per page:** Not supported in v1.

## Decisions Log

1. **Aesthetic = strict pinscreen** (over Arese or a hybrid merge). Justification: Dan picked it after clicking through all three options multiple times; the disciplined monochrome geometry aligns with ARES's "mechanical instrument" identity.
2. **Pin depth = resilience (broad-reading from Session 059)** (over verdict, confidence, or switchable lenses). Justification: tells the unique Phase 7 story; gives the visual variety required by Approach A's "watchable playback" goal; narrow-reading (100% stable, Session 060) becomes the future B-mode for still posts.
3. **Sequential playback** (over still snapshot, constant flux, or interactive pressure dial). Justification: tells the story over time without requiring viewer interaction; works inside an embedded section.
4. **Session 059 corpus** (over Session 048/050 framing benchmark, Session 060 narrow characterization, or combined). Justification: directly aligned with the resilience encoding; visually rich (~19% drift); uniquely Phase 7.
5. **3D Three.js renderer** (over 2D canvas with faked depth). Justification: matches Dan's original vision (the pinscreen reference image is viewed at 3/4 angle with pin extension clearly visible); real z-axis displacement carries the meaning rather than encoded via brightness/scale.
6. **ARES-VISION extension first** (over video clip or standalone web page). Justification: integrated into the existing visual layer; same aesthetic + deployment infrastructure; standalone exports follow from the same renderer.
7. **Cross-repo split.** Units 1–3 + JSON output live in `ares-phase-zero`; Units 4–5 live in `skyframe-main`. Justification: keeps research data and render logic on the right side of the boundary; `timeline.json` is the interface.

## Open Questions / Deferred

- **Zoom calibration.** The v2 mockup still feels slightly aggressive on mouse-wheel zoom. Empirical calibration during implementation; may drop `zoomSpeed` further (e.g., to 0.25) or implement custom wheel-event throttling.
- **`skyframe-main` file structure.** Exact paths within the site repo determined when the repo is opened during implementation.
- **Caption copy.** Working headline figure is "80 of 99 held under direct prose-mutation attack." Final copy depends on Paper 3 framing once that paper drafts.
- **Modes B (still snapshot, Session 060) and C (combined corpus chapters).** Inherit this design's renderer + timeline format with different inputs. Implementation deferred to v2/v3.
- **Ambient breathing post-sweep.** A very-slow whole-grid breathing animation after the final hold was discussed; deferred to v2 for evaluation after MVP ship.
