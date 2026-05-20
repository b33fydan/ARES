# Prism Labyrinth — Renderer v2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship Panel 1 (Labyrinth) of the Prism as a production page at `skyframe-main/assets/ares/prism.html`, faithfully porting the 2026-05-13 validated mockup against real Session 059 data with full-kit interactivity.

**Architecture:** Two-file renderer (HTML shell + companion `prism.js`) consuming the Phase A pipeline's `prism-timeline.json`. r128 classic Three.js scripts. Autoplay-first interaction with scrubber-takes-over on user touch. One Python contract test in ARES locks the JSON-renderer interface.

**Tech Stack:** Three.js r128 (classic CDN scripts), OrbitControls.js r128, vanilla JS, Python 3.11 + pytest, deterministic JSON. No build step.

**Spec:** `docs/superpowers/specs/2026-05-19-prism-labyrinth-renderer-v2-design.md`
**Mockup reference:** `docs/marketing/prism-mockup.html` (lines 261-572 are Panel 1; rest is Panels 2-4 and irrelevant to this build)
**Pinscreen precedent (file layout + r128 conventions):** `skyframe-main/assets/ares/pinscreen.html`

---

## File Structure

### ARES repo (`C:\ares-phase-zero`)

**Created:**
- `ares/dialectic/tests/visualization/test_prism_timeline_json_contract.py` — 8 tests locking the JSON contract

**Modified:**
- `CLAUDE.md` — test floor bump (3,725 → 3,733), new Session 062 entry, new Visualization heading in Key Code Locations

**Not modified:** Phase A pipeline files (`cycle_trace*.py`, `build_cycle_timeline.py`, `prism-timeline.json` source) — frozen per ARES "new files only" rule

### skyframe-main repo (`E:\Skyframe Innovations Website\skyframe-main`)

**Created:**
- `assets/ares/prism.html` — chrome (header, panel, canvas mount, controls, legend, footer)
- `assets/ares/prism.js` — scene init, replay loop, data binding, control wiring
- `assets/ares/prism-timeline.json` — copy of the ARES-generated JSON

**Modified:**
- `assets/ares/ares.html` — add second CTA link pointing to `prism.html` next to existing Pinscreen link

---

## Phase A — ARES JSON contract test

### Task 1: Write the JSON contract test (8 tests, single file, single commit)

**Files:**
- Create: `ares/dialectic/tests/visualization/test_prism_timeline_json_contract.py`

This task locks the prism-timeline.json schema as a regression guard. The JSON already exists from Phase A; these tests prove it matches the renderer's contract.

- [ ] **Step 1: Verify the test directory exists**

```bash
ls ares/dialectic/tests/visualization/
```

Expected: existing files including `test_cycle_trace.py`, `test_cycle_trace_builder.py`, `test_build_cycle_timeline_cli.py` (from Phase A).

- [ ] **Step 2: Write the test file**

Create `ares/dialectic/tests/visualization/test_prism_timeline_json_contract.py`:

```python
"""JSON contract guard for the Prism renderer.

prism-timeline.json is consumed by the standalone HTML renderer at
skyframe-main/assets/ares/prism.html. These tests lock the JSON shape
so that a future regen with renamed fields fails fast on the ARES side,
not silently in the browser.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[4]
TIMELINE_PATH = REPO_ROOT / "docs" / "marketing" / "prism-timeline.json"

REQUIRED_TOP_LEVEL_KEYS = frozenset({"operators", "pairs", "run_id", "schema_version"})
REQUIRED_PAIR_KEYS = frozenset({
    "pair_index",
    "operator",
    "scenario_id",
    "broad_leakage",
    "narrow_leakage",
    "first_diverging_layer",
})
EXPECTED_OPERATORS = (
    "framing_prefix_v1",
    "framing_suffix_v1",
    "synonym_substitution_conservative_v2",
)
VALID_DIVERGING_LAYERS = frozenset({"Architect", "Skeptic", "Oracle", "Final"})


@pytest.fixture(scope="module")
def timeline() -> dict:
    assert TIMELINE_PATH.exists(), f"prism-timeline.json missing at {TIMELINE_PATH}"
    with TIMELINE_PATH.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def test_top_level_keys(timeline: dict) -> None:
    assert REQUIRED_TOP_LEVEL_KEYS.issubset(timeline.keys()), (
        f"Missing top-level keys: {REQUIRED_TOP_LEVEL_KEYS - timeline.keys()}"
    )


def test_pair_count_is_98(timeline: dict) -> None:
    assert len(timeline["pairs"]) == 98


def test_exactly_one_broad_leakage_pair(timeline: dict) -> None:
    count = sum(1 for p in timeline["pairs"] if p["broad_leakage"])
    assert count == 1, f"Expected exactly 1 broad_leakage pair, found {count}"


def test_drift_pair_first_diverging_layer_is_valid(timeline: dict) -> None:
    drift_pairs = [p for p in timeline["pairs"] if p["broad_leakage"]]
    assert len(drift_pairs) == 1
    layer = drift_pairs[0]["first_diverging_layer"]
    assert layer in VALID_DIVERGING_LAYERS, (
        f"first_diverging_layer={layer!r} not in {VALID_DIVERGING_LAYERS}"
    )


def test_every_pair_has_required_keys(timeline: dict) -> None:
    for pair in timeline["pairs"]:
        missing = REQUIRED_PAIR_KEYS - pair.keys()
        assert not missing, f"Pair {pair.get('pair_index')} missing keys: {missing}"


def test_operators_equal_expected(timeline: dict) -> None:
    assert tuple(timeline["operators"]) == EXPECTED_OPERATORS


def test_each_pair_operator_is_in_operators_list(timeline: dict) -> None:
    operators = set(timeline["operators"])
    for pair in timeline["pairs"]:
        assert pair["operator"] in operators, (
            f"Pair {pair['pair_index']} operator={pair['operator']!r} not in {operators}"
        )


def test_pair_indices_are_unique_sorted_and_nonneg(timeline: dict) -> None:
    # The pipeline emits pair_index from the global 33 × 3 enumeration (max 99).
    # Some pairs are dropped when an operator is a no-op on a given scenario
    # (Session 058.5: synonym_substitution_conservative_v2 has 1 no-op),
    # so the index sequence has documented gaps. The renderer requires only
    # uniqueness, monotonic order, and non-negative values for its activation
    # timeline to make sense.
    indices = [p["pair_index"] for p in timeline["pairs"]]
    assert len(set(indices)) == len(indices), "pair_index values must be unique"
    assert indices == sorted(indices), "pair_index must be monotonically increasing"
    assert min(indices) >= 0, "pair_index must be non-negative"
    assert max(indices) < 200, f"max pair_index {max(indices)} unexpectedly large (sanity bound)"
```

- [ ] **Step 3: Run the tests**

```bash
pytest ares/dialectic/tests/visualization/test_prism_timeline_json_contract.py -v
```

Expected: 8 tests, all PASS. (The JSON already exists in the expected shape.)

- [ ] **Step 4: Run full test suite to confirm no regressions**

```bash
pytest ares/dialectic/tests/ -q
```

Expected: collected count ≥ 3,733 (3,725 + 8 new); zero failures.

- [ ] **Step 5: Commit**

```bash
git add ares/dialectic/tests/visualization/test_prism_timeline_json_contract.py
git commit -m "$(cat <<'EOF'
test(prism): JSON contract guard for prism-timeline.json

8 tests lock the renderer/pipeline interface so a future regen with
renamed fields fails fast on the ARES side rather than silently in the
browser. Tests cover: top-level keys, pair count, exactly-one drift
pair, valid first_diverging_layer, required pair keys, operators list
identity, per-pair operator membership, sequential pair indices.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Phase B — Renderer (skyframe-main)

> **Switch repos:** all Phase B work happens in `E:\Skyframe Innovations Website\skyframe-main`. Use `cd "E:\Skyframe Innovations Website\skyframe-main"` once at the start of Phase B. Commits in this repo go straight to `main` (Netlify auto-deploys on push; pinscreen Session 061 set this precedent).

### Task 2: HTML chrome scaffold

**Files:**
- Create: `assets/ares/prism.html`

- [ ] **Step 1: Verify the assets/ares directory exists**

```bash
ls assets/ares/
```

Expected: existing files including `pinscreen.html`, `ares.html`, `pinscreen-timeline.json`.

- [ ] **Step 2: Write `prism.html`**

Create `assets/ares/prism.html`:

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>ARES Prism — The Labyrinth</title>
  <link rel="preconnect" href="https://cdnjs.cloudflare.com">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
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
      padding: 26px 28px 16px;
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
    header h1 { margin: 0; font-size: 26px; font-weight: 500; }
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
    .panel-header { padding: 14px 20px 10px; border-bottom: 1px solid #141414; }
    .panel-tag {
      font-family: 'JetBrains Mono', monospace;
      font-size: 10px;
      letter-spacing: 1.5px;
      text-transform: uppercase;
      color: var(--subtle);
    }
    .panel-title { margin: 2px 0 0; font-size: 15px; font-weight: 500; }
    .panel-subtitle { margin: 4px 0 0; color: var(--muted); font-size: 12px; line-height: 1.45; }
    .panel-canvas {
      width: 100%;
      height: 620px;
      position: relative;
      cursor: grab;
    }
    .panel-canvas:active { cursor: grabbing; }
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
    .controls input[type=range] { flex: 1; min-width: 200px; }
    .controls select, .controls button {
      background: transparent;
      border: 1px solid #475569;
      color: var(--text);
      padding: 6px 10px;
      font-family: 'JetBrains Mono', monospace;
      font-size: 11px;
      border-radius: 4px;
      cursor: pointer;
    }
    .controls button:hover { border-color: var(--text); }
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
    .legend-dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; }
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
    #loading {
      position: absolute;
      top: 50%; left: 50%;
      transform: translate(-50%, -50%);
      color: var(--subtle);
      font-family: 'JetBrains Mono', monospace;
      font-size: 13px;
      letter-spacing: 1.5px;
    }
    footer {
      padding: 18px 28px 24px;
      color: var(--subtle);
      font-size: 11px;
      font-family: 'JetBrains Mono', monospace;
      letter-spacing: 0.5px;
      text-align: center;
      border-top: 1px solid var(--border);
    }
    footer a { color: var(--muted); text-decoration: none; }
    footer a:hover { color: var(--text); }
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
        <p class="panel-subtitle">Drag to orbit, scroll to zoom. Scrubber to step through cycles. Click a breadcrumb to focus its path.</p>
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
        <button id="play-pause" type="button">PAUSE</button>
        <label for="scrubber">Cycle</label>
        <input type="range" id="scrubber" min="0" max="97" value="0">
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
        <span class="legend-item"><span class="legend-dot" style="background:#10b981;box-shadow:0 0 4px #10b981"></span>Oracle (Python)</span>
        <span class="legend-item"><span class="legend-dot" style="background:#a78bfa"></span>Verdict</span>
        <span class="legend-item"><span class="legend-dot" style="background:#ef4444;box-shadow:0 0 4px #ef4444"></span>Drift moment</span>
      </div>
    </div>
  </main>

  <footer>
    ARES Phase 7 &middot; Session 059 broad-reading dataset &middot; <a href="pinscreen.html">view the Pinscreen</a>
  </footer>

  <script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/three@0.128.0/examples/js/controls/OrbitControls.js"></script>
  <script src="prism.js"></script>
</body>
</html>
```

- [ ] **Step 3: Verify the page loads (chrome only, no scene yet)**

```bash
# Serve the assets/ares directory
python -m http.server 8765 -d assets/ares/
```

Open `http://localhost:8765/prism.html` in a browser.

Expected: dark page with header, panel chrome, "LOADING TIMELINE…" centered in the canvas area, controls row (PAUSE button + scrubber + operator dial), legend strip, footer. No JS errors (only a 404 on `prism.js` since it doesn't exist yet — this is fine; later tasks add it).

Stop the server with Ctrl+C when done.

- [ ] **Step 4: Commit**

```bash
git add assets/ares/prism.html
git commit -m "feat(prism): HTML chrome for Panel 1 (Labyrinth)"
```

---

### Task 3: Three.js scene scaffold

**Files:**
- Create: `assets/ares/prism.js`

This task gets the empty scene + OrbitControls running. No chambers, no crumbs yet — just a dark canvas with working camera controls.

- [ ] **Step 1: Write `prism.js` initial scaffold**

Create `assets/ares/prism.js`:

```javascript
/*
 * ARES Prism — Panel 1 (Labyrinth)
 *
 * Reads prism-timeline.json (generated by ares/dialectic/visualization/
 * build_cycle_timeline.py) and renders 98 cycle traces through six agent
 * chambers as a 3D scene. Faithful port of docs/marketing/prism-mockup.html
 * (r160 ESM) to r128 classic scripts for skyframe-main.
 *
 * Spec: docs/superpowers/specs/2026-05-19-prism-labyrinth-renderer-v2-design.md
 */

'use strict';

// ────────────────────────────────────────────────────────────────────
// Constants
// ────────────────────────────────────────────────────────────────────

const CHAMBERS = [
  { id: 'input',     label: 'INPUT',     y:  25, color: 0x06b6d4 },
  { id: 'architect', label: 'ARCHITECT', y:  15, color: 0xf59e0b },
  { id: 'firewall',  label: 'FIREWALL',  y:   5, color: 0x22c55e },
  { id: 'skeptic',   label: 'SKEPTIC',   y:  -5, color: 0xf59e0b },
  { id: 'oracle',    label: 'ORACLE',    y: -15, color: 0x10b981 },
  { id: 'verdict',   label: 'VERDICT',   y: -25, color: 0xa78bfa },
];
const CHAMBER_W = 28, CHAMBER_H = 4, CHAMBER_D = 28;

const CYCLE_STAGGER_MS = 240;
const CRUMB_STAGGER_MS = 180;
const OPACITY_RAMP_MS  = 220;
const REPLAY_PAUSE_MS  = 5000;

const DRIFT_COLOR  = 0xef4444;
const HELD_TRAIL   = 0x506070;
const DRIFT_TRAIL  = 0xff5566;
const CONNECT_COLOR = 0x334155;

const SEED = 20260513;

// data field -> chamber id (case- and label-normalized)
const LAYER_TO_CHAMBER = {
  architect: 'architect',
  skeptic:   'skeptic',
  oracle:    'oracle',
  final:     'verdict',
};

// ────────────────────────────────────────────────────────────────────
// State
// ────────────────────────────────────────────────────────────────────

const STATE = {
  timeline: null,
  pairs: [],
  visiblePairs: [],
  operatorFilter: 'all',
  autoplayRunning: true,
  activeCycleIndex: 0,
  focusedPairIndex: null,
};

const SCENE = {
  scene: null,
  camera: null,
  renderer: null,
  controls: null,
  container: null,
  pinGroup: null,
  trailGroup: null,
  chamberMeshes: [],
};

// ────────────────────────────────────────────────────────────────────
// Utilities
// ────────────────────────────────────────────────────────────────────

function mulberry32(seed) {
  let s = seed >>> 0;
  return function() {
    s = (s + 0x6D2B79F5) >>> 0;
    let t = s;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function hexFromColor(num) {
  return '#' + num.toString(16).padStart(6, '0');
}

// ────────────────────────────────────────────────────────────────────
// Scene initialization
// ────────────────────────────────────────────────────────────────────

function initScene() {
  SCENE.container = document.getElementById('panel1-canvas');
  const w = SCENE.container.clientWidth;
  const h = SCENE.container.clientHeight;

  SCENE.scene = new THREE.Scene();
  SCENE.scene.background = new THREE.Color(0x040408);
  SCENE.scene.fog = new THREE.Fog(0x040408, 60, 220);

  SCENE.camera = new THREE.PerspectiveCamera(38, w / h, 0.1, 500);
  SCENE.camera.position.set(50, 0, 75);

  SCENE.renderer = new THREE.WebGLRenderer({ antialias: true });
  SCENE.renderer.setSize(w, h);
  SCENE.renderer.setPixelRatio(window.devicePixelRatio);
  SCENE.container.appendChild(SCENE.renderer.domElement);

  SCENE.controls = new THREE.OrbitControls(SCENE.camera, SCENE.renderer.domElement);
  SCENE.controls.enableDamping = true;
  SCENE.controls.dampingFactor = 0.08;
  SCENE.controls.rotateSpeed = 0.7;
  SCENE.controls.panSpeed = 0.6;
  SCENE.controls.minDistance = 35;
  SCENE.controls.maxDistance = 200;
  SCENE.controls.target.set(0, 0, 0);
  SCENE.controls.autoRotate = true;
  SCENE.controls.autoRotateSpeed = 0.25;

  SCENE.scene.add(new THREE.AmbientLight(0xffffff, 0.4));
  const key = new THREE.DirectionalLight(0xffffff, 0.5);
  key.position.set(30, 50, 30);
  SCENE.scene.add(key);

  window.addEventListener('resize', onResize);
}

function onResize() {
  if (!SCENE.renderer || !SCENE.container) return;
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

// ────────────────────────────────────────────────────────────────────
// Bootstrap
// ────────────────────────────────────────────────────────────────────

function init() {
  if (typeof THREE === 'undefined') {
    document.getElementById('loading').textContent = '3D RENDERER FAILED TO LOAD';
    return;
  }
  document.getElementById('loading').style.display = 'none';
  initScene();
  animate();
}

init();
```

- [ ] **Step 2: Verify the empty scene runs**

```bash
python -m http.server 8765 -d assets/ares/
```

Open `http://localhost:8765/prism.html`.

Expected: dark canvas with no errors. Drag inside the canvas → camera orbits the empty origin (auto-rotation is also active, slow). No "LOADING TIMELINE…" text. Browser console clean.

- [ ] **Step 3: Commit**

```bash
git add assets/ares/prism.js
git commit -m "feat(prism): Three.js r128 scene scaffold + OrbitControls"
```

---

### Task 4: Build chambers + connection lines

**Files:**
- Modify: `assets/ares/prism.js`

- [ ] **Step 1: Add chamber-building helpers and call from initScene()**

Add this block to `prism.js` **above** the `// Bootstrap` section comment, and a single call to `buildChambers()` at the end of `initScene()`:

```javascript
// ────────────────────────────────────────────────────────────────────
// Chamber geometry
// ────────────────────────────────────────────────────────────────────

function makeLabelSprite(text, hexColor) {
  const cnv = document.createElement('canvas');
  cnv.width = 384; cnv.height = 64;
  const ctx = cnv.getContext('2d');
  ctx.font = '500 32px "JetBrains Mono", monospace';
  ctx.fillStyle = hexColor;
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.fillText(text, cnv.width / 2, cnv.height / 2);
  const tex = new THREE.CanvasTexture(cnv);
  tex.minFilter = THREE.LinearFilter;
  const mat = new THREE.SpriteMaterial({ map: tex, transparent: true, depthWrite: false });
  const sprite = new THREE.Sprite(mat);
  sprite.scale.set(15, 2.5, 1);
  return sprite;
}

function buildChambers() {
  for (const ch of CHAMBERS) {
    const boxGeom = new THREE.BoxGeometry(CHAMBER_W, CHAMBER_H, CHAMBER_D);
    const boxMat = new THREE.MeshStandardMaterial({
      color: ch.color,
      metalness: 0.1,
      roughness: 0.9,
      transparent: true,
      opacity: 0.04,
    });
    const box = new THREE.Mesh(boxGeom, boxMat);
    box.position.y = ch.y;
    box.userData = { chamberId: ch.id };
    SCENE.scene.add(box);
    SCENE.chamberMeshes.push(box);

    const edges = new THREE.LineSegments(
      new THREE.EdgesGeometry(boxGeom),
      new THREE.LineBasicMaterial({ color: ch.color, transparent: true, opacity: 0.35 })
    );
    edges.position.y = ch.y;
    SCENE.scene.add(edges);

    const sprite = makeLabelSprite(ch.label, hexFromColor(ch.color));
    sprite.position.set(-CHAMBER_W / 2 - 10, ch.y, 0);
    SCENE.scene.add(sprite);
  }

  // Vertical connection lines between adjacent chambers
  for (let i = 0; i < CHAMBERS.length - 1; i++) {
    const yA = CHAMBERS[i].y - CHAMBER_H / 2;
    const yB = CHAMBERS[i + 1].y + CHAMBER_H / 2;
    const geom = new THREE.BufferGeometry().setFromPoints([
      new THREE.Vector3(0, yA, 0),
      new THREE.Vector3(0, yB, 0),
    ]);
    SCENE.scene.add(new THREE.Line(
      geom,
      new THREE.LineBasicMaterial({ color: CONNECT_COLOR, transparent: true, opacity: 0.4 })
    ));
  }
}
```

In `initScene()`, add `buildChambers();` immediately after the lights are added (before `window.addEventListener('resize', onResize);`).

- [ ] **Step 2: Verify chambers visible**

```bash
python -m http.server 8765 -d assets/ares/
```

Open `http://localhost:8765/prism.html`.

Expected: six wireframe-edged slabs stacked vertically. Each labeled to the left (INPUT cyan at top, ARCHITECT amber, FIREWALL green, SKEPTIC amber, ORACLE green, VERDICT purple at bottom). Vertical lines connect them through center. Slabs are very faint (4% fill) but edges are visible.

- [ ] **Step 3: Commit**

```bash
git add assets/ares/prism.js
git commit -m "feat(prism): six chamber slabs + wireframe edges + labels + connection lines"
```

---

### Task 5: Smooth zoom override

**Files:**
- Modify: `assets/ares/prism.js`

The default OrbitControls wheel handler reads raw `deltaY` (~100 per notch on Windows), making zoom jumpy. The mockup uses a custom step-based handler.

- [ ] **Step 1: Add smooth-zoom override inside `initScene()`**

In `prism.js`, in `initScene()`, **after** the `SCENE.controls` block (after `SCENE.controls.autoRotateSpeed = 0.25;`) and before the lights are added, add:

```javascript
  // ── Smooth zoom override ──────────────────────────────────────
  SCENE.controls.enableZoom = false;
  let zoomTarget = SCENE.camera.position.distanceTo(SCENE.controls.target);
  SCENE.renderer.domElement.addEventListener('wheel', (e) => {
    e.preventDefault();
    const dir = Math.sign(e.deltaY);
    const factor = dir > 0 ? 1.06 : 0.94;
    zoomTarget = Math.max(
      SCENE.controls.minDistance,
      Math.min(SCENE.controls.maxDistance, zoomTarget * factor)
    );
  }, { passive: false });
  const originalUpdate = SCENE.controls.update.bind(SCENE.controls);
  SCENE.controls.update = function() {
    const currentDist = SCENE.camera.position.distanceTo(SCENE.controls.target);
    if (Math.abs(currentDist - zoomTarget) > 0.01) {
      const newDist = currentDist + (zoomTarget - currentDist) * 0.12;
      const dirVec = SCENE.camera.position.clone().sub(SCENE.controls.target).normalize();
      SCENE.camera.position.copy(SCENE.controls.target).add(dirVec.multiplyScalar(newDist));
    }
    return originalUpdate();
  };
```

- [ ] **Step 2: Verify smooth zoom**

```bash
python -m http.server 8765 -d assets/ares/
```

Open `http://localhost:8765/prism.html`.

Expected: scrolling the wheel zooms the camera in/out smoothly (lerped over ~10 frames), not in single big jumps. No errors.

- [ ] **Step 3: Commit**

```bash
git add assets/ares/prism.js
git commit -m "feat(prism): custom step-based smooth-zoom override"
```

---

### Task 6: Copy timeline JSON and load it in the renderer

**Files:**
- Create: `assets/ares/prism-timeline.json`
- Modify: `assets/ares/prism.js`

- [ ] **Step 1: Copy the JSON from the ARES repo**

```bash
cp "C:/ares-phase-zero/docs/marketing/prism-timeline.json" assets/ares/prism-timeline.json
```

Expected: file copied (around 100-200 KB).

- [ ] **Step 2: Verify the copied JSON parses**

```bash
python -c "import json; d = json.load(open('assets/ares/prism-timeline.json')); print(f'pairs={len(d[chr(34)+chr(112)+chr(97)+chr(105)+chr(114)+chr(115)+chr(34)])}', f'operators={d[chr(34)+chr(111)+chr(112)+chr(101)+chr(114)+chr(97)+chr(116)+chr(111)+chr(114)+chr(115)+chr(34)]}')"
```

Or simply use python with normal quoting:

```bash
python -c "import json; d=json.load(open('assets/ares/prism-timeline.json')); print('pairs:', len(d['pairs'])); print('operators:', d['operators'])"
```

Expected: `pairs: 98`, three operators listed.

- [ ] **Step 3: Add timeline loading to `prism.js`**

Add this block to `prism.js` **above** `// Bootstrap`:

```javascript
// ────────────────────────────────────────────────────────────────────
// Data loading
// ────────────────────────────────────────────────────────────────────

async function loadTimeline() {
  const res = await fetch('prism-timeline.json');
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const data = await res.json();
  if (!data || typeof data !== 'object' ||
      !Array.isArray(data.pairs) || !Array.isArray(data.operators)) {
    throw new Error('invalid timeline format');
  }
  STATE.timeline = data;
  STATE.pairs = data.pairs;
  STATE.visiblePairs = data.pairs;
  return data;
}
```

Replace the existing `init()` with an async version that loads the timeline:

```javascript
async function init() {
  if (typeof THREE === 'undefined') {
    document.getElementById('loading').textContent = '3D RENDERER FAILED TO LOAD';
    return;
  }
  try {
    await loadTimeline();
  } catch (err) {
    document.getElementById('loading').textContent = 'FAILED TO LOAD: ' + err.message;
    console.error('Prism timeline load failed:', err);
    return;
  }
  document.getElementById('loading').style.display = 'none';
  initScene();
  console.log(`Prism: loaded ${STATE.pairs.length} pairs, operators:`, STATE.timeline.operators);
  animate();
}
```

- [ ] **Step 4: Verify timeline loads**

```bash
python -m http.server 8765 -d assets/ares/
```

Open `http://localhost:8765/prism.html`. Open the browser console.

Expected: console logs `Prism: loaded 98 pairs, operators: ["framing_prefix_v1", "framing_suffix_v1", "synonym_substitution_conservative_v2"]`. Six chambers still visible. No errors.

- [ ] **Step 5: Commit**

```bash
git add assets/ares/prism-timeline.json assets/ares/prism.js
git commit -m "feat(prism): copy Session 059 timeline JSON + async loader with schema check"
```

---

### Task 7: Render crumbs (held + drift, no replay yet)

**Files:**
- Modify: `assets/ares/prism.js`

This task places 98 × 6 = 588 crumb meshes at their final positions, with the one drift crumb (broad_leakage pair, Oracle layer) at the corner of its chamber. No animation yet — all crumbs visible at full opacity.

- [ ] **Step 1: Add crumb rendering to `prism.js`**

Add this block above `// Bootstrap`:

```javascript
// ────────────────────────────────────────────────────────────────────
// Crumb placement & rendering
// ────────────────────────────────────────────────────────────────────

function isDriftChamber(pair, chamber) {
  if (!pair.broad_leakage) return false;
  const layerKey = String(pair.first_diverging_layer || '').toLowerCase();
  return LAYER_TO_CHAMBER[layerKey] === chamber.id;
}

function computeCrumbPlacements() {
  const rng = mulberry32(SEED);
  const placements = [];
  for (const pair of STATE.pairs) {
    const cycleSpawnMs = pair.pair_index * CYCLE_STAGGER_MS;
    const crumbs = CHAMBERS.map((ch, chIdx) => {
      let x = (rng() - 0.5) * (CHAMBER_W - 4);
      let y = ch.y + (rng() - 0.5) * (CHAMBER_H - 1);
      let z = (rng() - 0.5) * (CHAMBER_D - 4);
      let color = ch.color;
      let isDrift = false;
      if (isDriftChamber(pair, ch)) {
        x = 11 + rng() * 2;
        z = 11 + rng() * 2;
        color = DRIFT_COLOR;
        isDrift = true;
      }
      return {
        chamberId: ch.id,
        chamberIdx: chIdx,
        x, y, z,
        color,
        isDrift,
        activationMs: cycleSpawnMs + chIdx * CRUMB_STAGGER_MS,
      };
    });
    placements.push({ pairIndex: pair.pair_index, isDrifted: pair.broad_leakage, operator: pair.operator, crumbs });
  }
  return placements;
}

function renderCrumbs() {
  if (SCENE.pinGroup) {
    SCENE.scene.remove(SCENE.pinGroup);
  }
  SCENE.pinGroup = new THREE.Group();
  SCENE.scene.add(SCENE.pinGroup);

  const placements = computeCrumbPlacements();
  const heldGeom = new THREE.SphereGeometry(0.3, 10, 10);
  const driftGeom = new THREE.SphereGeometry(0.5, 14, 14);

  for (const cyc of placements) {
    for (const cr of cyc.crumbs) {
      const mat = new THREE.MeshStandardMaterial({
        color: cr.color,
        emissive: cr.color,
        emissiveIntensity: cr.isDrift ? 1.6 : 0.7,
        metalness: 0,
        roughness: 0.6,
        transparent: true,
        opacity: cr.isDrift ? 0.85 : 0.55,
        depthWrite: false,
      });
      const sphere = new THREE.Mesh(cr.isDrift ? driftGeom : heldGeom, mat);
      sphere.position.set(cr.x, cr.y, cr.z);
      sphere.userData = {
        pairIndex: cyc.pairIndex,
        chamberId: cr.chamberId,
        isDrift: cr.isDrift,
        activationMs: cr.activationMs,
        operator: cyc.operator,
      };
      SCENE.pinGroup.add(sphere);
    }
  }
}
```

Call `renderCrumbs()` from `init()` after `initScene()`:

```javascript
async function init() {
  if (typeof THREE === 'undefined') {
    document.getElementById('loading').textContent = '3D RENDERER FAILED TO LOAD';
    return;
  }
  try {
    await loadTimeline();
  } catch (err) {
    document.getElementById('loading').textContent = 'FAILED TO LOAD: ' + err.message;
    console.error('Prism timeline load failed:', err);
    return;
  }
  document.getElementById('loading').style.display = 'none';
  initScene();
  renderCrumbs();
  console.log(`Prism: loaded ${STATE.pairs.length} pairs, operators:`, STATE.timeline.operators);
  animate();
}
```

- [ ] **Step 2: Verify crumbs render**

```bash
python -m http.server 8765 -d assets/ares/
```

Open `http://localhost:8765/prism.html`.

Expected: 98 × 6 = 588 small spheres scattered inside the six chambers, colored per chamber. Exactly ONE crumb is red and visibly off to the corner of the **Architect** slab (not Oracle — the Session 059 data has `first_diverging_layer="Architect"` for the single broad-leakage pair, INJ-001 framing_suffix_v1 at pair_index 1; the validated mockup hardcoded Oracle as a storytelling shortcut, but the renderer is data-driven per spec § 4). Rotate the camera — drift crumb stays distinctly out of cluster.

- [ ] **Step 3: Commit**

```bash
git add assets/ares/prism.js
git commit -m "feat(prism): render 588 crumbs at final positions with drift corner signature"
```

---

### Task 8: Replay loop + stats overlay

**Files:**
- Modify: `assets/ares/prism.js`

Now animate the crumbs: they fade in sequentially per the timeline. Stats panel updates live.

- [ ] **Step 1: Refactor renderCrumbs to set initial opacity to 0**

In `prism.js`, in `renderCrumbs()`, change the material creation to start invisible:

Find:
```javascript
        transparent: true,
        opacity: cr.isDrift ? 0.85 : 0.55,
        depthWrite: false,
```

Change to:
```javascript
        transparent: true,
        opacity: 0,
        depthWrite: false,
```

This means crumbs are invisible until the replay loop ramps them in.

- [ ] **Step 2: Add the replay tick function**

Add this block above `// Bootstrap`:

```javascript
// ────────────────────────────────────────────────────────────────────
// Replay loop
// ────────────────────────────────────────────────────────────────────

let replayStartTime = 0;
let replayTotalRuntimeMs = 0;

function recomputeReplayRuntime() {
  // Loop length is anchored to the MAX pair_index in the dataset (not the
  // pair count). pair_index values can have gaps because the upstream
  // pipeline drops no-op pairs while preserving the global enumeration
  // (Session 058.5: synonym_substitution_conservative_v2 has 1 no-op).
  // Using pair count would truncate the last pair's activation slot.
  // Filter affects visibility, not timeline length — filtered cycles
  // activate at their original slots and just stay invisible.
  if (STATE.pairs.length === 0) {
    replayTotalRuntimeMs = 0;
    return;
  }
  const maxPairIndex = STATE.pairs.reduce((m, p) => Math.max(m, p.pair_index), 0);
  const maxActivation = maxPairIndex * CYCLE_STAGGER_MS + CHAMBERS.length * CRUMB_STAGGER_MS;
  replayTotalRuntimeMs = maxActivation + REPLAY_PAUSE_MS;
}

function visiblePairIndexSet() {
  const set = new Set();
  for (const p of STATE.visiblePairs) set.add(p.pair_index);
  return set;
}

function tickReplay() {
  if (!SCENE.pinGroup || replayTotalRuntimeMs === 0) return;
  let t;
  if (STATE.autoplayRunning) {
    t = performance.now() - replayStartTime;
    if (t > replayTotalRuntimeMs) {
      replayStartTime = performance.now();
      t = 0;
    }
    STATE.activeCycleIndex = Math.floor(t / CYCLE_STAGGER_MS);
  } else {
    t = STATE.activeCycleIndex * CYCLE_STAGGER_MS + CHAMBERS.length * CRUMB_STAGGER_MS;
  }

  const visible = visiblePairIndexSet();
  let heldCount = 0;
  let driftCount = 0;

  SCENE.pinGroup.children.forEach((pin) => {
    const ud = pin.userData;
    if (!visible.has(ud.pairIndex)) {
      pin.material.opacity = 0;
      return;
    }
    const dt = t - ud.activationMs;
    if (dt < 0) {
      pin.material.opacity = 0;
    } else if (dt < OPACITY_RAMP_MS) {
      const k = dt / OPACITY_RAMP_MS;
      pin.material.opacity = k * (ud.isDrift ? 0.85 : 0.55);
      pin.material.emissiveIntensity = (ud.isDrift ? 1.6 : 0.7) * (1 + (1 - k) * 1.5);
    } else {
      pin.material.opacity = ud.isDrift ? 0.85 : 0.55;
      pin.material.emissiveIntensity = ud.isDrift ? 1.4 : 0.5;
    }
  });

  // Stats: count pairs whose final crumb has activated (chamber index 5)
  for (const pair of STATE.visiblePairs) {
    const finalActivation = pair.pair_index * CYCLE_STAGGER_MS + (CHAMBERS.length - 1) * CRUMB_STAGGER_MS;
    if (t >= finalActivation) {
      if (pair.broad_leakage) driftCount++;
      else heldCount++;
    }
  }
  const total = STATE.visiblePairs.length;
  const completed = heldCount + driftCount;
  document.getElementById('stat-cycles').textContent = `${completed}/${total}`;
  document.getElementById('stat-held').textContent = String(heldCount);
  document.getElementById('stat-drift').textContent = String(driftCount);
}
```

- [ ] **Step 3: Wire `tickReplay()` into the animate loop**

Update `animate()`:

```javascript
function animate() {
  requestAnimationFrame(animate);
  tickReplay();
  if (SCENE.controls) SCENE.controls.update();
  if (SCENE.renderer && SCENE.scene && SCENE.camera) {
    SCENE.renderer.render(SCENE.scene, SCENE.camera);
  }
}
```

- [ ] **Step 4: Initialize replay timing in `init()`**

In the existing `init()`, after `renderCrumbs();` add:

```javascript
  recomputeReplayRuntime();
  replayStartTime = performance.now();
```

So `init()` reads as:

```javascript
async function init() {
  if (typeof THREE === 'undefined') {
    document.getElementById('loading').textContent = '3D RENDERER FAILED TO LOAD';
    return;
  }
  try {
    await loadTimeline();
  } catch (err) {
    document.getElementById('loading').textContent = 'FAILED TO LOAD: ' + err.message;
    console.error('Prism timeline load failed:', err);
    return;
  }
  document.getElementById('loading').style.display = 'none';
  initScene();
  renderCrumbs();
  recomputeReplayRuntime();
  replayStartTime = performance.now();
  console.log(`Prism: loaded ${STATE.pairs.length} pairs, operators:`, STATE.timeline.operators);
  animate();
}
```

- [ ] **Step 5: Verify replay animates**

```bash
python -m http.server 8765 -d assets/ares/
```

Open `http://localhost:8765/prism.html`.

Expected: page loads empty (crumbs at opacity 0). Cycles start dropping in sequentially — top chamber first, working down. The drift pair is pair_index 1 (INJ-001 framing_suffix_v1), so the red drift crumb appears very early in the replay (~240ms in, at the corner of the Architect slab). Stats panel ticks `cycles: N/98 · held: H · drifted: 0` then `drifted: 1` once the drift pair's final-chamber crumb lands. Replay loops after ~30s (max pair_index is 99 due to documented index gaps; runtime is `99 × 240ms + 6 × 180ms + 5000ms ≈ 30s`).

- [ ] **Step 6: Commit**

```bash
git add assets/ares/prism.js
git commit -m "feat(prism): cinematic replay loop with opacity ramp + live stats overlay"
```

---

### Task 9: Cycle trail lines

**Files:**
- Modify: `assets/ares/prism.js`

Each cycle's six crumbs connect into a trail line — dim grey for held, brighter red for drift.

- [ ] **Step 1: Extend `renderCrumbs` to build trail lines per cycle**

In `prism.js`, modify `renderCrumbs()` to also build trail lines. Replace the entire `renderCrumbs()` function with:

```javascript
function renderCrumbs() {
  if (SCENE.pinGroup) SCENE.scene.remove(SCENE.pinGroup);
  if (SCENE.trailGroup) SCENE.scene.remove(SCENE.trailGroup);
  SCENE.pinGroup = new THREE.Group();
  SCENE.trailGroup = new THREE.Group();
  SCENE.scene.add(SCENE.pinGroup);
  SCENE.scene.add(SCENE.trailGroup);

  const placements = computeCrumbPlacements();
  const heldGeom = new THREE.SphereGeometry(0.3, 10, 10);
  const driftGeom = new THREE.SphereGeometry(0.5, 14, 14);

  for (const cyc of placements) {
    // Trail line connecting all six crumbs in this cycle
    const trailPositions = new Float32Array(CHAMBERS.length * 3);
    for (let i = 0; i < cyc.crumbs.length; i++) {
      const cr = cyc.crumbs[i];
      trailPositions[i * 3 + 0] = cr.x;
      trailPositions[i * 3 + 1] = cr.y;
      trailPositions[i * 3 + 2] = cr.z;
    }
    const trailGeom = new THREE.BufferGeometry();
    trailGeom.setAttribute('position', new THREE.BufferAttribute(trailPositions, 3));
    const trail = new THREE.Line(
      trailGeom,
      new THREE.LineBasicMaterial({
        color: cyc.isDrifted ? DRIFT_TRAIL : HELD_TRAIL,
        transparent: true,
        opacity: cyc.isDrifted ? 0.55 : 0.12,
      })
    );
    trail.userData = { pairIndex: cyc.pairIndex };
    SCENE.trailGroup.add(trail);

    // Crumbs
    for (const cr of cyc.crumbs) {
      const mat = new THREE.MeshStandardMaterial({
        color: cr.color,
        emissive: cr.color,
        emissiveIntensity: cr.isDrift ? 1.6 : 0.7,
        metalness: 0,
        roughness: 0.6,
        transparent: true,
        opacity: 0,
        depthWrite: false,
      });
      const sphere = new THREE.Mesh(cr.isDrift ? driftGeom : heldGeom, mat);
      sphere.position.set(cr.x, cr.y, cr.z);
      sphere.userData = {
        pairIndex: cyc.pairIndex,
        chamberId: cr.chamberId,
        isDrift: cr.isDrift,
        activationMs: cr.activationMs,
        operator: cyc.operator,
      };
      SCENE.pinGroup.add(sphere);
    }
  }
}
```

Trail lines render at full geometry up-front but their visual prominence is low (12% opacity on held trails). The drift trail at 55% reads as a brighter red line.

- [ ] **Step 2: Verify trails visible**

```bash
python -m http.server 8765 -d assets/ares/
```

Open `http://localhost:8765/prism.html`.

Expected: same replay as before, with faint grey trail lines connecting each cycle's six crumbs through the chambers. One trail is clearly brighter red (the drift pair) — visually traces straight down through the chambers then forks off to the corner at Oracle.

- [ ] **Step 3: Commit**

```bash
git add assets/ares/prism.js
git commit -m "feat(prism): per-cycle trail lines (held dim, drift accented)"
```

---

### Task 10: Scrubber + play/pause button

**Files:**
- Modify: `assets/ares/prism.js`

The scrubber jumps the replay to a specific cycle and pauses autoplay. Play button resumes from current position.

- [ ] **Step 1: Add control-wiring functions**

Add this block above `// Bootstrap`:

```javascript
// ────────────────────────────────────────────────────────────────────
// Controls
// ────────────────────────────────────────────────────────────────────

function wireScrubber() {
  const scr = document.getElementById('scrubber');
  scr.min = '0';
  scr.max = String(Math.max(0, STATE.visiblePairs.length - 1));
  scr.value = '0';
  scr.addEventListener('input', () => {
    STATE.autoplayRunning = false;
    STATE.activeCycleIndex = parseInt(scr.value, 10);
    setPlayPauseLabel();
  });
}

function setPlayPauseLabel() {
  const btn = document.getElementById('play-pause');
  btn.textContent = STATE.autoplayRunning ? 'PAUSE' : 'PLAY';
}

function wirePlayPause() {
  const btn = document.getElementById('play-pause');
  btn.addEventListener('click', () => {
    STATE.autoplayRunning = !STATE.autoplayRunning;
    if (STATE.autoplayRunning) {
      // Resume autoplay from the current scrubber position
      const offsetMs = STATE.activeCycleIndex * CYCLE_STAGGER_MS;
      replayStartTime = performance.now() - offsetMs;
    }
    setPlayPauseLabel();
  });
}
```

- [ ] **Step 2: Sync scrubber position back to UI during autoplay**

In `tickReplay()`, after `STATE.activeCycleIndex = Math.floor(t / CYCLE_STAGGER_MS);`, add a sync line so the scrubber slider visually follows autoplay:

```javascript
    document.getElementById('scrubber').value = String(STATE.activeCycleIndex);
```

The complete `tickReplay()` autoplay branch becomes:

```javascript
  if (STATE.autoplayRunning) {
    t = performance.now() - replayStartTime;
    if (t > replayTotalRuntimeMs) {
      replayStartTime = performance.now();
      t = 0;
    }
    STATE.activeCycleIndex = Math.floor(t / CYCLE_STAGGER_MS);
    document.getElementById('scrubber').value = String(STATE.activeCycleIndex);
  }
```

- [ ] **Step 3: Call control wirers from `init()`**

In `init()`, after `recomputeReplayRuntime();` and `replayStartTime = performance.now();`, add:

```javascript
  wireScrubber();
  wirePlayPause();
  setPlayPauseLabel();
```

- [ ] **Step 4: Verify scrubber + play/pause**

```bash
python -m http.server 8765 -d assets/ares/
```

Open `http://localhost:8765/prism.html`.

Expected:
- On load, button reads `PAUSE`, scrubber crawls right as autoplay advances
- Drag the scrubber → autoplay pauses, button label changes to `PLAY`, scene jumps to that cycle
- Click `PLAY` → autoplay resumes from the scrubber position
- Click `PAUSE` again → freezes scene

- [ ] **Step 5: Commit**

```bash
git add assets/ares/prism.js
git commit -m "feat(prism): scrubber + play/pause button with autoplay state machine"
```

---

### Task 11: Operator dial

**Files:**
- Modify: `assets/ares/prism.js`

Filter the visible pair set by operator. Re-renders crumbs and resets the replay loop.

- [ ] **Step 1: Add `wireOperatorDial()` and `applyOperatorFilter()`**

Add to the `// Controls` block (above `// Bootstrap`):

```javascript
function applyOperatorFilter() {
  // Filter controls visibility only — timeline + positions are anchored to
  // the full 98-pair ordering. Crumb meshes are not re-created on filter
  // change; we just update which ones tickReplay considers visible.
  if (STATE.operatorFilter === 'all') {
    STATE.visiblePairs = STATE.pairs;
  } else {
    STATE.visiblePairs = STATE.pairs.filter((p) => p.operator === STATE.operatorFilter);
  }
  // Show/hide trail lines per filter
  const visibleSet = new Set(STATE.visiblePairs.map((p) => p.pair_index));
  SCENE.trailGroup.children.forEach((trail) => {
    if (visibleSet.has(trail.userData.pairIndex)) {
      const pair = STATE.pairs[trail.userData.pairIndex];
      trail.material.opacity = pair && pair.broad_leakage ? 0.55 : 0.12;
    } else {
      trail.material.opacity = 0;
    }
  });
  // Reset replay to the start so the user sees the full filtered sequence
  replayStartTime = performance.now();
  STATE.activeCycleIndex = 0;
  STATE.autoplayRunning = true;
  setPlayPauseLabel();
  document.getElementById('scrubber').value = '0';
}

function populateOperatorDial() {
  const sel = document.getElementById('operator-dial');
  for (const op of STATE.timeline.operators) {
    const opt = document.createElement('option');
    opt.value = op;
    opt.textContent = op;
    sel.appendChild(opt);
  }
}

function wireOperatorDial() {
  const sel = document.getElementById('operator-dial');
  sel.addEventListener('change', () => {
    STATE.operatorFilter = sel.value;
    applyOperatorFilter();
  });
}
```

- [ ] **Step 2: Call from `init()`**

In `init()`, after `renderCrumbs();` and BEFORE `recomputeReplayRuntime();`, add:

```javascript
  populateOperatorDial();
```

And after the other wirers:

```javascript
  wireOperatorDial();
```

Final `init()`:

```javascript
async function init() {
  if (typeof THREE === 'undefined') {
    document.getElementById('loading').textContent = '3D RENDERER FAILED TO LOAD';
    return;
  }
  try {
    await loadTimeline();
  } catch (err) {
    document.getElementById('loading').textContent = 'FAILED TO LOAD: ' + err.message;
    console.error('Prism timeline load failed:', err);
    return;
  }
  document.getElementById('loading').style.display = 'none';
  initScene();
  renderCrumbs();
  populateOperatorDial();
  recomputeReplayRuntime();
  replayStartTime = performance.now();
  wireScrubber();
  wirePlayPause();
  wireOperatorDial();
  setPlayPauseLabel();
  console.log(`Prism: loaded ${STATE.pairs.length} pairs, operators:`, STATE.timeline.operators);
  animate();
}
```

- [ ] **Step 3: No loadTimeline change required**

`STATE.visiblePairs = data.pairs;` (set in Task 6) is correct for the simpler design. No re-indexing — `pair_index` stays as the original index throughout the lifetime of the page, so crumb userData remains valid across filter switches. Skip ahead to verification.

- [ ] **Step 4: Verify operator dial**

```bash
python -m http.server 8765 -d assets/ares/
```

Open `http://localhost:8765/prism.html`.

Expected:
- Operator `<select>` populated with 4 options: "All operators", "framing_prefix_v1", "framing_suffix_v1", "synonym_substitution_conservative_v2"
- Select `framing_prefix_v1` → scene resets, ~33 visible pairs activate over the ~24s loop (filtered-out pairs leave visible gaps in time), NO drift crumb (drift is on `framing_suffix_v1`)
- Select `framing_suffix_v1` → ~33 visible pairs activate over the ~24s loop, drift crumb appears
- Select `synonym_substitution_conservative_v2` → ~32 visible pairs activate, NO drift crumb
- Select `All operators` → back to all 98, dense activation across the full loop
- Stats panel `cycles: N/<visible count>` (denominator changes with filter)

- [ ] **Step 5: Commit**

```bash
git add assets/ares/prism.js
git commit -m "feat(prism): operator dial filters cycle set, resets replay"
```

---

### Task 12: Click-to-focus on a cycle

**Files:**
- Modify: `assets/ares/prism.js`

- [ ] **Step 1: Add raycaster-based click handling**

Add this block to the `// Controls` section (above `// Bootstrap`):

```javascript
const RAYCASTER = new THREE.Raycaster();
const POINTER = new THREE.Vector2();

function focusCycle(pairIndex) {
  STATE.focusedPairIndex = pairIndex;
  SCENE.pinGroup.children.forEach((pin) => {
    if (pin.userData.pairIndex === pairIndex) {
      pin.material.opacity = 1.0;
      pin.material.emissiveIntensity = pin.userData.isDrift ? 2.0 : 1.4;
    } else {
      pin.material.opacity = 0.06;
      pin.material.emissiveIntensity = 0.1;
    }
  });
  SCENE.trailGroup.children.forEach((trail) => {
    trail.material.opacity = (trail.userData.pairIndex === pairIndex) ? 0.9 : 0.04;
  });
}

function clearFocus() {
  STATE.focusedPairIndex = null;
  // Let tickReplay() restore opacity on next frame
}

function onCanvasClick(event) {
  const rect = SCENE.renderer.domElement.getBoundingClientRect();
  POINTER.x = ((event.clientX - rect.left) / rect.width) * 2 - 1;
  POINTER.y = -((event.clientY - rect.top) / rect.height) * 2 + 1;
  RAYCASTER.setFromCamera(POINTER, SCENE.camera);
  const hits = RAYCASTER.intersectObjects(SCENE.pinGroup.children);
  if (hits.length === 0) {
    clearFocus();
    return;
  }
  focusCycle(hits[0].object.userData.pairIndex);
}

function onKeyDown(event) {
  if (event.key === 'Escape') clearFocus();
}

function wireCanvasClick() {
  SCENE.renderer.domElement.addEventListener('click', onCanvasClick);
  window.addEventListener('keydown', onKeyDown);
}
```

- [ ] **Step 2: Skip the replay opacity update when a cycle is focused**

In `tickReplay()`, wrap the `SCENE.pinGroup.children.forEach(...)` block so it bails when focus is active:

```javascript
  if (STATE.focusedPairIndex === null) {
    SCENE.pinGroup.children.forEach((pin) => {
      // ...existing opacity-ramp logic...
    });
  }
```

The complete updated forEach section:

```javascript
  if (STATE.focusedPairIndex === null) {
    SCENE.pinGroup.children.forEach((pin) => {
      const ud = pin.userData;
      if (!visible.has(ud.pairIndex)) {
        pin.material.opacity = 0;
        return;
      }
      const dt = t - ud.activationMs;
      if (dt < 0) {
        pin.material.opacity = 0;
      } else if (dt < OPACITY_RAMP_MS) {
        const k = dt / OPACITY_RAMP_MS;
        pin.material.opacity = k * (ud.isDrift ? 0.85 : 0.55);
        pin.material.emissiveIntensity = (ud.isDrift ? 1.6 : 0.7) * (1 + (1 - k) * 1.5);
      } else {
        pin.material.opacity = ud.isDrift ? 0.85 : 0.55;
        pin.material.emissiveIntensity = ud.isDrift ? 1.4 : 0.5;
      }
    });
  }
```

- [ ] **Step 3: Wire from `init()`**

In `init()`, after `wireOperatorDial();`, add:

```javascript
  wireCanvasClick();
```

- [ ] **Step 4: Verify click-to-focus**

```bash
python -m http.server 8765 -d assets/ares/
```

Open `http://localhost:8765/prism.html`.

Expected:
- Wait for replay to fill in some crumbs, then click on one — that pair's six crumbs and trail brighten to full opacity; all other pairs fade to ~6% opacity
- Click on empty space → all crumbs return to replay state
- Press Esc → same as clicking empty space
- Try clicking the red drift crumb specifically → that cycle's trail is fully isolated (visibly the only path through the chambers)

- [ ] **Step 5: Commit**

```bash
git add assets/ares/prism.js
git commit -m "feat(prism): raycaster click-to-focus + Esc to clear"
```

---

### Task 13: prefers-reduced-motion gate

**Files:**
- Modify: `assets/ares/prism.js`

When the user has system-level reduced-motion preference, autoplay and orbit auto-rotation should be disabled. The scene renders all crumbs at final opacity immediately. Scrubber and dial still work.

- [ ] **Step 1: Add reduced-motion detection and application**

Add this to the top of `prism.js`, right after the `'use strict';` line:

```javascript
const PREFERS_REDUCED_MOTION = (
  typeof window !== 'undefined' &&
  window.matchMedia &&
  window.matchMedia('(prefers-reduced-motion: reduce)').matches
);
```

- [ ] **Step 2: Apply reduced-motion in `initScene` and `init`**

In `initScene()`, after `SCENE.controls.autoRotateSpeed = 0.25;`, add:

```javascript
  if (PREFERS_REDUCED_MOTION) {
    SCENE.controls.autoRotate = false;
  }
```

In `init()`, after `wireCanvasClick();`, add:

```javascript
  if (PREFERS_REDUCED_MOTION) {
    STATE.autoplayRunning = false;
    STATE.activeCycleIndex = STATE.visiblePairs.length - 1;
    setPlayPauseLabel();
    const scr = document.getElementById('scrubber');
    scr.value = String(STATE.activeCycleIndex);
  }
```

This sets the scene to "all cycles fully rendered" on load when reduced-motion is preferred. The user can still scrub backwards to explore.

- [ ] **Step 3: Verify reduced-motion gate**

```bash
python -m http.server 8765 -d assets/ares/
```

Open Chrome DevTools → Cmd/Ctrl+Shift+P → "Emulate CSS prefers-reduced-motion" → select "reduce". Reload `http://localhost:8765/prism.html`.

Expected:
- All 98 cycles rendered immediately at full opacity (no fade-in)
- Camera is NOT auto-rotating
- Stats panel reads `cycles: 98/98 · held: 97 · drifted: 1`
- Play/Pause button reads `PLAY` (autoplay paused)
- Scrubber works (drag back → fewer cycles visible)
- Operator dial works (filters set)

Then disable the emulation, reload — autoplay returns.

- [ ] **Step 4: Commit**

```bash
git add assets/ares/prism.js
git commit -m "feat(prism): prefers-reduced-motion gate (no autoplay, no auto-rotate)"
```

---

### Task 14: Final error-handling paths

**Files:**
- Modify: `assets/ares/prism.js`

Most error handling is in place from earlier tasks (THREE undefined check, fetch try/catch, JSON shape validation). This task adds the WebGL fallback and a small safety check.

- [ ] **Step 1: Add WebGL availability check inside `initScene`**

In `initScene()`, immediately after `SCENE.renderer = new THREE.WebGLRenderer({ antialias: true });`, add:

```javascript
  if (!SCENE.renderer.getContext()) {
    SCENE.container.innerHTML = '<div id="loading">3D RENDERER FAILED TO LOAD</div>';
    throw new Error('WebGL unavailable');
  }
```

- [ ] **Step 2: Wrap the `initScene` call in `init` to catch the WebGL failure**

Modify `init()` to catch `initScene()` failures:

```javascript
async function init() {
  if (typeof THREE === 'undefined') {
    document.getElementById('loading').textContent = '3D RENDERER FAILED TO LOAD';
    return;
  }
  try {
    await loadTimeline();
  } catch (err) {
    document.getElementById('loading').textContent = 'FAILED TO LOAD: ' + err.message;
    console.error('Prism timeline load failed:', err);
    return;
  }
  document.getElementById('loading').style.display = 'none';
  try {
    initScene();
  } catch (err) {
    console.error('Prism scene init failed:', err);
    return;
  }
  renderCrumbs();
  populateOperatorDial();
  recomputeReplayRuntime();
  replayStartTime = performance.now();
  wireScrubber();
  wirePlayPause();
  wireOperatorDial();
  wireCanvasClick();
  setPlayPauseLabel();
  if (PREFERS_REDUCED_MOTION) {
    STATE.autoplayRunning = false;
    STATE.activeCycleIndex = STATE.visiblePairs.length - 1;
    setPlayPauseLabel();
    document.getElementById('scrubber').value = String(STATE.activeCycleIndex);
  }
  console.log(`Prism: loaded ${STATE.pairs.length} pairs, operators:`, STATE.timeline.operators);
  animate();
}
```

- [ ] **Step 3: Verify no regression**

```bash
python -m http.server 8765 -d assets/ares/
```

Open `http://localhost:8765/prism.html`. Confirm scene still renders normally — no behavior change for WebGL-capable browsers.

(WebGL-disabled testing requires a browser flag; we don't need to actually exercise the fallback path here, only confirm the happy path is unaffected.)

- [ ] **Step 4: Commit**

```bash
git add assets/ares/prism.js
git commit -m "feat(prism): WebGL availability check + initScene error containment"
```

---

### Task 15: ares.html CTA link

**Files:**
- Modify: `assets/ares/ares.html`

Add a second CTA link to the Prism page next to the existing Pinscreen CTA.

- [ ] **Step 1: Locate the existing Pinscreen CTA in ares.html**

```bash
grep -n "pinscreen" assets/ares/ares.html
```

Note the line numbers and surrounding HTML so the second link uses the same markup style.

- [ ] **Step 2: Add the Prism CTA next to the Pinscreen CTA**

Open `assets/ares/ares.html` and find the Pinscreen `<a>` link. Add a sibling `<a>` link pointing to `prism.html` immediately after it, mirroring the existing class names and surrounding markup. Example pattern (substitute your file's actual classes/structure):

```html
<a href="pinscreen.html" class="ares-cta-link">view the Pinscreen</a>
<a href="prism.html" class="ares-cta-link">view the Prism</a>
```

If the existing link is inside a flexbox / gap container, place the new one in the same container.

- [ ] **Step 3: Verify locally**

```bash
python -m http.server 8765 -d assets/ares/
```

Open `http://localhost:8765/ares.html`. Find the Pinscreen CTA visually. Confirm:
- A second link to "Prism" (or equivalent label) sits next to it
- Clicking it navigates to `prism.html`
- Clicking the original Pinscreen CTA still navigates to `pinscreen.html`

- [ ] **Step 4: Commit**

```bash
git add assets/ares/ares.html
git commit -m "feat(ares.html): add Prism CTA link next to Pinscreen"
```

---

## Phase C — Local verification

### Task 16: Walk the 12-point manual checklist

**Files:** (no edits — verification only)

- [ ] **Step 1: Serve `assets/ares/` locally**

```bash
python -m http.server 8765 -d assets/ares/
```

- [ ] **Step 2: Walk the checklist from the spec § 5**

Open `http://localhost:8765/prism.html` and confirm each item:

1. Scene loads, no JS console errors
2. Six chambers visible with wireframe edges + labels
3. Crumbs appear sequentially via autoplay (~30s full loop including 5s pause, then resets — runtime anchored to max pair_index of 99, not pair count, since the JSON has documented index gaps)
4. The single drift crumb is red, at the corner of the **Architect** slab (data-driven; see Task 7 step 2 note), visibly off-cluster
5. Stats panel ticks `cycles: N/98 · held: H · drifted: D` — `D` rises from 0 to 1 as the drift pair lands
6. Drag-to-orbit works; scroll smooth-zooms; auto-rotate cycles slowly
7. Scrubber moves → autoplay pauses → scrubber position is source of truth
8. Operator dial filters to ~33 pairs per selection; drift only appears when `framing_suffix_v1` is the filter (or `all`)
9. Click a crumb → that pair's trail isolates; other trails dim to ~6% opacity
10. Esc or click empty space → focus clears
11. Mobile-width viewport (<1100px): panel switches to 92vw, controls usable (use DevTools device emulation)
12. `prefers-reduced-motion` (DevTools emulation): autoplay + auto-rotate disabled; static state with scrubber working

If any item fails, identify the regression, fix it, and re-run from Step 1.

- [ ] **Step 3: Test ares.html CTA link**

Open `http://localhost:8765/ares.html`. Click the new Prism CTA → loads `prism.html`. Click back to Pinscreen → loads `pinscreen.html`.

- [ ] **Step 4: Stop the local server**

Ctrl+C in the terminal running `python -m http.server`.

No commit needed for verification.

---

## Phase D — Deploy and finalize

### Task 17: Push skyframe-main and verify live

**Files:** (no edits — deploy only)

- [ ] **Step 1: Confirm clean state**

```bash
git status
```

Expected: nothing to commit, branch `main` ahead of `origin/main` by 4 commits (HTML chrome + scene scaffold consolidated, chambers, smooth zoom, JSON+load, crumbs, replay, trails, scrubber+playpause, operator dial, click focus, reduced-motion, error handling, CTA — the actual commit count depends on which tasks landed as separate commits).

- [ ] **Step 2: Push to origin/main**

```bash
git push origin main
```

Expected: pushes successfully. Netlify webhook fires; deploy starts.

- [ ] **Step 3: Wait for Netlify deploy (~60s) and verify live URL**

Open the Netlify dashboard or visit the production URL for `/ares/prism.html`. Walk the same 12-point checklist from Task 16 against the live URL.

Critical live-only checks:
- The page actually loads at the production domain
- `prism-timeline.json` fetches successfully (correct relative path: same directory as the HTML)
- The CTA link in `/ares/ares.html` routes correctly

If anything is broken:
```bash
# Roll back the breaking commit
git revert <commit_sha>
git push origin main
```

Netlify re-deploys in ~60s.

- [ ] **Step 4: No commit needed** — deploy is the artifact.

---

### Task 18: ARES — CLAUDE.md update + branch close

> **Switch back to ARES:** `cd C:/ares-phase-zero`. All remaining work is in this repo.

**Files:**
- Modify: `CLAUDE.md`

- [ ] **Step 1: Update CLAUDE.md test floor**

In `CLAUDE.md`, find the line:

```
**Test count floor (passing):** 3,725
```

Change to:

```
**Test count floor (passing):** 3,733
```

- [ ] **Step 2: Update CLAUDE.md last-updated date**

In `CLAUDE.md`, find the line:

```
**Last updated:** 2026-05-14
```

Change to:

```
**Last updated:** 2026-05-19
```

- [ ] **Step 3: Add a new Session 062 entry**

In `CLAUDE.md`, find the existing session log entries (most recent is `## Session 060 — Narrow-reading characterization extension` or the Session 061 entry). Add a new entry **after the most recent existing session** with this content:

```markdown
## Session 062 — Prism Labyrinth (Panel 1) renderer
- Origin: Phase A pipeline (cycle_trace.py + cycle_trace_builder.py + build_cycle_timeline.py + prism-timeline.json) shipped earlier on `session/062-prism-labyrinth`. Phase B/C (renderer) was attempted as a sphere-chain and parked 2026-05-14 because it diverged from the validated 2026-05-13 mockup. Session 062 re-ideated the renderer as a faithful port of the mockup against real Session 059 data.
- Direction: autoplay-first interaction with scrubber-takes-over on user touch. Six stacked translucent chamber slabs (INPUT → ARCHITECT → FIREWALL → SKEPTIC → ORACLE → VERDICT) with wireframe edges. 98 cycles drop breadcrumbs through the chambers in a 240ms-staggered replay loop; the one `broad_leakage=True` pair surfaces a red corner crumb at the chamber matching its `first_diverging_layer` (Oracle in the current dataset).
- Architecture (Approach 2 from the brainstorm): HTML shell + companion `prism.js` classic script. r128 stack matching `pinscreen.html`. Two-file deploy to skyframe-main + one CTA link addition.
- New ARES file: `ares/dialectic/tests/visualization/test_prism_timeline_json_contract.py` — 8 tests locking the JSON schema as a regression guard so that a future pipeline regen with renamed fields fails fast on the ARES side, not silently in the browser.
- New skyframe-main files: `assets/ares/prism.html`, `assets/ares/prism.js`, `assets/ares/prism-timeline.json`. Modified: `assets/ares/ares.html` (added second CTA link next to Pinscreen).
- The parked sphere-chain attempt is preserved at `docs/marketing/prism-2026-05-14-sphere-chain.html` per [[mockup-preservation]] discipline. The Phase A pipeline emits a renderer-agnostic JSON, so the parked artifact still loads if opened.
- Floor raised 3,725 → 3,733; actual collected count 3,725 → 3,733. Zero regressions. ARES side adds 1 new test file; no edits to existing `ares/` code outside `CLAUDE.md`.
```

- [ ] **Step 4: Add Session 062 sub-heading to Key Code Locations**

In `CLAUDE.md`, find the `### Visualization (Phase 7 / Session 061)` heading inside `## Key Code Locations`. Add a sibling heading **after** it:

```markdown
### Visualization (Phase 7 / Session 062)
- Renderer (skyframe-main): `assets/ares/prism.html` (chrome) + `assets/ares/prism.js` (scene + behavior, ~600 lines) + `assets/ares/prism-timeline.json` (copy of ARES-generated JSON)
- ARES JSON contract test: `ares/dialectic/tests/visualization/test_prism_timeline_json_contract.py`
- ares.html CTA wiring: `assets/ares/ares.html` (Prism link next to Pinscreen)
- Spec: `docs/superpowers/specs/2026-05-19-prism-labyrinth-renderer-v2-design.md`
- Plan: `docs/superpowers/plans/2026-05-19-prism-labyrinth-renderer-v2.md`
- Parked sphere-chain attempt (do not regress to): `docs/marketing/prism-2026-05-14-sphere-chain.html`
```

- [ ] **Step 5: Update the "Where We Are" current-status bullet**

In `CLAUDE.md`, find the last bullet in `## Where We Are`. After it, append a new bullet:

```markdown
- Session 062: Prism Labyrinth (Panel 1) renderer — production page at `skyframe-main/assets/ares/prism.html`, faithful port of the 2026-05-13 mockup against Session 059 data (98 cycles, 97 held / 1 drifted at Oracle). Autoplay-first replay with scrubber takeover; full-kit interactivity (scrubber + operator dial + play/pause + click-to-focus). The 2026-05-14 sphere-chain attempt remains parked as a dated learning artifact per mockup-preservation discipline.
```

- [ ] **Step 6: Run the full test suite**

```bash
pytest ares/dialectic/tests/ -q
```

Expected: collected ≥ 3,733, zero failures. `test_claude_md_freshness.py` should pass (floor and date now match).

- [ ] **Step 7: Commit the CLAUDE.md update**

```bash
git add CLAUDE.md
git commit -m "$(cat <<'EOF'
chore(claude-md): Session 062 entry + test floor 3,725 -> 3,733 + key code locations

Records Session 062 Prism Labyrinth (Panel 1) renderer build: faithful port
of the 2026-05-13 mockup against Session 059 data, after the 2026-05-14
sphere-chain attempt diverged and was parked. ARES adds 1 JSON contract
test file (8 tests). skyframe-main adds prism.html + prism.js + JSON copy
+ ares.html CTA wiring.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

- [ ] **Step 8: Squash-merge to main**

```bash
git checkout main
git pull origin main
git merge --squash session/062-prism-labyrinth
git commit -m "$(cat <<'EOF'
Session 062: Prism Labyrinth (Panel 1) renderer (squash)

Faithful port of the 2026-05-13 mockup against Session 059 data, after the
2026-05-14 sphere-chain attempt diverged and was parked. Six translucent
chamber slabs + wireframe + time-staggered crumb replay + scrubber takeover.

ARES: 1 new test file (8 JSON contract tests). Floor 3,725 -> 3,733.
skyframe-main: prism.html + prism.js + prism-timeline.json + ares.html CTA
(deployed separately on its own main branch; Netlify auto-deploys).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
git push origin main
```

- [ ] **Step 9: Confirm squash-merge landed cleanly**

```bash
git log --oneline main -5
```

Expected: top commit is `Session 062: Prism Labyrinth (Panel 1) renderer (squash)`. Below it: `Session 061: ...`, `Session 060: ...`, etc.

- [ ] **Step 10: Final test run on main**

```bash
pytest ares/dialectic/tests/ -q
```

Expected: zero failures, collected ≥ 3,733.

---

## Out of scope (do not implement)

These are explicitly out of scope for this build per the spec § "Out of scope":

- Panels 2–4 (Confidence Trajectories, Citation Drift Field, Adversarial Pressure)
- Cross-panel sync infrastructure
- The accumulated untracked working-tree files at brainstorm time (study HTMLs, pipeline excalidraws, paper_2 v1.2 work, AKIRA Core / ARES-vision experiments) — these are separate cleanup work
- Playwright tests for skyframe-main pages
- Confidence-driven crumb placement, hover tooltips, baseline-vs-mutated dual trails, narrow-leakage visuals

If you discover any of these during execution, flag them but do NOT implement them in this build.

---

## Notes for the implementing engineer

- The spec at `docs/superpowers/specs/2026-05-19-prism-labyrinth-renderer-v2-design.md` is the source of truth for any design question this plan doesn't answer. Read it first.
- The mockup at `docs/marketing/prism-mockup.html` is the visual source of truth. When in doubt about a constant, color, position, or behavior, the mockup wins.
- The parked sphere-chain at `docs/marketing/prism-2026-05-14-sphere-chain.html` shows what NOT to do — keep it as a reference; do not delete.
- Commits in skyframe-main go straight to `main` — Netlify auto-deploys. This matches the pinscreen Session 061 precedent.
- Commits in ARES go on `session/062-prism-labyrinth` and squash-merge to `main` at session close.
- TDD doesn't directly apply to the JavaScript renderer (no browser test framework in scope). Compensate with bite-sized commits and browser verification after each task.
