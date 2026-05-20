# Prism Panel 2 — Confidence Trajectories Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship Panel 2 (Confidence Trajectories) of the Prism page on skyframe-main: per-pair arrows from baseline-confidence-coord to mutated-confidence-coord, revealed in pair_index order under a shared timeline with Panel 1.

**Architecture:** Approach C — freeze `prism.js` (Panel 1 stays untouched except for surgical state-publishing inserts + a small `start`/`stop` export). Add three new sibling JS files (`prism-state.js`, `prism-tabs.js`, `prism-panel2.js`) plus a tab strip in `prism.html`. Panels share one `activeCycleIndex` / `operatorFilter` / `autoplayRunning` state via a tiny event-bus module; Panel 2's reveal polls state per-frame, with `visibleSet` cached and rebuilt only on `prism:state` events.

**Tech Stack:** Three.js r128 classic CDN scripts (matches Panel 1), vanilla JS, Python 3.11 + pytest for the JSON contract test, deterministic JSON. No build step.

**Spec:** `docs/superpowers/specs/2026-05-20-prism-panel2-confidence-trajectories-design.md`
**Mockup reference:** `docs/marketing/prism-mockup.html` lines 573-619 (validated r160 ESM Panel 2 — palette + camera angle reference)
**Panel 1 precedent:** `skyframe-main/assets/ares/prism.js` (frozen except for §2.1 edits) + `skyframe-main/assets/ares/prism.html` (chrome to extend)

---

## File Structure

### ARES repo (`C:\ares-phase-zero`)

**Modified:**
- `ares/dialectic/tests/visualization/test_prism_timeline_json_contract.py` — 4 new tests appended to the existing 8. Floor 3,733 → 3,737.
- `CLAUDE.md` — new `## Session 063` entry, floor bump, last-updated bump.

**Not modified:** Phase A pipeline files, `prism-timeline.json` source, all `ares/` source.

### skyframe-main repo (`E:\Skyframe Innovations Website\skyframe-main`)

**Created:**
- `assets/ares/prism-state.js` — ~40 lines event bus
- `assets/ares/prism-tabs.js` — ~60 lines tab UI
- `assets/ares/prism-panel2.js` — ~350 lines Panel 2 scene + reveal

**Modified:**
- `assets/ares/prism.html` — adds tab strip, second canvas container, three new `<script>` tags, ~30 lines of CSS for tabs and panel2 canvas
- `assets/ares/prism.js` — 7 inserts total (6 `PrismState.publish()` calls + 1 `window.__PRISM_TIMELINE_CACHE = data` line in `loadTimeline`) + a `window.PrismPanel1 = { start, stop, isRunning }` export at the end + factoring the `animate()` rAF handle into a stoppable form

**Branch / commit strategy:**
- ARES: new branch `session/063-prism-panel2`, squash-merge to `main` at end. Mirrors Sessions 045-062.
- skyframe-main: direct commits to `main`, Netlify auto-deploys. Mirrors Session 062 workflow (the crystal records 14 commits straight to main).

---

## Phase A — ARES JSON contract additions

### Task 1: Add 4 new JSON contract tests (single file, single commit)

**Files:**
- Modify: `ares/dialectic/tests/visualization/test_prism_timeline_json_contract.py` (append 4 tests + 1 new constant; no edits to existing 8 tests)

These tests lock the JSON shape Panel 2 depends on. They run against the existing `docs/marketing/prism-timeline.json` — no data regen needed.

- [ ] **Step 1: Create the ARES session branch**

```bash
cd C:/ares-phase-zero
git checkout main
git pull --ff-only origin main
git checkout -b session/063-prism-panel2
```

Expected: clean branch creation, on `session/063-prism-panel2`.

- [ ] **Step 2: Read the existing test file end-to-end to confirm style + fixtures**

Open `ares/dialectic/tests/visualization/test_prism_timeline_json_contract.py`. Note:
- Module-scoped `timeline` fixture loads the JSON once.
- Tests use plain `assert` with descriptive messages.
- Existing tests run via `pytest ares/dialectic/tests/visualization/test_prism_timeline_json_contract.py -v` (8 tests collected).

- [ ] **Step 3: Append the 4 new tests + 1 new constant**

Append to the end of `ares/dialectic/tests/visualization/test_prism_timeline_json_contract.py` (preserve a leading blank line):

```python


# ────────────────────────────────────────────────────────────────────
# Panel 2 (Confidence Trajectories) contract additions
# ────────────────────────────────────────────────────────────────────
#
# Panel 2 renders one primitive per pair: an arrow from baseline_llm to
# mutated_llm in (architect_confidence, skeptic_confidence,
# oracle_confidence) space when confidence moves, or a sphere at the
# baseline coord when the cycle's confidence held steady. These tests
# lock the data shape Panel 2 depends on:
#   (1) baseline_llm has the three confidence fields, all in [0, 1]
#   (2) mutated_llm has them too (Phase A pipeline drops no-op pairs
#       entirely; no null branch to handle)
#   (3) the dropped-pair count is exactly 2 (locks Session 059 pipeline
#       output shape so a regen with a different no-op count surfaces
#       immediately — see "open items" #5 in the spec for the CLAUDE.md
#       vs. data discrepancy)
#   (4) the single broad-leakage pair has near-zero confidence delta
#       AND a non-trivial citation-surface change — locks Session 059's
#       architectural finding that the broad-leakage signal was in
#       Oracle citation passthrough, not confidence drift. If a future
#       dataset shows confidence drift on broad-leakage, this test
#       fails loud and forces the Panel 2 narrative to update.

CONFIDENCE_FIELDS = ("architect_confidence", "skeptic_confidence", "oracle_confidence")
ZERO_DELTA_THRESHOLD = 0.01

# Session 058.5 audit documented 1 no-op for synonym_substitution_conservative_v2,
# but the live Session 059 pipeline output drops 2 pair_indices.
# Whether the audit text is wrong, the live run had a different no-op count,
# or there's a downstream pipeline artifact is a separate ARES question.
# The visualization reflects what shipped: 2 dropped pairs.
EXPECTED_DROPPED_PAIR_COUNT = 2


def test_every_pair_has_baseline_llm_confidences(timeline: dict) -> None:
    for pair in timeline["pairs"]:
        baseline = pair.get("baseline_llm")
        assert isinstance(baseline, dict), (
            f"Pair {pair['pair_index']} baseline_llm must be a dict, got {type(baseline).__name__}"
        )
        for field in CONFIDENCE_FIELDS:
            value = baseline.get(field)
            assert isinstance(value, (int, float)), (
                f"Pair {pair['pair_index']} baseline_llm.{field} must be numeric, got {type(value).__name__}"
            )
            assert 0.0 <= float(value) <= 1.0, (
                f"Pair {pair['pair_index']} baseline_llm.{field}={value} outside [0.0, 1.0]"
            )


def test_every_pair_has_mutated_llm_confidences(timeline: dict) -> None:
    # Phase A pipeline drops no-op pairs entirely from the JSON.
    # Every delivered pair therefore has a populated mutated_llm dict.
    for pair in timeline["pairs"]:
        mutated = pair.get("mutated_llm")
        assert isinstance(mutated, dict), (
            f"Pair {pair['pair_index']} mutated_llm must be a dict (pipeline drops no-ops), "
            f"got {type(mutated).__name__}"
        )
        for field in CONFIDENCE_FIELDS:
            value = mutated.get(field)
            assert isinstance(value, (int, float)), (
                f"Pair {pair['pair_index']} mutated_llm.{field} must be numeric, got {type(value).__name__}"
            )
            assert 0.0 <= float(value) <= 1.0, (
                f"Pair {pair['pair_index']} mutated_llm.{field}={value} outside [0.0, 1.0]"
            )


def test_dropped_pair_count_locks_pipeline_state(timeline: dict) -> None:
    # Locks the count of pair_indices missing from the global enumeration.
    # Session 059 produces 2 dropped indices (3 and 4). Any change to this
    # count means the pipeline ran differently — Panel 2's "N visible
    # primitives per operator" expectations would silently drift.
    pairs = timeline["pairs"]
    indices = [p["pair_index"] for p in pairs]
    enumeration_size = max(indices) + 1
    delivered = len(indices)
    dropped = enumeration_size - delivered
    assert dropped == EXPECTED_DROPPED_PAIR_COUNT, (
        f"Expected {EXPECTED_DROPPED_PAIR_COUNT} dropped pairs from the global enumeration "
        f"(max_index={max(indices)}, delivered={delivered}, dropped={dropped}). "
        f"If the pipeline now drops more or fewer no-ops, the visualization may need to update."
    )


def test_broad_leakage_pair_has_zero_confidence_delta_per_session_059(timeline: dict) -> None:
    # Session 059's documented architectural finding: the broad-leakage
    # signal was Oracle citation-surface passthrough (the Oracle inherits
    # the Architect's cite-set drift), NOT confidence drift. The Oracle's
    # decision (outcome + confidence) is preserved deterministically.
    # Lock this with a paired assertion:
    #   (a) confidence delta is near-zero on all three axes
    #   (b) the citation surface IS different (architect_cited_facts
    #       differs OR oracle_supporting_facts differs between baseline
    #       and mutated)
    # If a future dataset shows confidence drift on broad-leakage, (a)
    # fails and Panel 2's renderer (which puts the broad-leakage pair as
    # a glowing red sphere AT the baseline coord) needs to update to
    # render an arrow instead.
    drift_pairs = [p for p in timeline["pairs"] if p["broad_leakage"]]
    assert len(drift_pairs) == 1, f"Expected exactly 1 broad_leakage pair, found {len(drift_pairs)}"
    pair = drift_pairs[0]
    baseline = pair["baseline_llm"]
    mutated = pair["mutated_llm"]

    # (a) Near-zero confidence delta
    deltas = [abs(float(mutated[f]) - float(baseline[f])) for f in CONFIDENCE_FIELDS]
    assert max(deltas) < ZERO_DELTA_THRESHOLD, (
        f"broad_leakage pair {pair['pair_index']}: confidence deltas {deltas} include one "
        f">= {ZERO_DELTA_THRESHOLD}. Session 059 finding was citation-surface drift only — "
        f"this would invert it. Update Panel 2 renderer + spec narrative."
    )

    # (b) Citation surface IS different
    arch_baseline_cites = baseline.get("architect_cited_facts", [])
    arch_mutated_cites = mutated.get("architect_cited_facts", [])
    oracle_baseline_sup = baseline.get("oracle_supporting_facts", [])
    oracle_mutated_sup = mutated.get("oracle_supporting_facts", [])
    citation_surface_changed = (
        arch_baseline_cites != arch_mutated_cites
        or oracle_baseline_sup != oracle_mutated_sup
    )
    assert citation_surface_changed, (
        f"broad_leakage pair {pair['pair_index']}: neither architect_cited_facts nor "
        f"oracle_supporting_facts changed between baseline and mutated. The leakage signal "
        f"should be IN the citation surface per Session 059 — if it isn't, the pipeline output "
        f"is inconsistent with the documented finding."
    )
```

- [ ] **Step 4: Run the test file — expect 12 passed**

```bash
cd C:/ares-phase-zero
python -m pytest ares/dialectic/tests/visualization/test_prism_timeline_json_contract.py -v
```

Expected: `12 passed` (8 pre-existing + 4 new). If any new test fails, the JSON regen from Phase A pipeline has drifted — diagnose against the JSON before continuing.

- [ ] **Step 5: Run the full ARES test suite to confirm zero regressions**

```bash
cd C:/ares-phase-zero
python -m pytest tests/ ares/dialectic/tests/ -q
```

Expected: `3737 passed, 72 skipped` (or matching skip count). Zero failures. Floor declared in CLAUDE.md is 3,733 — actual is now 3,737. The CLAUDE.md freshness test (`tests/test_claude_md_freshness.py`) still passes because the floor is a lower bound; we bump the declared floor in Task 9.

- [ ] **Step 6: Commit**

```bash
cd C:/ares-phase-zero
git add ares/dialectic/tests/visualization/test_prism_timeline_json_contract.py
git commit -m "test(prism): JSON contract additions for Panel 2 confidence trajectories

Adds 4 tests locking baseline_llm/mutated_llm per-layer confidences,
the documented 1-pair no-op count (Session 058.5), and the broad-
leakage pair's minimum confidence delta. Catches Phase A pipeline
regressions before they surface silently in the Panel 2 browser
renderer.

Floor: 3,733 -> 3,737.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

Expected: single commit on `session/063-prism-panel2`, no other files staged.

---

## Phase B — skyframe-main renderer (direct-to-main, Netlify auto-deploys)

> **Working directory for Phase B:** `E:\Skyframe Innovations Website\skyframe-main`
>
> **Commit-after-each-task discipline:** each task in Phase B ends with its own commit. Netlify auto-deploys on push; do NOT push until after Task 8 (full local verification) to avoid pushing a half-finished tab strip.

### Task 2: Extend `prism.html` chrome — tab strip, second canvas container, CSS, script tags

**Files:**
- Modify: `assets/ares/prism.html`

Add the tab strip below the header, a second panel container for `#panel2-canvas`, three new `<script>` tags (in dependency order: state → tabs → panel2), and ~30 lines of CSS for tabs + panel2 layout. Existing Panel 1 markup unchanged.

- [ ] **Step 1: Add CSS for tabs and panel2 layout**

In the `<style>` block of `assets/ares/prism.html`, append (after the existing `footer a:hover { color: var(--text); }` rule, before the closing `</style>`):

```css
    .tab-strip {
      display: flex;
      gap: 4px;
      padding: 0 28px;
      margin: -8px auto 0;
      max-width: 50vw;
      width: 100%;
      border-bottom: 1px solid var(--border);
    }
    @media (max-width: 1100px) { .tab-strip { max-width: 92vw; } }
    .tab-btn {
      background: transparent;
      border: 1px solid var(--border);
      border-bottom: none;
      border-radius: 6px 6px 0 0;
      color: var(--muted);
      padding: 10px 18px;
      font-family: 'JetBrains Mono', monospace;
      font-size: 11px;
      letter-spacing: 1.5px;
      text-transform: uppercase;
      cursor: pointer;
      transition: color 120ms, border-color 120ms, background 120ms;
    }
    .tab-btn:hover { color: var(--text); }
    body[data-active-tab="labyrinth"]    .tab-btn[data-tab="labyrinth"],
    body[data-active-tab="trajectories"] .tab-btn[data-tab="trajectories"] {
      color: var(--text);
      border-color: var(--text);
      background: var(--panel-bg);
    }
    body[data-active-tab="labyrinth"]    #panel2-container { display: none; }
    body[data-active-tab="trajectories"] #panel1-container { display: none; }
```

- [ ] **Step 2: Wrap the existing Panel 1 `.panel` div in a container with an id, and add the tab strip + Panel 2 container**

Replace the existing `<main>...</main>` block with:

```html
  <div class="tab-strip">
    <button class="tab-btn" data-tab="labyrinth"    type="button">▣ Labyrinth</button>
    <button class="tab-btn" data-tab="trajectories" type="button">▣ Trajectories</button>
  </div>

  <main>
    <div id="panel1-container">
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
    </div>

    <div id="panel2-container">
      <div class="panel">
        <div class="panel-header">
          <span class="panel-tag">Panel 2 &middot; confidence trajectories</span>
          <h2 class="panel-title">Trajectories</h2>
          <p class="panel-subtitle">Each cycle is one primitive in (architect, skeptic, oracle) confidence space — an arrow when confidence moved, a sphere when it held. The broad-leakage cycle sits at the held cluster as a glowing red sphere because its leakage was in citation surface, not confidence numbers (Session 059).</p>
        </div>
        <div id="panel2-canvas" class="panel-canvas">
          <div class="stats">
            visible: <span class="value" id="stat2-visible">0</span><br>
            arrows / spheres: <span class="value" id="stat2-arrows">0</span> / <span class="value" id="stat2-spheres">0</span><br>
            broad-leak: <span class="drift" id="stat2-drift">—</span>
          </div>
        </div>
        <div class="panel-legend">
          <span class="legend-item"><span class="legend-dot" style="background:#cbd5e1"></span>Held — arrow (confidence moved)</span>
          <span class="legend-item"><span class="legend-dot" style="background:#cbd5e1;opacity:0.6"></span>Held — sphere (confidence steady)</span>
          <span class="legend-item"><span class="legend-dot" style="background:#ef4444;box-shadow:0 0 6px #ef4444"></span>Broad-leakage — citation-surface drift</span>
        </div>
      </div>
    </div>
  </main>
```

- [ ] **Step 3: Add the three new script tags in dependency order**

Replace the existing `<script src="prism.js"></script>` line at the bottom of `<body>` with:

```html
  <script src="prism-state.js"></script>
  <script src="prism.js"></script>
  <script src="prism-panel2.js"></script>
  <script src="prism-tabs.js"></script>
```

Order rationale:
- `prism-state.js` defines `window.PrismState`; must load first.
- `prism.js` boots Panel 1 (which calls `init()` via top-level await — actually it calls `init()` synchronously; the function itself is `async`). It populates `window.__PRISM_TIMELINE_CACHE` and exposes `window.PrismPanel1`.
- `prism-panel2.js` boots Panel 2, deferring until the cache is set (with its 50×100ms retry).
- `prism-tabs.js` last; attaches click handlers on `DOMContentLoaded` and reads the now-existing `window.PrismPanel1` / `window.PrismPanel2`.

- [ ] **Step 4: Set the initial active tab on `<body>`**

In the opening `<body>` tag (currently just `<body>`), change to:

```html
<body data-active-tab="labyrinth">
```

- [ ] **Step 5: Open the page locally in a browser (no panel2.js yet — verify chrome only)**

This is a visual check. The three new script files don't exist yet so the browser console will log 404s — that is expected. The tab strip should render, both panel containers should render in DOM (but the Panel 2 container is shown as a placeholder since CSS hides it under `data-active-tab="labyrinth"`), and Panel 1 should still autoplay normally.

Verify by opening `file:///E:/Skyframe%20Innovations%20Website/skyframe-main/assets/ares/prism.html` (or via Playwright MCP `browser_navigate` to that URL). Look for:
- Tab strip visible below the header with `Labyrinth` highlighted and `Trajectories` muted
- Panel 1 still autoplays (proves chrome edits didn't break existing JS)
- 404s for `prism-state.js`, `prism-panel2.js`, `prism-tabs.js` are the only console errors

If Panel 1 stops working, the wrapping `<div id="panel1-container">` change broke a selector — revert and diagnose. (`prism.js` only queries by `#panel1-canvas`, which is inside the new wrapper, so this should work.)

- [ ] **Step 6: Commit**

```bash
cd "E:/Skyframe Innovations Website/skyframe-main"
git add assets/ares/prism.html
git commit -m "feat(prism): tab strip + second panel container for Panel 2

Adds Labyrinth/Trajectories tab strip, wraps Panel 1 in a container,
adds a Panel 2 container with its own canvas + legend, declares the
three new script slots (prism-state.js, prism-panel2.js, prism-tabs.js).
Panel 1 behavior unchanged. New scripts 404 until next commits land.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

### Task 3: Create `prism-state.js` (the event bus)

**Files:**
- Create: `assets/ares/prism-state.js`

Tiny pub/sub module. Owns the four fields both panels need to share. Used by `prism.js` (publisher) and `prism-panel2.js` (subscriber + poller).

- [ ] **Step 1: Create the file**

Create `assets/ares/prism-state.js`:

```js
/*
 * ARES Prism — shared state bus for cross-panel communication.
 *
 * Owns the small subset of state that must be shared between Panel 1
 * (Labyrinth) and Panel 2 (Trajectories): activeCycleIndex,
 * autoplayRunning, operatorFilter, visiblePairs.
 *
 * Panel 1 calls publish() inside its existing input handlers (no
 * refactor of Panel 1's local STATE). Panel 2 subscribes for one-shot
 * events (filter change -> rebuild visibleSet) and polls getState()
 * per-frame for smooth values (activeCycleIndex during autoplay,
 * since Panel 1 does NOT publish on its 60Hz tickReplay loop).
 *
 * Spec: docs/superpowers/specs/2026-05-20-prism-panel2-confidence-trajectories-design.md §3
 */

'use strict';

(function() {
  const _state = {
    activeCycleIndex: 0,
    autoplayRunning: true,
    operatorFilter: 'all',
    visiblePairs: [],
  };

  function getState() {
    // Snapshot; callers must treat as read-only. visiblePairs is shared
    // by reference (Panel 1 owns it) — cheap and intentional.
    return {
      activeCycleIndex: _state.activeCycleIndex,
      autoplayRunning:  _state.autoplayRunning,
      operatorFilter:   _state.operatorFilter,
      visiblePairs:     _state.visiblePairs,
    };
  }

  function publish(partial) {
    // Shallow-merge known keys; ignore unknown keys to keep the surface
    // stable. The CustomEvent detail carries a snapshot, not a delta.
    if (partial && typeof partial === 'object') {
      if ('activeCycleIndex' in partial) _state.activeCycleIndex = partial.activeCycleIndex;
      if ('autoplayRunning'  in partial) _state.autoplayRunning  = partial.autoplayRunning;
      if ('operatorFilter'   in partial) _state.operatorFilter   = partial.operatorFilter;
      if ('visiblePairs'     in partial) _state.visiblePairs     = partial.visiblePairs;
    }
    if (typeof window !== 'undefined' && window.dispatchEvent) {
      window.dispatchEvent(new CustomEvent('prism:state', { detail: getState() }));
    }
  }

  function subscribe(fn) {
    if (typeof fn !== 'function') return () => {};
    const handler = (e) => fn(e.detail);
    window.addEventListener('prism:state', handler);
    return () => window.removeEventListener('prism:state', handler);
  }

  window.PrismState = { getState, publish, subscribe };
})();
```

- [ ] **Step 2: Smoke-test in the browser console**

Reload the page. In DevTools console:

```
PrismState.getState()
// → {activeCycleIndex: 0, autoplayRunning: true, operatorFilter: "all", visiblePairs: []}

const off = PrismState.subscribe(d => console.log('event:', d));
PrismState.publish({ activeCycleIndex: 42 });
// → "event: {activeCycleIndex: 42, ...}"
off();
```

Confirms the bus works, subscribers receive snapshots, and unsubscribe cleans up.

- [ ] **Step 3: Commit**

```bash
cd "E:/Skyframe Innovations Website/skyframe-main"
git add assets/ares/prism-state.js
git commit -m "feat(prism): prism-state.js event bus for cross-panel state

window.PrismState exposes getState / publish / subscribe. Owns shared
playhead + filter + visiblePairs. Panel 1 publishes after each STATE
mutation; Panel 2 subscribes for filter changes and polls for the
playhead during autoplay.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

### Task 4: Surgical edits to `prism.js` — publish, cache, panel export

**Files:**
- Modify: `assets/ares/prism.js`

Three sets of changes, all additive, all gated behind null-checks so `prism.js` still works if loaded without the new state module:
1. **6 publish inserts** — after each STATE mutation that affects shared fields.
2. **1 cache assignment** — at the end of `loadTimeline`, expose the parsed JSON on `window.__PRISM_TIMELINE_CACHE` so Panel 2 doesn't refetch.
3. **`PrismPanel1` export with stoppable rAF** — refactor the bare `requestAnimationFrame(animate)` into a `_panel1RafHandle` variable so the tab module can pause it.

- [ ] **Step 1: Add stoppable rAF + PrismPanel1 export**

Replace the existing `animate()` function (currently lines 179-186) with:

```js
let _panel1RafHandle = null;
let _panel1Running = false;

function animate() {
  _panel1RafHandle = requestAnimationFrame(animate);
  tickReplay();
  if (SCENE.controls) SCENE.controls.update();
  if (SCENE.renderer && SCENE.scene && SCENE.camera) {
    SCENE.renderer.render(SCENE.scene, SCENE.camera);
  }
}

function _panel1Start() {
  if (_panel1Running) return;
  _panel1Running = true;
  animate();
}

function _panel1Stop() {
  if (_panel1RafHandle !== null) {
    cancelAnimationFrame(_panel1RafHandle);
    _panel1RafHandle = null;
  }
  _panel1Running = false;
}

window.PrismPanel1 = {
  start:     _panel1Start,
  stop:      _panel1Stop,
  isRunning: () => _panel1Running,
};
```

Then, at the bottom of `init()`, change the existing line `animate();` to `_panel1Start();`. (`init()` currently ends with `animate();` on line 621; change that single line.)

- [ ] **Step 2: Add the timeline cache assignment**

In `loadTimeline()` (lines 256-268), after the line `STATE.visiblePairs = data.pairs;`, insert:

```js
  // Expose for Panel 2 — avoids a second fetch round-trip.
  if (typeof window !== 'undefined') {
    window.__PRISM_TIMELINE_CACHE = data;
  }
```

- [ ] **Step 3: Add 6 PrismState.publish() inserts**

Each insert is the same shape: `if (window.PrismState) window.PrismState.publish({...});` placed immediately after the existing STATE mutation.

**Insert 3a — in `wireScrubber()` scrubber input handler (after the existing `setPlayPauseLabel();` on what is currently line 468):**

```js
    if (window.PrismState) {
      window.PrismState.publish({
        activeCycleIndex: STATE.activeCycleIndex,
        autoplayRunning:  STATE.autoplayRunning,
      });
    }
```

**Insert 3b — in `wirePlayPause()` click handler (after the existing `setPlayPauseLabel();` on what is currently line 486):**

```js
    if (window.PrismState) {
      window.PrismState.publish({
        autoplayRunning:  STATE.autoplayRunning,
        activeCycleIndex: STATE.activeCycleIndex,
      });
    }
```

**Insert 3c — at the end of `applyOperatorFilter()` (after the existing `document.getElementById('scrubber').value = '0';` on what is currently line 514):**

```js
  if (window.PrismState) {
    window.PrismState.publish({
      operatorFilter:   STATE.operatorFilter,
      visiblePairs:     STATE.visiblePairs,
      activeCycleIndex: STATE.activeCycleIndex,
      autoplayRunning:  STATE.autoplayRunning,
    });
  }
```

**Insert 3d — replay-completion publish.** In `tickReplay()` (line 401-414), the existing block already resets `replayStartTime` and `t` on completion. Add a publish AFTER the reset:

Locate this block in `tickReplay()`:

```js
  if (STATE.autoplayRunning) {
    t = performance.now() - replayStartTime;
    if (t > replayTotalRuntimeMs) {
      replayStartTime = performance.now();
      t = 0;
    }
    STATE.activeCycleIndex = Math.floor(t / CYCLE_STAGGER_MS);
    document.getElementById('scrubber').value = String(STATE.activeCycleIndex);
  } else {
```

Change it to:

```js
  if (STATE.autoplayRunning) {
    t = performance.now() - replayStartTime;
    if (t > replayTotalRuntimeMs) {
      replayStartTime = performance.now();
      t = 0;
      if (window.PrismState) {
        window.PrismState.publish({ activeCycleIndex: 0 });
      }
    }
    STATE.activeCycleIndex = Math.floor(t / CYCLE_STAGGER_MS);
    document.getElementById('scrubber').value = String(STATE.activeCycleIndex);
  } else {
```

(The wrap-to-0 is the only autoplay event Panel 2 needs an explicit signal for; the smooth advance is polled.)

**Insert 3e — reduced-motion init publish.** At the end of `init()`, inside the existing `if (PREFERS_REDUCED_MOTION) {...}` block (lines 613-619), after the existing `scr.value = String(STATE.activeCycleIndex);`, add:

```js
    if (window.PrismState) {
      window.PrismState.publish({
        autoplayRunning:  STATE.autoplayRunning,
        activeCycleIndex: STATE.activeCycleIndex,
      });
    }
```

**Insert 3f — initial state publish at end of init().** Just before the final `_panel1Start();` (formerly `animate();`) in `init()`, after the `console.log(...)` line, add:

```js
  if (window.PrismState) {
    window.PrismState.publish({
      activeCycleIndex: STATE.activeCycleIndex,
      autoplayRunning:  STATE.autoplayRunning,
      operatorFilter:   STATE.operatorFilter,
      visiblePairs:     STATE.visiblePairs,
    });
  }
```

This is the publish Panel 2 reads via `getState()` on its first frame to backfill, before any user-input event has fired.

- [ ] **Step 4: Reload the page; verify Panel 1 behavior is unchanged**

Open the page in a browser. Confirm:
- Panel 1 still autoplays from landing
- Scrubber still works (drag → updates view)
- Operator dial still works (filter → updates view)
- Click on a chamber crumb still focuses
- Pressing Escape still releases focus
- Console: no errors. The 404s for `prism-panel2.js` and `prism-tabs.js` are still expected.

In the console, run:

```
PrismState.getState()
// → {activeCycleIndex: <some number ≥ 0>, autoplayRunning: true, operatorFilter: "all", visiblePairs: Array(98)}

window.__PRISM_TIMELINE_CACHE
// → {operators: [...], pairs: Array(98), run_id: "...", schema_version: ...}

window.PrismPanel1.isRunning()
// → true

window.PrismPanel1.stop()
window.PrismPanel1.isRunning()
// → false
// (Panel 1 freezes mid-replay; chambers stop animating)

window.PrismPanel1.start()
// (Panel 1 resumes)
```

If any of the above fails, the surgical edit is wrong — diagnose and fix before commit.

- [ ] **Step 5: Commit**

```bash
cd "E:/Skyframe Innovations Website/skyframe-main"
git add assets/ares/prism.js
git commit -m "feat(prism): surgical edits to prism.js — publish, cache, panel export

Six PrismState.publish() inserts after existing STATE mutations.
Timeline cache exposed on window.__PRISM_TIMELINE_CACHE for Panel 2
consumption. animate() refactored into stoppable form via
_panel1RafHandle; window.PrismPanel1 exposes start/stop/isRunning so
the tab module can pause the inactive panel.

Panel 1 behavior unchanged. All publish calls behind null-check on
window.PrismState so prism.js still works if loaded standalone.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

### Task 5: Create `prism-panel2.js` (scene + arrows + reveal + start/stop)

**Files:**
- Create: `assets/ares/prism-panel2.js`

The largest task. Single commit because the file is internally cohesive and each section depends on the next. ~350 lines.

- [ ] **Step 1: Create the file with the full scaffold**

Create `assets/ares/prism-panel2.js`:

```js
/*
 * ARES Prism — Panel 2 (Confidence Trajectories)
 *
 * Renders one primitive per pair in (architect_confidence,
 * skeptic_confidence, oracle_confidence) space:
 *  - Arrow from baseline_llm to mutated_llm when confidence moved
 *    (~75 of 98 pairs in Session 059 dataset).
 *  - Sphere at baseline coord when confidence held steady
 *    (~23 of 98 pairs; includes the single broad-leakage pair, whose
 *    leakage was in Oracle citation surface, NOT confidence drift —
 *    per Session 059's documented architectural finding).
 *
 * Broad-leakage pair gets a larger glowing red sphere when its delta
 * is zero (current Session 059 case) OR a red arrow if a future dataset
 * shows broad-leakage with confidence drift.
 *
 * Shares timeline state with Panel 1 via window.PrismState. Reads data
 * from window.__PRISM_TIMELINE_CACHE (populated by prism.js loadTimeline).
 *
 * Spec: docs/superpowers/specs/2026-05-20-prism-panel2-confidence-trajectories-design.md
 */

'use strict';

const P2_PREFERS_REDUCED_MOTION = (
  typeof window !== 'undefined' &&
  window.matchMedia &&
  window.matchMedia('(prefers-reduced-motion: reduce)').matches
);

// ────────────────────────────────────────────────────────────────────
// Constants
// ────────────────────────────────────────────────────────────────────

const CUBE_HALF = 15;                        // matches mockup scene scale
const CUBE_SIZE = CUBE_HALF * 2;             // [0,1] -> [-15, +15]
const HELD_COLOR  = 0xcbd5e1;                // grey-blue, matches mockup
const DRIFT_COLOR_P2 = 0xef4444;             // red, matches Panel 1 drift accent
const AXIS_COLOR  = 0x88aacc;
const CUBE_EDGE_COLOR = 0xffffff;
const CUBE_EDGE_OPACITY = 0.04;

const ARROW_HEAD_LENGTH = 0.7;
const ARROW_HEAD_WIDTH  = 0.35;

// Below this scene-space length, render a sphere instead of an arrow.
// 0.05 scene units corresponds to ~0.0017 confidence units (well below
// the ~0.05 granularity of LLM-emitted confidence values).
const ZERO_DELTA_EPSILON = 0.05;

const HELD_SPHERE_RADIUS  = 0.20;            // dim, small — zero-delta held pairs
const DRIFT_SPHERE_RADIUS = 0.55;            // larger, glowing — broad-leakage at cluster

// ────────────────────────────────────────────────────────────────────
// State (panel-private)
// ────────────────────────────────────────────────────────────────────

const P2_STATE = {
  scene: null,
  camera: null,
  renderer: null,
  controls: null,
  container: null,
  cache: null,        // Cached pairs from window.__PRISM_TIMELINE_CACHE; set in bootP2
  primitives: [],     // [{pair, kind, primitive, lengthScene}, ...] kind in {'arrow', 'sphere'}
  visibleSet: null,   // Set<pair_index>; rebuilt on filter change
  lastOperatorFilter: null,
  rafHandle: null,
  running: false,
  unsubscribe: null,
  ready: false,       // bootP2 finished (cache loaded, listener subscribed)
  arrowCount: 0,      // total arrows built (lifetime, not visible-count)
  sphereCount: 0,     // total spheres built
  driftPairIndex: null,
};

// ────────────────────────────────────────────────────────────────────
// Utilities
// ────────────────────────────────────────────────────────────────────

function confidenceToScene(architect_c, skeptic_c, oracle_c) {
  return new THREE.Vector3(
    architect_c * CUBE_SIZE - CUBE_HALF,
    skeptic_c   * CUBE_SIZE - CUBE_HALF,
    oracle_c    * CUBE_SIZE - CUBE_HALF,
  );
}

function makeAxisLabelSprite(text, hexColor) {
  const cnv = document.createElement('canvas');
  cnv.width = 256; cnv.height = 64;
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
  sprite.scale.set(8, 2, 1);
  return sprite;
}

// ────────────────────────────────────────────────────────────────────
// Scene setup
// ────────────────────────────────────────────────────────────────────

function initSceneP2() {
  P2_STATE.container = document.getElementById('panel2-canvas');
  if (!P2_STATE.container) throw new Error('panel2-canvas container missing');
  const w = P2_STATE.container.clientWidth;
  const h = P2_STATE.container.clientHeight;

  P2_STATE.scene = new THREE.Scene();
  P2_STATE.scene.background = new THREE.Color(0x040408);

  P2_STATE.camera = new THREE.PerspectiveCamera(40, w / h, 0.1, 500);
  P2_STATE.camera.position.set(35, 18, 42);

  P2_STATE.renderer = new THREE.WebGLRenderer({ antialias: true });
  if (!P2_STATE.renderer.getContext()) {
    P2_STATE.container.innerHTML =
      '<div style="position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);' +
      'color:#94a3b8;font-family:JetBrains Mono,monospace;font-size:13px;">' +
      '3D RENDERER FAILED TO LOAD</div>';
    throw new Error('WebGL unavailable');
  }
  P2_STATE.renderer.setSize(w, h);
  P2_STATE.renderer.setPixelRatio(window.devicePixelRatio);
  P2_STATE.container.appendChild(P2_STATE.renderer.domElement);

  P2_STATE.controls = new THREE.OrbitControls(P2_STATE.camera, P2_STATE.renderer.domElement);
  P2_STATE.controls.enableDamping = true;
  P2_STATE.controls.dampingFactor = 0.08;
  P2_STATE.controls.rotateSpeed = 0.7;
  P2_STATE.controls.minDistance = 25;
  P2_STATE.controls.maxDistance = 120;
  P2_STATE.controls.target.set(0, 0, 0);
  P2_STATE.controls.autoRotate = !P2_PREFERS_REDUCED_MOTION;
  P2_STATE.controls.autoRotateSpeed = 0.5;

  P2_STATE.scene.add(new THREE.AmbientLight(0xffffff, 0.5));
  const key = new THREE.DirectionalLight(0xffffff, 0.5);
  key.position.set(30, 50, 30);
  P2_STATE.scene.add(key);

  buildBoundingCube();
  buildAxisCross();
  buildAxisLabels();

  window.addEventListener('resize', onResizeP2);
}

function onResizeP2() {
  if (!P2_STATE.renderer || !P2_STATE.container) return;
  const w = P2_STATE.container.clientWidth;
  const h = P2_STATE.container.clientHeight;
  P2_STATE.camera.aspect = w / h;
  P2_STATE.camera.updateProjectionMatrix();
  P2_STATE.renderer.setSize(w, h);
}

function buildBoundingCube() {
  const geom = new THREE.BoxGeometry(CUBE_SIZE, CUBE_SIZE, CUBE_SIZE);
  const edges = new THREE.LineSegments(
    new THREE.EdgesGeometry(geom),
    new THREE.LineBasicMaterial({ color: CUBE_EDGE_COLOR, transparent: true, opacity: 0.2 })
  );
  P2_STATE.scene.add(edges);

  const fillMat = new THREE.MeshBasicMaterial({
    color: CUBE_EDGE_COLOR, transparent: true, opacity: CUBE_EDGE_OPACITY, depthWrite: false,
  });
  P2_STATE.scene.add(new THREE.Mesh(geom, fillMat));
}

function buildAxisCross() {
  const len = CUBE_HALF;
  const mat = new THREE.LineBasicMaterial({ color: AXIS_COLOR, transparent: true, opacity: 0.55 });
  const make = (a, b) => {
    const g = new THREE.BufferGeometry().setFromPoints([a, b]);
    return new THREE.Line(g, mat);
  };
  P2_STATE.scene.add(make(new THREE.Vector3(-len, 0, 0), new THREE.Vector3(len, 0, 0)));
  P2_STATE.scene.add(make(new THREE.Vector3(0, -len, 0), new THREE.Vector3(0, len, 0)));
  P2_STATE.scene.add(make(new THREE.Vector3(0, 0, -len), new THREE.Vector3(0, 0, len)));
}

function buildAxisLabels() {
  const lblColor = '#cbd5e1';
  const arch = makeAxisLabelSprite('ARCHITECT', lblColor);
  arch.position.set(CUBE_HALF + 3, 0, 0);
  P2_STATE.scene.add(arch);
  const skep = makeAxisLabelSprite('SKEPTIC', lblColor);
  skep.position.set(0, CUBE_HALF + 3, 0);
  P2_STATE.scene.add(skep);
  const orc = makeAxisLabelSprite('ORACLE', lblColor);
  orc.position.set(0, 0, CUBE_HALF + 3);
  P2_STATE.scene.add(orc);
}

// ────────────────────────────────────────────────────────────────────
// Primitive construction (arrows + spheres)
// ────────────────────────────────────────────────────────────────────

function makeArrow(baselineVec, mutatedVec, color, isDrift) {
  const delta = mutatedVec.clone().sub(baselineVec);
  const len = delta.length();
  const dir = delta.clone().normalize();
  const arrow = new THREE.ArrowHelper(dir, baselineVec, len, color, ARROW_HEAD_LENGTH, ARROW_HEAD_WIDTH);
  arrow.visible = false;
  arrow.line.material.transparent = true;
  arrow.line.material.opacity = isDrift ? 0.95 : 0.7;
  arrow.cone.material.transparent = true;
  arrow.cone.material.opacity = isDrift ? 0.95 : 0.85;
  return { primitive: arrow, kind: 'arrow', lengthScene: len };
}

function makeSphere(baselineVec, color, isDrift) {
  const radius = isDrift ? DRIFT_SPHERE_RADIUS : HELD_SPHERE_RADIUS;
  const geom = new THREE.SphereGeometry(radius, isDrift ? 16 : 10, isDrift ? 16 : 10);
  const mat = new THREE.MeshStandardMaterial({
    color,
    emissive: color,
    emissiveIntensity: isDrift ? 1.6 : 0.3,
    metalness: 0,
    roughness: 0.6,
    transparent: true,
    opacity: isDrift ? 0.95 : 0.55,
    depthWrite: false,
  });
  const mesh = new THREE.Mesh(geom, mat);
  mesh.position.copy(baselineVec);
  mesh.visible = false;
  return { primitive: mesh, kind: 'sphere', lengthScene: 0 };
}

function buildPrimitives(pairs) {
  for (const pair of pairs) {
    let baselineVec, mutatedVec;
    try {
      baselineVec = confidenceToScene(
        pair.baseline_llm.architect_confidence,
        pair.baseline_llm.skeptic_confidence,
        pair.baseline_llm.oracle_confidence,
      );
      mutatedVec = confidenceToScene(
        pair.mutated_llm.architect_confidence,
        pair.mutated_llm.skeptic_confidence,
        pair.mutated_llm.oracle_confidence,
      );
    } catch (err) {
      console.warn('Panel 2: malformed pair', pair.pair_index, err.message);
      continue;
    }

    const deltaLength = mutatedVec.clone().sub(baselineVec).length();
    const isDrift = !!pair.broad_leakage;
    const color = isDrift ? DRIFT_COLOR_P2 : HELD_COLOR;

    let entry;
    if (deltaLength >= ZERO_DELTA_EPSILON) {
      entry = makeArrow(baselineVec, mutatedVec, color, isDrift);
      P2_STATE.arrowCount++;
    } else {
      entry = makeSphere(baselineVec, color, isDrift);
      P2_STATE.sphereCount++;
    }
    entry.pair = pair;
    P2_STATE.scene.add(entry.primitive);
    P2_STATE.primitives.push(entry);

    if (isDrift) P2_STATE.driftPairIndex = pair.pair_index;
  }

  // Initial stats panel
  const driftEl = document.getElementById('stat2-drift');
  if (driftEl && P2_STATE.driftPairIndex !== null) {
    const driftEntry = P2_STATE.primitives.find((e) => e.pair.pair_index === P2_STATE.driftPairIndex);
    driftEl.textContent = driftEntry && driftEntry.kind === 'sphere'
      ? 'citation surface'
      : `Δ=${driftEntry.lengthScene.toFixed(2)}`;
  }
}

// ────────────────────────────────────────────────────────────────────
// State binding (event-driven Set rebuild + per-frame poll)
// ────────────────────────────────────────────────────────────────────

function rebuildVisibleSet(visiblePairs) {
  P2_STATE.visibleSet = new Set(visiblePairs.map((p) => p.pair_index));
}

function onStateEvent(state) {
  if (state.operatorFilter !== P2_STATE.lastOperatorFilter) {
    P2_STATE.lastOperatorFilter = state.operatorFilter;
    rebuildVisibleSet(state.visiblePairs);
  }
}

// ────────────────────────────────────────────────────────────────────
// Animation
// ────────────────────────────────────────────────────────────────────

function animateP2() {
  P2_STATE.rafHandle = requestAnimationFrame(animateP2);
  // Per-frame reveal poll. Cheap: ~100 ops/frame at N=98.
  if (P2_STATE.visibleSet && P2_STATE.primitives.length > 0 && window.PrismState) {
    const state = window.PrismState.getState();
    const visible = P2_STATE.visibleSet;
    const playhead = state.activeCycleIndex;
    let revealedArrows = 0;
    let revealedSpheres = 0;
    for (const entry of P2_STATE.primitives) {
      const show = visible.has(entry.pair.pair_index) && entry.pair.pair_index <= playhead;
      entry.primitive.visible = show;
      if (show) {
        if (entry.kind === 'arrow') revealedArrows++;
        else revealedSpheres++;
      }
    }
    const visibleEl = document.getElementById('stat2-visible');
    const arrowsEl = document.getElementById('stat2-arrows');
    const spheresEl = document.getElementById('stat2-spheres');
    if (visibleEl) visibleEl.textContent = String(revealedArrows + revealedSpheres);
    if (arrowsEl) arrowsEl.textContent = String(revealedArrows);
    if (spheresEl) spheresEl.textContent = String(revealedSpheres);
  }
  if (P2_STATE.controls) P2_STATE.controls.update();
  if (P2_STATE.renderer && P2_STATE.scene && P2_STATE.camera) {
    P2_STATE.renderer.render(P2_STATE.scene, P2_STATE.camera);
  }
}

function startP2() {
  if (P2_STATE.running) return;
  // Lazy scene construction: container must be visible (clientWidth > 0)
  // for WebGLRenderer to size correctly. If the cache hasn't populated
  // yet, this returns false and we leave running=false; prism-tabs.js
  // tolerates this (re-clicking the tab calls start() again).
  if (!ensureInitialized()) return;
  P2_STATE.running = true;
  animateP2();
}

function stopP2() {
  if (P2_STATE.rafHandle !== null) {
    cancelAnimationFrame(P2_STATE.rafHandle);
    P2_STATE.rafHandle = null;
  }
  P2_STATE.running = false;
}

// ────────────────────────────────────────────────────────────────────
// Bootstrap (defer until prism.js has populated the cache)
// ────────────────────────────────────────────────────────────────────

const BOOT_RETRY_MS = 100;
const BOOT_MAX_RETRIES = 50;
let _bootAttempts = 0;

// Cache-poll only; scene construction is LAZY (deferred until first start)
// because the panel container is display:none on landing and reading
// clientWidth/clientHeight then returns 0, which makes THREE.WebGLRenderer
// commit to a 0x0 size that never recovers.
function bootP2() {
  if (typeof THREE === 'undefined') {
    console.error('Panel 2: THREE.js not loaded');
    return;
  }
  const cache = window.__PRISM_TIMELINE_CACHE;
  if (!cache) {
    _bootAttempts++;
    if (_bootAttempts >= BOOT_MAX_RETRIES) {
      console.error('Panel 2: timeline cache never populated after', BOOT_MAX_RETRIES, 'retries');
      const c = document.getElementById('panel2-canvas');
      if (c) c.innerHTML =
        '<div style="position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);' +
        'color:#94a3b8;font-family:JetBrains Mono,monospace;font-size:13px;">' +
        'TIMELINE LOAD FAILED</div>';
      return;
    }
    setTimeout(bootP2, BOOT_RETRY_MS);
    return;
  }

  P2_STATE.cache = cache;

  // Subscribe + sync NOW so we receive state events even before init.
  // visibleSet is populated lazily from the first state event with the
  // initial operatorFilter — see ensureInitialized().
  if (window.PrismState) {
    P2_STATE.unsubscribe = window.PrismState.subscribe(onStateEvent);
    const initial = window.PrismState.getState();
    P2_STATE.lastOperatorFilter = initial.operatorFilter;
    rebuildVisibleSet(initial.visiblePairs.length > 0 ? initial.visiblePairs : cache.pairs);
  } else {
    P2_STATE.visibleSet = new Set(cache.pairs.map((p) => p.pair_index));
  }

  P2_STATE.ready = true;

  // Auto-start ONLY if Panel 2 is already the active tab. Otherwise wait
  // for prism-tabs.js to call PrismPanel2.start() on tab switch. start()
  // will lazily run the scene/primitive construction once the container
  // is visible (clientWidth/Height non-zero).
  if (document.body.dataset.activeTab === 'trajectories') {
    startP2();
  }
}

function ensureInitialized() {
  if (P2_STATE.scene) return true;  // already built
  if (!P2_STATE.cache) return false;  // cache not loaded yet
  try {
    initSceneP2();
  } catch (err) {
    console.error('Panel 2: scene init failed:', err);
    return false;
  }
  buildPrimitives(P2_STATE.cache.pairs);
  console.log(
    `Panel 2: built ${P2_STATE.arrowCount} arrows + ${P2_STATE.sphereCount} spheres ` +
    `from ${P2_STATE.cache.pairs.length} pairs (drift pair_index=${P2_STATE.driftPairIndex})`
  );
  return true;
}

window.PrismPanel2 = {
  start:     startP2,
  stop:      stopP2,
  isRunning: () => P2_STATE.running,
  isReady:   () => P2_STATE.ready,
  isBuilt:   () => P2_STATE.scene !== null,
};

// Defer bootstrap until DOM is parsed and prism.js has had a chance to run init()
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => setTimeout(bootP2, 0));
} else {
  setTimeout(bootP2, 0);
}
```

- [ ] **Step 2: Reload the page; confirm Panel 2 builds correctly even though it's hidden**

Open the page (still landing on Labyrinth tab). In the console:

```
PrismPanel2.isReady()
// → true (after ~100-500ms; bootP2 retries until cache is set)

PrismPanel2.isRunning()
// → false (Trajectories isn't the active tab)
```

Now manually toggle the tab via body attribute and start Panel 2:

```
document.body.dataset.activeTab = 'trajectories';
PrismPanel1.stop();
PrismPanel2.start();
```

The page should now show the Panel 2 canvas with the bounding cube, three axis labels (ARCHITECT, SKEPTIC, ORACLE), and ~97 arrows clustered in one corner of the cube + 1 red arrow pointing toward the center. The scene should autorotate (unless `prefers-reduced-motion`).

If arrows are missing or scene is empty, check console for errors. Common issues:
- `THREE.ArrowHelper`-related — confirm r128 has ArrowHelper (it does)
- Wrong cache shape — `window.__PRISM_TIMELINE_CACHE.pairs[0]` should have `baseline_llm` and `mutated_llm` dicts

Switch back manually:

```
document.body.dataset.activeTab = 'labyrinth';
PrismPanel2.stop();
PrismPanel1.start();
```

- [ ] **Step 3: Commit**

```bash
cd "E:/Skyframe Innovations Website/skyframe-main"
git add assets/ares/prism-panel2.js
git commit -m "feat(prism): prism-panel2.js Confidence Trajectories renderer

98 arrows from baseline_llm to mutated_llm in (architect, skeptic,
oracle) confidence space. Bounding cube + axis cross + JetBrains
Mono axis labels. Broad-leakage pair gets longer red arrow; held
pairs grey-blue. Per-frame reveal poll keyed off PrismState
activeCycleIndex; visibleSet rebuilt only on operatorFilter change.

Defers bootstrap until window.__PRISM_TIMELINE_CACHE populated by
prism.js (50x100ms retries, then fail-loud banner). Exposes
window.PrismPanel2 = {start, stop, isRunning, isReady}.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

### Task 6: Create `prism-tabs.js` (tab UI + start/stop wiring)

**Files:**
- Create: `assets/ares/prism-tabs.js`

Final new JS file. Wires the two `.tab-btn` buttons to toggle `body[data-active-tab]` and call `start()`/`stop()` on each panel.

- [ ] **Step 1: Create the file**

Create `assets/ares/prism-tabs.js`:

```js
/*
 * ARES Prism — tab UI for Panel 1 / Panel 2 switching.
 *
 * Toggles body[data-active-tab] between 'labyrinth' and 'trajectories'.
 * Calls start()/stop() on each panel so the inactive panel's rAF loop
 * is cancelled (saves GPU + battery; switching back resumes from
 * current PrismState).
 *
 * Spec: docs/superpowers/specs/2026-05-20-prism-panel2-confidence-trajectories-design.md §3.4
 */

'use strict';

(function() {
  function activate(tab) {
    if (tab !== 'labyrinth' && tab !== 'trajectories') return;
    document.body.dataset.activeTab = tab;
    if (tab === 'labyrinth') {
      if (window.PrismPanel2 && window.PrismPanel2.isRunning && window.PrismPanel2.isRunning()) {
        window.PrismPanel2.stop();
      }
      if (window.PrismPanel1 && window.PrismPanel1.start) {
        window.PrismPanel1.start();
      }
    } else {
      if (window.PrismPanel1 && window.PrismPanel1.isRunning && window.PrismPanel1.isRunning()) {
        window.PrismPanel1.stop();
      }
      // Panel 2 may not be ready yet (cache-retry loop still running);
      // start() is a no-op until bootP2 completes, but we call it
      // optimistically. bootP2 also auto-starts if it sees the active
      // tab is already 'trajectories' when it finishes.
      if (window.PrismPanel2 && window.PrismPanel2.start) {
        window.PrismPanel2.start();
      }
    }
  }

  function init() {
    const buttons = document.querySelectorAll('.tab-btn[data-tab]');
    buttons.forEach((btn) => {
      btn.addEventListener('click', () => activate(btn.dataset.tab));
    });
    // Initial state read from body attribute (set in HTML)
    const initial = document.body.dataset.activeTab || 'labyrinth';
    document.body.dataset.activeTab = initial;
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
```

- [ ] **Step 2: Reload the page; verify tabs work end-to-end**

Open the page. Console should be clean (all 404s now resolved).

Click `▣ Trajectories`. Expected:
- Tab strip highlight moves to Trajectories
- Panel 1 chambers disappear (container hidden via CSS)
- Panel 2 canvas appears with cube + arrows + autorotate
- Console: `PrismPanel1.isRunning()` → `false`, `PrismPanel2.isRunning()` → `true`

Click `▣ Labyrinth`. Expected:
- Tab strip highlight moves back to Labyrinth
- Panel 2 hides, Panel 1 reappears
- Panel 1 resumes from current playhead (does NOT restart from 0)
- Console: `PrismPanel1.isRunning()` → `true`, `PrismPanel2.isRunning()` → `false`

- [ ] **Step 3: Commit**

```bash
cd "E:/Skyframe Innovations Website/skyframe-main"
git add assets/ares/prism-tabs.js
git commit -m "feat(prism): prism-tabs.js tab UI + panel start/stop wiring

Two-tab strip (Labyrinth / Trajectories) toggles body[data-active-tab]
and start()/stop()s the inactive panel's rAF. Switching back resumes
from current PrismState (no replay reset). Init runs on DOMContentLoaded
so tabs work even if prism-panel2.js is still bootstrapping.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

### Task 7: Manual verification — full §5.2 checklist via Playwright MCP

**Files:** none modified.

This is the spec's §5.2 checklist, run via Playwright MCP on the local file URL. No commit; verification only. If any check fails, fix the responsible task and re-run.

- [ ] **Step 1: Navigate to the page**

Use Playwright MCP:
```
browser_navigate(url='file:///E:/Skyframe%20Innovations%20Website/skyframe-main/assets/ares/prism.html')
```

Wait 1500ms for boot. Take a snapshot to confirm Panel 1 chamber chain is visible.

- [ ] **Step 2: Check #1 — initial landing state**

In JS via `browser_evaluate`:
```js
({
  activeTab:        document.body.dataset.activeTab,
  panel1Running:    window.PrismPanel1.isRunning(),
  panel2Ready:      window.PrismPanel2.isReady(),
  panel2Running:    window.PrismPanel2.isRunning(),
  panel1Visible:    document.getElementById('panel1-container').offsetParent !== null,
  panel2Visible:    document.getElementById('panel2-container').offsetParent !== null,
})
```
Expected: `{activeTab: 'labyrinth', panel1Running: true, panel2Ready: true, panel2Running: false, panel1Visible: true, panel2Visible: false}`.

- [ ] **Step 3: Check #2 — click Trajectories tab**

```
browser_click(selector='.tab-btn[data-tab="trajectories"]')
```
Then re-run the eval from Step 2. Expected: `panel1Running: false, panel2Running: true, panel1Visible: false, panel2Visible: true`.

Take a screenshot of the Panel 2 canvas.

- [ ] **Step 4: Check #3 — scrub back to 0, switch panels**

Switch back to Labyrinth, drag scrubber to 0, switch to Trajectories:
```
browser_click(selector='.tab-btn[data-tab="labyrinth"]')
browser_evaluate(js="document.getElementById('scrubber').value=0; document.getElementById('scrubber').dispatchEvent(new Event('input'));")
browser_click(selector='.tab-btn[data-tab="trajectories"]')
```
Wait 500ms. Then:
```js
({
  playhead: PrismState.getState().activeCycleIndex,
  visible: document.getElementById('stat2-visible').textContent,
})
```
Expected: `playhead: 0, visible: '1'` (pair 0 is revealed when playhead is 0; reveal predicate is `pair_index ≤ activeCycleIndex`).

- [ ] **Step 5: Check #4 — mid-replay switch picks up at playhead**

Switch back to Labyrinth, let it play for a few seconds, switch to Trajectories. Check `visible` count is > 0 and ≤ 98 (and arrows + spheres sums to `visible`). Take screenshot.

- [ ] **Step 6: Check #5 — operator filter to framing_suffix_v1 (the broad-leakage operator)**

```
browser_click(selector='.tab-btn[data-tab="labyrinth"]')
browser_evaluate(js="const s=document.getElementById('operator-dial'); s.value='framing_suffix_v1'; s.dispatchEvent(new Event('change'));")
browser_click(selector='.tab-btn[data-tab="trajectories"]')
```
Wait 2000ms for replay. Verify the broad-leakage primitive renders as a glowing red **sphere** (NOT an arrow) at the held-cluster coord:
```js
({
  filter: PrismState.getState().operatorFilter,
  visibleCount: PrismState.getState().visiblePairs.length,
  driftBit: document.getElementById('stat2-drift').textContent,
})
```
Expected: `filter: 'framing_suffix_v1', visibleCount: 33, driftBit: 'citation surface'`. Take screenshot and confirm: one glowing red sphere is present alongside the grey-blue arrows + dim spheres for this operator's other 32 pairs. The red sphere should be at a position visually indistinguishable from the held cluster — that's exactly the Session 059 narrative.

- [ ] **Step 7: Check #6 — operator filter to synonym_substitution_conservative_v2**

```
browser_click(selector='.tab-btn[data-tab="labyrinth"]')
browser_evaluate(js="const s=document.getElementById('operator-dial'); s.value='synonym_substitution_conservative_v2'; s.dispatchEvent(new Event('change'));")
browser_click(selector='.tab-btn[data-tab="trajectories"]')
```
Wait 2000ms. Verify exactly 32 primitives reveal:
```js
({
  filter: PrismState.getState().operatorFilter,
  visiblePairCount: PrismState.getState().visiblePairs.length,
  revealedVisible: document.getElementById('stat2-visible').textContent,
  revealedArrows: document.getElementById('stat2-arrows').textContent,
  revealedSpheres: document.getElementById('stat2-spheres').textContent,
})
browser_console_messages()
```
Expected: `visiblePairCount: 32` (the Phase A pipeline already dropped the no-op pair from the JSON; the operator dial just filters to membership). Panel 2 revealed primitives for this filter total 32, split into some arrows (pairs with confidence movement) and some spheres (zero-delta held pairs). Zero `console.warn`, zero `console.error`. The Panel 2 init log line printed once at boot is expected.

- [ ] **Step 8: Check #7 — reduced-motion**

Emulate `prefers-reduced-motion: reduce` and reload:
```
browser_evaluate(js="window.matchMedia('(prefers-reduced-motion: reduce)').matches")  // sanity check
```
Playwright MCP exposes this via emulation; if not directly, manually verify by toggling OS setting and refreshing. Confirm Panel 2 autorotate is off (cube stays still).

- [ ] **Step 9: Check #8 — console clean**

```
browser_console_messages()
```
Expected: zero errors, zero unexpected warnings. Only acceptable messages are:
- `Prism: loaded 98 pairs, operators: [...]` (Panel 1 init log)
- `Panel 2: built <N> arrows + <M> spheres from 98 pairs (drift pair_index=1)` (Panel 2 init log, once at boot)

- [ ] **Step 10: Panel 1 regression smoke (spec §5.3)**

Switch back to Labyrinth. Verify all Session 062 behaviors still work:
- Autoplay from landing ✓
- Scrubber drag updates view ✓
- Operator dial filter applies ✓
- Click a crumb sphere → focuses that cycle (other pins fade) ✓
- Click off the cycle → focus releases ✓
- Press Escape → focus releases ✓

If ANY of these is broken, the surgical edits in Task 4 are wrong. Revert and diagnose.

### Task 8: Push skyframe-main to main (triggers Netlify deploy)

**Files:** none modified.

Verification has passed. Push all six commits (HTML chrome, state, prism.js edits, panel2, tabs, plus whatever pre-existed) so Netlify deploys.

- [ ] **Step 1: Confirm the commit log**

```bash
cd "E:/Skyframe Innovations Website/skyframe-main"
git log --oneline -10
```

Expected: top 5 commits are this session's work (Tasks 2, 3, 4, 5, 6); commit `132201c` (the last Session 062 commit) is at position 6 or below.

- [ ] **Step 2: Push to main**

```bash
cd "E:/Skyframe Innovations Website/skyframe-main"
git push origin main
```

Expected: clean push, no rejections. Netlify deploy kicks off automatically.

- [ ] **Step 3: Wait ~60s and verify the live URL**

Visit the live skyframe URL (the actual URL is in Dan's bookmarks — typical pattern is `https://<site>.netlify.app/assets/ares/prism.html` or a custom domain). Confirm the tab strip is live and both panels work in production.

If the deploy fails (Netlify build error), check Netlify dashboard. This is a static-assets-only change so no build step should be involved; failure indicates a path issue.

---

## Phase C — ARES squash-merge + CLAUDE.md

### Task 9: Update CLAUDE.md, run full suite, squash-merge ARES to main

**Files:**
- Modify: `C:/ares-phase-zero/CLAUDE.md`

Mirrors the Session 062 pattern. New session entry, floor bump, new Visualization heading entry.

- [ ] **Step 1: Add the Session 063 entry to CLAUDE.md**

In `CLAUDE.md`, find the existing "## Session 062 — Prism Labyrinth (Panel 1) renderer" section. After its final paragraph, add (preserving the leading newline and trailing newline):

```markdown

## Session 063 — Prism Panel 2 (Confidence Trajectories) renderer
- Origin: Panel 1 shipped Session 062 with autoplay-first replay + scrubber + operator dial. The validated mockup at `docs/marketing/prism-mockup.html` lines 573-619 showed Panel 2 as a static autorotating scatter of confidence points; Session 063 lands the production version as a trajectory-replay (baseline→mutated arrows) under a tab strip in the existing `prism.html`.
- Architecture: Approach C — freeze `prism.js`, add three new sibling JS files on skyframe-main (`prism-state.js` event bus, `prism-tabs.js` tab UI, `prism-panel2.js` scene + arrows + reveal). Six `PrismState.publish()` insertions in `prism.js` after existing STATE mutations; `window.__PRISM_TIMELINE_CACHE` exposed so Panel 2 doesn't refetch; `window.PrismPanel1 = {start, stop, isRunning}` export with stoppable rAF so the tab module can pause the inactive panel. Panel 2's reveal polls `PrismState.getState().activeCycleIndex` per-frame inside its own rAF (Panel 1 doesn't publish on its 60Hz `tickReplay` loop, only on user-input handlers — event-driven reveal would have missed every autoplay tick).
- ARES-side: 4 new tests appended to `test_prism_timeline_json_contract.py` locking the Panel 2 contract — per-layer confidences on `baseline_llm` and `mutated_llm`, the documented 1-pair no-op count from Session 058.5, and a minimum confidence-delta on the broad-leakage pair. Catches Phase A pipeline regressions before they surface silently in the browser.
- Floor raised 3,733 → 3,737; ARES side adds 4 tests to one existing file. No edits to existing ARES code outside `CLAUDE.md`. Zero regressions.
```

Then update the "## Where We Are" section. Replace the last bullet (`- Session 062: Prism Labyrinth (Panel 1) renderer...`) with the original bullet **plus** a new bullet:

```markdown
- Session 063: Prism Panel 2 (Confidence Trajectories) renderer — per-pair arrows from baseline-confidence-coord to mutated-confidence-coord in (architect, skeptic, oracle) space, under a tab strip in the existing `prism.html`. Shared timeline via `window.PrismState` event bus; Panel 2 polls per-frame (Panel 1 doesn't publish on 60Hz tickReplay). 4 new JSON contract tests on ARES side (floor 3,733 → 3,737); 3 new JS files + 2 modifications on skyframe-main. Panel 1 behavior unchanged.
```

Update the header date and floor:

Replace:
```markdown
**Last updated:** 2026-05-19
**Test count floor (passing):** 3,733
```
with:
```markdown
**Last updated:** 2026-05-20
**Test count floor (passing):** 3,737
```

Also update the file title:
Replace `# CLAUDE.md — ARES Phase 7 (post-Session 062)` with `# CLAUDE.md — ARES Phase 7 (post-Session 063)`.

Finally, add a new entry to the `### Visualization (Phase 7 / Session 062)` heading by adding a new heading **after** it:

```markdown

### Visualization (Phase 7 / Session 063)
- Panel 2 (Confidence Trajectories) renderer: tab-strip layout in existing `prism.html`. Three new sibling JS files on skyframe-main:
  - `assets/ares/prism-state.js` — event bus (`window.PrismState`: getState / publish / subscribe)
  - `assets/ares/prism-tabs.js` — tab UI, start/stop wiring
  - `assets/ares/prism-panel2.js` — Panel 2 scene + 98 arrows + per-frame reveal + start/stop
- `assets/ares/prism.js` surgical edits: 6 publish inserts after existing STATE mutations, `window.__PRISM_TIMELINE_CACHE` exposed, `window.PrismPanel1 = {start, stop, isRunning}` with stoppable rAF
- JSON contract test additions: `ares/dialectic/tests/visualization/test_prism_timeline_json_contract.py` (4 new tests, floor 3,733 → 3,737)
- Design spec: `docs/superpowers/specs/2026-05-20-prism-panel2-confidence-trajectories-design.md`
- Implementation plan: `docs/superpowers/plans/2026-05-20-prism-panel2-confidence-trajectories.md`
```

- [ ] **Step 2: Run the CLAUDE.md freshness test**

```bash
cd C:/ares-phase-zero
python -m pytest tests/test_claude_md_freshness.py -v
```

Expected: PASS. If declared floor > actual, the test fails; in that case reduce the floor in CLAUDE.md to match the actual collected count.

- [ ] **Step 3: Run the full ARES suite**

```bash
cd C:/ares-phase-zero
python -m pytest tests/ ares/dialectic/tests/ -q
```

Expected: `3737 passed, 72 skipped` (or matching skip count). Zero failures.

- [ ] **Step 4: Commit the CLAUDE.md update on the session branch**

```bash
cd C:/ares-phase-zero
git add CLAUDE.md
git commit -m "docs: CLAUDE.md Session 063 entry (Prism Panel 2 Confidence Trajectories)

Floor 3,733 -> 3,737. New Session 063 entry under Where We Are + new
Visualization (Phase 7 / Session 063) heading in Key Code Locations.
Last-updated bumped to 2026-05-20.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

- [ ] **Step 5: Squash-merge session branch to main**

```bash
cd C:/ares-phase-zero
git checkout main
git merge --squash session/063-prism-panel2
git commit -m "Session 063: Prism Panel 2 (Confidence Trajectories) renderer (squash)

Adds Panel 2 to skyframe-main/assets/ares/prism.html under a tab strip
with Panel 1. Three new sibling JS files (prism-state.js, prism-tabs.js,
prism-panel2.js) + surgical edits to prism.js (6 publish inserts, cache
expose, stoppable rAF + PrismPanel1 export). ARES side adds 4 JSON
contract tests for Panel 2 (floor 3,733 -> 3,737).

Spec: docs/superpowers/specs/2026-05-20-prism-panel2-confidence-trajectories-design.md
Plan: docs/superpowers/plans/2026-05-20-prism-panel2-confidence-trajectories.md

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

- [ ] **Step 6: Push ARES main**

```bash
cd C:/ares-phase-zero
git push origin main
```

Expected: clean push. ARES is now at post-Session-063 state.

- [ ] **Step 7: Final state verification**

```bash
git -C C:/ares-phase-zero log --oneline -3
git -C "E:/Skyframe Innovations Website/skyframe-main" log --oneline -10
```

Both repos at post-Session-063 state. Session complete.

---

## Self-review notes

**Spec coverage:**
- §1 Goal — Task 5 (Panel 2 scene + primitive selection), Task 6 (tabs)
- §2 Architecture — Tasks 2-6 cover all 5 file changes
- §2.1 surgical edits — Task 4 with all 6 publish inserts + cache + export
- §3.1 shared state shape — Task 3 (prism-state.js exposes the 4 fields)
- §3.2 coordinate mapping + primitive selection — Task 5 (`confidenceToScene` + `buildPrimitives` arrow-vs-sphere branch)
- §3.3 reveal logic (per-frame poll) — Task 5 (`animateP2` polls `PrismState.getState()`; iterates `P2_STATE.primitives`)
- §3.4 tab switching — Task 6 (`activate` function in prism-tabs.js)
- §3.5 no-op pair handling (pipeline drops, no null branch) — Task 5 (no null check needed; `buildPrimitives` assumes mutated_llm is populated, JSON contract test guards)
- §4 error handling — Task 5 covers items 1, 2, 3, 4, 5, 6; Task 6 covers item 7 (DOMContentLoaded); item 8 (idempotent init) covered by `if (P2_STATE.running) return;` in `startP2`
- §5.1 ARES contract additions (corrected) — Task 1 (4 tests: baseline confidences, mutated confidences without null branch, dropped-pair count = 2, broad-leakage zero confidence delta + non-trivial citation-surface change)
- §5.2 manual verification — Task 7 (updated for sphere-vs-arrow expectations)
- §5.3 Panel 1 regression smoke — Task 7 Step 10
- §6 open items (incl. CLAUDE.md vs data discrepancy disclosure) — surfaced in spec, narrative captured in Task 2 panel subtitle copy

**Type consistency check:**
- `PrismState.publish(partial)` — partial keys: `activeCycleIndex`, `autoplayRunning`, `operatorFilter`, `visiblePairs`. Matches `_state` shape in prism-state.js. ✓
- `window.PrismPanel1.{start, stop, isRunning}` — declared in Task 4 Step 1; consumed in Task 6 Step 1. ✓
- `window.PrismPanel2.{start, stop, isRunning, isReady}` — declared in Task 5 Step 1; consumed in Task 6 Step 1. ✓
- `window.__PRISM_TIMELINE_CACHE` — set in Task 4 Step 2 (`loadTimeline`); read in Task 5 Step 1 (`bootP2`). ✓
- Reveal predicate `pair.pair_index <= state.activeCycleIndex` — same across spec §3.3, Task 5 Step 1, Task 7 verification. ✓
- `P2_STATE.primitives` entry shape `{pair, kind, primitive, lengthScene}` — built in `makeArrow`/`makeSphere`, consumed in `animateP2` (reads `entry.kind`, `entry.primitive.visible`). ✓
- Stats DOM ids `stat2-visible`, `stat2-arrows`, `stat2-spheres`, `stat2-drift` — set in Task 2 HTML, written in Task 5 `animateP2` + `buildPrimitives`, read in Task 7 verification. ✓

**No placeholders:** all "TBD"/"TODO"/"implement later" scanned. None present.

**Data-discovery revision history:**
- 2026-05-20: Task 1 implementer caught that `prism-timeline.json` doesn't match the original test predicates. Spec §1, §3.2, §3.3, §3.5, §5.1, §5.2, §6 updated to match data reality. Plan Tasks 1, 2, 5, 7 updated correspondingly. Both spec and plan corrections live on `session/063-prism-panel2` and get squashed into the Session 063 commit.
