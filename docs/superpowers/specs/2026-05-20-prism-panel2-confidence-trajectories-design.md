# Prism Panel 2 — Confidence Trajectories renderer (design spec)

**Date:** 2026-05-20
**Status:** Design approved by Dan, ready for implementation plan.
**Predecessor:** `2026-05-19-prism-labyrinth-renderer-v2-design.md` (Panel 1, shipped Session 062).
**Sibling reference:** `docs/marketing/prism-mockup.html` lines 573-619 (validated r160 ESM Panel 2 code, mockup-faithful palette).

## 1. Goal

Add a second visualization to the Prism page on skyframe-main:

- **Panel 1 (Labyrinth):** chamber-by-chamber per-pair replay. Already shipped.
- **Panel 2 (Confidence Trajectories):** per-pair vectors from baseline-confidence-coord to mutated-confidence-coord, revealed in pair_index order. Shows leakage as motion across the (architect_conf, skeptic_conf, oracle_conf) confidence cube.

The two panels share one timeline. One scrubber, one play/pause, one operator dial — driven from the existing Panel 1 chrome, broadcast to both panels via a tiny shared-state event bus. Only the active tab renders; the inactive tab's rAF is paused.

## 2. Architecture (Approach C — sibling layer, freeze prior work)

**Files (all on skyframe-main):**

| File | Status | Purpose |
|------|--------|---------|
| `assets/ares/prism.html` | modified | Adds tab strip, second canvas container, three new `<script>` tags. |
| `assets/ares/prism.js` | minimal surgical edits | Six `PrismState.publish({...})` insertions after existing STATE mutations. STATE shape unchanged. Plus one tiny `window.PrismPanel1 = { start, stop, isRunning }` export at end. |
| `assets/ares/prism-state.js` | new (~40 lines) | Event bus: `getState()`, `publish(partial)`, `subscribe(fn)`. Dispatches `'prism:state'` CustomEvent on window. |
| `assets/ares/prism-tabs.js` | new (~60 lines) | Tab UI, `body[data-active-tab]` toggle, calls `start()`/`stop()` on each panel. |
| `assets/ares/prism-panel2.js` | new (~300-400 lines) | Panel 2 scene, arrows, reveal logic. Subscribes to `PrismState`. |

**Stack:** Three.js r128 classic script (matches Panel 1). No build step, no bundler. Three.js loaded once via existing CDN script in `prism.html`.

**Discipline:** Panel 1 stays frozen except for the surgical state-wiring edits and the `start`/`stop` export. Pattern matches "new files only" across Sessions 045-062.

### 2.1 The surgical edits to `prism.js`

Six insertions, all of the form:

```js
if (window.PrismState) window.PrismState.publish({ /* relevant subset */ });
```

Inserted after the following existing STATE mutations (line numbers per the file as shipped in commit `132201c` on skyframe-main; numbers may shift if other work lands first):

1. **~line 467** — scrubber-input handler → publishes `activeCycleIndex`.
2. **~line 480** — play/pause toggle → publishes `autoplayRunning` + `activeCycleIndex`.
3. **~line 530** — operator-dial change → publishes `operatorFilter` + `visiblePairs`.
4. **~lines 511-512** — `recomputeReplayRuntime` → publishes reset state.
5. **~lines 614-615** — replay-completion auto-pause → publishes.
6. **~line 620** — end of `loadTimeline` → publishes initial state.

Plus, at the bottom of the file:

```js
window.PrismPanel1 = {
  start: () => { /* resume Panel 1 rAF if stopped */ },
  stop:  () => { /* cancel Panel 1 rAF */ },
  isRunning: () => /* bool */,
};
```

Zero deletions. Zero refactors. All publish calls are behind a truthiness check so `prism.js` still works if loaded without the new state module (e.g., during a rollback).

## 3. Data flow

**One-way: Panel 1 chrome → state bus → both panels.**

```
User input (chrome controls in prism.html)
  ↓
prism.js STATE mutation (existing code, unchanged)
  ↓
PrismState.publish({...})        ← new line
  ↓
'prism:state' CustomEvent dispatched on window
  ↓ (in parallel)
  ├─→ Panel 1 listener: no-op (it's the source; ignores echoes)
  └─→ Panel 2 listener: re-derives arrow visibility from new state
```

### 3.1 Shared state shape

`PrismState.getState()` returns a snapshot object (callers must treat as read-only; not deep-frozen, but never mutated by the bus):

```js
{
  activeCycleIndex: number,   // current playhead in visiblePairs order
  autoplayRunning: boolean,
  operatorFilter:  string,    // 'all' | operator name
  visiblePairs:    Array<Pair>,  // already filtered by operator
}
```

Panel-specific fields (`focusedPairIndex`, `SCENE`, Panel 2's own arrow refs) stay private to each panel.

### 3.2 Per-pair coordinate mapping (Panel 2)

For each pair where `mutated_llm !== null`:

```
baselineVec3 = (
  pair.baseline_llm.architect_confidence,
  pair.baseline_llm.skeptic_confidence,
  pair.baseline_llm.oracle_confidence,
)
mutatedVec3  = (
  pair.mutated_llm.architect_confidence,
  pair.mutated_llm.skeptic_confidence,
  pair.mutated_llm.oracle_confidence,
)

# Map [0, 1] → [−CUBE_HALF, +CUBE_HALF] on each axis (CUBE_HALF=15 per mockup)
sceneBaseline = baselineVec3.scale(CUBE_SIZE).sub(CUBE_HALF_VEC)
sceneMutated  = mutatedVec3.scale(CUBE_SIZE).sub(CUBE_HALF_VEC)

arrow = THREE.ArrowHelper(
  dir    = (sceneMutated - sceneBaseline).normalize(),
  origin = sceneBaseline,
  length = (sceneMutated - sceneBaseline).length(),
  color  = pair.broad_leakage ? 0xef4444 : 0xcbd5e1,   // red for broad-leakage, grey for held
)
```

### 3.3 Reveal logic

- All arrows built once at scene init, default `arrow.visible = false`.
- On each `'prism:state'` event:
  ```js
  const visibleSet = new Set(state.visiblePairs.map((p) => p.pair_index));
  for (const {pair, arrow} of ARROWS) {
    arrow.visible =
      visibleSet.has(pair.pair_index) &&
      pair.pair_index <= state.activeCycleIndex;
  }
  ```
- O(N) per event with the Set lookup. Recomputed without diffing — cheap enough.

### 3.4 Tab switching

- `prism-tabs.js` toggles `body[data-active-tab="labyrinth"|"trajectories"]`.
- CSS hides the inactive canvas container via `display: none`.
- Active panel's `start()` is called; inactive's `stop()` cancels its rAF.
- State bus keeps publishing regardless of which tab is active, so switching back resumes correctly without state replay.
- First tab activation: `labyrinth` (preserves Panel 1 landing behavior).

### 3.5 No-op pair handling

One pair has `mutated_llm === null` (the `synonym_substitution_conservative_v2` no-op on one scenario, per Session 058.5 audit). Skip during arrow construction with a debug log. Not an error. JSON contract test (§5) locks this count at exactly 1.

## 4. Error handling (fail-loud, fail-visible)

1. **Three.js missing** — `prism-panel2.js` checks `typeof THREE === 'undefined'` at top of `init()`; if missing, `console.error` + DOM banner in `#panel2-canvas-container`.
2. **WebGL unavailable** — reuses Panel 1's `webglAvailable()` helper (commit `8873870`). Same banner pattern.
3. **`prism-timeline.json` fetch failure** — Panel 2 doesn't refetch; reads from `window.__PRISM_TIMELINE_CACHE` set by Panel 1 on load. If cache empty, defers via `setTimeout(init, 100)` up to 50 retries (~5s), then `console.error` + DOM banner.
4. **Malformed pair data** — try/catch per pair during arrow construction; bad pair logs `console.warn` and is skipped. Arrow count is informational, never asserted at runtime.
5. **State publish before Panel 2 ready** — on `init()`, Panel 2 calls `PrismState.getState()` to backfill (subscribe + sync pattern).
6. **`prefers-reduced-motion`** — Panel 2 inherits the gate from `prism.js` (commit `1a91e13`). Reveal becomes snap-cuts (no tweens), autorotate disabled.
7. **Tab init race** — `prism-tabs.js` loaded last; click handlers attached after `DOMContentLoaded`. `init()` idempotent; double-call no-ops.

**Out of scope:** network retry beyond Panel 1's existing fetch behavior, 2D fallback, custom touch gestures.

## 5. Testing

### 5.1 ARES side — JSON contract additions

File: `ares/dialectic/tests/visualization/test_prism_timeline_json_contract.py` (existing, 8 tests from Session 062).

Add 4 new tests, raising the floor 3,733 → 3,737:

1. `test_every_pair_has_baseline_llm_confidences` — for each non-no-op pair, `baseline_llm` contains `architect_confidence`, `skeptic_confidence`, `oracle_confidence`; all floats in `[0.0, 1.0]`.
2. `test_every_pair_has_mutated_llm_confidences_or_explicit_null` — `mutated_llm` is either null OR contains the same three confidence fields with same range invariant.
3. `test_no_op_pair_count_matches_audit` — exactly 1 pair has `mutated_llm === null` (matches Session 058.5 audit).
4. `test_broad_leakage_pair_has_nonzero_confidence_delta` — the single broad-leakage pair has at least one of the three Δ-confidence values ≥ 0.01.

Zero edits to existing ARES code outside `CLAUDE.md` and this new test block.

### 5.2 skyframe-main side — manual verification checklist (Playwright MCP on local file URL)

1. Page loads with `data-active-tab="labyrinth"` — Panel 1 renders, Panel 2 hidden.
2. Click `TRAJECTORIES` — Panel 2 visible, Panel 1 hidden. `window.PrismPanel1.isRunning() === false`.
3. Scrub Panel 1 back to 0, switch to Panel 2 — zero arrows.
4. Play Panel 1, switch mid-replay — Panel 2 reveals arrows in lockstep, picks up at current playhead.
5. Operator filter to `framing_suffix_v1` — switch to Panel 2 — only matching arrows visible; red broad-leakage arrow is in the set.
6. Operator filter to `synonym_substitution_conservative_v2` — Panel 2 shows exactly 32 arrows (33 scenarios minus 1 documented no-op); no console warnings.
7. Reduced-motion media query — autorotate off; arrows reveal as snap-cuts.
8. Console clean: zero errors, zero unexpected warnings.

### 5.3 Panel 1 regression smoke

Re-run all Session 062 manual checks: autoplay from landing, scrubber works, operator dial works, click-to-focus chambers, click-elsewhere releases focus. If any Panel 1 behavior changes, surgical edits to `prism.js` are wrong and get reverted.

### 5.4 No anchor test added

Panel 2's `init()` is the entry point; refactor risk caught by manual checklist. Anchor tests reserved for cross-cutting kill criteria (e.g., `light_skeptic.py:185`), not renderer entry points.

## 6. Open items

- **Floor expectation post-merge:** ARES count 3,733 → 3,737 (4 new contract tests). CLAUDE.md updated to reflect post-Session-063 (or whatever session number this lands as).
- **First tab on landing:** Labyrinth, hard-coded. No URL hash deep-link support in v1 (could be added later as `#trajectories`).
- **Arrow shaft thickness:** ArrowHelper default (`headLength`, `headWidth`) tuned to match the mockup's visual weight; concrete numbers picked during implementation pass against the live scene.
- **No-op-pair handling in operator filter:** when filtering to the operator whose no-op pair exists, the filtered set is 32 not 33; this is correct, not a bug.

## 7. Files at a glance

**New (4):**
- `assets/ares/prism-state.js`
- `assets/ares/prism-tabs.js`
- `assets/ares/prism-panel2.js`
- `ares/dialectic/tests/visualization/test_prism_timeline_json_contract.py` (additions to existing file — counts as additions, not new file)

**Modified (2):**
- `assets/ares/prism.html`
- `assets/ares/prism.js` (six publish-call insertions + one window export)

**Updated (1):**
- `CLAUDE.md` — new session entry + updated floor.

**Untouched:**
- `assets/ares/prism-timeline.json` — data unchanged.
- All other Panel 1 internals.
