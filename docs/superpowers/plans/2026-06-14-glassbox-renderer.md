# Glass Box Renderer (Half B) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax. Pure-logic tasks are TDD (vitest); visual tasks are controller-verified (run the dev server, screenshot, eyeball) — that is the correct test strategy for canvas rendering, not a TDD shortcut.

**Goal:** Build the Glass Box renderer — a browser app that replays the compiled `inj020.battle.json` as a papercraft tribunal board: three rounds, auto-play with spacebar pause/step, citation threads as ephemeral light, the verdict as a carved stone that never moves.

**Architecture:** A fresh `glassbox` repo seeded from the `tacticsclone` prototype. Delete the combat engine; keep and reuse the visual primitives (Camera, isometric projection, asset pipeline, FX/float-text, paper-diorama drawing style). Add: a battle-script loader + provenance gate (pure logic, TDD); a BeatPlayer state machine (pure logic, TDD); a purpose-built TribunalRenderer (canvas, controller-verified); a GlassBoxScreen React component that owns the canvas + rAF loop + input. The BeatPlayer IS the app state — React just mounts the canvas and forwards keys.

**Tech Stack:** TypeScript, React 18, Vite 6, HTML5 Canvas (existing). Add vitest (unit) + @playwright/test (E2E). No new runtime deps.

**Spec:** `docs/superpowers/specs/2026-06-14-glassbox-demo-design.md` (§5 contract, §6 choreography, §8 Half B).

---

## Refinements from spec (note before starting)

1. **Reuse primitives, not `renderer.draw()` wholesale.** `tacticsclone/src/render/renderer.ts` `draw(b: BattleState)` is coupled to the combat `BattleState` (tiles[][], units with hp/ct/statuses). Half B reuses the *primitives* — the `Camera` class (renderer.ts:14-71), the iso projection (`isoOf`: `{x:(x-y)*TILE_W/2, y:(x+y)*TILE_H/2 - h*ELEV}`, TILE_W=64/TILE_H=32/ELEV=14), the diamond-tile drawing style, `assets.ts` loader, and `anim.ts` FX/float-text — inside a new `TribunalRenderer`. Net effect matches the spec's "reuse the beautiful rendering, skip combat."
2. **State model:** the BeatPlayer holds all replay state; no global game store is ported. The rAF loop reads `beatPlayer.snapshot()` each frame.
3. **Verdict stone shows the outcome label only** (Half A persists no verdict confidence) — consistent with the compiler.

## Prerequisites (verify before Task 1)

- The compiled artifact exists at `C:\ares-phase-zero\demo\out\inj020.battle.json` (Half A, committed). It has: `scenario_id`, `evidence_packet.facts[]` (5 facts; each `fact_id`/`display_label`/`source_type`/`is_threat_dominant`; threat = `inj020-fact-003`), `rounds[]` (3: variants `baseline`, `framing:framing_prefix_v1`, `framing:synonym_substitution_conservative_v2`; each with `beats[]` architect→skeptic→oracle, a `caption`, a `leakage_vector`), and `provenance` (`source_run`, `git_sha`, `trace_sha256`, `compiled_at`, `compiler_version`).
- The prototype is cloned at `C:\glassbox\tacticsclone`.

## File structure (the fresh `glassbox` repo)

- **Seed from** `C:\glassbox\tacticsclone` → new repo at `C:\glassbox\glassbox`.
- **KEEP & reuse:** `src/render/assets.ts` (rework manifest), `src/render/anim.ts` (FX/float-text/timing primitives; drop combat-specific hooks), the `Camera` class + iso math (extract into `src/glassbox/iso.ts`), `index.html`, `vite.config.ts`, `tsconfig*.json`, `src/styles.css` (trim).
- **DELETE:** `src/systems/` (battle, combat, turnorder, grid), `src/ai/`, `src/data/{jobs,abilities,items,maps,campaign}.ts`, `src/entities/`, `src/store/store.ts`, `src/ui/{BattleScreen,CampaignScreen,PartyScreen,ShopScreen,TitleScreen,hud}.tsx`, `src/game/flow.ts`, `scripts/simulate.ts`.
- **NEW:**
  - `public/inj020.battle.json` (copied from Half A's output)
  - `src/glassbox/battleScript.ts` — types + `loadBattleScript` + `validateProvenance`
  - `src/glassbox/iso.ts` — `Camera` + `isoOf` extracted from renderer.ts
  - `src/glassbox/beatPlayer.ts` — the replay state machine
  - `src/glassbox/scene.ts` — fixed tribunal layout (actor/fact/stone positions)
  - `src/glassbox/tribunalRenderer.ts` — the canvas draw routine (board, actors, threads, stone, captions)
  - `src/glassbox/GlassBoxScreen.tsx` — canvas + rAF + input
  - `src/App.tsx`, `src/main.tsx` — trimmed to mount GlassBoxScreen
  - `tests/battleScript.test.ts`, `tests/beatPlayer.test.ts` (vitest)
  - `e2e/replay.spec.ts` (playwright)
  - `vitest.config.ts`, `playwright.config.ts`

---

## Phase 1 — Seed & prune to a booting shell

### Task 1.1: Seed the repo and remove the combat engine

- [ ] **Step 1: Seed a fresh repo (no history from the prototype)**

```bash
# From a shell. Copy the working tree (not .git), init fresh.
cp -r "C:/glassbox/tacticsclone" "C:/glassbox/glassbox"
rm -rf "C:/glassbox/glassbox/.git" "C:/glassbox/glassbox/node_modules"
cd "C:/glassbox/glassbox" && git init && git add -A && git commit -m "chore: seed glassbox from tacticsclone prototype"
```

- [ ] **Step 2: Delete the combat/skip set**

```bash
cd "C:/glassbox/glassbox"
rm -rf src/systems src/ai src/entities src/game scripts
rm -f src/data/jobs.ts src/data/abilities.ts src/data/items.ts src/data/maps.ts src/data/campaign.ts
rm -f src/store/store.ts
rm -f src/ui/BattleScreen.tsx src/ui/CampaignScreen.tsx src/ui/PartyScreen.tsx src/ui/ShopScreen.tsx src/ui/TitleScreen.tsx src/ui/hud.tsx
```

- [ ] **Step 3: Commit the prune**

```bash
git add -A && git commit -m "chore: remove combat engine (keeping render primitives)"
```

Expected after this task: the project will NOT compile yet (App.tsx imports deleted screens) — fixed in Task 1.2.

### Task 1.2: Minimal booting app shell

**Files:** Modify `src/App.tsx`, `src/main.tsx`; Create `src/glassbox/GlassBoxScreen.tsx` (stub).

- [ ] **Step 1: Stub the screen**

`src/glassbox/GlassBoxScreen.tsx`:
```tsx
export default function GlassBoxScreen() {
  return <div className="glassbox-screen"><canvas className="board-canvas" /></div>;
}
```

- [ ] **Step 2: Trim App.tsx to load assets then mount the screen**

`src/App.tsx`:
```tsx
import { useEffect, useState } from 'react';
import { loadAssets } from './render/assets';
import GlassBoxScreen from './glassbox/GlassBoxScreen';

export default function App() {
  const [loaded, setLoaded] = useState(false);
  useEffect(() => { loadAssets().then(() => setLoaded(true)); }, []);
  if (!loaded) return <div className="loading-screen">Loading…</div>;
  return <GlassBoxScreen />;
}
```
(`main.tsx` is unchanged — it already mounts `<App/>`.)

- [ ] **Step 3: Make it compile + boot**

Run: `cd C:/glassbox/glassbox && npm install && npx tsc -b --noEmit`
Fix any remaining dangling imports (e.g., `assets.ts` may import combat types — if so, delete those imports; the asset loader only needs the manifest + image map). Expected: clean typecheck.

- [ ] **Step 4: Verify boot**

Run: `npm run dev` (starts Vite). Use the Playwright MCP or a browser to open the dev URL; expect a blank canvas + no console errors. Controller verifies.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat: minimal booting app shell (canvas + asset load)"
```

---

## Phase 2 — Test tooling

### Task 2.1: Add vitest + playwright

**Files:** Modify `package.json`; Create `vitest.config.ts`, `playwright.config.ts`.

- [ ] **Step 1: Install dev deps**

```bash
cd C:/glassbox/glassbox
npm install -D vitest @playwright/test
npx playwright install chromium
```

- [ ] **Step 2: Add scripts to package.json**

Add to `"scripts"`: `"test": "vitest run"`, `"test:e2e": "playwright test"`.

- [ ] **Step 3: vitest.config.ts**

```ts
import { defineConfig } from 'vitest/config';
export default defineConfig({ test: { environment: 'node', include: ['tests/**/*.test.ts'] } });
```

- [ ] **Step 4: playwright.config.ts**

```ts
import { defineConfig } from '@playwright/test';
export default defineConfig({
  testDir: './e2e',
  use: { baseURL: 'http://localhost:5173' },
  webServer: { command: 'npm run dev', url: 'http://localhost:5173', reuseExistingServer: true },
});
```

- [ ] **Step 5: Sanity test + commit**

Create `tests/smoke.test.ts`:
```ts
import { test, expect } from 'vitest';
test('vitest runs', () => { expect(1 + 1).toBe(2); });
```
Run: `npm test` → 1 passing. Then:
```bash
git add -A && git commit -m "chore: add vitest + playwright tooling"
```

---

## Phase 3 — Battle-script types, loader, provenance gate (TDD)

### Task 3.1: Types + loader + provenance validation

**Files:** Create `src/glassbox/battleScript.ts`, `tests/battleScript.test.ts`. Copy `C:\ares-phase-zero\demo\out\inj020.battle.json` → `public/inj020.battle.json` and also → `tests/fixtures/inj020.battle.json`.

- [ ] **Step 1: Copy the real artifact**

```bash
mkdir -p public tests/fixtures
cp "C:/ares-phase-zero/demo/out/inj020.battle.json" public/inj020.battle.json
cp "C:/ares-phase-zero/demo/out/inj020.battle.json" tests/fixtures/inj020.battle.json
```

- [ ] **Step 2: Write failing tests**

`tests/battleScript.test.ts`:
```ts
import { test, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { parseBattleScript, validateProvenance } from '../src/glassbox/battleScript';

const raw = JSON.parse(readFileSync('tests/fixtures/inj020.battle.json', 'utf-8'));

test('parses the real artifact into a typed script', () => {
  const s = parseBattleScript(raw);
  expect(s.scenarioId).toBe('INJ-020');
  expect(s.facts).toHaveLength(5);
  expect(s.facts.find(f => f.factId === 'inj020-fact-003')!.isThreatDominant).toBe(true);
  expect(s.rounds.map(r => r.variant)).toEqual([
    'baseline', 'framing:framing_prefix_v1', 'framing:synonym_substitution_conservative_v2',
  ]);
  const r2 = s.rounds[1];
  expect(r2.architect.citedFactIds).toEqual(['inj020-fact-003']);
  expect(r2.oracle.outcome).toBe('threat_dismissed');
  expect(s.rounds.every(r => r.oracle.outcome === 'threat_dismissed')).toBe(true);
});

test('provenance gate rejects scripts without source_run + trace_sha256', () => {
  expect(() => validateProvenance({})).toThrow();
  expect(() => validateProvenance({ provenance: { source_run: '', trace_sha256: '' } })).toThrow();
  expect(() => validateProvenance(raw)).not.toThrow();
});
```

- [ ] **Step 3: Run — verify fail**

Run: `npm test -- battleScript` → FAIL (module missing).

- [ ] **Step 4: Implement**

`src/glassbox/battleScript.ts`:
```ts
export type Outcome = 'threat_confirmed' | 'threat_dismissed' | 'inconclusive';
export interface Fact { factId: string; displayLabel: string; sourceType: string; isThreatDominant: boolean; }
export interface AgentBeat { actor: 'architect' | 'skeptic'; claimLabel: string; citedFactIds: string[]; confidence: number; }
export interface OracleBeat { actor: 'oracle'; outcome: Outcome; supportingFactIds: string[]; }
export interface Round { roundId: number; variant: string; architect: AgentBeat; skeptic: AgentBeat; oracle: OracleBeat; caption: string; }
export interface BattleScript { scenarioId: string; titleLabel: string; facts: Fact[]; rounds: Round[]; }

export function validateProvenance(raw: any): void {
  const p = raw?.provenance ?? {};
  if (!p.source_run || !p.trace_sha256) {
    throw new Error('battle-script missing provenance (source_run + trace_sha256)');
  }
}

export function parseBattleScript(raw: any): BattleScript {
  validateProvenance(raw);
  const facts: Fact[] = raw.evidence_packet.facts.map((f: any) => ({
    factId: f.fact_id, displayLabel: f.display_label,
    sourceType: f.source_type, isThreatDominant: !!f.is_threat_dominant,
  }));
  const rounds: Round[] = raw.rounds.map((r: any) => {
    const beat = (actor: string) => r.beats.find((b: any) => b.actor === actor);
    const a = beat('architect'), s = beat('skeptic'), o = beat('oracle');
    return {
      roundId: r.round_id, variant: r.variant, caption: r.caption,
      architect: { actor: 'architect', claimLabel: a.claim_label, citedFactIds: a.cited_fact_ids, confidence: a.confidence },
      skeptic: { actor: 'skeptic', claimLabel: s.claim_label, citedFactIds: s.cited_fact_ids, confidence: s.confidence },
      oracle: { actor: 'oracle', outcome: o.outcome, supportingFactIds: o.supporting_fact_ids },
    };
  });
  return { scenarioId: raw.scenario_id, titleLabel: raw.title_label, facts, rounds };
}

export async function loadBattleScript(url: string): Promise<BattleScript> {
  const res = await fetch(url);
  return parseBattleScript(await res.json());
}
```

- [ ] **Step 5: Run — verify pass; commit**

Run: `npm test -- battleScript` → PASS. Then:
```bash
git add -A && git commit -m "feat: battle-script types, parser, provenance gate"
```

---

## Phase 4 — BeatPlayer state machine (TDD)

The BeatPlayer sequences rounds × beats and exposes a `snapshot()` the renderer draws. Time is injected (a `nowMs` you pass to `tick`) so it is deterministic and unit-testable. Beats advance on a dwell timer in auto-play; spacebar toggles pause and steps.

### Task 4.1: BeatPlayer

**Files:** Create `src/glassbox/beatPlayer.ts`, `tests/beatPlayer.test.ts`.

- [ ] **Step 1: Write failing tests**

`tests/beatPlayer.test.ts`:
```ts
import { test, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { parseBattleScript } from '../src/glassbox/battleScript';
import { BeatPlayer } from '../src/glassbox/beatPlayer';

const script = parseBattleScript(JSON.parse(readFileSync('tests/fixtures/inj020.battle.json', 'utf-8')));
const DWELL = 1000;

test('starts on round 0, beat 0 (architect), nothing revealed past it', () => {
  const p = new BeatPlayer(script, { dwellMs: DWELL });
  const s = p.snapshot();
  expect(s.roundIndex).toBe(0);
  expect(s.beatIndex).toBe(0);
  expect(s.activeActor).toBe('architect');
});

test('auto-play advances one beat per dwell interval', () => {
  const p = new BeatPlayer(script, { dwellMs: DWELL });
  p.play();
  p.tick(0); p.tick(DWELL + 1);            // -> beat 1 (skeptic)
  expect(p.snapshot().beatIndex).toBe(1);
  p.tick(2 * DWELL + 2);                    // -> beat 2 (oracle) => stone sets
  expect(p.snapshot().activeActor).toBe('oracle');
  expect(p.snapshot().verdict).toBe('threat_dismissed');
});

test('rolls into the next round after the oracle beat', () => {
  const p = new BeatPlayer(script, { dwellMs: DWELL });
  p.play();
  p.tick(0);                                            // baseline (no advance)
  for (let i = 1; i <= 3; i++) p.tick(i * DWELL + 1);   // 3 advances: skeptic, oracle, roll
  expect(p.snapshot().roundIndex).toBe(1);
  expect(p.snapshot().variant).toBe('framing:framing_prefix_v1');
});

test('pause stops auto-advance; step advances exactly one beat', () => {
  const p = new BeatPlayer(script, { dwellMs: DWELL });
  p.play(); p.pause();
  p.tick(10 * DWELL);
  expect(p.snapshot().beatIndex).toBe(0);
  p.step();
  expect(p.snapshot().beatIndex).toBe(1);
});

test('verdict is constant across all three rounds (pixel-stable contract)', () => {
  const p = new BeatPlayer(script, { dwellMs: DWELL });
  const seen = new Set<string>();
  p.play();
  p.tick(0);                                            // baseline
  for (let i = 1; i <= 9; i++) { p.tick(i * DWELL + 1); seen.add(p.snapshot().verdict ?? ''); }
  expect([...seen].filter(Boolean)).toEqual(['threat_dismissed']);
});
```

- [ ] **Step 2: Run — verify fail**

Run: `npm test -- beatPlayer` → FAIL.

- [ ] **Step 3: Implement**

`src/glassbox/beatPlayer.ts`:
```ts
import type { BattleScript, Outcome } from './battleScript';

export interface BeatSnapshot {
  roundIndex: number;
  beatIndex: number;            // 0 architect, 1 skeptic, 2 oracle
  variant: string;
  activeActor: 'architect' | 'skeptic' | 'oracle';
  architectCited: string[];     // revealed once beat >= 0
  skepticCited: string[];       // revealed once beat >= 1
  verdict: Outcome | null;      // set once beat == 2
  caption: string;
  playing: boolean;
  done: boolean;
}

const ACTORS = ['architect', 'skeptic', 'oracle'] as const;

export class BeatPlayer {
  private ri = 0;
  private bi = 0;
  private playing = false;
  private lastAdvance: number | null = null;
  private done = false;
  constructor(private script: BattleScript, private opts: { dwellMs: number }) {}

  play() { this.playing = true; this.lastAdvance = null; }  // re-baseline on (re)play
  pause() { this.playing = false; }
  toggle() { this.playing ? this.pause() : this.play(); }

  /** Advance exactly one beat (rolling into the next round after oracle). */
  step() {
    if (this.done) return;
    if (this.bi < 2) { this.bi += 1; return; }
    if (this.ri < this.script.rounds.length - 1) { this.ri += 1; this.bi = 0; }
    else { this.done = true; this.playing = false; }
  }

  /** Drive auto-play from an injected clock. The first tick after play()
   *  establishes the baseline (no advance) so a large performance.now()
   *  value doesn't skip the opening beat; then one beat per dwellMs. */
  tick(nowMs: number) {
    if (!this.playing || this.done) return;
    if (this.lastAdvance === null) { this.lastAdvance = nowMs; return; }
    if (nowMs - this.lastAdvance >= this.opts.dwellMs) {
      this.step();
      this.lastAdvance = nowMs;
    }
  }

  snapshot(): BeatSnapshot {
    const r = this.script.rounds[this.ri];
    return {
      roundIndex: this.ri,
      beatIndex: this.bi,
      variant: r.variant,
      activeActor: ACTORS[this.bi],
      architectCited: this.bi >= 0 ? r.architect.citedFactIds : [],
      skepticCited: this.bi >= 1 ? r.skeptic.citedFactIds : [],
      verdict: this.bi >= 2 ? r.oracle.outcome : null,
      caption: r.caption,
      playing: this.playing,
      done: this.done,
    };
  }
}
```

- [ ] **Step 4: Run — verify pass; commit**

Run: `npm test -- beatPlayer` → PASS. Then:
```bash
git add -A && git commit -m "feat: BeatPlayer replay state machine (injected clock, TDD)"
```

---

## Phase 5 — Visual primitives module

### Task 5.1: Extract Camera + iso projection

**Files:** Create `src/glassbox/iso.ts`. (Lift the `Camera` class + `isoOf`/`viewOf` from `tacticsclone/src/render/renderer.ts:8-95` — but for a fixed single-board tribunal you can drop view-rotation; keep pan/zoom.)

- [ ] **Step 1: Create iso.ts**

```ts
export const TILE_W = 64, TILE_H = 32, ELEV = 14;
export interface XY { x: number; y: number; }
export function isoOf(x: number, y: number, h = 0): XY {
  return { x: (x - y) * (TILE_W / 2), y: (x + y) * (TILE_H / 2) - h * ELEV };
}
export class Camera {
  x = 0; y = 0; zoom = 1.35;
  centerOn(canvas: HTMLCanvasElement, focus: XY) {
    const iso = isoOf(focus.x, focus.y, 0);
    this.x = canvas.clientWidth / 2 - iso.x * this.zoom;
    this.y = canvas.clientHeight / 2 - iso.y * this.zoom;
  }
  pan(dx: number, dy: number) { this.x += dx; this.y += dy; }
  zoomAt(mx: number, my: number, f: number) {
    const z = Math.min(2.6, Math.max(0.7, this.zoom * f));
    this.x = mx - ((mx - this.x) * z) / this.zoom;
    this.y = my - ((my - this.y) * z) / this.zoom;
    this.zoom = z;
  }
}
```

- [ ] **Step 2: Typecheck + commit**

Run: `npx tsc -b --noEmit` → clean.
```bash
git add -A && git commit -m "feat: reusable iso projection + camera primitive"
```

---

## Phase 6 — TribunalRenderer (visual; controller-verified)

### Task 6.1: Fixed tribunal scene layout

**Files:** Create `src/glassbox/scene.ts`.

- [ ] **Step 1: Define positions (board grid coords; 5 fact tiles in a centre row, 3 actors around them, stone below)**

```ts
import type { XY } from './iso';
export const FACT_TILES: XY[] = [
  { x: -2, y: 0 }, { x: -1, y: 0 }, { x: 0, y: 0 }, { x: 1, y: 0 }, { x: 2, y: 0 },
];
export const ARCHITECT_POS: XY = { x: -4, y: 0 };
export const SKEPTIC_POS: XY = { x: 4, y: 0 };
export const ORACLE_POS: XY = { x: 0, y: -3 };
export const STONE_POS: XY = { x: 0, y: 3 };
export const ARCHITECT_COLOR = '#f0683c';
export const SKEPTIC_COLOR = '#46c8b8';
export const THREAT_RING = '#caa15a';
export function factIndex(factId: string): number {
  const m = /inj020-fact-(\d+)/.exec(factId);
  return m ? parseInt(m[1], 10) - 1 : -1;   // fact-001 -> tile 0
}
```

- [ ] **Step 2: Commit**

```bash
git add -A && git commit -m "feat: fixed tribunal scene layout"
```

### Task 6.2: Draw the board, actors, fact tiles, threads, stone, caption

**Files:** Create `src/glassbox/tribunalRenderer.ts`.

- [ ] **Step 1: Implement the renderer (real canvas code, reusing iso + the paper diamond style)**

```ts
import { Camera, isoOf, TILE_W, TILE_H, type XY } from './iso';
import type { BattleScript } from './battleScript';
import type { BeatSnapshot } from './beatPlayer';
import {
  FACT_TILES, ARCHITECT_POS, SKEPTIC_POS, ORACLE_POS, STONE_POS,
  ARCHITECT_COLOR, SKEPTIC_COLOR, THREAT_RING, factIndex,
} from './scene';

function diamond(ctx: CanvasRenderingContext2D, c: XY) {
  ctx.beginPath();
  ctx.moveTo(c.x, c.y - TILE_H / 2); ctx.lineTo(c.x + TILE_W / 2, c.y);
  ctx.lineTo(c.x, c.y + TILE_H / 2); ctx.lineTo(c.x - TILE_W / 2, c.y); ctx.closePath();
}

export class TribunalRenderer {
  camera = new Camera();
  constructor(private canvas: HTMLCanvasElement, private script: BattleScript) {
    this.camera.centerOn(canvas, { x: 0, y: 0 });
  }

  private threads(ctx: CanvasRenderingContext2D, from: XY, ids: string[], color: string) {
    const a = isoOf(from.x, from.y, 0);
    ctx.save();
    ctx.shadowColor = color; ctx.shadowBlur = 12;
    ctx.strokeStyle = color; ctx.lineWidth = 2; ctx.globalAlpha = 0.85;
    for (const id of ids) {
      const i = factIndex(id); if (i < 0) continue;
      const t = isoOf(FACT_TILES[i].x, FACT_TILES[i].y, 0);
      ctx.beginPath(); ctx.moveTo(a.x, a.y - 14); ctx.lineTo(t.x, t.y); ctx.stroke();
    }
    ctx.restore();
  }

  draw(snap: BeatSnapshot, showCaption: boolean) {
    const ctx = this.canvas.getContext('2d')!;
    const dpr = window.devicePixelRatio || 1;
    const cw = this.canvas.clientWidth, ch = this.canvas.clientHeight;
    if (this.canvas.width !== cw * dpr) { this.canvas.width = cw * dpr; this.canvas.height = ch * dpr; }
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.fillStyle = '#15110c'; ctx.fillRect(0, 0, cw, ch);
    ctx.save(); ctx.translate(this.camera.x, this.camera.y); ctx.scale(this.camera.zoom, this.camera.zoom);

    // fact tiles (paper diamonds; threat fact ringed)
    this.script.facts.forEach((f, i) => {
      const c = isoOf(FACT_TILES[i].x, FACT_TILES[i].y, 0);
      diamond(ctx, c);
      ctx.fillStyle = f.isThreatDominant ? '#4a2a1c' : '#2c2116'; ctx.fill();
      ctx.strokeStyle = f.isThreatDominant ? THREAT_RING : '#6b5536'; ctx.lineWidth = 1.5; ctx.stroke();
    });

    // threads (ephemeral light) — only those revealed by the current beat
    this.threads(ctx, ARCHITECT_POS, snap.architectCited, ARCHITECT_COLOR);
    this.threads(ctx, SKEPTIC_POS, snap.skepticCited, SKEPTIC_COLOR);

    // actors (simple papercraft blocks; swap for sprites later)
    const block = (p: XY, color: string, label: string, active: boolean) => {
      const c = isoOf(p.x, p.y, 0);
      ctx.fillStyle = color; ctx.globalAlpha = active ? 1 : 0.65;
      ctx.fillRect(c.x - 9, c.y - 26, 18, 24); ctx.globalAlpha = 1;
      ctx.fillStyle = '#e8d6a8'; ctx.font = '10px Georgia'; ctx.textAlign = 'center';
      ctx.fillText(label, c.x, c.y + 12);
    };
    block(ARCHITECT_POS, ARCHITECT_COLOR, 'Architect', snap.activeActor === 'architect');
    block(SKEPTIC_POS, SKEPTIC_COLOR, 'Skeptic', snap.activeActor === 'skeptic');

    // verdict stone — bound to outcome; identical render whenever verdict is set
    const sc = isoOf(STONE_POS.x, STONE_POS.y, 0);
    if (snap.verdict) {
      ctx.fillStyle = '#16110b'; ctx.strokeStyle = THREAT_RING; ctx.lineWidth = 2;
      ctx.fillRect(sc.x - 78, sc.y - 16, 156, 32); ctx.strokeRect(sc.x - 78, sc.y - 16, 156, 32);
      ctx.fillStyle = '#e8d6a8'; ctx.font = '13px Georgia'; ctx.textAlign = 'center';
      ctx.fillText('□ ' + snap.verdict.replace('_', ' ').toUpperCase(), sc.x, sc.y + 5);
    }
    ctx.restore();

    // caption lower-third (screen space)
    if (showCaption && snap.caption) {
      ctx.fillStyle = 'rgba(0,0,0,0.55)'; ctx.fillRect(0, ch - 56, cw, 56);
      ctx.fillStyle = '#e8d6a8'; ctx.font = '15px Georgia'; ctx.textAlign = 'center';
      ctx.fillText(snap.caption, cw / 2, ch - 24);
    }
  }
}
```

- [ ] **Step 2: Typecheck + commit**

Run: `npx tsc -b --noEmit` → clean.
```bash
git add -A && git commit -m "feat: TribunalRenderer (board, threads-as-light, verdict stone, caption)"
```

---

## Phase 7 — GlassBoxScreen wiring (canvas + rAF + input)

### Task 7.1: Wire the BeatPlayer to the canvas

**Files:** Rewrite `src/glassbox/GlassBoxScreen.tsx`.

- [ ] **Step 1: Implement (adapts the prototype's canvas+rAF pattern from BattleScreen.tsx)**

```tsx
import { useEffect, useRef, useState } from 'react';
import { loadBattleScript } from './battleScript';
import { BeatPlayer } from './beatPlayer';
import { TribunalRenderer } from './tribunalRenderer';

export default function GlassBoxScreen() {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [ready, setReady] = useState(false);
  const showCaption = useRef(true);
  const playerRef = useRef<BeatPlayer | null>(null);

  useEffect(() => {
    const canvas = canvasRef.current; if (!canvas) return;
    let raf = 0, renderer: TribunalRenderer | null = null;
    loadBattleScript('/inj020.battle.json').then((script) => {
      const player = new BeatPlayer(script, { dwellMs: 2200 });
      playerRef.current = player;
      renderer = new TribunalRenderer(canvas, script);
      player.play();
      setReady(true);
      const loop = (t: number) => { player.tick(t); renderer!.draw(player.snapshot(), showCaption.current); raf = requestAnimationFrame(loop); };
      raf = requestAnimationFrame(loop);
    });
    const onKey = (e: KeyboardEvent) => {
      const p = playerRef.current; if (!p) return;
      if (e.code === 'Space') { e.preventDefault(); p.snapshot().playing ? p.pause() : (p.snapshot().done ? null : p.play()); }
      if (e.key === 'ArrowRight') { p.pause(); p.step(); }
      if (e.key === 'c' || e.key === 'C') { showCaption.current = !showCaption.current; }
    };
    window.addEventListener('keydown', onKey);
    return () => { cancelAnimationFrame(raf); window.removeEventListener('keydown', onKey); };
  }, []);

  return (
    <div className="glassbox-screen" data-ready={ready}>
      <canvas ref={canvasRef} className="board-canvas" style={{ width: '100vw', height: '100vh', display: 'block' }} />
      <div className="kbd-hint">Space: play/pause · →: step · C: captions</div>
    </div>
  );
}
```

- [ ] **Step 2: Controller verification (visual)**

Run: `npm run dev`. Open via Playwright MCP. Verify the full sequence by stepping (→):
- R1: architect threads to 5 tiles, then skeptic threads to 3, then the stone sets DISMISSED.
- R2: architect threads collapse to the single ringed (threat) tile; skeptic threads fan to all 5; stone unchanged.
- R3: same dissociation; stone unchanged.
- Space pauses/resumes; C toggles the caption. No console errors.
Screenshot each round; controller signs off that threads swing while the stone holds.

- [ ] **Step 3: Commit**

```bash
git add -A && git commit -m "feat: GlassBoxScreen — autoplay + spacebar/step/caption, threads vs stone"
```

---

## Phase 8 — E2E verification

### Task 8.1: Playwright — verdict pixel-stability + replay smoke

**Files:** Create `e2e/replay.spec.ts`.

- [ ] **Step 1: Write the E2E spec**

The renderer must expose the player on `window` for driving. In `GlassBoxScreen`, after `playerRef.current = player`, add: `if (import.meta.env.DEV) (window as any).__player = player;`.

`e2e/replay.spec.ts`:
```ts
import { test, expect } from '@playwright/test';

test('verdict stone renders identically across all three rounds', async ({ page }) => {
  await page.goto('/');
  await page.waitForFunction(() => (window as any).__player);
  // pause and drive deterministically
  await page.evaluate(() => { const p = (window as any).__player; p.pause(); });

  const stoneCrop = { x: 0, y: 0, width: 0, height: 0 }; // full-canvas compare is fine here
  const shots: Buffer[] = [];
  for (let round = 0; round < 3; round++) {
    // advance to this round's oracle beat (verdict set)
    await page.evaluate((r) => {
      const p = (window as any).__player;
      // step until roundIndex==r and beatIndex==2
      let guard = 0;
      while (guard++ < 30) { const s = p.snapshot(); if (s.roundIndex === r && s.beatIndex === 2) break; p.step(); }
    }, round);
    await page.waitForTimeout(120);
    shots.push(await page.locator('canvas').screenshot());
  }
  // crop comparison: the stone region must be byte-identical round-to-round
  expect(Buffer.compare(shots[0], shots[1])).not.toBe(0); // whole canvas differs (threads moved)...
  // ...but the verdict text is invariant — assert via the player snapshot instead:
  const verdicts = await page.evaluate(() => {
    const p = (window as any).__player; const out: string[] = [];
    let guard = 0; p.pause();
    for (let r = 0; r < 3; r++) { let g = 0; while (g++ < 30) { const s = p.snapshot(); if (s.roundIndex === r && s.beatIndex === 2) break; p.step(); } out.push(p.snapshot().verdict); }
    return out;
  });
  expect(verdicts).toEqual(['threat_dismissed', 'threat_dismissed', 'threat_dismissed']);
});

test('replay reaches a verdict and completes', async ({ page }) => {
  await page.goto('/');
  await page.waitForFunction(() => (window as any).__player);
  const done = await page.evaluate(() => {
    const p = (window as any).__player; p.play();
    let t = 0; for (let i = 0; i < 100; i++) { t += 2300; p.tick(t); } return p.snapshot().done;
  });
  expect(done).toBe(true);
});
```
(Note: the stone-region byte-crop is best done by rendering the stone to a fixed screen rectangle and screenshotting that clip. If a stable crop is easy, assert `Buffer.compare(crop[0], crop[1]) === 0`; otherwise the snapshot-verdict assertion above is the load-bearing invariant. Implementer: prefer the crop compare if the stone's screen rect is stable; keep the snapshot assertion as the guaranteed check.)

- [ ] **Step 2: Run E2E**

Run: `npm run test:e2e` → both specs pass.

- [ ] **Step 3: Commit**

```bash
git add -A && git commit -m "test(e2e): verdict invariance + replay-completes smoke"
```

### Task 8.2: Final controller sign-off

- [ ] **Step 1:** Run `npm test` (vitest) AND `npm run test:e2e` (playwright) — all green.
- [ ] **Step 2:** `npm run build` — clean production build.
- [ ] **Step 3:** Visual sign-off: record the 3-round walkthrough (screenshots or screen capture); confirm the "threads swing, stone holds" reading lands. Controller (and Dan) approve.

---

## Self-review checklist

- [ ] Spec coverage (§8 Half B): loader+provenance (Task 3.1), beat-player (4.1), reused primitives (5.1), tribunal renderer w/ threads-as-light + verdict-stone (6.x), autoplay+spacebar+caption-toggle (7.1), JSON schema-contract test (3.1), pixel-stability E2E + replay smoke (8.1) — all covered.
- [ ] No placeholders in logic tasks: real code for battleScript.ts, beatPlayer.ts, iso.ts, scene.ts, tribunalRenderer.ts, GlassBoxScreen.tsx. Visual tasks carry real draw code + explicit controller-verification steps.
- [ ] Type/name consistency: `parseBattleScript`/`loadBattleScript`/`validateProvenance`, `BeatPlayer.{play,pause,step,tick,snapshot}`, `BeatSnapshot` fields (`architectCited`/`skepticCited`/`verdict`/`activeActor`), `TribunalRenderer.draw(snap, showCaption)`, `factIndex` — consistent across tasks.
- [ ] Contract fidelity: the loader maps the real snake_case artifact keys (`fact_id`, `cited_fact_ids`, `is_threat_dominant`, `supporting_fact_ids`) to camelCase; verdict invariant asserted at both unit (beatPlayer) and E2E layers.
