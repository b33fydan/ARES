# ARES Tactics — Phase 2–4 Fidelity Addendum (engine recon)

> Companion to `2026-06-16-ares-tactics-behavior-viz.md`. Written after reading the **real**
> `C:\glassbox\tacticsclone` engine source (renderer, anim, assets, unit factory, maps).
> Where this conflicts with the base plan's Phase-2 code, **this wins** — it is grounded in the
> actual engine and serves Dan's directive: *"make the demo look as much as possible like a real
> Tactics clone."* The base plan's Phase-2 code was written before the engine internals were read;
> treat its TS snippets as intent, and these as the corrected ground truth.

The whole fidelity thesis: **the engine already looks like a real Tactics clone because it is one.**
Phase 2's job is to *preserve* the diorama renderer untouched and lay the ARES layer on top — not to
rebuild or flatten it.

---

## 1. Minimal-prune fork — CORRECTS Task 6's delete list

The base plan says delete `src/data/{jobs,abilities,items}.ts`, `src/systems/{combat,turnorder}.ts`,
`src/ai/`. **Do not.** The renderer's transitive import graph needs most of them:

- `render/renderer.ts` → `JOBS` (`data/jobs`), `getMap` (`data/maps`), `maxStats` (`entities/unit`), `unitSprite`/`getImage` (`render/assets`), `floatTexts`/`fxSprites`/`syncView`/`viewFor` (`render/anim`)
- `entities/unit.ts` → `EQUIPMENT` (`data/items`)
- `render/anim.ts` → `CombatEvent` **type** (`systems/combat`), `AnimHooks` **type** (`systems/battle`), `facingBetween` (`systems/grid`)
- `systems/battle.ts` → defines `AnimHooks` (references combat types)

Deleting any of `jobs / items / maps / unit / combat / battle / grid / anim / assets / renderer`
breaks `tsc -b`.

**DECISION: do not prune the engine.** Fork it whole; only swap the mounted entry point
(`src/main.tsx` mounts `AresTacticsScreen` instead of `App`). Dead combat/ai/shop code costs nothing
in a demo; pruning is pure fidelity/landmine risk. If you want tidiness, you may delete only the
React **screens** you don't render (`ui/{CampaignScreen,PartyScreen,ShopScreen,TitleScreen,BattleScreen}.tsx`,
`ui/hud.tsx`) **and only after** confirming nothing kept imports them (App.tsx imports them — you're
replacing App.tsx anyway). When in doubt, leave it.

## 2. The board MUST be a real map — CORRECTS Task 8 `buildScene`

`renderer.drawTileBlock` calls `getMap(b.mapId).envKey`, and `getMap` **throws** on an unknown id.
The base plan's `buildScene` builds a flat all-`grass` `h=0` board and **never sets `mapId`** — that
both breaks the renderer and throws away the entire diorama (elevation, env theme, props, water,
cliff strata). A flat green mat is the opposite of the screenshot.

**DECISION:** build the scene's tiles from a **real** map and set `mapId` to it:
```ts
import { getMap, parseMap } from '../data/maps';
const def = getMap('bastion');
const tiles = parseMap(def);   // real terraced Tile[][]
// scene = { mapId: 'bastion', tiles, w: def.rows[0].length, h: def.rows.length, units, factTiles, phase: 'combat', ... }
```
Real maps available (`id → envKey`): `greenford→meadow`, `cliffside→cliffs`, `ruins→ruins`,
`ashenpass→ash`, **`bastion→bastion`** (default — the stone fortress closest to Dan's reference shot).
`ruins` is the strong alternate (flat stone court framed by 4 pillars — a "drowned tribunal").

## 3. Tribunal staging — use the elevation as the story

`bastion` (12×12): high stone back wall (`h≈3`, rows 0–2), mid stone tiers (`h=2` row 3, `h=1` row 4),
a flat **dirt courtyard** (rows 6–9, `h=0`, cols 3–8), grass apron (rows 10–11), corner pillars.

- **Oracle** (dawnmender, gold; team `guest` → green ring) **elevated** on a stone tier (the judge's
  bench), centered, facing down into the courtyard — e.g. around `(5–6, 4)` on `h=1`, or a back tier.
- **Architect** (embercaller, fire; team `enemy` → red ring + the renderer's red tint) on one flank of
  the courtyard.
- **Skeptic** (bulwark, shield; team `player` → blue ring) on the opposite flank.
- **Fact tiles**: a legible band of the scenario's facts across the flat dirt courtyard *between* the
  debaters (e.g. cols 3–8 at `y=7`, wrapping to `y=8` when > 6 facts). Agents walk to the facts they cite.

The elevation *is* the narrative: the judge sits above; prosecutor and defender argue over the evidence
laid on the floor between them. Validate legibility at the **Task 9 visual sign-off**; widen the band /
split rows / pick `ruins` if cramped. (This is the board-scale open question from spec §11 — resolve it here.)

## 4. Build agents with the real factory

`createUnit({ name, job, level, team })` (`entities/unit.ts`) returns a fully-valid `Unit` (sets
`hp = maxStats`). Use it, then set `x/y/facing`. Jobs: Architect=`embercaller`, Skeptic=`bulwark`,
Oracle=`dawnmender`. Teams: Architect=`enemy`, Skeptic=`player`, Oracle=`guest`. Level ~5–8 (cosmetic).
Give them stable ids `'architect' | 'skeptic' | 'oracle'` (the action-mapper keys off these) — note
`createUnit` auto-generates ids, so either set `u.id` after, or construct the `Unit` literal directly
with all required fields and `hp = maxStats(u)`.

## 5. HP bar → confidence meter (zero engine change)

`renderer.drawUnit` draws an HP bar `= u.hp / maxStats(u).hp`, colored `>0.5` green / `>0.25` yellow /
else red, and **only** draws KO counters when `u.ko` and status pips when `u.statuses` is non-empty
(neither ever true for our agents).

**DECISION:** set each agent's `hp = round(confidence * maxStats(u).hp)` for the current condition, so
the existing bar reads as a **confidence meter** that recolors as confidence shifts across conditions —
meaningful, game-authentic, and *no renderer edit*. Update it on each condition change.

## 6. Per-agent FX — make the cast read as fire / shield / gold

`fxSprites` and `floatTexts` are exported **mutable** arrays (`render/anim.ts`). `AnimHooks.castFlash`
hardcodes `fx_buff`; for fidelity push the right fx directly at the acting tile(s):

- **Architect** cast → `fx_fire` (the flaming staff), pose `'cast'`, mode `'rise'`/`'burst'`.
- **Skeptic** defend → `fx_buff` (shield shimmer), pose `'attack'` or `'idle'` (the bulwark sprite already
  reads as a shield-raise).
- **Oracle** judge → `fx_heal` (gold), then `AnimHooks.banner(verdict, ms)` for the center verdict.

Available fx keys: `slash, impact, arrow, fire, heal, buff, revive, ko, poison`. Poses available:
`idle, walk, attack, cast, ko` (there is **no** `defend` pose — use `attack`/`idle` + `fx_buff`).

## 7. AnimHooks choreography seam (Tasks 11–12)

`makeAnimHooks({ onChange, focusTile, setBanner })` → `AnimHooks` (`render/anim.ts`). Drive the actions:

- `move` → `AnimHooks.unitWalk(u, path)` where `path` is a tile path from `u` to the target tile
  (`systems/grid`: `reachableTiles`, `pathTo`, `facingBetween`). `unitWalk` animates the bouncy walk and
  sets pose `walk`; **after it resolves, set `u.x/u.y = dest`** so `syncView` holds the unit there.
- `cast`/`pose` → `castFlash(u)` (+ push fx per §6) or `unitLunge(u, toward)`.
- `banner` → `AnimHooks.banner(text, ms)`.
- camera → `focusTile`/`Camera.centerOn` to frame the acting agent each beat (cinematic).

**Read `systems/battle.ts`** (the `AnimHooks` interface + `setAnimHooks` + how the real battle controller
sequences hooks) and **`systems/grid.ts`** before Task 12, and match their exact signatures.

## 8. The castle backdrop comes from the SCREEN, not `Renderer.draw`

`Renderer.draw` draws tiles/props/units/fx/floattexts only — the cut-paper castle backdrop
(`bg_campaign`) and canvas sizing are set up by the battle **screen** component. **Read
`src/ui/BattleScreen.tsx`** to see how it mounts the canvas, loads assets (`loadAssets`), draws/sets the
`bg_campaign` backdrop, and runs its rAF loop, then replicate that in `AresTacticsScreen.tsx` (mirroring
`C:\glassbox\glassbox\src\glassbox\GlassBoxScreen.tsx` for the `?autoplay`/`?dwell`/Space/→ presenter
plumbing). Keep `loadAssets()` and the default camera zoom (`1.35`) so terrain textures, cliff strata,
water shimmer, and warm-ink grid lines all render — that *is* the Tactics-clone look.

---

### One-line summary for the fork agent
Fork `tacticsclone` whole (no prune), mount a new `AresTacticsScreen`, build the scene on the **real
`bastion` map** with the three hero-agents staged as a tribunal (Oracle elevated), lay the fact tiles in
the courtyard, render confidence via the existing HP bar, and choreograph beats through the real
`AnimHooks` with per-agent fx. Preserve the diorama renderer untouched.
