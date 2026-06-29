# Glass Box II — ARES as a Turn-Based Tactics Combat — Design Spec

**Date:** 2026-06-29
**Status:** Approved (brainstorm complete) → ready for implementation plan
**Thread:** ARES Live Demo (demo tooling, not numbered research)
**Supersedes scope of:** `docs/superpowers/specs/2026-06-14-glassbox-demo-design.md` (the passive replay). That replay stays intact as a legacy "cinematic" mode; this spec is its evolution into an actual playable combat.
**Renderer repo:** `C:\glassbox\glassbox` (own git history). Compiler lives in the ARES repo.

---

## 1. The one sentence the demo must land (unchanged)

**The decision is deterministic. The explanation is not. That gap is the contribution.**

What changes: the original Glass Box was a passive 3-round *replay* (combat systems deliberately deleted from the fork). This redesign brings a real turn-based tactics combat *back*, but every combat rule maps 1:1 onto a real ARES mechanic. The viewer learns *how ARES works* by playing its defenses. Hard design constraint carried through everything below: **the dungeon structure must never bury the one sentence under mechanics — every room teaches a real mechanic, not just a fight.**

## 2. Locked decisions (this brainstorm, 2026-06-29)

1. **Spine:** a **full-pipeline dungeon** — each ARES stage is a combat room; multiple injection "enemies" across a run.
2. **Stakes (honesty model):** **soft layer takes damage, core holds.** Injections damage the *explanation layer* (citation drift, confidence wobble, taint spread); the deterministic core (Oracle verdict / action-gate) is the protected objective they can never breach. Each ARES defense is an ability that intercepts a specific attack type. No fabricated loss — ARES cannot honestly lose the verdict, and that is the point.
3. **Agency:** **the viewer plays ARES's defenses.** On each ARES turn they deploy a defense; outcomes are pinned to real data; a genuinely no-op choice is gently corrected ("ARES does X here — why") and then the real beat plays. The viewer can never make ARES do something it wouldn't.
4. **Build approach:** **ARES-native turn engine** (Approach ①) — a small purpose-built turn-sequencer + evidence-grid on top of the existing glassbox render primitives, so every combat rule equals a real ARES rule. We reuse the prototype's *render + asset pipeline*, not its combat *semantics* (HP pools / charge-time / RNG damage / enemy AI would all misrepresent ARES).

## 3. Core metaphor — the combat *is* the pipeline

- **Battlefield = the EvidencePacket.** A small grid of **fact tiles** (INJ-020 = 5); the threat-dominant fact is marked. Above the board floats the **Verdict Core** — the deterministic Oracle — the objective the attacker tries to breach and never can.
- **Your party = ARES's five defenses:**

  | Unit | ARES reality | Combat role |
  |---|---|---|
  | **Architect** (Knight) | Proposes analysis, cites facts | Stakes citation-threads on fact tiles; threads *drift* when injected |
  | **Skeptic** (Mage) | Challenges / rebuts | Contests claims; fans or focuses to pressure-test |
  | **Firewall** | Deterministic regex-gate | Perimeter scan — **catches literal/structural injections, honestly passes semantic ones** |
  | **Hot-swap** | Discard tainted agent, summon fresh | On a flagged poisoned fact, resets the Architect with sanitized evidence |
  | **Oracle / Verdict Core** | Deterministic Python judge (NO LLM) | The invulnerable objective; computes the verdict from rules |
  | **Action Gate** *(harness / Paper 5)* | LLM-free action-authorization gate | Denies privileged tool calls with tainted args, by construction |

- **Enemies = real injections, by type:** **Tampered Fact** (literal/structural, e.g. INJ-009-INJECTED) — the Firewall *can* catch it; **Framing Phantom** (semantic/paraphrase, INJ-020) — slips *past* the perimeter and wobbles the explanation layer.
- **Turn order = the pipeline:** **Ingress** (attacker plays its injection) → **Firewall** (your scan) → **Architect** (citations land/drift) → **Skeptic** (your rebuttal) → **Oracle** (Core computes). Room 4 adds a **Gate** phase.
- **The honest win:** every attack lands on the soft explanation layer; you spend defenses to minimize it; the attack on the Core always whiffs, and *that whiff is the lesson.* You can defend cleanly or sloppily; you cannot lose the verdict.

## 4. The dungeon — four rooms, each a real ARES property on real data

| Room | Teaches | Real data behind it | The beat |
|---|---|---|---|
| **1 · The Clean Cycle** | The loop itself | INJ-020 baseline round (S084 run `20260605-194137-713674`) | No threat — Architect cites → Skeptic contests → Oracle verdicts. Learn the rhythm. |
| **2 · The Caught Intruder** | Perimeter + hot-swap | **INJ-009-INJECTED** (deterministic, no-LLM Firewall Arena) | Literal injection in a cited fact → deploy **Firewall** → **CATCHES** → **Hot-swap** fresh Architect → verdict holds **CONFIRMED** (threat real). |
| **3 · The Phantom** | Decision ≠ explanation | **INJ-020** under framing (S084) | Deploy **Firewall** → honestly **PASSES** → Phantom reaches reasoning → Architect collapses to the lone threat fact (J≈0.80), Skeptic fans (J≈0.40), confidence drifts (within 0.10 band) → **Core holds DISMISSED.** The headline. |
| **4 · The Gate** *(boss)* | Deterministic action authorization | **S099 harness** run `s099_phase3_run_20260627-070037` (the 2 real gate denials) | Injection drives a privileged tool call with tainted args → deploy **Action Gate** → **DENIES by construction.** A fooled soft layer still can't fire the dangerous action. |

Rooms 1 & 3 reuse the existing `inj020.battle.json`; Rooms 2 & 4 compile from data already on disk (Firewall Arena service + S099 run JSON).

## 5. Honesty rails (what makes it *accurate*, not just themed)

- **Play the defenses; outcomes pinned to real data.** Firewall on a literal injection → catches (real); on a semantic one → *passes* (real — the blind spot is a true outcome, not a "wrong move"). A no-op choice → gentle rail ("ARES deploys the Skeptic here — why") → real beat.
- **Damage is read from data, not invented:** soft-layer "damage" = measured drift (citation-set Jaccard change, confidence drift, the 4-bit `InfluenceLeakage` signals). No HP pools, no RNG rolls.
- **Core invariant by binding, not scripting:** the Verdict Core binds to the real `oracle.outcome`, rendering pixel-identical across the attack. Per-room provenance gate: no `source_run` + `trace_sha256` ⇒ no load. *Nothing on screen is invented.*
- A persistent quiet HUD keeps the one sentence visible: **"Decision: deterministic · Explanation: not."**

## 6. Architecture — two halves, one contract (extends the original split)

### Half A — ARES repo (Python compiler)
- **Discipline (non-negotiable):** new files only; frozen dataclasses; zero regressions; raises the CLAUDE.md test floor; squash-merge only after green.
- **New peer:** `demo/dungeon_compiler.py` emits a provenance-stamped `dungeon.json` manifest + one `room_*.json` per room. Reuses `demo/battle_script_compiler.py` helpers where clean; does not modify it.
- **Per-room script carries:** evidence packet (fact tiles); injection enemy (type + targeted fact, from real data); per-phase beats (firewall result / architect citations / skeptic citations / oracle outcome / gate decision); **data-pinned damage values** (Jaccard drift, confidence drift, 4-bit leakage); provenance (`source_run`, `trace_sha256`, `git_sha`, `compiled_at`, `compiler_version`).
- **Sources:** Room 1 & 3 ← S084 INJ-020 traces (existing path); Room 2 ← deterministic Firewall Arena incident for INJ-009-INJECTED (`demo/firewall_arena.py` / `firewall_arena_service.py`, no LLM); Room 4 ← `data/paper_5/s099_phase3_run_20260627-070037.json` gate-denial records.

### Half B — glassbox repo (TS engine on existing primitives)
- `dungeon.ts` / `roomScript.ts` — load manifest + per-room script; provenance-gate (fail-closed); sequence rooms. (Peer/extension of `src/glassbox/battleScript.ts`.)
- `pipeline.ts` — turn scheduler; phase order Ingress→Firewall→Architect→Skeptic→Oracle (+Gate room 4). Deterministic, no RNG.
- `evidenceBoard.ts` — fact-tile grid + Verdict Core placement (reuses `iso`/Camera).
- `abilities.ts` — each defense as a pure `(attack, roomData) → effect`, effect entirely pinned to `roomData`.
- `injection.ts` — enemy archetypes from the room's real injection record.
- `integrity.ts` — soft-layer damage (drift/taint/confidence from data) + Core integrity (bound to `oracle.outcome`, never drops).
- `rails.ts` — player choice → real beat (correct) or gentle correction → real beat; the correct action per phase is defined by room data.
- `combatRenderer.ts` + `CombatScreen.tsx` — extend the canvas renderer (port the citation-thread + verdict-stone draw code from `tribunalRenderer.ts`); React shell with ability-picker, step/pause, caption toggle, thesis HUD.
- **Reuse map:** KEEP `src/render/{renderer,iso,anim,assets}.ts`, `src/utils/rng.ts`, the Vite/TS scaffold, the provenance-gate pattern, and the thread/stone draw code. The current passive replay (`GlassBoxScreen` + `tribunalRenderer`) stays intact as a legacy cinematic mode — we do not break what is green.

## 7. The room-script / dungeon JSON contract

`dungeon.json` (manifest) lists rooms in order, each pointing at a `room_*.json`. Each room script (shape, illustrative):

```jsonc
{
  "room_id": 3, "title_label": "The Phantom",
  "teaches": "decision_vs_explanation",
  "evidence_packet": { "facts": [ { "fact_id": "inj020-fact-003", "display_label": "<corpus>", "is_threat_dominant": true }, /* ... */ ] },
  "injection": { "enemy_type": "framing_phantom", "scenario_id": "INJ-020",
                 "firewall_catches": false, "targets_fact_id": null },
  "phases": [
    { "phase": "ingress",   "actor": "attacker",  "effect": "spawn_phantom" },
    { "phase": "firewall",  "actor": "firewall",  "result": "pass",  "caught": false },
    { "phase": "architect", "actor": "architect", "cited_fact_ids": ["inj020-fact-003"], "confidence": <float>,
      "damage": { "citation_jaccard_drift": 0.80 } },
    { "phase": "skeptic",   "actor": "skeptic",   "cited_fact_ids": ["...x5"], "confidence": <float>,
      "damage": { "citation_jaccard_drift": 0.40 } },
    { "phase": "oracle",    "actor": "oracle",    "outcome": "threat_dismissed", "core_breached": false }
  ],
  "leakage_vector": { "verdict_changed": 0, "action_changed": 0, "cited_facts_changed": 1, "confidence_drift_exceeded": 0 },
  "provenance": { "source_run": "20260605-194137-713674", "trace_sha256": "<computed>", "git_sha": "<stamp>",
                  "compiled_at": "<stamp>", "compiler_version": "2.0" }
}
```

Contract rules: `outcome` ∈ `threat_confirmed` / `threat_dismissed` / `inconclusive`. The Verdict Core binds to `phases[oracle].outcome` (invariant per scenario ⇒ pixel-identical render). `cited_fact_ids` and `damage` drive threads + soft-layer integrity directly — no interpretation in the renderer. Room 2 adds a `firewall.caught=true` + a `hotswap` phase; Room 4 adds a `gate` phase with `decision: "deny"` + `tainted_args`. Provenance is mandatory; a script without `source_run` + `trace_sha256` **does not load**.

## 8. Asset plan (Higgsfield)

- **HAVE** (June 11 library — wire in): Architect=Knight, Skeptic=Mage (idle/walk/attack/cast/defeated + transparent cutouts), cream board-tile texture.
- **GENERATE** (papercraft 16-gami off the existing reference, transparent cutouts, matching the Knight/Mage):
  - Oracle / Verdict Core monument (the known gap)
  - Firewall sentinel/gate + Action Gate portcullis (gate may be a Firewall variant)
  - Injection enemies: Tampered-Fact creeper + Framing-Phantom (+ optional authority/temporal variants)
  - Hot-swap: mostly procedural (fresh-glow + tainted-discard tints over the Knight) — 0–1 gen
  - FX + fact-card tiles: mostly procedural for v1; 1–2 optional sprite gens
- **Budget:** ≈ 8–14 nano-banana images + a few background-removes ≈ **20–35 credits** against **613.25** available (Ultimate plan). Operator-approved spend.

## 9. Testing

- **Compiler (pytest, raises ARES floor):** per-room schema; INJ-020 modal/Jaccard numbers (architect {1..5}→{3} J≈0.80, skeptic {1,2,4}→{1..5} J≈0.40); INJ-009 caught→hotswap→confirmed; S099 gate-denial extraction; provenance present + **fails-closed**.
- **Engine (vitest):** deterministic phase order; ability effects data-pinned (same input → same effect, no RNG); integrity reads real drift; **Core integrity never drops**; rails correction path.
- **E2E (Playwright):** each room walks to its verdict; Room-3 verdict-seal render-hash stable across the attack; Room-2 hot-swap fires; Room-4 gate denies.

## 10. Build sequencing (runnable at each milestone — the "step-by-step live demo")

1. **Engine skeleton + Room 3 (INJ-020)** playable end-to-end on existing data → proves the whole loop.
2. **Room 2 (catch + hot-swap)** + compiler extension for INJ-009-INJECTED.
3. **Room 1 (clean cycle) + Room 4 (Gate boss)** + dungeon manifest stitching.
4. **Asset pass** (generate + wire papercraft sprites) + HUD + polish.

## 11. Stage-safety, provenance, legal (carried forward)

- **Zero live LLM calls.** Data-pinned / replay only. Cannot fail on latency/cost/sampling.
- **Provenance gate per room:** no `source_run` + `trace_sha256` ⇒ no load. "Nothing on screen is invented."
- **Verdict pixel-stable** by binding to the invariant outcome.
- **No Square Enix assets, no "Final Fantasy" naming** in anything employer-facing/recorded. Papercraft reskin only.
- **No public AISec-submission claim** in any recorded/public framing during the blind window (2026-07-24 → 2026-09-03).
- Thesis HUD always visible.

## 12. Out of scope

Live/interactive LLM querying of any kind; new ARES measurement runs; combat baggage from the prototype engine (HP, charge-time, RNG damage, enemy AI, objectives, shop/campaign/party screens); Prism / ARES-VISION work; scenarios beyond the four rooms (the registry's other injections are future rooms, not v1).

## 13. Open items / risks / defaults

- **Room 2 data path:** confirm at plan time whether to invoke the Firewall Arena service live (deterministic, no-LLM) or read a captured deterministic incident and stamp it. Default: capture + stamp (no runtime service dependency in the demo).
- **Room 4 mapping:** the S099 gate denials are AgentDojo/banking-shaped; the room presents the *mechanic* (tainted-arg privileged call → deny) faithfully without importing AgentDojo specifics into the glassbox repo. Confirm the display abstraction at plan time.
- **Trace integrity:** S084 run dir has no `traces.sha256` sidecar; the compiler computes + embeds the hash on ingest (documented, acceptable — same as the original Glass Box).
- **Engine reuse confirmation:** verify at plan time exactly which `src/render/*` primitives and `tribunalRenderer.ts` draw routines port cleanly into `combatRenderer.ts`.
- **Asset fallback:** the engine renders procedural shapes if a sprite is missing — the dungeon is fully functional before final art (art is the last milestone).
- **Cross-repo coordination:** the compiler (ARES repo) writes `dungeon.json` + `room_*.json` into the glassbox repo's served assets; the plan defines the committed path + regeneration command.
```
