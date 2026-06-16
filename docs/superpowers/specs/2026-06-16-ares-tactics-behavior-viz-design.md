# ARES Tactics — Behavior Visualization — Design Spec

**Date:** 2026-06-16
**Status:** Approved (design A, 2026-06-16) → ready for implementation plan
**Thread:** ares-live-demo (sibling to Glass Box + Firewall Arena)
**Engine source:** `b33fydan/tacticsclone` ("Emberveil Tactics"), cloned at `C:\glassbox\tacticsclone` (deps installed 2026-06-16)

---

## 1. The one sentence the demo must land

**Three AI agents argue over the same evidence; a deterministic judge decides; watch the agents' reasoning visibly drift while the verdict holds — played out as Tactics characters on a papercraft board.**

The contribution we are dramatizing is the ARES research finding: *the decision is deterministic, the explanation is not.* The visualization keeps the research serious (every frame is real measured data) while being a nostalgic, accessible gift to a non-expert audience.

## 2. What it is (and is NOT)

- It IS a **data-driven replay** on top of the real Emberveil Tactics isometric engine: the three ARES agents are hero-characters who **carry out actions in response to the real ARES data**.
- It is NOT turn-based combat, NOT a playable game, NOT a monster hunt. The "threat" is the **evidence** the agents act on, not an enemy to kill (decision locked with Dan: "as long as I'm looking at individual characters carry out an action in response to the data... if there are no monsters we don't need them").
- No live LLM in the viewer — it replays a **compiled script** built from recorded data (the Glass Box / Firewall Arena discipline). $0 to run, deterministic, stage-safe.

## 3. Grounded feasibility (verified 2026-06-16)

Recon of the engine + a direct look at the real art confirm this is a reskin/replay, not an engine rewrite:

- **Engine is sim/render separated + data-driven.** `Unit {x,y,facing,job,team}` + `Tile {x,y,h,terrain,prop}` + `BattleState`. The `AnimHooks` seam (`unitWalk`, `unitLunge`, `castFlash`, `koFade`, `banner`, `focusUnit`, `delay`, `onChange`) drives all animation; a `FloatText` system already renders text over units (the seed for chat bubbles). Poses exist: `idle/walk/attack/cast/ko`. Seedable RNG. (`src/entities/types.ts`, `src/systems/battle.ts`, `src/render/{renderer,anim,assets}.ts`, `scripts/simulate.ts`.)
- **The art is real and perfect.** The five heroes are **voxel-papercraft figurines** (embercaller rust fire-mage w/ flaming staff; bulwark steel-blue shield-knight w/ red cape; skywarden green archer; duskblade purple/grey rogue; dawnmender gold healer). `bg_campaign` is a literal **cut-paper layered-terrain diorama** (folded-paper mountains, terraced hills, paper castle). This is Dan's 16-gami aesthetic, already built. No monster art exists — and we don't need it.
- **Proven reuse path.** Glass Box (`C:\glassbox\glassbox`) already forked this engine, kept the iso/render primitives, and drove them from a JSON script via a beat-player + rAF loop. We do the same but keep MORE of the engine (the real iso board + unit movement + FloatText), not the flat tribunal layout.
- **The data exists and is per-beat.** The S084 dual-agent run (`data/paper_3/leakage_runs/20260605-194137-713674/traces.jsonl`, $24.41, 1,680 records, 17 scenarios) records per resample and per condition: `architect_cited_facts`, `skeptic_cited_facts`, `architect_confidence`, `skeptic_confidence`, `oracle_supporting_facts`, `final_outcome`. Scenario fact text resolves via `injection_registry_v3` / `injection_corpus*`.

## 4. Cast (locked, grounded in the real models)

| Agent | Character | Role read |
|---|---|---|
| **Architect** (prosecutes the threat) | **embercaller** (fire-mage, `cast` pose + flaming staff) | fire **attacks** — projects the threat case |
| **Skeptic** (defends the benign reading) | **bulwark** (shield-knight, red cape) | shield **defends** — blocks the accusation, argues benign |
| **Oracle** (the deterministic judge) | **dawnmender** (gold healer) | gold **judges** — renders the verdict by fixed rule |

"Fire attacks, shield defends, gold judges" reads at a glance for a non-expert audience.

## 5. Data spine + the "link all the data" decision

- **v1 spine = S084** (the only per-beat, both-agent, multi-condition dataset). It IS "agents acting in response to data": who cited which facts, with what confidence, and the verdict — across baseline and framing conditions. The **drift between conditions** is the centerpiece behavior.
- **"All the data" is honored by a general adapter, not by cramming every run into v1.** The other paid runs are metric-shaped (leakage bits S059/S060/S075/S076; OOV evasion S089/S090; tier-4 frontier), not per-beat agent claims. The compiler's script schema is designed so these become **secondary layers later** (e.g. a multi-model "three judges" view from the leakage runs; an OOV "disguised evidence" beat). v1 ships the S084 dialectic; the adapter leaves the door open. (Explicitly noted so we never imply v1 animates all $33 of runs.)
- **Chat-bubble words:** v1 synthesizes each agent's claim deterministically from its cited facts + the scenario fact text (the Glass Box caption discipline — $0, provenanced). A small **targeted later run** (~\$3-8, locked-contract-first per Dan) captures the agents' real per-beat prose to upgrade the bubbles to the agents' actual words.

## 6. The beat loop (choreography = the "action in response to data")

Per scenario, driven entirely by the compiled script:

1. **Setup** — the incident loads; the scenario's evidence facts appear as **tiles** on the papercraft board; the three hero-agents take their marks (Architect left, Skeptic right, Oracle center-back).
2. **Architect acts** — walks/`cast`s toward the facts in `architect_cited_facts`; those tiles flare threat-red; a **chat bubble** states the threat case + `architect_confidence`. The injected fact (if any) is a visibly corrupted tile.
3. **Skeptic acts** — moves to its (smaller) `skeptic_cited_facts`, raises its shield over / greys the facts it deems benign; bubble argues the benign reading + `skeptic_confidence`.
4. **Oracle rules** — steps to center, weighs the cited sets by fixed rule (`oracle_supporting_facts` + `final_outcome`); a **banner** drops the verdict (THREAT CONFIRMED / DISMISSED / INCONCLUSIVE).
5. **The drift twist (the research)** — replay the SAME scenario under a framing condition: the agents' cited tiles visibly **drift** (e.g. Architect collapses to fewer facts, Skeptic fans wider), the choreography changes, **but the Oracle's verdict does not move.** This is the published finding, made visceral.

Presenter controls mirror Glass Box / Arena: `?autoplay=0` start paused, Space/→ step, scenario + condition selectors.

## 7. Architecture — two halves, one JSON contract

Same shape as Glass Box + Firewall Arena (proven twice).

```
ARES repo (C:\ares-phase-zero)                         ARES Tactics fork (C:\glassbox\arestactics)
──────────────────────────────                         ───────────────────────────────────────────
data/paper_3/leakage_runs/20260605-.../traces.jsonl ─┐
ares/dialectic/scripts/injection_registry_v3 (facts) ├─► demo/tactics_script_compiler.py ─► <scenario>.tactics.json ─► loader ─► AresTacticsPlayer ─► AnimHooks ─► iso renderer + sprites
                                                     ─┘        (Half A, Python, provenanced)        (the contract)         (Half B, TS, forked engine)
```

- **Half A — compiler (ARES repo, new files under `demo/`):** `demo/tactics_script_compiler.py`. Reads the S084 traces, computes per-condition **modal cited-fact sets** + median confidences + modal outcome (the Glass Box method), resolves fact IDs → display text + threat-dominance from `injection_registry_v3`, and emits a provenanced `tactics-script` JSON per scenario: `{ scenario, facts[], conditions[ { name, architect{cited,confidence,claim}, skeptic{cited,confidence,claim}, oracle{verdict,supporting} } ], provenance }`. Tests in `tests/demo/`. Counts toward the ARES freshness floor.
- **Half B — the fork (`C:\glassbox\arestactics`, fresh repo seeded from `tacticsclone`):** keep the iso renderer + `AnimHooks` + `anim.ts` + sprites + RNG; **skip** combat/turnorder/ai/jobs/abilities/items/shop/campaign/deploy. Add: a **script loader** (provenance-gated), an `AresTacticsPlayer` (beat stepper, Glass Box `beatPlayer` lineage), an **action-mapper** (script beat → AnimHooks calls: walk to cited tiles, `cast`/shield pose, banner), a **chat-bubble renderer** (extend `FloatText`: longer dwell, speech-bubble frame, positioned over the agent), and a **scene-builder** (place 3 agent units + evidence-fact tiles on a small paper board). The screen wires player → AnimHooks-driven renderer via rAF, with the presenter controls.

## 8. Component boundaries (each testable in isolation)

- `tactics_script_compiler.py` — pure transform: traces + fact text → script dict. Provenance gate (`source_run` + `trace_sha256`). Deterministic; unit-tested against the recorded S084 run.
- `tactics-script` JSON schema — the only thing crossing the halves; versioned; provenance-required.
- `loader.ts` / `parseTacticsScript` — provenance-gated parse → typed `TacticsScript`; vitest against a fixture generated from the real compiler.
- `AresTacticsPlayer` — pure beat state machine (setup → architect → skeptic → oracle → drift), reveal flags, first-tick baseline discipline (the Glass Box gotcha); vitest.
- `actionMapper.ts` — pure mapping (beat → list of AnimHooks intents); unit-testable without canvas.
- `sceneBuilder.ts` — script → initial `BattleState` (agent units + fact tiles placed on a small board); unit-testable.
- chat-bubble + renderer wiring — verified via Playwright + visual sign-off (canvas, like Glass Box / Arena).

## 9. Scope (v1) + out of scope

**v1:** the S084 scenarios (selectable), the 5-beat loop incl. the drift twist between baseline and one framing condition, synthesized chat bubbles, presenter controls, the papercraft board + the three real hero-agents. Ship a "money" scenario (e.g. INJ-020 the mirror, or INJ-001 the credential dump) as the default.

**Out of scope (anti-creep):** no combat/turn-order/monsters/new art; no live LLM in the viewer; no cramming the metric-shaped runs (leakage/OOV/tier-4) into v1 (adapter leaves them for a later layer); no hosting/deploy (localhost). The targeted real-prose run is a **later** step, after the script contract is locked.

## 10. Phased build (for the implementation plan)

- **P1 — compiler + contract (ARES repo):** `tactics_script_compiler.py` → provenanced `<scenario>.tactics.json` from S084 + fact text; tests; a generated fixture for the fork.
- **P2 — fork + scene + static render:** seed `C:\glassbox\arestactics` from tacticsclone; prune to the render core; scene-builder places 3 agents + fact tiles on a paper board; loader + parser; render a static beat. Vitest + first visual sign-off.
- **P3 — choreography + chat bubbles + drift twist:** `AresTacticsPlayer` + action-mapper drive agent walks/poses/banner via AnimHooks; chat-bubble renderer; the baseline→framing drift replay. Vitest (logic) + Playwright + visual sign-off.
- **P4 — polish + presenter controls + handoff:** scenario/condition selectors, autoplay/step keys, papercraft polish, the closing tie-in to Glass Box + Firewall Arena. Then (separately) the targeted real-prose run to fill bubbles with the agents' actual words.

## 11. Risks / open notes

- **Board scale:** a scenario can have ~7 facts + 3 agents; the paper board must fit them legibly. P2's scene-builder sign-off de-risks this (a live board render is available now that deps are installed).
- **"All data" expectation:** be explicit with the audience/Dan that v1 animates the S084 dialectic; other runs are a later layer. (Honesty discipline, per Dan's calibration.)
- **Chat-bubble truthfulness:** v1 bubbles are synthesized-from-facts (clearly provenanced), not the LLM's words, until the targeted run lands. Never present synthesized text as a verbatim model quote.

## 12. Doctrine fit

Sibling to Glass Box (recorded semantic-drift replay) and Firewall Arena (live syntactic catch). This is the **dialectic-behavior** view: the agents arguing, made into Tactics theater. Reuses the proven compiler+fork+beat-player pattern. Keeps serious research serious (real data, provenanced) while delivering the nostalgia + the audience gift Dan is after.
