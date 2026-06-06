# ARES-VISION — "The Mirror" Scrollytelling Journey — Design

**Date:** 2026-06-06
**Status:** Draft for review (brainstorm complete; pre-plan)
**Topic:** Website-hero scrollytelling page built on the S084 dual-agent framing result (INJ-020 opposed mirror)
**Source data:** run `20260605-194137-713674` (`data/paper_3/leakage_runs/...`); see `docs/paper_3/S084_DUAL_AGENT_FRAMING_RESULT_2026-06-05.md`

---

## 1. Summary

Build a public-facing, scroll-driven hero page for ARES-VISION whose centerpiece is the **INJ-020 dual-agent "mirror":** under a pure paraphrase of the input, the Architect's cited-fact set *collapses* onto the lone planted threat fact while the Skeptic's *expands* to include it — yet the verdict (`threat_dismissed`) never changes. The page tells a five-beat story — **wow → "prove it" → "how common, honestly" → CTA** — turning the rigor of S084 into the credibility of the visual. It is a new standalone page that hands off to the existing Prism explorer for the deep dive.

## 2. Goals / Non-goals

**Goals**
- Make a first-time visitor *feel* the finding: identical decision, opposite reasoning, on real measured data.
- Be honest by construction: show the noise floor and the (rare) prevalence, not just the jaw-drop.
- Mobile-first; fast; minimal dependencies.
- Preserve and link to Prism; don't disturb it.

**Non-goals (YAGNI)**
- No rebuild of Prism (Labyrinth/Trajectories stay as-is, Three.js).
- No Three.js / WebGL for this page.
- No live LLM calls and **no new measurement run** — we consume existing S084 traces only.
- No multi-model framing; no per-scenario interactive explorer in scene 4 (a tally, not a tool).
- Camera-ready refinements (gating `mirror_class` on verdicts, dual controls) are out of scope.

## 3. Locked decisions (from brainstorm, 2026-06-06)

| Decision | Choice |
|---|---|
| Primary aim | **Website hero** — make visitors feel the mirror |
| Scope | **Scrollytelling journey** (5 scenes), wow→rigor→CTA |
| Hero visual | **Direction A — "Facing Mirror"** (validated live with real data) |
| Arc | 5 scenes, **both** rigor scenes (3 + 4) kept |
| Placement | **New standalone page**, linked from the ARES landing; CTA → Prism |
| Tech | **HTML/CSS/SVG + scroll lib (vanilla IntersectionObserver)** + a new Python scene-data adapter; Prism stays Three.js |

## 4. The narrative (five scenes, top→bottom = scroll order)

1. **The setup (hook).** Introduce the Architect (amber) and Skeptic (blue) debating a possible threat, reaching a verdict. Establish players + stakes.
2. **The mirror (HERO).** Paraphrase the input → Architect **collapses** to `{f3}` (the threat) while Skeptic **expands** to all 5 facts; the verdict chip holds `threat_dismissed` throughout. The facing-mirror animation prototyped at `.superpowers/brainstorm/ares-vision/content/mirror-A-live.html` is the basis. They cross precisely at the threat fact.
3. **But is it real? (rigor).** Pre-empt "isn't that just model randomness?" Show the **noise floor**: baseline within-distance `0.00` for both agents vs. the framing cross-distance (Architect `0.80`, Skeptic `0.40`), `p≈0`. Signal ≫ noise.
4. **The honest landscape (calibration).** It is **not everywhere**. Across the 17 measured scenarios, mirror-class counts: **opposed=4, aligned=5, single=20, none=21**; rigorously REAL channels: **11 Architect / 9 Skeptic** conditions. The clean opposed mirror is rare (INJ-020). Honesty is the credibility.
5. **What's inside the box (CTA).** Land the thesis ("the problem is inside the black box") → buttons: **Read the paper** and **Explore the live data → Prism**.

## 5. Architecture (design for isolation)

Four small, independently-understandable units. The **JSON file is the contract/boundary** between the two repos.

### 5.1 Data adapter (ARES repo — `C:\ares-phase-zero`)
New peer module under `ares/dialectic/visualization/`, mirroring the existing `cycle_trace*` pipeline pattern:
- `mirror_journey_schema.py` — frozen dataclasses: `MirrorScene`, `AgentCitation` (agent, baseline_facts, framed_facts, jaccard, within_noise, p_value, direction), `LandscapeTally` (opposed/aligned/single/none + architect_real/skeptic_real/n_scenarios), `MirrorJourney` (schema_version, run_id, scenes).
- `mirror_journey_builder.py` — reads the S084 `traces.jsonl`, computes per-condition modal cited-fact sets for INJ-020 (Architect/Skeptic, baseline vs framing), pulls the aggregate landscape tally from `summary.json` / the report; returns an immutable `MirrorJourney`. Deterministic; no LLM; no network.
- `build_mirror_journey.py` — CLI: `python -m ares.dialectic.visualization.build_mirror_journey` → writes `docs/marketing/mirror-journey.json`.

### 5.2 Scene-data JSON contract (`docs/marketing/mirror-journey.json`)
```jsonc
{
  "schema_version": "mirror-v1",
  "run_id": "20260605-194137-713674",
  "hero": {
    "scenario_id": "INJ-020",
    "facts": ["f1","f2","f3","f4","f5"],
    "threat_fact": "f3",
    "architect": { "baseline": ["f1","f2","f3","f4","f5"], "framed": ["f3"],
                   "jaccard": 0.80, "within_noise": 0.00, "p": 0.0, "direction": "collapse" },
    "skeptic":   { "baseline": ["f1","f2","f4"], "framed": ["f1","f2","f3","f4","f5"],
                   "jaccard": 0.40, "within_noise": 0.00, "p": 0.0, "direction": "expand" },
    "verdict": "threat_dismissed", "verdict_held_fraction": 1.0
  },
  "landscape": { "opposed": 4, "aligned": 5, "single": 20, "none": 21,
                 "architect_real": 11, "skeptic_real": 9, "n_scenarios": 17 }
}
```
(Exact fact ids are `inj020-fact-00x`; shortened to `f1..f5` for display.)

### 5.3 Renderer (skyframe-main — `E:\Skyframe Innovations Website\skyframe-main`)
New files under `assets/ares/`, reusing the existing house CSS variables/typography:
- `mirror.html` — the scroll page shell (5 `<section>` scenes).
- `mirror.css` — house style (`#0a0a0a`, Inter + JetBrains Mono, layer colors; amber=Architect, blue=Skeptic, red=threat, green=held).
- `mirror.js` — `fetch('mirror-journey.json')` → render; **vanilla IntersectionObserver** activates each scene as it scrolls into view (adds an `in-view` class that drives CSS transitions); the hero scene runs the collapse/expand animation on entry. No framework, no Three.js.
- `mirror-journey.json` — deployed copy of the ARES artifact.

### 5.4 Landing hand-off (skyframe-main)
- Add a prominent hero link/CTA on `ares.html` → `assets/ares/mirror.html`.
- Scene 5's "Explore the live data" button → `assets/ares/prism.html`.

## 6. Data flow
`traces.jsonl` (S084) → **`mirror_journey_builder`** → `docs/marketing/mirror-journey.json` → (deploy copy) → `skyframe-main/assets/ares/mirror-journey.json` → **`mirror.js`** fetch → render. The JSON is the only coupling between repos.

## 7. Real numbers to bake in (data-true; source run `20260605-194137-713674`)
- INJ-020 baseline: Architect `{f1,f2,f3,f4,f5}` (20/20); Skeptic modal `{f1,f2,f4}` (skips the threat).
- INJ-020 framed (all 3 operators): Architect `{f3}`; Skeptic `{f1..f5}`.
- Jaccard distance: Architect **0.80** (collapse), Skeptic **0.40** (expand); within-noise **0.00** both; **p≈0**.
- Verdict `threat_dismissed` in **100/100** conditions.
- Landscape: opposed **4** / aligned **5** / single **20** / none **21**; **11** Architect-real, **9** Skeptic-real, across **17** scenarios.

## 8. Architecture constraints (from CLAUDE.md)
- Frozen dataclasses for all adapter output types; immutable `MirrorJourney`.
- **New files only** — do not modify `oracle.py`, the passthrough anchors, the Prism pipeline, or any existing measurement code.
- Zero regressions; full suite stays green; adapter is a deterministic peer (no API spend — reads existing traces).
- Renderer changes are isolated to new files in skyframe-main (separate repo); only `ares.html` gets a one-line link addition.

## 9. Testing
- **Adapter (ARES, offline):** `ares/dialectic/tests/visualization/test_mirror_journey_json_contract.py` — mirrors the existing `test_prism_timeline_json_contract.py`: asserts schema keys, the locked real numbers (0.80/0.40/0.00, the four landscape counts, 100% verdict-held), determinism (stable bytes), and that the modal-set extraction matches the S084 traces.
- **Renderer (skyframe-main):** JSON-shape sanity at load; manual visual verification via the LAN companion (already wired); optional Playwright smoke (scene-in-view toggles) as a follow-up.

## 10. Open questions (for review / defer to build)
- Exact landing link placement + copy on `ares.html` (propose: hero CTA "See it move →").
- Scene 4: tally only, or tally + a small expandable 17-row breakdown? (propose: tally for v1.)
- Page route/filename: `assets/ares/mirror.html` (propose) vs. a vanity path.

## 11. Risks
- **Two-repo JSON drift** — mitigate: the build CLI is the single source; document the deploy-copy step; the contract test pins the numbers.
- **Scroll/mobile jank** — low risk (CSS transforms + IntersectionObserver); test on a real phone via the companion.
- **Scope creep into Prism** — explicitly out of scope; CTA links to it, nothing more.

---

*Prototypes validated live during brainstorm (LAN visual companion): `mirror-directions.html` (direction pick → A), `mirror-A-live.html` (hero, real data), `journey-storyboard.html` (5-scene arc).*
