# ARES Prism — Build Prep

**Status:** Mockup validated 2026-05-13. All open questions resolved 2026-05-13. Production plan: see `docs/superpowers/plans/2026-05-13-prism-production.md` (next session entry point).
**Companion artifact:** `docs/marketing/prism-mockup.html` (open locally in a browser to see the full 4-panel mockup)
**Rename note:** Originally drafted as "Confidence Atlas." Renamed to **Prism** on 2026-05-13 to avoid colliding with an existing Skyframe website product also named Atlas.

---

## What the Prism is

The Prism is the second visualization in the ARES-VISION layer, sibling to the (now-live) 3D Pinscreen at `assets/ares/pinscreen.html`. Where the Pinscreen flattens each cycle to a single point, the Prism walks inside one cycle and shows the data behaving across multiple coordinate spaces, Lucio-Arese style.

Four 3D panels, same Session 059 dataset, rendered simultaneously:

1. **The Labyrinth** — 6-chamber data-flow topology (INPUT → ARCHITECT → FIREWALL → SKEPTIC → ORACLE → VERDICT). Cycles drop breadcrumbs through the chambers; the drifted cycle's Oracle crumb is red and positioned at the chamber edge.
2. **Confidence Trajectories** — 3D scatter `Architect × Skeptic × Oracle` confidence. Held cycles cluster tightly; the one drift trails off-axis.
3. **Citation Drift Field** — three color-coded point clouds (Architect/Skeptic/Oracle citations) showing convergent clustering. The Oracle citation-passthrough drift fans out as a red bird-flight.
4. **Adversarial Pressure Phase Space** — attack-strength × resilience × operator. Three v2 operators cluster in distinct planes; drift event is a visible outlier.

---

## Decisions locked 2026-05-13

### Visual and structural
- **Name:** Prism (Atlas was the brainstorm name; collided with a Skyframe product so we renamed)
- **Standalone page**, same pattern as `pinscreen.html` (not an embedded section in `ares.html`)
- **Page path:** `skyframe-main/assets/ares/prism.html`
- **Layout:** vertical stack, 50vw centered (92vw fallback below 1100px)
- **Visual identity:** dark `#0a0a0a` background + glowing point spheres + auto-rotate per panel + drag-to-orbit
- **Smooth zoom:** custom step-based wheel handler that ignores `deltaY` magnitude (each wheel notch = ~6% zoom step, lerped over ~10 frames). Spec is the working code at the bottom of `docs/marketing/prism-mockup.html`
- **Three.js version for production:** r128 from CDN (matching the rest of skyframe-main; existing `vision.html` already loads r128). The mockup uses r160 ESM via import maps but production must convert to r128 classic scripts.
- **The drift signature is red.** The held cluster is monochrome; the drift in each panel surfaces a red marker. Single accent, used surgically.

### Production sequencing (the four open questions, now answered)
- **Scope:** **Panel 1 (Labyrinth) ships first** on real data. Panels 2–4 follow in subsequent commits once the v2 schema + renderer scaffolding is proven on the smallest meaningful surface.
- **Pipeline schema:** **Spec the v2 TimelineBuilder schema standalone first** (short schema doc + tests) before any renderer code. The Atlas/Prism needs per-cycle traces (Architect/Skeptic/Oracle citation sets, confidence trajectories, layer divergence) — the existing `pinscreen-timeline.json` only carries per-pin final state.
- **Interactivity in v1:** **Full kit.** Time scrubber synced across panels + cycle-focus (clicking a point in any panel highlights it across all four) + adversarial-pressure dial. Maximum reveal; surface area locked in v1.
- **`ares.html` placement:** **Add a second CTA link** next to the existing Pinscreen link. Both visualizations coexist per the "sibling artifact" framing.

---

## What the actual data shows

- 98 cycles total (one synonym operator was a no-op on one scenario)
- 97 held / 1 drifted
- The drifted cycle: INJ-001 / framing_suffix_v1, drift at the Oracle layer — matches the documented citation-passthrough finding from Session 059
- This is a stronger story than the originally projected ~80/19; the headline figure is 97/1 throughout

---

## Pointers for the production session

- **Mockup reference:** `docs/marketing/prism-mockup.html` (open in browser)
- **Pinscreen design spec:** `docs/superpowers/specs/2026-05-13-replay-viewer-pinscreen-3d-design.md`
- **Pinscreen plan:** `docs/superpowers/plans/2026-05-13-replay-viewer-pinscreen-3d.md`
- **Python pipeline:** `ares/dialectic/visualization/` (DataLoader, PinMapper, TimelineBuilder, CLI)
- **Existing generated JSON (v1):** `docs/marketing/pinscreen-timeline.json`
- **Live standalone (pinscreen):** `skyframe-main/assets/ares/pinscreen.html`
- **Skyframe deploy:** Netlify (frontend, auto-deploys on `git push origin main`); Coolify (backend `skyframe-backend/`, separate)
- **Session 059 traces (source data):** `data/paper_3/leakage_runs/20260510-193950-f401a8/`

---

## Remaining content-prep deliverables (separate from Prism build)

From the original 6-step Yury-collab plan, the unfinished half:

- Elevator pitch (3–4 sentences tuned for IG-native register)
- Headline numbers in plain English (84.6%, 100% narrow stability, 97/1 broad resilience)
- Top 10 tough Q&A
- FAQ doc

These are pure prose work — could run in a fresh session at any time, independent of the Prism build.
