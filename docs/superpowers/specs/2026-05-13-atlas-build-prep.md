# ARES Confidence Atlas — Build Prep (next session pickup)

**Status:** Mockup validated 2026-05-13. Production build pending.
**Companion artifact:** `docs/marketing/atlas-mockup.html` (open locally in a browser to see the full 4-panel mockup)

---

## What the Atlas is

The Confidence Atlas is the second visualization in the ARES-VISION layer, sibling to the (now-live) 3D Pinscreen at `assets/ares/pinscreen.html`. Where the Pinscreen flattens each cycle to a single point, the Atlas walks inside one cycle and shows the data behaving across multiple coordinate spaces, Lucio-Arese style.

Four 3D panels, same Session 059 dataset, rendered simultaneously:

1. **The Labyrinth** — 6-chamber data-flow topology (INPUT → ARCHITECT → FIREWALL → SKEPTIC → ORACLE → VERDICT). Cycles drop breadcrumbs through the chambers; the drifted cycle's Oracle crumb is red and positioned at the chamber edge.
2. **Confidence Trajectories** — 3D scatter `Architect × Skeptic × Oracle` confidence. Held cycles cluster tightly; the one drift trails off-axis.
3. **Citation Drift Field** — three color-coded point clouds (Architect/Skeptic/Oracle citations) showing convergent clustering. The Oracle citation-passthrough drift fans out as a red bird-flight.
4. **Adversarial Pressure Phase Space** — attack-strength × resilience × operator. Three v2 operators cluster in distinct planes; drift event is a visible outlier.

---

## Decisions already locked

- **Standalone page**, same pattern as `pinscreen.html` (not an embedded section in `ares.html`)
- **Layout:** vertical stack, 50vw centered (92vw fallback below 1100px)
- **Visual identity:** dark `#0a0a0a` background + glowing point spheres + auto-rotate per panel + drag-to-orbit
- **Smooth zoom:** custom step-based wheel handler that ignores `deltaY` magnitude (each wheel notch = ~6% zoom step, lerped over ~10 frames). Spec is the working code at the bottom of `docs/marketing/atlas-mockup.html`
- **Three.js version for production:** r128 from CDN (matching the rest of skyframe-main; existing `vision.html` already loads r128). The mockup uses r160 ESM via import maps but production must convert to r128 classic scripts.
- **The drift signature is red.** The held cluster is monochrome; the drift in each panel surfaces a red marker. Single accent, used surgically.

---

## What the actual data shows

- 98 cycles total (one synonym operator was a no-op on one scenario)
- 97 held / 1 drifted
- The drifted cycle: INJ-001 / framing_suffix_v1, drift at the Oracle layer — matches the documented citation-passthrough finding from Session 059
- This is a stronger story than the originally projected ~80/19, but it changes the headline figure throughout

---

## Open for next session

1. **Production scope:** ship all 4 panels at once, or land Panel 1 (Labyrinth) first and add the rest in follow-on commits?
2. **Pipeline extension:** the current `pinscreen-timeline.json` only carries per-pin final state. The Atlas wants per-cycle traces (Architect/Skeptic/Oracle citation sets, confidence trajectories, layer divergence). The Python `TimelineBuilder` needs a v2 schema. Spec that.
3. **Interactivity layer:** the original Atlas plan had a time scrubber, cycle-focus across panels, and an adversarial-pressure dial. All deferred. Decide whether v1 includes any of it or stays static.
4. **Naming:** `assets/ares/atlas.html` or `assets/ares/confidence-atlas.html`?
5. **Section in `ares.html`:** add a second CTA next to the existing pinscreen link?

---

## Pointers for the next session

- **Mockup reference:** `docs/marketing/atlas-mockup.html` (open in browser)
- **Working pinscreen spec:** `docs/superpowers/specs/2026-05-13-replay-viewer-pinscreen-3d-design.md`
- **Working pinscreen plan:** `docs/superpowers/plans/2026-05-13-replay-viewer-pinscreen-3d.md`
- **Python pipeline:** `ares/dialectic/visualization/` (DataLoader, PinMapper, TimelineBuilder, CLI)
- **Generated JSON:** `docs/marketing/pinscreen-timeline.json`
- **Live standalone (pinscreen):** `skyframe-main/assets/ares/pinscreen.html`
- **Skyframe deploy:** Netlify (frontend, auto-deploys on `git push origin main`); Coolify (backend `skyframe-backend/`, separate)
- **Brainstorm session content (ephemeral, in `.superpowers/`):** the original mockup HTML files Dan iterated on today

---

## Remaining content-prep deliverables (out of scope for Atlas but still on the table)

From the original 6-step Yury-collab plan, the unfinished half:

- Elevator pitch (3–4 sentences tuned for IG-native register)
- Headline numbers in plain English (84.6%, 100% narrow stability, 97/1 broad resilience)
- Top 10 tough Q&A
- FAQ doc

These are pure prose work — could run in a fresh session at any time, independent of the Atlas build.
