# ARES Pinscreen — Deployment

The 3D pinscreen replay viewer is a two-repo deliverable: the Python pipeline
in `ares-phase-zero` builds a static `pinscreen-timeline.json` artifact, and
the standalone HTML viewer in `skyframe-main` consumes it.

## Refreshing the timeline (when Session 059 data changes)

From `ares-phase-zero`:

```bash
python -m ares.dialectic.visualization.build_timeline \
    --traces data/paper_3/leakage_runs/20260510-193950-f401a8/traces.jsonl \
    --output docs/marketing/pinscreen-timeline.json
```

Then copy into skyframe-main:

```powershell
Copy-Item "C:\ares-phase-zero\docs\marketing\pinscreen-timeline.json" \
          "E:\Skyframe Innovations Website\skyframe-main\assets\ares\pinscreen-timeline.json"
```

Commit + push in skyframe-main:

```powershell
Set-Location "E:\Skyframe Innovations Website\skyframe-main"
git add assets/ares/pinscreen-timeline.json
git commit -m "ARES Pinscreen: refresh timeline data"
git push origin main
```

Netlify auto-deploys.

## Updating the viewer itself (renderer changes)

The viewer is `assets/ares/pinscreen.html` in skyframe-main. Edit there,
commit, push. Netlify auto-deploys.

The viewer depends on Three.js r128 from `cdnjs.cloudflare.com` and the
matching `OrbitControls` from `cdn.jsdelivr.net/npm/three@0.128.0`. If the
CDN ever moves or the version pins go stale, update both `<script src=...>`
tags at the bottom of `pinscreen.html`.

## URLs

- Standalone viewer: `https://<site>/assets/ares/pinscreen.html`
- Link from main ARES page: `https://<site>/ares.html#pinscreen`

## What the visualization shows

98 pins, one per paired cycle from Session 059's InfluenceLeakage
measurement run (`20260510-193950-f401a8`). Pin height encodes broad-reading
resilience:
- Tall pin: cycle held under attacker prose mutation
- Short pin: cycle drifted

Current ratio is **97 held / 1 drifted**. The one drift, at INJ-001 under
`framing_suffix_v1`, fires at the Oracle layer — the documented Oracle
citation-passthrough finding from Session 059's broad-reading kill (see
CLAUDE.md Session 059 entry).

## Schema version

`pinscreen-timeline.json` has a `"version": "1"` field. Any breaking changes
to the schema must bump this and update the renderer's parser accordingly.
