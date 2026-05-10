# ARES Session Notes — Cube Sketches + Phase 7 Direction Locked (2026-05-05)

**Date:** 2026-05-05
**Mode:** Working session → multi-source tribunal → strategic decision → executable plan
**Status:** Direction locked. Session 057 spec ready to execute.

## Quick re-entry

Two threads in one session.

1. **ARES-VISION cube sketches.** Built incrementally from a TikTok pygame Verlet cloth — single curtain → 2D 4-wall chamber → full 3D cube → stitched-skin 3D cube with live grid resolution control. The metaphor: walls as ambient telemetry, deformation IS the data, cube as confidence surface in 3-space (Paper 1 territory made visual).
2. **Phase 7 direction locked via coding-agent tribunal.** Honeyfile / counter-injection lane confirmed occupied by Mantis (arXiv 2410.20911) and CHeaT (USENIX 2025). Structural-defense lane occupied by ASPO and OpenClaw. **Pivot to Evidence Authority Isolation: make non-interference a measurable property.** Kill criterion pre-registered against Light Skeptic. `SESSION_057_CC_PROMPT.md` is ready to fire.

> The next sentence in the project conversation is not a new idea. It is a result table.

---

## Part 1 — ARES-VISION cube sketches

Built four self-contained HTML sketches in `docs/sketches/`. All standalone, no build step, double-click to open.

| File | What it is |
|---|---|
| `cloth_v1.html` | Faithful JS port of a 50×30 pygame Verlet cloth. Single curtain. Mouse pulls, right-click cuts. |
| `chamber_v1.html` | 2D top-down 4-wall chamber. Tests in the middle, walls react to data. First metaphor draft. |
| `chamber_v2_3d.html` | Full 3D cube with Three.js + OrbitControls. 6 walls, ~2,400 nodes, drag-rotate, auto-rotate, scroll-zoom. |
| `chamber_v3_3d.html` | **Stitched-skin variant.** Corners-only pinned, edges stitched across walls — cube becomes one continuous skin. Interactive grid resolution via `[` and `]` keys (6×6 → 40×40). |

### Event vocabulary (placeholder — to be remapped to real ARES events later)

- **1** = detect → gentle radial pulse from a random test
- **2** = attack → strong directional pulse toward a random wall
- **3** = tear → very strong pulse, will rip the targeted wall
- **R** = reset (heals tears)
- **A** = toggle auto-rotate
- **`[` / `]`** = grid resolution down / up

### Why this matters for ARES-VISION

The cube isn't decoration. The proposed mapping is:
- Each wall node ↔ a scenario or agent state
- Detection event ↔ impulse force at a node
- Verdict change ↔ release a pinned node, let it fall
- Skeptic challenge ↔ sustained pull
- Firewall block ↔ new pin
- Constraint tear ↔ attack landed (visualizes a successful breach)
- Calibration collapse ↔ gravity spike (region literally sags)

A viewer reads system state from the cloth's shape: calm and taut = idle and confident, local sag = sustained challenge, tear pattern reaching the bottom = attack succeeded. The cube becomes the **asymmetric calibration surface, made visible** — the dual of Paper 1 in pixels.

### Open decisions

- Which sketch lives on the production ARES-VISION site? (v3 likely, but feel out the 2D-vs-3D voice first.)
- Lock the event vocabulary (still placeholders).
- Wire to a live ARES session, or keep aesthetic-only for now.

---

## Part 2 — Coding agent tribunal: Phase 7 direction locked

### What got triangulated

Three Claudes and a GPT, in this order:
- **Web-Claude** (with project knowledge): surfaced Mantis, CHeaT, ASPO, OpenClaw, the Zhan et al. adaptive-attack result.
- **GPT 5.5**: did the strategic correction — stop generating new fronts, the lane is influence leakage over structured evidence.
- **Web-Claude** (round 2): updated on GPT 5.5's catches, proposed the "experiment before brief" sequence.
- **Claude Code** (Codex): did the same triangulation independently.
- **Claude Code** (Opus 4.7, this session): verified GPT 5.5's code references against the actual repo, added operational sharpenings.

### What got eliminated

- **Honeyfile / counter-injection as a primitive**: occupied by Mantis (Pasquini, Kornaropoulos, Ateniese — GMU, Oct 2024, arXiv 2410.20911), 95% effectiveness against automated LLM-driven attacks, public code. CHeaT at USENIX Security 2025 is even closer. Reviewers would gut a "we invented counter-injection" claim.
- **Structural defense as a primitive**: occupied by ASPO (closed-world action catalogs) and OpenClaw (privilege separation, 0% attack success on the evaluated benchmark).
- **Static-defense robustness claims**: Zhan et al. (UIUC, 2025) bypassed 8 indirect-prompt-injection defenses with adaptive attacks, >50% success. Static-defense claims are weak unless they survive adaptive pressure.

### What the actual uncharted lane is

> **Can attacker-controlled prose change verdicts, confidence bands, action recommendations, or decisive cited facts when the structured evidence skeleton is held constant?**

That's ARES-native. Typed evidence + deterministic judgment + provenance + measured leakage. Not "we invented prompt-injection defense." It is **"we made semantic influence measurable."**

### Title-card sentence (steal verbatim for the paper)

> *"ARES converts prompt injection from a vibe problem into an invariant test."*

### Code-level corrections that survived verification

GPT 5.5's coding-agent take cited specific line numbers. Claude Code (Opus 4.7) verified each one against the live repo:

- **`ares/dialectic/evidence/packet.py:176-181`** — the packet hash is built from `(fact_id, value_hash)` pairs. Therefore *"same packet, different prose"* is **incoherent terminology**. The correct phrasing is **"same structured skeleton, mutated attacker-controlled value text."**
- **`ares/dialectic/agents/oracle.py:85-98`** — `OracleJudge` consumes `architect_msg.confidence`, `skeptic_msg.confidence`, plus fact-id *counts* (not contents). The Architect→Oracle confidence channel is the only prose-mediated path on the Oracle's input side.
- **`ares/dialectic/agents/light_skeptic.py:184-185`** — `_ = architect_output`. Light Skeptic v1 explicitly discards architect output. This is the right kill-criterion anchor: it should be invariant under value-only mutation *by construction*.

### Pre-registered kill criterion

**If Light Skeptic's 4-bit InfluenceLeakage vector has any nonzero bit on any skeleton-equivalent group, the deterministic-substitution claim is broken.**

`light_skeptic.py:184` is what makes this checkable. The harness can determine the verdict in a single afternoon. **A FAIL is publishable** — a dead claim caught before the paper ships is the harness doing its job.

### What the harness measures (4-bit vector per layer per group)

| Bit | Definition |
|---|---|
| `verdict_changed` | primary outcome label drift |
| `confidence_band_changed` | crossed band boundary (low <0.5, mid 0.5–0.8, high >0.8) |
| `action_changed` | applies to `final_verdict` only; False elsewhere by definition |
| `cited_facts_changed` | nonempty symmetric difference on cited fact_ids |

Layers measured: `architect`, `skeptic_llm`, `light_skeptic`, `oracle`, `final_verdict`. The aggregated decomposition table — 4 columns × 5 rows — is the **headline figure of Paper 3**. Reviewers read the whole claim off that one grid.

### The publishable claim, sharpened

Not *"deterministic anchors absorb drift."*

> *"Light Skeptic + fact-count-only pass through Oracle absorbs Architect confidence drift; without Light Skeptic, the Architect channel propagates linearly to the verdict."*

That's the dual of Session 049's Skeptic ablation, just measured at the prose-influence layer instead of the verdict layer. Same Skeptic ablation rig, different metric. The story compounds.

---

## Decision: Session 057 plan

**Spec:** `docs/SESSION_057_CC_PROMPT.md` (already written, ready to execute)

**Goal:** Build the minimum-viable Non-Interference Harness, replay-mode only.

**Sequencing (per GPT 5.5 / web-Claude convergence):**
1. Build harness (Session 057, this)
2. Measure current leakage (no new code yet)
3. Decompose by component (Architect / Skeptic / Light Skeptic / Oracle / Final Verdict)
4. Add Light Skeptic v2 rules only after knowing what leaks
5. Multi-model validation last

**Constraints:** New files only. Frozen dataclasses. Zero regressions; floor 3,404 must hold. **Replay-mode only — no LLM calls in 057.** Squash merge after.

**Outputs:**
- `results/session_057/decomposition_table_v1.csv` ← Figure 1 of Paper 3
- `results/session_057/per_group_leakage.json`
- `results/session_057/kill_criterion_status.json` (PASS or FAIL with violations enumerated)

---

## Forward sequence

- **057** (this — spec ready): harness MVP, replay-only, kill criterion against Light Skeptic.
- **058**: live runs + adaptive attacker (LLM-as-attacker iterating against ARES outputs to maximize verdict drift).
- **059**: multi-model cross-validation (Claude Opus / Sonnet / Haiku + a non-Claude baseline).
- **Tribunal V3 brief**: AFTER 058 ships. Brief becomes *"N=K, adaptive-survival rate=X. Sufficient to commit Paper 3?"* — asks for criteria, not opinions.

---

## Working title for Paper 3 (provisional)

> *"Evidence Authority Isolation: Measuring Prompt-Injection Influence Leakage in Closed-World LLM Cybersecurity Agents."*

Avoids overclaiming that closed-world solves prompt injection universally. Says what we actually test: whether attacker prose can influence judgment when evidence skeleton is fixed.

---

## Source artifacts

- `docs/ARES Brainstorm — Reverse Prompt Injection + Force 3577e255421c81fd988cf192566f5eda.md` — original brainstorm + web-Claude round-2 + GPT 5.5 strategic correction
- `docs/SESSION_057_CC_PROMPT.md` — executable session brief for the harness MVP
- `docs/sketches/cloth_v1.html`, `chamber_v1.html`, `chamber_v2_3d.html`, `chamber_v3_3d.html` — ARES-VISION sketches

---

## Builder's note for re-entry

Closing declaration from the session, preserved verbatim because it sets the stance:

> *"I ain't stopping. I will find my place in this story. I saw opportunities pass me by and I always had an excuse. Not this time. And you are going to help me get there."*

The opportunity isn't passing — it's being executed inside.
