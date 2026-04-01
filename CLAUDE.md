# ARES — Adversarial Reasoning Engine System
## CLAUDE.md — Project State (Post-Session 041)

**Last updated:** 2026-04-01
**Commit:** `e469d4a` on `session/041-oracle-v2-sweep`
**Tests:** 2,369 collected (2,304 passed, 65 skipped, 0 failures)

---

## What ARES Is

A dialectical AI framework for cybersecurity threat analysis. Three agents — Architect (prosecutor), Skeptic (defense attorney), Oracle (judge) — evaluate evidence packets under closed-world constraints where hallucinations become schema violations. Single-turn production pipeline: one Architect call, one Skeptic call, deterministic Oracle verdict.

**The core research finding:** Structured dialectical debate degrades LLM accuracy. Multi-turn is harmful. Single-turn is superior. This is confirmed across all configurations tested and independently corroborated by ETH Zurich.

---

## Tech Stack

- Python 3.11, Anthropic API (Claude Sonnet), Redis
- Three.js + WebSocket for visualization (ARES-VISION)
- Windows + PowerShell + venv
- Code location: `C:\ares-phase-zero`
- License: GPL-3.0

---

## Architecture — What's Built

### Evidence Pipeline
```
Raw data → Extractor → Facts → EvidencePacket.freeze() → Agents
```
Four extractors: Windows Event XML, BSD syslog, NetFlow CSV, PentAGI action JSON.

### Dialectical Pipeline
```
EvidencePacket → Architect (thesis, 1 LLM call) → Skeptic (antithesis, 1 LLM call) → OracleJudge (deterministic) → Verdict
```
- `run_cycle_with_strategies()` in `live_cycle.py` is the single LLM call point
- v4 prompts are production (`llm_strategy_v4.py`)
- OracleJudge (V1) in `oracle.py` — threshold-based decision table
- OracleJudgeV2 — delta-based 3-tier scoring (built Session 032, swept Session 041)
- OracleNarrator explains but cannot override verdict

### Corpus
- 33 SC scenarios (security telemetry): `get_full_corpus_v2()` — patches SC-011, SC-017
- 6 PT scenarios (pentest tool output): `get_pentagi_scenarios()`
- Combined 39: `get_pentagi_corpus()`

### Visual Pipeline (ARES-VISION)
```
run_live.py → WebSocket → Browser (v3/v4/v5 interchangeable frontends)
```
- CLI modes: `--mode pentagi | showcase | full`, `--scenario PT-001`, `--speed 0.5`
- Event schema: frozen dataclasses → JSON → ws://localhost:8765
- Three.js modules: AresScene, AresEvidenceGraph, AresConfidenceHeat, AresReplayHandler
- Multiple frontends can connect simultaneously ("mask swapping")

---

## Accuracy State

### V1 Oracle Baseline (live run, Session 041)
- SC: 26/33 (78.8%) — run-to-run variance observed; best-observed was 28/33 (84.8%)
- PT: 2/6 (33.3%) — all 4 misses are CONFIDENCE_CALIBRATION
- Combined: 28/39 (71.8%)

### V2 Oracle Winner: delta=0.30
- SC: 27/33 (+1, zero regressions)
- PT: 2/6 (unchanged at any threshold)
- Combined: 29/39 (74.4%)
- Improvement: SC-032 flipped correct [arch=0.65, skep=0.30]

### Intervention Hierarchy (Confirmed)
| Layer | Impact | Ceiling |
|-------|--------|---------|
| Prompt engineering (v1→v4) | 50% → ~80% | ~80% (variance-bounded) |
| Scoring architecture (V2 delta=0.30) | +2.6% clean | ~74-75% combined |
| Multi-turn debate | Negative | Degrades accuracy |

### The Structural Confidence Floor
The Architect quantizes at 0.75 on ambiguous scenarios regardless of prompt engineering, scoring architecture, or evidence source type. This is source-agnostic (confirmed across SC and PT evidence), structural (not fixable by any tested intervention), and publishable.

---

## Development Principles

- **New files over modifications.** Session branches, squash merge to main after zero regressions.
- **Frozen dataclasses everywhere.** The type system enforces constraints.
- **Measurement before optimization.** Benchmark infrastructure precedes tuning.
- **Binary forcing functions.** Pass/fail milestones prevent drift.
- **Surgical CC prompts.** Session-scoped prompts outperform large CLAUDE.md files.
- **Two-file deliverable.** Strategy brief + CC prompt as separate markdown files.

---

## Key File Locations

```
ares/dialectic/agents/strategies/
├── llm_strategy_v4.py      — Production prompts (v4)
├── live_cycle.py            — run_cycle_with_strategies() — single LLM call point
├── client.py                — AnthropicClient wrapper
└── ...                      — rule_based, retry, fallback, validation, observability

ares/dialectic/scripts/
├── pentagi_scenarios.py     — 6 PT scenarios + get_pentagi_corpus() (39 total)
├── scenario_corpus_v2.py    — 33 SC scenarios (patched verdicts)
├── benchmark_runner.py      — V1 benchmark runner
├── sweep_oracle_v2.py       — V2 threshold sweep (rescore + CLI)
└── benchmark_results/v2_sweep/sweep_results.json

ares/dialectic/agents/oracle.py  — OracleJudge (V1, deterministic)

ares/visual/
├── scripts/run_live.py      — Live analysis + WebSocket server
├── visualizer/index_v3.html — Live HUD (active default)
├── visualizer/index_v5.html — Particle physics + full HUD (most capable)
├── events.py, events_v2.py  — Frozen event dataclasses
└── nw_wrld_modules/         — Three.js components
```

---

## Publishable Findings (5 confirmed)

1. Multi-turn structured debate degrades LLM accuracy in cybersecurity threat analysis
2. Prompt engineering has a ceiling (~80%, with run-to-run variance)
3. Scoring architecture provides marginal clean gains but cannot overcome upstream calibration
4. The LLM confidence floor is source-agnostic (security telemetry + pentest evidence)
5. The confidence floor is structural — not addressable by any intervention layer tested

**Working title:** *"Structured Dialectical Debate Degrades LLM Accuracy in Cybersecurity Threat Analysis"*
**Target venues:** ACSAC, RAID, AISec workshop
**Differentiators vs ETH Zurich:** Real cybersecurity domain, mechanistic diagnosis, three fix attempts documented, solo-built testbed

---

## On the Horizon

1. **Pentest-specific Architect calibration** — Teach Architect to weight negative findings (exploited:false). Domain-specific prompt intervention. Most likely candidate for PT accuracy improvement.
2. **Adopt delta=0.30 as production default** — V2 Oracle winner, zero regressions confirmed.
3. **AKIRA visualizer rebuild** — Dark Interactive Particles spec (index_v2.html redesign). Theatrical layer on top of working data.
4. **Paper draft** — Five findings confirmed. Methodology scaffolding at `docs/ARES_METHODOLOGY.md`.
5. **Content** — ARES Chronicles Episodes 5-6. Three-mask demo clip. PT attack chain tree visualization.

---

## Session History (Abbreviated)

| Session | Tests | Cumulative | Key Outcome |
|---------|-------|------------|-------------|
| 001-008 | 926 | 926 | Phase 0-1: Foundation through multi-turn |
| 009-012 | 264 | 1,190 | LLM integration + benchmark infrastructure |
| 013-021 | 473 | 1,663 | Corpus expansion + prompt hardening |
| 022-024 | ~145 | ~1,808 | Phase 3: Selective escalation |
| 029 | 46 | ~1,927 | Visual emitter + nw_wrld modules |
| 030-032 | ~125 | ~2,050 | V2 Oracle + v3 prompts + corpus_v2 |
| 033-039 | ~196 | ~2,246 | Visualization pipeline hardening |
| 040 | 104 | 2,350 | PentAGI integration (6 PT scenarios) |
| **041** | **19** | **2,369** | **V2 Oracle sweep: delta=0.30 wins (74.4%, 0 regressions)** |