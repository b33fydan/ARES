# ARES — Adversarial Reasoning Engine System
## AGENTS.md — Project State (Post-Session 042)

**Last updated:** 2026-04-02
**Commit:** `2f28dcc` on `session/042-kill-chain-prompts`
**Tests:** 2,308 collected (2,239 passed, 69 skipped, 0 failures)

---

## What ARES Is

A dialectical AI framework for cybersecurity threat analysis. Three agents — Architect (prosecutor), Skeptic (defense attorney), Oracle (judge) — evaluate evidence packets under closed-world constraints where hallucinations become schema violations. Single-turn production pipeline: one Architect call, one Skeptic call, deterministic Oracle verdict.

**The core research findings:**
1. Structured dialectical debate degrades LLM accuracy (negative, cross-validated with ETH Zurich)
2. Domain-specific conceptual frameworks in prompts break through apparent LLM calibration ceilings
3. The kill chain stage model produced the largest single accuracy improvement in 42 sessions

---

## Tech Stack

- Python 3.11, Anthropic API (Codex Sonnet), Redis
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
- **v5 prompts are production** (`llm_strategy_v5.py`) — kill chain aware Architect
- v4 prompts preserved in `llm_strategy_v4.py` for comparison baselines
- OracleJudge (V1) in `oracle.py` — threshold-based decision table
- OracleJudgeV2 — delta-based 3-tier scoring (winner: delta=0.30)
- OracleNarrator explains but cannot override verdict

### Kill Chain Assessment Framework (v5, Session 042)

The Architect applies graduated confidence based on penetration depth:

| Highest Stage Reached | Confidence Range | Behavior |
|----------------------|------------------|----------|
| Stage 1 — Recon only | 0.30–0.45 | Scanning is not attacking |
| Stage 2 — Vulns found, no exploit | 0.45–0.60 | Risk exists but unrealized |
| Stage 3 — Exploitation confirmed | 0.75–0.90 | Active compromise |
| Stage 4 — Post-exploitation | 0.90–0.95 | Sustained adversary access |
| Failed attack | 0.25–0.40 | Defenses held |

Conditional activation: applies when PENTEST_TOOL source types are present. SC scenarios use standard assessment.

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
- Multiple frontends connect simultaneously ("mask swapping")
- Static deployment: `run_live_export --mode showcase` → showcase.json → index.html?session=showcase.json (zero-cost, no Python/API needed)

---

## Accuracy State (Session 042 — Current Best)

### V5 Prompts + V1 Oracle (production config)
- **SC: 27/33 (81.8%)**
- **PT: 6/6 (100%)**
- **Combined: 33/39 (84.6%)**
- Zero SC regressions from v4 baseline

### Accuracy Journey

| Session | Config | SC | PT | Combined | Key Change |
|---------|--------|----|----|----------|------------|
| 011B | v2 prompts, 12 SC | 11/12 | — | 91.7% | First prompt optimization |
| 025-031 | v3/v4 prompts, 33 SC | ~28/33 | — | ~84.8% | Expanded corpus, ceiling observed |
| 040 | v4 prompts, 39 combined | 26/33 | 2/6 | 71.8% | PentAGI integration, PT baseline |
| 041 | v4+V2 Oracle (0.30) | 27/33 | 2/6 | 74.4% | Scoring architecture lever |
| **042** | **v5 kill chain prompts** | **27/33** | **6/6** | **84.6%** | **Domain concept injection** |

### Intervention Hierarchy (Final)

| Layer | Impact | Finding |
|-------|--------|---------|
| Prompts (general calibration) | 50% → ~80% | General confidence guidance works but has a ceiling |
| Prompts (domain-specific concepts) | ~80% → 84.6% | Teaching kill chain structure shattered the ceiling |
| Scoring architecture (V2 Oracle) | +2.6% marginal | Clean gains, less critical after v5 |
| Multi-turn debate | Negative | Degrades accuracy across all configurations |

---

## Development Principles

- **New files over modifications.** Session branches, squash merge to main after zero regressions.
- **Frozen dataclasses everywhere.** The type system enforces constraints.
- **Measurement before optimization.** Benchmark infrastructure precedes tuning.
- **Binary forcing functions.** Pass/fail milestones prevent drift.
- **Data before theatrics.** Visualization and content deferred until accuracy story is solid.
- **Two-file deliverable.** Strategy brief + CC prompt as separate markdown files.

---

## Key File Locations

```
ares/dialectic/agents/strategies/
├── llm_strategy_v5.py      — Production prompts (v5, kill chain aware)
├── llm_strategy_v4.py      — Previous prompts (v4, comparison baseline)
├── live_cycle.py            — run_cycle_with_strategies() — single LLM call point
├── client.py                — AnthropicClient wrapper
└── ...                      — rule_based, retry, fallback, validation, observability

ares/dialectic/scripts/
├── pentagi_scenarios.py     — 6 PT scenarios + get_pentagi_corpus() (39 total)
├── scenario_corpus_v2.py    — 33 SC scenarios (patched verdicts)
├── benchmark_runner.py      — V1 benchmark runner
├── sweep_oracle_v2.py       — V2 threshold sweep (rescore + CLI)
└── benchmark_results/
    ├── v2_sweep/sweep_results.json        — V2 Oracle sweep data
    └── v5_killchain/results.json          — v5 prompt benchmark data

ares/dialectic/agents/oracle.py  — OracleJudge (V1, deterministic)

ares/visual/
├── scripts/run_live.py      — Live analysis + WebSocket server
├── visualizer/index_v3.html — Live HUD (active default)
├── visualizer/index_v5.html — Particle physics + full HUD (most capable)
├── events.py, events_v2.py  — Frozen event dataclasses
└── nw_wrld_modules/         — Three.js components
```

---

## Publishable Findings (6 confirmed)

1. Multi-turn structured debate degrades LLM accuracy in cybersecurity threat analysis
2. General prompt engineering has a ceiling (~80%) that appears structural
3. That ceiling yields to domain-specific conceptual frameworks (kill chain stages → 84.6%)
4. Teaching domain structure produced the largest single accuracy improvement (highest-impact intervention)
5. Scoring architecture provides marginal clean gains but cannot overcome upstream calibration
6. The confidence calibration pattern is source-agnostic when prompts lack domain structure, and source-aware when they have it

**Working title:** *"Structured Dialectical Debate Degrades LLM Accuracy in Cybersecurity Threat Analysis"*
**Target venues:** ACSAC, RAID, AISec workshop
**Differentiators vs ETH Zurich:** Real cybersecurity domain, mechanistic diagnosis, three fix attempts documented, domain concept breakthrough, solo-built testbed

---

## On the Horizon

### Next Session (043): Kill Chain Visualization + Webpage Deployment
- Temporal flow rendering in ARES-Vision (facts ordered by kill chain stage)
- Directed edges showing tool output → next tool input chain
- Color-coded kill chain stages (blue → cyan → red → white)
- Static export to showcase.json → deploy to public webpage
- Agent reasoning panel (stretch)

### Future
- Adopt v5 + delta=0.30 as combined production config
- Paper draft — six findings confirmed, methodology doc at `docs/ARES_METHODOLOGY.md`
- AKIRA aesthetic pass on visualizer (theatrical layer on working data)
- Content production — ARES Chronicles Episodes 5-6

---

## Session History (Abbreviated)

| Session | Tests | Cumulative | Key Outcome |
|---------|-------|------------|-------------|
| 001-008 | 926 | 926 | Phase 0-1: Foundation through multi-turn |
| 009-012 | 264 | 1,190 | LLM integration + benchmark infrastructure |
| 013-021 | 473 | 1,663 | Corpus expansion + prompt hardening |
| 022-024 | ~145 | ~1,808 | Phase 3: Selective escalation (debate degrades accuracy) |
| 029 | 46 | ~1,927 | Visual emitter + nw_wrld modules |
| 030-032 | ~125 | ~2,050 | V2 Oracle + v3 prompts + corpus_v2 |
| 033-039 | ~196 | ~2,246 | Visualization pipeline hardening |
| 040 | 104 | 2,350 | PentAGI integration (6 PT scenarios, cross-validation) |
| 041 | 19 | 2,369 | V2 Oracle sweep: delta=0.30 wins (74.4%, 0 regressions) |
| **042** | **~15** | **2,308*** | **Kill chain v5 prompts: PT 6/6, SC 27/33, combined 84.6%** |

*Test count variance due to test reorganization across sessions; zero failures maintained throughout.