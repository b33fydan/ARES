# ARES Development Project

## Context
Building ARES (Adversarial Reasoning Engine System) — a dialectical AI framework
for cybersecurity defense. Phase 4: Single-Turn Hardening + Visualization Layer.

## Current Status
- Phase 4, Session 029 (Visualization Layer)
- 1,881 tests passing across 24 sessions, zero regressions
- Single-turn accuracy: 81.8% on 33-scenario corpus
- Phase 3 finding: multi-turn debate degrades accuracy in all configurations tested
- Debate chapter closed. Single-turn is the production path.
- Session 029: Build the visual emitter that streams ARES reasoning as live data to nw_wrld

## Tech Stack
- Python 3.11, Windows + PowerShell + venv
- Anthropic API (Claude Sonnet) for LLM strategies
- Redis for Memory Stream
- websockets (Python) for visual emitter
- nw_wrld (Electron + Three.js) for visualization

## Code Location
C:\ares-phase-zero

## Architecture Principles
1. **Closed-world assumption** — Only frozen EvidencePackets as truth
2. **Hallucinations = Schema violations** — Not mysterious AI behavior
3. **All dataclasses frozen** — Immutability enforced at the type level
4. **New files only** — Never modify existing files
5. **Zero regressions** — Non-negotiable across all sessions
6. **The visual layer renders real data** — Every node, edge, and color maps to a frozen dataclass field

## New Subsystem: ares/visual/
Session 029 introduces `ares/visual/` — a new package for the visualization pipeline.
- `events.py` — Frozen event dataclasses (the JSON schema for WebSocket messages)
- `replayer.py` — Replays a scenario as a sequence of timed visual events
- `emitter.py` — WebSocket server that streams events to nw_wrld
- `nw_wrld_modules/` — JavaScript modules for nw_wrld (Three.js renderers)

## Development Commands
```powershell
# Activate venv
.\venv\Scripts\Activate.ps1

# Run tests
python -m pytest ares/ -v

# Run visual emitter (single scenario)
python -m ares.visual.scripts.run_visual --scenario SC-001

# Run visual emitter (all scenarios)
python -m ares.visual.scripts.run_visual --all

# List scenarios
python -m ares.visual.scripts.run_visual --list
```

## Session Progress
| Session | Component | Tests | Cumulative |
|---------|-----------|-------|------------|
| 001–010 | Phase 1: Core Architecture | 1,104 | 1,104 |
| 011–014 | Phase 2: Scenarios, Benchmarks, Prompts | 304 | 1,408 |
| 016–020 | Extractors + Anchored Debate | 187 | 1,595 |
| 021–024 | Phase 3: Selective Escalation (negative result) | 286 | 1,881 |
| **029** | **Visual Emitter + nw_wrld Module** | **TBD** | **TBD** |
