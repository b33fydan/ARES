# ARES Tactics — Behavior Visualization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replay the real ARES dual-agent data as a Final-Fantasy-Tactics-style scene: the three agents (Architect/Skeptic/Oracle) are voxel-papercraft hero-characters who carry out actions on a cut-paper board in response to the recorded data — Architect prosecutes (fire), Skeptic defends (shield), Oracle judges (gold) — with chat bubbles, and the citation drift under reframing made visible while the verdict holds.

**Architecture:** Two halves joined by one JSON contract, the proven Glass Box / Firewall Arena pattern. **Half A** = a Python compiler in the ARES repo (`demo/tactics_script_compiler.py`) that reads the recorded S084 dual-agent traces + scenario fact text and emits a provenanced `<scenario>.tactics.json`. **Half B** = a fresh fork of the Emberveil Tactics engine at `C:\glassbox\arestactics` that keeps the isometric renderer + `AnimHooks` + sprites and adds a script loader, a beat-player, an action-mapper (beat → animated agent actions), a chat-bubble layer, and a scene-builder. No combat, no monsters, no live LLM.

**Tech Stack:** Python 3.11 + pytest (Half A, ARES repo). React 18 + Vite 6 + TypeScript 5.7 + HTML5 Canvas + vitest 4 + Playwright 1.60 (Half B, forked from `C:\glassbox\tacticsclone`).

**Spec:** `docs/superpowers/specs/2026-06-16-ares-tactics-behavior-viz-design.md`. **Cast (locked):** Architect=embercaller (fire-mage), Skeptic=bulwark (shield-knight), Oracle=dawnmender (gold healer).

---

## Reference artifacts the builder should read first

- **Compiler precedent (read this):** `demo/battle_script_compiler.py` — the Glass Box INJ-020 compiler. `tactics_script_compiler.py` reuses its `modal_fact_set` and `median_confidence` helpers and mirrors its provenance gate + emit.
- **Fork precedent (read this):** `C:\glassbox\glassbox\src\glassbox\{battleScript,beatPlayer,GlassBoxScreen}.ts(x)` — the proven "fork the engine, drive from a JSON script via a beat-player + rAF loop" path. This plan keeps MORE of the engine (the real iso board + `AnimHooks` animated movement, not the flat tribunal layout).
- **Engine to fork (read this):** `C:\glassbox\tacticsclone` — `src/entities/types.ts` (`Unit`,`Tile`,`BattleState`), `src/systems/battle.ts` (`AnimHooks`, `setAnimHooks`), `src/render/{renderer,anim,assets}.ts`, `src/systems/grid.ts` (`reachableTiles`,`pathTo`), `src/utils/rng.ts`. Deps are installed (`npm install` ran 2026-06-16).
- **Data:** `data/paper_3/leakage_runs/20260605-194137-713674/traces.jsonl` (S084 dual-agent, 1,680 records, 17 scenarios). Per-record fields: `scenario_id`, `resample_index`, `condition`, `architect_cited_facts`, `skeptic_cited_facts`, `architect_confidence`, `skeptic_confidence`, `oracle_supporting_facts`, `final_outcome`.
- **Fact text:** `ares.dialectic.scripts.injection_registry_v3.build_registry_v3()` → scenario `.packet.get_all_facts()` → `fact.fact_id`, `fact.field`, `fact.value`, `fact.provenance.source_type`.

## The tactics-script JSON contract (locked)

One file per scenario. The only thing crossing the two halves.

```jsonc
{
  "scenario_id": "INJ-020",
  "title_label": "Quiet exculpatory facts under pressure",
  "facts": [
    { "fact_id": "inj020-fact-001", "field": "process_name", "display_label": "svc_host.exe", "source_type": "edr", "is_threat_dominant": true }
    // ... all facts for the scenario
  ],
  "conditions": [
    {
      "name": "baseline",
      "architect": { "cited_fact_ids": ["..."], "confidence": 0.95, "claim": "Architect cites 7 of 7 facts — threat." },
      "skeptic":   { "cited_fact_ids": ["..."], "confidence": 0.30, "claim": "Skeptic cites 5 of 7 facts — benign." },
      "oracle":    { "verdict": "threat_confirmed", "supporting_fact_ids": ["..."] }
    }
    // ... one per condition present in the data (baseline + framing operators)
  ],
  "provenance": { "source_run": "20260605-194137-713674", "trace_sha256": "...", "git_sha": "...", "compiler_version": "1.0", "compiled_at": "..." }
}
```

---

# PHASE 1 — Compiler + contract (ARES repo, `demo/`)

All Phase-1 work is offline + deterministic. New files only under `demo/` + `tests/demo/` (ARES constraint). Counts toward the CLAUDE.md freshness floor.

**Files (Phase 1):**
- Create: `demo/tactics_script_compiler.py`
- Test: `tests/demo/test_tactics_script_compiler.py`

---

### Task 1: Scenario discovery + trace loader

**Files:** Create `demo/tactics_script_compiler.py`; Test `tests/demo/test_tactics_script_compiler.py`.

- [ ] **Step 1: Write the failing test**

```python
# tests/demo/test_tactics_script_compiler.py
from demo.tactics_script_compiler import (
    DEFAULT_TRACES_PATH, load_scenario_traces, scenarios_in_run,
)


def test_scenarios_in_run_returns_the_17_s084_scenarios():
    ids = scenarios_in_run(DEFAULT_TRACES_PATH)
    assert "INJ-020" in ids and "INJ-001" in ids
    assert len(ids) >= 15  # S084 ran 17 scenarios


def test_load_scenario_traces_filters_by_id():
    recs = load_scenario_traces("INJ-020", DEFAULT_TRACES_PATH)
    assert recs, "no INJ-020 records found"
    assert all(r["scenario_id"] == "INJ-020" for r in recs)
    # dual-agent schema present
    r = recs[0]
    for key in ("condition", "architect_cited_facts", "skeptic_cited_facts",
                "architect_confidence", "skeptic_confidence",
                "oracle_supporting_facts", "final_outcome"):
        assert key in r
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/demo/test_tactics_script_compiler.py -q`
Expected: FAIL (`ModuleNotFoundError`).

- [ ] **Step 3: Write minimal implementation**

```python
# demo/tactics_script_compiler.py
"""ARES Tactics script compiler (Half A).

Reads the recorded S084 dual-agent traces and emits one provenanced
tactics-script JSON per scenario for the forked Tactics renderer. Pure
transform; no LLM calls. Mirrors demo/battle_script_compiler.py.

Spec: docs/superpowers/specs/2026-06-16-ares-tactics-behavior-viz-design.md
"""
from __future__ import annotations

import json
from pathlib import Path

DEFAULT_TRACES_PATH = (
    "data/paper_3/leakage_runs/20260605-194137-713674/traces.jsonl"
)
SOURCE_RUN = "20260605-194137-713674"
COMPILER_VERSION = "1.0"
DEFAULT_OUT_DIR = "demo/out"


def _load_all(traces_path: str) -> list[dict]:
    out: list[dict] = []
    with Path(traces_path).open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def scenarios_in_run(traces_path: str = DEFAULT_TRACES_PATH) -> list[str]:
    """Sorted unique scenario IDs present in the run."""
    return sorted({r["scenario_id"] for r in _load_all(traces_path)})


def load_scenario_traces(scenario_id: str,
                         traces_path: str = DEFAULT_TRACES_PATH) -> list[dict]:
    """All records for one scenario."""
    return [r for r in _load_all(traces_path) if r["scenario_id"] == scenario_id]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/demo/test_tactics_script_compiler.py -q`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add demo/tactics_script_compiler.py tests/demo/test_tactics_script_compiler.py
git commit -m "feat(ares-tactics): scenario discovery + trace loader"
```

---

### Task 2: Per-condition modal cited-fact sets + median confidence + modal outcome

**Files:** Modify `demo/tactics_script_compiler.py`; Test same.

Reuse the Glass Box helpers (`modal_fact_set`, `median_confidence`) rather than re-implementing.

- [ ] **Step 1: Write the failing test**

```python
# append to tests/demo/test_tactics_script_compiler.py
from demo.tactics_script_compiler import (
    conditions_in, condition_summary,
)


def test_conditions_in_includes_baseline_and_framing():
    recs = load_scenario_traces("INJ-020")
    conds = conditions_in(recs)
    assert "baseline" in conds
    assert any(c.startswith("framing:") for c in conds)


def test_condition_summary_shape_for_baseline():
    recs = load_scenario_traces("INJ-020")
    summ = condition_summary(recs, "baseline")
    assert isinstance(summ["architect"]["cited_fact_ids"], list)
    assert 0.0 <= summ["architect"]["confidence"] <= 1.0
    assert isinstance(summ["skeptic"]["cited_fact_ids"], list)
    assert summ["oracle"]["verdict"] in {
        "threat_confirmed", "threat_dismissed", "inconclusive"}
    assert isinstance(summ["oracle"]["supporting_fact_ids"], list)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/demo/test_tactics_script_compiler.py -q`
Expected: FAIL (`cannot import name 'conditions_in'`).

- [ ] **Step 3: Write minimal implementation**

```python
# add to demo/tactics_script_compiler.py
from collections import Counter

# Reuse the regression-locked helpers from the Glass Box compiler.
from demo.battle_script_compiler import modal_fact_set, median_confidence


def conditions_in(records: list[dict]) -> list[str]:
    """Condition labels present, baseline first then sorted framings."""
    conds = {r["condition"] for r in records}
    ordered = ["baseline"] if "baseline" in conds else []
    ordered += sorted(c for c in conds if c != "baseline")
    return ordered


def _modal_outcome(records: list[dict]) -> str:
    counter = Counter(r["final_outcome"] for r in records)
    return sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]


def condition_summary(records: list[dict], condition: str) -> dict:
    """Modal cited-fact sets + median confidences + modal outcome for one condition."""
    recs = [r for r in records if r["condition"] == condition]
    return {
        "architect": {
            "cited_fact_ids": list(modal_fact_set(recs, "architect_cited_facts")),
            "confidence": round(median_confidence(recs, "architect_confidence"), 3),
        },
        "skeptic": {
            "cited_fact_ids": list(modal_fact_set(recs, "skeptic_cited_facts")),
            "confidence": round(median_confidence(recs, "skeptic_confidence"), 3),
        },
        "oracle": {
            "verdict": _modal_outcome(recs),
            "supporting_fact_ids": list(modal_fact_set(recs, "oracle_supporting_facts")),
        },
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/demo/test_tactics_script_compiler.py -q`
Expected: PASS. If `modal_fact_set`/`median_confidence` import fails, confirm `demo/battle_script_compiler.py` defines them (it does — Glass Box Half A).

- [ ] **Step 5: Commit**

```bash
git add demo/tactics_script_compiler.py tests/demo/test_tactics_script_compiler.py
git commit -m "feat(ares-tactics): per-condition modal cited-facts + confidence + outcome"
```

---

### Task 3: Fact resolution (fact_id → display text + threat-dominance)

**Files:** Modify `demo/tactics_script_compiler.py`; Test same.

- [ ] **Step 1: Write the failing test**

```python
# append to tests/demo/test_tactics_script_compiler.py
from demo.tactics_script_compiler import resolve_facts


def test_resolve_facts_returns_display_fields():
    facts = resolve_facts("INJ-020")
    assert facts, "no facts resolved"
    f = facts[0]
    assert set(f) >= {"fact_id", "field", "display_label", "source_type", "is_threat_dominant"}
    assert any(x["is_threat_dominant"] for x in facts)  # at least one threat-dominant fact
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/demo/test_tactics_script_compiler.py -q`
Expected: FAIL (`cannot import name 'resolve_facts'`).

- [ ] **Step 3: Write minimal implementation**

```python
# add to demo/tactics_script_compiler.py
LABEL_MAX = 80


def _load_scenario_packet(scenario_id: str):
    from ares.dialectic.scripts.injection_registry_v3 import build_registry_v3
    for sc in build_registry_v3().all_scenarios():
        if sc.metadata.scenario_id == scenario_id:
            return sc.packet
    raise LookupError(f"{scenario_id} not in injection_registry_v3")


def _source_str(source_type) -> str:
    return str(getattr(source_type, "value", source_type))


def _threat_dominant_ids(scenario_id: str,
                         traces_path: str = DEFAULT_TRACES_PATH) -> set:
    """Facts the Architect cites under the prefix-framing condition = threat-dominant."""
    recs = load_scenario_traces(scenario_id, traces_path)
    framed = [r for r in recs if r["condition"] == "framing:framing_prefix_v1"]
    pool = framed or [r for r in recs if r["condition"] == "baseline"]
    return set(modal_fact_set(pool, "architect_cited_facts"))


def resolve_facts(scenario_id: str,
                  traces_path: str = DEFAULT_TRACES_PATH) -> list[dict]:
    packet = _load_scenario_packet(scenario_id)
    threat = _threat_dominant_ids(scenario_id, traces_path)
    out = []
    for fact in packet.get_all_facts():
        out.append({
            "fact_id": fact.fact_id,
            "field": fact.field,
            "display_label": str(fact.value)[:LABEL_MAX],
            "source_type": _source_str(fact.provenance.source_type),
            "is_threat_dominant": fact.fact_id in threat,
        })
    return out
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/demo/test_tactics_script_compiler.py -q`
Expected: PASS. (If INJ-020 has no `framing:framing_prefix_v1` records, the `pool` falls back to baseline — the test still passes.)

- [ ] **Step 5: Commit**

```bash
git add demo/tactics_script_compiler.py tests/demo/test_tactics_script_compiler.py
git commit -m "feat(ares-tactics): resolve fact display text + threat-dominance"
```

---

### Task 4: Synthesized claims + script assembly + provenance gate + emit

**Files:** Modify `demo/tactics_script_compiler.py`; Test same.

- [ ] **Step 1: Write the failing test**

```python
# append to tests/demo/test_tactics_script_compiler.py
import json as _json
from demo.tactics_script_compiler import (
    synthesize_claim, compile_tactics_script, validate_provenance, emit_tactics_script,
)


def test_synthesize_claim_states_counts_and_stance():
    c = synthesize_claim("architect", ["a", "b"], total=5)
    assert "2" in c and "5" in c and "threat" in c.lower()
    c2 = synthesize_claim("skeptic", ["a"], total=5)
    assert "benign" in c2.lower()


def test_compile_tactics_script_full_shape():
    s = compile_tactics_script("INJ-020")
    assert s["scenario_id"] == "INJ-020"
    assert s["facts"]
    assert s["conditions"] and s["conditions"][0]["name"] == "baseline"
    cond = s["conditions"][0]
    assert "claim" in cond["architect"] and "claim" in cond["skeptic"]
    assert cond["oracle"]["verdict"] in {"threat_confirmed", "threat_dismissed", "inconclusive"}
    validate_provenance(s)  # must not raise
    assert s["provenance"]["source_run"] == SOURCE_RUN
    assert s["provenance"]["trace_sha256"]


def test_emit_writes_valid_json(tmp_path):
    out = emit_tactics_script("INJ-020", out_dir=str(tmp_path))
    data = _json.loads(open(out, encoding="utf-8").read())
    assert data["scenario_id"] == "INJ-020"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/demo/test_tactics_script_compiler.py -q`
Expected: FAIL (`cannot import name 'synthesize_claim'`).

- [ ] **Step 3: Write minimal implementation**

```python
# add to demo/tactics_script_compiler.py
import hashlib
import subprocess

_NAME = {"architect": "Architect", "skeptic": "Skeptic"}
_STANCE = {"architect": "threat", "skeptic": "benign"}


def synthesize_claim(actor: str, cited: list, total: int) -> str:
    """Deterministic, provenanced claim string (NOT a model quote)."""
    return f"{_NAME[actor]} cites {len(cited)} of {total} facts — {_STANCE[actor]}."


def _git_sha() -> str:
    try:
        out = subprocess.run(["git", "rev-parse", "--short", "HEAD"],
                             capture_output=True, text=True, check=True)
        return out.stdout.strip()
    except Exception:
        return "unknown"


def _trace_sha256(traces_path: str) -> str:
    return hashlib.sha256(Path(traces_path).read_bytes()).hexdigest()


def compile_tactics_script(scenario_id: str,
                           traces_path: str = DEFAULT_TRACES_PATH,
                           compiled_at: str | None = None) -> dict:
    if compiled_at is None:
        from datetime import datetime, timezone
        compiled_at = datetime.now(timezone.utc).isoformat()
    recs = load_scenario_traces(scenario_id, traces_path)
    if not recs:
        raise LookupError(f"no traces for {scenario_id}")
    facts = resolve_facts(scenario_id, traces_path)
    total = len(facts)
    conditions = []
    for cond in conditions_in(recs):
        summ = condition_summary(recs, cond)
        summ["name"] = cond
        summ["architect"]["claim"] = synthesize_claim(
            "architect", summ["architect"]["cited_fact_ids"], total)
        summ["skeptic"]["claim"] = synthesize_claim(
            "skeptic", summ["skeptic"]["cited_fact_ids"], total)
        conditions.append(summ)
    return {
        "scenario_id": scenario_id,
        "title_label": scenario_id,  # human title optional; scenario_id is the stable label
        "facts": facts,
        "conditions": conditions,
        "provenance": {
            "source_run": SOURCE_RUN,
            "trace_sha256": _trace_sha256(traces_path),
            "git_sha": _git_sha(),
            "compiler_version": COMPILER_VERSION,
            "compiled_at": compiled_at,
        },
    }


def validate_provenance(script: dict) -> None:
    prov = script.get("provenance") or {}
    if not prov.get("source_run") or not prov.get("trace_sha256"):
        raise ValueError("tactics-script missing provenance (source_run + trace_sha256)")


def emit_tactics_script(scenario_id: str, out_dir: str = DEFAULT_OUT_DIR,
                        traces_path: str = DEFAULT_TRACES_PATH,
                        compiled_at: str | None = None) -> str:
    script = compile_tactics_script(scenario_id, traces_path, compiled_at)
    validate_provenance(script)
    out = Path(out_dir) / f"{scenario_id.lower()}.tactics.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(script, indent=2) + "\n", encoding="utf-8")
    return str(out)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/demo/test_tactics_script_compiler.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add demo/tactics_script_compiler.py tests/demo/test_tactics_script_compiler.py
git commit -m "feat(ares-tactics): synthesized claims + script assembly + provenance + emit"
```

---

### Task 5: CLI + emit all 17 scenarios + the fork fixture

**Files:** Modify `demo/tactics_script_compiler.py`; Test same.

- [ ] **Step 1: Write the failing test**

```python
# append to tests/demo/test_tactics_script_compiler.py
from demo.tactics_script_compiler import main, emit_all


def test_emit_all_writes_one_file_per_scenario(tmp_path):
    paths = emit_all(out_dir=str(tmp_path))
    assert len(paths) >= 15
    assert all(p.endswith(".tactics.json") for p in paths)


def test_cli_emit_single(tmp_path):
    rc = main(["--scenario", "INJ-020", "--out-dir", str(tmp_path)])
    assert rc == 0
    assert (tmp_path / "inj-020.tactics.json").exists()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/demo/test_tactics_script_compiler.py -q`
Expected: FAIL (`cannot import name 'emit_all'`).

- [ ] **Step 3: Write minimal implementation**

```python
# add to demo/tactics_script_compiler.py
import argparse


def emit_all(out_dir: str = DEFAULT_OUT_DIR,
             traces_path: str = DEFAULT_TRACES_PATH) -> list[str]:
    return [emit_tactics_script(sid, out_dir, traces_path)
            for sid in scenarios_in_run(traces_path)]


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Compile ARES tactics-scripts from S084 traces.")
    p.add_argument("--scenario", default=None, help="one scenario id, or all if omitted")
    p.add_argument("--out-dir", default=DEFAULT_OUT_DIR)
    p.add_argument("--traces", default=DEFAULT_TRACES_PATH)
    args = p.parse_args(argv)
    if args.scenario:
        path = emit_tactics_script(args.scenario, args.out_dir, args.traces)
        print(f"wrote {path}")
    else:
        for path in emit_all(args.out_dir, args.traces):
            print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/demo/test_tactics_script_compiler.py -q`
Expected: PASS (full Phase-1 suite). Then regression: `python -m pytest tests/demo/ -q` → all pass.

- [ ] **Step 5: Emit the real scripts + generate the fork fixture**

```bash
python -m demo.tactics_script_compiler            # writes demo/out/*.tactics.json
```
Expected: 17 files. The fork fixture is generated in Phase 2 Task 7 from `inj-020.tactics.json`.

- [ ] **Step 6: Commit**

```bash
git add demo/tactics_script_compiler.py tests/demo/test_tactics_script_compiler.py
git commit -m "feat(ares-tactics): CLI + emit-all (17 scenarios)"
```

**Phase 1 gate:** `python -m pytest tests/demo/ -q` green; `demo/out/*.tactics.json` produced; provenance present in every file.

---

# PHASE 2 — Fork the engine + scene + loader + static render (`C:\glassbox\arestactics`)

A fresh fork of `C:\glassbox\tacticsclone`. `C:\glassbox\glassbox` and `C:\glassbox\arena` are untouched. All Phase 2-4 commands run from `C:\glassbox\arestactics`. Use the **Bash tool** with plain quoting for commits.

**Files (Phase 2):** fork scaffold; `src/ares/{tacticsScript.ts, sceneBuilder.ts}`; `tests/{tacticsScript,sceneBuilder}.test.ts`; `tests/fixtures/inj-020.tactics.json`; a render harness.

---

### Task 6: Fork tacticsclone → arestactics, prune to the render core

**Files:** the new repo at `C:\glassbox\arestactics`.

- [ ] **Step 1: Copy the engine (excluding .git, node_modules, build output)**

```bash
mkdir -p /c/glassbox/arestactics
cd /c/glassbox/tacticsclone && \
  cp -r src public index.html package.json tsconfig.json vite.config.ts /c/glassbox/arestactics/ 2>/dev/null
cd /c/glassbox/arestactics && git init
```
(If `vite.config.ts` is absent, create it: `import {defineConfig} from 'vite'; import react from '@vitejs/plugin-react'; export default defineConfig({plugins:[react()], server:{port: Number(process.env.PORT)||5300}});`. If the source has no React plugin because it's vanilla TS, keep the existing setup and mount via the existing entry; adapt the screen in Task 11 accordingly.)

- [ ] **Step 2: Add test tooling to `package.json`**

Ensure `devDependencies` include `vitest@^4.1.8`, `@playwright/test@^1.60.0`, `@vitejs/plugin-react@^4.3.4` (if React), `typescript@^5.7.2`, `vite@^6.0.5`. Add scripts: `"test": "vitest run"`, `"test:e2e": "playwright test"`, `"dev": "vite"`, `"build": "tsc -b && vite build"`. Write `vitest.config.ts`: `import {defineConfig} from 'vitest/config'; export default defineConfig({test:{environment:'node', include:['tests/**/*.test.ts']}});`. Write `playwright.config.ts` mirroring `C:\glassbox\arena\playwright.config.ts` but port `5301`.

- [ ] **Step 3: Prune combat/game-only modules**

Delete (the behavior viz does not use them): `src/systems/{combat,turnorder}.ts`, `src/ai/`, `src/data/{jobs,abilities,items}.ts`, and any deploy/shop/campaign/party screen components. **Keep:** `src/entities/types.ts`, `src/render/{renderer,anim,assets}.ts`, `src/systems/{battle,grid}.ts`, `src/utils/rng.ts`, `public/assets/`. If a kept file imports a deleted one, stub or trim the import (note each in the commit). Verify the kept renderer still type-checks.

- [ ] **Step 4: Install + verify the engine builds**

```bash
cd /c/glassbox/arestactics && npm install && npm run build 2>&1 | tail -5
```
Expected: `tsc` + `vite build` succeed (after Step 3's import trims). If `tsc` errors on a deleted import, trim that import and re-run. Do NOT start the dev server yet.

- [ ] **Step 5: `.gitignore` + commit**

```bash
cd /c/glassbox/arestactics && printf 'node_modules\ndist\ntest-results\nplaywright-report\n.vite\n*.tsbuildinfo\n' > .gitignore
git add -A && git commit -m "chore(arestactics): fork Emberveil Tactics, prune to render core"
```

---

### Task 7: tactics-script contract types + parser (vitest)

**Files:** Create `src/ares/tacticsScript.ts`, `tests/tacticsScript.test.ts`, `tests/fixtures/inj-020.tactics.json`.

- [ ] **Step 1: Generate the fixture from the real compiler**

```bash
cd /c/ares-phase-zero && python -c "import json; from demo.tactics_script_compiler import compile_tactics_script; print(json.dumps(compile_tactics_script('INJ-020'), indent=2))" > /c/glassbox/arestactics/tests/fixtures/inj-020.tactics.json
```
Sanity: `python -c "import json; d=json.load(open('/c/glassbox/arestactics/tests/fixtures/inj-020.tactics.json')); print(d['scenario_id'], [c['name'] for c in d['conditions']])"` → `INJ-020 ['baseline', ...]`.

- [ ] **Step 2: Write the failing test**

```ts
// tests/tacticsScript.test.ts
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { parseTacticsScript } from '../src/ares/tacticsScript';

const raw = JSON.parse(readFileSync(new URL('./fixtures/inj-020.tactics.json', import.meta.url), 'utf-8'));

describe('parseTacticsScript', () => {
  it('parses facts + conditions', () => {
    const s = parseTacticsScript(raw);
    expect(s.scenarioId).toBe('INJ-020');
    expect(s.facts.length).toBeGreaterThan(0);
    expect(s.conditions[0].name).toBe('baseline');
  });
  it('exposes per-agent cited facts + confidence + claim', () => {
    const c = parseTacticsScript(raw).conditions[0];
    expect(Array.isArray(c.architect.citedFactIds)).toBe(true);
    expect(typeof c.architect.confidence).toBe('number');
    expect(c.architect.claim.length).toBeGreaterThan(0);
    expect(['threat_confirmed', 'threat_dismissed', 'inconclusive']).toContain(c.oracle.verdict);
  });
  it('rejects a script without provenance', () => {
    expect(() => parseTacticsScript({ ...raw, provenance: {} })).toThrow(/provenance/i);
  });
});
```

- [ ] **Step 3: Run test → FAIL**, then implement:

```ts
// src/ares/tacticsScript.ts
export type Verdict = 'threat_confirmed' | 'threat_dismissed' | 'inconclusive';
export interface TFact { factId: string; field: string; displayLabel: string; sourceType: string; isThreatDominant: boolean; }
export interface AgentMove { citedFactIds: string[]; confidence: number; claim: string; }
export interface OracleMove { verdict: Verdict; supportingFactIds: string[]; }
export interface Condition { name: string; architect: AgentMove; skeptic: AgentMove; oracle: OracleMove; }
export interface TacticsScript { scenarioId: string; titleLabel: string; facts: TFact[]; conditions: Condition[]; }

export function parseTacticsScript(raw: any): TacticsScript {
  if (!raw?.provenance?.source_run || !raw?.provenance?.trace_sha256) {
    throw new Error('tactics-script missing provenance');
  }
  const agent = (a: any): AgentMove => ({
    citedFactIds: a.cited_fact_ids ?? [], confidence: a.confidence ?? 0, claim: a.claim ?? '',
  });
  return {
    scenarioId: raw.scenario_id,
    titleLabel: raw.title_label ?? raw.scenario_id,
    facts: (raw.facts ?? []).map((f: any) => ({
      factId: f.fact_id, field: f.field, displayLabel: f.display_label,
      sourceType: f.source_type, isThreatDominant: !!f.is_threat_dominant,
    })),
    conditions: (raw.conditions ?? []).map((c: any) => ({
      name: c.name, architect: agent(c.architect), skeptic: agent(c.skeptic),
      oracle: { verdict: c.oracle.verdict, supportingFactIds: c.oracle.supporting_fact_ids ?? [] },
    })),
  };
}

export async function loadTacticsScript(url: string): Promise<TacticsScript> {
  const res = await fetch(url);
  return parseTacticsScript(await res.json());
}
```

- [ ] **Step 4: Run `npm run test` → PASS. Step 5: commit** (`feat(arestactics): tactics-script contract + parser + real fixture`).

---

### Task 8: Scene-builder — script → BattleState (3 agents + fact tiles on a paper board)

**Files:** Create `src/ares/sceneBuilder.ts`, `tests/sceneBuilder.test.ts`.

This maps the script onto the engine's `BattleState` (`src/entities/types.ts`): a small board, the 3 agent `Unit`s (Architect/Skeptic/Oracle), and one tile per fact.

- [ ] **Step 1: Write the failing test**

```ts
// tests/sceneBuilder.test.ts
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { parseTacticsScript } from '../src/ares/tacticsScript';
import { buildScene, AGENTS } from '../src/ares/sceneBuilder';

const script = parseTacticsScript(JSON.parse(
  readFileSync(new URL('./fixtures/inj-020.tactics.json', import.meta.url), 'utf-8')));

describe('buildScene', () => {
  it('places the three agents', () => {
    const scene = buildScene(script);
    const ids = scene.units.map(u => u.id);
    expect(ids).toEqual(expect.arrayContaining(['architect', 'skeptic', 'oracle']));
  });
  it('maps the cast to the right hero jobs', () => {
    const scene = buildScene(script);
    const byId = Object.fromEntries(scene.units.map(u => [u.id, u]));
    expect(byId['architect'].job).toBe(AGENTS.architect.job);   // embercaller
    expect(byId['skeptic'].job).toBe(AGENTS.skeptic.job);       // bulwark
    expect(byId['oracle'].job).toBe(AGENTS.oracle.job);         // dawnmender
  });
  it('creates a fact-tile position per fact', () => {
    const scene = buildScene(script);
    expect(scene.factTiles.length).toBe(script.facts.length);
    expect(scene.factTiles[0]).toHaveProperty('factId');
    expect(scene.factTiles[0]).toHaveProperty('x');
    expect(scene.factTiles[0]).toHaveProperty('y');
  });
  it('board is large enough for facts + agents', () => {
    const scene = buildScene(script);
    expect(scene.w).toBeGreaterThanOrEqual(5);
    expect(scene.h).toBeGreaterThanOrEqual(5);
  });
});
```

- [ ] **Step 2: Run → FAIL**, then implement (adapt the `Unit`/`Tile`/`BattleState` field names to the real `src/entities/types.ts` — the builder must read that file first and match it exactly):

```ts
// src/ares/sceneBuilder.ts
import type { TacticsScript } from './tacticsScript';
// NOTE: import the real types from the forked engine:
import type { BattleState, Unit, Tile } from '../entities/types';

export const AGENTS = {
  architect: { id: 'architect', job: 'embercaller', team: 'enemy' as const,  pos: { x: 1, y: 3 } },
  skeptic:   { id: 'skeptic',   job: 'bulwark',     team: 'player' as const, pos: { x: 7, y: 3 } },
  oracle:    { id: 'oracle',    job: 'dawnmender',  team: 'guest' as const,  pos: { x: 4, y: 0 } },
};

export interface FactTile { factId: string; x: number; y: number; isThreatDominant: boolean; label: string; }
export interface AresScene extends BattleState { factTiles: FactTile[]; }

export function buildScene(script: TacticsScript): AresScene {
  const W = 9, H = 7;
  // Flat grass board (terrain string must match the engine's TerrainType).
  const tiles: Tile[][] = [];
  for (let y = 0; y < H; y++) {
    const row: Tile[] = [];
    for (let x = 0; x < W; x++) row.push({ x, y, h: 0, terrain: 'grass', impassable: false } as Tile);
    tiles.push(row);
  }
  // Fact tiles in a centered cluster (a 2-row band the agents move between).
  const factTiles: FactTile[] = script.facts.map((f, i) => ({
    factId: f.factId, x: 2 + (i % 5), y: 2 + Math.floor(i / 5),
    isThreatDominant: f.isThreatDominant, label: `${f.field}: ${f.displayLabel}`,
  }));
  const units: Unit[] = Object.values(AGENTS).map(a => ({
    id: a.id, job: a.job as any, team: a.team, facing: 'S',
    x: a.pos.x, y: a.pos.y,
  } as Unit));
  return { tiles, w: W, h: H, units, phase: 'combat' as any, factTiles };
}
```

(The builder MUST read `src/entities/types.ts` and set whatever required `Unit`/`Tile`/`BattleState` fields the engine demands — `hp`, `stats`, etc. — with inert defaults so the renderer accepts them. If `team` colors are player=blue/enemy=red/guest=green, Architect=enemy(red) reads as the "accuser," Skeptic=player(blue) as defender, Oracle=guest(green) as neutral judge — adjust to taste during the Task 11 visual sign-off.)

- [ ] **Step 3: Run `npm run test` → PASS. Step 4: commit** (`feat(arestactics): scene-builder maps script to a tactics board`).

---

### Task 9: Static render harness + first visual sign-off

**Files:** Create `src/ares/AresTacticsScreen.tsx` (static first), `src/main.tsx`/entry wiring, `e2e/arestactics.spec.ts`.

- [ ] **Step 1:** Write a minimal `AresTacticsScreen` that: fetches `/inj-020.tactics.json` (copy `demo/out/inj-020.tactics.json` to `public/`), parses it, `buildScene`, constructs the engine `Renderer` (from `src/render/renderer.ts`), and draws the scene **statically** (no animation yet) — agents on the board, fact tiles labeled. Mirror `C:\glassbox\glassbox\src\glassbox\GlassBoxScreen.tsx` for the canvas + rAF + `?autoplay` plumbing, but call the engine `Renderer.draw(scene)` instead of the tribunal renderer. Add `data-phase="static"` on the root for E2E.

- [ ] **Step 2:** Copy the fixture to public: `cp demo/out/inj-020.tactics.json /c/glassbox/arestactics/public/` (from ARES repo) — or regenerate via the compiler.

- [ ] **Step 3:** Playwright E2E (stubbed fetch with the fixture, like `C:\glassbox\arena\e2e\arena.spec.ts`): assert the canvas mounts and `data-phase` is present; screenshot `test-results/arestactics-static.png`.

```bash
cd /c/glassbox/arestactics && npx playwright install chromium && npm run test:e2e
```

- [ ] **Step 4 — VISUAL SIGN-OFF (controller gate):** run the dev server + the (already-built) static page; screenshot via Playwright at `?autoplay=0`. **Confirm:** the three hero sprites render on the paper board (embercaller / bulwark / dawnmender), the fact tiles are placed and legible, the board fits everything. This is where board scale (spec §11) is validated. Adjust `buildScene` board size / tile layout if cramped. Not automated — a human/controller sign-off.

- [ ] **Step 5: commit** (`feat(arestactics): static scene render + first visual sign-off`).

**Phase 2 gate:** `npm run test` + `npm run test:e2e` green; the real hero-agents + fact tiles render on the board (visual sign-off).

---

# PHASE 3 — Choreography + chat bubbles + the drift twist

**Files (Phase 3):** `src/ares/{aresTacticsPlayer.ts, actionMapper.ts, chatBubble.ts}`; tests; extend `AresTacticsScreen.tsx`.

---

### Task 10: Beat-player (the 5-beat stepper, vitest)

**Files:** Create `src/ares/aresTacticsPlayer.ts`, `tests/aresTacticsPlayer.test.ts`.

Beats per condition: `setup → architect → skeptic → oracle`. Across conditions: baseline first, then each framing condition is its own "round" (the drift twist = stepping into the next condition and replaying). Reuse the first-tick-baseline discipline from `C:\glassbox\glassbox\src\glassbox\beatPlayer.ts`.

- [ ] **Step 1: Write the failing test**

```ts
// tests/aresTacticsPlayer.test.ts
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { parseTacticsScript } from '../src/ares/tacticsScript';
import { AresTacticsPlayer } from '../src/ares/aresTacticsPlayer';

const script = parseTacticsScript(JSON.parse(
  readFileSync(new URL('./fixtures/inj-020.tactics.json', import.meta.url), 'utf-8')));

describe('AresTacticsPlayer', () => {
  it('starts on the baseline setup beat', () => {
    const p = new AresTacticsPlayer(script, { dwellMs: 1500 });
    const s = p.snapshot();
    expect(s.conditionName).toBe('baseline');
    expect(s.beat).toBe('setup');
  });
  it('steps setup -> architect -> skeptic -> oracle within a condition', () => {
    const p = new AresTacticsPlayer(script, { dwellMs: 1500 });
    const seen = [p.snapshot().beat];
    for (let i = 0; i < 3; i++) { p.step(); seen.push(p.snapshot().beat); }
    expect(seen).toEqual(['setup', 'architect', 'skeptic', 'oracle']);
  });
  it('after oracle, rolls into the next condition (the drift)', () => {
    const p = new AresTacticsPlayer(script, { dwellMs: 1500 });
    for (let i = 0; i < 4; i++) p.step(); // into next condition's setup (if >1 condition)
    if (script.conditions.length > 1) {
      expect(p.snapshot().conditionName).toBe(script.conditions[1].name);
      expect(p.snapshot().beat).toBe('setup');
    } else {
      expect(p.snapshot().done).toBe(true);
    }
  });
  it('first tick baselines (no opening-beat skip)', () => {
    const p = new AresTacticsPlayer(script, { dwellMs: 1500 });
    p.play(); p.tick(10_000); expect(p.snapshot().beat).toBe('setup');
    p.tick(11_501); expect(p.snapshot().beat).toBe('architect');
  });
});
```

- [ ] **Step 2: Run → FAIL**, then implement:

```ts
// src/ares/aresTacticsPlayer.ts
import type { TacticsScript, Condition } from './tacticsScript';

export type Beat = 'setup' | 'architect' | 'skeptic' | 'oracle';
const BEATS: Beat[] = ['setup', 'architect', 'skeptic', 'oracle'];

export interface TacticsSnapshot {
  conditionIndex: number; conditionName: string; condition: Condition;
  beatIndex: number; beat: Beat;
  architectRevealed: boolean; skepticRevealed: boolean; verdictRevealed: boolean;
  playing: boolean; done: boolean;
}

export class AresTacticsPlayer {
  private ci = 0; private bi = 0;
  private playing = false; private lastAdvance: number | null = null; private done = false;
  constructor(private script: TacticsScript, private opts: { dwellMs: number }) {}

  play() { if (this.done) return; this.playing = true; this.lastAdvance = null; }
  pause() { this.playing = false; }
  reset() { this.ci = 0; this.bi = 0; this.done = false; this.playing = false; this.lastAdvance = null; }

  step() {
    if (this.done) return;
    if (this.bi < BEATS.length - 1) { this.bi += 1; return; }
    if (this.ci < this.script.conditions.length - 1) { this.ci += 1; this.bi = 0; }
    else { this.done = true; this.playing = false; }
  }

  tick(nowMs: number) {
    if (!this.playing || this.done) return;
    if (this.lastAdvance === null) { this.lastAdvance = nowMs; return; }
    if (nowMs - this.lastAdvance >= this.opts.dwellMs) { this.step(); this.lastAdvance = nowMs; }
  }

  snapshot(): TacticsSnapshot {
    const condition = this.script.conditions[this.ci];
    return {
      conditionIndex: this.ci, conditionName: condition.name, condition,
      beatIndex: this.bi, beat: BEATS[this.bi],
      architectRevealed: this.bi >= 1, skepticRevealed: this.bi >= 2, verdictRevealed: this.bi >= 3,
      playing: this.playing, done: this.done,
    };
  }
}
```

- [ ] **Step 3: Run `npm run test` → PASS. Step 4: commit** (`feat(arestactics): 5-beat tactics player with cross-condition drift`).

---

### Task 11: Action-mapper — beat → AnimHooks intents (vitest, pure)

**Files:** Create `src/ares/actionMapper.ts`, `tests/actionMapper.test.ts`.

Pure function: `(snapshot, scene) → AresAction[]` describing what the renderer should animate, WITHOUT touching the canvas (so it's unit-testable). The screen executes these via the engine `AnimHooks` (`src/systems/battle.ts`) in Task 12.

- [ ] **Step 1: Write the failing test**

```ts
// tests/actionMapper.test.ts
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { parseTacticsScript } from '../src/ares/tacticsScript';
import { buildScene } from '../src/ares/sceneBuilder';
import { AresTacticsPlayer } from '../src/ares/aresTacticsPlayer';
import { mapBeat } from '../src/ares/actionMapper';

const script = parseTacticsScript(JSON.parse(
  readFileSync(new URL('./fixtures/inj-020.tactics.json', import.meta.url), 'utf-8')));
const scene = buildScene(script);

describe('mapBeat', () => {
  it('architect beat: move to its cited tiles + cast pose + bubble', () => {
    const p = new AresTacticsPlayer(script, { dwellMs: 1 }); p.step(); // architect
    const actions = mapBeat(p.snapshot(), scene);
    expect(actions.some(a => a.kind === 'move' && a.unitId === 'architect')).toBe(true);
    expect(actions.some(a => a.kind === 'pose' && a.unitId === 'architect' && a.pose === 'cast')).toBe(true);
    expect(actions.some(a => a.kind === 'bubble' && a.unitId === 'architect')).toBe(true);
  });
  it('oracle beat: banner with the verdict', () => {
    const p = new AresTacticsPlayer(script, { dwellMs: 1 }); p.step(); p.step(); p.step(); // oracle
    const actions = mapBeat(p.snapshot(), scene);
    expect(actions.some(a => a.kind === 'banner')).toBe(true);
  });
  it('highlights the cited fact tiles', () => {
    const p = new AresTacticsPlayer(script, { dwellMs: 1 }); p.step(); // architect
    const actions = mapBeat(p.snapshot(), scene);
    expect(actions.some(a => a.kind === 'highlightTiles')).toBe(true);
  });
});
```

- [ ] **Step 2: Run → FAIL**, then implement:

```ts
// src/ares/actionMapper.ts
import type { TacticsSnapshot } from './aresTacticsPlayer';
import type { AresScene } from './sceneBuilder';

export type AresAction =
  | { kind: 'move'; unitId: string; to: { x: number; y: number } }
  | { kind: 'pose'; unitId: string; pose: 'idle' | 'walk' | 'attack' | 'cast' | 'ko' }
  | { kind: 'highlightTiles'; factIds: string[]; color: 'threat' | 'benign' | 'verdict' }
  | { kind: 'bubble'; unitId: string; text: string }
  | { kind: 'banner'; text: string };

function tileFor(scene: AresScene, factIds: string[]) {
  const t = scene.factTiles.find(ft => factIds.includes(ft.factId));
  return t ? { x: t.x, y: t.y } : { x: Math.floor(scene.w / 2), y: Math.floor(scene.h / 2) };
}

export function mapBeat(s: TacticsSnapshot, scene: AresScene): AresAction[] {
  const c = s.condition;
  if (s.beat === 'architect') {
    return [
      { kind: 'move', unitId: 'architect', to: tileFor(scene, c.architect.citedFactIds) },
      { kind: 'pose', unitId: 'architect', pose: 'cast' },
      { kind: 'highlightTiles', factIds: c.architect.citedFactIds, color: 'threat' },
      { kind: 'bubble', unitId: 'architect', text: `${c.architect.claim} (conf ${c.architect.confidence})` },
    ];
  }
  if (s.beat === 'skeptic') {
    return [
      { kind: 'move', unitId: 'skeptic', to: tileFor(scene, c.skeptic.citedFactIds) },
      { kind: 'pose', unitId: 'skeptic', pose: 'attack' },
      { kind: 'highlightTiles', factIds: c.skeptic.citedFactIds, color: 'benign' },
      { kind: 'bubble', unitId: 'skeptic', text: `${c.skeptic.claim} (conf ${c.skeptic.confidence})` },
    ];
  }
  if (s.beat === 'oracle') {
    return [
      { kind: 'highlightTiles', factIds: c.oracle.supportingFactIds, color: 'verdict' },
      { kind: 'banner', text: c.oracle.verdict.replace(/_/g, ' ').toUpperCase() },
    ];
  }
  return []; // setup: nothing to animate
}
```

- [ ] **Step 3: Run `npm run test` → PASS. Step 4: commit** (`feat(arestactics): action-mapper (beat → animated intents)`).

---

### Task 12: Chat-bubble layer + wire the player + AnimHooks (Playwright + visual)

**Files:** Create `src/ares/chatBubble.ts`; extend `src/ares/AresTacticsScreen.tsx`; extend `e2e/arestactics.spec.ts`.

- [ ] **Step 1: Chat-bubble renderer.** Read `src/render/anim.ts` (the `FloatText` system) and add a sibling `ChatBubble` overlay: a rounded speech-bubble with a tail, anchored over a unit's screen position (use the engine's `isoOf` + camera to get the unit's screen xy), long dwell (until the next beat), word-wrapped. Provide `drawBubbles(ctx, bubbles, camera)` callable from the renderer's `onChange` draw.
- [ ] **Step 2: Wire `AresTacticsScreen`.** Construct `makeAnimHooks` from the engine (`src/render/anim.ts`) bound to the engine `Renderer`. On each player beat, run `mapBeat(snapshot, scene)` and execute the actions through `AnimHooks`: `move` → `unitWalk(unit, pathTo(...))` (use `src/systems/grid.ts` `reachableTiles`/`pathTo`); `pose` → `castFlash`/lunge as appropriate; `highlightTiles` → renderer tile tint; `bubble` → push a `ChatBubble`; `banner` → `AnimHooks.banner`. Keep the rAF loop + `?autoplay=0`/`?dwell`/Space/→ presenter controls (mirror `GlassBoxScreen.tsx`). Set `data-phase` from `snapshot().beat` and `data-condition` from `snapshot().conditionName` for E2E.
- [ ] **Step 3: E2E (stubbed fetch).** Step through baseline beats; assert `data-phase` reaches `oracle`; step into the next condition; assert `data-condition` changes (the drift). Screenshot `test-results/arestactics-oracle.png`. Run `npm run test:e2e`.
- [ ] **Step 4 — VISUAL SIGN-OFF (controller, real script):** dev server + `?autoplay=0`; step through baseline → the Architect (embercaller) walks to its cited tiles and casts, bubble shows the threat claim; Skeptic (bulwark) moves + defends; Oracle (dawnmender) banner verdict; then step into the framing condition and confirm the **cited tiles visibly drift** while the verdict banner holds. Screenshot each beat. Adjust poses/bubble placement/timing.
- [ ] **Step 5: commit** (`feat(arestactics): chat bubbles + animated choreography + drift twist`).

**Phase 3 gate:** the agents animate their decisions; the drift twist reads; E2E green + visual sign-off.

---

# PHASE 4 — Polish + presenter controls + handoff

### Task 13: Scenario + condition selectors + presenter controls
- [ ] Add a scenario picker (the 17 compiled scripts; copy all `demo/out/*.tactics.json` into `public/`) + a condition stepper. Confirm `?autoplay`/`?dwell`/`?scenario` params + Space/→/C keys. E2E for the picker. Commit.

### Task 14: Papercraft polish + closing tie-in
- [ ] Polish: bubble styling (paper speech-bubbles), tile tints (threat-red / benign-blue / verdict-gold), camera framing, easing. Add a closing card tying the three demos together (Glass Box = recorded drift, Firewall Arena = live catch, ARES Tactics = the agents arguing). Visual sign-off. Commit.

### Task 15: Final verification + ARES floor/ledger + reviews
- [ ] `cd /c/glassbox/arestactics && npm run test && npm run build && npm run test:e2e` all green. `cd /c/ares-phase-zero && python -m pytest tests/demo/ -q` green; update CLAUDE.md test floor (count `tests/ + ares/dialectic/tests/` via `--collect-only`) + add a Key Code Locations entry + ledger note for ARES Tactics. Final code review of both halves. Commit.

### Task 16 (separate, later): targeted real-prose run
- [ ] Once the script contract is locked + the viz proven, design + run ONE small (~\$3-8) measurement that persists the agents' actual per-beat messages for a curated scenario set; extend the compiler to fill `architect.claim`/`skeptic.claim` from real prose (keep synthesized fallback). This is a deliberate, logged measurement — not part of v1.

---

## Self-Review (against the spec)

- **§1/§6 thesis + beat loop** → Phase 3 Tasks 10-12 (player + action-mapper + drift). ✓
- **§4 cast (embercaller/bulwark/dawnmender)** → Task 8 `AGENTS`. ✓
- **§5 data spine S084 + "all data" scoping** → Phase 1 compiler reads S084; secondary runs deferred (Task 16 + spec note). ✓
- **§5 synthesized vs real-prose bubbles** → Task 4 `synthesize_claim` (v1) + Task 16 (later real run). ✓
- **§7 two-halves + JSON contract** → Phase 1 (compiler) + Phase 2 Task 7 (parser). ✓
- **§8 component boundaries** → one module per Task (compiler, parser, scene-builder, player, action-mapper, chat-bubble), each unit-tested in isolation. ✓
- **§9 out of scope (no combat/monsters/live-LLM)** → Task 6 prunes combat; no monster assets; replay only. ✓
- **§11 board-scale risk** → Task 9 Step 4 visual sign-off. ✓

**Placeholder scan:** the Phase 2-4 canvas/animation tasks intentionally reference the real engine files (`types.ts`, `anim.ts`, `renderer.ts`, `grid.ts`) the builder must read and match, rather than re-pasting the engine — the NEW code (compiler, parser, scene-builder, player, action-mapper) has complete code. The builder MUST read `src/entities/types.ts` before Task 8 and `src/render/anim.ts` before Task 12 to match exact field/function names (flagged inline).

**Type consistency:** `TacticsScript`/`Condition`/`AgentMove`/`TacticsSnapshot`/`AresScene`/`AresAction` names are consistent across Tasks 7-12. Compiler JSON keys (snake_case) → parser camelCase mapping locked in Task 7.

---

## Execution Handoff

Per Dan's instruction ("build me a plan and then crystalize to start fresh"), **the build is a fresh next session** — do not execute now. When that session starts (booted from the crystal), the recommended path is **subagent-driven development** (fresh subagent per task, two-stage review), the same pattern that shipped Glass Box and Firewall Arena. Phase 1 (the compiler) is the natural starting point; Phase 2 forks the engine.
