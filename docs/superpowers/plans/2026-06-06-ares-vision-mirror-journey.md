# ARES-VISION "The Mirror" Journey — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a public-facing, scroll-driven hero page ("The Mirror") for ARES-VISION, centered on the S084 INJ-020 dual-agent finding (Architect collapses / Skeptic expands / verdict unchanged), fed by a new deterministic ARES data adapter.

**Architecture:** Two parts joined by one JSON file. **Part A (ARES repo, `C:\ares-phase-zero`):** a new peer module under `ares/dialectic/visualization/` reads the S084 `traces.jsonl`, recomputes the INJ-020 hero data, and emits `docs/marketing/mirror-journey.json`. **Part B (skyframe-main, `E:\Skyframe Innovations Website\skyframe-main`):** a standalone `assets/ares/mirror.html` (+ css/js) fetches that JSON and renders the 5-scene scroll via vanilla IntersectionObserver. Prism is untouched; the CTA links to it.

**Tech Stack:** Python 3.11 (frozen dataclasses, stdlib `json`, pytest); vanilla HTML/CSS/JS (no framework, no Three.js, IntersectionObserver for scroll).

**Spec:** `docs/superpowers/specs/2026-06-06-ares-vision-mirror-journey-design.md`
**Source data:** `data/paper_3/leakage_runs/20260605-194137-713674/traces.jsonl` (run `20260605-194137-713674`)
**Hero prototype (styling reference, validated live):** `.superpowers/brainstorm/ares-vision/content/mirror-A-live.html`

---

## File Structure

**Part A — ARES (`C:\ares-phase-zero`)**
- Create `ares/dialectic/visualization/mirror_journey_schema.py` — frozen dataclasses (`AgentFraming`, `Hero`, `Landscape`, `MirrorJourney`) + `mirror_journey_to_json`.
- Create `ares/dialectic/visualization/mirror_journey_builder.py` — parse S084 traces, modal fact-set extraction, jaccard, assemble `MirrorJourney`.
- Create `ares/dialectic/visualization/build_mirror_journey.py` — argparse CLI.
- Create `ares/dialectic/tests/visualization/test_mirror_journey_schema.py` — dataclass + serialization unit tests.
- Create `ares/dialectic/tests/visualization/test_mirror_journey_builder.py` — builder logic on a synthetic fixture.
- Create `ares/dialectic/tests/visualization/test_mirror_journey_json_contract.py` — pins the real numbers in the emitted artifact (deploy guard).
- Generated artifact: `docs/marketing/mirror-journey.json`.

**Part B — skyframe-main (`E:\Skyframe Innovations Website\skyframe-main`)**
- Create `assets/ares/mirror.html` — page shell, 5 `<section>` scenes.
- Create `assets/ares/mirror.css` — house style + hero animation + scroll-reveal.
- Create `assets/ares/mirror.js` — fetch JSON, build hero, IntersectionObserver activation.
- Create `assets/ares/mirror-journey.json` — deployed copy of the ARES artifact.
- Modify `ares.html` — add one hero link → `assets/ares/mirror.html`.

---

# PART A — ARES data adapter (strict TDD)

### Task 1: Schema dataclasses + serialization

**Files:**
- Create: `ares/dialectic/visualization/mirror_journey_schema.py`
- Test: `ares/dialectic/tests/visualization/test_mirror_journey_schema.py`

- [ ] **Step 1: Write the failing test**

```python
# ares/dialectic/tests/visualization/test_mirror_journey_schema.py
from __future__ import annotations

import json

import pytest

from ares.dialectic.visualization.mirror_journey_schema import (
    AgentFraming,
    Hero,
    Landscape,
    MirrorJourney,
    mirror_journey_to_json,
)


def _agent(agent="architect", direction="collapse"):
    return AgentFraming(
        agent=agent,
        baseline_facts=("inj020-fact-001", "inj020-fact-002", "inj020-fact-003",
                        "inj020-fact-004", "inj020-fact-005"),
        framed_facts=("inj020-fact-003",),
        jaccard=0.8,
        within_noise=0.0,
        p_value=0.0,
        direction=direction,
    )


def _journey():
    hero = Hero(
        scenario_id="INJ-020",
        facts=("inj020-fact-001", "inj020-fact-002", "inj020-fact-003",
               "inj020-fact-004", "inj020-fact-005"),
        threat_fact="inj020-fact-003",
        architect=_agent("architect", "collapse"),
        skeptic=AgentFraming(
            agent="skeptic",
            baseline_facts=("inj020-fact-001", "inj020-fact-002", "inj020-fact-004"),
            framed_facts=("inj020-fact-001", "inj020-fact-002", "inj020-fact-003",
                          "inj020-fact-004", "inj020-fact-005"),
            jaccard=0.4, within_noise=0.0, p_value=0.0, direction="expand",
        ),
        verdict="threat_dismissed",
        verdict_held_fraction=1.0,
    )
    landscape = Landscape(opposed=4, aligned=5, single=20, none_=21,
                          architect_real=11, skeptic_real=9, n_scenarios=17)
    return MirrorJourney(schema_version="mirror-v1", run_id="RUNID",
                         hero=hero, landscape=landscape)


def test_agent_rejects_bad_direction():
    with pytest.raises(ValueError):
        AgentFraming(agent="architect", baseline_facts=(), framed_facts=(),
                     jaccard=0.0, within_noise=0.0, p_value=0.0, direction="wobble")


def test_agent_rejects_jaccard_out_of_range():
    with pytest.raises(ValueError):
        AgentFraming(agent="architect", baseline_facts=(), framed_facts=(),
                     jaccard=1.5, within_noise=0.0, p_value=0.0, direction="collapse")


def test_landscape_rejects_negative():
    with pytest.raises(ValueError):
        Landscape(opposed=-1, aligned=5, single=20, none_=21,
                  architect_real=11, skeptic_real=9, n_scenarios=17)


def test_to_json_is_deterministic_and_sorted():
    a = mirror_journey_to_json(_journey())
    b = mirror_journey_to_json(_journey())
    assert a == b
    parsed = json.loads(a)
    assert parsed["schema_version"] == "mirror-v1"
    # none_ serializes to the wire key "none"
    assert parsed["landscape"]["none"] == 21
    assert "none_" not in parsed["landscape"]
    assert parsed["hero"]["architect"]["jaccard"] == 0.8
    assert parsed["hero"]["threat_fact"] == "inj020-fact-003"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest ares/dialectic/tests/visualization/test_mirror_journey_schema.py -v`
Expected: FAIL with `ModuleNotFoundError: ... mirror_journey_schema`.

- [ ] **Step 3: Write minimal implementation**

```python
# ares/dialectic/visualization/mirror_journey_schema.py
"""Schema for the ARES-VISION "Mirror" journey (mirror-v1).

One document per measurement run. Consumed by the standalone renderer at
skyframe-main/assets/ares/mirror.html. New file (ARES "new files only" rule);
peer of cycle_trace.py.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

_VALID_DIRECTIONS: frozenset[str] = frozenset({"collapse", "expand", "none"})


@dataclass(frozen=True)
class AgentFraming:
    """One agent's baseline->framed cited-fact shift for the hero scenario."""

    agent: str  # "architect" | "skeptic"
    baseline_facts: tuple[str, ...]
    framed_facts: tuple[str, ...]
    jaccard: float       # Jaccard DISTANCE, [0, 1]
    within_noise: float  # baseline within-distance, [0, 1]
    p_value: float
    direction: str       # "collapse" | "expand" | "none"

    def __post_init__(self) -> None:
        for name in ("jaccard", "within_noise", "p_value"):
            v = getattr(self, name)
            if not 0.0 <= v <= 1.0:
                raise ValueError(f"{name} must be in [0, 1]; got {v}")
        if self.direction not in _VALID_DIRECTIONS:
            raise ValueError(
                f"direction must be one of {sorted(_VALID_DIRECTIONS)}; "
                f"got {self.direction!r}"
            )


@dataclass(frozen=True)
class Hero:
    """The INJ-020 mirror: the page centerpiece."""

    scenario_id: str
    facts: tuple[str, ...]   # union of all facts, sorted
    threat_fact: str
    architect: AgentFraming
    skeptic: AgentFraming
    verdict: str
    verdict_held_fraction: float

    def __post_init__(self) -> None:
        if not self.scenario_id:
            raise ValueError("scenario_id must be non-empty")
        if self.threat_fact not in self.facts:
            raise ValueError("threat_fact must be one of facts")
        if not 0.0 <= self.verdict_held_fraction <= 1.0:
            raise ValueError("verdict_held_fraction must be in [0, 1]")


@dataclass(frozen=True)
class Landscape:
    """Aggregate prevalence across the 17 measured scenarios (S084)."""

    opposed: int
    aligned: int
    single: int
    none_: int
    architect_real: int
    skeptic_real: int
    n_scenarios: int

    def __post_init__(self) -> None:
        for name in ("opposed", "aligned", "single", "none_",
                     "architect_real", "skeptic_real", "n_scenarios"):
            if getattr(self, name) < 0:
                raise ValueError(f"{name} must be >= 0")


@dataclass(frozen=True)
class MirrorJourney:
    schema_version: str
    run_id: str
    hero: Hero
    landscape: Landscape

    def __post_init__(self) -> None:
        if self.schema_version != "mirror-v1":
            raise ValueError(
                f"schema_version must be 'mirror-v1'; got {self.schema_version!r}"
            )
        if not self.run_id:
            raise ValueError("run_id must be non-empty")


def _agent_to_dict(a: AgentFraming) -> dict:
    return {
        "agent": a.agent,
        "baseline_facts": list(a.baseline_facts),
        "framed_facts": list(a.framed_facts),
        "jaccard": a.jaccard,
        "within_noise": a.within_noise,
        "p_value": a.p_value,
        "direction": a.direction,
    }


def mirror_journey_to_json(journey: MirrorJourney) -> str:
    """Serialize to deterministic JSON (sorted keys, indent=2)."""
    payload = {
        "schema_version": journey.schema_version,
        "run_id": journey.run_id,
        "hero": {
            "scenario_id": journey.hero.scenario_id,
            "facts": list(journey.hero.facts),
            "threat_fact": journey.hero.threat_fact,
            "architect": _agent_to_dict(journey.hero.architect),
            "skeptic": _agent_to_dict(journey.hero.skeptic),
            "verdict": journey.hero.verdict,
            "verdict_held_fraction": journey.hero.verdict_held_fraction,
        },
        "landscape": {
            "opposed": journey.landscape.opposed,
            "aligned": journey.landscape.aligned,
            "single": journey.landscape.single,
            "none": journey.landscape.none_,
            "architect_real": journey.landscape.architect_real,
            "skeptic_real": journey.landscape.skeptic_real,
            "n_scenarios": journey.landscape.n_scenarios,
        },
    }
    return json.dumps(payload, indent=2, sort_keys=True)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest ares/dialectic/tests/visualization/test_mirror_journey_schema.py -v`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add ares/dialectic/visualization/mirror_journey_schema.py ares/dialectic/tests/visualization/test_mirror_journey_schema.py
git commit -m "feat(s085): mirror-journey schema + serialization"
```

---

### Task 2: Builder (parse S084 traces → MirrorJourney)

**Files:**
- Create: `ares/dialectic/visualization/mirror_journey_builder.py`
- Test: `ares/dialectic/tests/visualization/test_mirror_journey_builder.py`

**Reference — real S084 trace row keys** (`scenario_id`, `condition`, `resample_index`, `architect_cited_facts`, `skeptic_cited_facts`, `final_outcome`, ...). Conditions seen for INJ-020: `baseline`, `control`, `framing:framing_prefix_v1`, `framing:framing_suffix_v1`, `framing:synonym_substitution_conservative_v2`. Verified modal sets: baseline arch = all 5 / skep = `{001,002,004}`; framing arch = `{003}` / skep = all 5.

- [ ] **Step 1: Write the failing test (synthetic fixture — no dependency on the big real file)**

```python
# ares/dialectic/tests/visualization/test_mirror_journey_builder.py
from __future__ import annotations

import json
from pathlib import Path

import pytest

from ares.dialectic.visualization.mirror_journey_builder import (
    build_mirror_journey,
    jaccard_distance,
)

F = [f"inj020-fact-00{i}" for i in range(1, 6)]  # f1..f5


def _row(condition, arch, skep, outcome="threat_dismissed", ri=0):
    return {
        "scenario_id": "INJ-020", "condition": condition, "resample_index": ri,
        "architect_cited_facts": arch, "skeptic_cited_facts": skep,
        "final_outcome": outcome,
    }


def _write_traces(tmp_path: Path) -> Path:
    rows = []
    # baseline: arch all 5, skep {f1,f2,f4} (modal 3 of 4) + one minority set
    for ri in range(4):
        rows.append(_row("baseline", F, [F[0], F[1], F[3]], ri=ri))
    rows.append(_row("baseline", F, [F[0], F[1], F[3], F[4]], ri=4))  # minority
    # framing: arch {f3}, skep all 5
    for ri in range(5):
        rows.append(_row("framing:framing_prefix_v1", [F[2]], F, ri=ri))
    # a non-hero scenario row that must be ignored
    rows.append({"scenario_id": "INJ-001", "condition": "baseline", "resample_index": 0,
                 "architect_cited_facts": [F[0]], "skeptic_cited_facts": [F[0]],
                 "final_outcome": "threat_confirmed"})
    p = tmp_path / "traces.jsonl"
    p.write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")
    return p


def test_jaccard_distance_basic():
    assert jaccard_distance({"a", "b", "c", "d", "e"}, {"c"}) == pytest.approx(0.8)
    assert jaccard_distance({"a", "b", "d"}, {"a", "b", "c", "d", "e"}) == pytest.approx(0.4)
    assert jaccard_distance(set(), set()) == 0.0


def test_builder_extracts_hero(tmp_path):
    journey = build_mirror_journey(_write_traces(tmp_path), run_id="TESTRUN")
    h = journey.hero
    assert h.scenario_id == "INJ-020"
    assert h.threat_fact == "inj020-fact-003"
    assert h.architect.baseline_facts == tuple(F)        # all 5
    assert h.architect.framed_facts == ("inj020-fact-003",)
    assert h.architect.jaccard == pytest.approx(0.8)
    assert h.architect.direction == "collapse"
    assert h.skeptic.baseline_facts == ("inj020-fact-001", "inj020-fact-002", "inj020-fact-004")
    assert h.skeptic.framed_facts == tuple(F)
    assert h.skeptic.jaccard == pytest.approx(0.4)
    assert h.skeptic.direction == "expand"
    assert h.verdict == "threat_dismissed"
    assert h.verdict_held_fraction == 1.0


def test_builder_landscape_constants(tmp_path):
    j = build_mirror_journey(_write_traces(tmp_path), run_id="TESTRUN")
    assert (j.landscape.opposed, j.landscape.aligned, j.landscape.single, j.landscape.none_) == (4, 5, 20, 21)
    assert (j.landscape.architect_real, j.landscape.skeptic_real, j.landscape.n_scenarios) == (11, 9, 17)


def test_builder_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        build_mirror_journey(tmp_path / "nope.jsonl", run_id="X")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest ares/dialectic/tests/visualization/test_mirror_journey_builder.py -v`
Expected: FAIL with `ModuleNotFoundError`.

- [ ] **Step 3: Write minimal implementation**

```python
# ares/dialectic/visualization/mirror_journey_builder.py
"""Build a MirrorJourney (mirror-v1) from an S084 dual-agent traces.jsonl.

The S084 dual-agent run records BOTH agents' cited facts per resample, keyed by
`condition` (baseline | control | framing:<operator>). We recompute the INJ-020
hero (modal cited-fact sets, jaccard distances, verdict-held fraction) directly
from the traces. The aggregate "landscape" prevalence is the published S084
result, carried as documented constants (see source below) and pinned by the
JSON contract test.

New file (ARES "new files only" rule); peer of cycle_trace_builder.py.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from ares.dialectic.visualization.mirror_journey_schema import (
    AgentFraming,
    Hero,
    Landscape,
    MirrorJourney,
)

HERO_SCENARIO = "INJ-020"
BASELINE_CONDITION = "baseline"
HERO_FRAMING_CONDITION = "framing:framing_prefix_v1"
THREAT_FACT = "inj020-fact-003"

# Published S084 aggregate (run 20260605-194137-713674).
# Source: docs/paper_3/S084_DUAL_AGENT_FRAMING_RESULT_2026-06-05.md
#   mirror-class counts: opposed=4, aligned=5, single=20, none=21
#   rigorously REAL channels: 11 Architect, 9 Skeptic; 17 scenarios.
LANDSCAPE = Landscape(
    opposed=4, aligned=5, single=20, none_=21,
    architect_real=11, skeptic_real=9, n_scenarios=17,
)


def jaccard_distance(a: set[str], b: set[str]) -> float:
    union = a | b
    if not union:
        return 0.0
    return 1.0 - len(a & b) / len(union)


def _modal_facts(rows: list[dict], field: str) -> tuple[str, ...]:
    counter: Counter[tuple[str, ...]] = Counter()
    for r in rows:
        counter[tuple(sorted(r[field]))] += 1
    return counter.most_common(1)[0][0]


def _direction(baseline: tuple[str, ...], framed: tuple[str, ...]) -> str:
    if len(framed) < len(baseline):
        return "collapse"
    if len(framed) > len(baseline):
        return "expand"
    return "none"


def build_mirror_journey(traces_path: Path, run_id: str) -> MirrorJourney:
    if not traces_path.exists():
        raise FileNotFoundError(f"Traces file not found: {traces_path}")

    with traces_path.open("r", encoding="utf-8") as fh:
        rows = [json.loads(line) for line in fh if line.strip()]

    hero_rows = [r for r in rows if r.get("scenario_id") == HERO_SCENARIO]
    if not hero_rows:
        raise ValueError(f"No {HERO_SCENARIO} rows in {traces_path}")

    base = [r for r in hero_rows if r.get("condition") == BASELINE_CONDITION]
    framed = [r for r in hero_rows if r.get("condition") == HERO_FRAMING_CONDITION]
    if not base or not framed:
        raise ValueError(
            f"{HERO_SCENARIO} missing baseline or {HERO_FRAMING_CONDITION} rows"
        )

    arch_base = _modal_facts(base, "architect_cited_facts")
    arch_framed = _modal_facts(framed, "architect_cited_facts")
    skep_base = _modal_facts(base, "skeptic_cited_facts")
    skep_framed = _modal_facts(framed, "skeptic_cited_facts")

    held = sum(1 for r in framed if r.get("final_outcome") == "threat_dismissed")
    verdict_held_fraction = held / len(framed)

    facts = tuple(sorted(set(arch_base) | set(arch_framed)
                         | set(skep_base) | set(skep_framed)))

    architect = AgentFraming(
        agent="architect", baseline_facts=arch_base, framed_facts=arch_framed,
        jaccard=round(jaccard_distance(set(arch_base), set(arch_framed)), 4),
        within_noise=0.0, p_value=0.0,
        direction=_direction(arch_base, arch_framed),
    )
    skeptic = AgentFraming(
        agent="skeptic", baseline_facts=skep_base, framed_facts=skep_framed,
        jaccard=round(jaccard_distance(set(skep_base), set(skep_framed)), 4),
        within_noise=0.0, p_value=0.0,
        direction=_direction(skep_base, skep_framed),
    )
    hero = Hero(
        scenario_id=HERO_SCENARIO, facts=facts, threat_fact=THREAT_FACT,
        architect=architect, skeptic=skeptic,
        verdict="threat_dismissed", verdict_held_fraction=verdict_held_fraction,
    )
    return MirrorJourney(
        schema_version="mirror-v1", run_id=run_id, hero=hero, landscape=LANDSCAPE,
    )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest ares/dialectic/tests/visualization/test_mirror_journey_builder.py -v`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add ares/dialectic/visualization/mirror_journey_builder.py ares/dialectic/tests/visualization/test_mirror_journey_builder.py
git commit -m "feat(s085): mirror-journey builder (S084 trace parse + jaccard)"
```

---

### Task 3: CLI + generate the real artifact

**Files:**
- Create: `ares/dialectic/visualization/build_mirror_journey.py`
- Generated: `docs/marketing/mirror-journey.json`

- [ ] **Step 1: Write the CLI**

```python
# ares/dialectic/visualization/build_mirror_journey.py
"""CLI: read an S084 dual-agent traces.jsonl, write mirror-journey.json.

Usage:
    python -m ares.dialectic.visualization.build_mirror_journey \\
        --traces data/paper_3/leakage_runs/20260605-194137-713674/traces.jsonl \\
        --output docs/marketing/mirror-journey.json \\
        --run-id 20260605-194137-713674
"""

import argparse
import sys
from pathlib import Path

from ares.dialectic.visualization.mirror_journey_builder import build_mirror_journey
from ares.dialectic.visualization.mirror_journey_schema import mirror_journey_to_json


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--traces", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--run-id", required=True, type=str)
    args = parser.parse_args()

    try:
        journey = build_mirror_journey(args.traces, run_id=args.run_id)
    except (FileNotFoundError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(mirror_journey_to_json(journey), encoding="utf-8")
    print(f"Wrote {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 2: Generate the real artifact**

Run:
```bash
python -m ares.dialectic.visualization.build_mirror_journey \
  --traces data/paper_3/leakage_runs/20260605-194137-713674/traces.jsonl \
  --output docs/marketing/mirror-journey.json \
  --run-id 20260605-194137-713674
```
Expected: `Wrote docs/marketing/mirror-journey.json`.

- [ ] **Step 3: Eyeball the artifact**

Run: `python -c "import json;d=json.load(open('docs/marketing/mirror-journey.json'));print(d['hero']['architect']['jaccard'], d['hero']['skeptic']['jaccard'], d['landscape'])"`
Expected: `0.8 0.4 {'aligned': 5, 'architect_real': 11, ... 'opposed': 4, 'single': 20, 'none': 21, ...}`

- [ ] **Step 4: Commit**

```bash
git add ares/dialectic/visualization/build_mirror_journey.py docs/marketing/mirror-journey.json
git commit -m "feat(s085): mirror-journey CLI + generated artifact"
```

---

### Task 4: JSON contract test (deploy guard — pins the real numbers)

**Files:**
- Create: `ares/dialectic/tests/visualization/test_mirror_journey_json_contract.py`

- [ ] **Step 1: Write the test**

```python
# ares/dialectic/tests/visualization/test_mirror_journey_json_contract.py
"""Contract guard for the Mirror renderer artifact.

mirror-journey.json is consumed by skyframe-main/assets/ares/mirror.html.
Lock the shape AND the headline numbers so a regen that changes them fails
on the ARES side, not silently in the browser.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[4]
JOURNEY_PATH = REPO_ROOT / "docs" / "marketing" / "mirror-journey.json"

REQUIRED_TOP = frozenset({"schema_version", "run_id", "hero", "landscape"})
REQUIRED_AGENT = frozenset({"agent", "baseline_facts", "framed_facts",
                            "jaccard", "within_noise", "p_value", "direction"})


@pytest.fixture(scope="module")
def journey() -> dict:
    assert JOURNEY_PATH.exists(), f"mirror-journey.json missing at {JOURNEY_PATH}"
    with JOURNEY_PATH.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def test_top_level_keys(journey):
    assert REQUIRED_TOP.issubset(journey.keys())
    assert journey["schema_version"] == "mirror-v1"


def test_hero_agents_shape(journey):
    for agent in ("architect", "skeptic"):
        a = journey["hero"][agent]
        assert REQUIRED_AGENT.issubset(a.keys()), f"{agent} missing keys"


def test_hero_real_numbers(journey):
    h = journey["hero"]
    assert h["scenario_id"] == "INJ-020"
    assert h["threat_fact"] == "inj020-fact-003"
    assert h["architect"]["jaccard"] == 0.8
    assert h["architect"]["direction"] == "collapse"
    assert h["architect"]["framed_facts"] == ["inj020-fact-003"]
    assert h["skeptic"]["jaccard"] == 0.4
    assert h["skeptic"]["direction"] == "expand"
    assert len(h["skeptic"]["framed_facts"]) == 5  # expands to all 5
    assert h["verdict"] == "threat_dismissed"
    assert h["verdict_held_fraction"] == 1.0


def test_landscape_real_numbers(journey):
    ls = journey["landscape"]
    assert (ls["opposed"], ls["aligned"], ls["single"], ls["none"]) == (4, 5, 20, 21)
    assert (ls["architect_real"], ls["skeptic_real"], ls["n_scenarios"]) == (11, 9, 17)


def test_threat_fact_in_facts(journey):
    assert journey["hero"]["threat_fact"] in journey["hero"]["facts"]
```

- [ ] **Step 2: Run + verify pass**

Run: `python -m pytest ares/dialectic/tests/visualization/test_mirror_journey_json_contract.py -v`
Expected: PASS (5 tests).

- [ ] **Step 3: Full suite regression check**

Run: `python -m pytest tests/ ares/ -q`
Expected: all green (prior floor + new tests; 0 failures).

- [ ] **Step 4: Commit**

```bash
git add ares/dialectic/tests/visualization/test_mirror_journey_json_contract.py
git commit -m "test(s085): mirror-journey JSON contract guard"
```

---

# PART B — Renderer (skyframe-main, `E:\Skyframe Innovations Website\skyframe-main`)

> Frontend; verification is JSON-shape-at-load + live visual check via the LAN companion (already running) rather than unit tests. Hero animation logic is the validated prototype `.superpowers/brainstorm/ares-vision/content/mirror-A-live.html`, generalized to read from `mirror-journey.json`.

### Task 5: Page shell + CSS + data-driven hero

**Files (all under `E:\Skyframe Innovations Website\skyframe-main`):**
- Create: `assets/ares/mirror-journey.json` (copy of the ARES artifact)
- Create: `assets/ares/mirror.html`
- Create: `assets/ares/mirror.css`
- Create: `assets/ares/mirror.js`

- [ ] **Step 1: Deploy the data artifact**

```bash
cp "C:/ares-phase-zero/docs/marketing/mirror-journey.json" "E:/Skyframe Innovations Website/skyframe-main/assets/ares/mirror-journey.json"
```

- [ ] **Step 2: Create `assets/ares/mirror.html`**

```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ARES — The Mirror</title>
<link rel="stylesheet" href="mirror.css">
</head>
<body>
  <main id="scroll">
    <section class="scene" data-scene="setup">
      <div class="inner">
        <p class="eyebrow">ARES · adversarial reasoning</p>
        <h2>Two agents. One verdict.</h2>
        <p class="lede">An <b class="arch">Architect</b> argues the threat; a <b class="skep">Skeptic</b> pushes back. Together they reach a verdict.</p>
      </div>
    </section>

    <section class="scene hero" data-scene="mirror">
      <div class="inner">
        <p class="eyebrow">INJ-020 · the mirror</p>
        <h2>Same verdict. Opposite reasoning.</h2>
        <div id="mirror-stage"></div>
        <p class="readout" id="mirror-readout"></p>
      </div>
    </section>

    <section class="scene" data-scene="real">
      <div class="inner">
        <p class="eyebrow">but is it real?</p>
        <h2>Signal, not noise.</h2>
        <div id="noise-stage"></div>
        <p class="lede">At baseline both agents are dead-steady. The framing shift towers over the noise floor (p&#8776;0).</p>
      </div>
    </section>

    <section class="scene" data-scene="landscape">
      <div class="inner">
        <p class="eyebrow">the honest landscape</p>
        <h2>Rare — and we say so.</h2>
        <div id="landscape-stage"></div>
        <p class="lede" id="landscape-readout"></p>
      </div>
    </section>

    <section class="scene" data-scene="cta">
      <div class="inner">
        <p class="eyebrow">the problem is inside the black box</p>
        <h2>See the rest.</h2>
        <div class="cta-row">
          <a class="btn primary" href="#" id="paper-link">Read the paper</a>
          <a class="btn" href="prism.html">Explore the live data →</a>
        </div>
      </div>
    </section>
  </main>
  <script src="mirror.js"></script>
</body>
</html>
```

- [ ] **Step 3: Create `assets/ares/mirror.css`** (house style + hero animation + scroll-reveal)

```css
:root{--bg:#0a0a0a;--card:#0e0f12;--line:#1d2127;--arch:#f59e0b;--skep:#60a5fa;
  --threat:#ef4444;--held:#10b981;--text:#e2e8f0;--muted:#64748b;--faint:#39424f}
*{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth}
body{background:var(--bg);color:var(--text);font-family:Inter,system-ui,sans-serif}
.scene{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:48px 16px}
.inner{width:100%;max-width:600px;text-align:center;opacity:0;transform:translateY(24px);
  transition:opacity .8s ease,transform .8s cubic-bezier(.5,0,.15,1)}
.scene.in-view .inner{opacity:1;transform:none}
.eyebrow{font:600 11px/1.2 'JetBrains Mono',monospace;letter-spacing:.22em;
  text-transform:uppercase;color:var(--muted)}
h2{font-size:clamp(24px,6vw,40px);font-weight:760;letter-spacing:-.02em;margin:10px 0 16px}
.lede{color:var(--muted);font-size:15px;line-height:1.55;max-width:46ch;margin:14px auto 0}
.lede b,.arch{color:var(--arch)} .skep{color:var(--skep)}
.readout{color:var(--muted);font:600 13px/1.5 'JetBrains Mono',monospace;margin-top:18px;min-height:20px}
/* hero mirror (ported from validated prototype, data-driven) */
#mirror-stage{margin-top:22px}
.heads{display:flex;justify-content:space-between;font:700 12px/1 'JetBrains Mono',monospace;
  letter-spacing:.12em;margin-bottom:12px}
.heads .a{color:var(--arch)} .heads .s{color:var(--skep)} .heads .v{font-size:10px;color:var(--muted)}
.rows{display:flex;flex-direction:column;gap:10px;position:relative}
.seam{position:absolute;top:-6px;bottom:-6px;left:50%;width:2px;margin-left:-1px;
  background:linear-gradient(180deg,rgba(16,185,129,.05),var(--held),rgba(16,185,129,.05));
  box-shadow:0 0 14px rgba(16,185,129,.55)}
.row{display:grid;grid-template-columns:1fr 56px 1fr;align-items:center;height:20px}
.cell{height:14px;display:flex;align-items:center}
.cell.l{justify-content:flex-end} .cell.r{justify-content:flex-start}
.bar{height:14px;width:100%;border-radius:7px;opacity:.12;
  transition:opacity .6s ease,transform .75s cubic-bezier(.5,0,.15,1)}
.l .bar{transform-origin:right;transform:scaleX(.05);background:linear-gradient(270deg,var(--arch),rgba(245,158,11,.3))}
.r .bar{transform-origin:left;transform:scaleX(.05);background:linear-gradient(90deg,var(--skep),rgba(96,165,250,.3))}
.bar.cited{opacity:1;transform:scaleX(1)}
.lab{font:600 11px/1 'JetBrains Mono',monospace;color:var(--muted);text-align:center}
.row.threat .lab{color:var(--threat)}
.chip{display:inline-block;margin-top:20px;font:700 12px/1 'JetBrains Mono',monospace;color:var(--held);
  border:1px solid rgba(16,185,129,.4);background:rgba(16,185,129,.08);padding:7px 13px;border-radius:20px}
.chip .dot{display:inline-block;width:7px;height:7px;border-radius:50%;background:var(--held);
  margin-right:7px;box-shadow:0 0 8px var(--held)}
/* noise scene */
.noise{display:flex;align-items:flex-end;gap:14px;height:90px;justify-content:center;margin-top:8px}
.noise .b{width:30px;border-radius:5px 5px 0 0}
/* landscape tally */
.tally{display:flex;gap:8px;justify-content:center;margin-top:8px;flex-wrap:wrap}
.t{font:600 10px/1.3 'JetBrains Mono',monospace;color:var(--muted);border:1px solid var(--line);
  border-radius:8px;padding:9px 11px;min-width:64px}
.t b{display:block;font-size:18px;color:var(--text)}
.t.hot{border-color:rgba(239,68,68,.5);color:var(--threat)} .t.hot b{color:var(--threat)}
/* cta */
.cta-row{display:flex;gap:12px;justify-content:center;flex-wrap:wrap;margin-top:8px}
.btn{font:600 13px/1 Inter,sans-serif;padding:12px 18px;border-radius:10px;border:1px solid var(--line);
  color:var(--text);text-decoration:none}
.btn.primary{border-color:rgba(239,68,68,.5);background:rgba(239,68,68,.12);color:#fff}
```

- [ ] **Step 4: Create `assets/ares/mirror.js`** (fetch JSON + build/animate hero)

```javascript
(function () {
  fetch('mirror-journey.json').then(function (r) { return r.json(); }).then(init);

  function shortLabel(facts, id) { return 'f' + (facts.indexOf(id) + 1); }

  function init(data) {
    buildHero(data.hero);
    buildNoise(data.hero);
    buildLandscape(data.landscape);
    observeScenes();
  }

  function buildHero(hero) {
    var facts = hero.facts;
    var stage = document.getElementById('mirror-stage');
    var heads = '<div class="heads"><span class="a">ARCHITECT</span>' +
                '<span class="v">VERDICT</span><span class="s">SKEPTIC</span></div>';
    var rows = '<div class="rows"><div class="seam"></div>';
    facts.forEach(function (id, i) {
      var threat = id === hero.threat_fact;
      rows += '<div class="row' + (threat ? ' threat' : '') + '" data-fact="' + id + '">' +
        '<div class="cell l"><div class="bar" data-side="l" style="transition-delay:' + (i * 55) + 'ms"></div></div>' +
        '<div class="lab">' + shortLabel(facts, id) + (threat ? ' ⚠' : '') + '</div>' +
        '<div class="cell r"><div class="bar" data-side="r" style="transition-delay:' + (i * 55) + 'ms"></div></div></div>';
    });
    rows += '</div>';
    stage.innerHTML = heads + rows +
      '<div style="text-align:center"><span class="chip"><span class="dot"></span>' +
      hero.verdict.replace(/_/g, ' ') + '</span></div>';

    var ro = document.getElementById('mirror-readout');
    var A = hero.architect, S = hero.skeptic;
    function apply(phase) {
      facts.forEach(function (id) {
        var row = stage.querySelector('[data-fact="' + id + '"]');
        var aset = phase === 'baseline' ? A.baseline_facts : A.framed_facts;
        var sset = phase === 'baseline' ? S.baseline_facts : S.framed_facts;
        row.querySelector('.bar[data-side="l"]').classList.toggle('cited', aset.indexOf(id) > -1);
        row.querySelector('.bar[data-side="r"]').classList.toggle('cited', sset.indexOf(id) > -1);
      });
      ro.textContent = phase === 'baseline'
        ? 'Baseline · Architect cites ' + A.baseline_facts.length + '/' + facts.length +
          ' · Skeptic ' + S.baseline_facts.length + '/' + facts.length + ' (skips the threat)'
        : 'Under framing · Architect J=' + A.jaccard + ' (collapse) · Skeptic J=' + S.jaccard +
          ' (expand) · verdict UNCHANGED';
    }
    var phase = 'baseline'; apply(phase);
    stage._loop = function () {
      phase = phase === 'baseline' ? 'framed' : 'baseline';
      apply(phase);
      stage._t = setTimeout(stage._loop, phase === 'baseline' ? 2200 : 3200);
    };
  }

  function buildNoise(hero) {
    var s = document.getElementById('noise-stage');
    var sig = Math.max(hero.architect.jaccard, hero.skeptic.jaccard);
    s.innerHTML = '<div class="noise">' +
      '<span class="b" style="height:3px;background:var(--muted)"></span>' +
      '<span class="b" style="height:' + Math.round(sig * 88) + 'px;background:var(--threat)"></span></div>' +
      '<p class="readout">noise floor ' + hero.architect.within_noise.toFixed(2) +
      ' &nbsp;vs&nbsp; signal ' + sig.toFixed(2) + '</p>';
  }

  function buildLandscape(ls) {
    var s = document.getElementById('landscape-stage');
    s.innerHTML = '<div class="tally">' +
      '<span class="t hot"><b>' + ls.opposed + '</b>opposed</span>' +
      '<span class="t"><b>' + ls.aligned + '</b>aligned</span>' +
      '<span class="t"><b>' + ls.single + '</b>single</span>' +
      '<span class="t"><b>' + ls.none + '</b>none</span></div>';
    document.getElementById('landscape-readout').textContent =
      'Across ' + ls.n_scenarios + ' scenarios: ' + ls.architect_real +
      ' Architect-real, ' + ls.skeptic_real + ' Skeptic-real. The clean opposed mirror is rare.';
  }

  function observeScenes() {
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) {
        var scene = e.target;
        if (e.isIntersecting) {
          scene.classList.add('in-view');
          if (scene.dataset.scene === 'mirror') {
            var stage = document.getElementById('mirror-stage');
            if (stage._loop && !stage._t) stage._t = setTimeout(stage._loop, 1200);
          }
        } else if (scene.dataset.scene === 'mirror') {
          var st = document.getElementById('mirror-stage');
          clearTimeout(st._t); st._t = null;
        }
      });
    }, { threshold: 0.4 });
    document.querySelectorAll('.scene').forEach(function (s) { io.observe(s); });
  }
})();
```

- [ ] **Step 5: Verify live via the LAN companion / browser**

Open `assets/ares/mirror.html` (locally or via the deployed site). Confirm: 5 scenes scroll-reveal; the hero mirror loops baseline⇄framed (left collapses to the threat, right expands); verdict chip steady; noise/landscape/CTA populated from JSON. Fix any layout issues on mobile.

- [ ] **Step 6: Commit (in skyframe-main repo)**

```bash
git -C "E:/Skyframe Innovations Website/skyframe-main" add assets/ares/mirror.html assets/ares/mirror.css assets/ares/mirror.js assets/ares/mirror-journey.json
git -C "E:/Skyframe Innovations Website/skyframe-main" commit -m "feat: ARES-VISION 'The Mirror' scrollytelling page"
```

---

### Task 6: Landing hand-off (link from `ares.html`)

**Files:**
- Modify: `E:\Skyframe Innovations Website\skyframe-main\ares.html`

- [ ] **Step 1: Add a hero CTA link** to `ares.html` near the top hero/CTA block (match existing markup; insert a prominent anchor):

```html
<a class="ares-hero-cta" href="assets/ares/mirror.html">See it move &rarr;</a>
```
(Place adjacent to the existing Prism/Pinscreen CTA links — see those for the surrounding class/structure to mirror.)

- [ ] **Step 2: Verify** the link renders and navigates to the mirror page.

- [ ] **Step 3: Set the paper link** in `mirror.html` (`#paper-link` href) to the public paper URL when available; leave `#` until then (documented open item).

- [ ] **Step 4: Commit**

```bash
git -C "E:/Skyframe Innovations Website/skyframe-main" add ares.html
git -C "E:/Skyframe Innovations Website/skyframe-main" commit -m "feat: link 'The Mirror' from the ARES landing"
```

---

## Self-Review

**Spec coverage:** aim/scope/hero (Tasks 2,5) ✓; 5-scene arc (Task 5 html/js) ✓; placement = standalone + landing link + Prism CTA (Tasks 5,6) ✓; tech = CSS/SVG + IntersectionObserver + Python adapter (all) ✓; real numbers baked + pinned (Tasks 2,4) ✓; new-files-only + frozen dataclasses + no API spend (Tasks 1-3) ✓; testing (Tasks 1,2,4) ✓.

**Placeholder scan:** `#paper-link` is a documented open item (Task 6 Step 3), not a hidden TODO. No other placeholders.

**Type consistency:** `AgentFraming/Hero/Landscape/MirrorJourney`, `none_`→`"none"` wire mapping, `jaccard` (distance), `build_mirror_journey(traces_path, run_id)`, `jaccard_distance(set,set)` consistent across tasks and tests.

**Open items (carried from spec):** paper URL for `#paper-link`; scene-4 = tally-only for v1 (agreed); the JSON deploy is a manual `cp` (documented in Task 5 Step 1 + the spec's two-repo risk).
