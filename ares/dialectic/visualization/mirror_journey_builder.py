"""Build a MirrorJourney (mirror-v1) from an S084 dual-agent traces.jsonl.

The S084 dual-agent run records BOTH agents' cited facts per resample, keyed by
``condition`` (baseline | control | framing:<operator>). We recompute the
INJ-020 hero cited-fact sets (modal), jaccard distances, and verdict-held
fraction directly from the traces. The run-level aggregates the per-resample
traces don't expose — each agent's within-noise floor, the framing p-value, and
the cross-scenario "landscape" prevalence — are the published S084 result,
carried as documented constants (see below) and pinned by the JSON contract test.

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
# INJ-020 is operator-universal in S084 (arch -> {f3}, skep -> all 5,
# J=0.80/0.40 on prefix, suffix, AND synonym), so prefix is representative.
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

# INJ-020 within-noise floor and framing p-value (both agents, all operators).
# Source: S084 report + summary.json (within_median=0.000, p_value=0.000 for
# architect and skeptic on every framing operator). Carried as constants for the
# same reason as LANDSCAPE: they are run-level stats the per-resample traces do
# not expose. Retargeting this adapter to another run means updating these.
HERO_WITHIN_NOISE = 0.0
HERO_P_VALUE = 0.0


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
        within_noise=HERO_WITHIN_NOISE, p_value=HERO_P_VALUE,
        direction=_direction(arch_base, arch_framed),
    )
    skeptic = AgentFraming(
        agent="skeptic", baseline_facts=skep_base, framed_facts=skep_framed,
        jaccard=round(jaccard_distance(set(skep_base), set(skep_framed)), 4),
        within_noise=HERO_WITHIN_NOISE, p_value=HERO_P_VALUE,
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
