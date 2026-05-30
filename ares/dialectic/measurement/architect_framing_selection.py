"""Select pilot scenarios: those whose Architect cited-facts diverged under
mutation on the LLM path in a prior leakage run (e.g. S059 Sonnet traces)."""
from __future__ import annotations

import json
from pathlib import Path


def select_diverging_scenarios(traces_path: Path | str) -> list[str]:
    path = Path(traces_path)
    if not path.exists():
        return []

    baseline: dict[str, frozenset[str]] = {}
    mutated: dict[str, list[frozenset[str]]] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        r = json.loads(line)
        if r.get("pipeline") != "llm":
            continue
        sid = r["scenario_id"]
        cited = frozenset(r.get("architect_cited_facts") or [])
        if r.get("is_baseline"):
            baseline[sid] = cited
        else:
            mutated.setdefault(sid, []).append(cited)

    diverged = []
    for sid, base in baseline.items():
        if any(m != base for m in mutated.get(sid, [])):
            diverged.append(sid)
    return sorted(diverged)
