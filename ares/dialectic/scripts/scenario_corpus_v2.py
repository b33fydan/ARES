"""Scenario corpus v2 — patched expected verdicts for AMBIGUITY_MISMATCH.

Session 032: SC-011 and SC-017 were classified as AMBIGUITY_MISMATCH
in the Session 031 diagnosis. The system's DISMISSED verdicts are
defensible. This module patches expected verdicts without modifying
the original corpus.

Public API:
    get_full_corpus_v2()  — All 33 scenarios with patched expected verdicts
    VERDICT_PATCHES       — Map of scenario_id to new expected_verdict
"""

from __future__ import annotations

from dataclasses import replace
from typing import Tuple

from ares.dialectic.scripts.expanded_scenarios import get_full_corpus
from ares.dialectic.scripts.scenario_corpus import (
    BenchmarkScenario,
    ScenarioMetadata,
)


VERDICT_PATCHES = {
    "SC-011": "THREAT_DISMISSED",   # Was INCONCLUSIVE — system's DISMISSED is defensible
    "SC-017": "THREAT_DISMISSED",   # Was INCONCLUSIVE — system's DISMISSED is defensible
}


def get_full_corpus_v2() -> Tuple[BenchmarkScenario, ...]:
    """Return all 33 scenarios with patched expected verdicts.

    Creates new ScenarioMetadata instances for patched scenarios
    using dataclasses.replace(). Original corpus is untouched.

    Returns:
        Tuple of BenchmarkScenario instances with updated verdicts.
    """
    patched: list[BenchmarkScenario] = []

    for scenario in get_full_corpus():
        sid = scenario.metadata.scenario_id
        if sid in VERDICT_PATCHES:
            new_verdict = VERDICT_PATCHES[sid]
            new_meta = replace(
                scenario.metadata,
                expected_verdict=new_verdict,
            )
            patched.append(replace(scenario, metadata=new_meta))
        else:
            patched.append(scenario)

    return tuple(patched)
