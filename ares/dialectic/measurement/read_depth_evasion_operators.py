# ares/dialectic/measurement/read_depth_evasion_operators.py
"""Lexical-evasion mutation operators for the read-depth frontier (Phase B).

These deterministic, offline operators rewrite ``fact.value`` strings to evade
the tier-2 literal regexes while remaining meaning-preserving and skeleton-
invariant. They target tokens that tier 3's canonicalizer folds back
(``binary``->``exe``, ``temporary``->``temp``), so tier 2 flips and tier 3
recovers — the "reading values costs evadability, canonicalization buys some
back" axis. (Evasions outside tier 3's synonym map are a documented Phase-C
limitation, not built here.)

Family is ``"synonym"`` — the only valid `MutationOperator` families are
{synonym, severity, framing}; an ``exe``<->``binary`` swap is a synonym
substitution. Skeleton invariance is delegated to the mutator's
``_apply_value_replacements``.
"""
from __future__ import annotations

import re

from ares.dialectic.scripts.non_interference.paired_scenario_mutator import (
    MutationOperator,
    _apply_value_replacements,
)
from ares.dialectic.scripts.scenario_corpus import BenchmarkScenario

_DOT_EXE = re.compile(r"\.exe\b", re.IGNORECASE)
_WORD_TEMP = re.compile(r"\btemp\b", re.IGNORECASE)


def _rewrite_string_values(scenario: BenchmarkScenario, pattern: re.Pattern,
                           replacement: str) -> BenchmarkScenario:
    """Apply ``pattern -> replacement`` to every string value; skeleton-safe."""
    new_values: dict[str, str] = {}
    for fact in scenario.packet.get_all_facts():
        if not isinstance(fact.value, str):
            continue
        new_text = pattern.sub(replacement, fact.value)
        if new_text != fact.value:
            new_values[fact.fact_id] = new_text
    return _apply_value_replacements(scenario, new_values)


def exe_to_binary_transform(
    scenario: BenchmarkScenario, seed: int
) -> BenchmarkScenario:
    """Replace ``.exe`` extensions with the word ``binary`` (seed unused)."""
    _ = seed
    return _rewrite_string_values(scenario, _DOT_EXE, " binary")


def temp_to_temporary_transform(
    scenario: BenchmarkScenario, seed: int
) -> BenchmarkScenario:
    """Replace the whole word ``temp`` with ``temporary`` (seed unused)."""
    _ = seed
    return _rewrite_string_values(scenario, _WORD_TEMP, "temporary")


EVASION_OPERATORS: tuple[MutationOperator, ...] = (
    MutationOperator(
        operator_name="exe_to_binary_v1",
        family="synonym",
        description="Rewrite '.exe' extensions to the word 'binary' "
        "(tier-2 literal evasion; tier-3 folds binary->exe).",
        transform=exe_to_binary_transform,
    ),
    MutationOperator(
        operator_name="temp_to_temporary_v1",
        family="synonym",
        description="Rewrite the path token 'temp' to 'temporary' "
        "(tier-2 user-writable-dir evasion; tier-3 folds temporary->temp).",
        transform=temp_to_temporary_transform,
    ),
)
