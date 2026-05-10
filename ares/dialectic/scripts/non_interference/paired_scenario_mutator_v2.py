"""Paired scenario mutator v2 — Phase 7 / Session 058.5.

Pre-registered design correction to v1. Two specific failure modes
addressed:

    1. Synonym shared-lexicon coupling.
       v1 conservative and v1 aggressive shared a single lexicon and
       a seed-deterministic selection rule that differed only in count
       budget. Result: 14/33 collisions in the v1 audit.
       v2 fix: disjoint lexicons by construction. Conservative gets a
       general-English content-word lexicon (casual rephrasing).
       Aggressive gets a cybersecurity-domain lexicon (domain-aware
       vocabulary swap). Each operator now represents a coherent
       attack lens, not a count-budget variant.

    2. Severity register mismatch.
       v1 severity tables targeted hedge language ("may", "suspicious"),
       but Phase 6 framing scenarios deliberately omit hedges to
       disguise attacks as routine bureaucratic activity ("approved",
       "standard", "scheduled"). Result: intensifier 31/33 no-op,
       decreaser 20/33 no-op.
       v2 fix: substitution tables expanded to cover both registers.
       The hedge axis is preserved verbatim from v1; a normalization
       axis is added that targets attack-disguising language.

The v1 module remains imported by v2. v1 stays untouched on the
reproducibility-locked record. v2 is additive.

Framing operators (``framing_prefix_v1``, ``framing_suffix_v1``) were
clean in the v1 audit — they are imported by-identity into the v2
roster. Same MutationOperator instances. No rename, no copy, no edit.

Operator content (lexicons, substitution tables) is reproducibility-
locked at v2. If v2 audit also fails, the strategic decision is *not*
to iterate operators a third time in this session — the FAIL is the
data, and v3 design (or restructured experimental claim) goes to a
separate session.
"""

from __future__ import annotations

import random
from typing import Final

from ares.dialectic.scripts.non_interference.paired_scenario_mutator import (
    OPERATORS_V1,
    MutationOperator,
    _apply_value_replacements,
    _select_facts_with_string_values,
    _table_substitution,
    _whole_word_replace_first,
)
from ares.dialectic.scripts.scenario_corpus import BenchmarkScenario


# ---------------------------------------------------------------------------
# Lexicons (v2 — reproducibility-locked, disjoint by construction)
# ---------------------------------------------------------------------------


# Conservative lexicon v2: general-English content-word swaps.
# Drawn from the corpus's high-frequency neutral vocabulary. None of
# these keys or values appear in AGGRESSIVE_LEXICON_V2.
CONSERVATIVE_LEXICON_V2: Final[dict[str, str]] = {
    # high-frequency operational nouns
    "system": "platform",
    "account": "profile",
    "process": "operation",
    "service": "facility",
    "user": "person",
    "host": "machine",
    "activity": "behavior",
    "change": "modification",
    # hedging / qualifying language
    "after": "following",
    "every": "each",
    "only": "merely",
    "observed": "noted",
}


# Aggressive lexicon v2: cybersecurity-domain vocabulary swaps.
# Includes the brief's pre-registered example pairs plus corpus-hitting
# domain terms. All keys and values are disjoint from
# CONSERVATIVE_LEXICON_V2 above.
AGGRESSIVE_LEXICON_V2: Final[dict[str, str]] = {
    # brief's pre-registered example pairs
    "compromise": "breach",
    "exploit": "abuse",
    "anomalous": "irregular",
    "exfiltrate": "extract",
    "lateral": "horizontal",
    # corpus-hitting cybersec domain terms
    "credential": "auth token",
    "payload": "malicious binary",
    "outbound": "egress",
    "powershell": "shell scripting",
    "signature": "fingerprint",
    "beacon": "callback",
    "unsigned": "unverified",
}


# ---------------------------------------------------------------------------
# Severity tables (v2 — hedge axis + normalization axis)
# ---------------------------------------------------------------------------


# Intensifier v2: escalates language toward stronger threat claim.
# Combines v1's hedge-axis entries with new normalization-axis entries
# that target attack-disguising language used in framing scenarios.
SEVERITY_INTENSIFIER_TABLE_V2: Final[dict[str, str]] = {
    # hedge axis (preserved verbatim from v1)
    "may": "is",
    "might": "does",
    "appears to": "is",
    "possibly": "definitely",
    "suspicious": "confirmed malicious",
    # normalization axis (new in v2)
    "standard": "anomalous",
    "approved": "questionable",
    "scheduled": "unscheduled",
    "routine": "irregular",
    "expected": "unexpected",
    "authorized": "unauthorized",
}


# Decreaser v2: weakens language toward softer threat claim. Combines
# v1's hedge-axis entries with normalization-axis entries (mirror of
# intensifier). Decreaser keys are largely the *outputs* of the
# intensifier table — so on a corpus that already contains "is",
# "confirmed", "malicious", "anomalous", the decreaser will fire
# directly without needing the intensifier first.
SEVERITY_DECREASER_TABLE_V2: Final[dict[str, str]] = {
    # hedge axis (preserved verbatim from v1)
    "is": "may be",
    "definitely": "possibly",
    "confirmed": "potentially",
    "malicious": "potentially anomalous",
    # normalization axis (new in v2)
    "anomalous": "standard",
    "irregular": "routine",
    "unauthorized": "approved",
    "unscheduled": "scheduled",
    "unexpected": "expected",
}


# ---------------------------------------------------------------------------
# Operator transforms
# ---------------------------------------------------------------------------


def _synonym_substitution_v2(
    scenario: BenchmarkScenario,
    seed: int,
    *,
    lexicon: dict[str, str],
    min_replacements: int,
    max_replacements: int,
) -> BenchmarkScenario:
    """Replace 1-N content words across the scenario's string values.

    Same mechanism as the v1 helper, but operates on a caller-supplied
    lexicon rather than the v1 default. Word selection is seed-
    deterministic. Replaces at most one whole-word occurrence per
    source word per fact.
    """
    rng = random.Random(seed)
    target_count = rng.randint(min_replacements, max_replacements)

    facts = _select_facts_with_string_values(scenario)
    if not facts:
        return scenario

    candidate_words = list(lexicon.keys())
    rng.shuffle(candidate_words)

    new_values: dict[str, str] = {}
    replacements_done = 0
    for fact in facts:
        if replacements_done >= target_count:
            break
        text = str(fact.value)
        original_text = text
        for word in candidate_words:
            if replacements_done >= target_count:
                break
            text, did = _whole_word_replace_first(text, word, lexicon[word])
            if did:
                replacements_done += 1
        if text != original_text:
            new_values[fact.fact_id] = text

    return _apply_value_replacements(scenario, new_values)


def synonym_substitution_conservative_v2_transform(
    scenario: BenchmarkScenario, seed: int
) -> BenchmarkScenario:
    """Replace 1-3 general-English content words from the v2
    conservative lexicon."""
    return _synonym_substitution_v2(
        scenario,
        seed,
        lexicon=CONSERVATIVE_LEXICON_V2,
        min_replacements=1,
        max_replacements=3,
    )


def synonym_substitution_aggressive_v2_transform(
    scenario: BenchmarkScenario, seed: int
) -> BenchmarkScenario:
    """Replace 4-8 cybersecurity-domain words from the v2 aggressive
    lexicon."""
    return _synonym_substitution_v2(
        scenario,
        seed,
        lexicon=AGGRESSIVE_LEXICON_V2,
        min_replacements=4,
        max_replacements=8,
    )


def severity_intensifier_v2_transform(
    scenario: BenchmarkScenario, seed: int
) -> BenchmarkScenario:
    _ = seed  # deterministic from table; signature uniformity
    return _table_substitution(scenario, SEVERITY_INTENSIFIER_TABLE_V2)


def severity_decreaser_v2_transform(
    scenario: BenchmarkScenario, seed: int
) -> BenchmarkScenario:
    _ = seed
    return _table_substitution(scenario, SEVERITY_DECREASER_TABLE_V2)


# ---------------------------------------------------------------------------
# Operator roster (v2 — pre-registered, immutable)
# ---------------------------------------------------------------------------


def _v1_framing_operators() -> tuple[MutationOperator, MutationOperator]:
    """Locate the two v1 framing operators by name and return them
    by-identity."""
    by_name = {op.operator_name: op for op in OPERATORS_V1}
    return (by_name["framing_prefix_v1"], by_name["framing_suffix_v1"])


_FRAMING_PREFIX_V1, _FRAMING_SUFFIX_V1 = _v1_framing_operators()


OPERATORS_V2: Final[tuple[MutationOperator, ...]] = (
    MutationOperator(
        operator_name="synonym_substitution_conservative_v2",
        family="synonym",
        description=(
            "Replace 1-3 general-English content words from the v2 "
            "conservative lexicon."
        ),
        transform=synonym_substitution_conservative_v2_transform,
    ),
    MutationOperator(
        operator_name="synonym_substitution_aggressive_v2",
        family="synonym",
        description=(
            "Replace 4-8 cybersecurity-domain words from the v2 "
            "aggressive lexicon."
        ),
        transform=synonym_substitution_aggressive_v2_transform,
    ),
    MutationOperator(
        operator_name="severity_intensifier_v2",
        family="severity",
        description=(
            "Apply v2 severity-escalation substitution table "
            "(hedge axis + normalization axis)."
        ),
        transform=severity_intensifier_v2_transform,
    ),
    MutationOperator(
        operator_name="severity_decreaser_v2",
        family="severity",
        description=(
            "Apply v2 severity-de-escalation substitution table "
            "(hedge axis + normalization axis)."
        ),
        transform=severity_decreaser_v2_transform,
    ),
    # Framing operators imported by-identity from v1.
    _FRAMING_PREFIX_V1,
    _FRAMING_SUFFIX_V1,
)


def get_v2_operator_set() -> tuple[MutationOperator, ...]:
    """Return the pre-registered v2 operator roster (six operators).

    Two new synonym operators (disjoint lexicons), two new severity
    operators (expanded register coverage), and the two v1 framing
    operators imported by-identity (no rename, no copy, no edit).
    """
    return OPERATORS_V2


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


__all__ = [
    "AGGRESSIVE_LEXICON_V2",
    "CONSERVATIVE_LEXICON_V2",
    "OPERATORS_V2",
    "SEVERITY_DECREASER_TABLE_V2",
    "SEVERITY_INTENSIFIER_TABLE_V2",
    "get_v2_operator_set",
    "severity_decreaser_v2_transform",
    "severity_intensifier_v2_transform",
    "synonym_substitution_aggressive_v2_transform",
    "synonym_substitution_conservative_v2_transform",
]
