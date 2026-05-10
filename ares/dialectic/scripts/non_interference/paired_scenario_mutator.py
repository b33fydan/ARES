"""Paired scenario mutator — Phase 7 / Session 058.

Deterministic, programmatic skeleton-preserving mutation of
BenchmarkScenarios. The mutator is the load-bearing primitive for the
entire Paper 3 experimental claim:

    When the structured evidence skeleton (fact_id, field, entity_id,
    source_type, timestamp) is held byte-identical, mutation of
    attacker-controlled value text shall not change the Light Skeptic's
    InfluenceLeakage 4-bit vector.

If the mutator quietly violates skeleton invariance, every downstream
measurement is contaminated. ``MutatedScenarioPair.__post_init__`` is
the place where invariance becomes a typed property of the data
structure rather than a runtime hope.

No LLM calls. No network I/O. Deterministic given fixed seed. Operator
content (lexicons, substitution tables) is reproducibility-locked at
v1; iteration goes in v2 modules in future sessions.

Operator families (v1, six concrete operators):

    synonym  : synonym_substitution_conservative_v1
               synonym_substitution_aggressive_v1
    severity : severity_intensifier_v1
               severity_decreaser_v1
    framing  : framing_prefix_v1
               framing_suffix_v1
"""

from __future__ import annotations

import random
import re
from dataclasses import dataclass, field
from typing import Callable

from ares.dialectic.evidence.fact import Fact
from ares.dialectic.evidence.packet import EvidencePacket, TimeWindow
from ares.dialectic.schemas.skeleton_equivalence import skeleton_hash
from ares.dialectic.scripts.scenario_corpus import BenchmarkScenario


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class SkeletonInvariantError(ValueError):
    """Raised when a mutation breaks the skeleton invariant.

    This is a hard error. It signals an operator implementation bug,
    NOT a corpus property to be tolerated. Do not catch and silence.
    """


# ---------------------------------------------------------------------------
# Operator + pair dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MutationOperator:
    """A pure-function transformation that mutates value text while
    preserving the structured skeleton.

    Attributes:
        operator_name: Unique identifier (e.g., "synonym_substitution_v1").
        family: One of {"synonym", "severity", "framing"}.
        description: Human-readable summary.
        transform: Callable taking (BenchmarkScenario, seed) -> mutated
            BenchmarkScenario. Must be deterministic given fixed seed.
            Must preserve the skeleton; if it cannot meaningfully mutate
            the scenario, it must return an unchanged BenchmarkScenario
            (caller treats unchanged output as a no-op).
    """

    operator_name: str
    family: str
    description: str
    transform: Callable[[BenchmarkScenario, int], BenchmarkScenario]

    def __post_init__(self) -> None:
        if self.family not in _VALID_FAMILIES:
            raise ValueError(
                f"family must be one of {sorted(_VALID_FAMILIES)}; "
                f"got {self.family!r}"
            )
        if not self.operator_name:
            raise ValueError("operator_name must be non-empty")


_VALID_FAMILIES: frozenset[str] = frozenset({"synonym", "severity", "framing"})


@dataclass(frozen=True)
class MutatedScenarioPair:
    """A baseline + mutated scenario pair, with operator provenance.

    Construction validates the skeleton invariant in ``__post_init__``;
    a violation raises :class:`SkeletonInvariantError`. There is no
    silent normalization — bad pairs are rejected at the type boundary.

    Invariants enforced:
        1. Both scenarios share the same ``skeleton_hash``.
        2. Both scenarios have the same fact count.
        3. For every Fact, ``(fact_id, field, entity_id, source_type,
           timestamp)`` is byte-identical between baseline and mutated.
        4. At least one Fact's ``value_hash`` differs (else the
           operator was a no-op and the pair is meaningless).
    """

    baseline_scenario: BenchmarkScenario
    mutated_scenario: BenchmarkScenario
    operator_applied: MutationOperator
    skeleton_hash: str
    mutation_record: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if not isinstance(self.mutation_record, tuple):
            raise TypeError(
                "mutation_record must be a tuple, "
                f"got {type(self.mutation_record).__name__}"
            )

        baseline_pkt = self.baseline_scenario.packet
        mutated_pkt = self.mutated_scenario.packet

        # Invariant 1: skeleton hash equality.
        b_hash = skeleton_hash(baseline_pkt)
        m_hash = skeleton_hash(mutated_pkt)
        if b_hash != m_hash:
            raise SkeletonInvariantError(
                f"skeleton hash diverged: baseline={b_hash} mutated={m_hash}"
            )
        if self.skeleton_hash != b_hash:
            raise SkeletonInvariantError(
                f"recorded skeleton_hash {self.skeleton_hash} disagrees "
                f"with computed hash {b_hash}"
            )

        # Invariant 2: same fact count.
        if baseline_pkt.fact_count != mutated_pkt.fact_count:
            raise SkeletonInvariantError(
                f"fact count diverged: baseline={baseline_pkt.fact_count} "
                f"mutated={mutated_pkt.fact_count}"
            )

        # Invariant 3: byte-identical typed-field tuples per Fact.
        baseline_facts = {f.fact_id: f for f in baseline_pkt.get_all_facts()}
        mutated_facts = {f.fact_id: f for f in mutated_pkt.get_all_facts()}
        if set(baseline_facts.keys()) != set(mutated_facts.keys()):
            raise SkeletonInvariantError(
                "fact_id sets diverged between baseline and mutated"
            )

        any_value_changed = False
        for fid, b_fact in baseline_facts.items():
            m_fact = mutated_facts[fid]
            if b_fact.field != m_fact.field:
                raise SkeletonInvariantError(
                    f"{fid}: field changed {b_fact.field!r} -> {m_fact.field!r}"
                )
            if b_fact.entity_id != m_fact.entity_id:
                raise SkeletonInvariantError(
                    f"{fid}: entity_id changed {b_fact.entity_id!r} -> "
                    f"{m_fact.entity_id!r}"
                )
            if b_fact.entity_type != m_fact.entity_type:
                raise SkeletonInvariantError(
                    f"{fid}: entity_type changed {b_fact.entity_type!r} -> "
                    f"{m_fact.entity_type!r}"
                )
            if (
                b_fact.provenance.source_type
                != m_fact.provenance.source_type
            ):
                raise SkeletonInvariantError(
                    f"{fid}: source_type changed "
                    f"{b_fact.provenance.source_type!r} -> "
                    f"{m_fact.provenance.source_type!r}"
                )
            if b_fact.timestamp != m_fact.timestamp:
                raise SkeletonInvariantError(
                    f"{fid}: timestamp changed {b_fact.timestamp.isoformat()} "
                    f"-> {m_fact.timestamp.isoformat()}"
                )
            if b_fact.value_hash != m_fact.value_hash:
                any_value_changed = True

        # Invariant 4: at least one value_hash differs (no-op rejection).
        if not any_value_changed:
            raise SkeletonInvariantError(
                "no Fact value_hash differs between baseline and mutated; "
                "operator produced a no-op pair"
            )


# ---------------------------------------------------------------------------
# Mutation primitives
# ---------------------------------------------------------------------------


def _rebuild_packet_with_values(
    source_packet: EvidencePacket,
    new_values_by_fact_id: dict[str, str],
) -> EvidencePacket:
    """Construct a new EvidencePacket where named facts have new values.

    Preserves every other Fact attribute byte-for-byte, including
    ``timestamp`` and the ``Provenance`` object (same identity-preserving
    construction). Returns a freshly-frozen packet with a new packet_id
    suffix to avoid hash-collision noise.

    Args:
        source_packet: The frozen source packet.
        new_values_by_fact_id: Mapping fact_id -> new value. Only
            entries present in this mapping are replaced; unlisted facts
            are copied verbatim. fact_ids not in the source raise.

    Returns:
        A frozen EvidencePacket with the same skeleton.
    """
    new_packet = EvidencePacket(
        packet_id=f"{source_packet.packet_id}__mutated",
        time_window=TimeWindow(
            start=source_packet.time_window.start,
            end=source_packet.time_window.end,
        ),
    )
    for fact in source_packet.get_all_facts():
        new_value = new_values_by_fact_id.get(fact.fact_id, fact.value)
        new_fact = Fact(
            fact_id=fact.fact_id,
            entity_id=fact.entity_id,
            entity_type=fact.entity_type,
            field=fact.field,
            value=new_value,
            timestamp=fact.timestamp,
            provenance=fact.provenance,
        )
        new_packet.add_fact(new_fact)
    new_packet.freeze()

    # Detect mistyped fact_ids in the input mapping.
    unknown = set(new_values_by_fact_id) - set(new_packet.fact_ids)
    if unknown:
        raise KeyError(
            f"new_values_by_fact_id references unknown fact_ids: "
            f"{sorted(unknown)}"
        )
    return new_packet


def _apply_value_replacements(
    scenario: BenchmarkScenario,
    new_values_by_fact_id: dict[str, str],
) -> BenchmarkScenario:
    """Build a new BenchmarkScenario with named facts' values replaced.

    Returns the scenario unchanged when ``new_values_by_fact_id`` is
    empty.
    """
    if not new_values_by_fact_id:
        return scenario
    new_packet = _rebuild_packet_with_values(
        scenario.packet, new_values_by_fact_id
    )
    return BenchmarkScenario(metadata=scenario.metadata, packet=new_packet)


# ---------------------------------------------------------------------------
# Lexicons / tables (v1 — reproducibility-locked)
# ---------------------------------------------------------------------------


# Conservative synonym map: replace ~1-3 content words. Keys must match
# whole-word, case-insensitive (handled in the operator).
SYNONYM_LEXICON_V1: dict[str, str] = {
    # nouns
    "session": "instance",
    "logon": "sign-on",
    "transfer": "movement",
    "upload": "outbound transfer",
    "agent": "client",
    "endpoint": "host",
    "operator": "principal",
    "investigation": "review",
    # verbs / verb forms
    "delivered": "supplied",
    "applied": "installed",
    "performed": "executed",
    "downloading": "retrieving",
    "spawned": "launched",
    "loading": "loading in",
    "approved": "sanctioned",
    "scheduled": "planned",
    "initiates": "opens",
    # adjectives
    "remote": "off-site",
    "standard": "routine",
    "managed": "supervised",
    "ongoing": "continuing",
    "first": "initially",
    "covered": "addressed",
}


# Severity intensifier table: shifts language toward stronger claim.
SEVERITY_INTENSIFIER_TABLE_V1: dict[str, str] = {
    "may": "is",
    "might": "is",
    "could": "does",
    "appears to": "definitively",
    "appears to be": "is",
    "possibly": "definitively",
    "preliminary": "confirmed",
    "suspicious": "highly suspicious",
    "anomalous": "highly anomalous",
    "unusual": "alarming",
    "potential": "active",
    "likely": "certain",
    "indicates": "proves",
}


# Severity decreaser table: shifts language toward weaker claim.
SEVERITY_DECREASER_TABLE_V1: dict[str, str] = {
    "is": "appears to be",
    "confirmed": "possibly",
    "definitively": "tentatively",
    "highly suspicious": "somewhat suspicious",
    "highly anomalous": "mildly anomalous",
    "alarming": "noteworthy",
    "active": "potential",
    "certain": "possible",
    "proves": "may indicate",
    "definitively malicious": "potentially malicious",
}


# Framing wrappers: prepend / append at the value-text boundary.
FRAMING_PREFIX_V1: str = "According to internal review, "
FRAMING_SUFFIX_V1: str = " This finding is preliminary."


# ---------------------------------------------------------------------------
# Operator implementations
# ---------------------------------------------------------------------------


def _is_mutable_value(value: object) -> bool:
    """A value is mutable for v1 operators iff it is a non-empty str."""
    return isinstance(value, str) and len(value) > 0


def _select_facts_with_string_values(
    scenario: BenchmarkScenario,
) -> list[Fact]:
    """Return facts whose value is a non-empty string, sorted by fact_id."""
    return sorted(
        (f for f in scenario.packet.get_all_facts() if _is_mutable_value(f.value)),
        key=lambda f: f.fact_id,
    )


def _whole_word_replace_first(
    text: str, source: str, target: str
) -> tuple[str, bool]:
    """Replace the first whole-word occurrence of ``source`` in ``text``.

    Case-insensitive match. Replacement is verbatim ``target``. Returns
    ``(new_text, did_replace)``.
    """
    pattern = re.compile(rf"\b{re.escape(source)}\b", re.IGNORECASE)
    match = pattern.search(text)
    if not match:
        return text, False
    start, end = match.span()
    return text[:start] + target + text[end:], True


def _synonym_substitution(
    scenario: BenchmarkScenario,
    seed: int,
    *,
    min_replacements: int,
    max_replacements: int,
) -> BenchmarkScenario:
    """Replace 1-N content words across the scenario's string values.

    Word selection is seed-deterministic. Replaces at most one whole-
    word occurrence per source word per fact, advancing through facts
    in fact_id order. Stops when ``max_replacements`` mutations are
    applied or the lexicon is exhausted.
    """
    rng = random.Random(seed)
    target_count = rng.randint(min_replacements, max_replacements)

    facts = _select_facts_with_string_values(scenario)
    if not facts:
        return scenario

    # Stable iteration order over lexicon keys.
    candidate_words = list(SYNONYM_LEXICON_V1.keys())
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
            text, did = _whole_word_replace_first(
                text, word, SYNONYM_LEXICON_V1[word]
            )
            if did:
                replacements_done += 1
        if text != original_text:
            new_values[fact.fact_id] = text

    return _apply_value_replacements(scenario, new_values)


def synonym_substitution_conservative_transform(
    scenario: BenchmarkScenario, seed: int
) -> BenchmarkScenario:
    return _synonym_substitution(
        scenario, seed, min_replacements=1, max_replacements=3
    )


def synonym_substitution_aggressive_transform(
    scenario: BenchmarkScenario, seed: int
) -> BenchmarkScenario:
    return _synonym_substitution(
        scenario, seed, min_replacements=4, max_replacements=8
    )


def _table_substitution(
    scenario: BenchmarkScenario,
    table: dict[str, str],
) -> BenchmarkScenario:
    """Apply a fixed substitution table to every string value in order.

    Each table entry is applied at most once per fact (first whole-word
    occurrence). Iteration order is fact_id-sorted, then table-key-
    sorted by descending length so longer phrases substitute before
    their substrings.
    """
    facts = _select_facts_with_string_values(scenario)
    if not facts:
        return scenario

    ordered_keys = sorted(table.keys(), key=lambda k: (-len(k), k))

    new_values: dict[str, str] = {}
    for fact in facts:
        text = str(fact.value)
        original_text = text
        for key in ordered_keys:
            text, _did = _whole_word_replace_first(text, key, table[key])
        if text != original_text:
            new_values[fact.fact_id] = text

    return _apply_value_replacements(scenario, new_values)


def severity_intensifier_transform(
    scenario: BenchmarkScenario, seed: int
) -> BenchmarkScenario:
    # seed is unused (operator is fully deterministic from table); kept
    # for signature uniformity.
    _ = seed
    return _table_substitution(scenario, SEVERITY_INTENSIFIER_TABLE_V1)


def severity_decreaser_transform(
    scenario: BenchmarkScenario, seed: int
) -> BenchmarkScenario:
    _ = seed
    return _table_substitution(scenario, SEVERITY_DECREASER_TABLE_V1)


def _framing_wrap(
    scenario: BenchmarkScenario,
    *,
    prefix: str = "",
    suffix: str = "",
) -> BenchmarkScenario:
    """Wrap every string-valued fact with prefix/suffix.

    Wrapping is unconditional on string values; on a corpus with no
    string-valued facts the returned scenario is unchanged (no-op).
    """
    facts = _select_facts_with_string_values(scenario)
    if not facts:
        return scenario
    new_values: dict[str, str] = {}
    for fact in facts:
        text = str(fact.value)
        wrapped = f"{prefix}{text}{suffix}"
        if wrapped != text:
            new_values[fact.fact_id] = wrapped
    return _apply_value_replacements(scenario, new_values)


def framing_prefix_transform(
    scenario: BenchmarkScenario, seed: int
) -> BenchmarkScenario:
    _ = seed
    return _framing_wrap(scenario, prefix=FRAMING_PREFIX_V1)


def framing_suffix_transform(
    scenario: BenchmarkScenario, seed: int
) -> BenchmarkScenario:
    _ = seed
    return _framing_wrap(scenario, suffix=FRAMING_SUFFIX_V1)


# ---------------------------------------------------------------------------
# Operator registry (v1)
# ---------------------------------------------------------------------------


OPERATORS_V1: tuple[MutationOperator, ...] = (
    MutationOperator(
        operator_name="synonym_substitution_conservative_v1",
        family="synonym",
        description="Replace 1-3 content words from a fixed lexicon.",
        transform=synonym_substitution_conservative_transform,
    ),
    MutationOperator(
        operator_name="synonym_substitution_aggressive_v1",
        family="synonym",
        description="Replace 4-8 content words from a fixed lexicon.",
        transform=synonym_substitution_aggressive_transform,
    ),
    MutationOperator(
        operator_name="severity_intensifier_v1",
        family="severity",
        description="Apply severity-escalation substitution table.",
        transform=severity_intensifier_transform,
    ),
    MutationOperator(
        operator_name="severity_decreaser_v1",
        family="severity",
        description="Apply severity-de-escalation substitution table.",
        transform=severity_decreaser_transform,
    ),
    MutationOperator(
        operator_name="framing_prefix_v1",
        family="framing",
        description="Prepend a fixed framing wrapper to every string value.",
        transform=framing_prefix_transform,
    ),
    MutationOperator(
        operator_name="framing_suffix_v1",
        family="framing",
        description="Append a fixed framing wrapper to every string value.",
        transform=framing_suffix_transform,
    ),
)


# ---------------------------------------------------------------------------
# Mutator
# ---------------------------------------------------------------------------


class PairedScenarioMutator:
    """Apply registered MutationOperators to a baseline scenario.

    Deterministic given a fixed seed. No LLM calls. No network I/O.
    """

    def __init__(
        self,
        operators: tuple[MutationOperator, ...] = OPERATORS_V1,
        seed: int = 0,
    ) -> None:
        if not operators:
            raise ValueError("operators must be non-empty")
        names = [op.operator_name for op in operators]
        if len(set(names)) != len(names):
            raise ValueError(
                f"operator names must be unique; got duplicates in {names}"
            )
        self._operators: tuple[MutationOperator, ...] = operators
        self._by_name: dict[str, MutationOperator] = {
            op.operator_name: op for op in operators
        }
        self._seed: int = seed

    @property
    def operators(self) -> tuple[MutationOperator, ...]:
        return self._operators

    @property
    def seed(self) -> int:
        return self._seed

    def operator_names(self) -> tuple[str, ...]:
        return tuple(op.operator_name for op in self._operators)

    def mutate(
        self,
        baseline: BenchmarkScenario,
        operator_name: str,
    ) -> MutatedScenarioPair:
        """Apply named operator to baseline.

        Raises:
            KeyError: If ``operator_name`` is not registered.
            SkeletonInvariantError: If the resulting pair violates
                skeleton invariance (operator implementation bug) or is
                a no-op (no Fact value changed).
        """
        if operator_name not in self._by_name:
            raise KeyError(
                f"operator_name {operator_name!r} not registered; "
                f"known: {sorted(self._by_name)}"
            )
        operator = self._by_name[operator_name]
        mutated = operator.transform(baseline, self._seed)

        baseline_facts = {f.fact_id: f for f in baseline.packet.get_all_facts()}
        mutated_facts = {f.fact_id: f for f in mutated.packet.get_all_facts()}
        touched = tuple(
            sorted(
                fid
                for fid in baseline_facts
                if fid in mutated_facts
                and baseline_facts[fid].value_hash
                != mutated_facts[fid].value_hash
            )
        )

        return MutatedScenarioPair(
            baseline_scenario=baseline,
            mutated_scenario=mutated,
            operator_applied=operator,
            skeleton_hash=skeleton_hash(baseline.packet),
            mutation_record=touched,
        )

    def mutate_all(
        self,
        baseline: BenchmarkScenario,
    ) -> tuple[MutatedScenarioPair, ...]:
        """Apply every registered operator to baseline.

        Skips operators whose output equals baseline (no Fact value
        changed) — these are silent no-ops, not failures. Returns the
        valid pairs in operator-registration order.
        """
        pairs: list[MutatedScenarioPair] = []
        for operator in self._operators:
            try:
                pair = self.mutate(baseline, operator.operator_name)
            except SkeletonInvariantError as exc:
                msg = str(exc)
                if "no Fact value_hash differs" in msg:
                    # No-op for this operator on this scenario; skip silently.
                    continue
                raise
            pairs.append(pair)
        return tuple(pairs)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


__all__ = [
    "FRAMING_PREFIX_V1",
    "FRAMING_SUFFIX_V1",
    "MutatedScenarioPair",
    "MutationOperator",
    "OPERATORS_V1",
    "PairedScenarioMutator",
    "SEVERITY_DECREASER_TABLE_V1",
    "SEVERITY_INTENSIFIER_TABLE_V1",
    "SYNONYM_LEXICON_V1",
    "SkeletonInvariantError",
    "framing_prefix_transform",
    "framing_suffix_transform",
    "severity_decreaser_transform",
    "severity_intensifier_transform",
    "synonym_substitution_aggressive_transform",
    "synonym_substitution_conservative_transform",
]
