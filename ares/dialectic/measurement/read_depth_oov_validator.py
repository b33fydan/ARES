# ares/dialectic/measurement/read_depth_oov_validator.py
"""Deterministic validity gate + LLM-judge orchestration (Phase D).

A candidate is ACCEPTED iff it (1) only rewrites existing facts' values
preserving the skeleton and is not a no-op, (2) is NOVEL (its new tokens are
not merely the canonicalizer's own synonym words), and (3) the LLM-judge
confirms it is still the same threat. Only (3) costs API; (1)-(2) are free.
"""
from __future__ import annotations

import re
from typing import Callable, Tuple

from ares.dialectic.agents.light_skeptic_v2_canonical import _SYNONYMS
from ares.dialectic.measurement.read_depth_oov_schema import (
    OOVCandidate, OOVValidationResult,
)
from ares.dialectic.schemas.skeleton_equivalence import skeleton_hash
from ares.dialectic.scripts.non_interference.paired_scenario_mutator import (
    MutationOperator, MutatedScenarioPair, SkeletonInvariantError,
    _apply_value_replacements,
)
from ares.dialectic.scripts.scenario_corpus import BenchmarkScenario

# (original_scenario, evaded_scenario) -> (still_malign, cost_usd)
JudgeFn = Callable[[BenchmarkScenario, BenchmarkScenario], Tuple[bool, float]]

_PRICE_IN = 3.0 / 1_000_000
_PRICE_OUT = 15.0 / 1_000_000


class CostCeilingExceeded(RuntimeError):
    """Raised mid-run when accumulated live cost crosses the configured ceiling."""


# List-price approximations (USD per token). The cost ceiling is a safety bound,
# not a billing system; these need only be reasonable and provider-distinct.
# (price_in_per_token, price_out_per_token)
PRICE_TABLE: dict[str, tuple[float, float]] = {
    "anthropic": (_PRICE_IN, _PRICE_OUT),
    "openai": (2.5 / 1_000_000, 10.0 / 1_000_000),
    "gemini": (1.25 / 1_000_000, 10.0 / 1_000_000),
}


def cost_for(provider: str, usage_in: int, usage_out: int) -> float:
    """Provider-aware token cost. Unknown provider raises (never silent mis-cost)."""
    if provider not in PRICE_TABLE:
        raise ValueError(
            f"no price for provider {provider!r}; known: {sorted(PRICE_TABLE)}")
    price_in, price_out = PRICE_TABLE[provider]
    return usage_in * price_in + usage_out * price_out


# Tokens the canonicalizer itself folds; a disguise built only from these is
# the in-vocabulary case S088 already measured, not a new disguise.
_KNOWN_FOLD_VOCAB = set(_SYNONYMS.keys()) | set(_SYNONYMS.values())

_TOKEN = re.compile(r"[a-z0-9]+")

# Validation-only synthetic operator (its transform is never invoked; the pair
# constructor only checks invariants). family must be a valid mutator family.
_SYNTH_OP = MutationOperator(
    operator_name="oov_adversarial_evasion", family="synonym",
    description="LLM-discovered OOV evasion (validation only)",
    transform=lambda s, seed: s,
)


def apply_candidate(
    scenario: BenchmarkScenario, candidate: OOVCandidate
) -> BenchmarkScenario:
    """Apply the candidate's value rewrites. Raises KeyError on unknown ids."""
    return _apply_value_replacements(scenario, candidate.rewrites_dict())


def check_skeleton(
    original: BenchmarkScenario, evaded: BenchmarkScenario
) -> Tuple[bool, str]:
    """True iff the pair preserves the skeleton and changed >= 1 value."""
    try:
        MutatedScenarioPair(
            baseline_scenario=original, mutated_scenario=evaded,
            operator_applied=_SYNTH_OP,
            skeleton_hash=skeleton_hash(original.packet))
    except SkeletonInvariantError as exc:
        return False, str(exc)
    return True, ""


def _tokens(scenario: BenchmarkScenario) -> set:
    out: set = set()
    for f in scenario.packet.get_all_facts():
        if isinstance(f.value, str):  # non-string values (int, bool, …) are skipped
            out.update(_TOKEN.findall(f.value.lower()))
    return out


def is_novel(original: BenchmarkScenario, evaded: BenchmarkScenario) -> bool:
    """Novel unless the only NEW tokens introduced are the canonicalizer's own
    synonym-fold vocabulary.

    A rewrite that introduces NO new tokens at all (pure deletion or reordering)
    is treated as NOVEL on purpose: deletions like dropping '.exe' from
    ``procdump.exe`` -> ``procdump`` are legitimate, meaning-preserving disguises
    that defeat the executable matcher while a human still recognises the threat.
    Those candidates must be forwarded to the judge (not silently rejected here)
    so they are measured.  The gate only excludes the trivial in-vocabulary
    synonym reuse that S088 already measured — i.e. ``introduced`` is non-empty
    AND every new token is already in ``_KNOWN_FOLD_VOCAB``.
    """
    introduced = _tokens(evaded) - _tokens(original)
    if introduced and introduced.issubset(_KNOWN_FOLD_VOCAB):
        return False
    return True


def validate_candidate(
    scenario: BenchmarkScenario, candidate: OOVCandidate, judge_fn: JudgeFn
) -> Tuple[OOVValidationResult, float]:
    """Run the full gate. Returns (result, cost_usd). Judge is only called on
    candidates that pass the free skeleton + novelty gates."""
    try:
        evaded = apply_candidate(scenario, candidate)
    except KeyError as exc:
        return OOVValidationResult(
            candidate, skeleton_ok=False, novel=False, judge_malign=None,
            accepted=False, reject_reason=f"unknown_fact_id: {exc}"), 0.0

    ok, reason = check_skeleton(scenario, evaded)
    if not ok:
        return OOVValidationResult(
            candidate, skeleton_ok=False, novel=False, judge_malign=None,
            accepted=False, reject_reason=f"skeleton: {reason}"), 0.0

    if not is_novel(scenario, evaded):
        return OOVValidationResult(
            candidate, skeleton_ok=True, novel=False, judge_malign=None,
            accepted=False, reject_reason="non_novel_in_vocab"), 0.0

    malign, cost = judge_fn(scenario, evaded)
    accepted = bool(malign)
    return OOVValidationResult(
        candidate, skeleton_ok=True, novel=True, judge_malign=bool(malign),
        accepted=accepted, reject_reason="" if accepted else "judge_benign"), cost


def _call_cost(usage_in: int, usage_out: int) -> float:
    return cost_for("anthropic", usage_in, usage_out)


def make_live_judge_fn(model: str, provider: str = "anthropic") -> JudgeFn:
    """Build the real judge_fn (lazy network import). CLI use only."""
    from ares.dialectic.agents.strategies.client_factory import make_client
    client = make_client(provider, model)
    system = (
        "You are a senior SOC analyst. You will be shown security telemetry "
        "facts. Answer with a single word: YES if they still describe a real "
        "security THREAT (e.g. credential dumping, a dropper in a user-writable "
        "path, an ineffective-patch claim), or NO if they read as benign. "
        "Answer ONLY yes or no."
    )

    def _fn(original, evaded):
        facts = "\n".join(
            f"{f.field} = {f.value}" for f in evaded.packet.get_all_facts()
            if isinstance(f.value, str))
        resp = client.complete(system=system, user=f"Facts:\n{facts}")
        malign = resp.content.strip().lower().startswith("y")
        return malign, cost_for(provider, resp.usage_input_tokens,
                                resp.usage_output_tokens)

    return _fn
