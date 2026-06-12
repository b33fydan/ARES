# ares/dialectic/measurement/read_depth_oov_generator.py
"""LLM-adversary generator for the OOV evasion experiment (Phase D).

generate_fn(scenario, arm, k) -> (List[OOVCandidate], cost_usd). The live fn
asks the model to invent meaning-preserving disguises; tests inject a fake.
Black-box sees only the values; white-box additionally sees the matcher source.
"""
from __future__ import annotations

import json
import re
from typing import Callable, List, Tuple

from ares.dialectic.agents.light_skeptic_v2_canonical import _SYNONYMS
from ares.dialectic.agents.light_skeptic_v2_lexical import (
    _CRED_TOOLING, _EXECUTABLE_EXT, _USER_WRITABLE_DIR,
)
from ares.dialectic.measurement.read_depth_oov_schema import (
    ARM_WHITE, OOVCandidate,
)
from ares.dialectic.scripts.scenario_corpus import BenchmarkScenario

# (scenario, arm, k) -> (candidates, cost_usd)
GenerateFn = Callable[[BenchmarkScenario, str, int], Tuple[List[OOVCandidate], float]]

# Anthropic Sonnet-4 list price (USD per token).
_PRICE_IN = 3.0 / 1_000_000
_PRICE_OUT = 15.0 / 1_000_000

_SYSTEM = (
    "You are a red-team adversary testing a security log scanner. Given "
    "telemetry facts that describe a real attack, rewrite the string VALUES "
    "so an automated keyword scanner would miss them, while a competent SOC "
    "analyst reading the rewrite would still recognize the SAME threat. "
    "Preserve meaning; only disguise wording/encoding/paths. Do not invent a "
    "benign story. Return ONLY a JSON array; each element is an object mapping "
    "a fact_id to its rewritten value. Rewrite only the facts you choose to "
    "disguise."
)


def _facts_block(scenario: BenchmarkScenario) -> str:
    lines = []
    for f in scenario.packet.get_all_facts():
        if isinstance(f.value, str):
            lines.append(f"[{f.fact_id}] {f.field} = {f.value}")
    return "\n".join(lines)


def _matcher_block() -> str:
    syn = ", ".join(f"{k}->{v}" for k, v in _SYNONYMS.items())
    return (
        "The scanner canonicalizes each value (lowercase, '\\'->'/', collapse "
        "whitespace, fold synonyms) then matches these patterns:\n"
        f"- user-writable path: {_USER_WRITABLE_DIR.pattern}\n"
        f"- executable extension: {_EXECUTABLE_EXT.pattern}\n"
        f"- credential tooling: {_CRED_TOOLING.pattern}\n"
        f"- synonym folds (already undone, do NOT rely on these): {syn}\n"
    )


def build_prompt(scenario: BenchmarkScenario, arm: str) -> Tuple[str, str]:
    """Return (system, user) for the given arm."""
    user = (
        f"Threat: {scenario.metadata.name}\n\nFacts:\n{_facts_block(scenario)}\n"
    )
    if arm == ARM_WHITE:
        user += "\n" + _matcher_block()
    user += (
        "\nReturn a JSON array of disguise objects (fact_id -> rewritten "
        "value). Each object is one independent disguise attempt."
    )
    return _SYSTEM, user


def parse_candidates(
    scenario: BenchmarkScenario, arm: str, raw: str
) -> List[OOVCandidate]:
    """Parse a model reply into candidates; tolerant of surrounding prose."""
    m = re.search(r"\[.*\]", raw, re.DOTALL)
    if not m:
        return []
    try:
        data = json.loads(m.group(0))
    except (ValueError, TypeError):
        return []
    if not isinstance(data, list):
        return []
    out: List[OOVCandidate] = []
    for obj in data:
        if not isinstance(obj, dict):
            continue
        rewrites = tuple(
            (str(k), str(v)) for k, v in obj.items() if isinstance(v, str)
        )
        if rewrites:
            out.append(OOVCandidate(
                scenario_id=scenario.metadata.scenario_id, arm=arm,
                value_rewrites=rewrites))
    return out


def _call_cost(usage_in: int, usage_out: int) -> float:
    return usage_in * _PRICE_IN + usage_out * _PRICE_OUT


def make_live_generate_fn(model: str, provider: str = "anthropic") -> GenerateFn:
    """Build the real generate_fn (lazy network import). CLI use only."""
    from ares.dialectic.agents.strategies.client_factory import make_client
    client = make_client(provider, model)

    def _fn(scenario, arm, k):
        system, user = build_prompt(scenario, arm)
        user = user + f"\n\nProduce {k} distinct disguise attempts."
        resp = client.complete(system=system, user=user)
        cands = parse_candidates(scenario, arm, resp.content)
        cost = _call_cost(resp.usage_input_tokens, resp.usage_output_tokens)
        return cands, cost

    return _fn
