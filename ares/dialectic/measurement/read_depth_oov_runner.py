# ares/dialectic/measurement/read_depth_oov_runner.py
"""Offline orchestrator for the OOV evasion experiment (Phase D).

generate -> validate -> freeze accepted corpus -> measure flips on the string
tiers -> classify. The LLM is reached only via injected generate_fn / judge_fn;
all flip measurement and the verdict are deterministic.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Tuple

from ares.dialectic.agents.light_skeptic_v2_ladder import DETERMINISTIC_TIERS
from ares.dialectic.measurement.read_depth_corpus import (
    MALIGN_ENTRIES, corpus_digest,
)
from ares.dialectic.measurement.read_depth_frontier_metrics import (
    flip_rate, is_malign_verdict,
)
from ares.dialectic.measurement.read_depth_frontier_runner import (
    _neutral_architect,
)
from ares.dialectic.measurement.read_depth_oov_generator import GenerateFn
from ares.dialectic.measurement.read_depth_oov_schema import (
    ARMS, OOVArmSummary, OOVCandidate, OOVEvasionRecord, OOVFrontierSummary,
    classify_oov_verdict, oov_corpus_digest,
)
from ares.dialectic.measurement.read_depth_oov_validator import (
    JudgeFn, apply_candidate, validate_candidate,
)

_DEFAULT_MODEL = "claude-sonnet-4-20250514"


@dataclass(frozen=True)
class OOVConfig:
    k: int = 8
    seed: int = 0
    model: str = _DEFAULT_MODEL
    provider: str = "anthropic"
    arms: Tuple[str, ...] = ARMS


def estimate_cost_usd(cfg: OOVConfig, *, per_call_usd: float = 0.02) -> float:
    """Upper-bound estimate: one generation call per (arm, scenario) plus up to
    k judge calls per (arm, scenario)."""
    n_gen = len(cfg.arms) * len(MALIGN_ENTRIES)
    n_judge = len(cfg.arms) * len(MALIGN_ENTRIES) * cfg.k
    return round((n_gen + n_judge) * per_call_usd, 4)


def run_preflight(cfg: OOVConfig) -> Dict[str, object]:
    return {"estimate_usd": estimate_cost_usd(cfg),
            "corpus_digest": corpus_digest(),
            "n_malign": len(MALIGN_ENTRIES), "arms": list(cfg.arms), "k": cfg.k}


def _is_malign(tier_fn, packet, arch) -> bool:
    return is_malign_verdict(tier_fn(packet, arch), 0.0)


def run_oov_experiment(
    cfg: OOVConfig, *, generate_fn: GenerateFn, judge_fn: JudgeFn
) -> OOVFrontierSummary:
    arch = _neutral_architect()
    canonical = DETERMINISTIC_TIERS["v2_canonical"]
    lexical = DETERMINISTIC_TIERS["v2_lexical"]

    total_cost = 0.0
    accepted_all: List[OOVCandidate] = []
    records: List[OOVEvasionRecord] = []
    arm_summaries: List[OOVArmSummary] = []

    for arm in cfg.arms:
        n_cand = n_acc = n_rej_sk = n_rej_nov = n_rej_judge = 0
        evaded: set = set()
        arm_flips = 0
        for e in MALIGN_ENTRIES:
            cands, gcost = generate_fn(e.scenario, arm, cfg.k)
            total_cost += gcost
            n_cand += len(cands)
            base_canon = _is_malign(canonical, e.scenario.packet, arch)
            base_lex = _is_malign(lexical, e.scenario.packet, arch)
            for cand in cands:
                res, vcost = validate_candidate(e.scenario, cand, judge_fn)
                total_cost += vcost
                if not res.accepted:
                    if not res.skeleton_ok:
                        n_rej_sk += 1
                    elif not res.novel:
                        n_rej_nov += 1
                    else:
                        n_rej_judge += 1
                    continue
                n_acc += 1
                accepted_all.append(cand)
                evaded_sc = apply_candidate(e.scenario, cand)
                canon_flip = base_canon and not _is_malign(
                    canonical, evaded_sc.packet, arch)
                lex_flip = base_lex and not _is_malign(
                    lexical, evaded_sc.packet, arch)
                if canon_flip:
                    evaded.add(e.scenario_id)
                    arm_flips += 1
                records.append(OOVEvasionRecord(
                    e.scenario_id, arm, canon_flip, lex_flip))
        arm_summaries.append(OOVArmSummary(
            arm=arm, n_candidates=n_cand, n_accepted=n_acc,
            n_rejected_skeleton=n_rej_sk, n_rejected_novelty=n_rej_nov,
            n_rejected_judge=n_rej_judge,
            scenarios_evaded=tuple(sorted(evaded)),
            adversarial_x_scenario=flip_rate(len(MALIGN_ENTRIES), len(evaded)),
            per_candidate_flip_rate=flip_rate(n_acc, arm_flips),
            n_malign_scenarios=len(MALIGN_ENTRIES)))

    verdict = classify_oov_verdict(tuple(arm_summaries))
    return OOVFrontierSummary(
        arm_summaries=tuple(arm_summaries), records=tuple(records),
        verdict=verdict, corpus_digest=corpus_digest(),
        oov_corpus_digest=oov_corpus_digest(tuple(accepted_all)),
        total_cost_usd=round(total_cost, 4), model=cfg.model,
        provider=cfg.provider, k=cfg.k)
