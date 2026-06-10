# ares/dialectic/measurement/read_depth_tier4_anchor.py
"""Tier-4 LLM anchor runner for the read-depth frontier (Phase C).

cycle_fn(scenario, operator_name, is_baseline, resample_index) -> (malign, cost).
The default live cycle_fn wraps leakage_runner._run_one_cycle (pipeline="llm")
and maps final_outcome == "threat_confirmed" -> malign. Tests inject a mock.
The deterministic tiers run alongside (free) to build the cumulative view.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple

from ares.dialectic.agents.light_skeptic_v2_ladder import (
    DETERMINISTIC_TIERS, LADDER_ORDER,
)
from ares.dialectic.measurement.read_depth_corpus import (
    ALL_ENTRIES, BENIGN_ENTRIES, MALIGN_ENTRIES, corpus_digest,
)
from ares.dialectic.measurement.read_depth_frontier_metrics import (
    is_malign_verdict, tpr_fpr, youden_j, flip_rate,
)
from ares.dialectic.measurement.read_depth_tier4_metrics import (
    bootstrap_flip_rate_ci, flip_decision, majority_malign,
)
from ares.dialectic.measurement.read_depth_tier4_schema import (
    Tier4Coordinate, Tier4OperatorRecord, Tier4ScenarioRecord, Tier4Summary,
)
from ares.dialectic.measurement.read_depth_frontier_runner import (
    _SEMANTIC_OPERATORS, _mutate_variants, _neutral_architect,
)

CycleFn = Callable[[object, Optional[str], bool, int], Tuple[bool, float]]
_DEFAULT_MODEL = "claude-sonnet-4-20250514"
_DET_TIER_IDS = tuple(t for t in LADDER_ORDER if t in DETERMINISTIC_TIERS)


@dataclass(frozen=True)
class Tier4Config:
    k_resamples: int = 20
    seed: int = 0
    model: str = _DEFAULT_MODEL
    provider: str = "anthropic"


def estimate_cost_usd(cfg: Tier4Config, *, per_cycle_usd: float = 0.0144) -> float:
    n_ops = len(_SEMANTIC_OPERATORS)
    malign_cycles = len(MALIGN_ENTRIES) * (1 + n_ops) * cfg.k_resamples
    benign_cycles = len(BENIGN_ENTRIES) * 1 * cfg.k_resamples
    return round((malign_cycles + benign_cycles) * per_cycle_usd, 4)


def _det_or(scenario) -> bool:
    """OR of the four deterministic standalone malign verdicts (op-point 0)."""
    arch = _neutral_architect()
    return any(is_malign_verdict(DETERMINISTIC_TIERS[t](scenario.packet, arch), 0.0)
               for t in _DET_TIER_IDS)


def _resample(scenario, operator_name, is_baseline, cfg, cycle_fn) -> Tuple[List[bool], float]:
    verdicts, cost = [], 0.0
    for r in range(cfg.k_resamples):
        mal, c = cycle_fn(scenario, operator_name, is_baseline, r)
        verdicts.append(bool(mal))
        cost += float(c)
    return verdicts, cost


def run_tier4_anchor(cfg: Tier4Config, *, cycle_fn: CycleFn) -> Tier4Summary:
    total_cost = 0.0
    # Baselines for every scenario (LLM standalone + deterministic OR).
    base_llm: Dict[str, List[bool]] = {}
    det_or: Dict[str, bool] = {}
    for e in ALL_ENTRIES:
        v, c = _resample(e.scenario, None, True, cfg, cycle_fn)
        base_llm[e.scenario_id] = v
        det_or[e.scenario_id] = _det_or(e.scenario)
        total_cost += c

    # Per-malign-scenario framing perturbations (flip cells per view).
    records: List[Tier4ScenarioRecord] = []
    cells: Dict[str, List[bool]] = {"standalone": [], "cumulative": []}
    for e in MALIGN_ENTRIES:
        op_recs: List[Tier4OperatorRecord] = []
        variants = _mutate_variants(e.scenario, _SEMANTIC_OPERATORS, cfg.seed)
        op_names = [op.operator_name for op in _SEMANTIC_OPERATORS][: len(variants)]
        b = base_llm[e.scenario_id]
        for op_name, variant in zip(op_names, variants):
            pv, c = _resample(variant, op_name, False, cfg, cycle_fn)
            total_cost += c
            flipped_sa, p = flip_decision(b, pv, seed=cfg.seed)
            cells["standalone"].append(flipped_sa)
            # cumulative: OR with the (framing-invariant) deterministic verdict
            base_cum = [x or det_or[e.scenario_id] for x in b]
            pert_cum = [x or det_or[e.scenario_id] for x in pv]
            flipped_cum, _ = flip_decision(base_cum, pert_cum, seed=cfg.seed)
            cells["cumulative"].append(flipped_cum)
            op_recs.append(Tier4OperatorRecord(
                operator_name=op_name, perturbed_malign_rate=majority_malign(pv) and 1.0 or 0.0,
                flipped=flipped_sa, p_value=p, n_resamples=cfg.k_resamples))
        records.append(Tier4ScenarioRecord(
            scenario_id=e.scenario_id, is_malign=True, stratum=e.stratum,
            baseline_malign_rate=sum(b) / len(b),
            baseline_majority_malign=majority_malign(b), operator_records=tuple(op_recs)))

    coordinates: List[Tier4Coordinate] = []
    for view in ("standalone", "cumulative"):
        mal_v, ben_v = [], []
        for e in MALIGN_ENTRIES:
            m = majority_malign(base_llm[e.scenario_id])
            mal_v.append(m or det_or[e.scenario_id] if view == "cumulative" else m)
        for e in BENIGN_ENTRIES:
            m = majority_malign(base_llm[e.scenario_id])
            ben_v.append(m or det_or[e.scenario_id] if view == "cumulative" else m)
        tpr, fpr = tpr_fpr(mal_v, ben_v)
        flips = cells[view]
        x = flip_rate(len(flips), sum(1 for f in flips if f))
        lo, hi = bootstrap_flip_rate_ci(flips, seed=cfg.seed)
        coordinates.append(Tier4Coordinate(
            tier_id="llm_semantic", view=view, x_semantic=x,
            x_semantic_ci_low=lo, x_semantic_ci_high=hi, tpr=tpr, fpr=fpr,
            youden_j=youden_j(tpr, fpr), n_malign=len(MALIGN_ENTRIES),
            n_benign=len(BENIGN_ENTRIES), k_resamples=cfg.k_resamples,
            model=cfg.model, provider=cfg.provider))

    return Tier4Summary(
        coordinates=tuple(coordinates), records=tuple(records),
        corpus_digest=corpus_digest(), total_cost_usd=round(total_cost, 4),
        model=cfg.model, provider=cfg.provider, k_resamples=cfg.k_resamples)


def make_live_cycle_fn(cfg: Tier4Config) -> CycleFn:
    """Build the real cycle_fn (lazy network import). Used only by the CLI."""
    from ares.dialectic.agents.strategies.client_factory import make_client
    from ares.dialectic.measurement.leakage_runner import _run_one_cycle
    client = make_client(cfg.provider, cfg.model)
    counter = {"n": 0}

    def _fn(scenario, operator_name, is_baseline, resample_index):
        counter["n"] += 1
        trace, cost = _run_one_cycle(
            scenario=scenario, pipeline="llm", client=client,
            cycle_id=f"tier4-{counter['n']}", pair_index=resample_index,
            is_baseline=is_baseline, operator_name=operator_name)
        return (trace.final_outcome == "threat_confirmed"), cost

    return _fn
