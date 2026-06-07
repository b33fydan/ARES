# ares/dialectic/measurement/read_depth_frontier_runner.py
"""Offline runner for the read-depth robustness frontier (Phase B).

Pure deterministic computation over Adaptive Corpus C and the four deterministic
tiers. No LLM, no network, no cost, no preflight. Emits a FrontierSummary with a
(X_semantic, X_lexical, TPR, FPR, Youden-J) coordinate per tier per view.
"""
from __future__ import annotations

from typing import Dict, List, Tuple

from ares.dialectic.agents.light_skeptic_v2_ladder import (
    DETERMINISTIC_TIERS,
    LADDER_ORDER,
)
from ares.dialectic.measurement.read_depth_corpus import (
    ALL_ENTRIES,
    BENIGN_ENTRIES,
    MALIGN_ENTRIES,
    corpus_digest,
    inject_authorization,
)
from ares.dialectic.measurement.read_depth_evasion_operators import (
    EVASION_OPERATORS,
)
from ares.dialectic.measurement.read_depth_frontier_metrics import (
    cumulative_verdict,
    flip_rate,
    is_malign_verdict,
    tpr_fpr,
    youden_j,
)
from ares.dialectic.measurement.read_depth_frontier_schema import (
    VIEW_CUMULATIVE,
    VIEW_STANDALONE,
    VIEWS,
    FrontierConfig,
    FrontierSummary,
    PositiveControlRecord,
    ScenarioVerdictRecord,
    TierCoordinate,
)
from ares.dialectic.messages.protocol import (
    DialecticalMessage,
    MessageBuilder,
    MessageType,
    Phase,
)
from ares.dialectic.scripts.non_interference.paired_scenario_mutator import (
    OPERATORS_V1,
    MutationOperator,
    PairedScenarioMutator,
    SkeletonInvariantError,
)
from ares.dialectic.scripts.scenario_corpus import BenchmarkScenario

# The deterministic rungs, in ladder order (tier 4 / llm_semantic excluded).
_TIER_IDS: Tuple[str, ...] = tuple(
    t for t in LADDER_ORDER if t in DETERMINISTIC_TIERS
)
# Semantic family = the framing operators from the existing mutator (predicted
# X ~= 0 for substring-matching tiers).
_SEMANTIC_OPERATORS: Tuple[MutationOperator, ...] = tuple(
    op for op in OPERATORS_V1 if op.family == "framing"
)


def _neutral_architect() -> DialecticalMessage:
    """A minimal Architect message; the tiers ignore it (v1 ``_ = arch``)."""
    b = MessageBuilder(source_agent="frontier", packet_id="frontier",
                       cycle_id="frontier")
    b.set_phase(Phase.THESIS).set_type(MessageType.HYPOTHESIS).set_confidence(0.5)
    return b.build()


def _standalone_verdicts(
    scenario: BenchmarkScenario, arch: DialecticalMessage, op_point: float
) -> Dict[str, Tuple[bool, float]]:
    """{tier_id: (malign_verdict, malign_score)} for one scenario."""
    out: Dict[str, Tuple[bool, float]] = {}
    for tier_id in _TIER_IDS:
        j = DETERMINISTIC_TIERS[tier_id](scenario.packet, arch)
        out[tier_id] = (is_malign_verdict(j, op_point), j.malign_score)
    return out


def _cumulative_verdicts(standalone: Dict[str, Tuple[bool, float]]) -> Dict[str, bool]:
    """Cumulative verdict per tier = OR of standalone verdicts up to its depth."""
    out: Dict[str, bool] = {}
    for i, tier_id in enumerate(_TIER_IDS):
        prefix = [standalone[t][0] for t in _TIER_IDS[: i + 1]]
        out[tier_id] = cumulative_verdict(prefix)
    return out


def _verdict_by_view(
    scenario: BenchmarkScenario, arch: DialecticalMessage, op_point: float
) -> Tuple[Dict[str, Dict[str, bool]], Dict[str, Tuple[bool, float]]]:
    """Return ({view: {tier_id: malign_verdict}}, standalone_scores)."""
    standalone = _standalone_verdicts(scenario, arch, op_point)
    cumulative = _cumulative_verdicts(standalone)
    return {
        VIEW_STANDALONE: {t: standalone[t][0] for t in _TIER_IDS},
        VIEW_CUMULATIVE: cumulative,
    }, standalone


def _mutate_variants(
    scenario: BenchmarkScenario,
    operators: Tuple[MutationOperator, ...],
    seed: int,
) -> List[BenchmarkScenario]:
    """Apply each operator; keep only the ones that actually mutated."""
    mut = PairedScenarioMutator(operators=operators, seed=seed)
    variants: List[BenchmarkScenario] = []
    for op in operators:
        try:
            pair = mut.mutate(scenario, op.operator_name)
        except SkeletonInvariantError as exc:
            if "no Fact value_hash differs" in str(exc):
                continue  # no-op on this scenario; excluded from denominator
            raise
        variants.append(pair.mutated_scenario)
    return variants


def run_frontier(config: FrontierConfig | None = None) -> FrontierSummary:
    """Compute the deterministic read-depth frontier over Adaptive Corpus C."""
    if config is None:
        config = FrontierConfig(
            operating_point=0.0,
            semantic_operator_names=tuple(
                op.operator_name for op in _SEMANTIC_OPERATORS
            ),
            lexical_operator_names=tuple(
                op.operator_name for op in EVASION_OPERATORS
            ),
            seed=0,
        )
    arch = _neutral_architect()
    op_point = config.operating_point

    # Per-scenario baseline verdicts (both views) + standalone scores.
    baseline_views: Dict[str, Dict[str, Dict[str, bool]]] = {}
    baseline_scores: Dict[str, Dict[str, float]] = {}
    for e in ALL_ENTRIES:
        views, standalone = _verdict_by_view(e.scenario, arch, op_point)
        baseline_views[e.scenario_id] = views
        baseline_scores[e.scenario_id] = {t: standalone[t][1] for t in _TIER_IDS}

    # Perturbation flips on the malign scenarios.
    # flips[scenario_id][family][view][tier_id] = n_flips ; n_mut[scenario_id][family]
    flips: Dict[str, Dict[str, Dict[str, Dict[str, int]]]] = {}
    n_mut: Dict[str, Dict[str, int]] = {}
    for e in MALIGN_ENTRIES:
        flips[e.scenario_id] = {
            "semantic": {v: {t: 0 for t in _TIER_IDS} for v in VIEWS},
            "lexical": {v: {t: 0 for t in _TIER_IDS} for v in VIEWS},
        }
        n_mut[e.scenario_id] = {"semantic": 0, "lexical": 0}
        for family, operators in (
            ("semantic", _SEMANTIC_OPERATORS),
            ("lexical", EVASION_OPERATORS),
        ):
            for variant in _mutate_variants(e.scenario, operators, config.seed):
                n_mut[e.scenario_id][family] += 1
                vviews, _ = _verdict_by_view(variant, arch, op_point)
                for view in VIEWS:
                    for tier_id in _TIER_IDS:
                        base = baseline_views[e.scenario_id][view][tier_id]
                        pert = vviews[view][tier_id]
                        if base != pert:
                            flips[e.scenario_id][family][view][tier_id] += 1

    # Per-scenario records (standalone + cumulative).
    records: List[ScenarioVerdictRecord] = []
    for e in ALL_ENTRIES:
        for view in VIEWS:
            for tier_id in _TIER_IDS:
                is_mal = e.is_malign
                nm_sem = n_mut.get(e.scenario_id, {}).get("semantic", 0)
                nm_lex = n_mut.get(e.scenario_id, {}).get("lexical", 0)
                fl_sem = flips.get(e.scenario_id, {}).get(
                    "semantic", {}).get(view, {}).get(tier_id, 0)
                fl_lex = flips.get(e.scenario_id, {}).get(
                    "lexical", {}).get(view, {}).get(tier_id, 0)
                records.append(ScenarioVerdictRecord(
                    scenario_id=e.scenario_id, tier_id=tier_id, view=view,
                    is_malign=is_mal, stratum=e.stratum,
                    baseline_malign_verdict=baseline_views[
                        e.scenario_id][view][tier_id],
                    malign_score=baseline_scores[e.scenario_id][tier_id],
                    n_mut_semantic=nm_sem, flips_semantic=fl_sem,
                    n_mut_lexical=nm_lex, flips_lexical=fl_lex,
                ))

    # Aggregate to coordinates.
    coordinates: List[TierCoordinate] = []
    for view in VIEWS:
        for tier_id in _TIER_IDS:
            mal_v = [baseline_views[e.scenario_id][view][tier_id]
                     for e in MALIGN_ENTRIES]
            ben_v = [baseline_views[e.scenario_id][view][tier_id]
                     for e in BENIGN_ENTRIES]
            tpr, fpr = tpr_fpr(mal_v, ben_v)
            sem_num = sum(flips[e.scenario_id]["semantic"][view][tier_id]
                          for e in MALIGN_ENTRIES)
            sem_den = sum(n_mut[e.scenario_id]["semantic"] for e in MALIGN_ENTRIES)
            lex_num = sum(flips[e.scenario_id]["lexical"][view][tier_id]
                          for e in MALIGN_ENTRIES)
            lex_den = sum(n_mut[e.scenario_id]["lexical"] for e in MALIGN_ENTRIES)
            coordinates.append(TierCoordinate(
                tier_id=tier_id, view=view,
                x_semantic=flip_rate(sem_den, sem_num),
                x_lexical=flip_rate(lex_den, lex_num),
                tpr=tpr, fpr=fpr, youden_j=youden_j(tpr, fpr),
                n_malign=len(MALIGN_ENTRIES), n_benign=len(BENIGN_ENTRIES),
            ))

    # Positive controls (inject genuine authorization into each malign).
    pcs: List[PositiveControlRecord] = []
    for e in MALIGN_ENTRIES:
        controlled = inject_authorization(e.scenario)
        cviews, _ = _verdict_by_view(controlled, arch, op_point)
        for view in VIEWS:
            for tier_id in _TIER_IDS:
                base = baseline_views[e.scenario_id][view][tier_id]
                ctl = cviews[view][tier_id]
                pcs.append(PositiveControlRecord(
                    scenario_id=controlled.metadata.scenario_id,
                    tier_id=tier_id, view=view,
                    baseline_malign_verdict=base,
                    controlled_malign_verdict=ctl, moved=(base != ctl),
                ))

    return FrontierSummary(
        coordinates=tuple(coordinates),
        records=tuple(records),
        positive_control_records=tuple(pcs),
        corpus_digest=corpus_digest(),
        config=config,
    )
