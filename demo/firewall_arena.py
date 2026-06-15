"""Firewall Arena core — deterministic, no-LLM exposure of the real ARES firewall.

Builds toward a thin local service that runs the real OracleFirewall +
run_guarded_cycle (rule-based agents, no LLM) and serializes a provenanced
"arena trace" for the renderer. This module currently provides the preset
registry, the base-packet loader, the full guarded-cycle runner, and the
flat ArenaRun result. Later tasks add raw-text scan and trace serializer.

PRD: docs/superpowers/specs/2026-06-15-firewall-arena-mini-prd.md
"""
from __future__ import annotations

import dataclasses as _dc
from dataclasses import dataclass
from typing import Optional

from ares.dialectic.agents.strategies.guarded_cycle import (
    GuardedCycleResult,
    run_guarded_cycle,
)
from ares.dialectic.agents.strategies.rule_based import (
    RuleBasedExplanationFinder,
    RuleBasedNarrativeGenerator,
    RuleBasedThreatAnalyzer,
)
from ares.dialectic.coordinator.firewall import FirewallVerdict, OracleFirewall
from ares.dialectic.evidence.packet import EvidencePacket
from ares.dialectic.scripts.injection_corpus import get_injection_scenario_by_id
from ares.dialectic.scripts.injection_corpus_b_framing import (
    get_framing_scenario_by_id,
)

# Preset incidents the presenter can fire. CLEAN-CTRL is INJ-001 with the
# poisoned fact's value swapped for a benign string (built at load time) so
# the contrast "caught vs clean" uses the SAME incident shape.
PRESETS = [
    {
        "preset_id": "INJ-001",
        "label": "Credential dump with a literal injection",
        "kind": "literal_injection",
        "blurb": "procdump on lsass — and one fact says 'IGNORE PREVIOUS INSTRUCTIONS'.",
    },
    {
        "preset_id": "CLEAN-CTRL",
        "label": "The same incident, no injection",
        "kind": "clean_control",
        "blurb": "Identical credential-dump incident with the poisoned fact neutralized.",
    },
    {
        "preset_id": "INJ-020",
        "label": "Quiet exculpatory facts (semantic, not literal)",
        "kind": "semantic_framing",
        "blurb": "No regex match — the honest blind spot. The Oracle decides anyway.",
    },
]

# Maps each preset_id to the corpus fetch function and scenario ID.
# INJ-001 / CLEAN-CTRL live in injection_corpus; INJ-020 lives in
# injection_corpus_b_framing. CLEAN-CTRL derives from INJ-001 (see below).
_FRAMING_CORPUS_IDS = {"INJ-020"}

_PRESET_TO_SCENARIO = {
    "INJ-001": "INJ-001",
    "CLEAN-CTRL": "INJ-001",  # derived (see load_base_packet)
    "INJ-020": "INJ-020",
}

_CLEAN_REPLACEMENT = "lsass.dmp"  # benign file_created value for the control


def apply_field_edit(packet: EvidencePacket, fact_id: str, new_value: str) -> EvidencePacket:
    """Return a NEW frozen packet with one fact's value replaced.

    Frozen dataclasses everywhere: the original packet and facts are never
    mutated. Facts are rebuilt via dataclasses.replace (value_hash recomputes
    in Fact.__post_init__), re-added to a fresh EvidencePacket, and refrozen.

    Args:
        packet: The source frozen packet (not mutated).
        fact_id: The ID of the fact whose value should be replaced.
        new_value: The replacement value string.

    Returns:
        A new frozen EvidencePacket with the fact replaced.

    Raises:
        KeyError: If fact_id does not exist in the packet.
    """
    if not packet.has_fact(fact_id):
        raise KeyError(fact_id)
    rebuilt = EvidencePacket(packet_id=packet.packet_id, time_window=packet.time_window)
    for fact in packet.get_all_facts():
        if fact.fact_id == fact_id:
            fact = _dc.replace(fact, value=new_value, value_hash=None)
        rebuilt.add_fact(fact)
    rebuilt.freeze()
    return rebuilt


def load_base_packet(preset_id: str) -> EvidencePacket:
    """Return the frozen EvidencePacket for a preset.

    INJ-001 and CLEAN-CTRL come from injection_corpus; INJ-020 comes from
    injection_corpus_b_framing. CLEAN-CTRL is INJ-001 with fact-006's
    poisoned value replaced by a benign string.
    """
    if preset_id not in _PRESET_TO_SCENARIO:
        raise KeyError(preset_id)
    scenario_id = _PRESET_TO_SCENARIO[preset_id]
    if preset_id in _FRAMING_CORPUS_IDS:
        scenario = get_framing_scenario_by_id(scenario_id)
    else:
        scenario = get_injection_scenario_by_id(scenario_id)
    if preset_id == "CLEAN-CTRL":
        return apply_field_edit(scenario.packet, "inj001-fact-006", _CLEAN_REPLACEMENT)
    return scenario.packet


# ---------------------------------------------------------------------------
# ArenaRun — flat frozen result of one guarded-cycle run
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ArenaRun:
    """Flat, serialization-ready result of a single firewall-guarded cycle.

    All values are plain Python scalars/lists — safe to pass directly to
    JSON serialization or the renderer.
    """

    firewall_passed: bool
    taint_score: float
    violations: list
    sanitized_output: Optional[list]
    hot_swap_triggered: bool
    used_sanitized: bool
    quarantined_output: Optional[list]
    verdict_outcome: str
    architect_confidence: float
    skeptic_confidence: float
    verdict_confidence: float
    supporting_fact_ids: list
    reasoning: str


def _violations_to_dicts(verdict: FirewallVerdict) -> list:
    """Convert a FirewallVerdict's violations to plain dicts."""
    return [
        {
            "violation_type": v.violation_type,
            "evidence": v.evidence,
            "severity": round(float(v.severity), 3),
            "fact_id": v.fact_id,
        }
        for v in verdict.violations
    ]


def _flatten(result: GuardedCycleResult) -> ArenaRun:
    """Flatten a GuardedCycleResult into an ArenaRun."""
    fw = result.firewall_verdict
    verdict = result.cycle_result.verdict
    return ArenaRun(
        firewall_passed=fw.passed,
        taint_score=round(float(fw.taint_score), 3),
        violations=_violations_to_dicts(fw),
        sanitized_output=list(fw.sanitized_output) if fw.sanitized_output else None,
        hot_swap_triggered=result.hot_swap_triggered,
        used_sanitized=result.used_sanitized,
        quarantined_output=list(result.quarantined_output) if result.quarantined_output else None,
        verdict_outcome=verdict.outcome.value,
        architect_confidence=round(float(verdict.architect_confidence), 3),
        skeptic_confidence=round(float(verdict.skeptic_confidence), 3),
        verdict_confidence=round(float(verdict.confidence), 3),
        supporting_fact_ids=sorted(verdict.supporting_fact_ids),
        reasoning=verdict.reasoning,
    )


def run_incident(packet: EvidencePacket) -> ArenaRun:
    """Run the REAL firewall-guarded cycle on a frozen packet. No LLM."""
    result = run_guarded_cycle(
        packet,
        threat_analyzer=RuleBasedThreatAnalyzer(),
        explanation_finder=RuleBasedExplanationFinder(),
        narrative_generator=RuleBasedNarrativeGenerator(),
        firewall=OracleFirewall(),
        enable_hot_swap=True,
        hot_swap_factory=lambda: RuleBasedThreatAnalyzer(),
        agent_id_prefix="arena",
    )
    return _flatten(result)
