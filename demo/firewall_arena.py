"""Firewall Arena — live, deterministic exposure of the real ARES firewall.

Pure-Python core. Wraps OracleFirewall + run_guarded_cycle with rule-based
agents (NO LLM). Loads real injection-corpus incidents, runs the real
guarded cycle, and serializes a provenanced "arena trace" for the renderer.

PRD: docs/superpowers/specs/2026-06-15-firewall-arena-mini-prd.md
"""
from __future__ import annotations

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
_INJECTION_CORPUS_IDS = {"INJ-001", "CLEAN-CTRL"}
_FRAMING_CORPUS_IDS = {"INJ-020"}

_PRESET_TO_SCENARIO = {
    "INJ-001": "INJ-001",
    "CLEAN-CTRL": "INJ-001",  # derived (see load_base_packet)
    "INJ-020": "INJ-020",
}

_CLEAN_REPLACEMENT = "lsass.dmp"  # benign file_created value for the control


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
