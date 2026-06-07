# ares/dialectic/agents/light_skeptic_v2_canonical.py
"""Light Skeptic v2 — Tier 3 (canonical / normalized string-value). S086.

Rung 3. Tier-2's string rules, but each value is CANONICALIZED before matching:
lowercase, path-separator + whitespace normalization, and light synonym folding
(``binary``->``exe``, ``temporary``->``temp``). Prediction: detection >= tier 2
(catches obfuscated/paraphrased variants) AND susceptibility < tier 2
(surface-only paraphrases fold to the same canonical string).

Reuses tier-2 rule ids/weights for identity; matching is performed against the
canonicalized string with a canonical executable matcher (so a synonym-folded
bare ``exe`` token also counts). Zero LLM calls. Pure Python. Deterministic.
"""
from __future__ import annotations

import re
from typing import List, Optional, Tuple

from ares.dialectic.agents.light_skeptic_v2_common import (
    MalignHit,
    assemble_judgment,
)
from ares.dialectic.agents.light_skeptic_v2_lexical import (
    RULE_CRED_ACCESS_TOOLING,
    RULE_EXE_IN_USER_PATH,
    RULE_INEFFECTIVE_PATCH,
    WEIGHT_CRED_ACCESS_TOOLING,
    WEIGHT_EXE_IN_USER_PATH,
    WEIGHT_INEFFECTIVE_PATCH,
    _CRED_TOOLING,
    _USER_WRITABLE_DIR,
)
from ares.dialectic.coordinator.firewall import _BENIGN_INDICATOR_FIELDS
from ares.dialectic.evidence.packet import EvidencePacket
from ares.dialectic.messages.protocol import DialecticalMessage
from ares.dialectic.schemas.light_skeptic_judgment import LightSkepticJudgment

_WHITESPACE = re.compile(r"\s+")
_SYNONYMS = {
    "temporary": "temp",
    "tmp": "temp",
    "binary": "exe",
    "executable": "exe",
}
# Matches a literal ".exe"-style extension OR a bare canonical "exe" token
# (the latter appears after synonym folding of "binary"/"executable").
_EXECUTABLE_CANON = re.compile(
    r"(?:\.(?:exe|dll|ps1|bat|scr|vbs|js|hta|com)\b|\bexe\b)"
)


def canonicalize(value: str) -> str:
    """Lowercase, normalize separators/whitespace, fold light synonyms."""
    s = value.lower().replace("\\", "/")
    s = _WHITESPACE.sub(" ", s)
    for word, repl in _SYNONYMS.items():
        s = re.sub(rf"\b{re.escape(word)}\b", repl, s)
    return s


def _canonical_strings(packet: EvidencePacket) -> List[Tuple[str, str]]:
    return [
        (f.field, canonicalize(f.value))
        for f in packet.get_all_facts()
        if isinstance(f.value, str)
    ]


def _rule_exe_in_user_path(packet: EvidencePacket) -> Optional[MalignHit]:
    for field, value in _canonical_strings(packet):
        if _USER_WRITABLE_DIR.search(value) and _EXECUTABLE_CANON.search(value):
            return MalignHit(
                rule_id=RULE_EXE_IN_USER_PATH,
                weight=WEIGHT_EXE_IN_USER_PATH,
                rationale=(
                    f"{RULE_EXE_IN_USER_PATH}: executable in user-writable "
                    f"path in field '{field}' (canonical)"
                ),
            )
    return None


def _rule_cred_access_tooling(packet: EvidencePacket) -> Optional[MalignHit]:
    for field, value in _canonical_strings(packet):
        m = _CRED_TOOLING.search(value)
        if m:
            return MalignHit(
                rule_id=RULE_CRED_ACCESS_TOOLING,
                weight=WEIGHT_CRED_ACCESS_TOOLING,
                rationale=(
                    f"{RULE_CRED_ACCESS_TOOLING}: credential-access artifact "
                    f"'{m.group()}' in field '{field}' (canonical)"
                ),
            )
    return None


def _rule_ineffective_patch(packet: EvidencePacket) -> Optional[MalignHit]:
    fields = {f.field for f in packet.get_all_facts()}
    if not (fields & _BENIGN_INDICATOR_FIELDS):
        return None
    for field, value in _canonical_strings(packet):
        threat = _CRED_TOOLING.search(value) or (
            _USER_WRITABLE_DIR.search(value) and _EXECUTABLE_CANON.search(value)
        )
        if threat:
            return MalignHit(
                rule_id=RULE_INEFFECTIVE_PATCH,
                weight=WEIGHT_INEFFECTIVE_PATCH,
                rationale=(
                    f"{RULE_INEFFECTIVE_PATCH}: benign/patch context present but "
                    f"active threat signal in field '{field}' (canonical)"
                ),
            )
    return None


MALIGN_RULES = (
    _rule_exe_in_user_path,
    _rule_cred_access_tooling,
    _rule_ineffective_patch,
)


def evaluate(
    evidence_packet: EvidencePacket,
    architect_output: DialecticalMessage,
) -> LightSkepticJudgment:
    """Tier-3 canonical Light Skeptic judgment."""
    return assemble_judgment(evidence_packet, architect_output, MALIGN_RULES)
