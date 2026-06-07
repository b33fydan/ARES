# ares/dialectic/agents/light_skeptic_v2_lexical.py
"""Light Skeptic v2 — Tier 2 (lexical / string-value). S086 read-depth ladder.

Rung 2. Reads fact VALUES as raw strings via regex/keyword. Detection rises
(real malice lives in values) AND framing-susceptibility appears (a paraphrase
of a value can evade a literal pattern). Predicted X med-high, Y med-high.

Patterns are case-insensitive and separator-flexible (the realistic first cut a
developer writes); tier 3 (canonical) adds synonym/whitespace normalization on
top. Zero LLM calls. Pure Python. Deterministic.
"""
from __future__ import annotations

import re
from typing import List, Optional, Tuple

from ares.dialectic.agents.light_skeptic_v2_common import (
    MalignHit,
    assemble_judgment,
)
from ares.dialectic.coordinator.firewall import _BENIGN_INDICATOR_FIELDS
from ares.dialectic.evidence.packet import EvidencePacket
from ares.dialectic.messages.protocol import DialecticalMessage
from ares.dialectic.schemas.light_skeptic_judgment import LightSkepticJudgment

RULE_EXE_IN_USER_PATH = "malign_executable_in_user_writable_path"
RULE_CRED_ACCESS_TOOLING = "malign_credential_access_tooling"
RULE_INEFFECTIVE_PATCH = "malign_ineffective_patch_claim"

WEIGHT_EXE_IN_USER_PATH = 0.4
WEIGHT_CRED_ACCESS_TOOLING = 0.4
WEIGHT_INEFFECTIVE_PATCH = 0.3

# User-writable locations where a dropped executable is suspicious.
_USER_WRITABLE_DIR = re.compile(
    r"(?:[\\/]users[\\/]public|[\\/]users[\\/][^\\/]+|[\\/]temp[\\/]|[\\/]tmp[\\/]"
    r"|appdata|programdata|[\\/]downloads[\\/])",
    re.IGNORECASE,
)
_EXECUTABLE_EXT = re.compile(
    r"\.(?:exe|dll|ps1|bat|scr|vbs|js|hta|com)\b", re.IGNORECASE
)

# Credential-access tooling / artifacts.
_CRED_TOOLING = re.compile(
    r"(?:mimikatz|procdump|sekurlsa|lsass\.dmp|-ma\s+lsass|ntds\.dit|hashdump"
    r"|samdump|pwdump|comsvcs\.dll)",
    re.IGNORECASE,
)


def _string_values(packet: EvidencePacket) -> List[Tuple[str, str]]:
    return [
        (f.field, f.value)
        for f in packet.get_all_facts()
        if isinstance(f.value, str)
    ]


def _rule_exe_in_user_path(packet: EvidencePacket) -> Optional[MalignHit]:
    for field, value in _string_values(packet):
        if _USER_WRITABLE_DIR.search(value) and _EXECUTABLE_EXT.search(value):
            return MalignHit(
                rule_id=RULE_EXE_IN_USER_PATH,
                weight=WEIGHT_EXE_IN_USER_PATH,
                rationale=(
                    f"{RULE_EXE_IN_USER_PATH}: executable in user-writable "
                    f"path in field '{field}'"
                ),
            )
    return None


def _rule_cred_access_tooling(packet: EvidencePacket) -> Optional[MalignHit]:
    for field, value in _string_values(packet):
        m = _CRED_TOOLING.search(value)
        if m:
            return MalignHit(
                rule_id=RULE_CRED_ACCESS_TOOLING,
                weight=WEIGHT_CRED_ACCESS_TOOLING,
                rationale=(
                    f"{RULE_CRED_ACCESS_TOOLING}: credential-access artifact "
                    f"'{m.group()}' in field '{field}'"
                ),
            )
    return None


def _rule_ineffective_patch(packet: EvidencePacket) -> Optional[MalignHit]:
    fields = {f.field for f in packet.get_all_facts()}
    if not (fields & _BENIGN_INDICATOR_FIELDS):
        return None
    for field, value in _string_values(packet):
        threat = _CRED_TOOLING.search(value) or (
            _USER_WRITABLE_DIR.search(value) and _EXECUTABLE_EXT.search(value)
        )
        if threat:
            return MalignHit(
                rule_id=RULE_INEFFECTIVE_PATCH,
                weight=WEIGHT_INEFFECTIVE_PATCH,
                rationale=(
                    f"{RULE_INEFFECTIVE_PATCH}: benign/patch context present but "
                    f"active threat signal in field '{field}'"
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
    """Tier-2 lexical Light Skeptic judgment."""
    return assemble_judgment(evidence_packet, architect_output, MALIGN_RULES)
