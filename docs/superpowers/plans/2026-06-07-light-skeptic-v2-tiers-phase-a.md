# Light Skeptic v2 Tiers (Phase A) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the three deterministic "Light Skeptic v2" tiers (structural / lexical / canonical) as pure-Python peer modules that populate the dead `malign_score` channel — the middle three rungs of the read-depth robustness frontier.

**Architecture:** Each tier is a deterministic peer of `ares/dialectic/agents/light_skeptic.py` (the "peers, not wrappers" pattern), exposing the same `evaluate(packet, architect_output) -> LightSkepticJudgment` signature. The v1 **benign** channel is reused verbatim (via `light_skeptic.evaluate`) so every tier differs from v1 — and from each other — **only in the malign channel**, a clean experimental control. A shared `light_skeptic_v2_common.py` holds the malign-rule protocol and judgment assembly. Tiers ascend in read depth: tier 1 reads field-presence + kill-chain stage (un-paraphrasable), tier 2 reads string values via regex, tier 3 canonicalizes strings before matching.

**Tech Stack:** Python 3.11, frozen dataclasses, pytest. Zero LLM calls, zero network, zero filesystem, deterministic (the v1 non-negotiables, carried forward).

**Spec:** [docs/superpowers/specs/2026-06-07-read-depth-robustness-frontier-design.md](../specs/2026-06-07-read-depth-robustness-frontier-design.md) (§3 ladder, §7 architecture constraints). This plan covers **Phase A only** (§14). Phases B (Corpus C + harness) and C (pre-register + LLM anchor + report) are separate plans.

---

## File Structure

- Create: `ares/dialectic/agents/light_skeptic_v2_common.py` — `MalignHit`, `MalignRule` type, `assemble_judgment`, `_clamp01`. Shared by all tiers.
- Create: `ares/dialectic/agents/light_skeptic_v2_structured.py` — tier 1 (field-presence + stage malign rules).
- Create: `ares/dialectic/agents/light_skeptic_v2_lexical.py` — tier 2 (string-value regex malign rules).
- Create: `ares/dialectic/agents/light_skeptic_v2_canonical.py` — tier 3 (canonicalize-then-match).
- Create: `ares/dialectic/agents/light_skeptic_v2_ladder.py` — a registry mapping tier id → `evaluate` fn, for the Phase B/C harness to consume.
- Create: `ares/dialectic/tests/agents/test_light_skeptic_v2_common.py`
- Create: `ares/dialectic/tests/agents/test_light_skeptic_v2_structured.py`
- Create: `ares/dialectic/tests/agents/test_light_skeptic_v2_lexical.py`
- Create: `ares/dialectic/tests/agents/test_light_skeptic_v2_canonical.py`
- Create: `ares/dialectic/tests/agents/test_light_skeptic_v2_ladder_and_purity.py` — cross-tier anchor (no-LLM/no-network), registry contract, v1-unchanged guard.
- **Never modify:** `ares/dialectic/agents/light_skeptic.py` and its anchor test (must stay byte-stable so Paper 2 / S060 reproduce on HEAD).

**Constants reused (read-only imports — precedent: `light_skeptic.py` already imports `_AUTHORIZATION_FACT_FIELDS`/`_BENIGN_INDICATOR_FIELDS` from `firewall.py`):**
- From `ares.dialectic.agents.light_skeptic`: `_max_kill_chain_stage`, `RULE_DEFAULT_FLOOR`, `DEFAULT_CONFIDENCE`.
- From `ares.dialectic.coordinator.firewall`: `_HIGH_THREAT_FIELDS`, `_AUTHORIZATION_FACT_FIELDS`, `_BENIGN_INDICATOR_FIELDS`.

---

## Task 1: Shared scaffolding (`light_skeptic_v2_common.py`)

**Files:**
- Create: `ares/dialectic/agents/light_skeptic_v2_common.py`
- Test: `ares/dialectic/tests/agents/test_light_skeptic_v2_common.py`

- [ ] **Step 1: Write the failing test**

```python
# ares/dialectic/tests/agents/test_light_skeptic_v2_common.py
"""Tests for the shared v2 malign-rule scaffolding."""
from __future__ import annotations

from datetime import datetime

from ares.dialectic.agents.light_skeptic_v2_common import (
    MalignHit,
    assemble_judgment,
)
from ares.dialectic.evidence.fact import EntityType, Fact
from ares.dialectic.evidence.packet import EvidencePacket, TimeWindow
from ares.dialectic.evidence.provenance import Provenance, SourceType
from ares.dialectic.messages.protocol import MessageBuilder, MessageType, Phase
from ares.dialectic.schemas.light_skeptic_judgment import LightSkepticJudgment


def _packet(field_value_pairs):
    packet = EvidencePacket(
        packet_id="t-packet",
        time_window=TimeWindow(
            start=datetime(2026, 1, 1, 0, 0, 0),
            end=datetime(2026, 1, 1, 1, 0, 0),
        ),
    )
    prov = Provenance(
        source_type=SourceType.SYSLOG, source_id="src", parser_version="1.0.0"
    )
    for i, (field, value) in enumerate(field_value_pairs):
        packet.add_fact(Fact(
            fact_id=f"fact-{i:03d}", entity_id=f"ent-{i}",
            entity_type=EntityType.NODE, field=field, value=value,
            timestamp=datetime(2026, 1, 1, 0, 30, 0), provenance=prov,
        ))
    packet.freeze()
    return packet


def _arch():
    b = MessageBuilder(source_agent="a", packet_id="t-packet", cycle_id="c1")
    b.set_phase(Phase.THESIS).set_type(MessageType.HYPOTHESIS).set_confidence(0.5)
    return b.build()


def _always_fires(_packet):
    return MalignHit(rule_id="m_test", weight=0.4, rationale="m_test: fired")


def _never_fires(_packet):
    return None


def test_malign_lowers_confidence_below_benign_only():
    # change_ticket → v1 benign R1 (+0.4) and R3 low-stage (+0.2).
    packet = _packet([("change_ticket", "CR-1")])
    j = assemble_judgment(packet, _arch(), (_always_fires,))
    assert isinstance(j, LightSkepticJudgment)
    assert j.malign_score == 0.4
    assert "m_test" in j.triggered_rules
    # benign 0.6, malign 0.4 → 0.5 + 0.6 - 0.4 = 0.7
    assert j.confidence == 0.7


def test_no_signal_falls_back_to_default_floor():
    # process_name+command_line → no v1 benign rule, no malign rule fires.
    packet = _packet([("process_name", "evil.exe"), ("command_line", "evil.exe")])
    j = assemble_judgment(packet, _arch(), (_never_fires,))
    assert j.triggered_rules == ("default_floor",)
    assert j.confidence == 0.5
    assert j.benign_score == 0.0
    assert j.malign_score == 0.0


def test_default_floor_dropped_when_malign_fires_without_benign():
    packet = _packet([("process_name", "evil.exe")])  # no benign signal
    j = assemble_judgment(packet, _arch(), (_always_fires,))
    assert "default_floor" not in j.triggered_rules
    assert "m_test" in j.triggered_rules
    # benign 0.0, malign 0.4 → 0.5 + 0.0 - 0.4 = 0.1
    assert j.confidence == 0.1


def test_malign_score_clamped_to_one():
    packet = _packet([("process_name", "evil.exe")])
    heavy = (
        lambda p: MalignHit("m_a", 0.7, "a"),
        lambda p: MalignHit("m_b", 0.7, "b"),
    )
    j = assemble_judgment(packet, _arch(), heavy)
    assert j.malign_score == 1.0
    assert j.confidence == 0.0  # 0.5 + 0 - 1.0 clamped
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `python -m pytest ares/dialectic/tests/agents/test_light_skeptic_v2_common.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'ares.dialectic.agents.light_skeptic_v2_common'`

- [ ] **Step 3: Write the minimal implementation**

```python
# ares/dialectic/agents/light_skeptic_v2_common.py
"""Shared scaffolding for the Light Skeptic v2 read-depth ladder (S086).

Each v2 tier (structured / lexical / canonical) is a deterministic peer of
:mod:`ares.dialectic.agents.light_skeptic`. The tiers share:

  * the v1 BENIGN computation (reused verbatim via ``light_skeptic.evaluate`` so
    every tier's benign channel is byte-identical to v1 — the tiers differ from
    v1 and from each other ONLY in the malign channel),
  * the malign-rule protocol (a rule is a pure function ``packet -> MalignHit|None``),
  * judgment assembly enforcing ``confidence = clamp(0.5 + benign - malign)``.

Zero LLM calls. Pure Python. Deterministic. (The v1 non-negotiables.)
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional, Tuple

from ares.dialectic.agents import light_skeptic
from ares.dialectic.agents.light_skeptic import DEFAULT_CONFIDENCE, RULE_DEFAULT_FLOOR
from ares.dialectic.evidence.packet import EvidencePacket
from ares.dialectic.messages.protocol import DialecticalMessage
from ares.dialectic.schemas.light_skeptic_judgment import LightSkepticJudgment


@dataclass(frozen=True)
class MalignHit:
    """One malign rule firing: its id, weight contribution, and rationale."""

    rule_id: str
    weight: float
    rationale: str


# A malign rule reads a frozen packet and returns a hit or None.
MalignRule = Callable[[EvidencePacket], Optional[MalignHit]]


def _clamp01(x: float) -> float:
    if x < 0.0:
        return 0.0
    if x > 1.0:
        return 1.0
    return x


def assemble_judgment(
    evidence_packet: EvidencePacket,
    architect_output: DialecticalMessage,
    malign_rules: Tuple[MalignRule, ...],
) -> LightSkepticJudgment:
    """Compose v1 benign + tier malign into a LightSkepticJudgment.

    Benign is taken verbatim from ``light_skeptic.evaluate`` (v1); only the
    malign channel varies across tiers.
    """
    base = light_skeptic.evaluate(evidence_packet, architect_output)
    benign_score = base.benign_score

    # Inherit v1's benign audit trail minus the "no signal" floor — a tier that
    # finds malign signal has, by definition, found signal.
    triggered = [r for r in base.triggered_rules if r != RULE_DEFAULT_FLOOR]
    rationale = [r for r in base.rationale if not r.startswith(RULE_DEFAULT_FLOOR)]

    malign_score = 0.0
    for rule in malign_rules:
        hit = rule(evidence_packet)
        if hit is not None:
            malign_score += hit.weight
            triggered.append(hit.rule_id)
            rationale.append(hit.rationale)

    malign_score = _clamp01(malign_score)

    if not triggered:
        # Neither benign nor malign signal → v1's no-signal floor.
        return LightSkepticJudgment(
            confidence=DEFAULT_CONFIDENCE,
            rationale=(f"{RULE_DEFAULT_FLOOR}: no benign or malign signal matched",),
            triggered_rules=(RULE_DEFAULT_FLOOR,),
            benign_score=0.0,
            malign_score=0.0,
        )

    confidence = _clamp01(0.5 + benign_score - malign_score)
    return LightSkepticJudgment(
        confidence=confidence,
        rationale=tuple(rationale),
        triggered_rules=tuple(triggered),
        benign_score=_clamp01(benign_score),
        malign_score=malign_score,
    )
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `python -m pytest ares/dialectic/tests/agents/test_light_skeptic_v2_common.py -v`
Expected: PASS (4 passed)

- [ ] **Step 5: Commit**

```bash
git add ares/dialectic/agents/light_skeptic_v2_common.py ares/dialectic/tests/agents/test_light_skeptic_v2_common.py
git commit -m "feat(s086): Light Skeptic v2 shared malign-rule scaffolding"
```

---

## Task 2: Tier 1 — structural (`light_skeptic_v2_structured.py`)

**Files:**
- Create: `ares/dialectic/agents/light_skeptic_v2_structured.py`
- Test: `ares/dialectic/tests/agents/test_light_skeptic_v2_structured.py`

Rules (malign): `M1 high_threat_field` (any fact.field ∈ `_HIGH_THREAT_FIELDS`), `M2 high_stage_without_authorization` (max kill-chain stage ≥ 2 and no authorization fact). Both read only un-paraphrasable signals (field names, derived stage) → predicted framing-invariant.

- [ ] **Step 1: Write the failing test**

```python
# ares/dialectic/tests/agents/test_light_skeptic_v2_structured.py
"""Tests for Light Skeptic v2 tier 1 (structural)."""
from __future__ import annotations

from datetime import datetime

from ares.dialectic.agents.light_skeptic_v2_structured import (
    RULE_HIGH_STAGE_NO_AUTH,
    RULE_HIGH_THREAT_FIELD,
    evaluate,
)
from ares.dialectic.evidence.fact import EntityType, Fact
from ares.dialectic.evidence.packet import EvidencePacket, TimeWindow
from ares.dialectic.evidence.provenance import Provenance, SourceType
from ares.dialectic.messages.protocol import MessageBuilder, MessageType, Phase


def _packet(field_value_pairs):
    packet = EvidencePacket(
        packet_id="t", time_window=TimeWindow(
            start=datetime(2026, 1, 1), end=datetime(2026, 1, 1, 1)))
    prov = Provenance(
        source_type=SourceType.SYSLOG, source_id="s", parser_version="1.0.0")
    for i, (field, value) in enumerate(field_value_pairs):
        packet.add_fact(Fact(
            fact_id=f"f-{i:03d}", entity_id=f"e-{i}", entity_type=EntityType.NODE,
            field=field, value=value, timestamp=datetime(2026, 1, 1, 0, 30),
            provenance=prov))
    packet.freeze()
    return packet


def _arch():
    b = MessageBuilder(source_agent="a", packet_id="t", cycle_id="c")
    b.set_phase(Phase.THESIS).set_type(MessageType.HYPOTHESIS).set_confidence(0.5)
    return b.build()


def test_high_threat_field_fires():
    packet = _packet([("credential_dump", "lsass")])
    j = evaluate(packet, _arch())
    assert RULE_HIGH_THREAT_FIELD in j.triggered_rules
    assert j.malign_score >= 0.4


def test_high_stage_without_auth_fires():
    # process_name is unmapped → stage 2; no authorization fact present.
    packet = _packet([("process_name", "x.exe")])
    j = evaluate(packet, _arch())
    assert RULE_HIGH_STAGE_NO_AUTH in j.triggered_rules


def test_high_stage_suppressed_when_authorized():
    packet = _packet([("process_name", "x.exe"), ("change_ticket", "CR-1")])
    j = evaluate(packet, _arch())
    assert RULE_HIGH_STAGE_NO_AUTH not in j.triggered_rules


def test_blind_to_value_borne_attack():
    # The frontier's whole point: malice in the VALUE, generic field name.
    # Tier 1 does not read the value, so M1 (high-threat field) must NOT fire.
    packet = _packet([("process_name", "C:\\Users\\Public\\procdump.exe")])
    j = evaluate(packet, _arch())
    assert RULE_HIGH_THREAT_FIELD not in j.triggered_rules


def test_low_stage_benign_not_malign():
    packet = _packet([("patch_applied", "KB-1")])  # benign field, stage 0
    j = evaluate(packet, _arch())
    assert RULE_HIGH_THREAT_FIELD not in j.triggered_rules
    assert RULE_HIGH_STAGE_NO_AUTH not in j.triggered_rules
    assert j.malign_score == 0.0
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `python -m pytest ares/dialectic/tests/agents/test_light_skeptic_v2_structured.py -v`
Expected: FAIL — `ModuleNotFoundError: ...light_skeptic_v2_structured`

- [ ] **Step 3: Write the minimal implementation**

```python
# ares/dialectic/agents/light_skeptic_v2_structured.py
"""Light Skeptic v2 — Tier 1 (structural / field-presence). S086 read-depth ladder.

Rung 1. Reads only signals that cannot be paraphrased: which fields are present,
and the kill-chain stage derived from field names. Predicted framing-
susceptibility ~0 (invariant by construction); predicted detection capped,
because real injection scenarios encode malice in fact VALUES (strings), not
field names — which is exactly the frontier's point.

Zero LLM calls. Pure Python. Deterministic.
"""
from __future__ import annotations

from typing import Optional

from ares.dialectic.agents.light_skeptic import _max_kill_chain_stage
from ares.dialectic.agents.light_skeptic_v2_common import (
    MalignHit,
    assemble_judgment,
)
from ares.dialectic.coordinator.firewall import (
    _AUTHORIZATION_FACT_FIELDS,
    _HIGH_THREAT_FIELDS,
)
from ares.dialectic.evidence.packet import EvidencePacket
from ares.dialectic.messages.protocol import DialecticalMessage
from ares.dialectic.schemas.light_skeptic_judgment import LightSkepticJudgment

RULE_HIGH_THREAT_FIELD = "malign_high_threat_field"
RULE_HIGH_STAGE_NO_AUTH = "malign_high_stage_without_authorization"

WEIGHT_HIGH_THREAT_FIELD = 0.4
WEIGHT_HIGH_STAGE_NO_AUTH = 0.3

HIGH_STAGE_THRESHOLD = 2


def _has_authorization(packet: EvidencePacket) -> bool:
    return any(
        f.field in _AUTHORIZATION_FACT_FIELDS for f in packet.get_all_facts()
    )


def _rule_high_threat_field(packet: EvidencePacket) -> Optional[MalignHit]:
    hits = sorted(
        {f.field for f in packet.get_all_facts() if f.field in _HIGH_THREAT_FIELDS}
    )
    if not hits:
        return None
    return MalignHit(
        rule_id=RULE_HIGH_THREAT_FIELD,
        weight=WEIGHT_HIGH_THREAT_FIELD,
        rationale=(
            f"{RULE_HIGH_THREAT_FIELD}: high-threat field(s) present "
            f"({', '.join(hits)})"
        ),
    )


def _rule_high_stage_no_auth(packet: EvidencePacket) -> Optional[MalignHit]:
    stage = _max_kill_chain_stage(packet)
    if stage >= HIGH_STAGE_THRESHOLD and not _has_authorization(packet):
        return MalignHit(
            rule_id=RULE_HIGH_STAGE_NO_AUTH,
            weight=WEIGHT_HIGH_STAGE_NO_AUTH,
            rationale=(
                f"{RULE_HIGH_STAGE_NO_AUTH}: max kill-chain stage {stage} "
                f">= {HIGH_STAGE_THRESHOLD} with no authorization fact"
            ),
        )
    return None


MALIGN_RULES = (_rule_high_threat_field, _rule_high_stage_no_auth)


def evaluate(
    evidence_packet: EvidencePacket,
    architect_output: DialecticalMessage,
) -> LightSkepticJudgment:
    """Tier-1 structural Light Skeptic judgment."""
    return assemble_judgment(evidence_packet, architect_output, MALIGN_RULES)
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `python -m pytest ares/dialectic/tests/agents/test_light_skeptic_v2_structured.py -v`
Expected: PASS (5 passed)

- [ ] **Step 5: Commit**

```bash
git add ares/dialectic/agents/light_skeptic_v2_structured.py ares/dialectic/tests/agents/test_light_skeptic_v2_structured.py
git commit -m "feat(s086): Light Skeptic v2 tier 1 (structural malign rules)"
```

---

## Task 3: Tier 2 — lexical (`light_skeptic_v2_lexical.py`)

**Files:**
- Create: `ares/dialectic/agents/light_skeptic_v2_lexical.py`
- Test: `ares/dialectic/tests/agents/test_light_skeptic_v2_lexical.py`

Rules (malign), all reading string values: `L1 exe_in_user_writable_path`, `L2 credential_access_tooling`, `L3 ineffective_patch_claim` (a benign/patch field is present yet an active threat signal appears in some value). Grounded in real corpus values (e.g. INJ-001 `process_name=C:\Users\Public\procdump.exe`, `command_line=...-ma lsass.exe...`).

- [ ] **Step 1: Write the failing test**

```python
# ares/dialectic/tests/agents/test_light_skeptic_v2_lexical.py
"""Tests for Light Skeptic v2 tier 2 (lexical / string-value)."""
from __future__ import annotations

from datetime import datetime

from ares.dialectic.agents.light_skeptic_v2_lexical import (
    RULE_CRED_ACCESS_TOOLING,
    RULE_EXE_IN_USER_PATH,
    RULE_INEFFECTIVE_PATCH,
    evaluate,
)
from ares.dialectic.evidence.fact import EntityType, Fact
from ares.dialectic.evidence.packet import EvidencePacket, TimeWindow
from ares.dialectic.evidence.provenance import Provenance, SourceType
from ares.dialectic.messages.protocol import MessageBuilder, MessageType, Phase


def _packet(field_value_pairs):
    packet = EvidencePacket(
        packet_id="t", time_window=TimeWindow(
            start=datetime(2026, 1, 1), end=datetime(2026, 1, 1, 1)))
    prov = Provenance(
        source_type=SourceType.SYSLOG, source_id="s", parser_version="1.0.0")
    for i, (field, value) in enumerate(field_value_pairs):
        packet.add_fact(Fact(
            fact_id=f"f-{i:03d}", entity_id=f"e-{i}", entity_type=EntityType.NODE,
            field=field, value=value, timestamp=datetime(2026, 1, 1, 0, 30),
            provenance=prov))
    packet.freeze()
    return packet


def _arch():
    b = MessageBuilder(source_agent="a", packet_id="t", cycle_id="c")
    b.set_phase(Phase.THESIS).set_type(MessageType.HYPOTHESIS).set_confidence(0.5)
    return b.build()


def test_exe_in_user_path_fires_on_real_value():
    packet = _packet([("process_name", "C:\\Users\\Public\\procdump.exe")])
    j = evaluate(packet, _arch())
    assert RULE_EXE_IN_USER_PATH in j.triggered_rules


def test_cred_access_tooling_fires_on_command_line():
    packet = _packet([
        ("command_line", "procdump.exe -ma lsass.exe C:\\Temp\\lsass.dmp"),
    ])
    j = evaluate(packet, _arch())
    assert RULE_CRED_ACCESS_TOOLING in j.triggered_rules


def test_exe_in_system_path_does_not_fire():
    # System32 is not user-writable → no exe-in-user-path violation.
    packet = _packet([("process_name", "C:\\Windows\\System32\\svchost.exe")])
    j = evaluate(packet, _arch())
    assert RULE_EXE_IN_USER_PATH not in j.triggered_rules


def test_ineffective_patch_fires_when_threat_signal_present():
    packet = _packet([
        ("patch_applied", "KB5001"),
        ("command_line", "mimikatz sekurlsa::logonpasswords"),
    ])
    j = evaluate(packet, _arch())
    assert RULE_INEFFECTIVE_PATCH in j.triggered_rules


def test_non_string_value_is_skipped():
    # value=Any; a non-string value must not crash the string rules.
    packet = _packet([("file_size_bytes", 134217728)])
    j = evaluate(packet, _arch())  # must not raise
    assert RULE_EXE_IN_USER_PATH not in j.triggered_rules


def test_clean_benign_packet_no_malign():
    packet = _packet([("normal_login", "user jdoe 09:00")])
    j = evaluate(packet, _arch())
    assert j.malign_score == 0.0
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `python -m pytest ares/dialectic/tests/agents/test_light_skeptic_v2_lexical.py -v`
Expected: FAIL — `ModuleNotFoundError: ...light_skeptic_v2_lexical`

- [ ] **Step 3: Write the minimal implementation**

```python
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
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `python -m pytest ares/dialectic/tests/agents/test_light_skeptic_v2_lexical.py -v`
Expected: PASS (6 passed)

- [ ] **Step 5: Commit**

```bash
git add ares/dialectic/agents/light_skeptic_v2_lexical.py ares/dialectic/tests/agents/test_light_skeptic_v2_lexical.py
git commit -m "feat(s086): Light Skeptic v2 tier 2 (lexical string-value rules)"
```

---

## Task 4: Tier 3 — canonical (`light_skeptic_v2_canonical.py`)

**Files:**
- Create: `ares/dialectic/agents/light_skeptic_v2_canonical.py`
- Test: `ares/dialectic/tests/agents/test_light_skeptic_v2_canonical.py`

Tier 3 canonicalizes each string value (lowercase, separator + whitespace normalization, light synonym folding: `binary`→`exe`, `temporary`→`temp`) before applying tier-2-style matching. Prediction: catches obfuscated/paraphrased variants tier 2 misses (detection ≥ tier 2) while folding surface-only paraphrases to one form (susceptibility ≤ tier 2).

- [ ] **Step 1: Write the failing test**

```python
# ares/dialectic/tests/agents/test_light_skeptic_v2_canonical.py
"""Tests for Light Skeptic v2 tier 3 (canonical)."""
from __future__ import annotations

from datetime import datetime

from ares.dialectic.agents.light_skeptic_v2_canonical import (
    RULE_EXE_IN_USER_PATH,
    canonicalize,
    evaluate,
)
from ares.dialectic.agents.light_skeptic_v2_lexical import (
    evaluate as lexical_evaluate,
)
from ares.dialectic.evidence.fact import EntityType, Fact
from ares.dialectic.evidence.packet import EvidencePacket, TimeWindow
from ares.dialectic.evidence.provenance import Provenance, SourceType
from ares.dialectic.messages.protocol import MessageBuilder, MessageType, Phase


def _packet(field_value_pairs):
    packet = EvidencePacket(
        packet_id="t", time_window=TimeWindow(
            start=datetime(2026, 1, 1), end=datetime(2026, 1, 1, 1)))
    prov = Provenance(
        source_type=SourceType.SYSLOG, source_id="s", parser_version="1.0.0")
    for i, (field, value) in enumerate(field_value_pairs):
        packet.add_fact(Fact(
            fact_id=f"f-{i:03d}", entity_id=f"e-{i}", entity_type=EntityType.NODE,
            field=field, value=value, timestamp=datetime(2026, 1, 1, 0, 30),
            provenance=prov))
    packet.freeze()
    return packet


def _arch():
    b = MessageBuilder(source_agent="a", packet_id="t", cycle_id="c")
    b.set_phase(Phase.THESIS).set_type(MessageType.HYPOTHESIS).set_confidence(0.5)
    return b.build()


def test_canonicalize_folds_separators_and_synonyms():
    assert canonicalize("C:\\Users\\Public\\X.EXE") == "c:/users/public/x.exe"
    assert "exe" in canonicalize("dropped a BINARY in the folder")
    assert "temp" in canonicalize("the Temporary directory")


def test_catches_synonym_variant_that_lexical_misses():
    # "binary" (standalone) in a user path, no ".exe" literal → tier 2 misses;
    # tier 3 folds binary->exe and catches it.
    packet = _packet([("file_created", "binary written to C:\\Users\\Public\\")])
    assert RULE_EXE_IN_USER_PATH not in lexical_evaluate(packet, _arch()).triggered_rules
    assert RULE_EXE_IN_USER_PATH in evaluate(packet, _arch()).triggered_rules


def test_still_catches_plain_exe_in_user_path():
    packet = _packet([("process_name", "C:\\Users\\Public\\procdump.exe")])
    j = evaluate(packet, _arch())
    assert RULE_EXE_IN_USER_PATH in j.triggered_rules


def test_non_string_value_skipped():
    packet = _packet([("file_size_bytes", 999)])
    j = evaluate(packet, _arch())  # must not raise
    assert j.malign_score == 0.0
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `python -m pytest ares/dialectic/tests/agents/test_light_skeptic_v2_canonical.py -v`
Expected: FAIL — `ModuleNotFoundError: ...light_skeptic_v2_canonical`

- [ ] **Step 3: Write the minimal implementation**

```python
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
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `python -m pytest ares/dialectic/tests/agents/test_light_skeptic_v2_canonical.py -v`
Expected: PASS (4 passed)

- [ ] **Step 5: Commit**

```bash
git add ares/dialectic/agents/light_skeptic_v2_canonical.py ares/dialectic/tests/agents/test_light_skeptic_v2_canonical.py
git commit -m "feat(s086): Light Skeptic v2 tier 3 (canonical normalize-then-match)"
```

---

## Task 5: Ladder registry + cross-tier purity guards

**Files:**
- Create: `ares/dialectic/agents/light_skeptic_v2_ladder.py`
- Test: `ares/dialectic/tests/agents/test_light_skeptic_v2_ladder_and_purity.py`

The registry gives the Phase B/C harness a single ordered handle on all five rungs (tier 0 = v1, tiers 1-3 = v2, tier 4 = the LLM anchor, registered by name only — it is not built here). The purity test enforces the non-negotiables across every new module and guards v1 against accidental edits.

- [ ] **Step 1: Write the failing test**

```python
# ares/dialectic/tests/agents/test_light_skeptic_v2_ladder_and_purity.py
"""Ladder registry contract + cross-tier purity guards (S086 Phase A)."""
from __future__ import annotations

import importlib
import inspect
from datetime import datetime

from ares.dialectic.agents import light_skeptic
from ares.dialectic.agents.light_skeptic_v2_ladder import (
    DETERMINISTIC_TIERS,
    LADDER_ORDER,
)
from ares.dialectic.evidence.fact import EntityType, Fact
from ares.dialectic.evidence.packet import EvidencePacket, TimeWindow
from ares.dialectic.evidence.provenance import Provenance, SourceType
from ares.dialectic.messages.protocol import MessageBuilder, MessageType, Phase
from ares.dialectic.schemas.light_skeptic_judgment import LightSkepticJudgment

_V2_MODULES = (
    "ares.dialectic.agents.light_skeptic_v2_common",
    "ares.dialectic.agents.light_skeptic_v2_structured",
    "ares.dialectic.agents.light_skeptic_v2_lexical",
    "ares.dialectic.agents.light_skeptic_v2_canonical",
    "ares.dialectic.agents.light_skeptic_v2_ladder",
)


def _packet(pairs):
    packet = EvidencePacket(
        packet_id="t", time_window=TimeWindow(
            start=datetime(2026, 1, 1), end=datetime(2026, 1, 1, 1)))
    prov = Provenance(
        source_type=SourceType.SYSLOG, source_id="s", parser_version="1.0.0")
    for i, (field, value) in enumerate(pairs):
        packet.add_fact(Fact(
            fact_id=f"f-{i:03d}", entity_id=f"e-{i}", entity_type=EntityType.NODE,
            field=field, value=value, timestamp=datetime(2026, 1, 1, 0, 30),
            provenance=prov))
    packet.freeze()
    return packet


def _arch():
    b = MessageBuilder(source_agent="a", packet_id="t", cycle_id="c")
    b.set_phase(Phase.THESIS).set_type(MessageType.HYPOTHESIS).set_confidence(0.5)
    return b.build()


def test_ladder_order_is_five_rungs():
    assert LADDER_ORDER == (
        "v1_field", "v2_structured", "v2_lexical", "v2_canonical", "llm_semantic",
    )


def test_deterministic_tiers_are_callable_and_return_judgment():
    packet = _packet([("process_name", "C:\\Users\\Public\\procdump.exe")])
    for tier_id, fn in DETERMINISTIC_TIERS.items():
        j = fn(packet, _arch())
        assert isinstance(j, LightSkepticJudgment), tier_id


def test_deterministic_tiers_exclude_llm_anchor():
    # tier 4 is registered by name in LADDER_ORDER but NOT built here.
    assert "llm_semantic" not in DETERMINISTIC_TIERS
    assert set(DETERMINISTIC_TIERS) == {
        "v1_field", "v2_structured", "v2_lexical", "v2_canonical",
    }


def test_no_v2_module_imports_anthropic():
    for name in _V2_MODULES:
        mod = importlib.import_module(name)
        src = inspect.getsource(mod)
        assert "import anthropic" not in src, name
        assert "from anthropic" not in src, name


def test_no_v2_module_touches_network_or_random_or_fs():
    forbidden = ("import requests", "import socket", "import random",
                 "open(", "urllib")
    for name in _V2_MODULES:
        mod = importlib.import_module(name)
        src = inspect.getsource(mod)
        for token in forbidden:
            assert token not in src, f"{name} contains forbidden '{token}'"


def test_determinism_same_input_same_output():
    packet = _packet([("command_line", "mimikatz sekurlsa::logonpasswords")])
    for fn in DETERMINISTIC_TIERS.values():
        first = fn(packet, _arch()).to_json()
        second = fn(packet, _arch()).to_json()
        assert first == second


def test_v1_behaviour_unchanged_by_v2_presence():
    # Guard: importing the v2 ladder must not perturb v1's output. Known v1
    # value: change_ticket → R1(0.4)+R3(0.2) benign → 0.5+0.6 = 1.1 clamp 1.0.
    packet = _packet([("change_ticket", "CR-1")])
    assert light_skeptic.evaluate(packet, _arch()).confidence == 1.0
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `python -m pytest ares/dialectic/tests/agents/test_light_skeptic_v2_ladder_and_purity.py -v`
Expected: FAIL — `ModuleNotFoundError: ...light_skeptic_v2_ladder`

- [ ] **Step 3: Write the minimal implementation**

```python
# ares/dialectic/agents/light_skeptic_v2_ladder.py
"""The read-depth ladder registry (S086 Phase A).

A single ordered handle on the five rungs of the read-depth robustness frontier
for the Phase B/C measurement harness:

    v1_field      -> tier 0, ares.dialectic.agents.light_skeptic.evaluate
    v2_structured -> tier 1
    v2_lexical    -> tier 2
    v2_canonical  -> tier 3
    llm_semantic  -> tier 4 (the LLM anchor; reused from S084, NOT built here)

``DETERMINISTIC_TIERS`` exposes only the four offline tiers; the LLM anchor is
named in ``LADDER_ORDER`` for plotting but is supplied by the harness.
"""
from __future__ import annotations

from typing import Callable, Dict

from ares.dialectic.agents import (
    light_skeptic,
    light_skeptic_v2_canonical,
    light_skeptic_v2_lexical,
    light_skeptic_v2_structured,
)
from ares.dialectic.evidence.packet import EvidencePacket
from ares.dialectic.messages.protocol import DialecticalMessage
from ares.dialectic.schemas.light_skeptic_judgment import LightSkepticJudgment

TierFn = Callable[[EvidencePacket, DialecticalMessage], LightSkepticJudgment]

LADDER_ORDER = (
    "v1_field",
    "v2_structured",
    "v2_lexical",
    "v2_canonical",
    "llm_semantic",
)

DETERMINISTIC_TIERS: Dict[str, TierFn] = {
    "v1_field": light_skeptic.evaluate,
    "v2_structured": light_skeptic_v2_structured.evaluate,
    "v2_lexical": light_skeptic_v2_lexical.evaluate,
    "v2_canonical": light_skeptic_v2_canonical.evaluate,
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `python -m pytest ares/dialectic/tests/agents/test_light_skeptic_v2_ladder_and_purity.py -v`
Expected: PASS (7 passed)

- [ ] **Step 5: Commit**

```bash
git add ares/dialectic/agents/light_skeptic_v2_ladder.py ares/dialectic/tests/agents/test_light_skeptic_v2_ladder_and_purity.py
git commit -m "feat(s086): read-depth ladder registry + cross-tier purity guards"
```

---

## Task 6: Full-suite regression check

**Files:** none (verification only)

- [ ] **Step 1: Run the Phase A modules together**

Run: `python -m pytest ares/dialectic/tests/agents/test_light_skeptic_v2_common.py ares/dialectic/tests/agents/test_light_skeptic_v2_structured.py ares/dialectic/tests/agents/test_light_skeptic_v2_lexical.py ares/dialectic/tests/agents/test_light_skeptic_v2_canonical.py ares/dialectic/tests/agents/test_light_skeptic_v2_ladder_and_purity.py -v`
Expected: PASS (26 passed)

- [ ] **Step 2: Run the existing Light Skeptic tests to confirm zero regression**

Run: `python -m pytest ares/dialectic/tests/agents/test_light_skeptic.py ares/dialectic/tests/agents/test_light_skeptic_anchor.py ares/dialectic/tests/schemas/test_light_skeptic_judgment.py -v`
Expected: PASS (all green — v1 untouched)

- [ ] **Step 3: Run the full suite**

Run: `python -m pytest tests/ ares/ -q`
Expected: PASS — prior floor (4205) + the new Phase A tests, 0 failures.

- [ ] **Step 4: Update the CLAUDE.md test floor**

Update the "Test count floor (passing)" line in `CLAUDE.md` to the new total reported by Step 3.

- [ ] **Step 5: Commit**

```bash
git add CLAUDE.md
git commit -m "docs(s086): bump test floor after Phase A (Light Skeptic v2 tiers)"
```

---

## Self-Review

**Spec coverage (§3 ladder, §7 architecture):**
- Tier 1 structured → Task 2. Tier 2 lexical → Task 3. Tier 3 canonical → Task 4. ✓
- `malign_score` populated (was dead-wired 0.0) → Tasks 2-4 via `MalignHit`/`assemble_judgment`. ✓
- v1 benign reused verbatim, tiers differ only in malign → Task 1 `assemble_judgment`. ✓
- Peer modules, frozen dataclasses, zero-LLM/network/random, deterministic → Task 5 purity tests. ✓
- v1 byte-stable / unchanged → Task 5 guard + Task 6 Step 2. ✓
- Ladder handle for Phase B/C harness (incl. named LLM anchor) → Task 5. ✓
- Five malign rule *classes* from the spec: high-stage-no-auth (Task 2 M2), high-threat-field (Task 2 M1), exe-in-user-path (Task 3 L1), credential-access (Task 3 L2), ineffective-patch (Task 3 L3). The fifth tribunal class (post-exploitation-without-change-record) is a structured rule of the same shape as M2; it is **not** required to establish the frontier and is deferred to a fast-follow within Phase B if Corpus C surfaces a scenario that needs it. (Noted, not a placeholder — Phase A code is complete and runnable.)

**Placeholder scan:** No TBD/TODO. Every code step has complete, runnable code. Expected outputs and counts are concrete.

**Type consistency:** `MalignHit(rule_id, weight, rationale)` and `assemble_judgment(packet, arch, malign_rules)` are used identically across Tasks 1-4. Rule-id and weight constant names referenced in canonical (Task 4) are imported from lexical (Task 3) where defined. `evaluate(packet, arch)` signature matches v1 across all tiers and the registry `TierFn` type.

**Out of scope (per spec §10/§14):** measurement runner, Corpus C, perturbation harness, LLM anchor run, production wiring — all Phase B/C.
