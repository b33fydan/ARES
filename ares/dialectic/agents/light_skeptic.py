"""Session 050 Light Skeptic — deterministic, zero-LLM rule engine.

The Light Skeptic replaces the LLM Skeptic in the Session 050 "light"
pipeline variant. It evaluates an :class:`EvidencePacket` against a
small set of Python rules and emits a frozen
:class:`LightSkepticJudgment` that the OracleJudge consumes exactly as
it would a real LLM Skeptic's ``DialecticalMessage``.

Design constraints (non-negotiable):

    * Zero LLM calls. Importing ``anthropic`` inside this module is
      tested as a failure condition.
    * Pure Python. No network, no filesystem, no random.
    * Deterministic: same inputs, same outputs, every time.
    * Every decision that moves the confidence score away from 0.5 must
      appear in ``triggered_rules`` and emit a rationale entry.

Rule set (v1 — Session 050):

    R1 ``authorization_marker_present``
        If the packet contains any fact whose ``field`` is in the
        firewall's :data:`_AUTHORIZATION_FACT_FIELDS` set
        (``change_ticket``, ``approval``, ``authorized``, ...),
        ``benign_score += 0.4``.

    R2 ``benign_explanation_marker_present``
        If the packet contains any fact whose ``field`` is in the
        firewall's :data:`_BENIGN_INDICATOR_FIELDS` set
        (``patch_applied``, ``scheduled_task``, ``service_restart``,
        ``system_maintenance``, ``normal_login``, ``routine_update``,
        ``health_check``, ``backup_operation``, ``config_change``),
        ``benign_score += 0.3``.

    R3 ``kill_chain_stage_low``
        If the maximum kill-chain stage across all packet facts is
        <= 1 (reconnaissance / initial access only), ``benign_score
        += 0.2`` and the malign_score is capped at 0.5. Kill-chain
        stage is derived per-field via :data:`_STAGE_MAP`; unmapped
        fields default to stage 2 (any execution-and-beyond signal).

    R4 ``default_floor``
        If no other rule fired, ``confidence`` is set to 0.5 and the
        rationale reports ``no_signal``. Zero weight to either side.

Final confidence:

    ``confidence = clamp(0.5 + benign_score - malign_score, 0.0, 1.0)``

The Light Skeptic does not currently populate ``malign_score`` — all
v1 rules push toward benign. The attribute and clamping contract remain
to keep the schema stable across future rule expansions.
"""

from __future__ import annotations

from ares.dialectic.coordinator.firewall import (
    _AUTHORIZATION_FACT_FIELDS,
    _BENIGN_INDICATOR_FIELDS,
)
from ares.dialectic.evidence.packet import EvidencePacket
from ares.dialectic.messages.protocol import DialecticalMessage
from ares.dialectic.schemas.light_skeptic_judgment import LightSkepticJudgment


# Rule identifiers — stable strings exposed in triggered_rules and tests.
RULE_AUTHORIZATION_MARKER = "authorization_marker_present"
RULE_BENIGN_EXPLANATION_MARKER = "benign_explanation_marker_present"
RULE_KILL_CHAIN_STAGE_LOW = "kill_chain_stage_low"
RULE_DEFAULT_FLOOR = "default_floor"

# Weights — tunable via the rule engine below; kept as constants so the
# debrief and tests can reference them by name.
WEIGHT_AUTHORIZATION = 0.4
WEIGHT_BENIGN_EXPLANATION = 0.3
WEIGHT_KILL_CHAIN_STAGE_LOW = 0.2
DEFAULT_CONFIDENCE = 0.5

# Malign-side cap applied when R3 fires.
MALIGN_CAP_WHEN_STAGE_LOW = 0.5


# =============================================================================
# Kill-chain stage derivation
# =============================================================================


# Maps fact.field -> stage integer. Unmapped fields are treated as
# stage 2 ("execution and beyond") so a single execution/lateral signal
# is enough to disqualify R3.
_STAGE_MAP: dict[str, int] = {
    # Stage 0 — reconnaissance, context, authorization fields
    "src_ip_reputation": 0,
    "src_ip": 0,
    "dst_ip": 0,
    "change_ticket": 0,
    "change_id": 0,
    "ticket_id": 0,
    "authorization": 0,
    "approval": 0,
    "authorized": 0,
    "approved_by": 0,
    "red_team": 0,
    "penetration_test": 0,
    "pentest_authorization": 0,
    # Stage 1 — reconnaissance signal / telemetry
    "port_scan": 1,
    "scan_plugin": 1,
    "dns_resolution": 1,
    "alert_description": 1,
    "timing_pattern": 1,
    "ip_reputation": 1,
    # Benign indicator fields — treated as stage 0 (low-threat context)
    "patch_applied": 0,
    "scheduled_task": 0,
    "service_restart": 0,
    "system_maintenance": 0,
    "normal_login": 0,
    "routine_update": 0,
    "health_check": 0,
    "backup_operation": 0,
    "config_change": 0,
}
_DEFAULT_STAGE = 2


def _max_kill_chain_stage(packet: EvidencePacket) -> int:
    """Return the maximum derived kill-chain stage across a packet's facts.

    An empty packet returns 0 (nothing observed) so R3 can still fire
    — matching the "no threat signal" intuition.
    """
    facts = packet.get_all_facts()
    if not facts:
        return 0
    return max(_STAGE_MAP.get(f.field, _DEFAULT_STAGE) for f in facts)


# =============================================================================
# Rules
# =============================================================================


def _fields_in(packet: EvidencePacket, field_set: frozenset[str]) -> list[str]:
    """Return the subset of packet fields that appear in ``field_set``."""
    hits: list[str] = []
    for fact in packet.get_all_facts():
        if fact.field in field_set and fact.field not in hits:
            hits.append(fact.field)
    return hits


def _clamp01(x: float) -> float:
    if x < 0.0:
        return 0.0
    if x > 1.0:
        return 1.0
    return x


# =============================================================================
# Public API
# =============================================================================


def evaluate(
    evidence_packet: EvidencePacket,
    architect_output: DialecticalMessage,
) -> LightSkepticJudgment:
    """Produce a Light Skeptic judgment for a packet + Architect message.

    The architect_output is part of the interface for future rule
    extensions (e.g., "if architect cited no facts, boost benign");
    today's v1 rules ignore it, but the signature keeps them in-scope.

    Args:
        evidence_packet: The frozen evidence packet under analysis.
        architect_output: The Architect's THESIS/HYPOTHESIS message.

    Returns:
        A frozen :class:`LightSkepticJudgment` whose ``confidence``
        field is safe to pass as ``skeptic_confidence`` into the
        OracleJudge's decision table.
    """
    # Unused for v1 rules; retained in signature per public API.
    _ = architect_output

    benign_score = 0.0
    malign_score = 0.0
    triggered: list[str] = []
    rationale: list[str] = []

    # --- R1: authorization marker ------------------------------------
    auth_hits = _fields_in(evidence_packet, _AUTHORIZATION_FACT_FIELDS)
    if auth_hits:
        benign_score += WEIGHT_AUTHORIZATION
        triggered.append(RULE_AUTHORIZATION_MARKER)
        rationale.append(
            f"{RULE_AUTHORIZATION_MARKER}: authorization-class fields "
            f"observed ({', '.join(auth_hits)})"
        )

    # --- R2: benign-explanation marker -------------------------------
    benign_hits = _fields_in(evidence_packet, _BENIGN_INDICATOR_FIELDS)
    if benign_hits:
        benign_score += WEIGHT_BENIGN_EXPLANATION
        triggered.append(RULE_BENIGN_EXPLANATION_MARKER)
        rationale.append(
            f"{RULE_BENIGN_EXPLANATION_MARKER}: benign-indicator fields "
            f"observed ({', '.join(benign_hits)})"
        )

    # --- R3: kill-chain stage low ------------------------------------
    max_stage = _max_kill_chain_stage(evidence_packet)
    if max_stage <= 1:
        benign_score += WEIGHT_KILL_CHAIN_STAGE_LOW
        malign_score = min(malign_score, MALIGN_CAP_WHEN_STAGE_LOW)
        triggered.append(RULE_KILL_CHAIN_STAGE_LOW)
        rationale.append(
            f"{RULE_KILL_CHAIN_STAGE_LOW}: max derived kill-chain stage "
            f"is {max_stage} (reconnaissance/initial access only); "
            f"malign_score capped at {MALIGN_CAP_WHEN_STAGE_LOW}"
        )

    # --- R4: default floor -------------------------------------------
    if not triggered:
        triggered.append(RULE_DEFAULT_FLOOR)
        rationale.append(
            f"{RULE_DEFAULT_FLOOR}: no rules matched; "
            f"confidence defaults to {DEFAULT_CONFIDENCE}"
        )
        return LightSkepticJudgment(
            confidence=DEFAULT_CONFIDENCE,
            rationale=tuple(rationale),
            triggered_rules=tuple(triggered),
            benign_score=0.0,
            malign_score=0.0,
        )

    # --- Compose final confidence ------------------------------------
    # Clamp the contributions individually to [0, 1] so the schema's
    # invariants hold even if future rules overshoot.
    benign_score = _clamp01(benign_score)
    malign_score = _clamp01(malign_score)
    confidence = _clamp01(0.5 + benign_score - malign_score)

    return LightSkepticJudgment(
        confidence=confidence,
        rationale=tuple(rationale),
        triggered_rules=tuple(triggered),
        benign_score=benign_score,
        malign_score=malign_score,
    )
