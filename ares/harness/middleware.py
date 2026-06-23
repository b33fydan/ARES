"""ARES-Harness middleware: the single default-on hardened entrypoint.

Composes the Phase-1 input-path defense (capture -> ingress_scan -> quarantine)
and the deterministic action gate around a tool-using agent. The agent is the
ONLY LLM in the trusted path and is injected as a callable (``agent_fn``) so the
orchestration is deterministic and offline-testable; Phase 3's benchmark adapter
injects the real Anthropic-backed agent and wires actual tool execution behind an
ALLOW. Untrusted content reaches the agent only as redacted, inert,
provenance-tagged data; the proposed tool call is authorized on code-checkable
facts (capability class + argument taint), never on the model's free text.

Fail-closed everywhere: a scan error withholds the record and marks it
quarantined; a gate error denies the action.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Optional

from ares.harness.action_gate import (
    CapabilityClass,
    GateDecision,
    GateOutcome,
    ProposedAction,
    ToolPolicy,
    authorize,
)
from ares.harness.capture import CapturedRecord
from ares.harness.ingress_scan import scan
from ares.harness.quarantine import inert_render, redact

AgentFn = Callable[[str], Optional[ProposedAction]]

_QUARANTINED_NOTICE = (
    "[RECORD {record_id} WITHHELD: ingress scan failed; content quarantined.]"
)


@dataclass(frozen=True)
class IngressRecordReport:
    record_id: str
    passed: bool
    quarantined: bool
    violation_types: tuple
    ioc_names: tuple
    taint_score: float


@dataclass(frozen=True)
class HarnessTrace:
    record_reports: tuple
    inert_context: str
    proposed_action: Optional[dict]
    gate_decision: Optional[dict]
    any_record_quarantined: bool
    action_allowed: bool

    def to_dict(self) -> dict:
        return {
            "record_reports": [
                {
                    "record_id": r.record_id,
                    "passed": r.passed,
                    "quarantined": r.quarantined,
                    "violation_types": list(r.violation_types),
                    "ioc_names": list(r.ioc_names),
                    "taint_score": r.taint_score,
                }
                for r in self.record_reports
            ],
            "inert_context": self.inert_context,
            "proposed_action": self.proposed_action,
            "gate_decision": self.gate_decision,
            "any_record_quarantined": self.any_record_quarantined,
            "action_allowed": self.action_allowed,
        }


def _ingest(records: tuple) -> tuple:
    """Scan -> (redact on hit) -> inert-render each record. Fail-closed on error.

    Returns (reports, inert_parts, any_quarantined).
    """
    reports = []
    inert_parts = []
    any_quarantined = False
    for rec in records:
        try:
            result = scan(rec)
        except Exception:
            any_quarantined = True
            reports.append(
                IngressRecordReport(
                    record_id=rec.record_id,
                    passed=False,
                    quarantined=True,
                    violation_types=("SCAN_ERROR",),
                    ioc_names=(),
                    taint_score=1.0,
                )
            )
            inert_parts.append(_QUARANTINED_NOTICE.format(record_id=rec.record_id))
            continue
        quarantined = not result.passed
        safe_rec = redact(rec, result.violations) if quarantined else rec
        if quarantined:
            any_quarantined = True
        inert_parts.append(inert_render(safe_rec))
        reports.append(
            IngressRecordReport(
                record_id=rec.record_id,
                passed=result.passed,
                quarantined=quarantined,
                violation_types=tuple(v.violation_type for v in result.violations),
                ioc_names=tuple(m.ioc_name for m in result.ioc_matches),
                taint_score=result.taint_score,
            )
        )
    return tuple(reports), inert_parts, any_quarantined


def run_hardened_turn(
    records: tuple,
    agent_fn: AgentFn,
    policy: ToolPolicy,
) -> HarnessTrace:
    """Ingest untrusted records, run the injected agent over the inert context,
    and authorize its proposed tool call. Returns an auditable HarnessTrace.
    """
    reports, inert_parts, any_quarantined = _ingest(records)
    inert_context = "\n\n".join(inert_parts)

    action = agent_fn(inert_context)
    if action is None:
        return HarnessTrace(
            record_reports=reports,
            inert_context=inert_context,
            proposed_action=None,
            gate_decision=None,
            any_record_quarantined=any_quarantined,
            action_allowed=False,
        )

    try:
        decision = authorize(action, policy)
    except Exception:
        decision = GateDecision(
            outcome=GateOutcome.DENY,
            tool_name=getattr(action, "tool_name", "<unknown>"),
            capability_class=CapabilityClass.IRREVERSIBLE,
            tainted_args=(),
            reason="gate error -> fail-closed deny",
        )

    return HarnessTrace(
        record_reports=reports,
        inert_context=inert_context,
        proposed_action={"tool_name": action.tool_name, "args": dict(action.args)},
        gate_decision={
            "outcome": decision.outcome.value,
            "capability_class": decision.capability_class.value,
            "tainted_args": list(decision.tainted_args),
            "reason": decision.reason,
        },
        any_record_quarantined=any_quarantined,
        action_allowed=decision.outcome == GateOutcome.ALLOW,
    )
