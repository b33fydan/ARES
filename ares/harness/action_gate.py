"""Deterministic, LLM-free action-authorization gate — the ARES-Harness novel core.

Mirrors the OracleJudge "no LLM, ever" discipline: the decision to allow or deny a
proposed tool call depends ONLY on code-checkable facts — the tool's capability
class (assigned in config, never model-decided) and whether any argument was
derived from untrusted (injected) data. It never consults the model's free-text
justification. An injection can reach the agent's eyes as inert quoted data; it
cannot reach this decision.

Taint model (per the Phase-2 design): an argument is tainted if it is absent from
``arg_sources`` (fail-safe — unknown provenance is treated as untrusted), if its
source tuple is empty, or if ANY source informing it is untrusted. Trust is decided
solely via ``ares.harness.capture.TRUSTED_SOURCE_TYPES`` (the single trust SSOT).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping

from ares.dialectic.evidence import SourceType
from ares.harness.capture import TRUSTED_SOURCE_TYPES


class CapabilityClass(Enum):
    """Privilege class of a tool/action. Assigned at registration (config)."""

    READ_ONLY = "read_only"
    WRITE_LOCAL = "write_local"
    IRREVERSIBLE = "irreversible"
    EXFIL_SHAPED = "exfil_shaped"


# Privileged classes: a single tainted argument on any of these denies the call.
PRIVILEGED_CLASSES = frozenset(
    {
        CapabilityClass.WRITE_LOCAL,
        CapabilityClass.IRREVERSIBLE,
        CapabilityClass.EXFIL_SHAPED,
    }
)


@dataclass(frozen=True)
class ToolPolicy:
    """Maps tool names to capability classes. Unknown tools fail closed.

    ``default_class`` is the class assigned to any tool not present in
    ``mapping``; it defaults to ``IRREVERSIBLE`` (privileged) so an
    unregistered tool with a tainted argument is denied rather than allowed.
    Integrators may override the default per deployment.
    """

    mapping: Mapping[str, CapabilityClass]
    default_class: CapabilityClass = CapabilityClass.IRREVERSIBLE

    def classify(self, tool_name: str) -> CapabilityClass:
        return self.mapping.get(tool_name, self.default_class)


@dataclass(frozen=True)
class ProposedAction:
    """A tool call the agent proposes, plus the provenance of each argument.

    ``arg_sources`` maps an argument name to the tuple of ``SourceType``s of the
    captured records that informed it. An argument missing from this map is
    treated as untrusted-derived (fail-safe).
    """

    tool_name: str
    args: Mapping[str, Any]
    arg_sources: Mapping[str, tuple] = field(default_factory=dict)


def _source_trusted(source_type: SourceType) -> bool:
    return source_type in TRUSTED_SOURCE_TYPES


def arg_is_tainted(action: ProposedAction, arg_name: str) -> bool:
    """True if *arg_name* was (or may have been) derived from untrusted data."""
    sources = action.arg_sources.get(arg_name)
    if not sources:  # absent (None) or empty tuple -> unknown provenance -> tainted
        return True
    return any(not _source_trusted(st) for st in sources)


def tainted_args(action: ProposedAction) -> tuple:
    """The tuple of the action's argument names that are tainted (insertion order)."""
    return tuple(name for name in action.args if arg_is_tainted(action, name))


class GateOutcome(Enum):
    ALLOW = "allow"
    DENY = "deny"


@dataclass(frozen=True)
class GateDecision:
    outcome: GateOutcome
    tool_name: str
    capability_class: CapabilityClass
    tainted_args: tuple
    reason: str


def authorize(action: ProposedAction, policy: ToolPolicy) -> GateDecision:
    """Deterministic allow/deny for a proposed tool call.

    READ_ONLY actions are always allowed (no privileged effect to hijack).
    Any privileged action with one or more tainted arguments is denied — an
    untrusted source must not choose the target of a privileged action. The
    decision is a pure function of ``(capability_class, tainted_args)``.
    """
    cls = policy.classify(action.tool_name)
    tainted = tainted_args(action)
    if cls == CapabilityClass.READ_ONLY:
        return GateDecision(
            outcome=GateOutcome.ALLOW,
            tool_name=action.tool_name,
            capability_class=cls,
            tainted_args=tainted,
            reason="read-only action; allowed regardless of argument taint",
        )
    if tainted:
        return GateDecision(
            outcome=GateOutcome.DENY,
            tool_name=action.tool_name,
            capability_class=cls,
            tainted_args=tainted,
            reason=(
                f"privileged action ({cls.value}) with tainted argument(s) "
                f"{list(tainted)} derived from untrusted source(s)"
            ),
        )
    return GateDecision(
        outcome=GateOutcome.ALLOW,
        tool_name=action.tool_name,
        capability_class=cls,
        tainted_args=tainted,
        reason=f"privileged action ({cls.value}) with all-trusted arguments",
    )
