# tests/harness/test_action_gate_invariants.py
"""Anchor tests pinning the action gate's security guarantees.

These are invariants, not behaviors: if a future change breaks determinism,
loosens monotonicity, or introduces an LLM dependency into the gate, one of
these trips a deliberate failure rather than letting a silent regression ship.
"""
import pathlib

import pytest

from ares.dialectic.evidence import SourceType
from ares.harness.action_gate import (
    CapabilityClass,
    GateOutcome,
    ProposedAction,
    ToolPolicy,
    authorize,
)

_ALL_CLASSES = (
    CapabilityClass.READ_ONLY,
    CapabilityClass.WRITE_LOCAL,
    CapabilityClass.IRREVERSIBLE,
    CapabilityClass.EXFIL_SHAPED,
)


def _policy_for(cls):
    return ToolPolicy({"tool": cls})


def test_determinism_same_inputs_same_decision():
    action = ProposedAction("tool", {"a": "1"}, {"a": (SourceType.UNKNOWN,)})
    policy = _policy_for(CapabilityClass.WRITE_LOCAL)
    first = authorize(action, policy)
    second = authorize(action, policy)
    assert first == second  # frozen dataclasses compare by value


@pytest.mark.parametrize("cls", _ALL_CLASSES)
def test_monotone_in_taint_never_relaxes(cls):
    policy = _policy_for(cls)
    trusted = ProposedAction("tool", {"a": "1"}, {"a": (SourceType.MANUAL,)})
    tainted = ProposedAction("tool", {"a": "1"}, {"a": (SourceType.UNKNOWN,)})
    out_trusted = authorize(trusted, policy).outcome
    out_tainted = authorize(tainted, policy).outcome
    # Adding taint may only move ALLOW -> DENY, never DENY -> ALLOW.
    if out_trusted == GateOutcome.DENY:
        assert out_tainted == GateOutcome.DENY
    # READ_ONLY stays ALLOW under taint; privileged flips ALLOW -> DENY.
    if cls == CapabilityClass.READ_ONLY:
        assert out_tainted == GateOutcome.ALLOW
    else:
        assert out_trusted == GateOutcome.ALLOW
        assert out_tainted == GateOutcome.DENY


def test_adding_a_tainted_arg_never_reallows():
    policy = _policy_for(CapabilityClass.IRREVERSIBLE)
    clean = ProposedAction("tool", {"a": "1"}, {"a": (SourceType.MANUAL,)})
    assert authorize(clean, policy).outcome == GateOutcome.ALLOW
    # Add a second, tainted argument.
    dirtier = ProposedAction(
        "tool",
        {"a": "1", "b": "2"},
        {"a": (SourceType.MANUAL,), "b": (SourceType.UNKNOWN,)},
    )
    assert authorize(dirtier, policy).outcome == GateOutcome.DENY


def test_gate_source_has_no_llm_dependency():
    """The gate must remain pure deterministic code with no model client.

    Source-text anchor (mirrors read_depth's no-network anchor): if anyone wires
    an LLM provider into the gate, this trips deliberately.
    """
    src = (
        pathlib.Path(__file__).resolve().parents[2] / "ares" / "harness" / "action_gate.py"
    ).read_text(encoding="utf-8")
    lowered = src.lower()
    for forbidden in ("anthropic", "openai", "genai", "gemini", "make_client", "llmresponse"):
        assert forbidden not in lowered, f"action_gate must not reference {forbidden!r}"
