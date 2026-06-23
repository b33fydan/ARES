# tests/harness/test_action_gate.py
import dataclasses

import pytest

from ares.dialectic.evidence import SourceType
from ares.harness.action_gate import (
    CapabilityClass,
    GateDecision,
    GateOutcome,
    ProposedAction,
    ToolPolicy,
    arg_is_tainted,
    authorize,
    tainted_args,
)


def _policy():
    return ToolPolicy(
        {
            "read_file": CapabilityClass.READ_ONLY,
            "write_file": CapabilityClass.WRITE_LOCAL,
            "delete_file": CapabilityClass.IRREVERSIBLE,
            "send_email": CapabilityClass.EXFIL_SHAPED,
        }
    )


def _trusted_sources(*names):
    return {name: (SourceType.MANUAL,) for name in names}


def _untrusted_sources(*names):
    return {name: (SourceType.UNKNOWN,) for name in names}


def test_classify_known_and_unknown_tool():
    p = _policy()
    assert p.classify("read_file") == CapabilityClass.READ_ONLY
    # Unknown tool fails closed -> the privileged default class.
    assert p.classify("totally_unregistered_tool") == CapabilityClass.IRREVERSIBLE


def test_readonly_allows_even_when_tainted():
    action = ProposedAction("read_file", {"path": "/etc/hosts"}, _untrusted_sources("path"))
    d = authorize(action, _policy())
    assert d.outcome == GateOutcome.ALLOW
    assert d.capability_class == CapabilityClass.READ_ONLY


def test_privileged_with_trusted_args_allows():
    action = ProposedAction("delete_file", {"path": "/tmp/x"}, _trusted_sources("path"))
    d = authorize(action, _policy())
    assert d.outcome == GateOutcome.ALLOW
    assert d.tainted_args == ()


def test_privileged_with_tainted_arg_denies():
    action = ProposedAction("send_email", {"to": "x@evil.com"}, _untrusted_sources("to"))
    d = authorize(action, _policy())
    assert d.outcome == GateOutcome.DENY
    assert "to" in d.tainted_args
    assert d.capability_class == CapabilityClass.EXFIL_SHAPED


def test_failsafe_arg_without_provenance_is_tainted():
    # 'path' present in args but absent from arg_sources -> tainted (fail-safe).
    action = ProposedAction("write_file", {"path": "/tmp/x"}, arg_sources={})
    assert arg_is_tainted(action, "path") is True
    assert tainted_args(action) == ("path",)
    assert authorize(action, _policy()).outcome == GateOutcome.DENY


def test_failsafe_empty_source_tuple_is_tainted():
    action = ProposedAction("write_file", {"path": "/tmp/x"}, arg_sources={"path": ()})
    assert arg_is_tainted(action, "path") is True


def test_unknown_tool_fails_closed_on_taint():
    # Unregistered tool + a tainted arg -> denied via the privileged default class.
    action = ProposedAction("mystery_tool", {"x": "1"}, _untrusted_sources("x"))
    assert authorize(action, _policy()).outcome == GateOutcome.DENY


def test_privileged_no_args_allows():
    # No args -> no tainted args -> allowed (no injected data can steer the call).
    action = ProposedAction("delete_file", {}, arg_sources={})
    assert authorize(action, _policy()).outcome == GateOutcome.ALLOW


def test_mixed_sources_any_untrusted_taints():
    action = ProposedAction(
        "write_file",
        {"path": "/tmp/x"},
        {"path": (SourceType.MANUAL, SourceType.UNKNOWN)},
    )
    assert arg_is_tainted(action, "path") is True
    assert authorize(action, _policy()).outcome == GateOutcome.DENY


def test_gate_decision_is_frozen():
    d = authorize(ProposedAction("read_file", {}, {}), _policy())
    assert isinstance(d, GateDecision)
    with pytest.raises(dataclasses.FrozenInstanceError):
        d.outcome = GateOutcome.DENY
