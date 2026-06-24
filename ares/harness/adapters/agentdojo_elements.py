# ares/harness/adapters/agentdojo_elements.py
"""Duck-typed AgentDojo pipeline elements — imports NOTHING from agentdojo.

Both elements operate on list-of-dict messages, an injected duck-typed runtime
(.run_function / .functions), and (for the gated executor) an injected real
ToolsExecutor. Denied-call results are plain dicts matching AgentDojo's
ChatToolResultMessage schema. Consequence: the entire adapter unit-tests offline
in the main venv with synthetic messages + fakes. See the design note §3, §6.

GatedToolsExecutor allow/deny/execute/capture/record:
  - Delegate unchanged unless the last message is an assistant message with
    tool_calls.
  - Reconstruct captured records: the user query as MANUAL (trusted); prior tool
    outputs as UNKNOWN (untrusted), read from the tracker's RAW stash (never the
    sanitized messages -- design §5 raw-byte binding).
  - Per call: derive_arg_sources -> ProposedAction -> authorize; append the
    GateDecision to the tracker. Fail-closed: any error -> DENIED.
  - Execute ALLOWED calls via the real injected executor (patched last assistant
    message carrying only allowed tool_calls), capturing each raw output keyed by
    tool_call_id. DENIED calls get a schema-complete denied dict.

AresIngressElement (Task 4) sanitizes the appended tool messages afterward.
"""
from __future__ import annotations

import copy

from ares.dialectic.evidence import Provenance, SourceType
from ares.harness.action_gate import (
    GateOutcome,
    ProposedAction,
    ToolPolicy,
    authorize,
)
from ares.harness.capture import CapturedRecord
from ares.harness.ingress_scan import scan
from ares.harness.provenance_tracker import derive_arg_sources
from ares.harness.quarantine import inert_render, redact

_DENIED_ERROR_FMT = "blocked by ARES-Harness action gate (policy: {reason})"


def build_denied_result(tool_call) -> dict:
    """A schema-complete ChatToolResultMessage dict for a DENIED call.

    All five Required fields; ``content`` is a one-element block list (never a
    bare string) so AgentDojo's ``TaskResults(**res_dict)`` revalidation on
    reload does not raise (design §3b.3).
    """
    return {
        "role": "tool",
        "tool_call": tool_call,
        "tool_call_id": getattr(tool_call, "id", None),
        "error": _DENIED_ERROR_FMT.format(reason="capability gate denied"),
        "content": [{"type": "text", "content": ""}],
    }


class GateTracker:
    """Mutable per-task sink (the one deliberate mutable object — design §3b.2).

    Collects gate decisions and the RAW tool outputs (keyed by tool_call_id) the
    next turn's provenance derivation reads. Reset per task by the runner.
    """

    def __init__(self) -> None:
        self.decisions: list = []
        self.raw_outputs: dict[str, str] = {}

    def record_decision(self, decision) -> None:
        self.decisions.append(decision)

    def stash_output(self, tool_call_id: str, text: str) -> None:
        if tool_call_id is not None:
            self.raw_outputs[tool_call_id] = text

    def reset(self) -> None:
        self.decisions = []
        self.raw_outputs = {}


def _text_of_content(content) -> str:
    """Flatten a ChatToolResultMessage content (block list) to str with
    AgentDojo's get_text_content_as_str semantics: join non-None block contents
    with newlines. Tolerates a bare string defensively."""
    if isinstance(content, str):
        return content
    if not content:
        return ""
    parts = [b.get("content") for b in content if isinstance(b, dict)]
    return "\n".join(p for p in parts if p is not None)


def _reconstruct_records(messages) -> tuple[CapturedRecord, ...]:
    """User query -> MANUAL (trusted). (Prior tool outputs are supplied via the
    tracker's raw stash, not here -- see GatedToolsExecutor.query.)"""
    records: list[CapturedRecord] = []
    for m in messages:
        if m.get("role") == "user":
            text = _text_of_content(m.get("content"))
            records.append(
                CapturedRecord(
                    record_id=f"user:{len(records)}",
                    content=text,
                    provenance=Provenance(source_type=SourceType.MANUAL, source_id="user"),
                )
            )
    return tuple(records)


class GatedToolsExecutor:
    def __init__(self, real_executor, policy: ToolPolicy, tracker: GateTracker) -> None:
        self._real = real_executor
        self._policy = policy
        self._tracker = tracker

    def query(self, query, runtime, env, messages, extra_args):
        if not messages:
            return query, runtime, env, messages, extra_args
        last = messages[-1]
        if last.get("role") != "assistant" or not last.get("tool_calls"):
            return query, runtime, env, messages, extra_args

        # Build the captured-record set: user query (trusted) + raw stashed
        # untrusted tool outputs from prior turns.
        records = list(_reconstruct_records(messages))
        for cid, raw in self._tracker.raw_outputs.items():
            records.append(
                CapturedRecord(
                    record_id=f"tool:{cid}",
                    content=raw,
                    provenance=Provenance(source_type=SourceType.UNKNOWN, source_id=f"tool:{cid}"),
                )
            )

        allowed, denied = [], []
        for tc in last["tool_calls"]:
            try:
                arg_sources = derive_arg_sources(dict(tc.args), records)
                action = ProposedAction(tc.function, dict(tc.args), arg_sources)
                decision = authorize(action, self._policy)
            except Exception:
                self._tracker.record_decision(
                    _FailClosedDecision(tc.function)
                )
                denied.append(tc)
                continue
            self._tracker.record_decision(decision)
            (allowed if decision.outcome == GateOutcome.ALLOW else denied).append(tc)

        out = list(messages)
        # Execute ALLOWED calls via the real executor on a patched last message.
        if allowed:
            patched_last = copy.copy(last)
            patched_last["tool_calls"] = allowed
            _, _, _, executed_msgs, _ = self._real.query(
                query, runtime, env, [*messages[:-1], patched_last], extra_args
            )
            # The real executor appended one tool message per allowed call.
            new_tool_msgs = executed_msgs[len(messages):]
            for tm in new_tool_msgs:
                self._tracker.stash_output(
                    tm.get("tool_call_id"), _text_of_content(tm.get("content"))
                )
            out.extend(new_tool_msgs)
        # Append schema-complete denied results.
        for tc in denied:
            out.append(build_denied_result(tc))

        return query, runtime, env, out, extra_args


class _FailClosedDecision:
    """Minimal DENY decision recorded when gate derivation itself errors."""

    outcome = GateOutcome.DENY

    def __init__(self, tool_name: str) -> None:
        self.tool_name = tool_name
        self.reason = "gate derivation error -> fail-closed deny"
        self.tainted_args = ()


_WITHHELD_NOTICE = "[TOOL OUTPUT WITHHELD: ingress scan failed; content quarantined.]"


class AresIngressElement:
    """Sanitize the trailing block of newly-appended tool messages in place.

    Backward-walk the trailing consecutive ``role=="tool"`` messages, flatten +
    capture (UNKNOWN) + scan each; redact on a hit; inert-render; write back as a
    one-element text block list. Mutates the message dicts in place and returns
    the SAME messages list (the loop rebinds from the return). Idempotent across
    loop iterations and fail-closed on scan error.
    """

    def query(self, query, runtime, env, messages, extra_args):
        for i in range(len(messages) - 1, -1, -1):
            if messages[i].get("role") != "tool":
                break
            self._sanitize_in_place(messages[i], i)
        return query, runtime, env, messages, extra_args

    @staticmethod
    def _sanitize_in_place(message, index) -> None:
        text = _text_of_content(message.get("content"))
        record = CapturedRecord(
            record_id=f"tool-ingress:{index}",
            content=text,
            provenance=Provenance(source_type=SourceType.UNKNOWN, source_id="tool"),
        )
        try:
            result = scan(record)
        except Exception:
            message["content"] = [{"type": "text", "content": _WITHHELD_NOTICE}]
            return
        safe = redact(record, result.violations) if not result.passed else record
        rendered = inert_render(safe)
        message["content"] = [{"type": "text", "content": rendered}]
