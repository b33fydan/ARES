"""Per-suite capability policy for AgentDojo tools (config, not model-decided).

Each tool is assigned a CapabilityClass from its semantics (design §7). The
assignment is auditable: the offline test asserts every name in EXPECTED_BANKING_TOOLS
is classified; Task 8's bench-venv audit checks the mapping against the suite's
live runtime.functions. Unknown tools fall through to the fail-closed IRREVERSIBLE
default of ToolPolicy.
"""
from __future__ import annotations

from ares.harness.action_gate import CapabilityClass, ToolPolicy

# AgentDojo v1.2 default_suites/v1/banking/task_suite.py :: TOOLS (11 tools).
EXPECTED_BANKING_TOOLS = frozenset(
    {
        "get_iban",
        "send_money",
        "schedule_transaction",
        "update_scheduled_transaction",
        "get_balance",
        "get_most_recent_transactions",
        "get_scheduled_transactions",
        "read_file",
        "get_user_info",
        "update_password",
        "update_user_info",
    }
)

_BANKING_MAPPING = {
    # Read-only getters / file read.
    "get_iban": CapabilityClass.READ_ONLY,
    "get_balance": CapabilityClass.READ_ONLY,
    "get_most_recent_transactions": CapabilityClass.READ_ONLY,
    "get_scheduled_transactions": CapabilityClass.READ_ONLY,
    "read_file": CapabilityClass.READ_ONLY,
    "get_user_info": CapabilityClass.READ_ONLY,
    # Money movement / egress — the attacker target class.
    "send_money": CapabilityClass.EXFIL_SHAPED,
    "schedule_transaction": CapabilityClass.EXFIL_SHAPED,
    "update_scheduled_transaction": CapabilityClass.EXFIL_SHAPED,
    # Local account mutations.
    "update_password": CapabilityClass.WRITE_LOCAL,
    "update_user_info": CapabilityClass.WRITE_LOCAL,
}


def banking_policy() -> ToolPolicy:
    """ToolPolicy for the AgentDojo banking suite (fail-closed IRREVERSIBLE default)."""
    return ToolPolicy(mapping=dict(_BANKING_MAPPING))
