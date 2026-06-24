from ares.harness.action_gate import CapabilityClass
from ares.harness.adapters.agentdojo_policy import (
    EXPECTED_BANKING_TOOLS,
    banking_policy,
)


def test_every_banking_tool_is_classified():
    policy = banking_policy()
    for tool in EXPECTED_BANKING_TOOLS:
        assert tool in policy.mapping, f"{tool} unclassified"


def test_unknown_tool_fails_closed_to_irreversible():
    policy = banking_policy()
    assert policy.classify("totally_unregistered") == CapabilityClass.IRREVERSIBLE


def test_readonly_getters_are_read_only():
    policy = banking_policy()
    for tool in ("get_iban", "get_balance", "get_most_recent_transactions",
                 "get_scheduled_transactions", "read_file", "get_user_info"):
        assert policy.classify(tool) == CapabilityClass.READ_ONLY


def test_money_movers_are_exfil_shaped():
    policy = banking_policy()
    for tool in ("send_money", "schedule_transaction", "update_scheduled_transaction"):
        assert policy.classify(tool) == CapabilityClass.EXFIL_SHAPED


def test_local_mutations_are_write_local():
    policy = banking_policy()
    for tool in ("update_password", "update_user_info"):
        assert policy.classify(tool) == CapabilityClass.WRITE_LOCAL


def test_expected_set_has_eleven_tools():
    assert len(EXPECTED_BANKING_TOOLS) == 11
