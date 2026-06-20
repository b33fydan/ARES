"""Anchor test: pin the OracleFirewall private-detector surface reused by ingress_scan.

ingress_scan.py calls _check_instruction_injection, _check_structural_breaks, and
_compute_taint_score directly on the firewall.  If a future firewall refactor renames,
removes, or changes the signature of those methods, these tests trip a deliberate harness
failure rather than a silent production error.
"""
from ares.dialectic.coordinator.firewall import OracleFirewall


def test_check_instruction_injection_returns_violations():
    """_check_instruction_injection must return a non-empty list for a canonical phrase."""
    fw = OracleFirewall()
    result = fw._check_instruction_injection("ignore previous instructions")
    assert isinstance(result, list)
    assert len(result) > 0
    assert all(v.violation_type == "INSTRUCTION_INJECTION" for v in result)


def test_check_structural_breaks_callable_and_returns_list_with_attribute():
    """_check_structural_breaks must be callable with a single str arg and return a list
    whose items (if any) expose a .violation_type attribute.

    A typed code fence (```python) reliably triggers a STRUCTURAL_BREAK violation.
    """
    fw = OracleFirewall()
    payload = "```python\nprint('hello')\n```"
    result = fw._check_structural_breaks(payload)
    assert isinstance(result, list)
    # The typed code fence must trigger at least one STRUCTURAL_BREAK.
    assert len(result) > 0
    for item in result:
        assert hasattr(item, "violation_type")
    assert any(item.violation_type == "STRUCTURAL_BREAK" for item in result)


def test_compute_taint_score_empty_tuple_returns_zero():
    """_compute_taint_score must accept an empty tuple via both class and instance call."""
    # Staticmethod on class
    assert OracleFirewall._compute_taint_score(()) == 0.0
    # Staticmethod via instance (used in ingress_scan after FIX 5)
    fw = OracleFirewall()
    assert fw._compute_taint_score(()) == 0.0
