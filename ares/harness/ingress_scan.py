"""Ingress injection scan: normalize, then run the real firewall's
high-precision injection detectors fail-on-any over ALL captured content
(closing ARES's uncited-fact blind spot for the harness).
"""
from dataclasses import dataclass

from ares.dialectic.coordinator.firewall import FirewallViolation, OracleFirewall
from ares.harness.capture import CapturedRecord
from ares.harness.ioc_anchor import IOCMatch, scan_iocs
from ares.harness.normalize import normalize

HIGH_PRECISION_TYPES = frozenset({"INSTRUCTION_INJECTION", "STRUCTURAL_BREAK"})

_FIREWALL = OracleFirewall()


@dataclass(frozen=True)
class IngressScanResult:
    passed: bool
    normalized_text: str
    violations: tuple[FirewallViolation, ...]
    ioc_matches: tuple[IOCMatch, ...]
    taint_score: float


def scan(record: CapturedRecord) -> IngressScanResult:
    normalized = normalize(record.content)
    found = []
    found.extend(_FIREWALL._check_instruction_injection(normalized))
    found.extend(_FIREWALL._check_structural_breaks(normalized))
    violations = tuple(
        v for v in found if v.violation_type in HIGH_PRECISION_TYPES
    )
    taint = _FIREWALL._compute_taint_score(violations)
    iocs = scan_iocs(normalized)
    passed = len(violations) == 0
    return IngressScanResult(
        passed=passed,
        normalized_text=normalized,
        violations=violations,
        ioc_matches=iocs,
        taint_score=taint,
    )
