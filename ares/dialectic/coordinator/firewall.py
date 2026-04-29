"""Oracle Firewall — validates agent output before downstream propagation.

Session 045: Phase 5 injection resilience. The Oracle Firewall sits
between Architect output and Skeptic input, detecting and neutralizing
prompt injection attempts. Deterministic Python only — no LLM calls.

Public API:
    OracleFirewall      — Main validation class
    FirewallVerdict     — Frozen result of validation
    FirewallViolation   — Individual violation record
"""

import re
from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from ares.dialectic.evidence import EvidencePacket
    from ares.dialectic.messages import DialecticalMessage


# ---------------------------------------------------------------------------
# Frozen result types
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class FirewallViolation:
    """Individual violation detected by the Oracle Firewall.

    Attributes:
        violation_type: Category of violation detected.
        evidence: The offending text fragment.
        severity: How severe the violation is (0.0-1.0).
        fact_id: Which fact triggered it, if applicable.
    """

    violation_type: str   # INSTRUCTION_INJECTION, AUTHORITY_CLAIM, CONFIDENCE_MANIPULATION, STRUCTURAL_BREAK
    evidence: str
    severity: float
    fact_id: Optional[str] = None


@dataclass(frozen=True)
class FirewallVerdict:
    """Result of Oracle Firewall validation.

    Attributes:
        passed: Whether the message passed the firewall.
        violations: All violations detected.
        taint_score: 0.0 = clean, 1.0 = fully tainted.
        sanitized_output: Cleaned interpretations if tainted, None if passed clean.
        timestamp: When the validation was performed.

    Invariant:
        passed=False implies sanitized_output is not None. Downstream cycle
        runners rely on this to fail-closed without re-checking; constructing
        a fail verdict with no sanitized fallback would let a tainted message
        propagate to the Skeptic.
    """

    passed: bool
    violations: Tuple[FirewallViolation, ...]
    taint_score: float
    sanitized_output: Optional[Tuple[str, ...]]
    timestamp: datetime

    def __post_init__(self) -> None:
        if not self.passed and self.sanitized_output is None:
            raise ValueError(
                "FirewallVerdict invariant violated: "
                "passed=False requires sanitized_output to be non-None"
            )


# ---------------------------------------------------------------------------
# Compiled patterns (module-level for reuse)
# ---------------------------------------------------------------------------

# -- Instruction injection patterns --

_IGNORE_PATTERNS = re.compile(
    r"ignore\s+(?:previous|all|above|prior|the\s+above)\s+instructions?",
    re.IGNORECASE,
)

_DISREGARD_PATTERNS = re.compile(
    r"disregard\s+(?:previous|all|above|prior|the\s+above)",
    re.IGNORECASE,
)

_DIRECTIVE_PREFIXES = re.compile(
    r"(?:^|\n)\s*(?:new\s+instructions?|override|instruction|prompt)\s*:",
    re.IGNORECASE,
)

# "SYSTEM:" as a directive — must NOT match legitimate technical terms.
# Negative lookbehind for "operating " and negative lookahead for common
# technical suffixes like "process", "call", "32", "log", "event", "service",
# "account", "file", "drive", "error", "clock", "time", "config", "admin",
# "user", "kernel", "boot", "update", "path", "volume", "memory", "bus",
# "tray", "idle", "info", "monitor".
# The lookahead allows optional whitespace before the technical term so that
# both "system:process" and "system: process" are correctly excluded.
_SYSTEM_DIRECTIVE = re.compile(
    r"(?<!operating\s)"
    r"\bsystem\s*:\s*"
    r"(?!\s*(?:process|call|32|log\b|event|service|account|file|drive|error|"
    r"clock|time|config|admin|user|kernel|boot|update|path|volume|memory|"
    r"bus|tray|idle|info|monitor))",
    re.IGNORECASE,
)

_DO_NOT_FLAG = re.compile(
    r"do\s+not\s+(?:flag|report|classify|alert|detect|block|scan)",
    re.IGNORECASE,
)

_CODE_FENCE_INJECTION = re.compile(
    r"```[\s\S]*?"
    r"(?:ignore|disregard|override|instruction|new\s+instruction|system\s*:)",
    re.IGNORECASE,
)

# -- Authority claim patterns --

_AUTHORITY_VERBS = re.compile(
    r"(?:confirmed|approved|authorized|verified|validated)\s+by\b",
    re.IGNORECASE,
)

_AUTHORITY_ENTITIES = re.compile(
    r"\b(?:SOC\s+analyst|security\s+team\s+confirmed|management\s+approved|"
    r"change\s+ticket|incident\s+ticket)\b",
    re.IGNORECASE,
)

_FALSE_POSITIVE_CLAIMS = re.compile(
    r"\b(?:false\s+positive\s+confirmed|expected\s+behavior|"
    r"authorized\s+penetration\s+test)\b",
    re.IGNORECASE,
)

# Fields in the evidence packet that constitute real authorization evidence.
_AUTHORIZATION_FACT_FIELDS = frozenset({
    "authorization", "change_ticket", "approval", "authorized",
    "red_team", "approved_by", "change_id", "ticket_id",
    "penetration_test", "pentest_authorization",
})

# -- Confidence manipulation patterns --

_DOWNWARD_PUSH = re.compile(
    r"\b(?:definitely\s+benign|clearly\s+harmless|obviously\s+legitimate|"
    r"certainly\s+not\s+malicious|undoubtedly\s+authorized)\b",
    re.IGNORECASE,
)

_UPWARD_PUSH = re.compile(
    r"\b(?:critical\s+threat|immediate\s+escalation\s+required|"
    r"extremely\s+dangerous|catastrophic\s+risk)\b",
    re.IGNORECASE,
)

# -- Structural break patterns --

_CODE_FENCE = re.compile(r"```")

_CODE_FENCE_TYPED = re.compile(
    r"```(?:json|python|system|bash|sh|javascript|xml|yaml|sql)",
    re.IGNORECASE,
)

# Control characters that could disrupt prompt parsing (excluding normal
# whitespace: \t, \n, \r).
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

_EXCESSIVE_NEWLINES = re.compile(r"\n{5,}")

# -- High-threat fact fields for citation-confidence consistency --

_HIGH_THREAT_FIELDS = frozenset({
    "credential_dump", "privilege_escalation", "exploit_module",
    "lateral_movement", "exfiltration", "command_and_control",
    "malware_execution", "ransomware", "rootkit", "backdoor",
    "brute_force", "password_spray", "data_theft",
})

_BENIGN_INDICATOR_FIELDS = frozenset({
    "normal_login", "routine_update", "scheduled_task",
    "system_maintenance", "health_check", "backup_operation",
    "patch_applied", "service_restart", "config_change",
})


# ---------------------------------------------------------------------------
# OracleFirewall
# ---------------------------------------------------------------------------

class OracleFirewall:
    """Validates Architect output before it enters Skeptic context.

    Deterministic. No LLM calls. Pure Python pattern matching + evidence
    graph queries. The Oracle is the incorruptible anchor — it cannot be
    prompt-injected.
    """

    TAINT_THRESHOLD = 0.5

    TYPE_WEIGHTS = {
        "INSTRUCTION_INJECTION": 1.0,
        "STRUCTURAL_BREAK": 0.8,
        "AUTHORITY_CLAIM": 0.7,
        "CONFIDENCE_MANIPULATION": 0.5,
    }

    # -----------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------

    def validate(
        self,
        architect_message: "DialecticalMessage",
        packet: "EvidencePacket",
    ) -> FirewallVerdict:
        """Validate all assertions in the Architect's message.

        Runs every detection check across every assertion interpretation
        and every fact value referenced by those assertions. Calculates
        a composite taint score and returns a frozen verdict.

        Args:
            architect_message: The Architect's output message.
            packet: The evidence packet grounding this analysis.

        Returns:
            FirewallVerdict with pass/fail, violations, and optional
            sanitized output.
        """
        violations: List[FirewallViolation] = []

        for assertion in architect_message.assertions:
            # --- Scan the interpretation text ---
            text = assertion.interpretation
            violations.extend(self._check_instruction_injection(text))
            violations.extend(self._check_authority_claims(text, packet))
            violations.extend(self._check_confidence_manipulation(text))
            violations.extend(self._check_structural_breaks(text))

            # --- Scan the fact values referenced by this assertion ---
            for fact_id in assertion.fact_ids:
                if not packet.has_fact(fact_id):
                    continue
                fact = packet.get_fact(fact_id)
                fact_text = str(fact.value)

                for v in self._check_instruction_injection(fact_text):
                    violations.append(FirewallViolation(
                        violation_type=v.violation_type,
                        evidence=v.evidence,
                        severity=v.severity,
                        fact_id=fact_id,
                    ))

                for v in self._check_authority_claims(fact_text, packet):
                    violations.append(FirewallViolation(
                        violation_type=v.violation_type,
                        evidence=v.evidence,
                        severity=v.severity,
                        fact_id=fact_id,
                    ))

                for v in self._check_structural_breaks(fact_text):
                    violations.append(FirewallViolation(
                        violation_type=v.violation_type,
                        evidence=v.evidence,
                        severity=v.severity,
                        fact_id=fact_id,
                    ))

        # --- Citation-confidence consistency (message-level) ---
        violations.extend(
            self._check_citation_consistency(architect_message, packet)
        )

        # --- Compute taint score ---
        all_violations = tuple(violations)
        taint_score = self._compute_taint_score(all_violations)
        passed = taint_score < self.TAINT_THRESHOLD

        # --- Sanitize if tainted ---
        sanitized_output: Optional[Tuple[str, ...]] = None
        if all_violations:
            sanitized_output = tuple(
                self.sanitize(a.interpretation, all_violations)
                for a in architect_message.assertions
            )

        return FirewallVerdict(
            passed=passed,
            violations=all_violations,
            taint_score=taint_score,
            sanitized_output=sanitized_output,
            timestamp=datetime.utcnow(),
        )

    def sanitize(
        self,
        text: str,
        violations: Tuple[FirewallViolation, ...],
    ) -> str:
        """Remove detected injection content from interpretation text.

        For each violation whose evidence appears in *text*, apply the
        appropriate redaction strategy:
        - INSTRUCTION_INJECTION  -> ``[REDACTED]``
        - AUTHORITY_CLAIM        -> ``[UNVERIFIED CLAIM]``
        - STRUCTURAL_BREAK       -> strip code fences, normalize whitespace
        - CONFIDENCE_MANIPULATION -> ``[REDACTED]``

        Args:
            text: Raw interpretation text.
            violations: All violations from the current verdict.

        Returns:
            Cleaned text safe for downstream use.
        """
        result = text

        for v in violations:
            if v.evidence not in result:
                continue

            if v.violation_type == "INSTRUCTION_INJECTION":
                result = result.replace(v.evidence, "[REDACTED]")

            elif v.violation_type == "AUTHORITY_CLAIM":
                result = result.replace(v.evidence, "[UNVERIFIED CLAIM]")

            elif v.violation_type == "CONFIDENCE_MANIPULATION":
                result = result.replace(v.evidence, "[REDACTED]")

            elif v.violation_type == "STRUCTURAL_BREAK":
                # Strip code fences entirely, normalize whitespace.
                result = result.replace(v.evidence, "")

        # Normalize any leftover structural damage.
        result = _CODE_FENCE.sub("", result)
        result = _EXCESSIVE_NEWLINES.sub("\n\n", result)
        result = _CONTROL_CHARS.sub("", result)
        result = result.strip()

        return result

    # -----------------------------------------------------------------
    # Detection checks (all private, all deterministic)
    # -----------------------------------------------------------------

    def _check_instruction_injection(
        self,
        text: str,
    ) -> List[FirewallViolation]:
        """Detect prompt injection attempts in text.

        Scans for ignore/disregard directives, SYSTEM: prefixes,
        directive prefixes, code-fence injections, and suppression
        commands ("do not flag").

        Returns:
            List of INSTRUCTION_INJECTION violations.
        """
        violations: List[FirewallViolation] = []

        for pattern, severity in (
            (_IGNORE_PATTERNS, 1.0),
            (_DISREGARD_PATTERNS, 1.0),
            (_DIRECTIVE_PREFIXES, 0.95),
            (_SYSTEM_DIRECTIVE, 0.9),
            (_DO_NOT_FLAG, 0.95),
            (_CODE_FENCE_INJECTION, 0.9),
        ):
            for match in pattern.finditer(text):
                violations.append(FirewallViolation(
                    violation_type="INSTRUCTION_INJECTION",
                    evidence=match.group(),
                    severity=severity,
                ))

        return violations

    def _check_authority_claims(
        self,
        text: str,
        packet: "EvidencePacket",
    ) -> List[FirewallViolation]:
        """Detect unsubstantiated authority claims.

        Finds references to external authorization ("confirmed by SOC",
        "change ticket", "false positive confirmed", etc.) and cross-
        references against the evidence packet. If no supporting
        authorization fact exists, it is a violation.

        Returns:
            List of AUTHORITY_CLAIM violations.
        """
        violations: List[FirewallViolation] = []

        # Gather all authorization-related facts once.
        has_authorization_evidence = self._packet_has_authorization(packet)

        for pattern, severity in (
            (_AUTHORITY_VERBS, 0.7),
            (_AUTHORITY_ENTITIES, 0.7),
            (_FALSE_POSITIVE_CLAIMS, 0.8),
        ):
            for match in pattern.finditer(text):
                if has_authorization_evidence:
                    # The packet contains real authorization evidence —
                    # this is a legitimate reference, not an injection.
                    continue
                violations.append(FirewallViolation(
                    violation_type="AUTHORITY_CLAIM",
                    evidence=match.group(),
                    severity=severity,
                ))

        return violations

    def _check_confidence_manipulation(
        self,
        text: str,
    ) -> List[FirewallViolation]:
        """Detect language designed to artificially push confidence.

        Looks for absolute-certainty phrasing in both directions:
        "definitely benign" (downward) and "critical threat" (upward).
        Measured analytical language is NOT manipulation.

        Returns:
            List of CONFIDENCE_MANIPULATION violations.
        """
        violations: List[FirewallViolation] = []

        for match in _DOWNWARD_PUSH.finditer(text):
            violations.append(FirewallViolation(
                violation_type="CONFIDENCE_MANIPULATION",
                evidence=match.group(),
                severity=0.5,
            ))

        for match in _UPWARD_PUSH.finditer(text):
            violations.append(FirewallViolation(
                violation_type="CONFIDENCE_MANIPULATION",
                evidence=match.group(),
                severity=0.6,
            ))

        return violations

    def _check_structural_breaks(
        self,
        text: str,
    ) -> List[FirewallViolation]:
        """Detect attempts to break prompt structure.

        Looks for code fences, typed code fences, excessive newlines,
        and control characters that might disrupt prompt parsing.

        Returns:
            List of STRUCTURAL_BREAK violations.
        """
        violations: List[FirewallViolation] = []

        # Typed code fences are higher severity (more intentional).
        for match in _CODE_FENCE_TYPED.finditer(text):
            violations.append(FirewallViolation(
                violation_type="STRUCTURAL_BREAK",
                evidence=match.group(),
                severity=0.9,
            ))

        # Plain code fences — only flag those NOT already caught as typed.
        typed_positions = {m.start() for m in _CODE_FENCE_TYPED.finditer(text)}
        for match in _CODE_FENCE.finditer(text):
            if match.start() not in typed_positions:
                violations.append(FirewallViolation(
                    violation_type="STRUCTURAL_BREAK",
                    evidence=match.group(),
                    severity=0.8,
                ))

        for match in _EXCESSIVE_NEWLINES.finditer(text):
            violations.append(FirewallViolation(
                violation_type="STRUCTURAL_BREAK",
                evidence=repr(match.group()),
                severity=0.8,
            ))

        for match in _CONTROL_CHARS.finditer(text):
            violations.append(FirewallViolation(
                violation_type="STRUCTURAL_BREAK",
                evidence=repr(match.group()),
                severity=0.85,
            ))

        return violations

    def _check_citation_consistency(
        self,
        message: "DialecticalMessage",
        packet: "EvidencePacket",
    ) -> List[FirewallViolation]:
        """Check citation-conclusion consistency.

        Flags when message confidence is very low but cited facts have
        high-threat field names, or when confidence is very high but
        cited facts are all benign indicators.

        Returns:
            List of CONFIDENCE_MANIPULATION violations.
        """
        violations: List[FirewallViolation] = []
        confidence = message.confidence

        cited_fields: List[str] = []
        for assertion in message.assertions:
            for fact_id in assertion.fact_ids:
                if packet.has_fact(fact_id):
                    cited_fields.append(packet.get_fact(fact_id).field)

        if not cited_fields:
            return violations

        high_threat_count = sum(
            1 for f in cited_fields if f in _HIGH_THREAT_FIELDS
        )
        benign_count = sum(
            1 for f in cited_fields if f in _BENIGN_INDICATOR_FIELDS
        )
        total = len(cited_fields)

        # Low confidence but mostly high-threat citations.
        if confidence < 0.3 and total > 0 and high_threat_count / total > 0.5:
            violations.append(FirewallViolation(
                violation_type="CONFIDENCE_MANIPULATION",
                evidence=(
                    f"confidence={confidence:.2f} but "
                    f"{high_threat_count}/{total} cited facts are high-threat"
                ),
                severity=0.4,
            ))

        # High confidence but all benign citations.
        if confidence > 0.9 and total > 0 and benign_count == total:
            violations.append(FirewallViolation(
                violation_type="CONFIDENCE_MANIPULATION",
                evidence=(
                    f"confidence={confidence:.2f} but "
                    f"all {total} cited facts are benign indicators"
                ),
                severity=0.4,
            ))

        return violations

    # -----------------------------------------------------------------
    # Internal helpers
    # -----------------------------------------------------------------

    @staticmethod
    def _packet_has_authorization(packet: "EvidencePacket") -> bool:
        """Check whether the packet contains any authorization evidence.

        Scans every fact's field name against the known set of
        authorization-related fields.

        Returns:
            True if at least one authorization fact exists.
        """
        for fact in packet.get_all_facts():
            if fact.field in _AUTHORIZATION_FACT_FIELDS:
                return True
        return False

    @staticmethod
    def _compute_taint_score(
        violations: Tuple[FirewallViolation, ...],
    ) -> float:
        """Calculate composite taint score from all violations.

        Each violation contributes ``severity * type_weight``, capped
        at 1.0.

        Returns:
            Taint score between 0.0 and 1.0.
        """
        if not violations:
            return 0.0

        total = sum(
            v.severity * OracleFirewall.TYPE_WEIGHTS.get(v.violation_type, 0.5)
            for v in violations
        )
        return min(1.0, total)
