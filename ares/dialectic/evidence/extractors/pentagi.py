"""PentAGI evidence extractor.

Parses PentAGI action JSON into Facts for dialectical reasoning.
Supports nmap, sqlmap, metasploit, nuclei, and generic tool output.

PentAGI (github.com/vxcontrol/pentagi) produces structured action
results from autonomous penetration testing. This extractor transforms
those results into typed Facts that ARES agents can cite during debate.
"""

import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Optional

from ..provenance import Provenance, SourceType
from ..fact import Fact, EntityType
from .protocol import (
    ExtractionError,
    ExtractionStats,
    ExtractionResult,
)


# =============================================================================
# Constants
# =============================================================================

# Supported PentAGI tool types with dedicated handlers
SUPPORTED_TOOLS = frozenset({
    "nmap", "sqlmap", "metasploit", "nuclei",
    "nikto", "gobuster", "hydra",
})

# Error type constants
MALFORMED_JSON = "MALFORMED_JSON"
MISSING_FIELD = "MISSING_FIELD"
INVALID_TIMESTAMP = "INVALID_TIMESTAMP"
UNSUPPORTED_TOOL = "UNSUPPORTED_TOOL"
INVALID_RESULT = "INVALID_RESULT"


# =============================================================================
# Intermediate parsed types
# =============================================================================


@dataclass(frozen=True)
class PentAGIAction:
    """Parsed PentAGI action record.

    Attributes:
        action_id: Unique action identifier from PentAGI.
        tool: Tool name (nmap, sqlmap, metasploit, etc.).
        target: Target host, URL, or service.
        timestamp: When the action was executed.
        parameters: Tool invocation parameters.
        result: Tool-specific result dictionary.
        action_index: Position in the actions array (0-based).
    """

    action_id: str
    tool: str
    target: str
    timestamp: datetime
    parameters: str
    result: dict
    action_index: int


# =============================================================================
# Extractor
# =============================================================================


class PentAGIExtractor:
    """Parses PentAGI action JSON into Facts.

    Implements ExtractorProtocol. Handles nmap, sqlmap, metasploit,
    nuclei, and generic pentest tool output from PentAGI action logs.

    Input format: JSON string with top-level "actions" array. Each action
    has: action_id, tool, target, timestamp, parameters, result.

    Attributes:
        VERSION: Semantic version of this extractor.
    """

    VERSION: str = "1.0.0"

    def extract(
        self,
        raw: bytes | str,
        *,
        source_ref: str,
        strict: bool = True,
    ) -> ExtractionResult:
        """Parse PentAGI action JSON into Facts.

        Args:
            raw: Raw JSON data (bytes or string) with "actions" array.
            source_ref: Reference to data source for provenance tracking.
            strict: If True, raise on first error. If False, collect errors
                   and return partial results.

        Returns:
            ExtractionResult containing Facts, errors, and stats.

        Raises:
            ValueError: In strict mode, on first parse error.
        """
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8")

        # Parse top-level JSON
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as e:
            error = ExtractionError(
                line_number=None,
                raw_snippet=raw[:200],
                error_type=MALFORMED_JSON,
                message=f"Invalid JSON: {e}",
            )
            if strict:
                raise ValueError(error.message) from e
            return ExtractionResult(
                facts=(),
                errors=(error,),
                stats=ExtractionStats(
                    events_seen=0, events_parsed=0,
                    events_dropped=0, facts_emitted=0,
                ),
                source_ref=source_ref,
                extractor_version=self.VERSION,
            )

        actions_raw = data.get("actions", [])
        if not isinstance(actions_raw, list):
            error = ExtractionError(
                line_number=None,
                raw_snippet=str(data)[:200],
                error_type=MALFORMED_JSON,
                message="Top-level 'actions' must be a list",
            )
            if strict:
                raise ValueError(error.message)
            return ExtractionResult(
                facts=(),
                errors=(error,),
                stats=ExtractionStats(
                    events_seen=0, events_parsed=0,
                    events_dropped=0, facts_emitted=0,
                ),
                source_ref=source_ref,
                extractor_version=self.VERSION,
            )

        facts: list[Fact] = []
        errors: list[ExtractionError] = []
        events_seen = 0
        events_parsed = 0
        events_dropped = 0

        for idx, action_raw in enumerate(actions_raw):
            events_seen += 1

            # Parse action record
            action = self._parse_action(action_raw, idx)
            if action is None:
                events_dropped += 1
                error = ExtractionError(
                    line_number=idx,
                    raw_snippet=json.dumps(action_raw)[:200],
                    error_type=MISSING_FIELD,
                    message=f"Action {idx}: missing required fields (action_id, tool, target, timestamp, result)",
                )
                if strict:
                    raise ValueError(error.message)
                errors.append(error)
                continue

            # Extract facts from action
            try:
                action_facts = self._extract_facts(action, source_ref)
                if action_facts:
                    facts.extend(action_facts)
                    events_parsed += 1
                else:
                    events_dropped += 1
                    error = ExtractionError(
                        line_number=idx,
                        raw_snippet=json.dumps(action_raw)[:200],
                        error_type=INVALID_RESULT,
                        message=f"Action {idx}: tool '{action.tool}' produced no facts from result",
                    )
                    if strict:
                        raise ValueError(error.message)
                    errors.append(error)
            except ValueError as e:
                events_dropped += 1
                error = ExtractionError(
                    line_number=idx,
                    raw_snippet=json.dumps(action_raw)[:200],
                    error_type=INVALID_RESULT,
                    message=str(e),
                )
                if strict:
                    raise
                errors.append(error)

        stats = ExtractionStats(
            events_seen=events_seen,
            events_parsed=events_parsed,
            events_dropped=events_dropped,
            facts_emitted=len(facts),
        )

        return ExtractionResult(
            facts=tuple(facts),
            errors=tuple(errors),
            stats=stats,
            source_ref=source_ref,
            extractor_version=self.VERSION,
        )

    def _parse_action(
        self, raw: Any, index: int
    ) -> Optional[PentAGIAction]:
        """Parse a raw action dict into a PentAGIAction.

        Args:
            raw: Raw action dictionary from JSON.
            index: Position in the actions array.

        Returns:
            PentAGIAction if parsed successfully, None otherwise.
        """
        if not isinstance(raw, dict):
            return None

        required = ("action_id", "tool", "target", "timestamp", "result")
        for field in required:
            if field not in raw:
                return None

        # Parse timestamp
        try:
            ts = datetime.fromisoformat(raw["timestamp"].replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            return None

        result = raw["result"]
        if not isinstance(result, dict):
            return None

        return PentAGIAction(
            action_id=raw["action_id"],
            tool=raw["tool"].lower().strip(),
            target=raw["target"],
            timestamp=ts,
            parameters=raw.get("parameters", ""),
            result=result,
            action_index=index,
        )

    def _make_provenance(
        self, source_ref: str, action: PentAGIAction
    ) -> Provenance:
        """Create provenance for a fact from a PentAGI action.

        Args:
            source_ref: Data source reference.
            action: Parsed PentAGI action.

        Returns:
            Provenance instance with PENTEST_TOOL source type.
        """
        return Provenance(
            source_type=SourceType.PENTEST_TOOL,
            source_id=source_ref,
            parser_version=self.VERSION,
            raw_reference=f"action={action.action_id},tool={action.tool},index={action.action_index}",
        )

    def _make_fact(
        self,
        fact_id: str,
        entity_id: str,
        entity_type: EntityType,
        field: str,
        value: object,
        timestamp: datetime,
        provenance: Provenance,
    ) -> Fact:
        """Create a Fact with given parameters.

        Args:
            fact_id: Unique fact identifier.
            entity_id: Entity this fact describes.
            entity_type: NODE or EDGE.
            field: Field name.
            value: Field value.
            timestamp: When fact was observed.
            provenance: Source provenance.

        Returns:
            Fact instance.
        """
        return Fact(
            fact_id=fact_id,
            entity_id=entity_id,
            entity_type=entity_type,
            field=field,
            value=value,
            timestamp=timestamp,
            provenance=provenance,
        )

    def _extract_facts(
        self, action: PentAGIAction, source_ref: str
    ) -> list[Fact]:
        """Extract Facts from a parsed PentAGI action.

        Dispatches to tool-specific handlers.

        Args:
            action: Parsed PentAGI action.
            source_ref: Source reference for provenance.

        Returns:
            List of Facts, or empty list if not extractable.
        """
        tool = action.tool

        if tool == "nmap":
            return self._extract_nmap_facts(action, source_ref)
        elif tool == "sqlmap":
            return self._extract_sqlmap_facts(action, source_ref)
        elif tool == "metasploit":
            return self._extract_metasploit_facts(action, source_ref)
        elif tool == "nuclei":
            return self._extract_nuclei_facts(action, source_ref)
        elif tool == "nikto":
            return self._extract_nikto_facts(action, source_ref)
        elif tool == "gobuster":
            return self._extract_gobuster_facts(action, source_ref)
        elif tool == "hydra":
            return self._extract_hydra_facts(action, source_ref)
        else:
            return self._extract_generic_facts(action, source_ref)

    # =========================================================================
    # Nmap handler
    # =========================================================================

    def _extract_nmap_facts(
        self, action: PentAGIAction, source_ref: str
    ) -> list[Fact]:
        """Extract facts from nmap scan results.

        Handles open ports, services, and OS detection.

        Args:
            action: Parsed PentAGI action with nmap result.
            source_ref: Source reference for provenance.

        Returns:
            List of Facts.
        """
        result = action.result
        provenance = self._make_provenance(source_ref, action)
        entity_id = f"target:{action.target}"
        base_id = f"nmap-{action.action_id}"
        facts: list[Fact] = []

        # Base scan fact
        facts.append(self._make_fact(
            f"{base_id}-event_type", entity_id, EntityType.NODE,
            "event_type", "port_scan", action.timestamp, provenance,
        ))
        facts.append(self._make_fact(
            f"{base_id}-tool", entity_id, EntityType.NODE,
            "tool", "nmap", action.timestamp, provenance,
        ))
        facts.append(self._make_fact(
            f"{base_id}-target", entity_id, EntityType.NODE,
            "target", action.target, action.timestamp, provenance,
        ))
        facts.append(self._make_fact(
            f"{base_id}-parameters", entity_id, EntityType.NODE,
            "parameters", action.parameters, action.timestamp, provenance,
        ))

        # Open ports
        open_ports = result.get("open_ports", [])
        for port_info in open_ports:
            if not isinstance(port_info, dict) or "port" not in port_info:
                continue
            port = port_info["port"]
            service = port_info.get("service", "unknown")
            version = port_info.get("version", "")
            port_entity = f"service:{action.target}:{port}"
            port_base = f"{base_id}-port-{port}"

            facts.append(self._make_fact(
                f"{port_base}-port", port_entity, EntityType.NODE,
                "port", port, action.timestamp, provenance,
            ))
            facts.append(self._make_fact(
                f"{port_base}-service", port_entity, EntityType.NODE,
                "service_name", service, action.timestamp, provenance,
            ))
            if version:
                facts.append(self._make_fact(
                    f"{port_base}-version", port_entity, EntityType.NODE,
                    "service_version", version, action.timestamp, provenance,
                ))

        # OS detection
        os_info = result.get("os_detection")
        if os_info:
            facts.append(self._make_fact(
                f"{base_id}-os", entity_id, EntityType.NODE,
                "os_detection", os_info, action.timestamp, provenance,
            ))

        return facts

    # =========================================================================
    # SQLMap handler
    # =========================================================================

    def _extract_sqlmap_facts(
        self, action: PentAGIAction, source_ref: str
    ) -> list[Fact]:
        """Extract facts from sqlmap injection results.

        Args:
            action: Parsed PentAGI action with sqlmap result.
            source_ref: Source reference for provenance.

        Returns:
            List of Facts.
        """
        result = action.result
        provenance = self._make_provenance(source_ref, action)
        entity_id = f"target:{action.target}"
        base_id = f"sqlmap-{action.action_id}"
        facts: list[Fact] = []

        facts.append(self._make_fact(
            f"{base_id}-event_type", entity_id, EntityType.NODE,
            "event_type", "sql_injection_test", action.timestamp, provenance,
        ))
        facts.append(self._make_fact(
            f"{base_id}-tool", entity_id, EntityType.NODE,
            "tool", "sqlmap", action.timestamp, provenance,
        ))
        facts.append(self._make_fact(
            f"{base_id}-target", entity_id, EntityType.NODE,
            "target", action.target, action.timestamp, provenance,
        ))

        # Vulnerability status
        vulnerable = result.get("vulnerable", False)
        facts.append(self._make_fact(
            f"{base_id}-vulnerable", entity_id, EntityType.NODE,
            "vulnerable", vulnerable, action.timestamp, provenance,
        ))

        if vulnerable:
            injection_type = result.get("injection_type", "unknown")
            facts.append(self._make_fact(
                f"{base_id}-injection_type", entity_id, EntityType.NODE,
                "injection_type", injection_type, action.timestamp, provenance,
            ))

            parameter = result.get("parameter")
            if parameter:
                facts.append(self._make_fact(
                    f"{base_id}-parameter", entity_id, EntityType.NODE,
                    "vulnerable_parameter", parameter, action.timestamp, provenance,
                ))

            dbms = result.get("dbms")
            if dbms:
                facts.append(self._make_fact(
                    f"{base_id}-dbms", entity_id, EntityType.NODE,
                    "dbms", dbms, action.timestamp, provenance,
                ))

            databases = result.get("databases", [])
            if databases:
                facts.append(self._make_fact(
                    f"{base_id}-databases", entity_id, EntityType.NODE,
                    "databases_found", databases, action.timestamp, provenance,
                ))

        return facts

    # =========================================================================
    # Metasploit handler
    # =========================================================================

    def _extract_metasploit_facts(
        self, action: PentAGIAction, source_ref: str
    ) -> list[Fact]:
        """Extract facts from metasploit exploitation results.

        Args:
            action: Parsed PentAGI action with metasploit result.
            source_ref: Source reference for provenance.

        Returns:
            List of Facts.
        """
        result = action.result
        provenance = self._make_provenance(source_ref, action)
        entity_id = f"target:{action.target}"
        base_id = f"msf-{action.action_id}"
        facts: list[Fact] = []

        facts.append(self._make_fact(
            f"{base_id}-event_type", entity_id, EntityType.NODE,
            "event_type", "exploitation_attempt", action.timestamp, provenance,
        ))
        facts.append(self._make_fact(
            f"{base_id}-tool", entity_id, EntityType.NODE,
            "tool", "metasploit", action.timestamp, provenance,
        ))
        facts.append(self._make_fact(
            f"{base_id}-target", entity_id, EntityType.NODE,
            "target", action.target, action.timestamp, provenance,
        ))
        facts.append(self._make_fact(
            f"{base_id}-module", entity_id, EntityType.NODE,
            "exploit_module", action.parameters, action.timestamp, provenance,
        ))

        exploited = result.get("exploited", False)
        facts.append(self._make_fact(
            f"{base_id}-exploited", entity_id, EntityType.NODE,
            "exploited", exploited, action.timestamp, provenance,
        ))

        if exploited:
            payload = result.get("payload")
            if payload:
                facts.append(self._make_fact(
                    f"{base_id}-payload", entity_id, EntityType.NODE,
                    "payload", payload, action.timestamp, provenance,
                ))

            session_type = result.get("session_type")
            if session_type:
                facts.append(self._make_fact(
                    f"{base_id}-session_type", entity_id, EntityType.NODE,
                    "session_type", session_type, action.timestamp, provenance,
                ))

            access_level = result.get("access_level")
            if access_level:
                facts.append(self._make_fact(
                    f"{base_id}-access_level", entity_id, EntityType.NODE,
                    "access_level", access_level, action.timestamp, provenance,
                ))

        return facts

    # =========================================================================
    # Nuclei handler
    # =========================================================================

    def _extract_nuclei_facts(
        self, action: PentAGIAction, source_ref: str
    ) -> list[Fact]:
        """Extract facts from nuclei vulnerability scan results.

        Args:
            action: Parsed PentAGI action with nuclei result.
            source_ref: Source reference for provenance.

        Returns:
            List of Facts.
        """
        result = action.result
        provenance = self._make_provenance(source_ref, action)
        entity_id = f"target:{action.target}"
        base_id = f"nuclei-{action.action_id}"
        facts: list[Fact] = []

        facts.append(self._make_fact(
            f"{base_id}-event_type", entity_id, EntityType.NODE,
            "event_type", "vulnerability_scan", action.timestamp, provenance,
        ))
        facts.append(self._make_fact(
            f"{base_id}-tool", entity_id, EntityType.NODE,
            "tool", "nuclei", action.timestamp, provenance,
        ))
        facts.append(self._make_fact(
            f"{base_id}-target", entity_id, EntityType.NODE,
            "target", action.target, action.timestamp, provenance,
        ))

        # Findings array
        findings = result.get("findings", [])
        for i, finding in enumerate(findings):
            if not isinstance(finding, dict):
                continue
            f_base = f"{base_id}-finding-{i}"
            template_id = finding.get("template_id", f"unknown-{i}")
            severity = finding.get("severity", "unknown")
            matched_at = finding.get("matched_at", action.target)

            facts.append(self._make_fact(
                f"{f_base}-template_id", entity_id, EntityType.NODE,
                "template_id", template_id, action.timestamp, provenance,
            ))
            facts.append(self._make_fact(
                f"{f_base}-severity", entity_id, EntityType.NODE,
                "vulnerability_severity", severity, action.timestamp, provenance,
            ))
            facts.append(self._make_fact(
                f"{f_base}-matched_at", entity_id, EntityType.NODE,
                "matched_at", matched_at, action.timestamp, provenance,
            ))

            name = finding.get("name")
            if name:
                facts.append(self._make_fact(
                    f"{f_base}-name", entity_id, EntityType.NODE,
                    "vulnerability_name", name, action.timestamp, provenance,
                ))

        # Total count even if no findings
        facts.append(self._make_fact(
            f"{base_id}-finding_count", entity_id, EntityType.NODE,
            "finding_count", len(findings), action.timestamp, provenance,
        ))

        return facts

    # =========================================================================
    # Nikto handler
    # =========================================================================

    def _extract_nikto_facts(
        self, action: PentAGIAction, source_ref: str
    ) -> list[Fact]:
        """Extract facts from nikto web scan results.

        Args:
            action: Parsed PentAGI action with nikto result.
            source_ref: Source reference for provenance.

        Returns:
            List of Facts.
        """
        result = action.result
        provenance = self._make_provenance(source_ref, action)
        entity_id = f"target:{action.target}"
        base_id = f"nikto-{action.action_id}"
        facts: list[Fact] = []

        facts.append(self._make_fact(
            f"{base_id}-event_type", entity_id, EntityType.NODE,
            "event_type", "web_scan", action.timestamp, provenance,
        ))
        facts.append(self._make_fact(
            f"{base_id}-tool", entity_id, EntityType.NODE,
            "tool", "nikto", action.timestamp, provenance,
        ))
        facts.append(self._make_fact(
            f"{base_id}-target", entity_id, EntityType.NODE,
            "target", action.target, action.timestamp, provenance,
        ))

        vulnerabilities = result.get("vulnerabilities", [])
        for i, vuln in enumerate(vulnerabilities):
            if not isinstance(vuln, dict):
                continue
            v_base = f"{base_id}-vuln-{i}"
            facts.append(self._make_fact(
                f"{v_base}-id", entity_id, EntityType.NODE,
                "vulnerability_id", vuln.get("id", f"NIKTO-{i}"),
                action.timestamp, provenance,
            ))
            facts.append(self._make_fact(
                f"{v_base}-description", entity_id, EntityType.NODE,
                "vulnerability_description", vuln.get("description", ""),
                action.timestamp, provenance,
            ))
            uri = vuln.get("uri")
            if uri:
                facts.append(self._make_fact(
                    f"{v_base}-uri", entity_id, EntityType.NODE,
                    "vulnerable_uri", uri, action.timestamp, provenance,
                ))

        facts.append(self._make_fact(
            f"{base_id}-vuln_count", entity_id, EntityType.NODE,
            "vulnerability_count", len(vulnerabilities), action.timestamp, provenance,
        ))

        return facts

    # =========================================================================
    # Gobuster handler
    # =========================================================================

    def _extract_gobuster_facts(
        self, action: PentAGIAction, source_ref: str
    ) -> list[Fact]:
        """Extract facts from gobuster directory enumeration results.

        Args:
            action: Parsed PentAGI action with gobuster result.
            source_ref: Source reference for provenance.

        Returns:
            List of Facts.
        """
        result = action.result
        provenance = self._make_provenance(source_ref, action)
        entity_id = f"target:{action.target}"
        base_id = f"gobuster-{action.action_id}"
        facts: list[Fact] = []

        facts.append(self._make_fact(
            f"{base_id}-event_type", entity_id, EntityType.NODE,
            "event_type", "directory_enumeration", action.timestamp, provenance,
        ))
        facts.append(self._make_fact(
            f"{base_id}-tool", entity_id, EntityType.NODE,
            "tool", "gobuster", action.timestamp, provenance,
        ))
        facts.append(self._make_fact(
            f"{base_id}-target", entity_id, EntityType.NODE,
            "target", action.target, action.timestamp, provenance,
        ))

        paths = result.get("discovered_paths", [])
        for i, path_info in enumerate(paths):
            if isinstance(path_info, dict):
                path = path_info.get("path", "")
                status = path_info.get("status", 0)
            elif isinstance(path_info, str):
                path = path_info
                status = 200
            else:
                continue
            p_base = f"{base_id}-path-{i}"
            facts.append(self._make_fact(
                f"{p_base}-path", entity_id, EntityType.NODE,
                "discovered_path", path, action.timestamp, provenance,
            ))
            facts.append(self._make_fact(
                f"{p_base}-status", entity_id, EntityType.NODE,
                "http_status", status, action.timestamp, provenance,
            ))

        facts.append(self._make_fact(
            f"{base_id}-path_count", entity_id, EntityType.NODE,
            "discovered_path_count", len(paths), action.timestamp, provenance,
        ))

        return facts

    # =========================================================================
    # Hydra handler
    # =========================================================================

    def _extract_hydra_facts(
        self, action: PentAGIAction, source_ref: str
    ) -> list[Fact]:
        """Extract facts from hydra credential brute-force results.

        Args:
            action: Parsed PentAGI action with hydra result.
            source_ref: Source reference for provenance.

        Returns:
            List of Facts.
        """
        result = action.result
        provenance = self._make_provenance(source_ref, action)
        entity_id = f"target:{action.target}"
        base_id = f"hydra-{action.action_id}"
        facts: list[Fact] = []

        facts.append(self._make_fact(
            f"{base_id}-event_type", entity_id, EntityType.NODE,
            "event_type", "credential_bruteforce", action.timestamp, provenance,
        ))
        facts.append(self._make_fact(
            f"{base_id}-tool", entity_id, EntityType.NODE,
            "tool", "hydra", action.timestamp, provenance,
        ))
        facts.append(self._make_fact(
            f"{base_id}-target", entity_id, EntityType.NODE,
            "target", action.target, action.timestamp, provenance,
        ))

        service = result.get("service", "unknown")
        facts.append(self._make_fact(
            f"{base_id}-service", entity_id, EntityType.NODE,
            "target_service", service, action.timestamp, provenance,
        ))

        credentials = result.get("credentials_found", [])
        for i, cred in enumerate(credentials):
            if not isinstance(cred, dict):
                continue
            c_base = f"{base_id}-cred-{i}"
            username = cred.get("username", "unknown")
            facts.append(self._make_fact(
                f"{c_base}-username", entity_id, EntityType.NODE,
                "compromised_username", username, action.timestamp, provenance,
            ))
            # Intentionally do NOT extract passwords — store only the fact
            # that credentials were found, not the credential values
            facts.append(self._make_fact(
                f"{c_base}-found", entity_id, EntityType.NODE,
                "credential_found", True, action.timestamp, provenance,
            ))

        facts.append(self._make_fact(
            f"{base_id}-cred_count", entity_id, EntityType.NODE,
            "credentials_found_count", len(credentials), action.timestamp, provenance,
        ))

        return facts

    # =========================================================================
    # Generic handler (fallback)
    # =========================================================================

    def _extract_generic_facts(
        self, action: PentAGIAction, source_ref: str
    ) -> list[Fact]:
        """Extract facts from unknown/generic tool results.

        Captures tool name, target, and flattened result keys as facts.

        Args:
            action: Parsed PentAGI action.
            source_ref: Source reference for provenance.

        Returns:
            List of Facts.
        """
        provenance = self._make_provenance(source_ref, action)
        entity_id = f"target:{action.target}"
        base_id = f"pentagi-{action.tool}-{action.action_id}"
        facts: list[Fact] = []

        facts.append(self._make_fact(
            f"{base_id}-event_type", entity_id, EntityType.NODE,
            "event_type", f"pentest_{action.tool}", action.timestamp, provenance,
        ))
        facts.append(self._make_fact(
            f"{base_id}-tool", entity_id, EntityType.NODE,
            "tool", action.tool, action.timestamp, provenance,
        ))
        facts.append(self._make_fact(
            f"{base_id}-target", entity_id, EntityType.NODE,
            "target", action.target, action.timestamp, provenance,
        ))

        # Flatten top-level result keys as facts
        for key, value in action.result.items():
            # Skip nested structures — only capture scalar and list values
            if isinstance(value, dict):
                continue
            facts.append(self._make_fact(
                f"{base_id}-{key}", entity_id, EntityType.NODE,
                key, value, action.timestamp, provenance,
            ))

        return facts
