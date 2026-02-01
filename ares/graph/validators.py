"""
ARES Graph Validators

Constraint validation for graph integrity, schema compliance,
and security-specific rules.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING

from ares.graph.schema import (
    NODE_REGISTRY,
    EDGE_REGISTRY,
    NodeBase,
    EdgeBase,
    NodeType,
    EdgeType,
    UserNode,
    ProcessNode,
    FileNode,
    NetworkNode,
    ThreatNode,
    AgentNode,
    AgentType,
    ThreatStatus,
    PrivilegeLevel,
    EscalatesEdge,
    HypothesizesEdge,
    ChallengesEdge,
    SynthesizesEdge,
    DetectsEdge,
)

if TYPE_CHECKING:
    from ares.graph.store import AresGraph


class ValidationError(Exception):
    """Raised when graph validation fails."""

    def __init__(self, message: str, node_id: str | None = None, edge_id: str | None = None):
        self.message = message
        self.node_id = node_id
        self.edge_id = edge_id
        super().__init__(self._format_message())

    def _format_message(self) -> str:
        parts = [self.message]
        if self.node_id:
            parts.append(f"[node: {self.node_id}]")
        if self.edge_id:
            parts.append(f"[edge: {self.edge_id}]")
        return " ".join(parts)


@dataclass
class ValidationResult:
    """Result of validation with details."""

    is_valid: bool
    errors: list[ValidationError]
    warnings: list[str]

    @classmethod
    def success(cls) -> "ValidationResult":
        return cls(is_valid=True, errors=[], warnings=[])

    @classmethod
    def failure(cls, errors: list[ValidationError], warnings: list[str] | None = None) -> "ValidationResult":
        return cls(is_valid=False, errors=errors, warnings=warnings or [])

    def __bool__(self) -> bool:
        return self.is_valid


class GraphValidator:
    """
    Validates ARES graph integrity and schema compliance.

    Validation levels:
    - Schema validation: Type correctness, required fields
    - Referential integrity: Edge endpoints exist, foreign keys valid
    - Semantic validation: Business rules (e.g., escalation must increase privilege)
    - Temporal consistency: Timestamps make sense
    """

    def __init__(self, graph: "AresGraph"):
        self.graph = graph
        self._errors: list[ValidationError] = []
        self._warnings: list[str] = []

    def validate_all(self) -> ValidationResult:
        """Run all validation checks on the graph."""
        self._errors = []
        self._warnings = []

        # Validate all nodes
        for node_id, node in self.graph._nodes.items():
            self._validate_node(node)

        # Validate all edges
        for edge_id, edge in self.graph._edges.items():
            self._validate_edge(edge)

        # Validate graph-level constraints
        self._validate_graph_constraints()

        if self._errors:
            return ValidationResult.failure(self._errors, self._warnings)
        return ValidationResult(is_valid=True, errors=[], warnings=self._warnings)

    def validate_node(self, node: NodeBase) -> ValidationResult:
        """Validate a single node."""
        self._errors = []
        self._warnings = []
        self._validate_node(node)

        if self._errors:
            return ValidationResult.failure(self._errors, self._warnings)
        return ValidationResult(is_valid=True, errors=[], warnings=self._warnings)

    def validate_edge(self, edge: EdgeBase) -> ValidationResult:
        """Validate a single edge."""
        self._errors = []
        self._warnings = []
        self._validate_edge(edge)

        if self._errors:
            return ValidationResult.failure(self._errors, self._warnings)
        return ValidationResult(is_valid=True, errors=[], warnings=self._warnings)

    # =========================================================================
    # NODE VALIDATION
    # =========================================================================

    def _validate_node(self, node: NodeBase) -> None:
        """Validate a node against schema and semantic rules."""
        # Schema validation
        self._validate_node_schema(node)

        # Type-specific validation
        if isinstance(node, UserNode):
            self._validate_user_node(node)
        elif isinstance(node, ProcessNode):
            self._validate_process_node(node)
        elif isinstance(node, FileNode):
            self._validate_file_node(node)
        elif isinstance(node, NetworkNode):
            self._validate_network_node(node)
        elif isinstance(node, ThreatNode):
            self._validate_threat_node(node)
        elif isinstance(node, AgentNode):
            self._validate_agent_node(node)

    def _validate_node_schema(self, node: NodeBase) -> None:
        """Validate common node schema requirements."""
        # ID uniqueness is handled by graph store
        # Timestamp validity
        if node.created_at > datetime.utcnow():
            self._warnings.append(f"Node {node.id} has future created_at timestamp")

        if node.last_seen < node.created_at:
            self._add_error("last_seen cannot be before created_at", node_id=node.id)

        # Risk score bounds (already validated in __post_init__, but double-check)
        if not 0.0 <= node.risk_score <= 1.0:
            self._add_error(f"risk_score out of bounds: {node.risk_score}", node_id=node.id)

    def _validate_user_node(self, node: UserNode) -> None:
        """Validate USER node specific rules."""
        # Username format (allow alphanumeric, dots, underscores, hyphens)
        if not node.username:
            self._add_error("username cannot be empty", node_id=node.id)

        # Domain validation
        if not node.domain:
            self._add_error("domain cannot be empty", node_id=node.id)

        # Cross-platform consistency
        if node.sid and node.uid:
            self._warnings.append(
                f"User {node.id} has both SID and UID - unusual for single platform"
            )

        # Service account privilege check
        if node.account_type.name == "SERVICE" and node.privilege_level.name == "SYSTEM":
            self._warnings.append(
                f"Service account {node.username} has SYSTEM privileges - verify necessity"
            )

    def _validate_process_node(self, node: ProcessNode) -> None:
        """Validate PROCESS node specific rules."""
        # Process lifecycle consistency
        if node.ended_at and node.ended_at < node.started_at:
            self._add_error("ended_at cannot be before started_at", node_id=node.id)

        if node.status.name == "TERMINATED" and not node.ended_at:
            self._warnings.append(f"Terminated process {node.id} missing ended_at")

        if node.status.name == "RUNNING" and node.ended_at:
            self._add_error("Running process cannot have ended_at", node_id=node.id)

        # Parent process reference validation
        if node.parent_id:
            if not self.graph.has_node(node.parent_id):
                self._add_error(
                    f"Parent process {node.parent_id} not found",
                    node_id=node.id
                )
            else:
                parent = self.graph.get_node(node.parent_id)
                if not isinstance(parent, ProcessNode):
                    self._add_error(
                        f"Parent {node.parent_id} is not a ProcessNode",
                        node_id=node.id
                    )

        # User reference validation
        if node.user_id:
            if not self.graph.has_node(node.user_id):
                self._add_error(f"User {node.user_id} not found", node_id=node.id)
            else:
                user = self.graph.get_node(node.user_id)
                if not isinstance(user, UserNode):
                    self._add_error(
                        f"user_id {node.user_id} references non-User node",
                        node_id=node.id
                    )

    def _validate_file_node(self, node: FileNode) -> None:
        """Validate FILE node specific rules."""
        # Path validation
        if not node.path:
            self._add_error("path cannot be empty", node_id=node.id)

        # Size sanity check (warn on very large files)
        if node.size_bytes > 10 * 1024 * 1024 * 1024:  # 10 GB
            self._warnings.append(f"File {node.path} is very large: {node.size_bytes} bytes")

        # Entropy validation for executables
        if node.file_type.name == "EXECUTABLE" and node.entropy > 7.5:
            self._warnings.append(
                f"Executable {node.path} has high entropy ({node.entropy}) - possible packing"
            )

        # Owner reference validation
        if node.owner_id:
            if not self.graph.has_node(node.owner_id):
                self._add_error(f"Owner {node.owner_id} not found", node_id=node.id)

        # Timestamp consistency
        if node.accessed_at < node.created_at:
            self._warnings.append(f"File {node.id} accessed_at before created_at")

    def _validate_network_node(self, node: NetworkNode) -> None:
        """Validate NETWORK node specific rules."""
        # IP validation (basic check)
        if not node.ip_address:
            self._add_error("ip_address cannot be empty", node_id=node.id)
        else:
            # Simple IPv4/IPv6 format check
            parts = node.ip_address.split(".")
            is_ipv4 = len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)
            is_ipv6 = ":" in node.ip_address
            if not (is_ipv4 or is_ipv6):
                self._add_error(f"Invalid IP address format: {node.ip_address}", node_id=node.id)

        # Port validation
        if not 0 <= node.port <= 65535:
            self._add_error(f"Invalid port number: {node.port}", node_id=node.id)

        # External vs internal consistency
        if node.is_external:
            private_ranges = ["10.", "172.16.", "172.17.", "172.18.", "172.19.",
                             "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                             "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                             "172.30.", "172.31.", "192.168.", "127."]
            for prefix in private_ranges:
                if node.ip_address.startswith(prefix):
                    self._add_error(
                        f"Private IP {node.ip_address} marked as external",
                        node_id=node.id
                    )
                    break

        # Known bad with good reputation is contradictory
        if node.is_known_bad and node.reputation_score > 0.7:
            self._warnings.append(
                f"Network {node.id} is marked known_bad but has high reputation"
            )

    def _validate_threat_node(self, node: ThreatNode) -> None:
        """Validate THREAT node specific rules."""
        # Status lifecycle validation
        if node.status == ThreatStatus.CONFIRMED and node.confidence < 0.7:
            self._warnings.append(
                f"Confirmed threat {node.id} has low confidence ({node.confidence})"
            )

        if node.status == ThreatStatus.DISMISSED and node.confidence > 0.5:
            self._warnings.append(
                f"Dismissed threat {node.id} has moderate confidence ({node.confidence})"
            )

        # Resolution timestamp
        if node.status in (ThreatStatus.CONFIRMED, ThreatStatus.DISMISSED):
            if not node.resolved_at:
                self._warnings.append(f"Resolved threat {node.id} missing resolved_at")

        # Affected nodes must exist
        for affected_id in node.affected_node_ids:
            if not self.graph.has_node(affected_id):
                self._add_error(
                    f"Affected node {affected_id} not found",
                    node_id=node.id
                )

        # Attack chain edges must exist
        for edge_id in node.attack_chain_edge_ids:
            if not self.graph.has_edge(edge_id):
                self._add_error(
                    f"Attack chain edge {edge_id} not found",
                    node_id=node.id
                )

    def _validate_agent_node(self, node: AgentNode) -> None:
        """Validate AGENT node specific rules."""
        # Current hypothesis must exist if set
        if node.current_hypothesis_id:
            if not self.graph.has_node(node.current_hypothesis_id):
                self._add_error(
                    f"Current hypothesis {node.current_hypothesis_id} not found",
                    node_id=node.id
                )
            else:
                hypothesis = self.graph.get_node(node.current_hypothesis_id)
                if not isinstance(hypothesis, ThreatNode):
                    self._add_error(
                        f"current_hypothesis_id references non-Threat node",
                        node_id=node.id
                    )

        # Observed nodes must exist
        for obs_id in node.observed_node_ids:
            if not self.graph.has_node(obs_id):
                self._warnings.append(
                    f"Agent {node.id} observes non-existent node {obs_id}"
                )

        # Performance metrics consistency
        total_outcomes = node.hypotheses_confirmed + node.hypotheses_dismissed
        if total_outcomes > node.hypotheses_proposed:
            self._add_error(
                "Total outcomes exceed hypotheses proposed",
                node_id=node.id
            )

    # =========================================================================
    # EDGE VALIDATION
    # =========================================================================

    def _validate_edge(self, edge: EdgeBase) -> None:
        """Validate an edge against schema and semantic rules."""
        # Referential integrity - endpoints must exist
        self._validate_edge_endpoints(edge)

        # Type constraints
        self._validate_edge_type_constraints(edge)

        # Type-specific validation
        if isinstance(edge, EscalatesEdge):
            self._validate_escalates_edge(edge)
        elif isinstance(edge, HypothesizesEdge):
            self._validate_hypothesizes_edge(edge)
        elif isinstance(edge, ChallengesEdge):
            self._validate_challenges_edge(edge)
        elif isinstance(edge, SynthesizesEdge):
            self._validate_synthesizes_edge(edge)
        elif isinstance(edge, DetectsEdge):
            self._validate_detects_edge(edge)

    def _validate_edge_endpoints(self, edge: EdgeBase) -> None:
        """Validate edge source and target exist."""
        if not self.graph.has_node(edge.source_id):
            self._add_error(
                f"Source node {edge.source_id} not found",
                edge_id=edge.id
            )

        if not self.graph.has_node(edge.target_id):
            self._add_error(
                f"Target node {edge.target_id} not found",
                edge_id=edge.id
            )

    def _validate_edge_type_constraints(self, edge: EdgeBase) -> None:
        """Validate edge connects valid node types."""
        if not self.graph.has_node(edge.source_id) or not self.graph.has_node(edge.target_id):
            return  # Already reported in endpoint validation

        source = self.graph.get_node(edge.source_id)
        target = self.graph.get_node(edge.target_id)

        if source.NODE_TYPE not in edge.VALID_SOURCE_TYPES:
            self._add_error(
                f"Invalid source type {source.NODE_TYPE} for {edge.EDGE_TYPE} "
                f"(expected {edge.VALID_SOURCE_TYPES})",
                edge_id=edge.id
            )

        if target.NODE_TYPE not in edge.VALID_TARGET_TYPES:
            self._add_error(
                f"Invalid target type {target.NODE_TYPE} for {edge.EDGE_TYPE} "
                f"(expected {edge.VALID_TARGET_TYPES})",
                edge_id=edge.id
            )

    def _validate_escalates_edge(self, edge: EscalatesEdge) -> None:
        """Validate ESCALATES edge semantic rules."""
        # Successful escalation should increase privilege
        if edge.success:
            if edge.to_privilege.value <= edge.from_privilege.value:
                self._warnings.append(
                    f"Successful escalation {edge.id} does not increase privilege "
                    f"({edge.from_privilege.name} -> {edge.to_privilege.name})"
                )

        # High risk for large privilege jumps
        privilege_jump = edge.to_privilege.value - edge.from_privilege.value
        if privilege_jump >= 2 and edge.risk_score < 0.5:
            self._warnings.append(
                f"Large privilege jump ({privilege_jump} levels) with low risk score"
            )

    def _validate_hypothesizes_edge(self, edge: HypothesizesEdge) -> None:
        """Validate HYPOTHESIZES edge rules."""
        # Source should be ARCHITECT agent
        if self.graph.has_node(edge.source_id):
            source = self.graph.get_node(edge.source_id)
            if isinstance(source, AgentNode) and source.agent_type != AgentType.ARCHITECT:
                self._warnings.append(
                    f"Non-ARCHITECT agent hypothesizing threat in edge {edge.id}"
                )

        # Evidence nodes should exist
        for evidence_id in edge.evidence_node_ids:
            if not self.graph.has_node(evidence_id):
                self._warnings.append(
                    f"Evidence node {evidence_id} not found for hypothesis {edge.id}"
                )

    def _validate_challenges_edge(self, edge: ChallengesEdge) -> None:
        """Validate CHALLENGES edge rules."""
        # Source should be SKEPTIC agent
        if self.graph.has_node(edge.source_id):
            source = self.graph.get_node(edge.source_id)
            if isinstance(source, AgentNode) and source.agent_type != AgentType.SKEPTIC:
                self._warnings.append(
                    f"Non-SKEPTIC agent issuing challenge in edge {edge.id}"
                )

        # Target hypothesis must exist
        if not self.graph.has_node(edge.target_hypothesis_id):
            self._add_error(
                f"Target hypothesis {edge.target_hypothesis_id} not found",
                edge_id=edge.id
            )

    def _validate_synthesizes_edge(self, edge: SynthesizesEdge) -> None:
        """Validate SYNTHESIZES edge rules."""
        # Source should be ORACLE agent
        if self.graph.has_node(edge.source_id):
            source = self.graph.get_node(edge.source_id)
            if isinstance(source, AgentNode) and source.agent_type != AgentType.ORACLE:
                self._warnings.append(
                    f"Non-ORACLE agent synthesizing in edge {edge.id}"
                )

        # Source hypotheses should exist
        for hyp_id in edge.source_hypothesis_ids:
            if not self.graph.has_node(hyp_id):
                self._warnings.append(
                    f"Source hypothesis {hyp_id} not found for synthesis {edge.id}"
                )

    def _validate_detects_edge(self, edge: DetectsEdge) -> None:
        """Validate DETECTS edge rules."""
        # High confidence required for detection
        if edge.confidence < 0.7:
            self._warnings.append(
                f"Detection {edge.id} has low confidence ({edge.confidence})"
            )

        # Target threat should be confirmed
        if self.graph.has_node(edge.target_id):
            target = self.graph.get_node(edge.target_id)
            if isinstance(target, ThreatNode):
                if target.status not in (ThreatStatus.CONFIRMED, ThreatStatus.SYNTHESIZED):
                    self._warnings.append(
                        f"Detection {edge.id} targets non-confirmed threat"
                    )

    # =========================================================================
    # GRAPH-LEVEL VALIDATION
    # =========================================================================

    def _validate_graph_constraints(self) -> None:
        """Validate graph-wide constraints."""
        # Check for orphaned nodes (optional - may be valid in some cases)
        self._check_orphaned_threat_nodes()

        # Check agent balance
        self._check_agent_balance()

        # Check for cycles in certain edge types
        self._check_invalid_cycles()

    def _check_orphaned_threat_nodes(self) -> None:
        """Warn about threats with no evidence or agent connections."""
        for node_id, node in self.graph._nodes.items():
            if isinstance(node, ThreatNode):
                # Check if any agent hypothesized or detected this threat
                has_agent_connection = False
                for edge in self.graph._edges.values():
                    if edge.target_id == node_id and edge.EDGE_TYPE in (
                        "HYPOTHESIZES", "SYNTHESIZES", "DETECTS"
                    ):
                        has_agent_connection = True
                        break

                if not has_agent_connection and node.status == ThreatStatus.HYPOTHESIZED:
                    self._warnings.append(
                        f"Threat {node_id} has no agent connections"
                    )

    def _check_agent_balance(self) -> None:
        """Check for balanced dialectical agents."""
        agent_counts = {AgentType.ARCHITECT: 0, AgentType.SKEPTIC: 0, AgentType.ORACLE: 0}

        for node in self.graph._nodes.values():
            if isinstance(node, AgentNode):
                agent_counts[node.agent_type] += 1

        # Warn if no agents
        total_agents = sum(agent_counts.values())
        if total_agents == 0:
            return  # No agents yet, valid for initialization

        # Warn if missing agent types
        for agent_type, count in agent_counts.items():
            if count == 0 and total_agents > 0:
                self._warnings.append(
                    f"No {agent_type.name} agents present - dialectical reasoning incomplete"
                )

    def _check_invalid_cycles(self) -> None:
        """Check for cycles that shouldn't exist (e.g., self-loops)."""
        for edge_id, edge in self.graph._edges.items():
            if edge.source_id == edge.target_id:
                # Self-loops are invalid for most edge types
                if edge.EDGE_TYPE not in ("OBSERVES",):  # OBSERVES might self-reference
                    self._add_error(
                        f"Self-loop detected for edge type {edge.EDGE_TYPE}",
                        edge_id=edge_id
                    )

    # =========================================================================
    # HELPERS
    # =========================================================================

    def _add_error(self, message: str, node_id: str | None = None, edge_id: str | None = None) -> None:
        """Add a validation error."""
        self._errors.append(ValidationError(message, node_id, edge_id))

    def _add_warning(self, message: str) -> None:
        """Add a validation warning."""
        self._warnings.append(message)
