"""
Unit tests for ARES Graph Validators.

Tests schema validation, referential integrity, semantic rules,
and graph-level constraints.
"""

from datetime import datetime, timedelta

import pytest

from ares.graph.schema import (
    UserNode,
    ProcessNode,
    FileNode,
    NetworkNode,
    ThreatNode,
    AgentNode,
    ExecutesEdge,
    AccessesEdge,
    EscalatesEdge,
    CommunicatesEdge,
    ObservesEdge,
    HypothesizesEdge,
    ChallengesEdge,
    SynthesizesEdge,
    DetectsEdge,
    PrivilegeLevel,
    ProcessStatus,
    ThreatStatus,
    ThreatType,
    AgentType,
    ReasoningState,
    EscalationMethod,
)
from ares.graph.store import AresGraph
from ares.graph.validators import GraphValidator, ValidationError, ValidationResult


class TestValidationResult:
    """Tests for ValidationResult."""

    def test_success_result(self):
        """Create success result."""
        result = ValidationResult.success()
        assert result.is_valid
        assert len(result.errors) == 0
        assert bool(result) is True

    def test_failure_result(self):
        """Create failure result."""
        errors = [ValidationError("test error")]
        result = ValidationResult.failure(errors)
        assert not result.is_valid
        assert len(result.errors) == 1
        assert bool(result) is False


class TestValidationError:
    """Tests for ValidationError."""

    def test_basic_error(self):
        """Create basic error."""
        error = ValidationError("Something went wrong")
        assert "Something went wrong" in str(error)

    def test_error_with_node_id(self):
        """Create error with node reference."""
        error = ValidationError("Invalid node", node_id="node-123")
        assert "node-123" in str(error)

    def test_error_with_edge_id(self):
        """Create error with edge reference."""
        error = ValidationError("Invalid edge", edge_id="edge-456")
        assert "edge-456" in str(error)


class TestNodeValidation:
    """Tests for node-level validation."""

    def test_valid_user_node(self):
        """Valid user passes validation."""
        graph = AresGraph()
        user = UserNode(username="testuser", domain="CORP")
        graph.add_node(user)

        validator = GraphValidator(graph)
        result = validator.validate_node(user)
        assert result.is_valid

    def test_user_future_timestamp_warning(self):
        """Warn on future created_at timestamp."""
        graph = AresGraph()
        user = UserNode(username="test")
        future_time = datetime.utcnow() + timedelta(days=1)
        user.created_at = future_time
        user.last_seen = future_time  # Must be >= created_at to avoid error
        graph.add_node(user)

        validator = GraphValidator(graph)
        result = validator.validate_node(user)
        # Future timestamp generates warning, not error
        assert result.is_valid
        assert len(result.warnings) > 0
        assert "future" in result.warnings[0].lower()

    def test_user_last_seen_before_created(self):
        """Error when last_seen is before created_at."""
        graph = AresGraph()
        user = UserNode(username="test")
        user.last_seen = user.created_at - timedelta(days=1)
        graph.add_node(user)

        validator = GraphValidator(graph)
        result = validator.validate_node(user)
        assert not result.is_valid
        assert any("last_seen" in str(e) for e in result.errors)

    def test_process_invalid_lifecycle(self):
        """Running process cannot have ended_at."""
        graph = AresGraph()
        proc = ProcessNode(
            name="test.exe",
            pid=1,
            status=ProcessStatus.RUNNING,
        )
        proc.ended_at = datetime.utcnow()
        graph.add_node(proc)

        validator = GraphValidator(graph)
        result = validator.validate_node(proc)
        assert not result.is_valid

    def test_process_valid_parent_reference(self):
        """Valid parent process reference passes."""
        graph = AresGraph()
        parent = ProcessNode(name="parent.exe", pid=1)
        child = ProcessNode(name="child.exe", pid=2, parent_id=parent.id)
        graph.add_node(parent)
        graph.add_node(child)

        validator = GraphValidator(graph)
        result = validator.validate_node(child)
        assert result.is_valid

    def test_process_invalid_parent_reference(self):
        """Invalid parent reference fails validation."""
        graph = AresGraph()
        child = ProcessNode(name="child.exe", pid=2, parent_id="nonexistent")
        graph.add_node(child)

        validator = GraphValidator(graph)
        result = validator.validate_node(child)
        assert not result.is_valid
        assert any("not found" in str(e).lower() for e in result.errors)

    def test_network_private_ip_external_error(self):
        """Private IP marked as external fails."""
        graph = AresGraph()
        net = NetworkNode(
            ip_address="192.168.1.1",
            port=80,
            is_external=True,
        )
        graph.add_node(net)

        validator = GraphValidator(graph)
        result = validator.validate_node(net)
        assert not result.is_valid
        assert any("private" in str(e).lower() for e in result.errors)

    def test_network_valid_external(self):
        """Public IP as external passes."""
        graph = AresGraph()
        net = NetworkNode(
            ip_address="8.8.8.8",
            port=53,
            is_external=True,
        )
        graph.add_node(net)

        validator = GraphValidator(graph)
        result = validator.validate_node(net)
        assert result.is_valid

    def test_threat_low_confidence_confirmed_warning(self):
        """Warn when confirmed threat has low confidence."""
        graph = AresGraph()
        threat = ThreatNode(
            status=ThreatStatus.CONFIRMED,
            confidence=0.3,
        )
        graph.add_node(threat)

        validator = GraphValidator(graph)
        result = validator.validate_node(threat)
        assert result.is_valid  # Warning, not error
        assert any("low confidence" in w.lower() for w in result.warnings)

    def test_threat_affected_nodes_must_exist(self):
        """Affected nodes must exist in graph."""
        graph = AresGraph()
        threat = ThreatNode(
            affected_node_ids=["nonexistent-1", "nonexistent-2"],
        )
        graph.add_node(threat)

        validator = GraphValidator(graph)
        result = validator.validate_node(threat)
        assert not result.is_valid
        assert len(result.errors) >= 2

    def test_agent_valid_hypothesis_reference(self):
        """Agent's current hypothesis must be a Threat node."""
        graph = AresGraph()
        threat = ThreatNode(threat_type=ThreatType.MALWARE)
        agent = AgentNode(
            agent_type=AgentType.ARCHITECT,
            current_hypothesis_id=threat.id,
        )
        graph.add_node(threat)
        graph.add_node(agent)

        validator = GraphValidator(graph)
        result = validator.validate_node(agent)
        assert result.is_valid

    def test_agent_invalid_hypothesis_type(self):
        """Agent's hypothesis pointing to non-Threat fails."""
        graph = AresGraph()
        user = UserNode(username="test")
        agent = AgentNode(
            agent_type=AgentType.ARCHITECT,
            current_hypothesis_id=user.id,
        )
        graph.add_node(user)
        graph.add_node(agent)

        validator = GraphValidator(graph)
        result = validator.validate_node(agent)
        assert not result.is_valid


class TestEdgeValidation:
    """Tests for edge-level validation."""

    def test_valid_executes_edge(self):
        """Valid EXECUTES edge passes."""
        graph = AresGraph()
        user = UserNode(username="test")
        proc = ProcessNode(name="test.exe", pid=1)
        graph.add_node(user)
        graph.add_node(proc)

        edge = ExecutesEdge(source_id=user.id, target_id=proc.id)
        graph.add_edge(edge)

        validator = GraphValidator(graph)
        result = validator.validate_edge(edge)
        assert result.is_valid

    def test_edge_missing_source_fails(self):
        """Edge with missing source node fails."""
        graph = AresGraph()
        proc = ProcessNode(name="test.exe", pid=1)
        graph.add_node(proc)

        # Manually create edge with bad reference
        edge = ExecutesEdge(source_id="nonexistent", target_id=proc.id)
        graph._edges[edge.id] = edge

        validator = GraphValidator(graph)
        result = validator.validate_edge(edge)
        assert not result.is_valid
        assert any("source" in str(e).lower() for e in result.errors)

    def test_edge_type_constraint_violation(self):
        """Edge connecting wrong node types fails."""
        graph = AresGraph()
        file1 = FileNode(path="/a.txt")
        file2 = FileNode(path="/b.txt")
        graph.add_node(file1)
        graph.add_node(file2)

        # EXECUTES should be USER->PROCESS, not FILE->FILE
        edge = ExecutesEdge(source_id=file1.id, target_id=file2.id)
        graph._edges[edge.id] = edge

        validator = GraphValidator(graph)
        result = validator.validate_edge(edge)
        assert not result.is_valid
        assert any("invalid source type" in str(e).lower() for e in result.errors)

    def test_escalation_no_increase_warning(self):
        """Warn when escalation doesn't increase privilege."""
        graph = AresGraph()
        user1 = UserNode(username="u1", privilege_level=PrivilegeLevel.ADMIN)
        user2 = UserNode(username="u2", privilege_level=PrivilegeLevel.ADMIN)
        graph.add_node(user1)
        graph.add_node(user2)

        edge = EscalatesEdge(
            source_id=user1.id,
            target_id=user2.id,
            from_privilege=PrivilegeLevel.ADMIN,
            to_privilege=PrivilegeLevel.ADMIN,
            success=True,
        )
        graph.add_edge(edge)

        validator = GraphValidator(graph)
        result = validator.validate_edge(edge)
        assert result.is_valid  # Warning, not error
        assert any("does not increase" in w.lower() for w in result.warnings)

    def test_hypothesizes_non_architect_warning(self):
        """Warn when non-ARCHITECT agent hypothesizes."""
        graph = AresGraph()
        skeptic = AgentNode(agent_type=AgentType.SKEPTIC)
        threat = ThreatNode()
        graph.add_node(skeptic)
        graph.add_node(threat)

        edge = HypothesizesEdge(
            source_id=skeptic.id,
            target_id=threat.id,
            confidence=0.7,
        )
        graph.add_edge(edge)

        validator = GraphValidator(graph)
        result = validator.validate_edge(edge)
        assert result.is_valid  # Warning, not error
        assert any("non-architect" in w.lower() for w in result.warnings)

    def test_challenges_non_skeptic_warning(self):
        """Warn when non-SKEPTIC agent challenges."""
        graph = AresGraph()
        architect = AgentNode(agent_type=AgentType.ARCHITECT)
        oracle = AgentNode(agent_type=AgentType.ORACLE)
        threat = ThreatNode()
        graph.add_node(architect)
        graph.add_node(oracle)
        graph.add_node(threat)

        edge = ChallengesEdge(
            source_id=architect.id,  # Should be SKEPTIC
            target_id=oracle.id,
            target_hypothesis_id=threat.id,
        )
        graph.add_edge(edge)

        validator = GraphValidator(graph)
        result = validator.validate_edge(edge)
        assert any("non-skeptic" in w.lower() for w in result.warnings)

    def test_synthesizes_non_oracle_warning(self):
        """Warn when non-ORACLE agent synthesizes."""
        graph = AresGraph()
        architect = AgentNode(agent_type=AgentType.ARCHITECT)
        threat = ThreatNode()
        graph.add_node(architect)
        graph.add_node(threat)

        edge = SynthesizesEdge(
            source_id=architect.id,  # Should be ORACLE
            target_id=threat.id,
            result_confidence=0.8,
        )
        graph.add_edge(edge)

        validator = GraphValidator(graph)
        result = validator.validate_edge(edge)
        assert any("non-oracle" in w.lower() for w in result.warnings)

    def test_detects_low_confidence_warning(self):
        """Warn on low-confidence detection."""
        graph = AresGraph()
        agent = AgentNode(agent_type=AgentType.ORACLE)
        threat = ThreatNode(status=ThreatStatus.CONFIRMED)
        graph.add_node(agent)
        graph.add_node(threat)

        edge = DetectsEdge(
            source_id=agent.id,
            target_id=threat.id,
            confidence=0.5,  # Low for detection
        )
        graph.add_edge(edge)

        validator = GraphValidator(graph)
        result = validator.validate_edge(edge)
        assert any("low confidence" in w.lower() for w in result.warnings)


class TestGraphLevelValidation:
    """Tests for graph-wide validation."""

    def test_self_loop_error(self):
        """Self-loops are invalid for most edge types."""
        graph = AresGraph()
        user = UserNode(username="test")
        graph.add_node(user)

        # Self-escalation makes no sense
        edge = EscalatesEdge(
            source_id=user.id,
            target_id=user.id,
            from_privilege=PrivilegeLevel.STANDARD,
            to_privilege=PrivilegeLevel.ADMIN,
        )
        graph._edges[edge.id] = edge
        graph._outgoing_edges[user.id].add(edge.id)
        graph._incoming_edges[user.id].add(edge.id)

        validator = GraphValidator(graph)
        result = validator.validate_all()
        assert not result.is_valid
        assert any("self-loop" in str(e).lower() for e in result.errors)

    def test_missing_agent_types_warning(self):
        """Warn when dialectical agents are incomplete."""
        graph = AresGraph()
        # Only add ARCHITECT, missing SKEPTIC and ORACLE
        agent = AgentNode(agent_type=AgentType.ARCHITECT)
        graph.add_node(agent)

        validator = GraphValidator(graph)
        result = validator.validate_all()
        assert result.is_valid  # Warnings only
        assert any("skeptic" in w.lower() for w in result.warnings)
        assert any("oracle" in w.lower() for w in result.warnings)

    def test_complete_agents_no_warning(self):
        """Complete agent set generates no warnings."""
        graph = AresGraph()
        graph.add_node(AgentNode(agent_type=AgentType.ARCHITECT))
        graph.add_node(AgentNode(agent_type=AgentType.SKEPTIC))
        graph.add_node(AgentNode(agent_type=AgentType.ORACLE))

        validator = GraphValidator(graph)
        result = validator.validate_all()
        assert result.is_valid
        # Should not warn about missing agent types
        assert not any("dialectical" in w.lower() for w in result.warnings)

    def test_orphaned_threat_warning(self):
        """Warn about threats with no agent connections."""
        graph = AresGraph()
        threat = ThreatNode(status=ThreatStatus.HYPOTHESIZED)
        graph.add_node(threat)
        # No HYPOTHESIZES or DETECTS edges

        validator = GraphValidator(graph)
        result = validator.validate_all()
        assert result.is_valid  # Warning only
        assert any("no agent" in w.lower() for w in result.warnings)

    def test_threat_with_hypothesis_no_warning(self):
        """Threat with hypothesis edge is not orphaned."""
        graph = AresGraph()
        agent = AgentNode(agent_type=AgentType.ARCHITECT)
        threat = ThreatNode(status=ThreatStatus.HYPOTHESIZED)
        graph.add_node(agent)
        graph.add_node(threat)

        edge = HypothesizesEdge(
            source_id=agent.id,
            target_id=threat.id,
            confidence=0.7,
        )
        graph.add_edge(edge)

        validator = GraphValidator(graph)
        result = validator.validate_all()
        # Should not warn about orphaned threat
        assert not any("no agent" in w.lower() for w in result.warnings)


class TestFullValidation:
    """Integration tests for full graph validation."""

    def test_valid_attack_chain(self):
        """Complete valid attack chain passes validation."""
        graph = AresGraph()

        # Security layer
        attacker = UserNode(username="attacker", privilege_level=PrivilegeLevel.STANDARD)
        admin = UserNode(username="admin", privilege_level=PrivilegeLevel.ADMIN)
        proc = ProcessNode(name="malware.exe", pid=666, user_id=attacker.id)
        secret = FileNode(path="/etc/shadow", is_sensitive=True)
        c2 = NetworkNode(ip_address="evil.com", port=4444, is_external=True, is_known_bad=True)

        # Workaround: evil.com is not a valid IP
        c2.ip_address = "203.0.113.1"  # Documentation IP range

        for node in [attacker, admin, proc, secret, c2]:
            graph.add_node(node)

        # Attack edges
        graph.add_edge(ExecutesEdge(source_id=attacker.id, target_id=proc.id))
        graph.add_edge(AccessesEdge(source_id=proc.id, target_id=secret.id))
        graph.add_edge(CommunicatesEdge(source_id=proc.id, target_id=c2.id))
        graph.add_edge(EscalatesEdge(
            source_id=attacker.id,
            target_id=admin.id,
            from_privilege=PrivilegeLevel.STANDARD,
            to_privilege=PrivilegeLevel.ADMIN,
        ))

        # Reasoning layer
        architect = AgentNode(agent_type=AgentType.ARCHITECT)
        skeptic = AgentNode(agent_type=AgentType.SKEPTIC)
        oracle = AgentNode(agent_type=AgentType.ORACLE)
        threat = ThreatNode(
            threat_type=ThreatType.INTRUSION,
            affected_node_ids=[attacker.id, proc.id],
        )

        for node in [architect, skeptic, oracle, threat]:
            graph.add_node(node)

        graph.add_edge(ObservesEdge(source_id=architect.id, target_id=proc.id))
        graph.add_edge(HypothesizesEdge(
            source_id=architect.id,
            target_id=threat.id,
            confidence=0.8,
            evidence_node_ids=[proc.id, c2.id],
        ))

        validator = GraphValidator(graph)
        result = validator.validate_all()

        # Should pass with possible warnings
        assert result.is_valid
