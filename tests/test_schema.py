"""
Unit tests for ARES Graph Schema.

Tests node/edge creation, validation, feature vector generation,
and serialization for all schema types.
"""

import numpy as np
import pytest
from datetime import datetime, timedelta

from ares.graph.schema import (
    # Enums
    PrivilegeLevel,
    AccountType,
    ProcessStatus,
    FileType,
    NetworkDirection,
    Protocol,
    ThreatType,
    Severity,
    ThreatStatus,
    AgentType,
    ReasoningState,
    AccessType,
    EscalationMethod,
    ExecutionContext,
    ArgumentType,
    ChallengeType,
    # Nodes
    UserNode,
    ProcessNode,
    FileNode,
    NetworkNode,
    ThreatNode,
    AgentNode,
    # Edges
    ExecutesEdge,
    AccessesEdge,
    EscalatesEdge,
    CommunicatesEdge,
    ObservesEdge,
    HypothesizesEdge,
    DebatesEdge,
    ChallengesEdge,
    SynthesizesEdge,
    DetectsEdge,
    # Registries
    NODE_REGISTRY,
    EDGE_REGISTRY,
)


class TestUserNode:
    """Tests for UserNode."""

    def test_create_minimal(self):
        """Create user with minimal required fields."""
        user = UserNode(username="testuser")
        assert user.username == "testuser"
        assert user.domain == "LOCAL"
        assert user.privilege_level == PrivilegeLevel.STANDARD
        assert user.account_type == AccountType.UNKNOWN
        assert user.is_active is True
        assert user.risk_score == 0.0
        assert len(user.id) == 36  # UUID format

    def test_create_full(self):
        """Create user with all fields."""
        user = UserNode(
            username="admin",
            domain="CORP",
            sid="S-1-5-21-123456789",
            uid=1001,
            privilege_level=PrivilegeLevel.ADMIN,
            account_type=AccountType.HUMAN,
            is_active=True,
            groups=["Domain Admins", "IT"],
            auth_failures=3,
            sessions_count=2,
            risk_score=0.7,
        )
        assert user.username == "admin"
        assert user.privilege_level == PrivilegeLevel.ADMIN
        assert user.groups == ["Domain Admins", "IT"]
        assert user.risk_score == 0.7

    def test_invalid_risk_score(self):
        """Risk score must be in [0, 1]."""
        with pytest.raises(ValueError, match="risk_score"):
            UserNode(username="test", risk_score=1.5)

        with pytest.raises(ValueError, match="risk_score"):
            UserNode(username="test", risk_score=-0.1)

    def test_empty_username_rejected(self):
        """Username cannot be empty."""
        with pytest.raises(ValueError, match="username"):
            UserNode(username="")

    def test_feature_vector_shape(self):
        """Feature vector has correct shape."""
        user = UserNode(username="test")
        features = user.to_feature_vector()
        assert features.shape == (UserNode.FEATURE_DIM,)
        assert features.dtype == np.float32

    def test_feature_vector_privilege_encoding(self):
        """Privilege level is one-hot encoded."""
        user = UserNode(username="test", privilege_level=PrivilegeLevel.ADMIN)
        features = user.to_feature_vector()
        # ADMIN is value 3, so index 2 should be 1.0
        assert features[2] == 1.0
        assert features[0] == 0.0  # STANDARD
        assert features[1] == 0.0  # ELEVATED
        assert features[3] == 0.0  # SYSTEM

    def test_to_dict(self):
        """Serialization to dict."""
        user = UserNode(username="test", privilege_level=PrivilegeLevel.ELEVATED)
        d = user.to_dict()
        assert d["username"] == "test"
        assert d["privilege_level"] == "ELEVATED"
        assert d["node_type"] == "USER"
        assert "id" in d
        assert "created_at" in d

    def test_update_last_seen(self):
        """Update last_seen timestamp."""
        user = UserNode(username="test")
        original = user.last_seen
        user.update_last_seen()
        assert user.last_seen >= original


class TestProcessNode:
    """Tests for ProcessNode."""

    def test_create_minimal(self):
        """Create process with minimal fields."""
        proc = ProcessNode(name="python.exe", pid=1234)
        assert proc.name == "python.exe"
        assert proc.pid == 1234
        assert proc.status == ProcessStatus.RUNNING

    def test_create_with_parent(self):
        """Create process with parent reference."""
        parent_id = "parent-uuid-123"
        proc = ProcessNode(
            name="child.exe",
            pid=5678,
            parent_id=parent_id,
            is_elevated=True,
        )
        assert proc.parent_id == parent_id
        assert proc.is_elevated is True

    def test_invalid_pid(self):
        """PID cannot be negative."""
        with pytest.raises(ValueError):
            ProcessNode(name="test", pid=-1)

    def test_feature_vector(self):
        """Feature vector generation."""
        proc = ProcessNode(
            name="test.exe",
            pid=1000,
            status=ProcessStatus.RUNNING,
            is_elevated=True,
            cpu_percent=50.0,
            memory_mb=256.0,
        )
        features = proc.to_feature_vector()
        assert features.shape == (ProcessNode.FEATURE_DIM,)
        assert features[4] == 1.0  # is_elevated


class TestFileNode:
    """Tests for FileNode."""

    def test_create_minimal(self):
        """Create file with minimal fields."""
        f = FileNode(path="/etc/passwd")
        assert f.path == "/etc/passwd"
        assert f.name == "passwd"
        assert f.extension == ""  # No extension

    def test_auto_extract_name_extension(self):
        """Name and extension auto-extracted from path."""
        f = FileNode(path="C:\\Windows\\System32\\cmd.exe")
        assert f.name == "cmd.exe"
        assert f.extension == "exe"

    def test_entropy_bounds(self):
        """Entropy must be in [0, 8]."""
        with pytest.raises(ValueError, match="entropy"):
            FileNode(path="/test", entropy=9.0)

        with pytest.raises(ValueError, match="entropy"):
            FileNode(path="/test", entropy=-1.0)

    def test_feature_vector(self):
        """Feature vector generation."""
        f = FileNode(
            path="/tmp/test.txt",
            size_bytes=1024,
            file_type=FileType.DATA,
            is_sensitive=True,
            entropy=4.5,
        )
        features = f.to_feature_vector()
        assert features.shape == (FileNode.FEATURE_DIM,)
        assert features[7] == 1.0  # is_sensitive


class TestNetworkNode:
    """Tests for NetworkNode."""

    def test_create_minimal(self):
        """Create network node with minimal fields."""
        net = NetworkNode(ip_address="192.168.1.1", port=443)
        assert net.ip_address == "192.168.1.1"
        assert net.port == 443
        assert net.protocol == Protocol.TCP

    def test_invalid_port(self):
        """Port must be in valid range."""
        with pytest.raises(ValueError, match="port"):
            NetworkNode(ip_address="10.0.0.1", port=70000)

    def test_reputation_bounds(self):
        """Reputation score must be in [0, 1]."""
        with pytest.raises(ValueError, match="reputation"):
            NetworkNode(ip_address="10.0.0.1", port=80, reputation_score=1.5)

    def test_feature_vector(self):
        """Feature vector generation."""
        net = NetworkNode(
            ip_address="8.8.8.8",
            port=53,
            protocol=Protocol.DNS,
            direction=NetworkDirection.OUTBOUND,
            is_external=True,
            is_encrypted=False,
        )
        features = net.to_feature_vector()
        assert features.shape == (NetworkNode.FEATURE_DIM,)


class TestThreatNode:
    """Tests for ThreatNode."""

    def test_create_minimal(self):
        """Create threat with minimal fields."""
        threat = ThreatNode()
        assert threat.status == ThreatStatus.HYPOTHESIZED
        assert threat.confidence == 0.5

    def test_create_full(self):
        """Create threat with full details."""
        threat = ThreatNode(
            threat_type=ThreatType.LATERAL_MOVEMENT,
            severity=Severity.HIGH,
            status=ThreatStatus.CONFIRMED,
            confidence=0.95,
            description="Detected lateral movement via PsExec",
            mitre_tactics=["TA0008"],
            mitre_techniques=["T1021.002"],
            affected_node_ids=["user-1", "host-2"],
        )
        assert threat.threat_type == ThreatType.LATERAL_MOVEMENT
        assert threat.severity == Severity.HIGH
        assert len(threat.mitre_tactics) == 1

    def test_invalid_confidence(self):
        """Confidence must be in [0, 1]."""
        with pytest.raises(ValueError, match="confidence"):
            ThreatNode(confidence=1.5)

    def test_feature_vector(self):
        """Feature vector generation."""
        threat = ThreatNode(
            threat_type=ThreatType.MALWARE,
            severity=Severity.CRITICAL,
            confidence=0.9,
        )
        features = threat.to_feature_vector()
        assert features.shape == (ThreatNode.FEATURE_DIM,)


class TestAgentNode:
    """Tests for AgentNode."""

    def test_create_architect(self):
        """Create ARCHITECT agent."""
        agent = AgentNode(agent_type=AgentType.ARCHITECT)
        assert agent.agent_type == AgentType.ARCHITECT
        assert agent.reasoning_state == ReasoningState.OBSERVING

    def test_create_skeptic(self):
        """Create SKEPTIC agent."""
        agent = AgentNode(agent_type=AgentType.SKEPTIC)
        assert agent.agent_type == AgentType.SKEPTIC

    def test_create_oracle(self):
        """Create ORACLE agent."""
        agent = AgentNode(agent_type=AgentType.ORACLE)
        assert agent.agent_type == AgentType.ORACLE

    def test_feature_vector(self):
        """Feature vector generation."""
        agent = AgentNode(
            agent_type=AgentType.ARCHITECT,
            reasoning_state=ReasoningState.HYPOTHESIZING,
            confidence=0.8,
        )
        features = agent.to_feature_vector()
        assert features.shape == (AgentNode.FEATURE_DIM,)


class TestExecutesEdge:
    """Tests for ExecutesEdge."""

    def test_create_minimal(self):
        """Create execution edge with minimal fields."""
        edge = ExecutesEdge(source_id="user-1", target_id="proc-1")
        assert edge.source_id == "user-1"
        assert edge.target_id == "proc-1"
        assert edge.context == ExecutionContext.INTERACTIVE

    def test_missing_source(self):
        """Source ID is required."""
        with pytest.raises(ValueError, match="source_id"):
            ExecutesEdge(source_id="", target_id="proc-1")

    def test_feature_vector(self):
        """Feature vector generation."""
        edge = ExecutesEdge(
            source_id="user-1",
            target_id="proc-1",
            context=ExecutionContext.REMOTE,
        )
        features = edge.to_feature_vector()
        assert features.shape == (ExecutesEdge.FEATURE_DIM,)


class TestAccessesEdge:
    """Tests for AccessesEdge."""

    def test_create_read_access(self):
        """Create read access edge."""
        edge = AccessesEdge(
            source_id="proc-1",
            target_id="file-1",
            access_type=AccessType.READ,
            bytes_transferred=1024,
        )
        assert edge.access_type == AccessType.READ
        assert edge.bytes_transferred == 1024

    def test_feature_vector(self):
        """Feature vector generation."""
        edge = AccessesEdge(
            source_id="proc-1",
            target_id="file-1",
            access_type=AccessType.WRITE,
        )
        features = edge.to_feature_vector()
        assert features.shape == (AccessesEdge.FEATURE_DIM,)


class TestEscalatesEdge:
    """Tests for EscalatesEdge."""

    def test_create_escalation(self):
        """Create privilege escalation edge."""
        edge = EscalatesEdge(
            source_id="user-1",
            target_id="user-2",
            from_privilege=PrivilegeLevel.STANDARD,
            to_privilege=PrivilegeLevel.ADMIN,
            method=EscalationMethod.SUDO,
        )
        assert edge.from_privilege == PrivilegeLevel.STANDARD
        assert edge.to_privilege == PrivilegeLevel.ADMIN

    def test_feature_vector(self):
        """Feature vector includes escalation magnitude."""
        edge = EscalatesEdge(
            source_id="u1",
            target_id="u2",
            from_privilege=PrivilegeLevel.STANDARD,
            to_privilege=PrivilegeLevel.SYSTEM,
        )
        features = edge.to_feature_vector()
        # Magnitude should be (4-1)/3 = 1.0
        assert features[9] == 1.0


class TestCommunicatesEdge:
    """Tests for CommunicatesEdge."""

    def test_create_communication(self):
        """Create network communication edge."""
        edge = CommunicatesEdge(
            source_id="proc-1",
            target_id="net-1",
            bytes_sent=1000,
            bytes_received=500,
            is_encrypted=True,
        )
        assert edge.bytes_sent == 1000
        assert edge.is_encrypted is True

    def test_feature_vector_ratio(self):
        """Feature vector captures send/receive ratio."""
        edge = CommunicatesEdge(
            source_id="p1",
            target_id="n1",
            bytes_sent=1000,
            bytes_received=0,
        )
        features = edge.to_feature_vector()
        # All outbound = ratio of 1.0
        assert features[4] == 1.0


class TestReasoningEdges:
    """Tests for reasoning layer edges."""

    def test_observes_edge(self):
        """Create observation edge."""
        edge = ObservesEdge(
            source_id="agent-1",
            target_id="user-1",
            attention_weight=0.8,
        )
        assert edge.attention_weight == 0.8

    def test_observes_invalid_weight(self):
        """Attention weight must be in [0, 1]."""
        with pytest.raises(ValueError, match="attention"):
            ObservesEdge(source_id="a", target_id="b", attention_weight=1.5)

    def test_hypothesizes_edge(self):
        """Create hypothesis edge."""
        edge = HypothesizesEdge(
            source_id="architect-1",
            target_id="threat-1",
            confidence=0.75,
            evidence_node_ids=["user-1", "proc-1"],
            reasoning_chain=["Observed unusual login", "Cross-referenced with threat intel"],
        )
        assert edge.confidence == 0.75
        assert len(edge.evidence_node_ids) == 2

    def test_debates_edge(self):
        """Create debate edge."""
        edge = DebatesEdge(
            source_id="architect-1",
            target_id="skeptic-1",
            topic_threat_id="threat-1",
            argument_type=ArgumentType.SUPPORT,
            argument_content="Evidence supports malware hypothesis",
            argument_strength=0.7,
        )
        assert edge.topic_threat_id == "threat-1"
        assert edge.argument_type == ArgumentType.SUPPORT

    def test_debates_missing_topic(self):
        """Debate must reference a topic."""
        with pytest.raises(ValueError, match="topic"):
            DebatesEdge(
                source_id="a",
                target_id="b",
                topic_threat_id="",
            )

    def test_challenges_edge(self):
        """Create challenge edge."""
        edge = ChallengesEdge(
            source_id="skeptic-1",
            target_id="architect-1",
            target_hypothesis_id="threat-1",
            challenge_type=ChallengeType.ALTERNATIVE_EXPLANATION,
            alternative_explanation="Could be scheduled backup process",
        )
        assert edge.challenge_type == ChallengeType.ALTERNATIVE_EXPLANATION

    def test_synthesizes_edge(self):
        """Create synthesis edge."""
        edge = SynthesizesEdge(
            source_id="oracle-1",
            target_id="threat-final",
            source_hypothesis_ids=["threat-1", "threat-2"],
            synthesis_method="MERGE",
            result_confidence=0.85,
        )
        assert len(edge.source_hypothesis_ids) == 2
        assert edge.synthesis_method == "MERGE"

    def test_detects_edge(self):
        """Create detection edge."""
        edge = DetectsEdge(
            source_id="oracle-1",
            target_id="threat-1",
            confidence=0.95,
            false_positive_probability=0.05,
            debate_rounds=3,
        )
        assert edge.confidence == 0.95
        assert edge.debate_rounds == 3


class TestRegistries:
    """Tests for NODE_REGISTRY and EDGE_REGISTRY."""

    def test_all_node_types_registered(self):
        """All node types are in registry."""
        expected = {"USER", "PROCESS", "FILE", "NETWORK", "THREAT", "AGENT"}
        assert set(NODE_REGISTRY.keys()) == expected

    def test_all_edge_types_registered(self):
        """All edge types are in registry."""
        expected = {
            "EXECUTES", "ACCESSES", "ESCALATES", "COMMUNICATES",
            "OBSERVES", "HYPOTHESIZES", "DEBATES", "CHALLENGES",
            "SYNTHESIZES", "DETECTS"
        }
        assert set(EDGE_REGISTRY.keys()) == expected

    def test_registry_classes_match(self):
        """Registry maps to correct classes."""
        assert NODE_REGISTRY["USER"] == UserNode
        assert NODE_REGISTRY["AGENT"] == AgentNode
        assert EDGE_REGISTRY["EXECUTES"] == ExecutesEdge
        assert EDGE_REGISTRY["DETECTS"] == DetectsEdge
