"""
Unit tests for ARES Graph Store.

Tests graph operations, traversal, PyTorch Geometric export,
and serialization.
"""

import json
import tempfile
from pathlib import Path

import numpy as np
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
    CommunicatesEdge,
    ObservesEdge,
    HypothesizesEdge,
    PrivilegeLevel,
    AccountType,
    AgentType,
    ThreatType,
    Protocol,
)
from ares.graph.store import AresGraph, HAS_TORCH_GEOMETRIC


class TestGraphNodeOperations:
    """Tests for node CRUD operations."""

    def test_add_node(self):
        """Add node to graph."""
        graph = AresGraph()
        user = UserNode(username="testuser")
        node_id = graph.add_node(user)

        assert node_id == user.id
        assert graph.has_node(node_id)
        assert graph.node_count == 1

    def test_add_duplicate_node_rejected(self):
        """Cannot add node with existing ID."""
        graph = AresGraph()
        user = UserNode(username="test")
        graph.add_node(user)

        with pytest.raises(ValueError, match="already exists"):
            graph.add_node(user)  # Same instance = same ID

    def test_get_node(self):
        """Retrieve node by ID."""
        graph = AresGraph()
        user = UserNode(username="test")
        graph.add_node(user)

        retrieved = graph.get_node(user.id)
        assert retrieved.username == "test"
        assert retrieved is user

    def test_get_nonexistent_node(self):
        """KeyError for missing node."""
        graph = AresGraph()
        with pytest.raises(KeyError):
            graph.get_node("nonexistent-id")

    def test_remove_node(self):
        """Remove node from graph."""
        graph = AresGraph()
        user = UserNode(username="test")
        graph.add_node(user)
        assert graph.has_node(user.id)

        graph.remove_node(user.id)
        assert not graph.has_node(user.id)
        assert graph.node_count == 0

    def test_remove_node_removes_edges(self):
        """Removing node also removes connected edges."""
        graph = AresGraph()
        user = UserNode(username="test")
        proc = ProcessNode(name="test.exe", pid=1)
        graph.add_node(user)
        graph.add_node(proc)

        edge = ExecutesEdge(source_id=user.id, target_id=proc.id)
        graph.add_edge(edge)
        assert graph.edge_count == 1

        graph.remove_node(user.id)
        assert graph.edge_count == 0

    def test_update_node(self):
        """Update existing node."""
        graph = AresGraph()
        user = UserNode(username="test", risk_score=0.1)
        graph.add_node(user)

        user.risk_score = 0.9
        graph.update_node(user)

        retrieved = graph.get_node(user.id)
        assert retrieved.risk_score == 0.9

    def test_get_nodes_by_type(self):
        """Get all nodes of a specific type."""
        graph = AresGraph()
        graph.add_node(UserNode(username="user1"))
        graph.add_node(UserNode(username="user2"))
        graph.add_node(ProcessNode(name="proc1", pid=1))

        users = graph.get_nodes_by_type("USER")
        assert len(users) == 2
        assert all(isinstance(u, UserNode) for u in users)

    def test_iter_nodes(self):
        """Iterate over all nodes."""
        graph = AresGraph()
        graph.add_node(UserNode(username="u1"))
        graph.add_node(ProcessNode(name="p1", pid=1))

        nodes = list(graph.iter_nodes())
        assert len(nodes) == 2

    def test_iter_nodes_by_type(self):
        """Iterate over nodes filtered by type."""
        graph = AresGraph()
        graph.add_node(UserNode(username="u1"))
        graph.add_node(UserNode(username="u2"))
        graph.add_node(ProcessNode(name="p1", pid=1))

        users = list(graph.iter_nodes("USER"))
        assert len(users) == 2


class TestGraphEdgeOperations:
    """Tests for edge CRUD operations."""

    def test_add_edge(self):
        """Add edge between nodes."""
        graph = AresGraph()
        user = UserNode(username="test")
        proc = ProcessNode(name="test.exe", pid=1)
        graph.add_node(user)
        graph.add_node(proc)

        edge = ExecutesEdge(source_id=user.id, target_id=proc.id)
        edge_id = graph.add_edge(edge)

        assert graph.has_edge(edge_id)
        assert graph.edge_count == 1

    def test_add_edge_missing_source(self):
        """Cannot add edge with missing source."""
        graph = AresGraph()
        proc = ProcessNode(name="test.exe", pid=1)
        graph.add_node(proc)

        edge = ExecutesEdge(source_id="missing", target_id=proc.id)
        with pytest.raises(ValueError, match="Source node"):
            graph.add_edge(edge)

    def test_add_edge_missing_target(self):
        """Cannot add edge with missing target."""
        graph = AresGraph()
        user = UserNode(username="test")
        graph.add_node(user)

        edge = ExecutesEdge(source_id=user.id, target_id="missing")
        with pytest.raises(ValueError, match="Target node"):
            graph.add_edge(edge)

    def test_get_edge(self):
        """Retrieve edge by ID."""
        graph = AresGraph()
        user = UserNode(username="test")
        proc = ProcessNode(name="test.exe", pid=1)
        graph.add_node(user)
        graph.add_node(proc)

        edge = ExecutesEdge(source_id=user.id, target_id=proc.id)
        graph.add_edge(edge)

        retrieved = graph.get_edge(edge.id)
        assert retrieved is edge

    def test_remove_edge(self):
        """Remove edge from graph."""
        graph = AresGraph()
        user = UserNode(username="test")
        proc = ProcessNode(name="test.exe", pid=1)
        graph.add_node(user)
        graph.add_node(proc)

        edge = ExecutesEdge(source_id=user.id, target_id=proc.id)
        graph.add_edge(edge)

        graph.remove_edge(edge.id)
        assert not graph.has_edge(edge.id)

    def test_get_edges_by_type(self):
        """Get all edges of a specific type."""
        graph = AresGraph()
        user = UserNode(username="test")
        proc = ProcessNode(name="test.exe", pid=1)
        file = FileNode(path="/test.txt")
        graph.add_node(user)
        graph.add_node(proc)
        graph.add_node(file)

        graph.add_edge(ExecutesEdge(source_id=user.id, target_id=proc.id))
        graph.add_edge(AccessesEdge(source_id=proc.id, target_id=file.id))

        executes = graph.get_edges_by_type("EXECUTES")
        assert len(executes) == 1
        assert all(e.EDGE_TYPE == "EXECUTES" for e in executes)


class TestGraphTraversal:
    """Tests for graph traversal operations."""

    @pytest.fixture
    def sample_graph(self):
        """Create a sample graph for testing."""
        graph = AresGraph(name="test_graph")

        # Create nodes
        user = UserNode(username="attacker", privilege_level=PrivilegeLevel.STANDARD)
        proc1 = ProcessNode(name="powershell.exe", pid=1000)
        proc2 = ProcessNode(name="cmd.exe", pid=1001, parent_id=proc1.id)
        file = FileNode(path="C:\\secrets.txt")
        network = NetworkNode(ip_address="192.168.1.100", port=4444)

        for node in [user, proc1, proc2, file, network]:
            graph.add_node(node)

        # Create edges
        graph.add_edge(ExecutesEdge(source_id=user.id, target_id=proc1.id))
        graph.add_edge(ExecutesEdge(source_id=user.id, target_id=proc2.id))
        graph.add_edge(AccessesEdge(source_id=proc1.id, target_id=file.id))
        graph.add_edge(CommunicatesEdge(source_id=proc1.id, target_id=network.id))

        return graph, {"user": user, "proc1": proc1, "proc2": proc2, "file": file, "network": network}

    def test_get_neighbors_outgoing(self, sample_graph):
        """Get outgoing neighbors."""
        graph, nodes = sample_graph
        neighbors = graph.get_neighbors(nodes["user"].id, direction="outgoing")
        assert len(neighbors) == 2
        neighbor_names = {n.name for n in neighbors}
        assert neighbor_names == {"powershell.exe", "cmd.exe"}

    def test_get_neighbors_incoming(self, sample_graph):
        """Get incoming neighbors."""
        graph, nodes = sample_graph
        neighbors = graph.get_neighbors(nodes["proc1"].id, direction="incoming")
        assert len(neighbors) == 1
        assert neighbors[0].username == "attacker"

    def test_get_neighbors_both(self, sample_graph):
        """Get neighbors in both directions."""
        graph, nodes = sample_graph
        neighbors = graph.get_neighbors(nodes["proc1"].id, direction="both")
        # Incoming: user, Outgoing: file, network
        assert len(neighbors) == 3

    def test_get_neighbors_filter_edge_type(self, sample_graph):
        """Filter neighbors by edge type."""
        graph, nodes = sample_graph
        neighbors = graph.get_neighbors(
            nodes["proc1"].id,
            direction="outgoing",
            edge_types=["ACCESSES"]
        )
        assert len(neighbors) == 1
        assert neighbors[0].path == "C:\\secrets.txt"

    def test_get_neighbors_filter_node_type(self, sample_graph):
        """Filter neighbors by node type."""
        graph, nodes = sample_graph
        neighbors = graph.get_neighbors(
            nodes["proc1"].id,
            direction="outgoing",
            node_types=["NETWORK"]
        )
        assert len(neighbors) == 1
        assert neighbors[0].ip_address == "192.168.1.100"

    def test_get_edges_between(self, sample_graph):
        """Get edges between two nodes."""
        graph, nodes = sample_graph
        edges = graph.get_edges_between(nodes["user"].id, nodes["proc1"].id)
        assert len(edges) == 1
        assert edges[0].EDGE_TYPE == "EXECUTES"

    def test_get_node_edges(self, sample_graph):
        """Get all edges for a node."""
        graph, nodes = sample_graph
        edges = graph.get_node_edges(nodes["proc1"].id, direction="outgoing")
        assert len(edges) == 2  # ACCESSES to file, COMMUNICATES to network

    def test_get_subgraph(self, sample_graph):
        """Extract subgraph."""
        graph, nodes = sample_graph
        subgraph = graph.get_subgraph([nodes["user"].id, nodes["proc1"].id])

        assert subgraph.node_count == 2
        assert subgraph.edge_count == 1  # Only the EXECUTES edge

    def test_shortest_path(self, sample_graph):
        """Find shortest path between nodes."""
        graph, nodes = sample_graph
        path = graph.shortest_path(nodes["user"].id, nodes["file"].id)
        assert path is not None
        assert len(path) == 3  # user -> proc1 -> file


class TestGraphSerialization:
    """Tests for graph serialization."""

    def test_to_dict(self):
        """Serialize graph to dict."""
        graph = AresGraph(name="test")
        graph.add_node(UserNode(username="test"))

        d = graph.to_dict()
        assert d["name"] == "test"
        assert len(d["nodes"]) == 1
        assert "created_at" in d

    def test_save_and_load(self):
        """Save and load graph from file."""
        graph = AresGraph(name="test")
        user = UserNode(username="test", privilege_level=PrivilegeLevel.ADMIN)
        proc = ProcessNode(name="test.exe", pid=1)
        graph.add_node(user)
        graph.add_node(proc)
        graph.add_edge(ExecutesEdge(source_id=user.id, target_id=proc.id))

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = Path(f.name)

        try:
            graph.save(path)
            loaded = AresGraph.load(path)

            assert loaded.name == "test"
            assert loaded.node_count == 2
            assert loaded.edge_count == 1

            loaded_user = loaded.get_node(user.id)
            assert loaded_user.username == "test"
            assert loaded_user.privilege_level == PrivilegeLevel.ADMIN
        finally:
            path.unlink()

    def test_roundtrip_all_node_types(self):
        """Roundtrip serialization for all node types."""
        graph = AresGraph()

        # Add one of each node type
        graph.add_node(UserNode(username="user1"))
        graph.add_node(ProcessNode(name="proc1", pid=1))
        graph.add_node(FileNode(path="/test.txt"))
        graph.add_node(NetworkNode(ip_address="10.0.0.1", port=80))
        graph.add_node(ThreatNode(threat_type=ThreatType.MALWARE))
        graph.add_node(AgentNode(agent_type=AgentType.ARCHITECT))

        # Serialize and deserialize
        data = graph.to_dict()
        loaded = AresGraph.from_dict(data)

        assert loaded.node_count == 6
        assert len(loaded.get_nodes_by_type("USER")) == 1
        assert len(loaded.get_nodes_by_type("AGENT")) == 1


@pytest.mark.skipif(not HAS_TORCH_GEOMETRIC, reason="PyTorch Geometric not installed")
class TestPyTorchGeometricExport:
    """Tests for PyTorch Geometric export."""

    def test_to_pyg_homogeneous_empty(self):
        """Export empty graph."""
        graph = AresGraph()
        data = graph.to_pyg_homogeneous()
        assert data.num_nodes == 0

    def test_to_pyg_homogeneous(self):
        """Export to homogeneous Data."""
        graph = AresGraph()
        user = UserNode(username="test")
        proc = ProcessNode(name="test.exe", pid=1)
        graph.add_node(user)
        graph.add_node(proc)
        graph.add_edge(ExecutesEdge(source_id=user.id, target_id=proc.id))

        data = graph.to_pyg_homogeneous()

        assert data.num_nodes == 2
        assert data.x.shape[0] == 2
        assert data.edge_index.shape == (2, 1)

    def test_to_pyg_homogeneous_filter_types(self):
        """Export with type filtering."""
        graph = AresGraph()
        graph.add_node(UserNode(username="u1"))
        graph.add_node(UserNode(username="u2"))
        graph.add_node(ProcessNode(name="p1", pid=1))

        data = graph.to_pyg_homogeneous(node_types=["USER"])
        assert data.num_nodes == 2

    def test_to_pyg_heterogeneous(self):
        """Export to HeteroData."""
        graph = AresGraph()
        user = UserNode(username="test")
        proc = ProcessNode(name="test.exe", pid=1)
        file = FileNode(path="/test.txt")
        graph.add_node(user)
        graph.add_node(proc)
        graph.add_node(file)
        graph.add_edge(ExecutesEdge(source_id=user.id, target_id=proc.id))
        graph.add_edge(AccessesEdge(source_id=proc.id, target_id=file.id))

        data = graph.to_pyg_heterogeneous()

        # Check node types present
        assert "USER" in data.node_types
        assert "PROCESS" in data.node_types
        assert "FILE" in data.node_types

        # Check edge types present
        assert ("USER", "EXECUTES", "PROCESS") in data.edge_types
        assert ("PROCESS", "ACCESSES", "FILE") in data.edge_types


class TestGraphStatistics:
    """Tests for graph statistics."""

    def test_empty_stats(self):
        """Stats for empty graph."""
        graph = AresGraph()
        stats = graph.stats()
        assert stats["total_nodes"] == 0
        assert stats["total_edges"] == 0

    def test_stats(self):
        """Stats for populated graph."""
        graph = AresGraph(name="test")
        graph.add_node(UserNode(username="u1"))
        graph.add_node(UserNode(username="u2"))
        graph.add_node(ProcessNode(name="p1", pid=1))

        stats = graph.stats()
        assert stats["name"] == "test"
        assert stats["total_nodes"] == 3
        assert stats["nodes_by_type"]["USER"] == 2
        assert stats["nodes_by_type"]["PROCESS"] == 1

    def test_repr(self):
        """String representation."""
        graph = AresGraph(name="test")
        graph.add_node(UserNode(username="u1"))
        assert "AresGraph" in repr(graph)
        assert "test" in repr(graph)
        assert "nodes=1" in repr(graph)
