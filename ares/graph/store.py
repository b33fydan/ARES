"""
ARES Graph Store

NetworkX-based graph storage with PyTorch Geometric export.
Designed for Phase 0/1 rapid iteration with Phase 2+ Neo4j compatibility.
"""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Iterator, Sequence

import networkx as nx
import numpy as np

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
)

# Optional PyTorch Geometric import
try:
    import torch
    from torch_geometric.data import Data, HeteroData
    HAS_TORCH_GEOMETRIC = True
except ImportError:
    HAS_TORCH_GEOMETRIC = False
    torch = None
    Data = None
    HeteroData = None


class AresGraph:
    """
    In-memory graph store for ARES.

    Features:
    - NetworkX MultiDiGraph backend for flexible querying
    - Type-safe node/edge access with schema classes
    - Efficient neighbor/edge lookups by type
    - Export to PyTorch Geometric tensors
    - Serialization to/from JSON
    """

    def __init__(self, name: str = "ares_graph"):
        self.name = name
        self.created_at = datetime.utcnow()

        # Primary storage - schema objects indexed by ID
        self._nodes: dict[str, NodeBase] = {}
        self._edges: dict[str, EdgeBase] = {}

        # NetworkX graph for traversal algorithms
        self._nx_graph = nx.MultiDiGraph()

        # Indices for fast lookup by type
        self._nodes_by_type: dict[NodeType, set[str]] = defaultdict(set)
        self._edges_by_type: dict[EdgeType, set[str]] = defaultdict(set)

        # Adjacency indices
        self._outgoing_edges: dict[str, set[str]] = defaultdict(set)  # node_id -> edge_ids
        self._incoming_edges: dict[str, set[str]] = defaultdict(set)  # node_id -> edge_ids

    # =========================================================================
    # NODE OPERATIONS
    # =========================================================================

    def add_node(self, node: NodeBase) -> str:
        """
        Add a node to the graph.

        Args:
            node: Node instance to add

        Returns:
            Node ID

        Raises:
            ValueError: If node ID already exists
        """
        if node.id in self._nodes:
            raise ValueError(f"Node with ID {node.id} already exists")

        self._nodes[node.id] = node
        self._nodes_by_type[node.NODE_TYPE].add(node.id)
        self._nx_graph.add_node(node.id, node_type=node.NODE_TYPE)

        return node.id

    def get_node(self, node_id: str) -> NodeBase:
        """
        Retrieve a node by ID.

        Raises:
            KeyError: If node not found
        """
        if node_id not in self._nodes:
            raise KeyError(f"Node {node_id} not found")
        return self._nodes[node_id]

    def has_node(self, node_id: str) -> bool:
        """Check if a node exists."""
        return node_id in self._nodes

    def remove_node(self, node_id: str) -> None:
        """
        Remove a node and all connected edges.

        Raises:
            KeyError: If node not found
        """
        if node_id not in self._nodes:
            raise KeyError(f"Node {node_id} not found")

        node = self._nodes[node_id]

        # Remove connected edges first
        edges_to_remove = list(self._outgoing_edges[node_id] | self._incoming_edges[node_id])
        for edge_id in edges_to_remove:
            self.remove_edge(edge_id)

        # Remove from indices
        self._nodes_by_type[node.NODE_TYPE].discard(node_id)
        self._nx_graph.remove_node(node_id)

        # Remove from primary storage
        del self._nodes[node_id]

    def update_node(self, node: NodeBase) -> None:
        """
        Update an existing node.

        Raises:
            KeyError: If node not found
        """
        if node.id not in self._nodes:
            raise KeyError(f"Node {node.id} not found")

        old_node = self._nodes[node.id]
        if old_node.NODE_TYPE != node.NODE_TYPE:
            raise ValueError("Cannot change node type during update")

        self._nodes[node.id] = node

    def get_nodes_by_type(self, node_type: NodeType) -> list[NodeBase]:
        """Get all nodes of a specific type."""
        return [self._nodes[nid] for nid in self._nodes_by_type.get(node_type, set())]

    def iter_nodes(self, node_type: NodeType | None = None) -> Iterator[NodeBase]:
        """Iterate over nodes, optionally filtered by type."""
        if node_type:
            for node_id in self._nodes_by_type.get(node_type, set()):
                yield self._nodes[node_id]
        else:
            yield from self._nodes.values()

    # =========================================================================
    # EDGE OPERATIONS
    # =========================================================================

    def add_edge(self, edge: EdgeBase) -> str:
        """
        Add an edge to the graph.

        Args:
            edge: Edge instance to add

        Returns:
            Edge ID

        Raises:
            ValueError: If edge ID exists or endpoints don't exist
        """
        if edge.id in self._edges:
            raise ValueError(f"Edge with ID {edge.id} already exists")

        if edge.source_id not in self._nodes:
            raise ValueError(f"Source node {edge.source_id} not found")

        if edge.target_id not in self._nodes:
            raise ValueError(f"Target node {edge.target_id} not found")

        self._edges[edge.id] = edge
        self._edges_by_type[edge.EDGE_TYPE].add(edge.id)

        # Update adjacency indices
        self._outgoing_edges[edge.source_id].add(edge.id)
        self._incoming_edges[edge.target_id].add(edge.id)

        # Add to NetworkX
        self._nx_graph.add_edge(
            edge.source_id,
            edge.target_id,
            key=edge.id,
            edge_type=edge.EDGE_TYPE
        )

        return edge.id

    def get_edge(self, edge_id: str) -> EdgeBase:
        """
        Retrieve an edge by ID.

        Raises:
            KeyError: If edge not found
        """
        if edge_id not in self._edges:
            raise KeyError(f"Edge {edge_id} not found")
        return self._edges[edge_id]

    def has_edge(self, edge_id: str) -> bool:
        """Check if an edge exists."""
        return edge_id in self._edges

    def remove_edge(self, edge_id: str) -> None:
        """
        Remove an edge from the graph.

        Raises:
            KeyError: If edge not found
        """
        if edge_id not in self._edges:
            raise KeyError(f"Edge {edge_id} not found")

        edge = self._edges[edge_id]

        # Remove from indices
        self._edges_by_type[edge.EDGE_TYPE].discard(edge_id)
        self._outgoing_edges[edge.source_id].discard(edge_id)
        self._incoming_edges[edge.target_id].discard(edge_id)

        # Remove from NetworkX
        self._nx_graph.remove_edge(edge.source_id, edge.target_id, key=edge_id)

        # Remove from primary storage
        del self._edges[edge_id]

    def get_edges_by_type(self, edge_type: EdgeType) -> list[EdgeBase]:
        """Get all edges of a specific type."""
        return [self._edges[eid] for eid in self._edges_by_type.get(edge_type, set())]

    def iter_edges(self, edge_type: EdgeType | None = None) -> Iterator[EdgeBase]:
        """Iterate over edges, optionally filtered by type."""
        if edge_type:
            for edge_id in self._edges_by_type.get(edge_type, set()):
                yield self._edges[edge_id]
        else:
            yield from self._edges.values()

    # =========================================================================
    # GRAPH TRAVERSAL
    # =========================================================================

    def get_neighbors(
        self,
        node_id: str,
        direction: str = "both",
        edge_types: Sequence[EdgeType] | None = None,
        node_types: Sequence[NodeType] | None = None,
    ) -> list[NodeBase]:
        """
        Get neighboring nodes with optional filtering.

        Args:
            node_id: Source node ID
            direction: "outgoing", "incoming", or "both"
            edge_types: Filter by edge types (None = all)
            node_types: Filter by neighbor node types (None = all)

        Returns:
            List of neighboring nodes
        """
        if node_id not in self._nodes:
            raise KeyError(f"Node {node_id} not found")

        neighbor_ids = set()

        # Collect edge IDs based on direction
        if direction in ("outgoing", "both"):
            for edge_id in self._outgoing_edges.get(node_id, set()):
                edge = self._edges[edge_id]
                if edge_types is None or edge.EDGE_TYPE in edge_types:
                    neighbor_ids.add(edge.target_id)

        if direction in ("incoming", "both"):
            for edge_id in self._incoming_edges.get(node_id, set()):
                edge = self._edges[edge_id]
                if edge_types is None or edge.EDGE_TYPE in edge_types:
                    neighbor_ids.add(edge.source_id)

        # Filter by node type and return
        neighbors = [self._nodes[nid] for nid in neighbor_ids]
        if node_types:
            neighbors = [n for n in neighbors if n.NODE_TYPE in node_types]

        return neighbors

    def get_edges_between(
        self,
        source_id: str,
        target_id: str,
        edge_type: EdgeType | None = None,
    ) -> list[EdgeBase]:
        """Get all edges between two nodes."""
        edges = []
        for edge_id in self._outgoing_edges.get(source_id, set()):
            edge = self._edges[edge_id]
            if edge.target_id == target_id:
                if edge_type is None or edge.EDGE_TYPE == edge_type:
                    edges.append(edge)
        return edges

    def get_node_edges(
        self,
        node_id: str,
        direction: str = "both",
        edge_type: EdgeType | None = None,
    ) -> list[EdgeBase]:
        """Get all edges connected to a node."""
        edges = []

        if direction in ("outgoing", "both"):
            for edge_id in self._outgoing_edges.get(node_id, set()):
                edge = self._edges[edge_id]
                if edge_type is None or edge.EDGE_TYPE == edge_type:
                    edges.append(edge)

        if direction in ("incoming", "both"):
            for edge_id in self._incoming_edges.get(node_id, set()):
                edge = self._edges[edge_id]
                if edge_type is None or edge.EDGE_TYPE == edge_type:
                    edges.append(edge)

        return edges

    def get_subgraph(
        self,
        node_ids: Sequence[str],
        include_edges: bool = True,
    ) -> "AresGraph":
        """
        Extract a subgraph containing specified nodes.

        Args:
            node_ids: Node IDs to include
            include_edges: Whether to include edges between selected nodes

        Returns:
            New AresGraph containing the subgraph
        """
        subgraph = AresGraph(name=f"{self.name}_subgraph")

        # Add nodes
        for node_id in node_ids:
            if node_id in self._nodes:
                subgraph.add_node(self._nodes[node_id])

        # Add edges between included nodes
        if include_edges:
            node_set = set(node_ids)
            for edge in self._edges.values():
                if edge.source_id in node_set and edge.target_id in node_set:
                    subgraph.add_edge(edge)

        return subgraph

    # =========================================================================
    # PYTORCH GEOMETRIC EXPORT
    # =========================================================================

    def to_pyg_homogeneous(
        self,
        node_types: Sequence[NodeType] | None = None,
        edge_types: Sequence[EdgeType] | None = None,
    ) -> "Data":
        """
        Export graph to PyTorch Geometric homogeneous Data object.

        All node types are mapped to a single node type with combined features.
        Useful for simple GNN architectures.

        Args:
            node_types: Node types to include (None = all)
            edge_types: Edge types to include (None = all)

        Returns:
            PyTorch Geometric Data object
        """
        if not HAS_TORCH_GEOMETRIC:
            raise ImportError("PyTorch Geometric not installed")

        # Filter nodes
        if node_types:
            nodes = [n for n in self._nodes.values() if n.NODE_TYPE in node_types]
        else:
            nodes = list(self._nodes.values())

        if not nodes:
            return Data()

        # Create node ID to index mapping
        node_to_idx = {node.id: idx for idx, node in enumerate(nodes)}

        # Build feature matrix (pad to max feature dim)
        max_dim = max(getattr(n, 'FEATURE_DIM', 16) for n in nodes)
        x = np.zeros((len(nodes), max_dim), dtype=np.float32)
        for idx, node in enumerate(nodes):
            features = node.to_feature_vector()
            x[idx, :len(features)] = features

        # Build edge index
        edge_index = []
        edge_attr_list = []

        for edge in self._edges.values():
            if edge_types and edge.EDGE_TYPE not in edge_types:
                continue
            if edge.source_id not in node_to_idx or edge.target_id not in node_to_idx:
                continue

            src_idx = node_to_idx[edge.source_id]
            tgt_idx = node_to_idx[edge.target_id]
            edge_index.append([src_idx, tgt_idx])
            edge_attr_list.append(edge.to_feature_vector())

        # Convert to tensors
        x_tensor = torch.tensor(x, dtype=torch.float)

        if edge_index:
            edge_index_tensor = torch.tensor(edge_index, dtype=torch.long).t().contiguous()
            max_edge_dim = max(len(e) for e in edge_attr_list)
            edge_attr = np.zeros((len(edge_attr_list), max_edge_dim), dtype=np.float32)
            for idx, attr in enumerate(edge_attr_list):
                edge_attr[idx, :len(attr)] = attr
            edge_attr_tensor = torch.tensor(edge_attr, dtype=torch.float)
        else:
            edge_index_tensor = torch.empty((2, 0), dtype=torch.long)
            edge_attr_tensor = torch.empty((0, 1), dtype=torch.float)

        return Data(
            x=x_tensor,
            edge_index=edge_index_tensor,
            edge_attr=edge_attr_tensor,
            num_nodes=len(nodes),
        )

    def to_pyg_heterogeneous(self) -> "HeteroData":
        """
        Export graph to PyTorch Geometric HeteroData object.

        Preserves node and edge types for heterogeneous GNN architectures.
        This is the preferred export for ARES as it maintains type semantics.

        Returns:
            PyTorch Geometric HeteroData object
        """
        if not HAS_TORCH_GEOMETRIC:
            raise ImportError("PyTorch Geometric not installed")

        data = HeteroData()

        # Build node features per type
        node_to_idx: dict[str, dict[str, int]] = {}  # node_type -> node_id -> idx

        for node_type in NODE_REGISTRY.keys():
            nodes = self.get_nodes_by_type(node_type)
            if not nodes:
                continue

            node_to_idx[node_type] = {node.id: idx for idx, node in enumerate(nodes)}

            # Get feature dimension for this type
            feature_dim = getattr(nodes[0], 'FEATURE_DIM', 16)
            x = np.zeros((len(nodes), feature_dim), dtype=np.float32)

            for idx, node in enumerate(nodes):
                features = node.to_feature_vector()
                x[idx, :len(features)] = features

            data[node_type].x = torch.tensor(x, dtype=torch.float)
            data[node_type].num_nodes = len(nodes)

        # Build edge indices per edge type
        for edge_type, edge_class in EDGE_REGISTRY.items():
            edges = self.get_edges_by_type(edge_type)
            if not edges:
                continue

            # Group edges by (source_type, target_type) combinations
            edge_groups: dict[tuple[str, str], list[EdgeBase]] = defaultdict(list)

            for edge in edges:
                source_node = self._nodes.get(edge.source_id)
                target_node = self._nodes.get(edge.target_id)
                if source_node and target_node:
                    key = (source_node.NODE_TYPE, target_node.NODE_TYPE)
                    edge_groups[key].append(edge)

            # Create edge tensors for each (src_type, edge_type, tgt_type) triple
            for (src_type, tgt_type), group_edges in edge_groups.items():
                edge_index = []
                edge_attr_list = []

                for edge in group_edges:
                    src_idx = node_to_idx.get(src_type, {}).get(edge.source_id)
                    tgt_idx = node_to_idx.get(tgt_type, {}).get(edge.target_id)

                    if src_idx is not None and tgt_idx is not None:
                        edge_index.append([src_idx, tgt_idx])
                        edge_attr_list.append(edge.to_feature_vector())

                if edge_index:
                    rel_key = (src_type, edge_type, tgt_type)
                    data[rel_key].edge_index = torch.tensor(
                        edge_index, dtype=torch.long
                    ).t().contiguous()

                    # Edge attributes
                    max_dim = max(len(e) for e in edge_attr_list)
                    edge_attr = np.zeros((len(edge_attr_list), max_dim), dtype=np.float32)
                    for idx, attr in enumerate(edge_attr_list):
                        edge_attr[idx, :len(attr)] = attr
                    data[rel_key].edge_attr = torch.tensor(edge_attr, dtype=torch.float)

        return data

    # =========================================================================
    # NETWORKX ACCESS
    # =========================================================================

    @property
    def nx(self) -> nx.MultiDiGraph:
        """Access underlying NetworkX graph for advanced algorithms."""
        return self._nx_graph

    def shortest_path(
        self,
        source_id: str,
        target_id: str,
        edge_types: Sequence[EdgeType] | None = None,
    ) -> list[str] | None:
        """
        Find shortest path between two nodes.

        Args:
            source_id: Source node ID
            target_id: Target node ID
            edge_types: Restrict path to these edge types (None = all)

        Returns:
            List of node IDs in path, or None if no path exists
        """
        if edge_types:
            # Create filtered view
            def edge_filter(u, v, k):
                edge = self._edges.get(k)
                return edge and edge.EDGE_TYPE in edge_types

            view = nx.subgraph_view(
                self._nx_graph,
                filter_edge=edge_filter
            )
        else:
            view = self._nx_graph

        try:
            return nx.shortest_path(view, source_id, target_id)
        except nx.NetworkXNoPath:
            return None

    # =========================================================================
    # SERIALIZATION
    # =========================================================================

    def to_dict(self) -> dict[str, Any]:
        """Serialize graph to dictionary."""
        return {
            "name": self.name,
            "created_at": self.created_at.isoformat(),
            "nodes": [node.to_dict() for node in self._nodes.values()],
            "edges": [edge.to_dict() for edge in self._edges.values()],
        }

    def save(self, path: str | Path) -> None:
        """Save graph to JSON file."""
        path = Path(path)
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2)

    @classmethod
    def load(cls, path: str | Path) -> "AresGraph":
        """Load graph from JSON file."""
        path = Path(path)
        with open(path, "r") as f:
            data = json.load(f)

        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AresGraph":
        """Deserialize graph from dictionary."""
        graph = cls(name=data.get("name", "ares_graph"))
        graph.created_at = datetime.fromisoformat(data["created_at"])

        # Reconstruct nodes
        for node_data in data.get("nodes", []):
            node_type = node_data.pop("node_type")
            node_class = NODE_REGISTRY[node_type]

            # Convert enum strings back to enums
            node_data = cls._deserialize_node_data(node_type, node_data)
            node = node_class(**node_data)
            graph.add_node(node)

        # Reconstruct edges
        for edge_data in data.get("edges", []):
            edge_type = edge_data.pop("edge_type")
            edge_class = EDGE_REGISTRY[edge_type]

            # Convert enum strings back to enums
            edge_data = cls._deserialize_edge_data(edge_type, edge_data)
            edge = edge_class(**edge_data)
            graph.add_edge(edge)

        return graph

    @staticmethod
    def _deserialize_node_data(node_type: str, data: dict) -> dict:
        """Convert serialized node data back to proper types."""
        from ares.graph.schema import (
            PrivilegeLevel, AccountType, ProcessStatus, FileType,
            NetworkDirection, Protocol, ThreatType, Severity,
            ThreatStatus, AgentType, ReasoningState
        )

        # Convert datetime strings
        for field in ["created_at", "last_seen", "started_at", "ended_at",
                      "modified_at", "accessed_at", "first_seen", "resolved_at", "last_action"]:
            if field in data and data[field]:
                data[field] = datetime.fromisoformat(data[field])

        # Convert embedding back to numpy
        if "embedding" in data and data["embedding"]:
            data["embedding"] = np.array(data["embedding"], dtype=np.float32)

        # Node-specific enum conversions
        enum_mappings = {
            "USER": {"privilege_level": PrivilegeLevel, "account_type": AccountType},
            "PROCESS": {"status": ProcessStatus},
            "FILE": {"file_type": FileType},
            "NETWORK": {"direction": NetworkDirection, "protocol": Protocol},
            "THREAT": {"threat_type": ThreatType, "severity": Severity, "status": ThreatStatus},
            "AGENT": {"agent_type": AgentType, "reasoning_state": ReasoningState},
        }

        for field, enum_class in enum_mappings.get(node_type, {}).items():
            if field in data and isinstance(data[field], str):
                data[field] = enum_class[data[field]]

        return data

    @staticmethod
    def _deserialize_edge_data(edge_type: str, data: dict) -> dict:
        """Convert serialized edge data back to proper types."""
        from ares.graph.schema import (
            ExecutionContext, AccessType, EscalationMethod,
            PrivilegeLevel, ArgumentType, ChallengeType
        )

        # Convert datetime strings
        for field in ["timestamp"]:
            if field in data and data[field]:
                data[field] = datetime.fromisoformat(data[field])

        # Edge-specific enum conversions
        enum_mappings = {
            "EXECUTES": {"context": ExecutionContext},
            "ACCESSES": {"access_type": AccessType},
            "ESCALATES": {
                "method": EscalationMethod,
                "from_privilege": PrivilegeLevel,
                "to_privilege": PrivilegeLevel,
            },
            "DEBATES": {"argument_type": ArgumentType},
            "CHALLENGES": {"challenge_type": ChallengeType},
        }

        for field, enum_class in enum_mappings.get(edge_type, {}).items():
            if field in data and isinstance(data[field], str):
                data[field] = enum_class[data[field]]

        return data

    # =========================================================================
    # STATISTICS
    # =========================================================================

    @property
    def node_count(self) -> int:
        """Total number of nodes."""
        return len(self._nodes)

    @property
    def edge_count(self) -> int:
        """Total number of edges."""
        return len(self._edges)

    def stats(self) -> dict[str, Any]:
        """Get graph statistics."""
        return {
            "name": self.name,
            "total_nodes": self.node_count,
            "total_edges": self.edge_count,
            "nodes_by_type": {
                node_type: len(ids)
                for node_type, ids in self._nodes_by_type.items()
            },
            "edges_by_type": {
                edge_type: len(ids)
                for edge_type, ids in self._edges_by_type.items()
            },
            "density": nx.density(self._nx_graph) if self.node_count > 0 else 0,
            "is_connected": nx.is_weakly_connected(self._nx_graph) if self.node_count > 0 else True,
        }

    def __repr__(self) -> str:
        return f"AresGraph(name={self.name!r}, nodes={self.node_count}, edges={self.edge_count})"
