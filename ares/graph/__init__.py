"""
ARES Graph Module

Contains the graph schema, storage, and PyTorch Geometric integration
for the security knowledge graph and reasoning layer.
"""

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
    # Node types
    NodeBase,
    UserNode,
    ProcessNode,
    FileNode,
    NetworkNode,
    ThreatNode,
    AgentNode,
    # Edge types
    EdgeBase,
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
    # Type definitions
    NodeType,
    EdgeType,
    NODE_REGISTRY,
    EDGE_REGISTRY,
)

from ares.graph.store import AresGraph
from ares.graph.validators import GraphValidator, ValidationError

__all__ = [
    # Enums
    "PrivilegeLevel",
    "AccountType",
    "ProcessStatus",
    "FileType",
    "NetworkDirection",
    "Protocol",
    "ThreatType",
    "Severity",
    "ThreatStatus",
    "AgentType",
    "ReasoningState",
    "AccessType",
    "EscalationMethod",
    "ExecutionContext",
    "ArgumentType",
    "ChallengeType",
    # Nodes
    "NodeBase",
    "UserNode",
    "ProcessNode",
    "FileNode",
    "NetworkNode",
    "ThreatNode",
    "AgentNode",
    # Edges
    "EdgeBase",
    "ExecutesEdge",
    "AccessesEdge",
    "EscalatesEdge",
    "CommunicatesEdge",
    "ObservesEdge",
    "HypothesizesEdge",
    "DebatesEdge",
    "ChallengesEdge",
    "SynthesizesEdge",
    "DetectsEdge",
    # Types
    "NodeType",
    "EdgeType",
    "NODE_REGISTRY",
    "EDGE_REGISTRY",
    # Graph
    "AresGraph",
    "GraphValidator",
    "ValidationError",
]
