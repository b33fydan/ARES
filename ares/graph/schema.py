"""
ARES Graph Schema

Defines all node types, edge types, and their properties for the
security knowledge graph and reasoning layer.

Architecture:
- Security Layer: USER, PROCESS, FILE, NETWORK, THREAT nodes
- Reasoning Layer: AGENT nodes that observe and reason about security layer
- Temporal tracking: All entities have timestamps, edges track duration
"""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import Any, ClassVar, Literal, TypeAlias

import numpy as np


# =============================================================================
# ENUMERATIONS
# =============================================================================


class PrivilegeLevel(Enum):
    """User/Process privilege levels for escalation detection."""
    STANDARD = auto()      # Normal user privileges
    ELEVATED = auto()      # Some elevated permissions (e.g., sudo for specific commands)
    ADMIN = auto()         # Administrative access
    SYSTEM = auto()        # Kernel/root level access


class AccountType(Enum):
    """Distinguishes user account behaviors for anomaly detection."""
    HUMAN = auto()         # Interactive human user
    SERVICE = auto()       # Service account (automated processes)
    MACHINE = auto()       # Machine/computer account
    UNKNOWN = auto()       # Unclassified account


class ProcessStatus(Enum):
    """Process lifecycle states."""
    RUNNING = auto()
    TERMINATED = auto()
    SUSPENDED = auto()
    ZOMBIE = auto()


class FileType(Enum):
    """File classification for risk assessment."""
    EXECUTABLE = auto()    # .exe, .dll, .so, ELF binaries
    SCRIPT = auto()        # .ps1, .sh, .py, .js
    DOCUMENT = auto()      # .docx, .pdf, .xlsx
    CONFIG = auto()        # .conf, .ini, .yaml, .json
    DATA = auto()          # .csv, .db, .log
    ARCHIVE = auto()       # .zip, .tar, .7z
    UNKNOWN = auto()


class NetworkDirection(Enum):
    """Network connection directionality."""
    INBOUND = auto()       # External -> Internal
    OUTBOUND = auto()      # Internal -> External
    LATERAL = auto()       # Internal -> Internal


class Protocol(Enum):
    """Network protocols for connection classification."""
    TCP = auto()
    UDP = auto()
    ICMP = auto()
    HTTP = auto()
    HTTPS = auto()
    DNS = auto()
    SSH = auto()
    RDP = auto()
    SMB = auto()
    OTHER = auto()


class ThreatType(Enum):
    """MITRE ATT&CK aligned threat categories."""
    MALWARE = auto()                # Malicious software execution
    INTRUSION = auto()              # Initial access attempts
    EXFILTRATION = auto()           # Data theft
    PRIVILEGE_ESCALATION = auto()   # Vertical privilege gain
    LATERAL_MOVEMENT = auto()       # Horizontal spread
    PERSISTENCE = auto()            # Maintaining access
    COMMAND_AND_CONTROL = auto()    # C2 communication
    DEFENSE_EVASION = auto()        # Detection avoidance
    CREDENTIAL_ACCESS = auto()      # Credential theft
    DISCOVERY = auto()              # Environment reconnaissance
    COLLECTION = auto()             # Data gathering pre-exfil


class Severity(Enum):
    """Threat severity levels."""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class ThreatStatus(Enum):
    """Threat lifecycle in dialectical reasoning."""
    HYPOTHESIZED = auto()  # Initial proposal by ARCHITECT
    DEBATED = auto()       # Under SKEPTIC challenge
    SYNTHESIZED = auto()   # ORACLE has merged contradictions
    CONFIRMED = auto()     # High confidence detection
    DISMISSED = auto()     # Rejected as false positive


class AgentType(Enum):
    """Dialectical reasoning agent roles."""
    ARCHITECT = auto()     # Thesis: proposes threat hypotheses
    SKEPTIC = auto()       # Antithesis: challenges hypotheses
    ORACLE = auto()        # Synthesis: resolves contradictions


class ReasoningState(Enum):
    """Agent reasoning lifecycle."""
    OBSERVING = auto()     # Gathering evidence from security graph
    HYPOTHESIZING = auto() # Formulating threat hypothesis
    DEBATING = auto()      # Engaged in dialectical exchange
    SYNTHESIZING = auto()  # Oracle merging contradictions
    RESOLVED = auto()      # Reasoning cycle complete


class AccessType(Enum):
    """File access operations."""
    READ = auto()
    WRITE = auto()
    DELETE = auto()
    EXECUTE = auto()
    CREATE = auto()
    MODIFY_PERMISSIONS = auto()


class EscalationMethod(Enum):
    """Privilege escalation techniques."""
    SUDO = auto()                # Unix sudo elevation
    RUNAS = auto()               # Windows RunAs
    EXPLOIT = auto()             # Vulnerability exploitation
    TOKEN_MANIPULATION = auto()  # Access token modification
    UAC_BYPASS = auto()          # Windows UAC bypass
    SETUID = auto()              # Unix setuid abuse
    CREDENTIAL_INJECTION = auto()


class ExecutionContext(Enum):
    """How a process was initiated."""
    INTERACTIVE = auto()   # User shell/GUI
    SERVICE = auto()       # System service
    SCHEDULED = auto()     # Cron/Task Scheduler
    REMOTE = auto()        # Remote execution (PSExec, SSH)
    CHILD = auto()         # Spawned by parent process


class ArgumentType(Enum):
    """Types of dialectical arguments."""
    SUPPORT = auto()       # Evidence supporting hypothesis
    REFUTE = auto()        # Evidence against hypothesis
    QUESTION = auto()      # Request for clarification
    CONCEDE = auto()       # Partial agreement


class ChallengeType(Enum):
    """Skeptic challenge categories."""
    INSUFFICIENT_EVIDENCE = auto()
    ALTERNATIVE_EXPLANATION = auto()
    FALSE_POSITIVE_INDICATOR = auto()
    TEMPORAL_INCONSISTENCY = auto()
    BEHAVIORAL_BASELINE = auto()


# =============================================================================
# TYPE DEFINITIONS
# =============================================================================

NodeType: TypeAlias = Literal["USER", "PROCESS", "FILE", "NETWORK", "THREAT", "AGENT"]
EdgeType: TypeAlias = Literal[
    "EXECUTES", "ACCESSES", "ESCALATES", "COMMUNICATES",
    "OBSERVES", "HYPOTHESIZES", "DEBATES", "CHALLENGES", "SYNTHESIZES", "DETECTS"
]


# =============================================================================
# BASE CLASSES
# =============================================================================


@dataclass
class NodeBase(ABC):
    """
    Abstract base class for all graph nodes.

    All nodes have:
    - Unique identifier (UUID)
    - Creation and last-seen timestamps for temporal tracking
    - Risk score for threat assessment
    - Optional embedding vector for GNN representations
    """

    NODE_TYPE: ClassVar[NodeType]

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: datetime = field(default_factory=datetime.utcnow)
    last_seen: datetime = field(default_factory=datetime.utcnow)
    risk_score: float = 0.0
    embedding: np.ndarray | None = None

    def __post_init__(self) -> None:
        """Validate common node constraints."""
        if not 0.0 <= self.risk_score <= 1.0:
            raise ValueError(f"risk_score must be in [0.0, 1.0], got {self.risk_score}")
        if self.embedding is not None and not isinstance(self.embedding, np.ndarray):
            raise TypeError(f"embedding must be np.ndarray, got {type(self.embedding)}")

    @abstractmethod
    def to_feature_vector(self) -> np.ndarray:
        """Convert node properties to numeric feature vector for GNN input."""
        pass

    def update_last_seen(self) -> None:
        """Update last_seen timestamp to current time."""
        self.last_seen = datetime.utcnow()

    def to_dict(self) -> dict[str, Any]:
        """Serialize node to dictionary for storage/export."""
        result = {
            "id": self.id,
            "node_type": self.NODE_TYPE,
            "created_at": self.created_at.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "risk_score": self.risk_score,
        }
        if self.embedding is not None:
            result["embedding"] = self.embedding.tolist()
        return result


@dataclass
class EdgeBase(ABC):
    """
    Abstract base class for all graph edges.

    All edges have:
    - Unique identifier
    - Source and target node IDs
    - Timestamp for temporal tracking
    - Optional duration for time-bounded relationships
    - Risk score contribution
    """

    EDGE_TYPE: ClassVar[EdgeType]
    VALID_SOURCE_TYPES: ClassVar[tuple[NodeType, ...]]
    VALID_TARGET_TYPES: ClassVar[tuple[NodeType, ...]]

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    source_id: str = ""
    target_id: str = ""
    timestamp: datetime = field(default_factory=datetime.utcnow)
    duration: float | None = None  # Duration in seconds, None if ongoing/instantaneous
    risk_score: float = 0.0

    def __post_init__(self) -> None:
        """Validate common edge constraints."""
        if not self.source_id:
            raise ValueError("source_id is required")
        if not self.target_id:
            raise ValueError("target_id is required")
        if not 0.0 <= self.risk_score <= 1.0:
            raise ValueError(f"risk_score must be in [0.0, 1.0], got {self.risk_score}")
        if self.duration is not None and self.duration < 0:
            raise ValueError(f"duration must be non-negative, got {self.duration}")

    @abstractmethod
    def to_feature_vector(self) -> np.ndarray:
        """Convert edge properties to numeric feature vector for GNN input."""
        pass

    def to_dict(self) -> dict[str, Any]:
        """Serialize edge to dictionary for storage/export."""
        return {
            "id": self.id,
            "edge_type": self.EDGE_TYPE,
            "source_id": self.source_id,
            "target_id": self.target_id,
            "timestamp": self.timestamp.isoformat(),
            "duration": self.duration,
            "risk_score": self.risk_score,
        }


# =============================================================================
# SECURITY LAYER NODES
# =============================================================================


@dataclass
class UserNode(NodeBase):
    """
    Represents a user account/identity in the security graph.

    The USER node is the "who" - connecting identities to processes,
    files, and network activity. Critical for:
    - Lateral movement detection (compromised credentials)
    - Privilege escalation tracking
    - Behavioral anomaly detection
    """

    NODE_TYPE: ClassVar[NodeType] = "USER"
    FEATURE_DIM: ClassVar[int] = 16

    username: str = ""
    domain: str = "LOCAL"
    sid: str | None = None         # Windows Security Identifier
    uid: int | None = None         # Unix User ID
    privilege_level: PrivilegeLevel = PrivilegeLevel.STANDARD
    account_type: AccountType = AccountType.UNKNOWN
    is_active: bool = True
    groups: list[str] = field(default_factory=list)
    auth_failures: int = 0         # Recent authentication failure count
    sessions_count: int = 0        # Active session count

    def __post_init__(self) -> None:
        super().__post_init__()
        if not self.username:
            raise ValueError("username is required")
        if self.auth_failures < 0:
            raise ValueError("auth_failures cannot be negative")
        if self.sessions_count < 0:
            raise ValueError("sessions_count cannot be negative")

    def to_feature_vector(self) -> np.ndarray:
        """
        Encode user properties as numeric features.

        Features:
        - privilege_level (one-hot, 4 dims)
        - account_type (one-hot, 4 dims)
        - is_active (binary)
        - risk_score (normalized)
        - auth_failures (log-scaled)
        - sessions_count (log-scaled)
        - groups_count (log-scaled)
        - has_sid (binary)
        - has_uid (binary)
        - account_age_days (log-scaled)
        """
        features = np.zeros(self.FEATURE_DIM, dtype=np.float32)

        # Privilege level one-hot (indices 0-3)
        features[self.privilege_level.value - 1] = 1.0

        # Account type one-hot (indices 4-7)
        features[4 + self.account_type.value - 1] = 1.0

        # Binary and numeric features (indices 8-15)
        features[8] = float(self.is_active)
        features[9] = self.risk_score
        features[10] = np.log1p(self.auth_failures)
        features[11] = np.log1p(self.sessions_count)
        features[12] = np.log1p(len(self.groups))
        features[13] = float(self.sid is not None)
        features[14] = float(self.uid is not None)

        # Account age in days (log-scaled)
        age_seconds = (datetime.utcnow() - self.created_at).total_seconds()
        features[15] = np.log1p(age_seconds / 86400)  # Convert to days

        return features

    def to_dict(self) -> dict[str, Any]:
        result = super().to_dict()
        result.update({
            "username": self.username,
            "domain": self.domain,
            "sid": self.sid,
            "uid": self.uid,
            "privilege_level": self.privilege_level.name,
            "account_type": self.account_type.name,
            "is_active": self.is_active,
            "groups": self.groups,
            "auth_failures": self.auth_failures,
            "sessions_count": self.sessions_count,
        })
        return result


@dataclass
class ProcessNode(NodeBase):
    """
    Represents an operating system process.

    The PROCESS node is the "what" - the executable action connecting
    users to resources. Critical for:
    - Process tree analysis (parent-child relationships)
    - Execution anomaly detection
    - Living-off-the-land binary (LOLBin) identification
    """

    NODE_TYPE: ClassVar[NodeType] = "PROCESS"
    FEATURE_DIM: ClassVar[int] = 20

    pid: int = 0
    name: str = ""
    command_line: str = ""
    executable_path: str = ""
    executable_hash: str | None = None  # SHA-256 hash
    parent_id: str | None = None        # Reference to parent ProcessNode
    user_id: str | None = None          # Reference to owning UserNode
    status: ProcessStatus = ProcessStatus.RUNNING
    is_elevated: bool = False
    started_at: datetime = field(default_factory=datetime.utcnow)
    ended_at: datetime | None = None
    cpu_percent: float = 0.0
    memory_mb: float = 0.0
    open_handles: int = 0
    child_count: int = 0

    def __post_init__(self) -> None:
        super().__post_init__()
        if not self.name:
            raise ValueError("name is required")
        if self.pid < 0:
            raise ValueError("pid cannot be negative")

    def to_feature_vector(self) -> np.ndarray:
        """
        Encode process properties as numeric features.

        Features include status encoding, elevation flag, resource usage,
        process tree metrics, and temporal features.
        """
        features = np.zeros(self.FEATURE_DIM, dtype=np.float32)

        # Status one-hot (indices 0-3)
        features[self.status.value - 1] = 1.0

        # Binary flags (indices 4-6)
        features[4] = float(self.is_elevated)
        features[5] = float(self.parent_id is not None)
        features[6] = float(self.executable_hash is not None)

        # Numeric features (indices 7-13)
        features[7] = self.risk_score
        features[8] = np.log1p(self.pid)
        features[9] = min(self.cpu_percent / 100.0, 1.0)
        features[10] = np.log1p(self.memory_mb)
        features[11] = np.log1p(self.open_handles)
        features[12] = np.log1p(self.child_count)
        features[13] = np.log1p(len(self.command_line))

        # Path depth (indices 14)
        features[14] = np.log1p(self.executable_path.count("/") +
                                self.executable_path.count("\\"))

        # Runtime in seconds (index 15)
        if self.ended_at:
            runtime = (self.ended_at - self.started_at).total_seconds()
        else:
            runtime = (datetime.utcnow() - self.started_at).total_seconds()
        features[15] = np.log1p(runtime)

        # Reserved for learned features (indices 16-19)

        return features

    def to_dict(self) -> dict[str, Any]:
        result = super().to_dict()
        result.update({
            "pid": self.pid,
            "name": self.name,
            "command_line": self.command_line,
            "executable_path": self.executable_path,
            "executable_hash": self.executable_hash,
            "parent_id": self.parent_id,
            "user_id": self.user_id,
            "status": self.status.name,
            "is_elevated": self.is_elevated,
            "started_at": self.started_at.isoformat(),
            "ended_at": self.ended_at.isoformat() if self.ended_at else None,
            "cpu_percent": self.cpu_percent,
            "memory_mb": self.memory_mb,
            "open_handles": self.open_handles,
            "child_count": self.child_count,
        })
        return result


@dataclass
class FileNode(NodeBase):
    """
    Represents a file system object.

    The FILE node tracks data at rest - documents, executables, configs.
    Critical for:
    - Data exfiltration detection
    - Ransomware behavior (mass file modifications)
    - Sensitive file access monitoring
    """

    NODE_TYPE: ClassVar[NodeType] = "FILE"
    FEATURE_DIM: ClassVar[int] = 18

    path: str = ""
    name: str = ""
    extension: str = ""
    size_bytes: int = 0
    file_hash: str | None = None  # SHA-256 hash
    file_type: FileType = FileType.UNKNOWN
    owner_id: str | None = None   # Reference to UserNode
    modified_at: datetime = field(default_factory=datetime.utcnow)
    accessed_at: datetime = field(default_factory=datetime.utcnow)
    is_sensitive: bool = False    # Contains PII, credentials, etc.
    is_system: bool = False       # System/protected file
    access_count: int = 0         # Recent access frequency
    permissions: str = ""         # Unix-style or ACL string
    entropy: float = 0.0          # File content entropy [0.0-8.0]

    def __post_init__(self) -> None:
        super().__post_init__()
        if not self.path:
            raise ValueError("path is required")
        if self.size_bytes < 0:
            raise ValueError("size_bytes cannot be negative")
        if not 0.0 <= self.entropy <= 8.0:
            raise ValueError(f"entropy must be in [0.0, 8.0], got {self.entropy}")

        # Auto-extract name and extension if not provided
        if not self.name:
            self.name = self.path.split("/")[-1].split("\\")[-1]
        if not self.extension and "." in self.name:
            self.extension = self.name.rsplit(".", 1)[-1].lower()

    def to_feature_vector(self) -> np.ndarray:
        """Encode file properties as numeric features."""
        features = np.zeros(self.FEATURE_DIM, dtype=np.float32)

        # File type one-hot (indices 0-6)
        features[self.file_type.value - 1] = 1.0

        # Binary flags (indices 7-10)
        features[7] = float(self.is_sensitive)
        features[8] = float(self.is_system)
        features[9] = float(self.file_hash is not None)
        features[10] = float(self.owner_id is not None)

        # Numeric features (indices 11-17)
        features[11] = self.risk_score
        features[12] = np.log1p(self.size_bytes)
        features[13] = np.log1p(self.access_count)
        features[14] = self.entropy / 8.0  # Normalize to [0, 1]
        features[15] = np.log1p(self.path.count("/") + self.path.count("\\"))

        # Time since modified (hours, log-scaled)
        mod_age = (datetime.utcnow() - self.modified_at).total_seconds() / 3600
        features[16] = np.log1p(mod_age)

        # Time since accessed (hours, log-scaled)
        acc_age = (datetime.utcnow() - self.accessed_at).total_seconds() / 3600
        features[17] = np.log1p(acc_age)

        return features

    def to_dict(self) -> dict[str, Any]:
        result = super().to_dict()
        result.update({
            "path": self.path,
            "name": self.name,
            "extension": self.extension,
            "size_bytes": self.size_bytes,
            "file_hash": self.file_hash,
            "file_type": self.file_type.name,
            "owner_id": self.owner_id,
            "modified_at": self.modified_at.isoformat(),
            "accessed_at": self.accessed_at.isoformat(),
            "is_sensitive": self.is_sensitive,
            "is_system": self.is_system,
            "access_count": self.access_count,
            "permissions": self.permissions,
            "entropy": self.entropy,
        })
        return result


@dataclass
class NetworkNode(NodeBase):
    """
    Represents a network endpoint/connection.

    The NETWORK node tracks data in motion - connections, flows, endpoints.
    Critical for:
    - C2 communication detection
    - Data exfiltration monitoring
    - Lateral movement tracking
    """

    NODE_TYPE: ClassVar[NodeType] = "NETWORK"
    FEATURE_DIM: ClassVar[int] = 22

    ip_address: str = ""
    port: int = 0
    protocol: Protocol = Protocol.TCP
    hostname: str | None = None
    direction: NetworkDirection = NetworkDirection.OUTBOUND
    is_external: bool = True
    geo_country: str | None = None
    geo_city: str | None = None
    asn: str | None = None              # Autonomous System Number
    reputation_score: float = 0.5       # External threat intel score [0, 1]
    bytes_sent: int = 0
    bytes_received: int = 0
    packets_sent: int = 0
    packets_received: int = 0
    first_seen: datetime = field(default_factory=datetime.utcnow)
    connection_count: int = 1
    is_encrypted: bool = False
    is_known_bad: bool = False          # On blocklist

    def __post_init__(self) -> None:
        super().__post_init__()
        if not self.ip_address:
            raise ValueError("ip_address is required")
        if not 0 <= self.port <= 65535:
            raise ValueError(f"port must be in [0, 65535], got {self.port}")
        if not 0.0 <= self.reputation_score <= 1.0:
            raise ValueError(f"reputation_score must be in [0.0, 1.0]")

    def to_feature_vector(self) -> np.ndarray:
        """Encode network properties as numeric features."""
        features = np.zeros(self.FEATURE_DIM, dtype=np.float32)

        # Protocol one-hot (indices 0-9)
        features[self.protocol.value - 1] = 1.0

        # Direction one-hot (indices 10-12)
        features[10 + self.direction.value - 1] = 1.0

        # Binary flags (indices 13-16)
        features[13] = float(self.is_external)
        features[14] = float(self.is_encrypted)
        features[15] = float(self.is_known_bad)
        features[16] = float(self.hostname is not None)

        # Numeric features (indices 17-21)
        features[17] = self.risk_score
        features[18] = self.reputation_score
        features[19] = np.log1p(self.bytes_sent + self.bytes_received)
        features[20] = np.log1p(self.connection_count)

        # Port risk heuristic (well-known ports are lower risk)
        if self.port < 1024:
            features[21] = 0.2
        elif self.port < 49152:
            features[21] = 0.5
        else:
            features[21] = 0.8  # Ephemeral ports

        return features

    def to_dict(self) -> dict[str, Any]:
        result = super().to_dict()
        result.update({
            "ip_address": self.ip_address,
            "port": self.port,
            "protocol": self.protocol.name,
            "hostname": self.hostname,
            "direction": self.direction.name,
            "is_external": self.is_external,
            "geo_country": self.geo_country,
            "geo_city": self.geo_city,
            "asn": self.asn,
            "reputation_score": self.reputation_score,
            "bytes_sent": self.bytes_sent,
            "bytes_received": self.bytes_received,
            "packets_sent": self.packets_sent,
            "packets_received": self.packets_received,
            "first_seen": self.first_seen.isoformat(),
            "connection_count": self.connection_count,
            "is_encrypted": self.is_encrypted,
            "is_known_bad": self.is_known_bad,
        })
        return result


@dataclass
class ThreatNode(NodeBase):
    """
    Represents a detected or hypothesized threat.

    The THREAT node is the output of the reasoning system - a proposed
    or confirmed security incident. Lifecycle:
    1. HYPOTHESIZED by ARCHITECT agent
    2. DEBATED between ARCHITECT and SKEPTIC
    3. SYNTHESIZED by ORACLE (resolving contradictions)
    4. CONFIRMED or DISMISSED based on confidence
    """

    NODE_TYPE: ClassVar[NodeType] = "THREAT"
    FEATURE_DIM: ClassVar[int] = 24

    threat_type: ThreatType = ThreatType.MALWARE
    severity: Severity = Severity.MEDIUM
    status: ThreatStatus = ThreatStatus.HYPOTHESIZED
    confidence: float = 0.5
    description: str = ""

    # MITRE ATT&CK mapping
    mitre_tactics: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)

    # Attack chain references
    affected_node_ids: list[str] = field(default_factory=list)
    attack_chain_edge_ids: list[str] = field(default_factory=list)

    # Evidence tracking
    evidence_node_ids: list[str] = field(default_factory=list)
    evidence_edge_ids: list[str] = field(default_factory=list)

    # Dialectical reasoning metadata
    hypothesis_count: int = 0      # Times this threat was hypothesized
    challenge_count: int = 0       # Times this threat was challenged
    supporting_agent_ids: list[str] = field(default_factory=list)

    # Resolution
    resolved_at: datetime | None = None
    resolution_notes: str = ""
    false_positive_probability: float = 0.5

    def __post_init__(self) -> None:
        super().__post_init__()
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"confidence must be in [0.0, 1.0], got {self.confidence}")
        if not 0.0 <= self.false_positive_probability <= 1.0:
            raise ValueError("false_positive_probability must be in [0.0, 1.0]")

    def to_feature_vector(self) -> np.ndarray:
        """Encode threat properties as numeric features."""
        features = np.zeros(self.FEATURE_DIM, dtype=np.float32)

        # Threat type one-hot (indices 0-10)
        features[self.threat_type.value - 1] = 1.0

        # Status one-hot (indices 11-15)
        features[11 + self.status.value - 1] = 1.0

        # Severity (normalized, index 16)
        features[16] = self.severity.value / 4.0

        # Numeric features (indices 17-23)
        features[17] = self.confidence
        features[18] = 1.0 - self.false_positive_probability
        features[19] = self.risk_score
        features[20] = np.log1p(len(self.affected_node_ids))
        features[21] = np.log1p(len(self.mitre_techniques))
        features[22] = np.log1p(self.hypothesis_count)
        features[23] = np.log1p(self.challenge_count)

        return features

    def to_dict(self) -> dict[str, Any]:
        result = super().to_dict()
        result.update({
            "threat_type": self.threat_type.name,
            "severity": self.severity.name,
            "status": self.status.name,
            "confidence": self.confidence,
            "description": self.description,
            "mitre_tactics": self.mitre_tactics,
            "mitre_techniques": self.mitre_techniques,
            "affected_node_ids": self.affected_node_ids,
            "attack_chain_edge_ids": self.attack_chain_edge_ids,
            "evidence_node_ids": self.evidence_node_ids,
            "evidence_edge_ids": self.evidence_edge_ids,
            "hypothesis_count": self.hypothesis_count,
            "challenge_count": self.challenge_count,
            "supporting_agent_ids": self.supporting_agent_ids,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "resolution_notes": self.resolution_notes,
            "false_positive_probability": self.false_positive_probability,
        })
        return result


# =============================================================================
# REASONING LAYER NODES
# =============================================================================


@dataclass
class AgentNode(NodeBase):
    """
    Represents a dialectical reasoning agent.

    AGENT nodes exist in a separate "reasoning layer" that observes
    and reasons about the security graph. Three agent types:

    - ARCHITECT (Thesis): Proposes threat hypotheses from patterns
    - SKEPTIC (Antithesis): Challenges hypotheses, finds counter-evidence
    - ORACLE (Synthesis): Resolves contradictions, produces final judgment
    """

    NODE_TYPE: ClassVar[NodeType] = "AGENT"
    FEATURE_DIM: ClassVar[int] = 16

    agent_type: AgentType = AgentType.ARCHITECT
    reasoning_state: ReasoningState = ReasoningState.OBSERVING
    confidence: float = 0.5

    # Current focus
    current_hypothesis_id: str | None = None  # THREAT node being considered
    observed_node_ids: list[str] = field(default_factory=list)
    observed_edge_ids: list[str] = field(default_factory=list)

    # Performance metrics
    hypotheses_proposed: int = 0
    hypotheses_confirmed: int = 0
    hypotheses_dismissed: int = 0
    debates_participated: int = 0

    # Last action tracking
    last_action: datetime = field(default_factory=datetime.utcnow)
    last_action_type: str = "INITIALIZE"

    def __post_init__(self) -> None:
        super().__post_init__()
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"confidence must be in [0.0, 1.0], got {self.confidence}")

    def to_feature_vector(self) -> np.ndarray:
        """Encode agent properties as numeric features."""
        features = np.zeros(self.FEATURE_DIM, dtype=np.float32)

        # Agent type one-hot (indices 0-2)
        features[self.agent_type.value - 1] = 1.0

        # Reasoning state one-hot (indices 3-7)
        features[3 + self.reasoning_state.value - 1] = 1.0

        # Numeric features (indices 8-15)
        features[8] = self.confidence
        features[9] = self.risk_score
        features[10] = float(self.current_hypothesis_id is not None)
        features[11] = np.log1p(len(self.observed_node_ids))
        features[12] = np.log1p(self.hypotheses_proposed)
        features[13] = np.log1p(self.debates_participated)

        # Success rate (if applicable)
        total = self.hypotheses_confirmed + self.hypotheses_dismissed
        if total > 0:
            features[14] = self.hypotheses_confirmed / total
        else:
            features[14] = 0.5

        # Time since last action (log-scaled hours)
        time_since = (datetime.utcnow() - self.last_action).total_seconds() / 3600
        features[15] = np.log1p(time_since)

        return features

    def to_dict(self) -> dict[str, Any]:
        result = super().to_dict()
        result.update({
            "agent_type": self.agent_type.name,
            "reasoning_state": self.reasoning_state.name,
            "confidence": self.confidence,
            "current_hypothesis_id": self.current_hypothesis_id,
            "observed_node_ids": self.observed_node_ids,
            "observed_edge_ids": self.observed_edge_ids,
            "hypotheses_proposed": self.hypotheses_proposed,
            "hypotheses_confirmed": self.hypotheses_confirmed,
            "hypotheses_dismissed": self.hypotheses_dismissed,
            "debates_participated": self.debates_participated,
            "last_action": self.last_action.isoformat(),
            "last_action_type": self.last_action_type,
        })
        return result


# =============================================================================
# SECURITY LAYER EDGES
# =============================================================================


@dataclass
class ExecutesEdge(EdgeBase):
    """
    USER -> PROCESS: A user executing a process.

    Captures the context of how processes are launched, critical for:
    - Detecting unauthorized process execution
    - Service account abuse
    - Remote execution attacks
    """

    EDGE_TYPE: ClassVar[EdgeType] = "EXECUTES"
    VALID_SOURCE_TYPES: ClassVar[tuple[NodeType, ...]] = ("USER",)
    VALID_TARGET_TYPES: ClassVar[tuple[NodeType, ...]] = ("PROCESS",)
    FEATURE_DIM: ClassVar[int] = 8

    context: ExecutionContext = ExecutionContext.INTERACTIVE
    success: bool = True
    arguments_hash: str | None = None  # Hash of command line args
    working_directory: str = ""
    environment_hash: str | None = None

    def to_feature_vector(self) -> np.ndarray:
        """Encode execution edge as feature vector."""
        features = np.zeros(self.FEATURE_DIM, dtype=np.float32)

        # Context one-hot (indices 0-4)
        features[self.context.value - 1] = 1.0

        # Binary and numeric (indices 5-7)
        features[5] = float(self.success)
        features[6] = self.risk_score
        features[7] = float(self.arguments_hash is not None)

        return features

    def to_dict(self) -> dict[str, Any]:
        result = super().to_dict()
        result.update({
            "context": self.context.name,
            "success": self.success,
            "arguments_hash": self.arguments_hash,
            "working_directory": self.working_directory,
            "environment_hash": self.environment_hash,
        })
        return result


@dataclass
class AccessesEdge(EdgeBase):
    """
    PROCESS -> FILE or USER -> FILE: File access events.

    Tracks all file operations for:
    - Data exfiltration detection (mass reads)
    - Ransomware behavior (mass writes)
    - Sensitive file access monitoring
    """

    EDGE_TYPE: ClassVar[EdgeType] = "ACCESSES"
    VALID_SOURCE_TYPES: ClassVar[tuple[NodeType, ...]] = ("PROCESS", "USER")
    VALID_TARGET_TYPES: ClassVar[tuple[NodeType, ...]] = ("FILE",)
    FEATURE_DIM: ClassVar[int] = 10

    access_type: AccessType = AccessType.READ
    success: bool = True
    bytes_transferred: int = 0
    is_first_access: bool = False     # First time this entity accessed file
    access_denied_count: int = 0      # Permission denied attempts before success

    def to_feature_vector(self) -> np.ndarray:
        """Encode access edge as feature vector."""
        features = np.zeros(self.FEATURE_DIM, dtype=np.float32)

        # Access type one-hot (indices 0-5)
        features[self.access_type.value - 1] = 1.0

        # Binary and numeric (indices 6-9)
        features[6] = float(self.success)
        features[7] = self.risk_score
        features[8] = np.log1p(self.bytes_transferred)
        features[9] = float(self.is_first_access)

        return features

    def to_dict(self) -> dict[str, Any]:
        result = super().to_dict()
        result.update({
            "access_type": self.access_type.name,
            "success": self.success,
            "bytes_transferred": self.bytes_transferred,
            "is_first_access": self.is_first_access,
            "access_denied_count": self.access_denied_count,
        })
        return result


@dataclass
class EscalatesEdge(EdgeBase):
    """
    USER -> USER or PROCESS -> PROCESS: Privilege escalation events.

    Tracks privilege changes across:
    - User context switches (su, sudo, runas)
    - Process elevation (token manipulation)
    - Critical for detecting privilege escalation attacks
    """

    EDGE_TYPE: ClassVar[EdgeType] = "ESCALATES"
    VALID_SOURCE_TYPES: ClassVar[tuple[NodeType, ...]] = ("USER", "PROCESS")
    VALID_TARGET_TYPES: ClassVar[tuple[NodeType, ...]] = ("USER", "PROCESS")
    FEATURE_DIM: ClassVar[int] = 12

    from_privilege: PrivilegeLevel = PrivilegeLevel.STANDARD
    to_privilege: PrivilegeLevel = PrivilegeLevel.ELEVATED
    method: EscalationMethod = EscalationMethod.SUDO
    success: bool = True
    is_legitimate: bool | None = None  # None = unknown/unverified

    def __post_init__(self) -> None:
        super().__post_init__()
        # Validate escalation makes sense
        if self.to_privilege.value <= self.from_privilege.value and self.success:
            # Not actually an escalation - could be de-escalation or lateral
            pass  # Allow for flexibility

    def to_feature_vector(self) -> np.ndarray:
        """Encode escalation edge as feature vector."""
        features = np.zeros(self.FEATURE_DIM, dtype=np.float32)

        # Method one-hot (indices 0-6)
        features[self.method.value - 1] = 1.0

        # Privilege levels (indices 7-8)
        features[7] = self.from_privilege.value / 4.0
        features[8] = self.to_privilege.value / 4.0

        # Escalation magnitude (index 9)
        features[9] = (self.to_privilege.value - self.from_privilege.value) / 3.0

        # Binary and numeric (indices 10-11)
        features[10] = float(self.success)
        features[11] = self.risk_score

        return features

    def to_dict(self) -> dict[str, Any]:
        result = super().to_dict()
        result.update({
            "from_privilege": self.from_privilege.name,
            "to_privilege": self.to_privilege.name,
            "method": self.method.name,
            "success": self.success,
            "is_legitimate": self.is_legitimate,
        })
        return result


@dataclass
class CommunicatesEdge(EdgeBase):
    """
    PROCESS -> NETWORK or NETWORK -> NETWORK: Network communication.

    Tracks network flows for:
    - C2 beacon detection (periodic outbound)
    - Data exfiltration (large outbound transfers)
    - Lateral movement (internal-to-internal)
    """

    EDGE_TYPE: ClassVar[EdgeType] = "COMMUNICATES"
    VALID_SOURCE_TYPES: ClassVar[tuple[NodeType, ...]] = ("PROCESS", "NETWORK")
    VALID_TARGET_TYPES: ClassVar[tuple[NodeType, ...]] = ("NETWORK",)
    FEATURE_DIM: ClassVar[int] = 12

    bytes_sent: int = 0
    bytes_received: int = 0
    packets_sent: int = 0
    packets_received: int = 0
    is_established: bool = True
    is_encrypted: bool = False
    session_id: str | None = None

    def to_feature_vector(self) -> np.ndarray:
        """Encode communication edge as feature vector."""
        features = np.zeros(self.FEATURE_DIM, dtype=np.float32)

        # Traffic metrics (indices 0-3)
        features[0] = np.log1p(self.bytes_sent)
        features[1] = np.log1p(self.bytes_received)
        features[2] = np.log1p(self.packets_sent)
        features[3] = np.log1p(self.packets_received)

        # Traffic ratio (index 4) - high ratio = potential exfil
        total = self.bytes_sent + self.bytes_received
        if total > 0:
            features[4] = self.bytes_sent / total
        else:
            features[4] = 0.5

        # Binary flags (indices 5-7)
        features[5] = float(self.is_established)
        features[6] = float(self.is_encrypted)
        features[7] = self.risk_score

        # Duration features (indices 8-9)
        if self.duration is not None:
            features[8] = np.log1p(self.duration)
            # Bytes per second
            if self.duration > 0:
                features[9] = np.log1p(total / self.duration)

        # Reserved (indices 10-11)

        return features

    def to_dict(self) -> dict[str, Any]:
        result = super().to_dict()
        result.update({
            "bytes_sent": self.bytes_sent,
            "bytes_received": self.bytes_received,
            "packets_sent": self.packets_sent,
            "packets_received": self.packets_received,
            "is_established": self.is_established,
            "is_encrypted": self.is_encrypted,
            "session_id": self.session_id,
        })
        return result


# =============================================================================
# REASONING LAYER EDGES
# =============================================================================


@dataclass
class ObservesEdge(EdgeBase):
    """
    AGENT -> (any security node): Agent observing a graph element.

    Tracks what agents are paying attention to for:
    - Attention visualization
    - Explaining reasoning paths
    - Coordinating agent focus
    """

    EDGE_TYPE: ClassVar[EdgeType] = "OBSERVES"
    VALID_SOURCE_TYPES: ClassVar[tuple[NodeType, ...]] = ("AGENT",)
    VALID_TARGET_TYPES: ClassVar[tuple[NodeType, ...]] = ("USER", "PROCESS", "FILE", "NETWORK", "THREAT")
    FEATURE_DIM: ClassVar[int] = 6

    attention_weight: float = 1.0      # How much attention [0, 1]
    observation_type: str = "PASSIVE"  # PASSIVE, ACTIVE, FOCUSED
    triggered_by: str | None = None    # What caused this observation

    def __post_init__(self) -> None:
        super().__post_init__()
        if not 0.0 <= self.attention_weight <= 1.0:
            raise ValueError("attention_weight must be in [0.0, 1.0]")

    def to_feature_vector(self) -> np.ndarray:
        """Encode observation edge as feature vector."""
        features = np.zeros(self.FEATURE_DIM, dtype=np.float32)
        features[0] = self.attention_weight
        features[1] = self.risk_score
        features[2] = float(self.observation_type == "PASSIVE")
        features[3] = float(self.observation_type == "ACTIVE")
        features[4] = float(self.observation_type == "FOCUSED")
        features[5] = float(self.triggered_by is not None)
        return features

    def to_dict(self) -> dict[str, Any]:
        result = super().to_dict()
        result.update({
            "attention_weight": self.attention_weight,
            "observation_type": self.observation_type,
            "triggered_by": self.triggered_by,
        })
        return result


@dataclass
class HypothesizesEdge(EdgeBase):
    """
    AGENT -> THREAT: Agent proposing a threat hypothesis.

    Created by ARCHITECT agents when patterns suggest a threat.
    Contains the reasoning chain that led to the hypothesis.
    """

    EDGE_TYPE: ClassVar[EdgeType] = "HYPOTHESIZES"
    VALID_SOURCE_TYPES: ClassVar[tuple[NodeType, ...]] = ("AGENT",)
    VALID_TARGET_TYPES: ClassVar[tuple[NodeType, ...]] = ("THREAT",)
    FEATURE_DIM: ClassVar[int] = 8

    confidence: float = 0.5
    evidence_node_ids: list[str] = field(default_factory=list)
    evidence_edge_ids: list[str] = field(default_factory=list)
    reasoning_chain: list[str] = field(default_factory=list)  # Steps in reasoning
    hypothesis_iteration: int = 1  # Which iteration of hypothesis refinement

    def __post_init__(self) -> None:
        super().__post_init__()
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be in [0.0, 1.0]")

    def to_feature_vector(self) -> np.ndarray:
        """Encode hypothesis edge as feature vector."""
        features = np.zeros(self.FEATURE_DIM, dtype=np.float32)
        features[0] = self.confidence
        features[1] = self.risk_score
        features[2] = np.log1p(len(self.evidence_node_ids))
        features[3] = np.log1p(len(self.evidence_edge_ids))
        features[4] = np.log1p(len(self.reasoning_chain))
        features[5] = np.log1p(self.hypothesis_iteration)
        # Reserved indices 6-7
        return features

    def to_dict(self) -> dict[str, Any]:
        result = super().to_dict()
        result.update({
            "confidence": self.confidence,
            "evidence_node_ids": self.evidence_node_ids,
            "evidence_edge_ids": self.evidence_edge_ids,
            "reasoning_chain": self.reasoning_chain,
            "hypothesis_iteration": self.hypothesis_iteration,
        })
        return result


@dataclass
class DebatesEdge(EdgeBase):
    """
    AGENT -> AGENT: Dialectical argument exchange.

    Represents one turn in the thesis-antithesis dialogue.
    Tracks argument type, content, and strength.
    """

    EDGE_TYPE: ClassVar[EdgeType] = "DEBATES"
    VALID_SOURCE_TYPES: ClassVar[tuple[NodeType, ...]] = ("AGENT",)
    VALID_TARGET_TYPES: ClassVar[tuple[NodeType, ...]] = ("AGENT",)
    FEATURE_DIM: ClassVar[int] = 10

    topic_threat_id: str = ""          # THREAT being debated
    argument_type: ArgumentType = ArgumentType.SUPPORT
    argument_content: str = ""
    argument_strength: float = 0.5     # Persuasiveness [0, 1]
    evidence_ids: list[str] = field(default_factory=list)
    round_number: int = 1              # Which round of debate

    def __post_init__(self) -> None:
        super().__post_init__()
        if not self.topic_threat_id:
            raise ValueError("topic_threat_id is required")
        if not 0.0 <= self.argument_strength <= 1.0:
            raise ValueError("argument_strength must be in [0.0, 1.0]")

    def to_feature_vector(self) -> np.ndarray:
        """Encode debate edge as feature vector."""
        features = np.zeros(self.FEATURE_DIM, dtype=np.float32)

        # Argument type one-hot (indices 0-3)
        features[self.argument_type.value - 1] = 1.0

        # Numeric features (indices 4-9)
        features[4] = self.argument_strength
        features[5] = self.risk_score
        features[6] = np.log1p(len(self.evidence_ids))
        features[7] = np.log1p(self.round_number)
        features[8] = np.log1p(len(self.argument_content))
        # Reserved index 9

        return features

    def to_dict(self) -> dict[str, Any]:
        result = super().to_dict()
        result.update({
            "topic_threat_id": self.topic_threat_id,
            "argument_type": self.argument_type.name,
            "argument_content": self.argument_content,
            "argument_strength": self.argument_strength,
            "evidence_ids": self.evidence_ids,
            "round_number": self.round_number,
        })
        return result


@dataclass
class ChallengesEdge(EdgeBase):
    """
    AGENT (SKEPTIC) -> AGENT: Challenging a hypothesis.

    Specific edge type for SKEPTIC agents to formally
    challenge hypotheses with counter-evidence.
    """

    EDGE_TYPE: ClassVar[EdgeType] = "CHALLENGES"
    VALID_SOURCE_TYPES: ClassVar[tuple[NodeType, ...]] = ("AGENT",)
    VALID_TARGET_TYPES: ClassVar[tuple[NodeType, ...]] = ("AGENT",)
    FEATURE_DIM: ClassVar[int] = 10

    target_hypothesis_id: str = ""     # THREAT being challenged
    challenge_type: ChallengeType = ChallengeType.INSUFFICIENT_EVIDENCE
    counter_evidence_ids: list[str] = field(default_factory=list)
    alternative_explanation: str = ""
    challenge_strength: float = 0.5

    def __post_init__(self) -> None:
        super().__post_init__()
        if not self.target_hypothesis_id:
            raise ValueError("target_hypothesis_id is required")
        if not 0.0 <= self.challenge_strength <= 1.0:
            raise ValueError("challenge_strength must be in [0.0, 1.0]")

    def to_feature_vector(self) -> np.ndarray:
        """Encode challenge edge as feature vector."""
        features = np.zeros(self.FEATURE_DIM, dtype=np.float32)

        # Challenge type one-hot (indices 0-4)
        features[self.challenge_type.value - 1] = 1.0

        # Numeric features (indices 5-9)
        features[5] = self.challenge_strength
        features[6] = self.risk_score
        features[7] = np.log1p(len(self.counter_evidence_ids))
        features[8] = float(len(self.alternative_explanation) > 0)
        # Reserved index 9

        return features

    def to_dict(self) -> dict[str, Any]:
        result = super().to_dict()
        result.update({
            "target_hypothesis_id": self.target_hypothesis_id,
            "challenge_type": self.challenge_type.name,
            "counter_evidence_ids": self.counter_evidence_ids,
            "alternative_explanation": self.alternative_explanation,
            "challenge_strength": self.challenge_strength,
        })
        return result


@dataclass
class SynthesizesEdge(EdgeBase):
    """
    AGENT (ORACLE) -> THREAT: Synthesizing contradictions.

    Created when ORACLE resolves thesis-antithesis into synthesis.
    Records source hypotheses and synthesis method.
    """

    EDGE_TYPE: ClassVar[EdgeType] = "SYNTHESIZES"
    VALID_SOURCE_TYPES: ClassVar[tuple[NodeType, ...]] = ("AGENT",)
    VALID_TARGET_TYPES: ClassVar[tuple[NodeType, ...]] = ("THREAT",)
    FEATURE_DIM: ClassVar[int] = 8

    source_hypothesis_ids: list[str] = field(default_factory=list)
    synthesis_method: str = "MERGE"    # MERGE, SPLIT, REFINE, DISMISS
    result_confidence: float = 0.5
    contradictions_resolved: int = 0
    reasoning_summary: str = ""

    def __post_init__(self) -> None:
        super().__post_init__()
        if not 0.0 <= self.result_confidence <= 1.0:
            raise ValueError("result_confidence must be in [0.0, 1.0]")

    def to_feature_vector(self) -> np.ndarray:
        """Encode synthesis edge as feature vector."""
        features = np.zeros(self.FEATURE_DIM, dtype=np.float32)
        features[0] = self.result_confidence
        features[1] = self.risk_score
        features[2] = np.log1p(len(self.source_hypothesis_ids))
        features[3] = np.log1p(self.contradictions_resolved)
        features[4] = float(self.synthesis_method == "MERGE")
        features[5] = float(self.synthesis_method == "SPLIT")
        features[6] = float(self.synthesis_method == "REFINE")
        features[7] = float(self.synthesis_method == "DISMISS")
        return features

    def to_dict(self) -> dict[str, Any]:
        result = super().to_dict()
        result.update({
            "source_hypothesis_ids": self.source_hypothesis_ids,
            "synthesis_method": self.synthesis_method,
            "result_confidence": self.result_confidence,
            "contradictions_resolved": self.contradictions_resolved,
            "reasoning_summary": self.reasoning_summary,
        })
        return result


@dataclass
class DetectsEdge(EdgeBase):
    """
    AGENT -> THREAT: Confirmed detection.

    Created when a THREAT reaches high confidence after
    dialectical reasoning. This is the final output edge.
    """

    EDGE_TYPE: ClassVar[EdgeType] = "DETECTS"
    VALID_SOURCE_TYPES: ClassVar[tuple[NodeType, ...]] = ("AGENT",)
    VALID_TARGET_TYPES: ClassVar[tuple[NodeType, ...]] = ("THREAT",)
    FEATURE_DIM: ClassVar[int] = 8

    confidence: float = 0.9
    detection_method: str = "DIALECTICAL"
    false_positive_probability: float = 0.1
    debate_rounds: int = 0
    total_evidence_count: int = 0

    def __post_init__(self) -> None:
        super().__post_init__()
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be in [0.0, 1.0]")
        if not 0.0 <= self.false_positive_probability <= 1.0:
            raise ValueError("false_positive_probability must be in [0.0, 1.0]")

    def to_feature_vector(self) -> np.ndarray:
        """Encode detection edge as feature vector."""
        features = np.zeros(self.FEATURE_DIM, dtype=np.float32)
        features[0] = self.confidence
        features[1] = 1.0 - self.false_positive_probability
        features[2] = self.risk_score
        features[3] = np.log1p(self.debate_rounds)
        features[4] = np.log1p(self.total_evidence_count)
        # Reserved indices 5-7
        return features

    def to_dict(self) -> dict[str, Any]:
        result = super().to_dict()
        result.update({
            "confidence": self.confidence,
            "detection_method": self.detection_method,
            "false_positive_probability": self.false_positive_probability,
            "debate_rounds": self.debate_rounds,
            "total_evidence_count": self.total_evidence_count,
        })
        return result


# =============================================================================
# REGISTRIES
# =============================================================================

NODE_REGISTRY: dict[NodeType, type[NodeBase]] = {
    "USER": UserNode,
    "PROCESS": ProcessNode,
    "FILE": FileNode,
    "NETWORK": NetworkNode,
    "THREAT": ThreatNode,
    "AGENT": AgentNode,
}

EDGE_REGISTRY: dict[EdgeType, type[EdgeBase]] = {
    "EXECUTES": ExecutesEdge,
    "ACCESSES": AccessesEdge,
    "ESCALATES": EscalatesEdge,
    "COMMUNICATES": CommunicatesEdge,
    "OBSERVES": ObservesEdge,
    "HYPOTHESIZES": HypothesizesEdge,
    "DEBATES": DebatesEdge,
    "CHALLENGES": ChallengesEdge,
    "SYNTHESIZES": SynthesizesEdge,
    "DETECTS": DetectsEdge,
}
