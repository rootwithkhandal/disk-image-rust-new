"""Remote acquisition — agent, client, RBAC, and evidence sync."""

from core.remote.agent import AgentStatus, AgentTask, AgentTaskResult, RemoteAgent
from core.remote.agent_client import AgentClient, ConnectionInfo
from core.remote.rbac import ROLE_PERMISSIONS, RBACManager, Role, Session, User
from core.remote.sync import EvidenceSync, SyncManifest, SyncResult

__all__ = [
    "RemoteAgent",
    "AgentTask",
    "AgentTaskResult",
    "AgentStatus",
    "AgentClient",
    "ConnectionInfo",
    "RBACManager",
    "Role",
    "User",
    "Session",
    "ROLE_PERMISSIONS",
    "EvidenceSync",
    "SyncResult",
    "SyncManifest",
]
