"""
Role-Based Access Control (RBAC)
==================================
Manages users, roles, and permissions for multi-user ForgeLens deployments.

Roles:
    admin       — full access to all operations
    examiner    — can acquire, analyze, and report
    analyst     — read-only access to evidence and reports
    viewer      — read-only access to cases and reports

Usage:
    from core.remote.rbac import RBACManager, Role

    mgr = RBACManager()
    mgr.create_user("alice", Role.EXAMINER, password="secure123")
    token = mgr.authenticate("alice", "secure123")
    mgr.require_permission(token, "acquire")
"""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

from loguru import logger

from core.config import settings


class Role(str, Enum):
    ADMIN = "admin"
    EXAMINER = "examiner"
    ANALYST = "analyst"
    VIEWER = "viewer"


# Permission matrix
ROLE_PERMISSIONS: dict[Role, set[str]] = {
    Role.ADMIN: {
        "acquire",
        "image",
        "analyze",
        "report",
        "export",
        "manage_cases",
        "manage_users",
        "delete_evidence",
        "encrypt",
        "remote_agent",
        "memory",
        "view",
    },
    Role.EXAMINER: {
        "acquire",
        "image",
        "analyze",
        "report",
        "export",
        "manage_cases",
        "encrypt",
        "remote_agent",
        "memory",
        "view",
    },
    Role.ANALYST: {
        "analyze",
        "report",
        "export",
        "view",
    },
    Role.VIEWER: {
        "view",
    },
}


@dataclass
class User:
    username: str
    role: Role
    created_at: str = ""
    last_login: str = ""
    is_active: bool = True
    email: str = ""
    full_name: str = ""
    # Never stored in plain text
    _password_hash: str = field(default="", repr=False)
    _salt: str = field(default="", repr=False)

    def to_dict(self) -> dict:
        d = asdict(self)
        d.pop("_password_hash", None)
        d.pop("_salt", None)
        return d

    @property
    def permissions(self) -> set[str]:
        return ROLE_PERMISSIONS.get(self.role, set())

    def has_permission(self, permission: str) -> bool:
        return permission in self.permissions


@dataclass
class Session:
    token: str
    username: str
    role: Role
    created_at: float = field(default_factory=time.time)
    expires_at: float = 0.0
    ip_address: str = ""

    @property
    def is_expired(self) -> bool:
        return self.expires_at > 0 and time.time() > self.expires_at

    @property
    def is_valid(self) -> bool:
        return not self.is_expired


class RBACManager:
    """
    Manages users, roles, sessions, and permission checks.
    Stores user data in a JSON file (production should use a proper DB).
    """

    USERS_FILE = "users.json"
    SESSION_TTL = 8 * 3600  # 8 hours

    def __init__(self, base_path: Path | None = None) -> None:
        self.base_path = Path(base_path or settings.evidence.base_path)
        self.base_path.mkdir(parents=True, exist_ok=True)
        self._users_path = self.base_path / self.USERS_FILE
        self._users: dict[str, dict] = self._load_users()
        self._sessions: dict[str, Session] = {}

    # ── User management ───────────────────────────────────────────────────────

    def _load_users(self) -> dict[str, dict]:
        if self._users_path.exists():
            try:
                return json.loads(self._users_path.read_text(encoding="utf-8"))
            except Exception as exc:
                logger.error("Failed to load users: {}", exc)
        return {}

    def _save_users(self) -> None:
        self._users_path.write_text(
            json.dumps(self._users, indent=2, default=str),
            encoding="utf-8",
        )

    @staticmethod
    def _hash_password(password: str, salt: str) -> str:
        """Hash a password with PBKDF2-HMAC-SHA256."""
        return hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt.encode("utf-8"),
            iterations=600_000,
        ).hex()

    def create_user(
        self,
        username: str,
        role: Role,
        password: str,
        email: str = "",
        full_name: str = "",
    ) -> User:
        """Create a new user with a hashed password."""
        if username in self._users:
            raise ValueError(f"User '{username}' already exists")

        salt = secrets.token_hex(32)
        password_hash = self._hash_password(password, salt)
        now = datetime.now(timezone.utc).isoformat()

        user_data = {
            "username": username,
            "role": role.value,
            "created_at": now,
            "last_login": "",
            "is_active": True,
            "email": email,
            "full_name": full_name,
            "_password_hash": password_hash,
            "_salt": salt,
        }
        self._users[username] = user_data
        self._save_users()

        logger.info("User created | username={} | role={}", username, role.value)
        return User(username=username, role=role, created_at=now, email=email, full_name=full_name)

    def get_user(self, username: str) -> User | None:
        """Retrieve a user by username."""
        data = self._users.get(username)
        if not data:
            return None
        return User(
            username=data["username"],
            role=Role(data["role"]),
            created_at=data.get("created_at", ""),
            last_login=data.get("last_login", ""),
            is_active=data.get("is_active", True),
            email=data.get("email", ""),
            full_name=data.get("full_name", ""),
            _password_hash=data.get("_password_hash", ""),
            _salt=data.get("_salt", ""),
        )

    def update_role(self, username: str, new_role: Role) -> bool:
        """Change a user's role."""
        if username not in self._users:
            return False
        self._users[username]["role"] = new_role.value
        self._save_users()
        logger.info("Role updated | username={} | role={}", username, new_role.value)
        return True

    def deactivate_user(self, username: str) -> bool:
        """Deactivate a user account."""
        if username not in self._users:
            return False
        self._users[username]["is_active"] = False
        self._save_users()
        logger.info("User deactivated: {}", username)
        return True

    def list_users(self) -> list[User]:
        """Return all users."""
        return [self.get_user(u) for u in self._users if self.get_user(u)]

    # ── Authentication ────────────────────────────────────────────────────────

    def authenticate(self, username: str, password: str, ip_address: str = "") -> str | None:
        """
        Authenticate a user and return a session token.
        Returns None if authentication fails.
        """
        user = self.get_user(username)
        if not user or not user.is_active:
            logger.warning("Auth failed: user not found or inactive | username={}", username)
            return None

        expected = self._hash_password(password, user._salt)
        if not secrets.compare_digest(expected, user._password_hash):
            logger.warning("Auth failed: wrong password | username={}", username)
            return None

        # Create session
        token = secrets.token_urlsafe(32)
        session = Session(
            token=token,
            username=username,
            role=user.role,
            created_at=time.time(),
            expires_at=time.time() + self.SESSION_TTL,
            ip_address=ip_address,
        )
        self._sessions[token] = session

        # Update last login
        self._users[username]["last_login"] = datetime.now(timezone.utc).isoformat()
        self._save_users()

        logger.info("Auth success | username={} | role={}", username, user.role.value)
        return token

    def validate_token(self, token: str) -> Session | None:
        """Validate a session token and return the session if valid."""
        session = self._sessions.get(token)
        if not session or session.is_expired:
            if session:
                del self._sessions[token]
            return None
        return session

    def logout(self, token: str) -> None:
        """Invalidate a session token."""
        self._sessions.pop(token, None)

    # ── Permission checks ─────────────────────────────────────────────────────

    def require_permission(self, token: str, permission: str) -> Session:
        """
        Validate token and check permission.
        Raises PermissionError if not authorized.
        """
        session = self.validate_token(token)
        if not session:
            raise PermissionError("Invalid or expired session token")

        perms = ROLE_PERMISSIONS.get(session.role, set())
        if permission not in perms:
            raise PermissionError(
                f"Role '{session.role.value}' does not have permission: {permission}"
            )
        return session

    def check_permission(self, token: str, permission: str) -> bool:
        """Check permission without raising — returns True/False."""
        try:
            self.require_permission(token, permission)
            return True
        except PermissionError:
            return False

    def get_active_sessions(self) -> list[Session]:
        """Return all active (non-expired) sessions."""
        active = [s for s in self._sessions.values() if s.is_valid]
        # Clean up expired
        expired = [t for t, s in self._sessions.items() if s.is_expired]
        for t in expired:
            del self._sessions[t]
        return active
