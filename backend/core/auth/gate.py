"""
ForgeLens Authentication Gate
================================
Controls access to the entire CLI. When auth is enabled, users must
log in before any command runs. Sessions are persisted locally so
you only authenticate once per session (configurable TTL).

Security model:
  - Passwords hashed with PBKDF2-HMAC-SHA256, 600,000 iterations
  - Session token stored in a local session file (not in .env or source)
  - Session file is readable only by the current OS user (chmod 600)
  - Failed logins are rate-limited (3 attempts, then 30s lockout)
  - Auth can be disabled for single-analyst offline deployments

Session file location:
  evidence/.session  (inside the evidence vault, never committed)

Usage:
    from core.auth.gate import AuthGate

    gate = AuthGate()
    gate.require()          # prompt for login if no valid session
    gate.whoami()           # return current session info
"""

from __future__ import annotations

import json
import os
import stat
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from loguru import logger

from core.config import settings
from core.remote.rbac import RBACManager, Role

# Session file lives in the evidence vault directory
_SESSION_FILE = Path(settings.evidence.base_path) / ".session"
_LOCKOUT_FILE = Path(settings.evidence.base_path) / ".lockout"

# Auth lock file — if this exists, auth is enabled
_AUTH_ENABLED_FILE = Path(settings.evidence.base_path) / ".auth_enabled"

# Session TTL — default 8 hours
_SESSION_TTL = 8 * 3600

# Brute-force protection
_MAX_ATTEMPTS = 3
_LOCKOUT_SECONDS = 30


@dataclass
class LocalSession:
    username: str
    role: str
    token: str
    created_at: float
    expires_at: float

    @property
    def is_valid(self) -> bool:
        return time.time() < self.expires_at

    @property
    def expires_in_minutes(self) -> int:
        remaining = self.expires_at - time.time()
        return max(0, int(remaining / 60))

    def __str__(self) -> str:
        return (
            f"{self.username} [{self.role}] "
            f"— expires in {self.expires_in_minutes}m"
        )


class AuthGate:
    """
    CLI authentication gate.
    Wraps RBACManager with a local session file for persistent auth.
    """

    def __init__(self) -> None:
        self._rbac = RBACManager()
        _SESSION_FILE.parent.mkdir(parents=True, exist_ok=True)

    # ── Auth state ────────────────────────────────────────────────────────────

    def is_enabled(self) -> bool:
        """Return True if auth is enabled (lock file exists)."""
        return _AUTH_ENABLED_FILE.exists()

    def enable(self) -> None:
        """Enable authentication requirement."""
        _AUTH_ENABLED_FILE.parent.mkdir(parents=True, exist_ok=True)
        _AUTH_ENABLED_FILE.write_text("auth_enabled", encoding="utf-8")
        logger.info("Authentication ENABLED")

    def disable(self, confirm: bool = False) -> None:
        """
        Disable authentication requirement.
        Requires explicit confirm=True — do not expose this lightly.
        """
        if not confirm:
            raise ValueError("disable() requires confirm=True")
        _AUTH_ENABLED_FILE.unlink(missing_ok=True)
        _SESSION_FILE.unlink(missing_ok=True)
        logger.warning("Authentication DISABLED")

    # ── Session management ────────────────────────────────────────────────────

    def _read_session(self) -> LocalSession | None:
        """Read and validate the local session file."""
        if not _SESSION_FILE.exists():
            return None
        try:
            data = json.loads(_SESSION_FILE.read_text(encoding="utf-8"))
            session = LocalSession(
                username=data["username"],
                role=data["role"],
                token=data["token"],
                created_at=float(data["created_at"]),
                expires_at=float(data["expires_at"]),
            )
            if not session.is_valid:
                _SESSION_FILE.unlink(missing_ok=True)
                return None
            # Also validate token with RBACManager
            rbac_session = self._rbac.validate_token(session.token)
            if not rbac_session:
                _SESSION_FILE.unlink(missing_ok=True)
                return None
            return session
        except Exception:
            return None

    def _write_session(self, username: str, role: str, token: str) -> LocalSession:
        """Persist a new session to the local session file."""
        now = time.time()
        session = LocalSession(
            username=username,
            role=role,
            token=token,
            created_at=now,
            expires_at=now + _SESSION_TTL,
        )
        data = {
            "username": session.username,
            "role": session.role,
            "token": session.token,
            "created_at": session.created_at,
            "expires_at": session.expires_at,
        }
        _SESSION_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")
        # Restrict to current user only (unix)
        try:
            os.chmod(_SESSION_FILE, stat.S_IRUSR | stat.S_IWUSR)
        except Exception:
            pass
        return session

    def _clear_session(self) -> None:
        _SESSION_FILE.unlink(missing_ok=True)

    # ── Lockout ───────────────────────────────────────────────────────────────

    def _check_lockout(self) -> tuple[bool, float]:
        """
        Check if the system is in lockout due to failed attempts.
        Returns (locked_out, seconds_remaining).
        """
        if not _LOCKOUT_FILE.exists():
            return False, 0.0
        try:
            data = json.loads(_LOCKOUT_FILE.read_text(encoding="utf-8"))
            attempts = int(data.get("attempts", 0))
            last_attempt = float(data.get("last_attempt", 0))
            if attempts >= _MAX_ATTEMPTS:
                remaining = _LOCKOUT_SECONDS - (time.time() - last_attempt)
                if remaining > 0:
                    return True, remaining
                else:
                    _LOCKOUT_FILE.unlink(missing_ok=True)
        except Exception:
            pass
        return False, 0.0

    def _record_failed_attempt(self) -> int:
        """Record a failed login attempt. Returns total attempts so far."""
        data: dict = {"attempts": 0, "last_attempt": time.time()}
        if _LOCKOUT_FILE.exists():
            try:
                data = json.loads(_LOCKOUT_FILE.read_text(encoding="utf-8"))
            except Exception:
                pass
        data["attempts"] = int(data.get("attempts", 0)) + 1
        data["last_attempt"] = time.time()
        _LOCKOUT_FILE.write_text(json.dumps(data), encoding="utf-8")
        try:
            os.chmod(_LOCKOUT_FILE, stat.S_IRUSR | stat.S_IWUSR)
        except Exception:
            pass
        return data["attempts"]

    def _clear_lockout(self) -> None:
        _LOCKOUT_FILE.unlink(missing_ok=True)

    # ── Core auth flow ────────────────────────────────────────────────────────

    def login(self, username: str, password: str) -> LocalSession | None:
        """
        Authenticate and create a local session.
        Returns LocalSession on success, None on failure.
        """
        locked, remaining = self._check_lockout()
        if locked:
            raise PermissionError(
                f"Too many failed attempts. Wait {int(remaining)}s before trying again."
            )

        token = self._rbac.authenticate(username, password)
        if not token:
            attempts = self._record_failed_attempt()
            remaining_attempts = max(0, _MAX_ATTEMPTS - attempts)
            logger.warning("Login failed | user={} | attempts={}", username, attempts)
            return None

        self._clear_lockout()
        user = self._rbac.get_user(username)
        session = self._write_session(username, user.role.value if user else "viewer", token)
        logger.info("Login success | user={} | role={}", username, session.role)
        return session

    def logout(self) -> None:
        """Log out the current session."""
        session = self._read_session()
        if session:
            self._rbac.logout(session.token)
        self._clear_session()
        logger.info("Logged out")

    def whoami(self) -> LocalSession | None:
        """Return the current session if valid, else None."""
        return self._read_session()

    def require(self) -> LocalSession:
        """
        Enforce authentication. Called before every CLI command.
        If auth is disabled, returns a synthetic admin session.
        If auth is enabled but no valid session exists, prompts for login.
        """
        # Auth disabled — pass through
        if not self.is_enabled():
            return LocalSession(
                username="local",
                role="admin",
                token="",
                created_at=time.time(),
                expires_at=time.time() + 86400,
            )

        # Valid session exists
        session = self._read_session()
        if session:
            return session

        # No valid session — interactive login
        return self._interactive_login()

    def _interactive_login(self) -> LocalSession:
        """
        Prompt the user for credentials interactively.
        Exits the process on failure.
        """
        import getpass

        # Check if there are any users yet
        users = self._rbac.list_users()
        if not users:
            print()
            print("  ForgeLens — First-time setup")
            print("  No users found. Create an admin account to continue.")
            print()
            username = input("  New admin username: ").strip()
            if not username:
                print("  Username cannot be empty.")
                sys.exit(1)
            password = getpass.getpass("  New admin password: ")
            if len(password) < 8:
                print("  Password must be at least 8 characters.")
                sys.exit(1)
            confirm = getpass.getpass("  Confirm password: ")
            if password != confirm:
                print("  Passwords do not match.")
                sys.exit(1)
            self._rbac.create_user(username, Role.ADMIN, password)
            print(f"\n  Admin account '{username}' created.")
            print()
        else:
            print()

        print("  ForgeLens — Authentication Required")
        print()

        locked, remaining = self._check_lockout()
        if locked:
            print(f"  Too many failed attempts. Wait {int(remaining)}s.")
            sys.exit(1)

        username = input("  Username: ").strip()
        password = getpass.getpass("  Password: ")

        session = self.login(username, password)
        if not session:
            locked, _ = self._check_lockout()
            remaining_attempts = _MAX_ATTEMPTS - (
                json.loads(_LOCKOUT_FILE.read_text()).get("attempts", 0)
                if _LOCKOUT_FILE.exists() else 0
            )
            print(f"\n  Invalid credentials. {max(0, remaining_attempts)} attempt(s) remaining.")
            sys.exit(1)

        print(f"\n  Logged in as {session.username} [{session.role}]")
        print(f"  Session valid for {session.expires_in_minutes} minutes.")
        print()
        return session

    # ── User management helpers ───────────────────────────────────────────────

    def create_user(
        self,
        username: str,
        role: Role,
        password: str,
        email: str = "",
        full_name: str = "",
    ) -> None:
        """Create a new user (admin only operation)."""
        self._rbac.create_user(username, role, password, email, full_name)

    def list_users(self):
        return self._rbac.list_users()

    def deactivate_user(self, username: str) -> bool:
        return self._rbac.deactivate_user(username)

    def update_role(self, username: str, role: Role) -> bool:
        return self._rbac.update_role(username, role)

    def change_password(self, username: str, new_password: str) -> bool:
        """Change a user's password."""
        import secrets as _sec
        user_data = self._rbac._users.get(username)
        if not user_data:
            return False
        salt = _sec.token_hex(32)
        pw_hash = RBACManager._hash_password(new_password, salt)
        user_data["_password_hash"] = pw_hash
        user_data["_salt"] = salt
        self._rbac._save_users()
        logger.info("Password changed for {}", username)
        return True


# ── Module-level singleton ────────────────────────────────────────────────────
gate = AuthGate()
