"""
SQLite Artifact Parser Engine
================================
Parses SQLite databases from mobile apps, browsers, and OS artifacts.
Supports schema discovery, table enumeration, and targeted queries.

Usage:
    from core.artifacts.sqlite_parser import SQLiteParser

    parser = SQLiteParser("/evidence/mmssms.db")
    tables = parser.list_tables()
    sms = parser.query("SELECT address, body, date FROM sms ORDER BY date DESC LIMIT 100")
    parser.export_all_tables("/evidence/exports/")
"""

from __future__ import annotations

import json
import shutil
import sqlite3
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from loguru import logger


@dataclass
class TableInfo:
    name: str
    row_count: int = 0
    columns: list[str] = field(default_factory=list)
    sample_rows: list[dict] = field(default_factory=list)


@dataclass
class QueryResult:
    query: str
    columns: list[str] = field(default_factory=list)
    rows: list[dict] = field(default_factory=list)
    row_count: int = 0
    error: str = ""

    @property
    def success(self) -> bool:
        return self.error == ""


class SQLiteParser:
    """
    Forensic SQLite database parser.
    Copies the database to a temp file before opening (handles locked files).
    """

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        self._tmp: Path | None = None
        self._conn: sqlite3.Connection | None = None

    def open(self) -> bool:
        """Open the database (copies to temp file first)."""
        if not self.db_path.exists():
            logger.error("Database not found: {}", self.db_path)
            return False
        try:
            self._tmp = Path(tempfile.mktemp(suffix=".db"))
            shutil.copy2(self.db_path, self._tmp)
            self._conn = sqlite3.connect(str(self._tmp))
            self._conn.row_factory = sqlite3.Row
            logger.debug("SQLite opened: {}", self.db_path.name)
            return True
        except Exception as exc:
            logger.error("SQLite open error {}: {}", self.db_path, exc)
            return False

    def close(self) -> None:
        """Close the database and clean up temp file."""
        if self._conn:
            self._conn.close()
            self._conn = None
        if self._tmp:
            self._tmp.unlink(missing_ok=True)
            self._tmp = None

    def __enter__(self) -> SQLiteParser:
        self.open()
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    # ── Schema discovery ──────────────────────────────────────────────────────

    def list_tables(self) -> list[str]:
        """Return all table names in the database."""
        if not self._conn and not self.open():
            return []
        try:
            cursor = self._conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            )
            return [row[0] for row in cursor.fetchall()]
        except Exception as exc:
            logger.error("list_tables error: {}", exc)
            return []

    def describe_table(self, table: str, sample_size: int = 3) -> TableInfo:
        """Get column info and sample rows for a table."""
        info = TableInfo(name=table)
        if not self._conn and not self.open():
            return info
        try:
            # Columns
            cursor = self._conn.execute(f"PRAGMA table_info({table})")  # noqa: S608
            info.columns = [row[1] for row in cursor.fetchall()]

            # Row count
            cursor = self._conn.execute(f"SELECT COUNT(*) FROM {table}")  # noqa: S608
            info.row_count = cursor.fetchone()[0]

            # Sample rows
            cursor = self._conn.execute(f"SELECT * FROM {table} LIMIT {sample_size}")  # noqa: S608
            info.sample_rows = [dict(row) for row in cursor.fetchall()]

        except Exception as exc:
            logger.debug("describe_table error {}: {}", table, exc)
        return info

    def get_schema(self) -> dict[str, TableInfo]:
        """Return full schema: all tables with column info and row counts."""
        schema: dict[str, TableInfo] = {}
        for table in self.list_tables():
            schema[table] = self.describe_table(table)
        return schema

    # ── Querying ──────────────────────────────────────────────────────────────

    def query(self, sql: str, params: tuple = ()) -> QueryResult:
        """
        Execute a SELECT query and return results.

        Args:
            sql:    SQL SELECT statement.
            params: Query parameters (for parameterized queries).

        Returns:
            QueryResult with columns and rows.
        """
        result = QueryResult(query=sql)
        if not self._conn and not self.open():
            result.error = f"Cannot open {self.db_path}"
            return result
        try:
            cursor = self._conn.execute(sql, params)
            result.columns = [desc[0] for desc in cursor.description or []]
            rows = cursor.fetchall()
            result.rows = [dict(row) for row in rows]
            result.row_count = len(result.rows)
        except Exception as exc:
            result.error = str(exc)
            logger.debug("SQLite query error: {} | {}", exc, sql[:100])
        return result

    def query_table(self, table: str, limit: int = 1000, order_by: str = "") -> QueryResult:
        """Query all rows from a table with optional ordering."""
        order = f" ORDER BY {order_by}" if order_by else ""
        return self.query(f"SELECT * FROM {table}{order} LIMIT {limit}")  # noqa: S608

    # ── Export ────────────────────────────────────────────────────────────────

    def export_table_json(self, table: str, output_path: Path, limit: int = 10000) -> bool:
        """Export a table to JSON."""
        result = self.query_table(table, limit=limit)
        if not result.success:
            return False
        output_path.write_text(
            json.dumps({"table": table, "rows": result.rows}, indent=2, default=str),
            encoding="utf-8",
        )
        return True

    def export_all_tables(
        self, output_dir: str | Path, limit_per_table: int = 10000
    ) -> dict[str, Path]:
        """Export all tables to individual JSON files."""
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        exported: dict[str, Path] = {}

        for table in self.list_tables():
            path = out / f"{table}.json"
            if self.export_table_json(table, path, limit=limit_per_table):
                exported[table] = path
                logger.debug("Exported table: {} -> {}", table, path)

        logger.info("SQLite export: {} table(s) from {}", len(exported), self.db_path.name)
        return exported

    # ── Forensic helpers ──────────────────────────────────────────────────────

    def recover_deleted_rows(self) -> QueryResult:
        """
        Attempt to recover deleted rows via sqlite_sequence and freelist analysis.
        Note: Full carving requires offline tools (sqlite-dissect, etc.)
        """
        # Check for sqlite_sequence (auto-increment tables)
        tables = self.list_tables()
        if "sqlite_sequence" in tables:
            return self.query("SELECT * FROM sqlite_sequence")
        return QueryResult(
            query="recover_deleted",
            error="No sqlite_sequence table — use offline carving tools for full recovery",
        )

    @staticmethod
    def is_sqlite(path: Path) -> bool:
        """Check if a file is a SQLite database by magic bytes."""
        try:
            with open(path, "rb") as f:
                return f.read(16) == b"SQLite format 3\x00"
        except Exception:
            return False

    @staticmethod
    def find_sqlite_files(directory: Path, recursive: bool = True) -> list[Path]:
        """Find all SQLite databases in a directory."""
        found: list[Path] = []
        pattern = "**/*" if recursive else "*"
        for path in directory.glob(pattern):
            if path.is_file() and SQLiteParser.is_sqlite(path):
                found.append(path)
        logger.info("Found {} SQLite database(s) in {}", len(found), directory)
        return found
