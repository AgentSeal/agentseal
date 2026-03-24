"""
SQLite-backed scan history for delta/diff scanning.

Stores guard scan results and provides comparison against previous scans.
Scoped by scan_path so different scan contexts never cross-compare.
"""

import json
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from agentseal.guard_models import GuardReport

_DEFAULT_DB = Path.home() / ".agentseal" / "history.db"
_RETENTION_DAYS = 90
_MAX_ROWS = 1000

_SCHEMA = """
CREATE TABLE IF NOT EXISTS guard_scans (
    id INTEGER PRIMARY KEY,
    timestamp TEXT NOT NULL,
    scan_path TEXT,
    report_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scope ON guard_scans(scan_path, timestamp);
"""


class HistoryStore:
    """SQLite store for guard scan history."""

    def __init__(
        self,
        db_path: Optional[Path] = None,
        max_rows: int = _MAX_ROWS,
        retention_days: int = _RETENTION_DAYS,
    ):
        self._db_path = db_path or _DEFAULT_DB
        self._max_rows = max_rows
        self._retention_days = retention_days
        self._conn: Optional[sqlite3.Connection] = None

    def _connect(self) -> sqlite3.Connection:
        if self._conn is None:
            self._db_path.parent.mkdir(parents=True, exist_ok=True)
            try:
                self._conn = sqlite3.connect(str(self._db_path))
                self._conn.executescript(_SCHEMA)
            except sqlite3.Error as e:
                print(f"Warning: cannot open history DB: {e}", file=sys.stderr)
                raise
        return self._conn

    def _normalize_path(self, scan_path: Optional[str]) -> Optional[str]:
        if scan_path is None:
            return None
        return str(Path(scan_path).resolve())

    def save(self, report: GuardReport, *, scan_path: Optional[str]) -> None:
        """Save a guard report to history."""
        scan_path = self._normalize_path(scan_path)
        try:
            conn = self._connect()
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                "INSERT INTO guard_scans (timestamp, scan_path, report_json) VALUES (?, ?, ?)",
                (report.timestamp, scan_path, json.dumps(report.to_dict())),
            )
            conn.commit()
        except sqlite3.Error as e:
            print(f"Warning: cannot save to history: {e}", file=sys.stderr)
            if self._conn:
                try:
                    self._conn.rollback()
                except sqlite3.Error:
                    pass

    def load_previous(self, *, scan_path: Optional[str]) -> Optional[GuardReport]:
        """Load the second-most-recent scan for the given scope.

        Returns None if there is no previous scan (0 or 1 scans in scope).
        """
        scan_path = self._normalize_path(scan_path)
        try:
            conn = self._connect()
            if scan_path is None:
                row = conn.execute(
                    "SELECT report_json FROM guard_scans "
                    "WHERE scan_path IS NULL "
                    "ORDER BY timestamp DESC LIMIT 1 OFFSET 1",
                ).fetchone()
            else:
                row = conn.execute(
                    "SELECT report_json FROM guard_scans "
                    "WHERE scan_path = ? "
                    "ORDER BY timestamp DESC LIMIT 1 OFFSET 1",
                    (scan_path,),
                ).fetchone()
            if row is None:
                return None
            return GuardReport.from_dict(json.loads(row[0]))
        except (sqlite3.Error, json.JSONDecodeError, KeyError, TypeError) as e:
            print(f"Warning: cannot load previous scan: {e}", file=sys.stderr)
            return None

    def prune(self) -> None:
        """Remove scans older than retention period and enforce row cap."""
        try:
            conn = self._connect()
            cutoff = (
                datetime.now(timezone.utc) - timedelta(days=self._retention_days)
            ).isoformat()
            conn.execute("DELETE FROM guard_scans WHERE timestamp < ?", (cutoff,))
            conn.execute(
                "DELETE FROM guard_scans WHERE id NOT IN "
                "(SELECT id FROM guard_scans ORDER BY timestamp DESC LIMIT ?)",
                (self._max_rows,),
            )
            conn.commit()
        except sqlite3.Error as e:
            print(f"Warning: cannot prune history: {e}", file=sys.stderr)

    def _count(self) -> int:
        """Return total row count (for testing)."""
        conn = self._connect()
        row = conn.execute("SELECT COUNT(*) FROM guard_scans").fetchone()
        return row[0] if row else 0

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None
