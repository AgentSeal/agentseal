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

from agentseal.guard_models import (
    DeltaEntry,
    DeltaResult,
    GuardReport,
    MCPServerResult,
    SkillResult,
)

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


def normalize_skill_path(path: str, *, scan_path: Optional[str] = None) -> str:
    """Normalize a skill path for consistent matching across scans.

    - Home dir prefix -> ~/
    - Relative to scan_path if set
    - Fallback: last two path segments
    """
    home = str(Path.home())
    if path.startswith(home + "/"):
        return "~/" + path[len(home) + 1:]
    if scan_path:
        resolved_scan = str(Path(scan_path).resolve())
        if path.startswith(resolved_scan + "/"):
            return path[len(resolved_scan) + 1:]
    # Fallback: last two segments
    parts = [p for p in path.rstrip("/").split("/") if p]
    if len(parts) >= 2:
        return "/".join(parts[-2:])
    return parts[-1] if parts else path


def compute_delta(
    current: GuardReport,
    previous: GuardReport,
    *,
    scan_path: Optional[str] = None,
) -> DeltaResult:
    """Compute the delta between two guard scans.

    Compares skills (by normalized path), MCP servers (by name+source_file),
    and agents (by agent_type, new/removed only).
    """
    entries: list[DeltaEntry] = []

    # -- Skills --
    def _skill_key(sr: SkillResult) -> str:
        return normalize_skill_path(sr.path, scan_path=scan_path)

    curr_skills = {_skill_key(s): s for s in current.skill_results}
    prev_skills = {_skill_key(s): s for s in previous.skill_results}

    for key, curr_s in curr_skills.items():
        prev_s = prev_skills.get(key)
        if prev_s is None:
            entries.append(DeltaEntry(
                change_type="new_entity", entity_type="skill",
                entity_name=key, title=curr_s.name,
            ))
            continue
        # Finding-level diff (by code)
        curr_codes = {f.code for f in curr_s.findings}
        prev_codes = {f.code for f in prev_s.findings}
        has_finding_diff = bool(curr_codes ^ prev_codes)
        for code in curr_codes - prev_codes:
            f = next(f for f in curr_s.findings if f.code == code)
            entries.append(DeltaEntry(
                change_type="new", entity_type="skill",
                entity_name=key, code=code, title=f.title, severity=f.severity,
            ))
        for code in prev_codes - curr_codes:
            f = next(f for f in prev_s.findings if f.code == code)
            entries.append(DeltaEntry(
                change_type="resolved", entity_type="skill",
                entity_name=key, code=code, title=f.title, severity=f.severity,
            ))
        # Verdict change (only if no finding-level diffs explain the change)
        if curr_s.verdict != prev_s.verdict and not has_finding_diff:
            entries.append(DeltaEntry(
                change_type="changed", entity_type="skill",
                entity_name=key,
                old_verdict=prev_s.verdict.value,
                new_verdict=curr_s.verdict.value,
            ))

    for key in prev_skills:
        if key not in curr_skills:
            entries.append(DeltaEntry(
                change_type="removed_entity", entity_type="skill",
                entity_name=key, title=prev_skills[key].name,
            ))

    # -- MCP servers (matched by name + normalized source_file) --
    def _mcp_key(mr: MCPServerResult) -> str:
        normalized_sf = normalize_skill_path(mr.source_file, scan_path=scan_path)
        return f"{mr.name}:{normalized_sf}"

    curr_mcps = {_mcp_key(m): m for m in current.mcp_results}
    prev_mcps = {_mcp_key(m): m for m in previous.mcp_results}

    for key, curr_m in curr_mcps.items():
        prev_m = prev_mcps.get(key)
        if prev_m is None:
            entries.append(DeltaEntry(
                change_type="new_entity", entity_type="mcp",
                entity_name=curr_m.name, title=curr_m.name,
            ))
            continue
        curr_codes = {f.code for f in curr_m.findings}
        prev_codes = {f.code for f in prev_m.findings}
        has_finding_diff = bool(curr_codes ^ prev_codes)
        for code in curr_codes - prev_codes:
            f = next(f for f in curr_m.findings if f.code == code)
            entries.append(DeltaEntry(
                change_type="new", entity_type="mcp",
                entity_name=curr_m.name, code=code, title=f.title, severity=f.severity,
            ))
        for code in prev_codes - curr_codes:
            f = next(f for f in prev_m.findings if f.code == code)
            entries.append(DeltaEntry(
                change_type="resolved", entity_type="mcp",
                entity_name=curr_m.name, code=code, title=f.title, severity=f.severity,
            ))
        if curr_m.verdict != prev_m.verdict and not has_finding_diff:
            entries.append(DeltaEntry(
                change_type="changed", entity_type="mcp",
                entity_name=curr_m.name,
                old_verdict=prev_m.verdict.value,
                new_verdict=curr_m.verdict.value,
            ))

    for key in prev_mcps:
        if key not in curr_mcps:
            entries.append(DeltaEntry(
                change_type="removed_entity", entity_type="mcp",
                entity_name=prev_mcps[key].name, title=prev_mcps[key].name,
            ))

    # -- Agents (new/removed only, no verdict) --
    curr_agents = {
        a.agent_type for a in current.agents_found
        if a.status in ("found", "installed_no_config")
    }
    prev_agents = {
        a.agent_type for a in previous.agents_found
        if a.status in ("found", "installed_no_config")
    }
    for at in curr_agents - prev_agents:
        entries.append(DeltaEntry(
            change_type="new_entity", entity_type="agent",
            entity_name=at, title="new agent detected",
        ))
    for at in prev_agents - curr_agents:
        entries.append(DeltaEntry(
            change_type="removed_entity", entity_type="agent",
            entity_name=at, title="agent no longer detected",
        ))

    return DeltaResult(
        previous_timestamp=previous.timestamp,
        entries=entries,
    )
