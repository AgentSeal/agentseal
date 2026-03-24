from datetime import datetime, timedelta, timezone

from agentseal.guard_models import (
    AgentConfigResult,
    GuardReport,
    GuardVerdict,
    MCPServerResult,
    SkillFinding,
    SkillResult,
)
from agentseal.history import HistoryStore, compute_delta, normalize_skill_path


class TestHistoryStore:
    def _minimal_report(self, ts="2026-03-23T10:00:00Z"):
        return GuardReport(
            timestamp=ts, duration_seconds=1.0,
            agents_found=[], skill_results=[], mcp_results=[],
        )

    def test_save_and_load_previous(self, tmp_path):
        db = tmp_path / "test.db"
        store = HistoryStore(db)
        r1 = self._minimal_report("2026-03-23T10:00:00Z")
        r2 = self._minimal_report("2026-03-23T11:00:00Z")
        store.save(r1, scan_path=None)
        store.save(r2, scan_path=None)
        prev = store.load_previous(scan_path=None)
        assert prev is not None
        assert prev.timestamp == "2026-03-23T10:00:00Z"

    def test_load_previous_no_history(self, tmp_path):
        db = tmp_path / "test.db"
        store = HistoryStore(db)
        prev = store.load_previous(scan_path=None)
        assert prev is None

    def test_load_previous_single_scan(self, tmp_path):
        db = tmp_path / "test.db"
        store = HistoryStore(db)
        store.save(self._minimal_report(), scan_path=None)
        prev = store.load_previous(scan_path=None)
        assert prev is None  # only one scan, no "previous"

    def test_scope_isolation(self, tmp_path):
        db = tmp_path / "test.db"
        store = HistoryStore(db)
        store.save(self._minimal_report("2026-03-23T09:00:00Z"), scan_path=None)
        store.save(self._minimal_report("2026-03-23T10:00:00Z"), scan_path="/project-a")
        store.save(self._minimal_report("2026-03-23T11:00:00Z"), scan_path="/project-a")
        prev = store.load_previous(scan_path="/project-a")
        assert prev is not None
        assert prev.timestamp == "2026-03-23T10:00:00Z"
        prev_null = store.load_previous(scan_path=None)
        assert prev_null is None

    def test_prune_by_age(self, tmp_path):
        db = tmp_path / "test.db"
        store = HistoryStore(db)
        old_ts = (datetime.now(timezone.utc) - timedelta(days=100)).isoformat()
        new_ts = datetime.now(timezone.utc).isoformat()
        store.save(self._minimal_report(old_ts), scan_path=None)
        store.save(self._minimal_report(new_ts), scan_path=None)
        store.prune()
        count = store._count()
        assert count == 1

    def test_prune_by_count(self, tmp_path):
        db = tmp_path / "test.db"
        store = HistoryStore(db, max_rows=5)
        for i in range(10):
            ts = f"2026-03-{i+10:02d}T10:00:00Z"
            store.save(self._minimal_report(ts), scan_path=None)
        store.prune()
        count = store._count()
        assert count == 5

    def test_db_created_on_first_save(self, tmp_path):
        db = tmp_path / "subdir" / "test.db"
        assert not db.exists()
        store = HistoryStore(db)
        store.save(self._minimal_report(), scan_path=None)
        assert db.exists()

    def test_scan_path_normalized(self, tmp_path):
        db = tmp_path / "test.db"
        store = HistoryStore(db)
        store.save(self._minimal_report("2026-03-23T09:00:00Z"),
                   scan_path=str(tmp_path / "project"))
        store.save(self._minimal_report("2026-03-23T10:00:00Z"),
                   scan_path=str(tmp_path / "project"))
        prev = store.load_previous(scan_path=str(tmp_path / "project"))
        assert prev is not None


class TestNormalizeSkillPath:
    def test_home_prefix(self):
        import os
        home = os.path.expanduser("~")
        result = normalize_skill_path(f"{home}/projects/CLAUDE.md", scan_path=None)
        assert result == "~/projects/CLAUDE.md"

    def test_relative_to_scan_root(self):
        result = normalize_skill_path("/a/b/c/CLAUDE.md", scan_path="/a/b")
        assert result == "c/CLAUDE.md"

    def test_fallback_last_two_segments(self):
        result = normalize_skill_path("/unrelated/deep/path/sub/file.md", scan_path="/other")
        assert result == "sub/file.md"

    def test_single_segment(self):
        result = normalize_skill_path("/CLAUDE.md", scan_path=None)
        assert result == "CLAUDE.md"


class TestComputeDelta:
    def _report(self, ts, skills=None, mcps=None, agents=None):
        return GuardReport(
            timestamp=ts, duration_seconds=1.0,
            agents_found=agents or [],
            skill_results=skills or [],
            mcp_results=mcps or [],
        )

    def test_new_finding(self):
        prev = self._report("T1", skills=[
            SkillResult("CLAUDE.md", "~/CLAUDE.md", GuardVerdict.SAFE),
        ])
        curr = self._report("T2", skills=[
            SkillResult("CLAUDE.md", "~/CLAUDE.md", GuardVerdict.WARNING,
                [SkillFinding("SKILL-001", "Cred theft", "D", "high", "E", "R")]),
        ])
        delta = compute_delta(curr, prev)
        assert delta.total_new == 1
        assert delta.entries[0].code == "SKILL-001"
        assert delta.entries[0].change_type == "new"

    def test_resolved_finding(self):
        prev = self._report("T1", skills=[
            SkillResult("CLAUDE.md", "~/CLAUDE.md", GuardVerdict.WARNING,
                [SkillFinding("SKILL-001", "T", "D", "high", "E", "R")]),
        ])
        curr = self._report("T2", skills=[
            SkillResult("CLAUDE.md", "~/CLAUDE.md", GuardVerdict.SAFE),
        ])
        delta = compute_delta(curr, prev)
        assert delta.total_resolved == 1
        assert delta.entries[0].change_type == "resolved"

    def test_verdict_changed(self):
        prev = self._report("T1", skills=[
            SkillResult("CLAUDE.md", "~/CLAUDE.md", GuardVerdict.WARNING),
        ])
        curr = self._report("T2", skills=[
            SkillResult("CLAUDE.md", "~/CLAUDE.md", GuardVerdict.DANGER),
        ])
        delta = compute_delta(curr, prev)
        assert delta.total_changed == 1
        assert delta.entries[0].old_verdict == "warning"
        assert delta.entries[0].new_verdict == "danger"

    def test_new_entity(self):
        prev = self._report("T1")
        curr = self._report("T2", skills=[
            SkillResult("CLAUDE.md", "~/CLAUDE.md", GuardVerdict.SAFE),
        ])
        delta = compute_delta(curr, prev)
        assert delta.total_new == 1
        assert delta.entries[0].change_type == "new_entity"

    def test_removed_entity(self):
        prev = self._report("T1", skills=[
            SkillResult("CLAUDE.md", "~/CLAUDE.md", GuardVerdict.SAFE),
        ])
        curr = self._report("T2")
        delta = compute_delta(curr, prev)
        assert delta.total_resolved == 1
        assert delta.entries[0].change_type == "removed_entity"

    def test_new_agent(self):
        prev = self._report("T1")
        curr = self._report("T2", agents=[
            AgentConfigResult("Cursor", "/f", "cursor", 1, 0, "found"),
        ])
        delta = compute_delta(curr, prev)
        assert delta.total_new == 1
        assert delta.entries[0].entity_type == "agent"
        assert delta.entries[0].change_type == "new_entity"

    def test_removed_agent(self):
        prev = self._report("T1", agents=[
            AgentConfigResult("Cursor", "/f", "cursor", 1, 0, "found"),
        ])
        curr = self._report("T2")
        delta = compute_delta(curr, prev)
        assert delta.total_resolved == 1
        assert delta.entries[0].entity_type == "agent"

    def test_mcp_matched_by_name_and_source(self):
        prev = self._report("T1", mcps=[
            MCPServerResult("filesystem", "npx old", "/f/mcp.json", GuardVerdict.SAFE),
        ])
        curr = self._report("T2", mcps=[
            MCPServerResult("filesystem", "npx new", "/f/mcp.json", GuardVerdict.SAFE),
        ])
        delta = compute_delta(curr, prev)
        # Same name+source_file = same entity, no delta
        assert len(delta.entries) == 0

    def test_no_changes(self):
        r = self._report("T1", skills=[
            SkillResult("CLAUDE.md", "~/CLAUDE.md", GuardVerdict.SAFE),
        ])
        delta = compute_delta(r, r)
        assert len(delta.entries) == 0

    def test_not_installed_agents_skipped(self):
        prev = self._report("T1")
        curr = self._report("T2", agents=[
            AgentConfigResult("W", "/f", "windsurf", 0, 0, "not_installed"),
        ])
        delta = compute_delta(curr, prev)
        assert len(delta.entries) == 0
