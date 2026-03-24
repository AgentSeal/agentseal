from datetime import datetime, timedelta, timezone

from agentseal.guard_models import GuardReport
from agentseal.history import HistoryStore


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
