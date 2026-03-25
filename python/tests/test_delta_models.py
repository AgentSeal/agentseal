from agentseal.guard_models import DeltaEntry, DeltaResult


class TestDeltaEntry:
    def test_to_dict(self):
        e = DeltaEntry(
            change_type="new", entity_type="skill",
            entity_name=".cursorrules", code="SKILL-001",
            title="Cred theft", severity="critical",
        )
        d = e.to_dict()
        assert d["change_type"] == "new"
        assert d["entity_name"] == ".cursorrules"
        assert d["code"] == "SKILL-001"

    def test_defaults(self):
        e = DeltaEntry(change_type="new_entity", entity_type="agent", entity_name="cursor")
        assert e.code == ""
        assert e.severity == ""
        assert e.old_verdict == ""
        assert e.new_verdict == ""


class TestDeltaResult:
    def test_counts_from_entries(self):
        entries = [
            DeltaEntry("new", "skill", "a", code="SKILL-001"),
            DeltaEntry("new_entity", "agent", "cursor"),
            DeltaEntry("resolved", "mcp", "fs", code="MCP-007"),
            DeltaEntry("removed_entity", "agent", "windsurf"),
            DeltaEntry("changed", "skill", "b", old_verdict="warning", new_verdict="safe"),
        ]
        dr = DeltaResult(previous_timestamp="2026-03-22T10:00:00Z", entries=entries)
        assert dr.total_new == 2       # new + new_entity
        assert dr.total_resolved == 2  # resolved + removed_entity
        assert dr.total_changed == 1

    def test_empty(self):
        dr = DeltaResult(previous_timestamp="T", entries=[])
        assert dr.total_new == 0
        assert dr.total_resolved == 0
        assert dr.total_changed == 0

    def test_to_dict(self):
        dr = DeltaResult(
            previous_timestamp="2026-03-22T10:00:00Z",
            entries=[DeltaEntry("new", "skill", "x", code="SKILL-001")],
        )
        d = dr.to_dict()
        assert d["previous_timestamp"] == "2026-03-22T10:00:00Z"
        assert len(d["entries"]) == 1
        assert d["total_new"] == 1
