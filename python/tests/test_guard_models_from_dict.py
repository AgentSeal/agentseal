import pytest
from agentseal.guard_models import (
    AgentConfigResult,
    GuardReport,
    GuardVerdict,
    MCPFinding,
    MCPServerResult,
    SkillFinding,
    SkillResult,
)


class TestSkillFindingFromDict:
    def test_roundtrip(self):
        f = SkillFinding(
            code="SKILL-001", title="Cred theft", description="Reads keys",
            severity="critical", evidence="cat ~/.ssh", remediation="Remove it",
        )
        d = f.to_dict()
        f2 = SkillFinding.from_dict(d)
        assert f2.code == "SKILL-001"
        assert f2.severity == "critical"

    def test_missing_fields_defaults(self):
        f = SkillFinding.from_dict({"code": "X", "title": "T"})
        assert f.description == ""
        assert f.severity == ""
        assert f.evidence == ""
        assert f.remediation == ""


class TestSkillResultFromDict:
    def test_roundtrip(self):
        sr = SkillResult(
            name="CLAUDE.md", path="/fake/CLAUDE.md",
            verdict=GuardVerdict.WARNING,
            findings=[SkillFinding("SKILL-001", "T", "D", "high", "E", "R")],
            sha256="abc123",
        )
        d = sr.to_dict()
        sr2 = SkillResult.from_dict(d)
        assert sr2.name == "CLAUDE.md"
        assert sr2.verdict == GuardVerdict.WARNING
        assert len(sr2.findings) == 1
        assert sr2.findings[0].code == "SKILL-001"
        assert sr2.sha256 == "abc123"

    def test_empty_findings(self):
        sr = SkillResult.from_dict({"name": "x", "path": "/x", "verdict": "safe"})
        assert sr.findings == []
        assert sr.verdict == GuardVerdict.SAFE


class TestMCPFindingFromDict:
    def test_roundtrip(self):
        f = MCPFinding(
            code="MCP-007", title="Sensitive path",
            description="Accesses ~/.ssh", severity="high", remediation="Fix",
        )
        f2 = MCPFinding.from_dict(f.to_dict())
        assert f2.code == "MCP-007"


class TestMCPServerResultFromDict:
    def test_roundtrip(self):
        mr = MCPServerResult(
            name="filesystem", command="node", source_file="/f/mcp.json",
            verdict=GuardVerdict.WARNING,
            findings=[MCPFinding("MCP-007", "T", "D", "high", "R")],
        )
        mr2 = MCPServerResult.from_dict(mr.to_dict())
        assert mr2.name == "filesystem"
        assert mr2.verdict == GuardVerdict.WARNING
        assert len(mr2.findings) == 1


class TestAgentConfigResultFromDict:
    def test_roundtrip(self):
        a = AgentConfigResult("Cursor", "/fake", "cursor", 3, 2, "found")
        a2 = AgentConfigResult.from_dict(a.to_dict())
        assert a2.agent_type == "cursor"
        assert a2.mcp_servers == 3
        assert a2.status == "found"


class TestGuardReportFromDict:
    def test_roundtrip_minimal(self):
        r = GuardReport(
            timestamp="2026-03-23T10:00:00Z",
            duration_seconds=1.5,
            agents_found=[],
            skill_results=[],
            mcp_results=[],
        )
        d = r.to_dict()
        r2 = GuardReport.from_dict(d)
        assert r2.timestamp == "2026-03-23T10:00:00Z"
        assert r2.duration_seconds == 1.5
        assert r2.agents_found == []
        assert r2.skill_results == []
        assert r2.mcp_results == []
        assert r2.mcp_runtime_results == []
        assert r2.toxic_flows == []

    def test_roundtrip_with_findings(self):
        r = GuardReport(
            timestamp="2026-03-23T10:00:00Z",
            duration_seconds=2.0,
            agents_found=[AgentConfigResult("C", "/f", "cursor", 1, 0, "found")],
            skill_results=[SkillResult("CLAUDE.md", "/f", GuardVerdict.WARNING,
                [SkillFinding("SKILL-001", "T", "D", "high", "E", "R")])],
            mcp_results=[MCPServerResult("fs", "node", "/f", GuardVerdict.SAFE)],
        )
        d = r.to_dict()
        r2 = GuardReport.from_dict(d)
        assert len(r2.agents_found) == 1
        assert r2.agents_found[0].agent_type == "cursor"
        assert len(r2.skill_results) == 1
        assert r2.skill_results[0].findings[0].code == "SKILL-001"

    def test_missing_optional_fields(self):
        d = {
            "timestamp": "T", "duration_seconds": 0.0,
            "agents_found": [], "skill_results": [], "mcp_results": [],
        }
        r = GuardReport.from_dict(d)
        assert r.mcp_runtime_results == []
        assert r.toxic_flows == []
        assert r.baseline_changes == []
        assert r.llm_tokens_used == 0
        assert r.config_path == ""

    def test_corrupt_data_raises(self):
        with pytest.raises((KeyError, TypeError, ValueError)):
            GuardReport.from_dict("not a dict")
