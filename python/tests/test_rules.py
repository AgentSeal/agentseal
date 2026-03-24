"""Tests for the YAML community rule engine."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest
import yaml
from agentseal.guard_models import CustomFinding
from agentseal.rules import Rule, RuleEngine

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_yaml(path: Path, data: dict) -> Path:
    path.write_text(yaml.dump(data, default_flow_style=False), encoding="utf-8")
    return path


def _minimal_rule(**overrides) -> dict:
    base = {
        "id": "TEST-001",
        "title": "Test rule",
        "description": "A test rule",
        "severity": "high",
        "verdict": "warning",
        "remediation": "Fix it",
        "match": {"type": "mcp", "command": ["*miner*"]},
    }
    base.update(overrides)
    return base


@dataclass
class FakeServer:
    name: str = ""
    command: str = ""
    source_file: str = ""


@dataclass
class FakeSkill:
    name: str = ""
    path: str = ""


@dataclass
class FakeAgent:
    name: str = ""
    agent_type: str = ""
    config_path: str = ""


# ===========================================================================
# 1. TestRuleLoading
# ===========================================================================

class TestRuleLoading:

    def test_load_valid_rule_file(self, tmp_path: Path):
        f = _write_yaml(tmp_path / "rules.yaml", {"rules": [_minimal_rule()]})
        engine = RuleEngine.from_paths([str(f)])
        assert len(engine.rules) == 1
        r = engine.rules[0]
        assert r.id == "TEST-001"
        assert r.title == "Test rule"
        assert r.severity == "high"
        assert r.verdict == "warning"
        assert r.match["type"] == "mcp"
        assert r.source_file == str(f)

    def test_load_directory(self, tmp_path: Path):
        _write_yaml(tmp_path / "a.yaml", {"rules": [_minimal_rule(id="A-001")]})
        _write_yaml(tmp_path / "b.yml", {"rules": [_minimal_rule(id="B-001")]})
        engine = RuleEngine.from_paths([str(tmp_path)])
        assert len(engine.rules) == 2
        ids = {r.id for r in engine.rules}
        assert ids == {"A-001", "B-001"}

    def test_load_invalid_yaml(self, tmp_path: Path):
        bad = tmp_path / "bad.yaml"
        bad.write_text(":\n  - :\n    bad: [", encoding="utf-8")
        with pytest.raises(ValueError, match="Cannot parse"):
            RuleEngine.from_paths([str(bad)])

    def test_load_missing_required_field(self, tmp_path: Path):
        rule = _minimal_rule()
        del rule["severity"]
        f = _write_yaml(tmp_path / "r.yaml", {"rules": [rule]})
        with pytest.raises(ValueError, match="missing required field 'severity'"):
            RuleEngine.from_paths([str(f)])

    def test_load_invalid_severity(self, tmp_path: Path):
        f = _write_yaml(tmp_path / "r.yaml", {"rules": [_minimal_rule(severity="extreme")]})
        with pytest.raises(ValueError, match="invalid severity 'extreme'"):
            RuleEngine.from_paths([str(f)])

    def test_load_invalid_verdict(self, tmp_path: Path):
        f = _write_yaml(tmp_path / "r.yaml", {"rules": [_minimal_rule(verdict="safe")]})
        with pytest.raises(ValueError, match="invalid verdict 'safe'"):
            RuleEngine.from_paths([str(f)])

    def test_load_invalid_type(self, tmp_path: Path):
        rule = _minimal_rule(match={"type": "unknown", "command": ["*"]})
        f = _write_yaml(tmp_path / "r.yaml", {"rules": [rule]})
        with pytest.raises(ValueError, match="invalid match type 'unknown'"):
            RuleEngine.from_paths([str(f)])

    def test_load_duplicate_ids(self, tmp_path: Path):
        _write_yaml(tmp_path / "a.yaml", {"rules": [_minimal_rule(id="DUP-001")]})
        _write_yaml(tmp_path / "b.yaml", {"rules": [_minimal_rule(id="DUP-001")]})
        with pytest.raises(ValueError, match="duplicate rule ID 'DUP-001'"):
            RuleEngine.from_paths([str(tmp_path)])

    def test_load_no_rules_key(self, tmp_path: Path):
        f = _write_yaml(tmp_path / "misc.yaml", {"version": 1, "metadata": "test"})
        engine = RuleEngine.from_paths([str(f)])
        assert len(engine.rules) == 0

    def test_load_nonexistent_path(self):
        engine = RuleEngine.from_paths(["/nonexistent/path/rules.yaml"])
        assert len(engine.rules) == 0


# ===========================================================================
# 2. TestPatternMatching
# ===========================================================================

class TestPatternMatching:

    def _engine_with_rule(self, **match_overrides) -> RuleEngine:
        match = {"type": "mcp"}
        match.update(match_overrides)
        rule = Rule(
            id="PAT-001",
            title="Pattern test",
            description="",
            severity="high",
            verdict="warning",
            remediation="",
            match=match,
            tests=[],
            source_file="<test>",
        )
        return RuleEngine([rule])

    def test_glob_or_logic(self):
        engine = self._engine_with_rule(command=["*miner*", "*xmrig*"])
        rule = engine.rules[0]
        assert engine._match_entity(rule, {"command": "npx xmrig-proxy"})
        assert engine._match_entity(rule, {"command": "crypto-miner-start"})

    def test_glob_and_logic(self):
        engine = self._engine_with_rule(name=["*evil*"], command=["*npx*"])
        rule = engine.rules[0]
        # Both match
        assert engine._match_entity(rule, {"name": "evil-server", "command": "npx run"})
        # Only name matches
        assert not engine._match_entity(rule, {"name": "evil-server", "command": "python run"})
        # Only command matches
        assert not engine._match_entity(rule, {"name": "good-server", "command": "npx run"})

    def test_case_insensitive(self):
        engine = self._engine_with_rule(command=["*MINER*"])
        rule = engine.rules[0]
        assert engine._match_entity(rule, {"command": "my-miner"})
        assert engine._match_entity(rule, {"command": "MY-MINER"})

    def test_empty_pattern_list(self):
        engine = self._engine_with_rule(command=[])
        rule = engine.rules[0]
        assert not engine._match_entity(rule, {"command": "anything"})

    def test_no_match(self):
        engine = self._engine_with_rule(command=["*crypto*"])
        rule = engine.rules[0]
        assert not engine._match_entity(rule, {"command": "npx filesystem"})


# ===========================================================================
# 3. TestEvaluateMCP
# ===========================================================================

class TestEvaluateMCP:

    def _make_engine(self, tmp_path: Path) -> RuleEngine:
        rule = _minimal_rule(
            id="MCP-RULE-001",
            title="Miner detected",
            severity="critical",
            verdict="danger",
            remediation="Remove this server",
            match={"type": "mcp", "command": ["*miner*"]},
        )
        f = _write_yaml(tmp_path / "r.yaml", {"rules": [rule]})
        return RuleEngine.from_paths([str(f)])

    def test_matches_by_command(self, tmp_path: Path):
        engine = self._make_engine(tmp_path)
        server = FakeServer(name="bad-server", command="npx crypto-miner", source_file="/config.json")
        findings = engine.evaluate_mcp(server, {"command": "npx crypto-miner", "args": []})
        assert len(findings) == 1
        assert findings[0].code == "MCP-RULE-001"

    def test_no_match(self, tmp_path: Path):
        engine = self._make_engine(tmp_path)
        server = FakeServer(name="safe-server", command="npx filesystem", source_file="/config.json")
        findings = engine.evaluate_mcp(server, {"command": "npx filesystem", "args": []})
        assert len(findings) == 0

    def test_returns_custom_finding(self, tmp_path: Path):
        engine = self._make_engine(tmp_path)
        server = FakeServer(name="evil-miner", command="run-miner", source_file="/c.json")
        findings = engine.evaluate_mcp(server, {"command": "run-miner", "args": ["--fast"]})
        assert len(findings) == 1
        f = findings[0]
        assert isinstance(f, CustomFinding)
        assert f.code == "MCP-RULE-001"
        assert f.title == "Miner detected"
        assert f.severity == "critical"
        assert f.verdict == "danger"
        assert f.remediation == "Remove this server"
        assert f.entity_type == "mcp"
        assert f.entity_name == "evil-miner"
        assert "r.yaml" in f.rule_file


# ===========================================================================
# 4. TestEvaluateSkill
# ===========================================================================

class TestEvaluateSkill:

    def _make_engine(self, tmp_path: Path, **match_overrides) -> RuleEngine:
        match = {"type": "skill", "content": ["*ssh*"]}
        match.update(match_overrides)
        rule = _minimal_rule(
            id="SKILL-RULE-001",
            title="SSH access in skill",
            severity="high",
            verdict="danger",
            match=match,
        )
        f = _write_yaml(tmp_path / "r.yaml", {"rules": [rule]})
        return RuleEngine.from_paths([str(f)])

    def test_matches_by_content(self, tmp_path: Path):
        engine = self._make_engine(tmp_path)
        skill = FakeSkill(name="deploy", path="/skills/deploy.md")
        findings = engine.evaluate_skill(skill, "Connect via ssh to the remote host")
        assert len(findings) == 1
        assert findings[0].code == "SKILL-RULE-001"

    def test_content_truncated(self, tmp_path: Path):
        """Content over 10KB gets truncated; pattern at end should not match."""
        engine = self._make_engine(tmp_path)
        skill = FakeSkill(name="big", path="/skills/big.md")
        # Place "ssh" well past the 10240 byte boundary
        content = "a" * 11000 + " ssh connection"
        findings = engine.evaluate_skill(skill, content)
        assert len(findings) == 0

    def test_content_within_limit_matches(self, tmp_path: Path):
        """Content within 10KB limit should match normally."""
        engine = self._make_engine(tmp_path)
        skill = FakeSkill(name="small", path="/skills/small.md")
        content = "a" * 100 + " ssh connection"
        findings = engine.evaluate_skill(skill, content)
        assert len(findings) == 1


# ===========================================================================
# 5. TestEvaluateAgent
# ===========================================================================

class TestEvaluateAgent:

    def test_matches_by_agent_type(self, tmp_path: Path):
        rule = _minimal_rule(
            id="AGENT-RULE-001",
            title="Cursor agent",
            severity="medium",
            verdict="warning",
            match={"type": "agent", "agent_type": ["*cursor*"]},
        )
        f = _write_yaml(tmp_path / "r.yaml", {"rules": [rule]})
        engine = RuleEngine.from_paths([str(f)])

        agent = FakeAgent(name="My Cursor", agent_type="cursor-ide", config_path="/etc/cursor.json")
        findings = engine.evaluate_agent(agent)
        assert len(findings) == 1
        assert findings[0].code == "AGENT-RULE-001"
        assert findings[0].entity_type == "agent"
        assert findings[0].entity_name == "My Cursor"

    def test_no_match_agent(self, tmp_path: Path):
        rule = _minimal_rule(
            id="AGENT-RULE-002",
            title="Cursor agent",
            severity="medium",
            verdict="warning",
            match={"type": "agent", "agent_type": ["*cursor*"]},
        )
        f = _write_yaml(tmp_path / "r.yaml", {"rules": [rule]})
        engine = RuleEngine.from_paths([str(f)])

        agent = FakeAgent(name="Claude Desktop", agent_type="claude-desktop", config_path="/etc/claude.json")
        findings = engine.evaluate_agent(agent)
        assert len(findings) == 0


# ===========================================================================
# 6. TestRunTests
# ===========================================================================

class TestRunTests:

    def test_all_pass(self, tmp_path: Path):
        rule = _minimal_rule(
            id="INLINE-001",
            match={"type": "mcp", "command": ["*miner*"]},
            tests=[
                {"name": "should match miner", "input": {"command": "npx miner"}, "expect": "match"},
                {"name": "should not match safe", "input": {"command": "npx safe"}, "expect": "no_match"},
            ],
        )
        f = _write_yaml(tmp_path / "r.yaml", {"rules": [rule]})
        engine = RuleEngine.from_paths([str(f)])
        results = engine.run_tests()
        assert len(results) == 2
        assert all(r.passed for r in results)
        assert results[0].rule_id == "INLINE-001"
        assert results[0].test_name == "should match miner"
        assert results[0].expected == "match"
        assert results[0].actual == "match"

    def test_one_fails(self, tmp_path: Path):
        rule = _minimal_rule(
            id="INLINE-002",
            match={"type": "mcp", "command": ["*miner*"]},
            tests=[
                # This test expects no_match, but "crypto-miner" WILL match "*miner*"
                {"name": "wrong expectation", "input": {"command": "crypto-miner"}, "expect": "no_match"},
            ],
        )
        f = _write_yaml(tmp_path / "r.yaml", {"rules": [rule]})
        engine = RuleEngine.from_paths([str(f)])
        results = engine.run_tests()
        assert len(results) == 1
        assert not results[0].passed
        assert results[0].expected == "no_match"
        assert results[0].actual == "match"

    def test_no_tests(self, tmp_path: Path):
        rule = _minimal_rule(id="INLINE-003")
        # Ensure no tests field
        rule.pop("tests", None)
        f = _write_yaml(tmp_path / "r.yaml", {"rules": [rule]})
        engine = RuleEngine.from_paths([str(f)])
        results = engine.run_tests()
        assert len(results) == 0
