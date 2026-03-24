
import pytest
import yaml
from agentseal.guard_models import AgentConfigResult
from agentseal.project_config import (
    ProjectConfig,
    generate_unlisted_findings,
    load_project_config,
    resolve_project_config,
    should_fail,
    should_ignore_finding,
    should_ignore_path,
)


class TestLoadProjectConfig:
    def test_load_minimal_config(self, tmp_path):
        f = tmp_path / ".agentseal.yaml"
        f.write_text("fail_on: danger\n")
        cfg = load_project_config(f)
        assert cfg.fail_on == "danger"
        assert cfg.allowed_agents == []
        assert cfg.allowed_mcp_servers == []
        assert cfg.ignore_paths == []
        assert cfg.ignore_findings == []

    def test_load_full_config(self, tmp_path):
        f = tmp_path / ".agentseal.yaml"
        f.write_text(yaml.dump({
            "fail_on": "warning",
            "allowed_agents": ["claude-desktop", "cursor"],
            "allowed_mcp_servers": ["filesystem@claude-desktop", "slack@cursor"],
            "ignore_paths": ["node_modules", ".git"],
            "ignore_findings": [
                {"id": "SKILL-001:./CLAUDE.md", "reason": "Known safe"},
            ],
        }))
        cfg = load_project_config(f)
        assert cfg.fail_on == "warning"
        assert cfg.allowed_agents == ["claude-desktop", "cursor"]
        assert cfg.allowed_mcp_servers == ["filesystem@claude-desktop", "slack@cursor"]
        assert cfg.ignore_paths == ["node_modules", ".git"]
        assert len(cfg.ignore_findings) == 1
        assert cfg.ignore_findings[0]["id"] == "SKILL-001:./CLAUDE.md"

    def test_load_empty_file(self, tmp_path):
        f = tmp_path / ".agentseal.yaml"
        f.write_text("")
        cfg = load_project_config(f)
        assert cfg.fail_on == "danger"

    def test_load_unknown_keys_ignored(self, tmp_path, capsys):
        f = tmp_path / ".agentseal.yaml"
        f.write_text("fail_on: danger\nfuture_field: true\n")
        cfg = load_project_config(f)
        assert cfg.fail_on == "danger"
        captured = capsys.readouterr()
        assert "future_field" in captured.err

    def test_invalid_fail_on_raises(self, tmp_path):
        f = tmp_path / ".agentseal.yaml"
        f.write_text("fail_on: critical\n")
        with pytest.raises(ValueError, match="fail_on"):
            load_project_config(f)

    def test_invalid_yaml_raises(self, tmp_path):
        f = tmp_path / ".agentseal.yaml"
        f.write_text("fail_on: [unterminated\n")
        with pytest.raises(ValueError, match="parse"):
            load_project_config(f)

    def test_ignore_findings_missing_reason_warns(self, tmp_path, capsys):
        f = tmp_path / ".agentseal.yaml"
        f.write_text(yaml.dump({
            "ignore_findings": [{"id": "SKILL-001"}],
        }))
        cfg = load_project_config(f)
        assert len(cfg.ignore_findings) == 1
        captured = capsys.readouterr()
        assert "reason" in captured.err

    def test_allowed_mcp_servers_without_agent_type(self, tmp_path):
        f = tmp_path / ".agentseal.yaml"
        f.write_text(yaml.dump({
            "allowed_mcp_servers": ["filesystem"],
        }))
        cfg = load_project_config(f)
        assert cfg.allowed_mcp_servers == ["filesystem"]


class TestResolveProjectConfig:
    def test_find_in_cwd(self, tmp_path):
        f = tmp_path / ".agentseal.yaml"
        f.write_text("fail_on: danger\n")
        cfg = resolve_project_config(search_dir=tmp_path)
        assert cfg is not None
        assert cfg.fail_on == "danger"

    def test_walk_up_to_parent(self, tmp_path):
        (tmp_path / ".agentseal.yaml").write_text("fail_on: warning\n")
        child = tmp_path / "subdir"
        child.mkdir()
        cfg = resolve_project_config(search_dir=child)
        assert cfg is not None
        assert cfg.fail_on == "warning"

    def test_stop_at_git_root(self, tmp_path):
        # Config above git root should NOT be found
        (tmp_path / ".agentseal.yaml").write_text("fail_on: warning\n")
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / ".git").mkdir()
        cfg = resolve_project_config(search_dir=repo)
        assert cfg is None

    def test_config_at_git_root(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / ".git").mkdir()
        (repo / ".agentseal.yaml").write_text("fail_on: danger\n")
        child = repo / "src"
        child.mkdir()
        cfg = resolve_project_config(search_dir=child)
        assert cfg is not None
        assert cfg.fail_on == "danger"

    def test_explicit_config_path(self, tmp_path):
        f = tmp_path / "custom.yaml"
        f.write_text("fail_on: warning\n")
        cfg = resolve_project_config(config_path=f)
        assert cfg is not None
        assert cfg.fail_on == "warning"

    def test_explicit_config_missing_raises(self, tmp_path):
        f = tmp_path / "missing.yaml"
        with pytest.raises(FileNotFoundError):
            resolve_project_config(config_path=f)

    def test_no_config_returns_none(self, tmp_path):
        # Create .git to guarantee a stop boundary
        (tmp_path / ".git").mkdir()
        cfg = resolve_project_config(search_dir=tmp_path)
        assert cfg is None


class TestUnlistedFindings:
    def _agent(self, name, agent_type, status="found"):
        return AgentConfigResult(
            name=name, config_path="/fake", agent_type=agent_type,
            mcp_servers=0, skills_count=0, status=status,
        )

    def _mcp(self, name, agent_type="claude-desktop"):
        return {"name": name, "agent_type": agent_type, "command": "node"}

    def test_empty_allowlist_no_findings(self):
        cfg = ProjectConfig(allowed_agents=[], allowed_mcp_servers=[])
        agents = [self._agent("Claude Desktop", "claude-desktop")]
        mcps = [self._mcp("filesystem")]
        findings = generate_unlisted_findings(cfg, agents, mcps)
        assert findings == []

    def test_unlisted_agent(self):
        cfg = ProjectConfig(allowed_agents=["cursor"])
        agents = [
            self._agent("Cursor", "cursor"),
            self._agent("Claude Desktop", "claude-desktop"),
        ]
        findings = generate_unlisted_findings(cfg, agents, [])
        assert len(findings) == 1
        assert findings[0].code == "GUARD-001"
        assert "claude-desktop" in findings[0].description

    def test_allowed_agent_no_finding(self):
        cfg = ProjectConfig(allowed_agents=["claude-desktop"])
        agents = [self._agent("Claude Desktop", "claude-desktop")]
        findings = generate_unlisted_findings(cfg, agents, [])
        assert findings == []

    def test_unlisted_mcp_with_agent_type(self):
        cfg = ProjectConfig(allowed_mcp_servers=["filesystem@claude-desktop"])
        mcps = [
            self._mcp("filesystem", "claude-desktop"),
            self._mcp("slack", "cursor"),
        ]
        findings = generate_unlisted_findings(cfg, [], mcps)
        assert len(findings) == 1
        assert findings[0].code == "GUARD-002"
        assert "slack" in findings[0].description

    def test_unlisted_mcp_bare_name_matches_any_agent(self):
        cfg = ProjectConfig(allowed_mcp_servers=["filesystem"])
        mcps = [
            self._mcp("filesystem", "claude-desktop"),
            self._mcp("filesystem", "cursor"),
        ]
        findings = generate_unlisted_findings(cfg, [], mcps)
        assert findings == []

    def test_not_installed_agents_skipped(self):
        cfg = ProjectConfig(allowed_agents=["cursor"])
        agents = [self._agent("Windsurf", "windsurf", status="not_installed")]
        findings = generate_unlisted_findings(cfg, agents, [])
        assert findings == []


class TestIgnorePath:
    def test_match_prefix(self):
        cfg = ProjectConfig(ignore_paths=["node_modules"])
        assert should_ignore_path(cfg, "node_modules/pkg/index.js") is True
        assert should_ignore_path(cfg, "src/app.py") is False

    def test_match_with_trailing_slash(self):
        cfg = ProjectConfig(ignore_paths=["node_modules/"])
        assert should_ignore_path(cfg, "node_modules/pkg") is True

    def test_match_nested(self):
        cfg = ProjectConfig(ignore_paths=[".git"])
        assert should_ignore_path(cfg, ".git/objects/abc") is True
        assert should_ignore_path(cfg, "src/.git/config") is True

    def test_empty_list(self):
        cfg = ProjectConfig(ignore_paths=[])
        assert should_ignore_path(cfg, "anything") is False


class TestIgnoreFinding:
    def test_bare_code_match(self):
        cfg = ProjectConfig(ignore_findings=[{"id": "SKILL-001", "reason": "safe"}])
        assert should_ignore_finding(cfg, "SKILL-001", "./CLAUDE.md") is True
        assert should_ignore_finding(cfg, "SKILL-001", "./other.md") is True

    def test_code_path_match(self):
        cfg = ProjectConfig(ignore_findings=[
            {"id": "SKILL-001:./CLAUDE.md", "reason": "safe"},
        ])
        assert should_ignore_finding(cfg, "SKILL-001", "./CLAUDE.md") is True
        assert should_ignore_finding(cfg, "SKILL-001", "./other.md") is False

    def test_no_match(self):
        cfg = ProjectConfig(ignore_findings=[{"id": "MCP-007", "reason": "safe"}])
        assert should_ignore_finding(cfg, "SKILL-001", "./CLAUDE.md") is False

    def test_empty_list(self):
        cfg = ProjectConfig(ignore_findings=[])
        assert should_ignore_finding(cfg, "SKILL-001", "./CLAUDE.md") is False


class TestShouldFail:
    def test_fail_on_danger_with_danger(self):
        assert should_fail("danger", has_danger=True, has_warning=True) is True

    def test_fail_on_danger_with_warning_only(self):
        assert should_fail("danger", has_danger=False, has_warning=True) is False

    def test_fail_on_warning_with_warning(self):
        assert should_fail("warning", has_danger=False, has_warning=True) is True

    def test_fail_on_safe_always_fails(self):
        assert should_fail("safe", has_danger=False, has_warning=False, has_safe=True) is True

    def test_fail_on_safe_no_findings(self):
        assert should_fail("safe", has_danger=False, has_warning=False, has_safe=False) is False
