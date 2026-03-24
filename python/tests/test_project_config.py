import pytest
import yaml
from pathlib import Path

from agentseal.project_config import ProjectConfig, load_project_config, resolve_project_config


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
