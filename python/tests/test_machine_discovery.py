# tests/test_machine_discovery.py
"""Tests for machine-level agent discovery."""

import json
import pytest
from pathlib import Path
from unittest.mock import patch

from agentseal.machine_discovery import (
    scan_machine,
    _strip_json_comments,
    _get_well_known_configs,
)
from agentseal.guard_models import AgentConfigResult


class TestStripJsonComments:
    def test_no_comments(self):
        text = '{"key": "value"}'
        assert json.loads(_strip_json_comments(text)) == {"key": "value"}

    def test_single_line_comments(self):
        text = '{\n  // This is a comment\n  "key": "value"\n}'
        assert json.loads(_strip_json_comments(text)) == {"key": "value"}

    def test_multiline_comments(self):
        text = '{\n  /* comment\n  block */\n  "key": "value"\n}'
        assert json.loads(_strip_json_comments(text)) == {"key": "value"}

    def test_urls_in_strings_preserved(self):
        """URLs containing // inside string values must NOT be stripped."""
        text = '{\n  // This is a comment\n  "url": "https://example.com/api/v1",\n  "other": "http://localhost:11434/v1"\n}'
        result = json.loads(_strip_json_comments(text))
        assert result == {"url": "https://example.com/api/v1", "other": "http://localhost:11434/v1"}

    def test_url_with_inline_comment(self):
        """URL in string followed by a // comment on the same line."""
        text = '{\n  "url": "https://example.com" // comment here\n}'
        result = json.loads(_strip_json_comments(text))
        assert result == {"url": "https://example.com"}

    def test_escaped_quotes_in_strings(self):
        """Escaped quotes in strings should not confuse the parser."""
        text = '{"key": "value with \\"quotes\\"", "k2": "v2"}'
        result = json.loads(_strip_json_comments(text))
        assert result == {"key": 'value with "quotes"', "k2": "v2"}

    def test_mixed_comments_and_urls(self):
        """Complex JSONC with comments, URLs, and nested values."""
        text = '''{
  // Server config
  "servers": {
    "api": {
      "command": "npx",
      "args": ["-y", "@example/server"],
      /* This URL should be preserved */
      "url": "https://api.example.com/v2/endpoint"
    }
  }
}'''
        result = json.loads(_strip_json_comments(text))
        assert result["servers"]["api"]["url"] == "https://api.example.com/v2/endpoint"


class TestGetWellKnownConfigs:
    def test_returns_list_of_configs(self):
        configs = _get_well_known_configs()
        assert isinstance(configs, list)
        assert len(configs) >= 27

    def test_each_config_has_required_keys(self):
        configs = _get_well_known_configs()
        for cfg in configs:
            assert "name" in cfg
            assert "agent_type" in cfg
            assert "paths" in cfg
            assert "mcp_key" in cfg

    def test_known_agents_present(self):
        configs = _get_well_known_configs()
        names = [c["name"] for c in configs]
        assert "Claude Desktop" in names
        assert "Claude Code" in names
        assert "Cursor" in names
        assert "VS Code" in names
        # New agents (March 2026)
        assert "Amazon Q" in names
        assert "Copilot CLI" in names
        assert "Junie" in names
        assert "Goose" in names
        assert "Crush" in names
        assert "Qwen Code" in names
        assert "Grok CLI" in names
        assert "Visual Studio" in names


class TestScanMachine:
    def test_returns_three_tuple(self, tmp_path):
        """scan_machine returns (agents, mcp_servers, skill_paths)."""
        # Mock to avoid scanning real machine configs
        with patch("agentseal.machine_discovery._get_well_known_configs", return_value=[]):
            with patch("agentseal.machine_discovery._home", return_value=tmp_path):
                agents, servers, skills = scan_machine()
                assert isinstance(agents, list)
                assert isinstance(servers, list)
                assert isinstance(skills, list)

    def test_finds_agent_config(self, tmp_path):
        """When a config file exists, agent is marked as found with MCP server count."""
        config_dir = tmp_path / ".cursor"
        config_dir.mkdir()
        config_file = config_dir / "mcp.json"
        config_file.write_text(json.dumps({
            "mcpServers": {
                "brave": {"command": "npx", "args": ["@anthropic/brave-search"]},
                "fs": {"command": "npx", "args": ["/home"]},
            }
        }))

        mock_configs = [{
            "name": "Cursor",
            "agent_type": "cursor",
            "paths": {"all": config_file},
            "mcp_key": "mcpServers",
        }]

        with patch("agentseal.machine_discovery._get_well_known_configs", return_value=mock_configs):
            with patch("agentseal.machine_discovery._home", return_value=tmp_path):
                agents, servers, skills = scan_machine()

        assert len(agents) == 1
        assert agents[0].status == "found"
        assert agents[0].mcp_servers == 2
        assert len(servers) == 2

    def test_missing_config_marked_not_installed(self, tmp_path):
        mock_configs = [{
            "name": "TestAgent",
            "agent_type": "test",
            "paths": {"all": tmp_path / ".testagent" / "config.json"},
            "mcp_key": "mcpServers",
        }]

        with patch("agentseal.machine_discovery._get_well_known_configs", return_value=mock_configs):
            with patch("agentseal.machine_discovery._home", return_value=tmp_path):
                agents, servers, skills = scan_machine()

        assert len(agents) == 1
        assert agents[0].status == "not_installed"

    def test_corrupt_config_marked_error(self, tmp_path):
        config_file = tmp_path / "bad.json"
        config_file.write_text("not valid json {{{{")

        mock_configs = [{
            "name": "BadAgent",
            "agent_type": "bad",
            "paths": {"all": config_file},
            "mcp_key": "mcpServers",
        }]

        with patch("agentseal.machine_discovery._get_well_known_configs", return_value=mock_configs):
            with patch("agentseal.machine_discovery._home", return_value=tmp_path):
                agents, servers, skills = scan_machine()

        assert agents[0].status == "error"

    def test_dedup_with_list_command(self, tmp_path):
        """MCP server with command as list (not string) must not crash dedup."""
        cfg = tmp_path / "config.json"
        cfg.write_text(json.dumps({"mcpServers": {
            "myserver": {"command": ["npx", "-y", "@example/server"], "args": []},
        }}))

        mock_configs = [
            {"name": "Agent1", "agent_type": "a1", "paths": {"all": cfg}, "mcp_key": "mcpServers"},
        ]

        with patch("agentseal.machine_discovery._get_well_known_configs", return_value=mock_configs):
            with patch("agentseal.machine_discovery._home", return_value=tmp_path):
                agents, servers, skills = scan_machine()

        assert len(servers) == 1
        assert servers[0]["name"] == "myserver"

    def test_deduplicates_mcp_servers(self, tmp_path):
        """Same MCP server in two configs should be deduplicated."""
        cfg1 = tmp_path / "config1.json"
        cfg2 = tmp_path / "config2.json"
        server_data = json.dumps({"mcpServers": {"brave": {"command": "npx brave", "args": []}}})
        cfg1.write_text(server_data)
        cfg2.write_text(server_data)

        mock_configs = [
            {"name": "Agent1", "agent_type": "a1", "paths": {"all": cfg1}, "mcp_key": "mcpServers"},
            {"name": "Agent2", "agent_type": "a2", "paths": {"all": cfg2}, "mcp_key": "mcpServers"},
        ]

        with patch("agentseal.machine_discovery._get_well_known_configs", return_value=mock_configs):
            with patch("agentseal.machine_discovery._home", return_value=tmp_path):
                agents, servers, skills = scan_machine()

        assert len(servers) == 1  # Deduplicated

    def test_finds_skill_files(self, tmp_path):
        """Discovers skill files in well-known directories."""
        skill_dir = tmp_path / ".cursor" / "rules"
        skill_dir.mkdir(parents=True)
        (skill_dir / "my-rule.md").write_text("# My Rule\n")

        with patch("agentseal.machine_discovery._get_well_known_configs", return_value=[]):
            with patch("agentseal.machine_discovery._home", return_value=tmp_path):
                agents, servers, skills = scan_machine()

        assert any("my-rule.md" in str(s) for s in skills)

    def test_finds_cursorrules_in_cwd(self, tmp_path, monkeypatch):
        """Discovers .cursorrules in the current working directory."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".cursorrules").write_text("# Rules\n")

        with patch("agentseal.machine_discovery._get_well_known_configs", return_value=[]):
            with patch("agentseal.machine_discovery._home", return_value=tmp_path):
                agents, servers, skills = scan_machine()

        assert any(".cursorrules" in str(s) for s in skills)
