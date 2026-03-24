"""Tests for guard + project config integration."""
from pathlib import Path
from unittest.mock import patch

from agentseal.guard import Guard
from agentseal.guard_models import AgentConfigResult
from agentseal.project_config import ProjectConfig


class TestGuardConfigIntegration:
    @patch("agentseal.guard.scan_machine")
    def test_ignore_paths_filters_skills(self, mock_scan_machine):
        """Skills in ignored paths should be excluded."""
        cfg = ProjectConfig(ignore_paths=["node_modules"])
        mock_scan_machine.return_value = (
            [],
            [],
            [Path("node_modules/.cursorrules"), Path("src/CLAUDE.md")],
        )
        guard = Guard(project_config=cfg)
        report = guard.run()
        scanned_paths = [s.path for s in report.skill_results]
        assert not any("node_modules" in p for p in scanned_paths)

    @patch("agentseal.guard.scan_machine")
    def test_unlisted_agents_appear_in_report(self, mock_scan_machine):
        cfg = ProjectConfig(allowed_agents=["cursor"])
        mock_scan_machine.return_value = (
            [
                AgentConfigResult("Cursor", "/fake", "cursor", 0, 0, "found"),
                AgentConfigResult("Claude Desktop", "/fake", "claude-desktop", 0, 0, "found"),
            ],
            [],
            [],
        )
        guard = Guard(project_config=cfg)
        report = guard.run()
        assert len(report.unlisted_findings) == 1
        assert report.unlisted_findings[0].code == "GUARD-001"

    @patch("agentseal.guard.scan_machine")
    def test_config_path_in_report(self, mock_scan_machine):
        cfg = ProjectConfig(config_path="/tmp/test/.agentseal.yaml")
        mock_scan_machine.return_value = ([], [], [])
        guard = Guard(project_config=cfg)
        report = guard.run()
        assert report.config_path == "/tmp/test/.agentseal.yaml"
