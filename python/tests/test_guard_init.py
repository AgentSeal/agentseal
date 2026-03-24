"""Tests for the guard init command flow."""
from unittest.mock import patch

from agentseal.guard_models import AgentConfigResult


class TestGuardInit:
    def _mock_scan_machine(self):
        agents = [
            AgentConfigResult(
                name="Cursor", config_path="/fake/.cursor/mcp.json",
                agent_type="cursor", mcp_servers=1, skills_count=0, status="found",
            ),
        ]
        mcps = [{"name": "db", "agent_type": "cursor", "command": "node"}]
        skills = []
        return agents, mcps, skills

    @patch("agentseal.machine_discovery.scan_machine")
    @patch("agentseal.machine_discovery.scan_directory")
    def test_init_writes_config(self, mock_scan_dir, mock_scan_machine, tmp_path):
        from agentseal.project_config import run_guard_init
        mock_scan_machine.return_value = self._mock_scan_machine()
        mock_scan_dir.return_value = ([], [], [])

        result = run_guard_init(target_dir=tmp_path, force=False, interactive=False)
        assert result is True
        config_file = tmp_path / ".agentseal.yaml"
        assert config_file.exists()
        content = config_file.read_text()
        assert "cursor" in content
        assert "db@cursor" in content

    @patch("agentseal.machine_discovery.scan_machine")
    @patch("agentseal.machine_discovery.scan_directory")
    def test_init_existing_config_no_force(self, mock_scan_dir, mock_scan_machine, tmp_path):
        from agentseal.project_config import run_guard_init
        (tmp_path / ".agentseal.yaml").write_text("fail_on: danger\n")

        result = run_guard_init(target_dir=tmp_path, force=False, interactive=False)
        assert result is False  # did not overwrite

    @patch("agentseal.machine_discovery.scan_machine")
    @patch("agentseal.machine_discovery.scan_directory")
    def test_init_existing_config_with_force(self, mock_scan_dir, mock_scan_machine, tmp_path):
        from agentseal.project_config import run_guard_init
        mock_scan_machine.return_value = self._mock_scan_machine()
        mock_scan_dir.return_value = ([], [], [])
        (tmp_path / ".agentseal.yaml").write_text("old content\n")

        result = run_guard_init(target_dir=tmp_path, force=True, interactive=False)
        assert result is True
        content = (tmp_path / ".agentseal.yaml").read_text()
        assert "old content" not in content
        assert "fail_on" in content

    @patch("agentseal.machine_discovery.scan_machine")
    @patch("agentseal.machine_discovery.scan_directory")
    def test_init_no_agents_found(self, mock_scan_dir, mock_scan_machine, tmp_path):
        from agentseal.project_config import run_guard_init
        mock_scan_machine.return_value = ([], [], [])
        mock_scan_dir.return_value = ([], [], [])

        result = run_guard_init(target_dir=tmp_path, force=False, interactive=False)
        assert result is True
        content = (tmp_path / ".agentseal.yaml").read_text()
        assert "allowed_agents: []" in content
