"""
Project-level configuration for AgentSeal Guard.

Loads and validates `.agentseal.yaml` files that define scanning policy
per-project: allowlists, ignore rules, and CI gate thresholds.
"""

import sys
from dataclasses import dataclass, field
from pathlib import Path

import yaml


_VALID_FAIL_ON = ("safe", "warning", "danger")

_KNOWN_KEYS = {
    "fail_on", "allowed_agents", "allowed_mcp_servers",
    "ignore_paths", "ignore_findings",
}


@dataclass
class ProjectConfig:
    """Parsed .agentseal.yaml project configuration."""
    fail_on: str = "danger"
    allowed_agents: list[str] = field(default_factory=list)
    allowed_mcp_servers: list[str] = field(default_factory=list)
    ignore_paths: list[str] = field(default_factory=list)
    ignore_findings: list[dict] = field(default_factory=list)
    config_path: str = ""


def load_project_config(path: Path) -> ProjectConfig:
    """Load and validate a .agentseal.yaml file.

    Args:
        path: Path to the .agentseal.yaml file.

    Returns:
        Parsed ProjectConfig.

    Raises:
        ValueError: If YAML is invalid or fail_on has a bad value.
    """
    try:
        raw = path.read_text(encoding="utf-8")
    except Exception as e:
        raise ValueError(f"Cannot read {path}: {e}") from e

    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as e:
        raise ValueError(f"Cannot parse {path}: {e}") from e

    if data is None:
        data = {}

    if not isinstance(data, dict):
        raise ValueError(f"Expected mapping in {path}, got {type(data).__name__}")

    # Warn on unknown keys
    for key in data:
        if key not in _KNOWN_KEYS:
            print(f"Warning: unknown key '{key}' in {path} (ignored)", file=sys.stderr)

    fail_on = data.get("fail_on", "danger")
    if fail_on not in _VALID_FAIL_ON:
        raise ValueError(
            f"fail_on must be one of {_VALID_FAIL_ON}, got '{fail_on}'"
        )

    ignore_findings = data.get("ignore_findings", []) or []
    for entry in ignore_findings:
        if isinstance(entry, dict) and "reason" not in entry:
            fid = entry.get("id", "?")
            print(
                f"Warning: ignore_findings entry '{fid}' has no reason field",
                file=sys.stderr,
            )

    return ProjectConfig(
        fail_on=fail_on,
        allowed_agents=data.get("allowed_agents", []) or [],
        allowed_mcp_servers=data.get("allowed_mcp_servers", []) or [],
        ignore_paths=data.get("ignore_paths", []) or [],
        ignore_findings=ignore_findings,
        config_path=str(path),
    )
