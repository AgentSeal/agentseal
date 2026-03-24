# agentseal/machine_discovery.py
"""
Machine-level agent discovery — finds ALL AI agents, MCP servers, and skills
installed on the user's machine by checking well-known config paths.

This is different from discovery.py which scans a project directory.
machine_discovery.py scans the entire machine's well-known locations.
"""

import json
import os
import platform
import re
from pathlib import Path
from typing import Optional

from agentseal.guard_models import AgentConfigResult


def _home() -> Path:
    return Path.home()


# Project-level MCP config definitions (shared between scan_machine and scan_directory)
_PROJECT_MCP_CONFIGS = [
    (".mcp.json", "mcpServers", None),
    (".cursor/mcp.json", "mcpServers", None),
    (".vscode/mcp.json", "servers", "jsonc"),
    ("mcp_config.json", "servers", None),
    ("mcp.json", "mcpServers", None),
    (".kiro/settings/mcp.json", "mcpServers", None),
    (".kilocode/mcp.json", "mcpServers", None),
    (".roo/mcp.json", "mcpServers", None),
    (".trae/mcp.json", "mcpServers", None),
    (".amazonq/mcp.json", "mcpServers", None),
    (".copilot/mcp-config.json", "mcpServers", None),
    (".junie/mcp/mcp.json", "mcpServers", None),
    (".grok/settings.json", "mcpServers", None),
]

# Project-level skill files
_PROJECT_SKILL_FILES = [
    ".cursorrules", ".windsurfrules",
    "CLAUDE.md", ".claude/CLAUDE.md", "AGENTS.md",
    ".github/copilot-instructions.md",
    "GEMINI.md",
    ".junie/guidelines.md",
    ".roomodes",
]

# Project-level skill directories
_PROJECT_SKILL_DIRS = [
    ".cursor/rules", ".roo/rules", ".kiro/rules",
    ".trae/rules", ".junie/rules", ".qwen/skills",
    ".windsurf/rules",
]


def _get_well_known_configs() -> list[dict]:
    """Return all known agent config locations for the current platform."""
    home = _home()
    system = platform.system()

    # Windows APPDATA (may not exist on other platforms)
    appdata = Path(os.environ.get("APPDATA", "")) if system == "Windows" else None

    # All paths verified against official documentation (March 2026).
    # Sources linked in each entry comment.
    configs = [
        # https://modelcontextprotocol.io/docs/develop/connect-local-servers
        {
            "name": "Claude Desktop",
            "agent_type": "claude-desktop",
            "paths": {
                "Darwin": home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json",
                "Windows": appdata / "Claude" / "claude_desktop_config.json" if appdata else None,
                "Linux": home / ".config" / "Claude" / "claude_desktop_config.json",
            },
            "mcp_key": "mcpServers",
        },
        # https://code.claude.com/docs/en/mcp — MCP is in ~/.claude.json, NOT settings.json
        {
            "name": "Claude Code",
            "agent_type": "claude-code",
            "paths": {"all": home / ".claude.json"},
            "mcp_key": "mcpServers",
        },
        # https://cursor.com/docs/context/mcp
        {
            "name": "Cursor",
            "agent_type": "cursor",
            "paths": {"all": home / ".cursor" / "mcp.json"},
            "mcp_key": "mcpServers",
        },
        # https://docs.windsurf.com/windsurf/cascade/mcp
        {
            "name": "Windsurf",
            "agent_type": "windsurf",
            "paths": {
                "Darwin": home / ".codeium" / "windsurf" / "mcp_config.json",
                "Windows": home / ".codeium" / "windsurf" / "mcp_config.json",
                "Linux": home / ".codeium" / "windsurf" / "mcp_config.json",
            },
            "mcp_key": "mcpServers",
        },
        # https://code.visualstudio.com/docs/copilot/reference/mcp-configuration
        {
            "name": "VS Code",
            "agent_type": "vscode",
            "paths": {
                "Darwin": home / "Library" / "Application Support" / "Code" / "User" / "mcp.json",
                "Windows": appdata / "Code" / "User" / "mcp.json" if appdata else None,
                "Linux": home / ".config" / "Code" / "User" / "mcp.json",
            },
            "mcp_key": "servers",
            "format": "jsonc",
        },
        # https://geminicli.com/docs/reference/configuration/
        {
            "name": "Gemini CLI",
            "agent_type": "gemini-cli",
            "paths": {"all": home / ".gemini" / "settings.json"},
            "mcp_key": "mcpServers",
        },
        # https://developers.openai.com/codex/config-reference/
        {
            "name": "Codex CLI",
            "agent_type": "codex",
            "paths": {"all": home / ".codex" / "config.toml"},
            "mcp_key": "mcp_servers",
            "format": "toml",
        },
        # https://docs.openclaw.ai/start/getting-started
        {
            "name": "OpenClaw",
            "agent_type": "openclaw",
            "paths": {"all": home / ".openclaw" / "openclaw.json"},
            "mcp_key": "mcpServers",
            "format": "jsonc",
        },
        # https://kiro.dev/docs/mcp/configuration/
        {
            "name": "Kiro",
            "agent_type": "kiro",
            "paths": {"all": home / ".kiro" / "settings" / "mcp.json"},
            "mcp_key": "mcpServers",
        },
        # https://opencode.ai/docs/mcp-servers/
        {
            "name": "OpenCode",
            "agent_type": "opencode",
            "paths": {
                "Darwin": home / ".config" / "opencode" / "opencode.json",
                "Linux": home / ".config" / "opencode" / "opencode.json",
                "Windows": appdata / "opencode" / "opencode.json" if appdata else None,
            },
            "mcp_key": "mcp",
        },
        # https://docs.continue.dev/customize/deep-dives/mcp
        {
            "name": "Continue",
            "agent_type": "continue",
            "paths": {"all": home / ".continue" / "config.yaml"},
            "mcp_key": "mcpServers",
            "format": "yaml",
        },
        # https://docs.cline.bot/mcp/configuring-mcp-servers
        {
            "name": "Cline",
            "agent_type": "cline",
            "paths": {
                "Darwin": home / "Library" / "Application Support" / "Code" / "User" / "globalStorage" / "saoudrizwan.claude-dev" / "settings" / "cline_mcp_settings.json",
                "Windows": appdata / "Code" / "User" / "globalStorage" / "saoudrizwan.claude-dev" / "settings" / "cline_mcp_settings.json" if appdata else None,
                "Linux": home / ".config" / "Code" / "User" / "globalStorage" / "saoudrizwan.claude-dev" / "settings" / "cline_mcp_settings.json",
            },
            "mcp_key": "mcpServers",
        },
        # https://docs.roocode.com/features/mcp/using-mcp-in-roo
        {
            "name": "Roo Code",
            "agent_type": "roo-code",
            "paths": {
                "Darwin": home / "Library" / "Application Support" / "Code" / "User" / "globalStorage" / "rooveterinaryinc.roo-cline" / "settings" / "mcp_settings.json",
                "Windows": appdata / "Code" / "User" / "globalStorage" / "rooveterinaryinc.roo-cline" / "settings" / "mcp_settings.json" if appdata else None,
                "Linux": home / ".config" / "Code" / "User" / "globalStorage" / "rooveterinaryinc.roo-cline" / "settings" / "mcp_settings.json",
            },
            "mcp_key": "mcpServers",
        },
        # https://kilo.ai/docs/features/mcp/using-mcp-in-kilo-code
        {
            "name": "Kilo Code",
            "agent_type": "kilo-code",
            "paths": {
                "Darwin": home / "Library" / "Application Support" / "Code" / "User" / "globalStorage" / "kilocode.kilo" / "mcp_settings.json",
                "Windows": appdata / "Code" / "User" / "globalStorage" / "kilocode.kilo" / "mcp_settings.json" if appdata else None,
                "Linux": home / ".config" / "Code" / "User" / "globalStorage" / "kilocode.kilo" / "mcp_settings.json",
            },
            "mcp_key": "mcpServers",
        },
        # https://zed.dev/docs/ai/mcp
        {
            "name": "Zed",
            "agent_type": "zed",
            "paths": {
                "Darwin": home / ".zed" / "settings.json",
                "Linux": home / ".config" / "zed" / "settings.json",
                "Windows": appdata / "Zed" / "settings.json" if appdata else None,
            },
            "mcp_key": "context_servers",
            "format": "jsonc",
        },
        # https://ampcode.com/manual
        {
            "name": "Amp",
            "agent_type": "amp",
            "paths": {
                "Darwin": home / ".config" / "amp" / "settings.json",
                "Linux": home / ".config" / "amp" / "settings.json",
                "Windows": appdata / "amp" / "settings.json" if appdata else None,
            },
            "mcp_key": "amp.mcpServers",
        },
        # Aider does not support MCP (PRs rejected). Detect install only.
        {
            "name": "Aider",
            "agent_type": "aider",
            "paths": {"all": home / ".aider.conf.yml"},
            "mcp_key": None,
        },
        # ── New agents (verified March 2026) ────────────────────────────
        # https://docs.aws.amazon.com/amazonq/latest/qdeveloper-ug/command-line-mcp-config-CLI.html
        {
            "name": "Amazon Q",
            "agent_type": "amazon-q",
            "paths": {"all": home / ".aws" / "amazonq" / "mcp.json"},
            "mcp_key": "mcpServers",
        },
        # https://docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/add-mcp-servers
        {
            "name": "Copilot CLI",
            "agent_type": "copilot-cli",
            "paths": {"all": home / ".copilot" / "mcp-config.json"},
            "mcp_key": "mcpServers",
        },
        # https://junie.jetbrains.com/docs/junie-cli-mcp-configuration.html
        {
            "name": "Junie",
            "agent_type": "junie",
            "paths": {"all": home / ".junie" / "mcp" / "mcp.json"},
            "mcp_key": "mcpServers",
        },
        # https://block.github.io/goose/docs/getting-started/using-extensions
        # Goose uses "extensions" key, "cmd" instead of "command", "envs" instead of "env"
        {
            "name": "Goose",
            "agent_type": "goose",
            "paths": {
                "Darwin": home / ".config" / "goose" / "config.yaml",
                "Linux": home / ".config" / "goose" / "config.yaml",
            },
            "mcp_key": "extensions",
            "format": "yaml",
        },
        # https://github.com/charmbracelet/crush — key is "mcp" not "mcpServers"
        {
            "name": "Crush",
            "agent_type": "crush",
            "paths": {"all": home / ".config" / "crush" / "crush.json"},
            "mcp_key": "mcp",
        },
        # https://qwenlm.github.io/qwen-code-docs/en/developers/tools/mcp-server/
        {
            "name": "Qwen Code",
            "agent_type": "qwen-code",
            "paths": {"all": home / ".qwen" / "settings.json"},
            "mcp_key": "mcpServers",
        },
        # https://github.com/superagent-ai/grok-cli (third-party, not official xAI)
        {
            "name": "Grok CLI",
            "agent_type": "grok-cli",
            "paths": {"all": home / ".grok" / "user-settings.json"},
            "mcp_key": "mcpServers",
        },
        # https://learn.microsoft.com/en-us/visualstudio/ide/mcp-servers
        # Visual Studio (not VS Code) — Windows only, uses "servers" key
        {
            "name": "Visual Studio",
            "agent_type": "visual-studio",
            "paths": {
                "Windows": home / ".mcp.json",
            },
            "mcp_key": "servers",
        },
        # https://moonshotai.github.io/kimi-cli/en/customization/mcp.html
        {
            "name": "Kimi CLI",
            "agent_type": "kimi-cli",
            "paths": {"all": home / ".kimi" / "mcp.json"},
            "mcp_key": "mcpServers",
        },
        # https://trae.ai/docs/mcp-servers
        {
            "name": "Trae",
            "agent_type": "trae",
            "paths": {
                "Darwin": home / "Library" / "Application Support" / "Trae" / "mcp_config.json",
                "Linux": home / ".config" / "Trae" / "mcp_config.json",
            },
            "mcp_key": "mcpServers",
        },
        # https://github.com/Lichas/maxclaw — MiniMax M2.5 agent
        {
            "name": "MaxClaw",
            "agent_type": "maxclaw",
            "paths": {"all": home / ".maxclaw" / "config.json"},
            "mcp_key": "mcpServers",
        },
    ]

    return configs


# Well-known skill directories to scan (in $HOME)
_SKILL_DIRS = [
    ".openclaw/skills",
    ".openclaw/workspace/skills",
    ".cursor/rules",
    ".roo/rules",
    ".continue/rules",
    ".trae/rules",
    ".kiro/rules",
    ".qwen/skills",
]

# Well-known skill files (single files that act as agent instructions, in $HOME)
_SKILL_FILES = [
    ".cursorrules",
    ".claude/CLAUDE.md",
    ".github/copilot-instructions.md",
    ".windsurfrules",
    "AGENTS.md",
    "CLAUDE.md",
    "GEMINI.md",
]

# Max file size for skill scanning (10 MB — anything larger is not a skill file)
_MAX_SKILL_SIZE = 10 * 1024 * 1024


def _strip_json_comments(text: str) -> str:
    """Strip // and /* */ comments from JSONC (VS Code-style configs).

    Correctly handles:
    - URLs inside strings like "http://example.com" (preserved)
    - Single-line // comments outside strings (removed)
    - Multi-line /* ... */ comments outside strings (removed)
    """
    result: list[str] = []
    i = 0
    n = len(text)
    while i < n:
        # String literal — consume entire string including escapes
        if text[i] == '"':
            j = i + 1
            while j < n:
                if text[j] == '\\':
                    j += 2  # skip escaped character
                elif text[j] == '"':
                    j += 1
                    break
                else:
                    j += 1
            result.append(text[i:j])
            i = j
        # Single-line comment
        elif text[i:i+2] == '//':
            # Skip to end of line
            while i < n and text[i] != '\n':
                i += 1
        # Multi-line comment
        elif text[i:i+2] == '/*':
            i += 2
            while i < n - 1 and text[i:i+2] != '*/':
                i += 1
            if i < n - 1:
                i += 2  # skip */
        else:
            result.append(text[i])
            i += 1
    return ''.join(result)


def scan_machine() -> tuple[
    list[AgentConfigResult],  # Which agents are installed
    list[dict],               # All MCP server configs found
    list[Path],               # All skill files found
]:
    """Discover all AI agents, MCP servers, and skills on this machine.

    Returns:
        agents: List of discovered agent configurations
        mcp_servers: List of MCP server config dicts (with source_file and agent_type added)
        skill_paths: List of Path objects pointing to skill files
    """
    system = platform.system()
    home = _home()
    configs = _get_well_known_configs()

    agent_results: list[AgentConfigResult] = []
    all_mcp_servers: list[dict] = []
    all_skill_paths: list[Path] = []

    for cfg in configs:
        # Resolve path for current platform
        path = cfg["paths"].get(system) or cfg["paths"].get("all")
        if path is None:
            continue

        path = Path(path).expanduser()

        if not path.is_file():
            # Check if the agent directory exists even if config file doesn't
            agent_dir = path.parent
            if agent_dir.is_dir():
                agent_results.append(AgentConfigResult(
                    name=cfg["name"],
                    config_path=str(agent_dir),
                    agent_type=cfg["agent_type"],
                    mcp_servers=0,
                    skills_count=0,
                    status="installed_no_config",
                ))
            else:
                agent_results.append(AgentConfigResult(
                    name=cfg["name"],
                    config_path=str(path),
                    agent_type=cfg["agent_type"],
                    mcp_servers=0,
                    skills_count=0,
                    status="not_installed",
                ))
            continue

        # Parse config file
        try:
            raw_text = path.read_text(encoding="utf-8")
            fmt = cfg.get("format")
            if fmt == "toml":
                try:
                    import tomllib
                except ImportError:
                    import tomli as tomllib  # type: ignore[no-redef]
                data = tomllib.loads(raw_text)
            elif fmt == "yaml":
                import yaml
                data = yaml.safe_load(raw_text) or {}
            else:
                # Only strip comments for configs known to use JSONC (VS Code-style).
                # Plain JSON files (Claude, Gemini, etc.) should not be modified
                # as the comment regex can mangle URLs containing //.
                if cfg.get("format") == "jsonc":
                    raw_text = _strip_json_comments(raw_text)
                data = json.loads(raw_text)
        except Exception:
            agent_results.append(AgentConfigResult(
                name=cfg["name"],
                config_path=str(path),
                agent_type=cfg["agent_type"],
                mcp_servers=0,
                skills_count=0,
                status="error",
            ))
            continue

        # Extract MCP servers
        mcp_key = cfg.get("mcp_key")
        if mcp_key is None:
            # Agent exists but has no MCP support (e.g., Aider)
            mcp_servers = {}
        elif "." in mcp_key:
            # Dotted key like "amp.mcpServers" — traverse nested dict
            parts = mcp_key.split(".")
            node = data
            for part in parts:
                node = node.get(part, {}) if isinstance(node, dict) else {}
            mcp_servers = node
        else:
            mcp_servers = data.get(mcp_key, {})
        server_count = 0

        if isinstance(mcp_servers, dict):
            for srv_name, srv_cfg in mcp_servers.items():
                if not isinstance(srv_cfg, dict):
                    continue
                # Normalize non-standard key names (Goose uses cmd/envs)
                normalized = dict(srv_cfg)
                if "cmd" in normalized and "command" not in normalized:
                    normalized["command"] = normalized.pop("cmd")
                if "envs" in normalized and "env" not in normalized:
                    normalized["env"] = normalized.pop("envs")
                all_mcp_servers.append({
                    "name": srv_name,
                    "source_file": str(path),
                    "agent_type": cfg["agent_type"],
                    **normalized,
                })
                server_count += 1

        # Extract skills path if configured (e.g., OpenClaw)
        skills_key = cfg.get("skills_dir_key")
        if skills_key and skills_key in data:
            sp = Path(str(data[skills_key])).expanduser()
            # Only scan if it's a real directory (not a symlink to avoid traversal)
            if sp.is_dir() and not sp.is_symlink():
                try:
                    for f in sp.rglob("SKILL.md"):
                        if f.is_file() and not f.is_symlink():
                            all_skill_paths.append(f)
                except OSError:
                    pass

        agent_results.append(AgentConfigResult(
            name=cfg["name"],
            config_path=str(path),
            agent_type=cfg["agent_type"],
            mcp_servers=server_count,
            skills_count=0,  # Updated later from skill scan
            status="found",
        ))

    # Check well-known skill directories
    seen_skill_paths: set[str] = set()

    for skill_dir_rel in _SKILL_DIRS:
        skill_dir = home / skill_dir_rel
        if skill_dir.is_dir() and not skill_dir.is_symlink():
            for pattern in ["SKILL.md", "*.md"]:
                try:
                    for f in skill_dir.rglob(pattern):
                        # Skip symlinks (prevent loops), oversized files, non-files
                        if f.is_symlink() or not f.is_file():
                            continue
                        try:
                            if f.stat().st_size > _MAX_SKILL_SIZE:
                                continue
                        except OSError:
                            continue
                        resolved = str(f.resolve())
                        if resolved not in seen_skill_paths:
                            seen_skill_paths.add(resolved)
                            all_skill_paths.append(f)
                except OSError:
                    continue  # Permission denied or deleted mid-scan

    # Check well-known single skill files
    for skill_file_rel in _SKILL_FILES:
        skill_file = home / skill_file_rel
        if skill_file.is_file():
            resolved = str(skill_file.resolve())
            if resolved not in seen_skill_paths:
                seen_skill_paths.add(resolved)
                all_skill_paths.append(skill_file)

    # Check cwd for skill files (guard against deleted cwd)
    try:
        cwd = Path.cwd()
    except OSError:
        cwd = None

    if cwd:
        # Skill files in CWD
        for cwd_file in _PROJECT_SKILL_FILES:
            candidate = cwd / cwd_file
            if candidate.is_file():
                resolved = str(candidate.resolve())
                if resolved not in seen_skill_paths:
                    seen_skill_paths.add(resolved)
                    all_skill_paths.append(candidate)

        # Also scan .clinerules-* pattern files (Roo Code custom modes)
        try:
            for f in cwd.glob(".clinerules-*"):
                if f.is_file() and not f.is_symlink():
                    resolved = str(f.resolve())
                    if resolved not in seen_skill_paths:
                        seen_skill_paths.add(resolved)
                        all_skill_paths.append(f)
        except OSError:
            pass

        # Skill dirs in CWD
        for cwd_skill_dir in _PROJECT_SKILL_DIRS:
            skill_dir = cwd / cwd_skill_dir
            if skill_dir.is_dir() and not skill_dir.is_symlink():
                try:
                    for f in skill_dir.rglob("*.md"):
                        if f.is_symlink() or not f.is_file():
                            continue
                        resolved = str(f.resolve())
                        if resolved not in seen_skill_paths:
                            seen_skill_paths.add(resolved)
                            all_skill_paths.append(f)
                except OSError:
                    pass

        # Project-level MCP configs in CWD
        for rel_path, mcp_key, fmt in _PROJECT_MCP_CONFIGS:
            mcp_file = cwd / rel_path
            if not mcp_file.is_file():
                continue
            try:
                raw = mcp_file.read_text(encoding="utf-8")
                if fmt == "jsonc":
                    raw = _strip_json_comments(raw)
                data = json.loads(raw)
                servers = data.get(mcp_key, {})
                if isinstance(servers, dict):
                    for srv_name, srv_cfg in servers.items():
                        if not isinstance(srv_cfg, dict):
                            continue
                        all_mcp_servers.append({
                            "name": srv_name,
                            "source_file": str(mcp_file),
                            "agent_type": "project",
                            **srv_cfg,
                        })
            except Exception:
                continue

    # Deduplicate MCP servers by (name, command_or_url) tuple
    seen_servers: set[tuple[str, str]] = set()
    unique_servers: list[dict] = []
    for srv in all_mcp_servers:
        cmd = srv.get("command", "") or srv.get("url", "")
        identifier = " ".join(cmd) if isinstance(cmd, list) else str(cmd)
        key = (srv.get("name", ""), identifier)
        if key not in seen_servers:
            seen_servers.add(key)
            unique_servers.append(srv)

    return agent_results, unique_servers, all_skill_paths


def scan_directory(directory: Path) -> tuple[
    list[AgentConfigResult],
    list[dict],
    list[Path],
]:
    """Scan a specific project directory for MCP configs and skill files.

    Unlike scan_machine(), this only looks within the given directory —
    no global agent configs or home-directory skill paths.
    """
    directory = Path(directory).resolve()
    if not directory.is_dir():
        return [], [], []

    all_mcp_servers: list[dict] = []
    all_skill_paths: list[Path] = []
    seen_skill_paths: set[str] = set()

    # Project-level MCP configs
    for rel_path, mcp_key, fmt in _PROJECT_MCP_CONFIGS:
        mcp_file = directory / rel_path
        if not mcp_file.is_file():
            continue
        try:
            raw = mcp_file.read_text(encoding="utf-8")
            if fmt == "jsonc":
                raw = _strip_json_comments(raw)
            data = json.loads(raw)
            servers = data.get(mcp_key, {})
            if isinstance(servers, dict):
                for srv_name, srv_cfg in servers.items():
                    if not isinstance(srv_cfg, dict):
                        continue
                    all_mcp_servers.append({
                        "name": srv_name,
                        "source_file": str(mcp_file),
                        "agent_type": "project",
                        **srv_cfg,
                    })
        except Exception:
            continue

    # Skill files
    for skill_file_rel in _PROJECT_SKILL_FILES:
        candidate = directory / skill_file_rel
        if candidate.is_file():
            resolved = str(candidate.resolve())
            if resolved not in seen_skill_paths:
                seen_skill_paths.add(resolved)
                all_skill_paths.append(candidate)

    # .clinerules-* pattern
    try:
        for f in directory.glob(".clinerules-*"):
            if f.is_file() and not f.is_symlink():
                resolved = str(f.resolve())
                if resolved not in seen_skill_paths:
                    seen_skill_paths.add(resolved)
                    all_skill_paths.append(f)
    except OSError:
        pass

    # Skill dirs
    for skill_dir_rel in _PROJECT_SKILL_DIRS:
        skill_dir = directory / skill_dir_rel
        if skill_dir.is_dir() and not skill_dir.is_symlink():
            try:
                for f in skill_dir.rglob("*.md"):
                    if f.is_symlink() or not f.is_file():
                        continue
                    resolved = str(f.resolve())
                    if resolved not in seen_skill_paths:
                        seen_skill_paths.add(resolved)
                        all_skill_paths.append(f)
            except OSError:
                pass

    # Return empty agents list (we're scanning a project, not the machine)
    return [], all_mcp_servers, all_skill_paths
