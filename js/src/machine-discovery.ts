/**
 * Machine-level agent discovery — finds ALL AI agents, MCP servers, and skills
 * installed on the user's machine by checking well-known config paths.
 *
 * Port of Python agentseal/machine_discovery.py — same locations, same logic.
 */

import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import type { AgentConfigResult } from "./guard-models.js";

// ═══════════════════════════════════════════════════════════════════════
// CONSTANTS
// ═══════════════════════════════════════════════════════════════════════

const MAX_SKILL_SIZE = 10 * 1024 * 1024; // 10 MB

/** Project-level MCP config definitions. [relPath, mcpKey, format] */
export const PROJECT_MCP_CONFIGS: Array<[string, string, string | null]> = [
  [".mcp.json", "mcpServers", null],
  [".cursor/mcp.json", "mcpServers", null],
  [".vscode/mcp.json", "servers", "jsonc"],
  ["mcp_config.json", "servers", null],
  ["mcp.json", "mcpServers", null],
  [".kiro/settings/mcp.json", "mcpServers", null],
  [".kilocode/mcp.json", "mcpServers", null],
  [".roo/mcp.json", "mcpServers", null],
  [".trae/mcp.json", "mcpServers", null],
  [".amazonq/mcp.json", "mcpServers", null],
  [".copilot/mcp-config.json", "mcpServers", null],
  [".junie/mcp/mcp.json", "mcpServers", null],
  [".grok/settings.json", "mcpServers", null],
];

/** Project-level skill files. */
export const PROJECT_SKILL_FILES: string[] = [
  ".cursorrules",
  ".windsurfrules",
  "CLAUDE.md",
  ".claude/CLAUDE.md",
  "AGENTS.md",
  ".github/copilot-instructions.md",
  "GEMINI.md",
  ".junie/guidelines.md",
  ".roomodes",
];

/** Project-level skill directories. */
export const PROJECT_SKILL_DIRS: string[] = [
  ".cursor/rules",
  ".roo/rules",
  ".kiro/rules",
  ".trae/rules",
  ".junie/rules",
  ".qwen/skills",
  ".windsurf/rules",
];

/** Well-known skill directories in $HOME. */
const SKILL_DIRS: string[] = [
  ".openclaw/skills",
  ".openclaw/workspace/skills",
  ".cursor/rules",
  ".roo/rules",
  ".continue/rules",
  ".trae/rules",
  ".kiro/rules",
  ".qwen/skills",
];

/** Well-known single skill files in $HOME. */
const SKILL_FILES: string[] = [
  ".cursorrules",
  ".claude/CLAUDE.md",
  ".github/copilot-instructions.md",
  ".windsurfrules",
  "AGENTS.md",
  "CLAUDE.md",
  "GEMINI.md",
];

// ═══════════════════════════════════════════════════════════════════════
// AGENT CONFIG DEFINITIONS
// ═══════════════════════════════════════════════════════════════════════

interface AgentDef {
  name: string;
  agent_type: string;
  paths: Record<string, string | null>;
  mcp_key: string | null;
  format?: string;
}

export function getWellKnownConfigs(): AgentDef[] {
  const home = homedir();
  const appdata = process.platform === "win32" ? process.env.APPDATA ?? "" : null;
  const p = (...parts: string[]) => join(home, ...parts);
  const ap = (...parts: string[]) => (appdata ? join(appdata, ...parts) : null);

  // Map process.platform to Python-style names used in path keys
  const sys = process.platform === "darwin" ? "Darwin" : process.platform === "win32" ? "Windows" : "Linux";

  const configs: AgentDef[] = [
    {
      name: "Claude Desktop",
      agent_type: "claude-desktop",
      paths: {
        Darwin: p("Library", "Application Support", "Claude", "claude_desktop_config.json"),
        Windows: ap("Claude", "claude_desktop_config.json"),
        Linux: p(".config", "Claude", "claude_desktop_config.json"),
      },
      mcp_key: "mcpServers",
    },
    {
      name: "Claude Code",
      agent_type: "claude-code",
      paths: { all: p(".claude.json") },
      mcp_key: "mcpServers",
    },
    {
      name: "Cursor",
      agent_type: "cursor",
      paths: { all: p(".cursor", "mcp.json") },
      mcp_key: "mcpServers",
    },
    {
      name: "Windsurf",
      agent_type: "windsurf",
      paths: {
        Darwin: p(".codeium", "windsurf", "mcp_config.json"),
        Windows: p(".codeium", "windsurf", "mcp_config.json"),
        Linux: p(".codeium", "windsurf", "mcp_config.json"),
      },
      mcp_key: "mcpServers",
    },
    {
      name: "VS Code",
      agent_type: "vscode",
      paths: {
        Darwin: p("Library", "Application Support", "Code", "User", "mcp.json"),
        Windows: ap("Code", "User", "mcp.json"),
        Linux: p(".config", "Code", "User", "mcp.json"),
      },
      mcp_key: "servers",
      format: "jsonc",
    },
    {
      name: "Gemini CLI",
      agent_type: "gemini-cli",
      paths: { all: p(".gemini", "settings.json") },
      mcp_key: "mcpServers",
    },
    {
      name: "Codex CLI",
      agent_type: "codex",
      paths: { all: p(".codex", "config.toml") },
      mcp_key: "mcp_servers",
      format: "toml",
    },
    {
      name: "OpenClaw",
      agent_type: "openclaw",
      paths: { all: p(".openclaw", "openclaw.json") },
      mcp_key: "mcpServers",
      format: "jsonc",
    },
    {
      name: "Kiro",
      agent_type: "kiro",
      paths: { all: p(".kiro", "settings", "mcp.json") },
      mcp_key: "mcpServers",
    },
    {
      name: "OpenCode",
      agent_type: "opencode",
      paths: {
        Darwin: p(".config", "opencode", "opencode.json"),
        Linux: p(".config", "opencode", "opencode.json"),
        Windows: ap("opencode", "opencode.json"),
      },
      mcp_key: "mcp",
    },
    {
      name: "Continue",
      agent_type: "continue",
      paths: { all: p(".continue", "config.yaml") },
      mcp_key: "mcpServers",
      format: "yaml",
    },
    {
      name: "Cline",
      agent_type: "cline",
      paths: {
        Darwin: p("Library", "Application Support", "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json"),
        Windows: ap("Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json"),
        Linux: p(".config", "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json"),
      },
      mcp_key: "mcpServers",
    },
    {
      name: "Roo Code",
      agent_type: "roo-code",
      paths: {
        Darwin: p("Library", "Application Support", "Code", "User", "globalStorage", "rooveterinaryinc.roo-cline", "settings", "mcp_settings.json"),
        Windows: ap("Code", "User", "globalStorage", "rooveterinaryinc.roo-cline", "settings", "mcp_settings.json"),
        Linux: p(".config", "Code", "User", "globalStorage", "rooveterinaryinc.roo-cline", "settings", "mcp_settings.json"),
      },
      mcp_key: "mcpServers",
    },
    {
      name: "Kilo Code",
      agent_type: "kilo-code",
      paths: {
        Darwin: p("Library", "Application Support", "Code", "User", "globalStorage", "kilocode.kilo", "mcp_settings.json"),
        Windows: ap("Code", "User", "globalStorage", "kilocode.kilo", "mcp_settings.json"),
        Linux: p(".config", "Code", "User", "globalStorage", "kilocode.kilo", "mcp_settings.json"),
      },
      mcp_key: "mcpServers",
    },
    {
      name: "Zed",
      agent_type: "zed",
      paths: {
        Darwin: p(".zed", "settings.json"),
        Linux: p(".config", "zed", "settings.json"),
        Windows: ap("Zed", "settings.json"),
      },
      mcp_key: "context_servers",
      format: "jsonc",
    },
    {
      name: "Amp",
      agent_type: "amp",
      paths: {
        Darwin: p(".config", "amp", "settings.json"),
        Linux: p(".config", "amp", "settings.json"),
        Windows: ap("amp", "settings.json"),
      },
      mcp_key: "amp.mcpServers",
    },
    {
      name: "Aider",
      agent_type: "aider",
      paths: { all: p(".aider.conf.yml") },
      mcp_key: null,
    },
    {
      name: "Amazon Q",
      agent_type: "amazon-q",
      paths: { all: p(".aws", "amazonq", "mcp.json") },
      mcp_key: "mcpServers",
    },
    {
      name: "Copilot CLI",
      agent_type: "copilot-cli",
      paths: { all: p(".copilot", "mcp-config.json") },
      mcp_key: "mcpServers",
    },
    {
      name: "Junie",
      agent_type: "junie",
      paths: { all: p(".junie", "mcp", "mcp.json") },
      mcp_key: "mcpServers",
    },
    {
      name: "Goose",
      agent_type: "goose",
      paths: {
        Darwin: p(".config", "goose", "config.yaml"),
        Linux: p(".config", "goose", "config.yaml"),
      },
      mcp_key: "extensions",
      format: "yaml",
    },
    {
      name: "Crush",
      agent_type: "crush",
      paths: { all: p(".config", "crush", "crush.json") },
      mcp_key: "mcp",
    },
    {
      name: "Qwen Code",
      agent_type: "qwen-code",
      paths: { all: p(".qwen", "settings.json") },
      mcp_key: "mcpServers",
    },
    {
      name: "Grok CLI",
      agent_type: "grok-cli",
      paths: { all: p(".grok", "user-settings.json") },
      mcp_key: "mcpServers",
    },
    {
      name: "Visual Studio",
      agent_type: "visual-studio",
      paths: { Windows: p(".mcp.json") },
      mcp_key: "servers",
    },
    {
      name: "Kimi CLI",
      agent_type: "kimi-cli",
      paths: { all: p(".kimi", "mcp.json") },
      mcp_key: "mcpServers",
    },
    {
      name: "Trae",
      agent_type: "trae",
      paths: {
        Darwin: p("Library", "Application Support", "Trae", "mcp_config.json"),
        Linux: p(".config", "Trae", "mcp_config.json"),
      },
      mcp_key: "mcpServers",
    },
    {
      name: "MaxClaw",
      agent_type: "maxclaw",
      paths: { all: p(".maxclaw", "config.json") },
      mcp_key: "mcpServers",
    },
  ];

  // Resolve paths for current platform
  return configs.map((cfg) => ({
    ...cfg,
    paths: Object.fromEntries(
      Object.entries(cfg.paths).filter(([, v]) => v !== null),
    ),
  }));
}

// ═══════════════════════════════════════════════════════════════════════
// JSONC COMMENT STRIPPING
// ═══════════════════════════════════════════════════════════════════════

/** Strip // and /* * / comments from JSONC. Preserves URLs inside strings. */
export function stripJsonComments(text: string): string {
  const result: string[] = [];
  let i = 0;
  const n = text.length;

  while (i < n) {
    if (text[i] === '"') {
      // String literal — consume including escapes
      let j = i + 1;
      while (j < n) {
        if (text[j] === "\\") {
          j += 2;
        } else if (text[j] === '"') {
          j += 1;
          break;
        } else {
          j += 1;
        }
      }
      result.push(text.slice(i, j));
      i = j;
    } else if (text.slice(i, i + 2) === "//") {
      while (i < n && text[i] !== "\n") i++;
    } else if (text.slice(i, i + 2) === "/*") {
      i += 2;
      while (i < n - 1 && text.slice(i, i + 2) !== "*/") i++;
      if (i < n - 1) i += 2;
    } else {
      result.push(text[i]!);
      i += 1;
    }
  }
  return result.join("");
}

// ═══════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════

function isFile(p: string): boolean {
  try {
    return statSync(p).isFile();
  } catch {
    return false;
  }
}

function isDir(p: string): boolean {
  try {
    return statSync(p).isDirectory();
  } catch {
    return false;
  }
}

/** Recursively glob for files matching a pattern in a directory. */
function rglob(dir: string, patterns: string[]): string[] {
  const results: string[] = [];
  const _walk = (d: string) => {
    let entries: string[];
    try {
      entries = readdirSync(d);
    } catch {
      return;
    }
    for (const entry of entries) {
      const full = join(d, entry);
      try {
        const st = statSync(full);
        if (st.isDirectory()) {
          _walk(full);
        } else if (st.isFile()) {
          for (const pat of patterns) {
            if (pat === "*.md" && entry.endsWith(".md")) {
              results.push(full);
              break;
            } else if (pat === "SKILL.md" && entry === "SKILL.md") {
              results.push(full);
              break;
            } else if (entry === pat) {
              results.push(full);
              break;
            }
          }
        }
      } catch {
        continue;
      }
    }
  };
  _walk(dir);
  return results;
}

/** Glob for files matching a prefix pattern (e.g., ".clinerules-*"). */
function globPrefix(dir: string, prefix: string): string[] {
  try {
    return readdirSync(dir)
      .filter((f) => f.startsWith(prefix))
      .map((f) => join(dir, f))
      .filter((f) => isFile(f));
  } catch {
    return [];
  }
}

function readJsonSafe(path: string, format?: string | null): Record<string, any> | null {
  try {
    let raw = readFileSync(path, "utf-8");
    if (format === "jsonc") {
      raw = stripJsonComments(raw);
    }
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

// ═══════════════════════════════════════════════════════════════════════
// MCP SERVER EXTRACTION
// ═══════════════════════════════════════════════════════════════════════

interface MCPServerConfig {
  name: string;
  source_file: string;
  agent_type: string;
  [key: string]: unknown;
}

function extractMCPServers(
  data: Record<string, any>,
  mcpKey: string | null,
  sourceFile: string,
  agentType: string,
): MCPServerConfig[] {
  if (mcpKey === null) return [];

  let servers: any;
  if (mcpKey.includes(".")) {
    const parts = mcpKey.split(".");
    let node: any = data;
    for (const part of parts) {
      node = node && typeof node === "object" ? node[part] : undefined;
    }
    servers = node ?? {};
  } else {
    servers = data[mcpKey] ?? {};
  }

  const results: MCPServerConfig[] = [];
  if (typeof servers === "object" && servers !== null && !Array.isArray(servers)) {
    for (const [srvName, srvCfg] of Object.entries(servers)) {
      if (typeof srvCfg !== "object" || srvCfg === null) continue;
      const normalized = { ...(srvCfg as Record<string, any>) };
      // Normalize Goose keys
      if ("cmd" in normalized && !("command" in normalized)) {
        normalized.command = normalized.cmd;
        delete normalized.cmd;
      }
      if ("envs" in normalized && !("env" in normalized)) {
        normalized.env = normalized.envs;
        delete normalized.envs;
      }
      results.push({
        name: srvName,
        source_file: sourceFile,
        agent_type: agentType,
        ...normalized,
      });
    }
  }
  return results;
}

// ═══════════════════════════════════════════════════════════════════════
// MAIN DISCOVERY FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════

export interface DiscoveryResult {
  agents: AgentConfigResult[];
  mcpServers: MCPServerConfig[];
  skillPaths: string[];
}

/**
 * Discover all AI agents, MCP servers, and skills on this machine.
 * Scans well-known config paths + CWD.
 */
export function scanMachine(): DiscoveryResult {
  const sys = process.platform === "darwin" ? "Darwin" : process.platform === "win32" ? "Windows" : "Linux";
  const home = homedir();
  const configs = getWellKnownConfigs();

  const agents: AgentConfigResult[] = [];
  const allMCPServers: MCPServerConfig[] = [];
  const allSkillPaths: string[] = [];
  const seenSkillPaths = new Set<string>();

  for (const cfg of configs) {
    const path = cfg.paths[sys] ?? cfg.paths["all"] ?? null;
    if (path === null) continue;

    if (!isFile(path)) {
      const dir = dirname(path);
      if (isDir(dir)) {
        agents.push({
          name: cfg.name,
          config_path: dir,
          agent_type: cfg.agent_type,
          mcp_servers: 0,
          skills_count: 0,
          status: "installed_no_config",
        });
      } else {
        agents.push({
          name: cfg.name,
          config_path: path,
          agent_type: cfg.agent_type,
          mcp_servers: 0,
          skills_count: 0,
          status: "not_installed",
        });
      }
      continue;
    }

    // Skip YAML/TOML formats in JS (would need extra deps)
    if (cfg.format === "yaml" || cfg.format === "toml") {
      agents.push({
        name: cfg.name,
        config_path: path,
        agent_type: cfg.agent_type,
        mcp_servers: 0,
        skills_count: 0,
        status: "found",
      });
      continue;
    }

    const data = readJsonSafe(path, cfg.format);
    if (data === null) {
      agents.push({
        name: cfg.name,
        config_path: path,
        agent_type: cfg.agent_type,
        mcp_servers: 0,
        skills_count: 0,
        status: "error",
      });
      continue;
    }

    const servers = extractMCPServers(data, cfg.mcp_key, path, cfg.agent_type);
    allMCPServers.push(...servers);

    agents.push({
      name: cfg.name,
      config_path: path,
      agent_type: cfg.agent_type,
      mcp_servers: servers.length,
      skills_count: 0,
      status: "found",
    });
  }

  // Well-known skill directories
  for (const skillDirRel of SKILL_DIRS) {
    const skillDir = join(home, skillDirRel);
    if (isDir(skillDir)) {
      for (const f of rglob(skillDir, ["SKILL.md", "*.md"])) {
        try {
          if (statSync(f).size > MAX_SKILL_SIZE) continue;
        } catch {
          continue;
        }
        const resolved = resolve(f);
        if (!seenSkillPaths.has(resolved)) {
          seenSkillPaths.add(resolved);
          allSkillPaths.push(f);
        }
      }
    }
  }

  // Well-known single skill files
  for (const skillFileRel of SKILL_FILES) {
    const skillFile = join(home, skillFileRel);
    if (isFile(skillFile)) {
      const resolved = resolve(skillFile);
      if (!seenSkillPaths.has(resolved)) {
        seenSkillPaths.add(resolved);
        allSkillPaths.push(skillFile);
      }
    }
  }

  // CWD scanning
  let cwd: string | null;
  try {
    cwd = process.cwd();
  } catch {
    cwd = null;
  }

  if (cwd) {
    _scanProjectDir(cwd, allMCPServers, allSkillPaths, seenSkillPaths);
  }

  // Deduplicate MCP servers
  const seenServers = new Set<string>();
  const uniqueServers: MCPServerConfig[] = [];
  for (const srv of allMCPServers) {
    const cmd = srv.command ?? srv.url ?? "";
    const id = Array.isArray(cmd) ? cmd.join(" ") : String(cmd);
    const key = `${srv.name}::${id}`;
    if (!seenServers.has(key)) {
      seenServers.add(key);
      uniqueServers.push(srv);
    }
  }

  return { agents, mcpServers: uniqueServers, skillPaths: allSkillPaths };
}

/**
 * Scan a specific project directory for MCP configs and skill files.
 * Unlike scanMachine(), this only looks within the given directory.
 */
export function scanDirectory(directory: string): DiscoveryResult {
  const dir = resolve(directory);
  if (!isDir(dir)) return { agents: [], mcpServers: [], skillPaths: [] };

  const mcpServers: MCPServerConfig[] = [];
  const skillPaths: string[] = [];
  const seenSkillPaths = new Set<string>();

  _scanProjectDir(dir, mcpServers, skillPaths, seenSkillPaths);

  return { agents: [], mcpServers, skillPaths };
}

function _scanProjectDir(
  dir: string,
  mcpServers: MCPServerConfig[],
  skillPaths: string[],
  seenSkillPaths: Set<string>,
): void {
  // Project-level MCP configs
  for (const [relPath, mcpKey, fmt] of PROJECT_MCP_CONFIGS) {
    const mcpFile = join(dir, relPath);
    if (!isFile(mcpFile)) continue;
    const data = readJsonSafe(mcpFile, fmt);
    if (data === null) continue;
    const servers = data[mcpKey];
    if (typeof servers === "object" && servers !== null && !Array.isArray(servers)) {
      for (const [srvName, srvCfg] of Object.entries(servers)) {
        if (typeof srvCfg !== "object" || srvCfg === null) continue;
        mcpServers.push({
          name: srvName,
          source_file: mcpFile,
          agent_type: "project",
          ...(srvCfg as Record<string, any>),
        });
      }
    }
  }

  // Skill files
  for (const skillFileRel of PROJECT_SKILL_FILES) {
    const candidate = join(dir, skillFileRel);
    if (isFile(candidate)) {
      const resolved = resolve(candidate);
      if (!seenSkillPaths.has(resolved)) {
        seenSkillPaths.add(resolved);
        skillPaths.push(candidate);
      }
    }
  }

  // .clinerules-* files
  for (const f of globPrefix(dir, ".clinerules-")) {
    const resolved = resolve(f);
    if (!seenSkillPaths.has(resolved)) {
      seenSkillPaths.add(resolved);
      skillPaths.push(f);
    }
  }

  // Skill directories
  for (const skillDirRel of PROJECT_SKILL_DIRS) {
    const skillDir = join(dir, skillDirRel);
    if (isDir(skillDir)) {
      for (const f of rglob(skillDir, ["*.md"])) {
        const resolved = resolve(f);
        if (!seenSkillPaths.has(resolved)) {
          seenSkillPaths.add(resolved);
          skillPaths.push(f);
        }
      }
    }
  }
}
