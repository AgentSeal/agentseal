/**
 * .agentseal.yaml project config loader, resolution, and filtering.
 *
 * Port of Python agentseal/project_config.py — same structure, TypeScript implementation.
 */

import { existsSync, readFileSync, writeFileSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { parse } from "yaml";
import type { AgentConfigResult, UnlistedFinding } from "./guard-models.js";

// ═══════════════════════════════════════════════════════════════════════
// INTERFACES
// ═══════════════════════════════════════════════════════════════════════

export interface IgnoreFindingEntry {
  id: string;
  reason?: string;
}

export interface ProjectConfig {
  fail_on: string;              // "danger" | "warning" | "safe", default: "danger"
  allowed_agents: string[];
  allowed_mcp_servers: string[];
  ignore_paths: string[];
  ignore_findings: IgnoreFindingEntry[];
  rules_paths: string[];
  config_path: string;          // resolved absolute path of loaded config
}

// ═══════════════════════════════════════════════════════════════════════
// CONSTANTS
// ═══════════════════════════════════════════════════════════════════════

const VALID_FAIL_ON = new Set(["danger", "warning", "safe"]);
const CONFIG_FILENAME = ".agentseal.yaml";
const KNOWN_KEYS = new Set([
  "fail_on",
  "allowed_agents",
  "allowed_mcp_servers",
  "ignore_paths",
  "ignore_findings",
  "rules_paths",
]);

// ═══════════════════════════════════════════════════════════════════════
// loadProjectConfig
// ═══════════════════════════════════════════════════════════════════════

/**
 * Parse a .agentseal.yaml file and return a validated ProjectConfig.
 * Throws on invalid YAML, invalid fail_on, or non-dict root.
 */
export function loadProjectConfig(configPath: string): ProjectConfig {
  const raw = readFileSync(configPath, "utf-8");
  let data: unknown;
  try {
    data = parse(raw);
  } catch (err) {
    throw new Error(`Invalid YAML in ${configPath}: ${err}`);
  }

  // Empty file parses as null/undefined — treat as empty dict
  if (data === null || data === undefined) {
    data = {};
  }

  if (typeof data !== "object" || Array.isArray(data)) {
    throw new Error(`Expected a YAML mapping (dict) at root of ${configPath}, got ${Array.isArray(data) ? "array" : typeof data}`);
  }

  const d = data as Record<string, unknown>;

  // Warn on unknown keys
  for (const key of Object.keys(d)) {
    if (!KNOWN_KEYS.has(key)) {
      console.error(`Warning: unknown key '${key}' in ${configPath}`);
    }
  }

  // Validate fail_on
  const failOn = (d.fail_on as string) ?? "danger";
  if (!VALID_FAIL_ON.has(failOn)) {
    throw new Error(`Invalid fail_on value '${failOn}' in ${configPath}. Must be one of: danger, warning, safe`);
  }

  // Coerce null/undefined to empty arrays
  const allowedAgents: string[] = (d.allowed_agents as string[]) ?? [];
  const allowedMcpServers: string[] = (d.allowed_mcp_servers as string[]) ?? [];
  const ignorePaths: string[] = (d.ignore_paths as string[]) ?? [];
  const rulesPaths: string[] = (d.rules_paths as string[]) ?? [];

  // Parse ignore_findings with warning for missing reason
  const rawFindings = (d.ignore_findings as Array<Record<string, unknown>>) ?? [];
  const ignoreFindings: IgnoreFindingEntry[] = [];
  for (const entry of rawFindings) {
    if (typeof entry === "object" && entry !== null && "id" in entry) {
      const item: IgnoreFindingEntry = { id: String(entry.id) };
      if (entry.reason !== undefined && entry.reason !== null) {
        item.reason = String(entry.reason);
      } else {
        console.error(`Warning: ignore_findings entry '${item.id}' is missing a 'reason' field in ${configPath}`);
      }
      ignoreFindings.push(item);
    }
  }

  return {
    fail_on: failOn,
    allowed_agents: allowedAgents,
    allowed_mcp_servers: allowedMcpServers,
    ignore_paths: ignorePaths,
    ignore_findings: ignoreFindings,
    rules_paths: rulesPaths,
    config_path: resolve(configPath),
  };
}

// ═══════════════════════════════════════════════════════════════════════
// resolveProjectConfig
// ═══════════════════════════════════════════════════════════════════════

/**
 * Resolve project config by explicit path or by walking up from searchDir.
 * Returns null if no config found.
 */
export function resolveProjectConfig(opts?: {
  configPath?: string;
  searchDir?: string;
}): ProjectConfig | null {
  const { configPath, searchDir } = opts ?? {};

  if (configPath) {
    if (!existsSync(configPath)) {
      throw new Error(`Config file not found: ${configPath}`);
    }
    return loadProjectConfig(configPath);
  }

  const startDir = resolve(searchDir ?? process.cwd());
  const home = homedir();
  const root = resolve("/");
  let current = startDir;

  while (true) {
    // Check for config in current dir
    const candidate = join(current, CONFIG_FILENAME);
    if (existsSync(candidate)) {
      try {
        return loadProjectConfig(candidate);
      } catch {
        // If the file is invalid, skip it
      }
    }

    // Check stop conditions AFTER checking for config in current dir
    // Stop if we found a .git directory (project boundary)
    const gitDir = join(current, ".git");
    if (_isDirectory(gitDir)) {
      return null;
    }

    // Stop at HOME
    if (current === home) {
      return null;
    }

    // Stop at filesystem root
    const parent = dirname(current);
    if (parent === current) {
      return null;
    }

    current = parent;
  }
}

function _isDirectory(p: string): boolean {
  try {
    return statSync(p).isDirectory();
  } catch {
    return false;
  }
}

// ═══════════════════════════════════════════════════════════════════════
// shouldIgnorePath
// ═══════════════════════════════════════════════════════════════════════

/**
 * Check if a file path should be ignored based on config.ignore_paths.
 * Splits path on "/" and checks if ANY segment exactly matches an ignore entry.
 */
export function shouldIgnorePath(config: ProjectConfig, path: string): boolean {
  if (config.ignore_paths.length === 0) return false;
  const segments = path.split("/");
  const ignoreSet = new Set(config.ignore_paths);
  return segments.some((seg) => ignoreSet.has(seg));
}

// ═══════════════════════════════════════════════════════════════════════
// shouldIgnoreFinding
// ═══════════════════════════════════════════════════════════════════════

/**
 * Check if a finding should be ignored based on config.ignore_findings.
 * Entry id can be bare code ("SKILL-001") or code:path ("SKILL-001:./file.md").
 */
export function shouldIgnoreFinding(
  config: ProjectConfig,
  code: string,
  path?: string,
): boolean {
  for (const entry of config.ignore_findings) {
    const colonIdx = entry.id.indexOf(":");
    if (colonIdx === -1) {
      // Bare code — matches any path
      if (entry.id === code) return true;
    } else {
      // code:path — must match both
      const entryCode = entry.id.slice(0, colonIdx);
      const entryPath = entry.id.slice(colonIdx + 1);
      if (entryCode === code && path !== undefined && entryPath === path) {
        return true;
      }
    }
  }
  return false;
}

// ═══════════════════════════════════════════════════════════════════════
// shouldFail
// ═══════════════════════════════════════════════════════════════════════

/**
 * Determine if the scan should fail based on fail_on level and verdicts.
 */
export function shouldFail(
  failOn: string,
  verdicts: { hasDanger: boolean; hasWarning: boolean; hasSafe?: boolean },
): boolean {
  switch (failOn) {
    case "danger":
      return verdicts.hasDanger;
    case "warning":
      return verdicts.hasDanger || verdicts.hasWarning;
    case "safe":
      return verdicts.hasDanger || verdicts.hasWarning || (verdicts.hasSafe ?? false);
    default:
      return verdicts.hasDanger;
  }
}

// ═══════════════════════════════════════════════════════════════════════
// generateUnlistedFindings
// ═══════════════════════════════════════════════════════════════════════

/**
 * Generate GUARD-001 (unlisted agent) and GUARD-002 (unlisted MCP server) findings.
 * Only checks if the respective allowlist is non-empty.
 */
export function generateUnlistedFindings(
  config: ProjectConfig,
  agents: AgentConfigResult[],
  mcpServers: Record<string, any>[],
): UnlistedFinding[] {
  const findings: UnlistedFinding[] = [];

  // Check agents (GUARD-001)
  if (config.allowed_agents.length > 0) {
    const allowedSet = new Set(config.allowed_agents);
    const activeAgents = agents.filter(
      (a) => a.status !== "not_installed" && a.status !== "error",
    );
    for (const agent of activeAgents) {
      if (!allowedSet.has(agent.agent_type)) {
        findings.push({
          code: "GUARD-001",
          title: "Unlisted agent detected",
          description: `Agent '${agent.agent_type}' is not in the allowed_agents list in .agentseal.yaml`,
          severity: "medium",
          item_name: agent.agent_type,
          item_type: "agent",
        });
      }
    }
  }

  // Check MCP servers (GUARD-002)
  if (config.allowed_mcp_servers.length > 0) {
    // Build allowlist sets for both formats: plain name and name@agent_type
    const plainNames = new Set<string>();
    const qualifiedNames = new Set<string>();
    for (const entry of config.allowed_mcp_servers) {
      if (entry.includes("@")) {
        qualifiedNames.add(entry);
      } else {
        plainNames.add(entry);
      }
    }

    for (const srv of mcpServers) {
      const name = srv.name as string;
      const agentType = srv.agent_type as string | undefined;
      const qualified = agentType ? `${name}@${agentType}` : name;

      // Match if plain name is in the list OR if the qualified name is in the list
      if (!plainNames.has(name) && !qualifiedNames.has(qualified)) {
        findings.push({
          code: "GUARD-002",
          title: "Unlisted MCP server detected",
          description: `MCP server '${name}' is not in the allowed_mcp_servers list in .agentseal.yaml`,
          severity: "medium",
          item_name: name,
          item_type: "mcp_server",
        });
      }
    }
  }

  return findings;
}

// ═══════════════════════════════════════════════════════════════════════
// generateConfigYaml
// ═══════════════════════════════════════════════════════════════════════

/**
 * Generate a .agentseal.yaml config string from discovered agents and MCP servers.
 */
export function generateConfigYaml(
  agents: AgentConfigResult[],
  mcpServers: Record<string, any>[],
): string {
  const activeAgents = agents.filter(
    (a) => a.status === "found" || a.status === "installed_no_config",
  );
  const agentTypes = activeAgents.map((a) => a.agent_type);
  const serverNameSet = new Set<string>();
  for (const s of mcpServers) {
    serverNameSet.add(s.name as string);
  }
  const serverNames = Array.from(serverNameSet);

  const agentLines =
    agentTypes.length > 0
      ? agentTypes.map((t) => `  - ${t}`).join("\n")
      : "  # - cursor\n  # - claude-desktop";

  const serverLines =
    serverNames.length > 0
      ? serverNames.map((n) => `  - ${n}`).join("\n")
      : "  # - filesystem\n  # - sqlite";

  return `# AgentSeal project configuration
# https://agentseal.org/docs/config

# Exit code behavior: "danger" (default), "warning", or "safe"
fail_on: danger

# Agents expected on this machine (unlisted agents trigger GUARD-001)
allowed_agents:
${agentLines}

# MCP servers expected (unlisted servers trigger GUARD-002)
# Use "name" or "name@agent_type" for agent-specific allowlisting
allowed_mcp_servers:
${serverLines}

# Paths to ignore during skill scanning (matched by path segment)
ignore_paths:
  - node_modules
  - .git
  - __pycache__

# Findings to ignore (by code, or code:path for file-specific ignores)
ignore_findings: []
  # - id: "SKILL-001"
  #   reason: "Known safe pattern"
  # - id: "MCP-002:./configs/server.json"
  #   reason: "Accepted risk for this file"

# Additional rule directories
rules_paths: []
  # - ./rules
  # - ./custom-rules
`;
}

// ═══════════════════════════════════════════════════════════════════════
// runGuardInit
// ═══════════════════════════════════════════════════════════════════════

/**
 * Initialize a .agentseal.yaml config in the target directory.
 * Returns true if written, false if file exists and not force.
 */
export function runGuardInit(opts?: {
  targetDir?: string;
  force?: boolean;
  interactive?: boolean;
}): boolean {
  const { targetDir, force = false, interactive = true } = opts ?? {};
  const dir = targetDir ?? process.cwd();
  const configFile = join(dir, CONFIG_FILENAME);

  // Check if file already exists
  if (existsSync(configFile) && !force) {
    return false;
  }

  // Discover agents and MCP servers
  let agents: AgentConfigResult[] = [];
  let allMcpServers: Record<string, any>[] = [];

  try {
    // Dynamic import to avoid circular dependency issues at module level
    const { scanMachine, scanDirectory } = require("./machine-discovery.js") as typeof import("./machine-discovery.js");

    const machineResult = scanMachine();
    agents = machineResult.agents;
    allMcpServers = [...machineResult.mcpServers];

    // Also scan the target directory
    const dirResult = scanDirectory(dir);
    // Merge MCP servers, dedup by name+agent_type
    const seen = new Set(allMcpServers.map((s) => `${s.name}::${s.agent_type}`));
    for (const srv of dirResult.mcpServers) {
      const key = `${srv.name}::${srv.agent_type}`;
      if (!seen.has(key)) {
        seen.add(key);
        allMcpServers.push(srv);
      }
    }
  } catch {
    // If discovery fails, proceed with empty lists
  }

  // Generate and write config
  const yaml = generateConfigYaml(agents, allMcpServers);
  writeFileSync(configFile, yaml, "utf-8");
  return true;
}
