import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { mkdtempSync, writeFileSync, mkdirSync, existsSync, readFileSync, rmSync } from "node:fs";
import { tmpdir, homedir } from "node:os";
import { join, resolve } from "node:path";

import {
  loadProjectConfig,
  resolveProjectConfig,
  shouldIgnorePath,
  shouldIgnoreFinding,
  shouldFail,
  generateUnlistedFindings,
  generateConfigYaml,
  runGuardInit,
} from "../src/project-config.js";
import type { ProjectConfig } from "../src/project-config.js";
import type { AgentConfigResult } from "../src/guard-models.js";

// ═══════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════

function makeTmpDir(): string {
  return mkdtempSync(join(tmpdir(), "pc-"));
}

function writeYaml(dir: string, filename: string, content: string): string {
  const p = join(dir, filename);
  writeFileSync(p, content, "utf-8");
  return p;
}

function makeAgent(overrides: Partial<AgentConfigResult> = {}): AgentConfigResult {
  return {
    name: "Test Agent",
    config_path: "/tmp/test",
    agent_type: "cursor",
    mcp_servers: 1,
    skills_count: 0,
    status: "found",
    ...overrides,
  };
}

function makeMCPServer(overrides: Record<string, any> = {}): Record<string, any> {
  return {
    name: "test-server",
    agent_type: "cursor",
    command: "npx",
    source_file: "/tmp/config.json",
    ...overrides,
  };
}

// ═══════════════════════════════════════════════════════════════════════
// loadProjectConfig
// ═══════════════════════════════════════════════════════════════════════

describe("loadProjectConfig", () => {
  it("parses valid YAML with all fields", () => {
    const dir = makeTmpDir();
    const yamlContent = `
fail_on: warning
allowed_agents:
  - cursor
  - claude-desktop
allowed_mcp_servers:
  - filesystem
ignore_paths:
  - node_modules
  - .git
ignore_findings:
  - id: "SKILL-001"
    reason: "Known safe"
  - id: "MCP-002"
    reason: "Accepted risk"
rules_paths:
  - ./rules
`;
    const p = writeYaml(dir, ".agentseal.yaml", yamlContent);
    const cfg = loadProjectConfig(p);

    expect(cfg.fail_on).toBe("warning");
    expect(cfg.allowed_agents).toEqual(["cursor", "claude-desktop"]);
    expect(cfg.allowed_mcp_servers).toEqual(["filesystem"]);
    expect(cfg.ignore_paths).toEqual(["node_modules", ".git"]);
    expect(cfg.ignore_findings).toHaveLength(2);
    expect(cfg.ignore_findings[0]!.id).toBe("SKILL-001");
    expect(cfg.ignore_findings[0]!.reason).toBe("Known safe");
    expect(cfg.rules_paths).toEqual(["./rules"]);
    expect(cfg.config_path).toBe(resolve(p));
  });

  it("uses default fail_on='danger' when not specified", () => {
    const dir = makeTmpDir();
    const p = writeYaml(dir, ".agentseal.yaml", "allowed_agents:\n  - cursor\n");
    const cfg = loadProjectConfig(p);
    expect(cfg.fail_on).toBe("danger");
  });

  it("throws on invalid fail_on value", () => {
    const dir = makeTmpDir();
    const p = writeYaml(dir, ".agentseal.yaml", "fail_on: critical\n");
    expect(() => loadProjectConfig(p)).toThrow(/fail_on/);
  });

  it("warns on unknown keys via stderr", () => {
    const dir = makeTmpDir();
    const p = writeYaml(dir, ".agentseal.yaml", "unknown_key: true\nanother_bad: 1\n");
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    const cfg = loadProjectConfig(p);
    expect(spy).toHaveBeenCalledWith(expect.stringContaining("unknown key"));
    expect(spy).toHaveBeenCalledWith(expect.stringContaining("unknown_key"));
    spy.mockRestore();
  });

  it("coerces YAML null/~ values to empty arrays", () => {
    const dir = makeTmpDir();
    const yamlContent = `
fail_on: danger
allowed_agents: ~
allowed_mcp_servers: null
ignore_paths:
ignore_findings: ~
rules_paths: null
`;
    const p = writeYaml(dir, ".agentseal.yaml", yamlContent);
    const cfg = loadProjectConfig(p);
    expect(cfg.allowed_agents).toEqual([]);
    expect(cfg.allowed_mcp_servers).toEqual([]);
    expect(cfg.ignore_paths).toEqual([]);
    expect(cfg.ignore_findings).toEqual([]);
    expect(cfg.rules_paths).toEqual([]);
  });

  it("throws on non-dict root", () => {
    const dir = makeTmpDir();
    const p = writeYaml(dir, ".agentseal.yaml", "- item1\n- item2\n");
    expect(() => loadProjectConfig(p)).toThrow();
  });

  it("throws on invalid YAML syntax", () => {
    const dir = makeTmpDir();
    const p = writeYaml(dir, ".agentseal.yaml", "{ invalid: yaml: : }\n");
    expect(() => loadProjectConfig(p)).toThrow();
  });

  it("warns on ignore_findings entries without reason", () => {
    const dir = makeTmpDir();
    const yamlContent = `
ignore_findings:
  - id: "SKILL-001"
`;
    const p = writeYaml(dir, ".agentseal.yaml", yamlContent);
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    const cfg = loadProjectConfig(p);
    expect(spy).toHaveBeenCalledWith(expect.stringContaining("reason"));
    expect(cfg.ignore_findings).toHaveLength(1);
    spy.mockRestore();
  });

  it("handles empty file as empty dict", () => {
    const dir = makeTmpDir();
    // YAML parse of empty string returns null, which should be treated as empty config
    const p = writeYaml(dir, ".agentseal.yaml", "");
    // empty string YAML parses to null/undefined — treat as empty dict
    const cfg = loadProjectConfig(p);
    expect(cfg.fail_on).toBe("danger");
    expect(cfg.allowed_agents).toEqual([]);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// resolveProjectConfig
// ═══════════════════════════════════════════════════════════════════════

describe("resolveProjectConfig", () => {
  it("loads explicit configPath", () => {
    const dir = makeTmpDir();
    const p = writeYaml(dir, ".agentseal.yaml", "fail_on: warning\n");
    const cfg = resolveProjectConfig({ configPath: p });
    expect(cfg).not.toBeNull();
    expect(cfg!.fail_on).toBe("warning");
  });

  it("throws if explicit configPath does not exist", () => {
    expect(() =>
      resolveProjectConfig({ configPath: "/nonexistent/.agentseal.yaml" })
    ).toThrow();
  });

  it("walks up directories to find config", () => {
    const dir = makeTmpDir();
    writeYaml(dir, ".agentseal.yaml", "fail_on: safe\n");
    const subDir = join(dir, "sub", "deep");
    mkdirSync(subDir, { recursive: true });
    const cfg = resolveProjectConfig({ searchDir: subDir });
    expect(cfg).not.toBeNull();
    expect(cfg!.fail_on).toBe("safe");
  });

  it("stops at .git directory boundary", () => {
    const dir = makeTmpDir();
    // Put config ABOVE the .git dir — should NOT be found
    writeYaml(dir, ".agentseal.yaml", "fail_on: warning\n");
    const projectDir = join(dir, "project");
    mkdirSync(projectDir, { recursive: true });
    mkdirSync(join(projectDir, ".git"), { recursive: true });
    const subDir = join(projectDir, "src");
    mkdirSync(subDir, { recursive: true });
    const cfg = resolveProjectConfig({ searchDir: subDir });
    // Should stop at projectDir (has .git), not find config in dir above
    expect(cfg).toBeNull();
  });

  it("returns null when nothing found", () => {
    const dir = makeTmpDir();
    // Create a .git to stop traversal
    mkdirSync(join(dir, ".git"), { recursive: true });
    const cfg = resolveProjectConfig({ searchDir: dir });
    expect(cfg).toBeNull();
  });

  it("finds config in searchDir itself", () => {
    const dir = makeTmpDir();
    writeYaml(dir, ".agentseal.yaml", "fail_on: danger\n");
    const cfg = resolveProjectConfig({ searchDir: dir });
    expect(cfg).not.toBeNull();
    expect(cfg!.fail_on).toBe("danger");
  });

  it("finds config in dir with .git boundary at same level", () => {
    // Config and .git in same dir — should find config before stopping
    const dir = makeTmpDir();
    writeYaml(dir, ".agentseal.yaml", "fail_on: warning\n");
    mkdirSync(join(dir, ".git"), { recursive: true });
    const cfg = resolveProjectConfig({ searchDir: dir });
    expect(cfg).not.toBeNull();
    expect(cfg!.fail_on).toBe("warning");
  });
});

// ═══════════════════════════════════════════════════════════════════════
// shouldIgnorePath
// ═══════════════════════════════════════════════════════════════════════

describe("shouldIgnorePath", () => {
  const baseConfig: ProjectConfig = {
    fail_on: "danger",
    allowed_agents: [],
    allowed_mcp_servers: [],
    ignore_paths: ["node_modules", ".git", "__pycache__"],
    ignore_findings: [],
    rules_paths: [],
    config_path: "/tmp/.agentseal.yaml",
  };

  it("matches a segment in the middle of a path", () => {
    expect(shouldIgnorePath(baseConfig, "foo/node_modules/bar.md")).toBe(true);
  });

  it("matches a segment at the start", () => {
    expect(shouldIgnorePath(baseConfig, "node_modules/package/index.js")).toBe(true);
  });

  it("matches a segment at the end", () => {
    expect(shouldIgnorePath(baseConfig, "project/.git")).toBe(true);
  });

  it("returns false when no match", () => {
    expect(shouldIgnorePath(baseConfig, "src/utils/helpers.ts")).toBe(false);
  });

  it("returns false with empty ignore_paths", () => {
    const cfg = { ...baseConfig, ignore_paths: [] };
    expect(shouldIgnorePath(cfg, "foo/node_modules/bar.md")).toBe(false);
  });

  it("does not match partial segment names", () => {
    expect(shouldIgnorePath(baseConfig, "my_node_modules_backup/file.ts")).toBe(false);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// shouldIgnoreFinding
// ═══════════════════════════════════════════════════════════════════════

describe("shouldIgnoreFinding", () => {
  const baseConfig: ProjectConfig = {
    fail_on: "danger",
    allowed_agents: [],
    allowed_mcp_servers: [],
    ignore_paths: [],
    ignore_findings: [
      { id: "SKILL-001", reason: "Known safe" },
      { id: "MCP-002:./configs/server.json", reason: "Only this file" },
      { id: "MCP-CVE:2024:./file.md" },
    ],
    rules_paths: [],
    config_path: "/tmp/.agentseal.yaml",
  };

  it("matches bare code against any path", () => {
    expect(shouldIgnoreFinding(baseConfig, "SKILL-001", "./some/file.md")).toBe(true);
  });

  it("matches bare code with no path argument", () => {
    expect(shouldIgnoreFinding(baseConfig, "SKILL-001")).toBe(true);
  });

  it("matches code:path entry when both match", () => {
    expect(shouldIgnoreFinding(baseConfig, "MCP-002", "./configs/server.json")).toBe(true);
  });

  it("does not match code:path entry when code matches but path differs", () => {
    expect(shouldIgnoreFinding(baseConfig, "MCP-002", "./other/file.json")).toBe(false);
  });

  it("returns false when no match", () => {
    expect(shouldIgnoreFinding(baseConfig, "UNKNOWN-999", "./file.md")).toBe(false);
  });

  it("handles colon in code correctly (first-colon split)", () => {
    // "MCP-CVE:2024:./file.md" — first colon at MCP-CVE, rest is 2024:./file.md
    // code part = "MCP-CVE", path part = "2024:./file.md"
    // This should NOT match "MCP-CVE" alone (it has a path constraint)
    expect(shouldIgnoreFinding(baseConfig, "MCP-CVE")).toBe(false);
    // Should match when path is exactly "2024:./file.md"
    expect(shouldIgnoreFinding(baseConfig, "MCP-CVE", "2024:./file.md")).toBe(true);
  });

  it("returns false with empty ignore_findings", () => {
    const cfg = { ...baseConfig, ignore_findings: [] };
    expect(shouldIgnoreFinding(cfg, "SKILL-001")).toBe(false);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// shouldFail
// ═══════════════════════════════════════════════════════════════════════

describe("shouldFail", () => {
  it("danger level fails only on danger", () => {
    expect(shouldFail("danger", { hasDanger: true, hasWarning: false })).toBe(true);
    expect(shouldFail("danger", { hasDanger: false, hasWarning: true })).toBe(false);
    expect(shouldFail("danger", { hasDanger: false, hasWarning: false })).toBe(false);
  });

  it("warning level fails on danger or warning", () => {
    expect(shouldFail("warning", { hasDanger: true, hasWarning: false })).toBe(true);
    expect(shouldFail("warning", { hasDanger: false, hasWarning: true })).toBe(true);
    expect(shouldFail("warning", { hasDanger: false, hasWarning: false })).toBe(false);
  });

  it("safe level fails on danger, warning, or safe", () => {
    expect(shouldFail("safe", { hasDanger: true, hasWarning: false })).toBe(true);
    expect(shouldFail("safe", { hasDanger: false, hasWarning: true })).toBe(true);
    expect(shouldFail("safe", { hasDanger: false, hasWarning: false, hasSafe: true })).toBe(true);
    expect(shouldFail("safe", { hasDanger: false, hasWarning: false, hasSafe: false })).toBe(false);
    expect(shouldFail("safe", { hasDanger: false, hasWarning: false })).toBe(false);
  });

  it("hasSafe defaults to false when undefined", () => {
    expect(shouldFail("safe", { hasDanger: false, hasWarning: false })).toBe(false);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// generateUnlistedFindings
// ═══════════════════════════════════════════════════════════════════════

describe("generateUnlistedFindings", () => {
  it("returns empty when allowlists are empty", () => {
    const cfg: ProjectConfig = {
      fail_on: "danger",
      allowed_agents: [],
      allowed_mcp_servers: [],
      ignore_paths: [],
      ignore_findings: [],
      rules_paths: [],
      config_path: "/tmp/.agentseal.yaml",
    };
    const findings = generateUnlistedFindings(
      cfg,
      [makeAgent({ agent_type: "cursor" })],
      [makeMCPServer({ name: "filesystem" })],
    );
    expect(findings).toEqual([]);
  });

  it("generates GUARD-001 for unlisted agents", () => {
    const cfg: ProjectConfig = {
      fail_on: "danger",
      allowed_agents: ["cursor"],
      allowed_mcp_servers: [],
      ignore_paths: [],
      ignore_findings: [],
      rules_paths: [],
      config_path: "/tmp/.agentseal.yaml",
    };
    const findings = generateUnlistedFindings(
      cfg,
      [makeAgent({ agent_type: "cursor" }), makeAgent({ agent_type: "windsurf", name: "Windsurf" })],
      [],
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]!.code).toBe("GUARD-001");
    expect(findings[0]!.item_name).toBe("windsurf");
    expect(findings[0]!.item_type).toBe("agent");
  });

  it("generates GUARD-002 for unlisted MCP servers", () => {
    const cfg: ProjectConfig = {
      fail_on: "danger",
      allowed_agents: [],
      allowed_mcp_servers: ["filesystem"],
      ignore_paths: [],
      ignore_findings: [],
      rules_paths: [],
      config_path: "/tmp/.agentseal.yaml",
    };
    const findings = generateUnlistedFindings(
      cfg,
      [],
      [makeMCPServer({ name: "filesystem" }), makeMCPServer({ name: "evil-server" })],
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]!.code).toBe("GUARD-002");
    expect(findings[0]!.item_name).toBe("evil-server");
    expect(findings[0]!.item_type).toBe("mcp_server");
  });

  it("filters out not_installed and error agents", () => {
    const cfg: ProjectConfig = {
      fail_on: "danger",
      allowed_agents: ["cursor"],
      allowed_mcp_servers: [],
      ignore_paths: [],
      ignore_findings: [],
      rules_paths: [],
      config_path: "/tmp/.agentseal.yaml",
    };
    const findings = generateUnlistedFindings(
      cfg,
      [
        makeAgent({ agent_type: "cursor" }),
        makeAgent({ agent_type: "windsurf", status: "not_installed" }),
        makeAgent({ agent_type: "vscode", status: "error" }),
      ],
      [],
    );
    expect(findings).toEqual([]);
  });

  it("matches MCP servers by name@agent_type format", () => {
    const cfg: ProjectConfig = {
      fail_on: "danger",
      allowed_agents: [],
      allowed_mcp_servers: ["filesystem@cursor"],
      ignore_paths: [],
      ignore_findings: [],
      rules_paths: [],
      config_path: "/tmp/.agentseal.yaml",
    };
    const findings = generateUnlistedFindings(
      cfg,
      [],
      [
        makeMCPServer({ name: "filesystem", agent_type: "cursor" }),
        makeMCPServer({ name: "filesystem", agent_type: "windsurf" }),
      ],
    );
    // "filesystem@cursor" is allowed, but "filesystem@windsurf" is not
    expect(findings).toHaveLength(1);
    expect(findings[0]!.item_name).toBe("filesystem");
  });

  it("matches MCP servers by plain name", () => {
    const cfg: ProjectConfig = {
      fail_on: "danger",
      allowed_agents: [],
      allowed_mcp_servers: ["filesystem"],
      ignore_paths: [],
      ignore_findings: [],
      rules_paths: [],
      config_path: "/tmp/.agentseal.yaml",
    };
    const findings = generateUnlistedFindings(
      cfg,
      [],
      [
        makeMCPServer({ name: "filesystem", agent_type: "cursor" }),
        makeMCPServer({ name: "filesystem", agent_type: "windsurf" }),
      ],
    );
    // Both match by plain name
    expect(findings).toEqual([]);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// generateConfigYaml
// ═══════════════════════════════════════════════════════════════════════

describe("generateConfigYaml", () => {
  it("includes default ignore_paths", () => {
    const yaml = generateConfigYaml([], []);
    expect(yaml).toContain("node_modules");
    expect(yaml).toContain(".git");
    expect(yaml).toContain("__pycache__");
  });

  it("includes found agents", () => {
    const agents = [
      makeAgent({ agent_type: "cursor", status: "found" }),
      makeAgent({ agent_type: "windsurf", status: "found" }),
    ];
    const yaml = generateConfigYaml(agents, []);
    expect(yaml).toContain("cursor");
    expect(yaml).toContain("windsurf");
  });

  it("includes installed_no_config agents", () => {
    const agents = [makeAgent({ agent_type: "cursor", status: "installed_no_config" })];
    const yaml = generateConfigYaml(agents, []);
    expect(yaml).toContain("cursor");
  });

  it("filters out not_installed agents", () => {
    const agents = [
      makeAgent({ agent_type: "cursor", status: "found" }),
      makeAgent({ agent_type: "windsurf", status: "not_installed" }),
    ];
    const yaml = generateConfigYaml(agents, []);
    expect(yaml).toContain("cursor");
    expect(yaml).not.toContain("windsurf");
  });

  it("includes MCP server names", () => {
    const servers = [
      makeMCPServer({ name: "filesystem" }),
      makeMCPServer({ name: "sqlite" }),
    ];
    const yaml = generateConfigYaml([], servers);
    expect(yaml).toContain("filesystem");
    expect(yaml).toContain("sqlite");
  });

  it("contains fail_on default", () => {
    const yaml = generateConfigYaml([], []);
    expect(yaml).toContain("fail_on: danger");
  });
});

// ═══════════════════════════════════════════════════════════════════════
// runGuardInit
// ═══════════════════════════════════════════════════════════════════════

describe("runGuardInit", () => {
  it("creates .agentseal.yaml in target directory", () => {
    const dir = makeTmpDir();
    const result = runGuardInit({ targetDir: dir, interactive: false });
    expect(result).toBe(true);
    expect(existsSync(join(dir, ".agentseal.yaml"))).toBe(true);
  });

  it("skips if file already exists and force is false", () => {
    const dir = makeTmpDir();
    writeFileSync(join(dir, ".agentseal.yaml"), "existing: true", "utf-8");
    const result = runGuardInit({ targetDir: dir, interactive: false });
    expect(result).toBe(false);
    // Original content preserved
    const content = readFileSync(join(dir, ".agentseal.yaml"), "utf-8");
    expect(content).toContain("existing: true");
  });

  it("overwrites if file exists and force is true", () => {
    const dir = makeTmpDir();
    writeFileSync(join(dir, ".agentseal.yaml"), "old: true", "utf-8");
    const result = runGuardInit({ targetDir: dir, force: true, interactive: false });
    expect(result).toBe(true);
    const content = readFileSync(join(dir, ".agentseal.yaml"), "utf-8");
    expect(content).not.toContain("old: true");
    expect(content).toContain("fail_on");
  });

  it("writes valid YAML that can be loaded", () => {
    const dir = makeTmpDir();
    runGuardInit({ targetDir: dir, interactive: false });
    const p = join(dir, ".agentseal.yaml");
    // Should be loadable without throwing
    const cfg = loadProjectConfig(p);
    expect(cfg.fail_on).toBe("danger");
  });
});
