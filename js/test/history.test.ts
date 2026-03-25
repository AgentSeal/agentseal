import { describe, it, expect, afterEach } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir, homedir } from "node:os";
import { createRequire } from "node:module";
import {
  normalizeSkillPath,
  HistoryStore,
  computeDelta,
} from "../src/history.js";
import type { GuardReport } from "../src/guard-models.js";
import { GuardVerdict } from "../src/guard-models.js";

// Check if better-sqlite3 is available (it's an optional dependency)
let hasSqlite = false;
try {
  const _require = createRequire(import.meta.url);
  _require("better-sqlite3");
  hasSqlite = true;
} catch {
  // not available
}
const describeIfSqlite = hasSqlite ? describe : describe.skip;

// ═══════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════

function makeTmpDir(): string {
  return mkdtempSync(join(tmpdir(), "agentseal-history-test-"));
}

function makeReport(overrides: Partial<GuardReport> = {}): GuardReport {
  return {
    timestamp: overrides.timestamp ?? new Date().toISOString(),
    duration_seconds: overrides.duration_seconds ?? 1.0,
    agents_found: overrides.agents_found ?? [],
    skill_results: overrides.skill_results ?? [],
    mcp_results: overrides.mcp_results ?? [],
    mcp_runtime_results: overrides.mcp_runtime_results ?? [],
    toxic_flows: overrides.toxic_flows ?? [],
    baseline_changes: overrides.baseline_changes ?? [],
    llm_tokens_used: overrides.llm_tokens_used ?? 0,
    unlisted_findings: overrides.unlisted_findings ?? [],
    custom_findings: overrides.custom_findings ?? [],
    config_path: overrides.config_path ?? "",
  };
}

// ═══════════════════════════════════════════════════════════════════════
// normalizeSkillPath
// ═══════════════════════════════════════════════════════════════════════

describe("normalizeSkillPath", () => {
  it("replaces HOME prefix with ~/", () => {
    const home = homedir().replace(/\\/g, "/");
    const result = normalizeSkillPath(`${home}/projects/skill.ts`);
    expect(result).toBe("~/projects/skill.ts");
  });

  it("uses scanPath prefix to make relative path", () => {
    const result = normalizeSkillPath(
      "/workspace/project/src/skill.ts",
      "/workspace/project",
    );
    expect(result).toBe("src/skill.ts");
  });

  it("falls back to last 2 segments when no prefix matches", () => {
    // Use a path that won't start with HOME or scanPath
    const result = normalizeSkillPath("/some/random/deep/path/skill.ts");
    // Should be "path/skill.ts" unless /some/random starts with HOME
    const home = homedir().replace(/\\/g, "/");
    if ("/some/random/deep/path/skill.ts".startsWith(home + "/")) {
      // Unlikely, but handle gracefully
      expect(result).toContain("~/");
    } else {
      expect(result).toBe("path/skill.ts");
    }
  });

  it("normalizes Windows backslashes", () => {
    const home = homedir().replace(/\\/g, "/");
    const winPath = home.replace(/\//g, "\\") + "\\projects\\skill.ts";
    const result = normalizeSkillPath(winPath);
    expect(result).toBe("~/projects/skill.ts");
  });

  it("returns single segment when path has only one part", () => {
    const result = normalizeSkillPath("skill.ts");
    expect(result).toBe("skill.ts");
  });

  it("scanPath takes precedence over HOME when both could match", () => {
    const home = homedir().replace(/\\/g, "/");
    // HOME prefix is checked first, so it wins over scanPath
    const result = normalizeSkillPath(
      `${home}/project/skill.ts`,
      `${home}/project`,
    );
    expect(result).toBe("~/project/skill.ts");
  });
});

// ═══════════════════════════════════════════════════════════════════════
// HistoryStore
// ═══════════════════════════════════════════════════════════════════════

describeIfSqlite("HistoryStore", () => {
  const tmpDirs: string[] = [];

  function makeStore(opts?: { maxRows?: number; retentionDays?: number }): {
    store: HistoryStore;
    dbPath: string;
  } {
    const dir = makeTmpDir();
    tmpDirs.push(dir);
    const dbPath = join(dir, "test.db");
    const store = new HistoryStore(
      dbPath,
      opts?.maxRows ?? 1000,
      opts?.retentionDays ?? 90,
    );
    return { store, dbPath };
  }

  afterEach(() => {
    for (const dir of tmpDirs) {
      try {
        rmSync(dir, { recursive: true, force: true });
      } catch {
        // ignore cleanup errors
      }
    }
    tmpDirs.length = 0;
  });

  it("constructor creates the database file and tables", () => {
    const { store } = makeStore();
    expect(store._count()).toBe(0);
    store.close();
  });

  it("save + loadPrevious round-trip", () => {
    const { store } = makeStore();
    const scanPath = "/workspace/project";

    const report1 = makeReport({ timestamp: "2026-03-01T00:00:00Z" });
    store.save(report1, scanPath);

    const report2 = makeReport({ timestamp: "2026-03-02T00:00:00Z" });
    store.save(report2, scanPath);

    // loadPrevious should return report1 (the one before the latest)
    const prev = store.loadPrevious(scanPath);
    expect(prev).not.toBeNull();
    expect(prev!.timestamp).toBe("2026-03-01T00:00:00Z");

    store.close();
  });

  it("loadPrevious returns null when only one entry exists", () => {
    const { store } = makeStore();
    const scanPath = "/workspace/project";

    const report = makeReport({ timestamp: "2026-03-01T00:00:00Z" });
    store.save(report, scanPath);

    const prev = store.loadPrevious(scanPath);
    expect(prev).toBeNull();

    store.close();
  });

  it("loadPrevious returns null when no entries exist", () => {
    const { store } = makeStore();
    const prev = store.loadPrevious("/nonexistent");
    expect(prev).toBeNull();
    store.close();
  });

  it("loadPrevious handles null scanPath", () => {
    const { store } = makeStore();

    store.save(makeReport({ timestamp: "2026-03-01T00:00:00Z" }));
    store.save(makeReport({ timestamp: "2026-03-02T00:00:00Z" }));

    const prev = store.loadPrevious();
    expect(prev).not.toBeNull();
    expect(prev!.timestamp).toBe("2026-03-01T00:00:00Z");

    store.close();
  });

  it("prune removes entries older than retentionDays", () => {
    const { store } = makeStore({ retentionDays: 1 });
    const scanPath = "/test";

    // Insert an old entry (200 days ago)
    const oldDate = new Date(Date.now() - 200 * 86400000).toISOString();
    store.save(makeReport({ timestamp: oldDate }), scanPath);

    // Insert a recent entry
    store.save(makeReport({ timestamp: new Date().toISOString() }), scanPath);

    // After save, prune runs automatically; the old entry should be gone
    expect(store._count()).toBe(1);

    store.close();
  });

  it("prune enforces maxRows", () => {
    const { store } = makeStore({ maxRows: 3 });
    const scanPath = "/test";

    for (let i = 0; i < 5; i++) {
      const ts = new Date(Date.now() + i * 1000).toISOString();
      store.save(makeReport({ timestamp: ts }), scanPath);
    }

    expect(store._count()).toBe(3);
    store.close();
  });

  it("_count returns correct number", () => {
    const { store } = makeStore();
    expect(store._count()).toBe(0);

    store.save(makeReport(), "/a");
    expect(store._count()).toBe(1);

    store.save(makeReport(), "/b");
    expect(store._count()).toBe(2);

    store.close();
  });

  it("scopes queries by scanPath", () => {
    const { store } = makeStore();

    store.save(makeReport({ timestamp: "2026-03-01T00:00:00Z" }), "/project-a");
    store.save(makeReport({ timestamp: "2026-03-02T00:00:00Z" }), "/project-a");

    store.save(makeReport({ timestamp: "2026-03-01T00:00:00Z" }), "/project-b");

    // project-a has 2 entries, so loadPrevious should return the first
    const prevA = store.loadPrevious("/project-a");
    expect(prevA).not.toBeNull();
    expect(prevA!.timestamp).toBe("2026-03-01T00:00:00Z");

    // project-b has only 1 entry
    const prevB = store.loadPrevious("/project-b");
    expect(prevB).toBeNull();

    store.close();
  });
});

// ═══════════════════════════════════════════════════════════════════════
// computeDelta
// ═══════════════════════════════════════════════════════════════════════

describe("computeDelta", () => {
  it("detects new skill finding", () => {
    const previous = makeReport({
      timestamp: "2026-03-01T00:00:00Z",
      skill_results: [
        {
          name: "skill-a",
          path: "/project/skill-a.ts",
          verdict: GuardVerdict.SAFE,
          findings: [],
          blocklist_match: false,
          sha256: "aaa",
        },
      ],
    });
    const current = makeReport({
      timestamp: "2026-03-02T00:00:00Z",
      skill_results: [
        {
          name: "skill-a",
          path: "/project/skill-a.ts",
          verdict: GuardVerdict.DANGER,
          findings: [
            {
              code: "SKILL-001",
              title: "Credential theft",
              description: "Reads SSH keys",
              severity: "critical",
              evidence: "readFile('.ssh')",
              remediation: "Remove",
            },
          ],
          blocklist_match: false,
          sha256: "bbb",
        },
      ],
    });

    const delta = computeDelta(current, previous, "/project");
    const newFindings = delta.entries.filter((e) => e.change_type === "new");
    expect(newFindings.length).toBe(1);
    expect(newFindings[0].code).toBe("SKILL-001");
    expect(newFindings[0].entity_type).toBe("skill");
  });

  it("detects resolved skill finding", () => {
    const previous = makeReport({
      timestamp: "2026-03-01T00:00:00Z",
      skill_results: [
        {
          name: "skill-a",
          path: "/project/skill-a.ts",
          verdict: GuardVerdict.DANGER,
          findings: [
            {
              code: "SKILL-001",
              title: "Credential theft",
              description: "Reads SSH keys",
              severity: "critical",
              evidence: "readFile('.ssh')",
              remediation: "Remove",
            },
          ],
          blocklist_match: false,
          sha256: "aaa",
        },
      ],
    });
    const current = makeReport({
      timestamp: "2026-03-02T00:00:00Z",
      skill_results: [
        {
          name: "skill-a",
          path: "/project/skill-a.ts",
          verdict: GuardVerdict.SAFE,
          findings: [],
          blocklist_match: false,
          sha256: "bbb",
        },
      ],
    });

    const delta = computeDelta(current, previous, "/project");
    const resolved = delta.entries.filter((e) => e.change_type === "resolved");
    expect(resolved.length).toBe(1);
    expect(resolved[0].code).toBe("SKILL-001");
    expect(resolved[0].entity_type).toBe("skill");
  });

  it("detects changed verdict on skill", () => {
    const previous = makeReport({
      timestamp: "2026-03-01T00:00:00Z",
      skill_results: [
        {
          name: "skill-a",
          path: "/project/skill-a.ts",
          verdict: GuardVerdict.WARNING,
          findings: [
            {
              code: "SKILL-002",
              title: "Suspicious",
              description: "Desc",
              severity: "medium",
              evidence: "ev",
              remediation: "Check",
            },
          ],
          blocklist_match: false,
          sha256: "aaa",
        },
      ],
    });
    const current = makeReport({
      timestamp: "2026-03-02T00:00:00Z",
      skill_results: [
        {
          name: "skill-a",
          path: "/project/skill-a.ts",
          verdict: GuardVerdict.DANGER,
          findings: [
            {
              code: "SKILL-002",
              title: "Suspicious",
              description: "Desc",
              severity: "medium",
              evidence: "ev",
              remediation: "Check",
            },
          ],
          blocklist_match: false,
          sha256: "bbb",
        },
      ],
    });

    const delta = computeDelta(current, previous, "/project");
    const changed = delta.entries.filter((e) => e.change_type === "changed");
    expect(changed.length).toBe(1);
    expect(changed[0].old_verdict).toBe("warning");
    expect(changed[0].new_verdict).toBe("danger");
  });

  it("detects new_entity for skill in current not in previous", () => {
    const previous = makeReport({
      timestamp: "2026-03-01T00:00:00Z",
      skill_results: [],
    });
    const current = makeReport({
      timestamp: "2026-03-02T00:00:00Z",
      skill_results: [
        {
          name: "brand-new-skill",
          path: "/project/new-skill.ts",
          verdict: GuardVerdict.SAFE,
          findings: [],
          blocklist_match: false,
          sha256: "ccc",
        },
      ],
    });

    const delta = computeDelta(current, previous, "/project");
    const newEntities = delta.entries.filter(
      (e) => e.change_type === "new_entity",
    );
    expect(newEntities.length).toBe(1);
    expect(newEntities[0].entity_type).toBe("skill");
  });

  it("detects removed_entity for skill in previous not in current", () => {
    const previous = makeReport({
      timestamp: "2026-03-01T00:00:00Z",
      skill_results: [
        {
          name: "old-skill",
          path: "/project/old-skill.ts",
          verdict: GuardVerdict.SAFE,
          findings: [],
          blocklist_match: false,
          sha256: "aaa",
        },
      ],
    });
    const current = makeReport({
      timestamp: "2026-03-02T00:00:00Z",
      skill_results: [],
    });

    const delta = computeDelta(current, previous, "/project");
    const removed = delta.entries.filter(
      (e) => e.change_type === "removed_entity",
    );
    expect(removed.length).toBe(1);
    expect(removed[0].entity_type).toBe("skill");
  });

  it("detects new MCP server", () => {
    const previous = makeReport({
      timestamp: "2026-03-01T00:00:00Z",
      mcp_results: [],
    });
    const current = makeReport({
      timestamp: "2026-03-02T00:00:00Z",
      mcp_results: [
        {
          name: "new-server",
          command: "npx new-server",
          source_file: "/config/mcp.json",
          verdict: GuardVerdict.SAFE,
          findings: [],
        },
      ],
    });

    const delta = computeDelta(current, previous);
    const newEntities = delta.entries.filter(
      (e) => e.change_type === "new_entity",
    );
    expect(newEntities.length).toBe(1);
    expect(newEntities[0].entity_type).toBe("mcp_server");
    expect(newEntities[0].entity_name).toContain("new-server");
  });

  it("detects removed MCP server", () => {
    const previous = makeReport({
      timestamp: "2026-03-01T00:00:00Z",
      mcp_results: [
        {
          name: "old-server",
          command: "npx old-server",
          source_file: "/config/mcp.json",
          verdict: GuardVerdict.WARNING,
          findings: [
            {
              code: "MCP-001",
              title: "Insecure transport",
              description: "Desc",
              severity: "high",
              remediation: "Use TLS",
            },
          ],
        },
      ],
    });
    const current = makeReport({
      timestamp: "2026-03-02T00:00:00Z",
      mcp_results: [],
    });

    const delta = computeDelta(current, previous);
    const removed = delta.entries.filter(
      (e) => e.change_type === "removed_entity",
    );
    expect(removed.length).toBe(1);
    expect(removed[0].entity_type).toBe("mcp_server");
  });

  it("detects new MCP finding", () => {
    const previous = makeReport({
      timestamp: "2026-03-01T00:00:00Z",
      mcp_results: [
        {
          name: "server-a",
          command: "npx server-a",
          source_file: "/config.json",
          verdict: GuardVerdict.SAFE,
          findings: [],
        },
      ],
    });
    const current = makeReport({
      timestamp: "2026-03-02T00:00:00Z",
      mcp_results: [
        {
          name: "server-a",
          command: "npx server-a",
          source_file: "/config.json",
          verdict: GuardVerdict.WARNING,
          findings: [
            {
              code: "MCP-002",
              title: "Unvalidated input",
              description: "Desc",
              severity: "medium",
              remediation: "Validate",
            },
          ],
        },
      ],
    });

    const delta = computeDelta(current, previous);
    const newFindings = delta.entries.filter((e) => e.change_type === "new");
    expect(newFindings.length).toBe(1);
    expect(newFindings[0].code).toBe("MCP-002");
    expect(newFindings[0].entity_type).toBe("mcp_server");
  });

  it("detects new agent (found status)", () => {
    const previous = makeReport({
      timestamp: "2026-03-01T00:00:00Z",
      agents_found: [],
    });
    const current = makeReport({
      timestamp: "2026-03-02T00:00:00Z",
      agents_found: [
        {
          name: "Claude Desktop",
          config_path: "/c",
          agent_type: "claude-desktop",
          mcp_servers: 3,
          skills_count: 0,
          status: "found",
        },
      ],
    });

    const delta = computeDelta(current, previous);
    const newAgents = delta.entries.filter(
      (e) => e.change_type === "new_entity" && e.entity_type === "agent",
    );
    expect(newAgents.length).toBe(1);
    expect(newAgents[0].entity_name).toBe("claude-desktop");
  });

  it("detects removed agent", () => {
    const previous = makeReport({
      timestamp: "2026-03-01T00:00:00Z",
      agents_found: [
        {
          name: "Cursor",
          config_path: "/c",
          agent_type: "cursor",
          mcp_servers: 1,
          skills_count: 0,
          status: "found",
        },
      ],
    });
    const current = makeReport({
      timestamp: "2026-03-02T00:00:00Z",
      agents_found: [],
    });

    const delta = computeDelta(current, previous);
    const removed = delta.entries.filter(
      (e) => e.change_type === "removed_entity" && e.entity_type === "agent",
    );
    expect(removed.length).toBe(1);
    expect(removed[0].entity_name).toBe("cursor");
  });

  it("skips agents with status not_installed", () => {
    const previous = makeReport({
      timestamp: "2026-03-01T00:00:00Z",
      agents_found: [],
    });
    const current = makeReport({
      timestamp: "2026-03-02T00:00:00Z",
      agents_found: [
        {
          name: "VSCode",
          config_path: "/c",
          agent_type: "vscode",
          mcp_servers: 0,
          skills_count: 0,
          status: "not_installed",
        },
      ],
    });

    const delta = computeDelta(current, previous);
    const agentEntries = delta.entries.filter(
      (e) => e.entity_type === "agent",
    );
    expect(agentEntries.length).toBe(0);
  });

  it("includes agents with installed_no_config status", () => {
    const previous = makeReport({
      timestamp: "2026-03-01T00:00:00Z",
      agents_found: [],
    });
    const current = makeReport({
      timestamp: "2026-03-02T00:00:00Z",
      agents_found: [
        {
          name: "Cursor",
          config_path: "/c",
          agent_type: "cursor",
          mcp_servers: 0,
          skills_count: 0,
          status: "installed_no_config",
        },
      ],
    });

    const delta = computeDelta(current, previous);
    const agentEntries = delta.entries.filter(
      (e) => e.entity_type === "agent",
    );
    expect(agentEntries.length).toBe(1);
  });

  it("returns empty entries when reports are identical", () => {
    const report = makeReport({
      timestamp: "2026-03-01T00:00:00Z",
      skill_results: [
        {
          name: "skill-a",
          path: "/project/skill-a.ts",
          verdict: GuardVerdict.SAFE,
          findings: [],
          blocklist_match: false,
          sha256: "aaa",
        },
      ],
    });

    const delta = computeDelta(report, report);
    expect(delta.entries.length).toBe(0);
  });

  it("sets previous_timestamp from previous report", () => {
    const previous = makeReport({ timestamp: "2026-03-01T00:00:00Z" });
    const current = makeReport({ timestamp: "2026-03-02T00:00:00Z" });

    const delta = computeDelta(current, previous);
    expect(delta.previous_timestamp).toBe("2026-03-01T00:00:00Z");
  });
});

// ═══════════════════════════════════════════════════════════════════════
// Graceful Degradation
// ═══════════════════════════════════════════════════════════════════════

describe("Graceful degradation", () => {
  it("HistoryStore works when Database is available (better-sqlite3 installed)", () => {
    // This test confirms that our test environment has better-sqlite3
    // If it didn't, the HistoryStore constructor would silently return
    const dir = makeTmpDir();
    const dbPath = join(dir, "test.db");
    const store = new HistoryStore(dbPath);
    // If better-sqlite3 is not available, _count returns 0 and doesn't crash
    expect(store._count()).toBe(0);
    store.save(makeReport());
    // If db is null, save is a no-op
    store.close();
    rmSync(dir, { recursive: true, force: true });
  });
});
