/**
 * SQLite history store with delta computation for guard scans.
 *
 * Uses better-sqlite3 (optional dependency) for persistence.
 * If better-sqlite3 is not installed, all history features degrade gracefully.
 */

import { createRequire } from "node:module";
import { homedir } from "node:os";
import { resolve, dirname, join } from "node:path";
import { mkdirSync } from "node:fs";
import type {
  GuardReport,
  SkillResult,
  MCPServerResult,
  AgentConfigResult,
  DeltaEntry,
} from "./guard-models.js";
import { DeltaResult, guardReportFromDict } from "./guard-models.js";

// ═══════════════════════════════════════════════════════════════════════
// OPTIONAL better-sqlite3 IMPORT (ESM-safe)
// ═══════════════════════════════════════════════════════════════════════

const _require = createRequire(import.meta.url);

let Database: any = null;
try {
  Database = _require("better-sqlite3");
} catch {
  // better-sqlite3 not installed — history features disabled
}

// ═══════════════════════════════════════════════════════════════════════
// normalizeSkillPath
// ═══════════════════════════════════════════════════════════════════════

/**
 * Normalize a skill/file path for use as a stable key in delta comparison.
 *
 * - Replaces `\` with `/` (Windows compat)
 * - If path starts with HOME directory, replaces HOME prefix with `~/`
 * - Else if scanPath provided and path starts with it, makes it relative
 * - Else fallback: last 2 path segments (or last 1 if only 1)
 */
export function normalizeSkillPath(
  skillPath: string,
  scanPath?: string,
): string {
  const p = skillPath.replace(/\\/g, "/");
  const home = homedir().replace(/\\/g, "/");

  if (p.startsWith(home + "/")) {
    return "~/" + p.slice(home.length + 1);
  }

  if (scanPath) {
    const sp = scanPath.replace(/\\/g, "/");
    if (p.startsWith(sp + "/")) {
      return p.slice(sp.length + 1);
    }
  }

  const parts = p.split("/").filter(Boolean);
  return parts.length >= 2
    ? parts.slice(-2).join("/")
    : parts[parts.length - 1] || p;
}

// ═══════════════════════════════════════════════════════════════════════
// HistoryStore
// ═══════════════════════════════════════════════════════════════════════

/**
 * SQLite-backed store for guard scan history. Enables delta computation
 * between consecutive scans.
 *
 * If better-sqlite3 is not available, all methods degrade gracefully
 * (save is a no-op, loadPrevious returns null, etc.).
 */
export class HistoryStore {
  private db: any = null;
  private maxRows: number = 1000;
  private retentionDays: number = 90;

  constructor(dbPath?: string, maxRows = 1000, retentionDays = 90) {
    if (!Database) return; // graceful degradation

    this.maxRows = maxRows;
    this.retentionDays = retentionDays;

    const finalPath = dbPath ?? join(homedir(), ".agentseal", "history.db");
    mkdirSync(dirname(finalPath), { recursive: true });

    this.db = new Database(finalPath);
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS guard_scans (
        id INTEGER PRIMARY KEY,
        timestamp TEXT NOT NULL,
        scan_path TEXT,
        report_json TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_scope ON guard_scans(scan_path, timestamp);
    `);
  }

  /**
   * Save a guard report to the history store.
   */
  save(report: GuardReport, scanPath?: string): void {
    if (!this.db) return;

    const normalizedPath =
      scanPath !== undefined ? resolve(scanPath) : null;

    const insert = this.db.prepare(
      "INSERT INTO guard_scans (timestamp, scan_path, report_json) VALUES (?, ?, ?)",
    );

    const tx = this.db.transaction(() => {
      insert.run(
        report.timestamp,
        normalizedPath,
        JSON.stringify(report),
      );
    });
    tx();

    this.prune();
  }

  /**
   * Load the previous report (second-most-recent) for a given scan path.
   * Returns null if fewer than 2 entries exist or on any error.
   */
  loadPrevious(scanPath?: string): GuardReport | null {
    if (!this.db) return null;

    try {
      const normalizedPath =
        scanPath !== undefined ? resolve(scanPath) : null;

      let row: any;
      if (normalizedPath === null) {
        row = this.db
          .prepare(
            "SELECT report_json FROM guard_scans WHERE scan_path IS NULL ORDER BY timestamp DESC LIMIT 1 OFFSET 1",
          )
          .get();
      } else {
        row = this.db
          .prepare(
            "SELECT report_json FROM guard_scans WHERE scan_path = ? ORDER BY timestamp DESC LIMIT 1 OFFSET 1",
          )
          .get(normalizedPath);
      }

      if (!row) return null;

      const parsed = JSON.parse(row.report_json);
      return guardReportFromDict(parsed);
    } catch (err) {
      process.stderr.write(
        `[agentseal] warning: failed to load previous report: ${err}\n`,
      );
      return null;
    }
  }

  /**
   * Remove stale entries: older than retentionDays, or exceeding maxRows.
   */
  prune(): void {
    if (!this.db) return;

    // Delete entries older than retentionDays
    const cutoff = new Date(
      Date.now() - this.retentionDays * 86400000,
    ).toISOString();
    this.db
      .prepare("DELETE FROM guard_scans WHERE timestamp < ?")
      .run(cutoff);

    // Delete beyond maxRows (keep newest)
    this.db
      .prepare(
        `DELETE FROM guard_scans WHERE id NOT IN (
          SELECT id FROM guard_scans ORDER BY timestamp DESC LIMIT ?
        )`,
      )
      .run(this.maxRows);
  }

  /**
   * Return the total number of rows in the store. For test assertions.
   */
  _count(): number {
    if (!this.db) return 0;
    const row = this.db
      .prepare("SELECT COUNT(*) as cnt FROM guard_scans")
      .get();
    return row?.cnt ?? 0;
  }

  /**
   * Close the database connection.
   */
  close(): void {
    if (this.db) {
      this.db.close();
      this.db = null;
    }
  }
}

// ═══════════════════════════════════════════════════════════════════════
// computeDelta
// ═══════════════════════════════════════════════════════════════════════

/**
 * Build a map of skill results keyed by their normalized path.
 */
function skillMap(
  skills: SkillResult[],
  scanPath?: string,
): Map<string, SkillResult> {
  const m = new Map<string, SkillResult>();
  for (const s of skills) {
    m.set(normalizeSkillPath(s.path, scanPath), s);
  }
  return m;
}

/**
 * Build a map of MCP results keyed by "name:normalizeSkillPath(source_file)".
 */
function mcpMap(
  mcps: MCPServerResult[],
  scanPath?: string,
): Map<string, MCPServerResult> {
  const m = new Map<string, MCPServerResult>();
  for (const mcp of mcps) {
    const key = `${mcp.name}:${normalizeSkillPath(mcp.source_file, scanPath)}`;
    m.set(key, mcp);
  }
  return m;
}

/**
 * Filter agents to only those that are meaningful for delta comparison.
 */
function activeAgents(agents: AgentConfigResult[]): AgentConfigResult[] {
  return agents.filter(
    (a) => a.status === "found" || a.status === "installed_no_config",
  );
}

/**
 * Compute a delta between the current and previous guard reports.
 *
 * Tracks:
 * - Skills: new/resolved findings, changed verdicts, new/removed entities
 * - MCP servers: new/resolved findings, changed verdicts, new/removed entities
 * - Agents: new/removed entities (no findings on agents)
 */
export function computeDelta(
  current: GuardReport,
  previous: GuardReport,
  scanPath?: string,
): DeltaResult {
  const entries: DeltaEntry[] = [];

  // ── SKILLS ──
  const curSkills = skillMap(current.skill_results, scanPath);
  const prevSkills = skillMap(previous.skill_results, scanPath);

  for (const [key, curSkill] of curSkills) {
    const prevSkill = prevSkills.get(key);
    if (!prevSkill) {
      // New entity
      entries.push({
        change_type: "new_entity",
        entity_type: "skill",
        entity_name: key,
      });
      continue;
    }

    const curCodes = new Set(curSkill.findings.map((f) => f.code));
    const prevCodes = new Set(prevSkill.findings.map((f) => f.code));

    // New findings
    for (const f of curSkill.findings) {
      if (!prevCodes.has(f.code)) {
        entries.push({
          change_type: "new",
          entity_type: "skill",
          entity_name: key,
          code: f.code,
          title: f.title,
          severity: f.severity,
        });
      }
    }

    // Resolved findings
    for (const f of prevSkill.findings) {
      if (!curCodes.has(f.code)) {
        entries.push({
          change_type: "resolved",
          entity_type: "skill",
          entity_name: key,
          code: f.code,
          title: f.title,
          severity: f.severity,
        });
      }
    }

    // Changed verdict (when no finding-level changes)
    const hasNewFindings = curSkill.findings.some(
      (f) => !prevCodes.has(f.code),
    );
    const hasResolvedFindings = prevSkill.findings.some(
      (f) => !curCodes.has(f.code),
    );
    if (
      !hasNewFindings &&
      !hasResolvedFindings &&
      curSkill.verdict !== prevSkill.verdict
    ) {
      entries.push({
        change_type: "changed",
        entity_type: "skill",
        entity_name: key,
        old_verdict: prevSkill.verdict,
        new_verdict: curSkill.verdict,
      });
    }
  }

  // Removed skill entities
  for (const [key] of prevSkills) {
    if (!curSkills.has(key)) {
      entries.push({
        change_type: "removed_entity",
        entity_type: "skill",
        entity_name: key,
      });
    }
  }

  // ── MCP SERVERS ──
  const curMcps = mcpMap(current.mcp_results, scanPath);
  const prevMcps = mcpMap(previous.mcp_results, scanPath);

  for (const [key, curMcp] of curMcps) {
    const prevMcp = prevMcps.get(key);
    if (!prevMcp) {
      entries.push({
        change_type: "new_entity",
        entity_type: "mcp_server",
        entity_name: key,
      });
      continue;
    }

    const curCodes = new Set(curMcp.findings.map((f) => f.code));
    const prevCodes = new Set(prevMcp.findings.map((f) => f.code));

    // New findings
    for (const f of curMcp.findings) {
      if (!prevCodes.has(f.code)) {
        entries.push({
          change_type: "new",
          entity_type: "mcp_server",
          entity_name: key,
          code: f.code,
          title: f.title,
          severity: f.severity,
        });
      }
    }

    // Resolved findings
    for (const f of prevMcp.findings) {
      if (!curCodes.has(f.code)) {
        entries.push({
          change_type: "resolved",
          entity_type: "mcp_server",
          entity_name: key,
          code: f.code,
          title: f.title,
          severity: f.severity,
        });
      }
    }

    // Changed verdict
    const hasNewFindings = curMcp.findings.some(
      (f) => !prevCodes.has(f.code),
    );
    const hasResolvedFindings = prevMcp.findings.some(
      (f) => !curCodes.has(f.code),
    );
    if (
      !hasNewFindings &&
      !hasResolvedFindings &&
      curMcp.verdict !== prevMcp.verdict
    ) {
      entries.push({
        change_type: "changed",
        entity_type: "mcp_server",
        entity_name: key,
        old_verdict: prevMcp.verdict,
        new_verdict: curMcp.verdict,
      });
    }
  }

  // Removed MCP entities
  for (const [key] of prevMcps) {
    if (!curMcps.has(key)) {
      entries.push({
        change_type: "removed_entity",
        entity_type: "mcp_server",
        entity_name: key,
      });
    }
  }

  // ── AGENTS ──
  const curAgents = activeAgents(current.agents_found);
  const prevAgents = activeAgents(previous.agents_found);

  const curAgentTypes = new Set(curAgents.map((a) => a.agent_type));
  const prevAgentTypes = new Set(prevAgents.map((a) => a.agent_type));

  for (const agentType of curAgentTypes) {
    if (!prevAgentTypes.has(agentType)) {
      entries.push({
        change_type: "new_entity",
        entity_type: "agent",
        entity_name: agentType,
      });
    }
  }

  for (const agentType of prevAgentTypes) {
    if (!curAgentTypes.has(agentType)) {
      entries.push({
        change_type: "removed_entity",
        entity_type: "agent",
        entity_name: agentType,
      });
    }
  }

  return new DeltaResult(previous.timestamp, entries);
}
