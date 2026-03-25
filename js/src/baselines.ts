/**
 * Rug pull detection via baseline fingerprinting.
 *
 * On first scan, fingerprints MCP server configurations. On subsequent scans,
 * detects changes and alerts the user.
 *
 * Storage: ~/.agentseal/baselines/{agent_type}/{server_name}.json
 *
 * Port of Python agentseal/baselines.py.
 */

import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, unlinkSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import type { BaselineChangeResult } from "./guard-models.js";

// ═══════════════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════════════

export interface BaselineEntry {
  server_name: string;
  agent_type: string;
  config_hash: string;
  binary_hash: string | null;
  binary_path: string | null;
  command: string;
  args: string[];
  first_seen: string;
  last_verified: string;
  tool_signatures_hash?: string | null;
  tool_count?: number | null;
  tools_detail?: Array<{ name: string; hash: string }> | null;
}

export interface BaselineChange {
  server_name: string;
  agent_type: string;
  change_type: string;  // "config_changed", "binary_changed", "new_server"
  old_value?: string | null;
  new_value?: string | null;
  detail: string;
}

// ═══════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════

function configFingerprint(server: Record<string, any>): string {
  const rawCmd = server.command ?? "";
  const cmdStr = Array.isArray(rawCmd) ? rawCmd.join(" ") : String(rawCmd);
  const parts = [
    cmdStr,
    JSON.stringify([...(server.args ?? [])].map(String).sort()),
    JSON.stringify(Object.keys(server.env ?? {}).map(String).sort()),
    server.url ?? "",
    JSON.stringify(Object.keys(server.headers ?? {}).map(String).sort()),
  ];
  return createHash("sha256").update(parts.join("|")).digest("hex");
}

function sanitizeName(name: string): string {
  return name.replace(/[^a-zA-Z0-9_-]/g, "_");
}

function rglob(dir: string, ext: string): string[] {
  const results: string[] = [];
  const walk = (d: string) => {
    try {
      for (const entry of readdirSync(d, { withFileTypes: true })) {
        const full = join(d, entry.name);
        if (entry.isDirectory()) walk(full);
        else if (entry.isFile() && entry.name.endsWith(ext)) results.push(full);
      }
    } catch { /* ignore */ }
  };
  walk(dir);
  return results;
}

// ═══════════════════════════════════════════════════════════════════════
// BASELINE STORE
// ═══════════════════════════════════════════════════════════════════════

export class BaselineStore {
  private readonly _dir: string;

  constructor(baselinesDir?: string) {
    this._dir = baselinesDir ?? join(homedir(), ".agentseal", "baselines");
  }

  private _entryPath(agentType: string, serverName: string): string {
    return join(this._dir, sanitizeName(agentType), `${sanitizeName(serverName)}.json`);
  }

  /** Load a stored baseline entry. Returns null if not found. */
  load(agentType: string, serverName: string): BaselineEntry | null {
    const path = this._entryPath(agentType, serverName);
    if (!existsSync(path)) return null;
    try {
      const data = JSON.parse(readFileSync(path, "utf-8"));
      return data as BaselineEntry;
    } catch {
      return null;
    }
  }

  /** Save a baseline entry to disk. */
  save(entry: BaselineEntry): void {
    const path = this._entryPath(entry.agent_type, entry.server_name);
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, JSON.stringify(entry, null, 2), "utf-8");
  }

  /** Check a single MCP server against its stored baseline. */
  checkServer(server: Record<string, any>): BaselineChange | null {
    const name: string = server.name ?? "unknown";
    const agentType: string = server.agent_type ?? "unknown";
    const rawCmd = server.command ?? "";
    const command: string = Array.isArray(rawCmd) ? rawCmd.join(" ") : String(rawCmd);
    const args = (server.args ?? []).filter((a: any): a is string => typeof a === "string");
    const now = new Date().toISOString();

    const configHash = configFingerprint(server);
    const existing = this.load(agentType, name);

    if (existing === null) {
      // First time — create baseline
      this.save({
        server_name: name,
        agent_type: agentType,
        config_hash: configHash,
        binary_hash: null,
        binary_path: null,
        command,
        args,
        first_seen: now,
        last_verified: now,
      });
      return {
        server_name: name,
        agent_type: agentType,
        change_type: "new_server",
        detail: `New MCP server '${name}' baselined.`,
      };
    }

    // Check for config changes
    if (existing.config_hash !== configHash) {
      const change: BaselineChange = {
        server_name: name,
        agent_type: agentType,
        change_type: "config_changed",
        old_value: existing.config_hash.slice(0, 12),
        new_value: configHash.slice(0, 12),
        detail: `Config for '${name}' changed (command/args/env modified).`,
      };
      existing.config_hash = configHash;
      existing.command = command;
      existing.args = args;
      existing.last_verified = now;
      this.save(existing);
      return change;
    }

    // No change — update timestamp
    existing.last_verified = now;
    this.save(existing);
    return null;
  }

  /** Check all servers. Returns list of changes (empty = no changes). */
  checkAll(servers: Array<Record<string, any>>, includeNew = false): BaselineChange[] {
    const changes: BaselineChange[] = [];
    for (const srv of servers) {
      const change = this.checkServer(srv);
      if (change === null) continue;
      if (change.change_type === "new_server" && !includeNew) continue;
      changes.push(change);
    }
    return changes;
  }

  /** Remove all baselines. Returns count of entries removed. */
  reset(): number {
    let count = 0;
    for (const f of rglob(this._dir, ".json")) {
      try {
        unlinkSync(f);
        count++;
      } catch { /* ignore */ }
    }
    return count;
  }

  /** List all stored baseline entries. */
  listEntries(): BaselineEntry[] {
    const entries: BaselineEntry[] = [];
    for (const f of rglob(this._dir, ".json")) {
      try {
        const data = JSON.parse(readFileSync(f, "utf-8"));
        entries.push(data as BaselineEntry);
      } catch { /* ignore */ }
    }
    return entries;
  }
}
