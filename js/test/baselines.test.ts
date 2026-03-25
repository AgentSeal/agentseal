import { describe, it, expect } from "vitest";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { BaselineStore } from "../src/baselines.js";

function makeTmpStore(): BaselineStore {
  const dir = mkdtempSync(join(tmpdir(), "bl-"));
  return new BaselineStore(dir);
}

// ═══════════════════════════════════════════════════════════════════════
// BASELINE STORE
// ═══════════════════════════════════════════════════════════════════════

describe("BaselineStore", () => {
  it("returns null for unknown entry", () => {
    const store = makeTmpStore();
    expect(store.load("test", "unknown")).toBeNull();
  });

  it("creates new baseline on first check", () => {
    const store = makeTmpStore();
    const change = store.checkServer({
      name: "test-server",
      agent_type: "cursor",
      command: "npx",
      args: ["-y", "server"],
    });
    expect(change).not.toBeNull();
    expect(change!.change_type).toBe("new_server");
  });

  it("returns null on second check with same config", () => {
    const store = makeTmpStore();
    const server = {
      name: "test-server",
      agent_type: "cursor",
      command: "npx",
      args: ["-y", "server"],
    };
    store.checkServer(server); // First time
    const change = store.checkServer(server); // Same config
    expect(change).toBeNull();
  });

  it("detects config change", () => {
    const store = makeTmpStore();
    store.checkServer({
      name: "test-server",
      agent_type: "cursor",
      command: "npx",
      args: ["-y", "server@1.0"],
    });
    const change = store.checkServer({
      name: "test-server",
      agent_type: "cursor",
      command: "npx",
      args: ["-y", "server@2.0"],
    });
    expect(change).not.toBeNull();
    expect(change!.change_type).toBe("config_changed");
    expect(change!.detail).toContain("changed");
  });

  it("detects env key change", () => {
    const store = makeTmpStore();
    store.checkServer({
      name: "srv",
      agent_type: "claude",
      command: "node",
      env: { KEY1: "val" },
    });
    const change = store.checkServer({
      name: "srv",
      agent_type: "claude",
      command: "node",
      env: { KEY1: "val", KEY2: "val2" },
    });
    expect(change).not.toBeNull();
    expect(change!.change_type).toBe("config_changed");
  });

  it("does NOT flag env value changes (only keys matter)", () => {
    const store = makeTmpStore();
    store.checkServer({
      name: "srv",
      agent_type: "claude",
      command: "node",
      env: { API_KEY: "old-value" },
    });
    const change = store.checkServer({
      name: "srv",
      agent_type: "claude",
      command: "node",
      env: { API_KEY: "new-value" },
    });
    // Same keys → same hash
    expect(change).toBeNull();
  });

  it("checkAll skips new_server by default", () => {
    const store = makeTmpStore();
    const changes = store.checkAll([
      { name: "s1", agent_type: "test", command: "node" },
      { name: "s2", agent_type: "test", command: "python" },
    ]);
    expect(changes).toEqual([]);
  });

  it("checkAll includes new_server when asked", () => {
    const store = makeTmpStore();
    const changes = store.checkAll(
      [
        { name: "s1", agent_type: "test", command: "node" },
      ],
      true,
    );
    expect(changes).toHaveLength(1);
    expect(changes[0]!.change_type).toBe("new_server");
  });

  it("checkAll detects config changes", () => {
    const store = makeTmpStore();
    store.checkServer({ name: "s1", agent_type: "test", command: "node", args: ["v1"] });
    const changes = store.checkAll([
      { name: "s1", agent_type: "test", command: "node", args: ["v2"] },
    ]);
    expect(changes).toHaveLength(1);
    expect(changes[0]!.change_type).toBe("config_changed");
  });

  it("reset clears all entries", () => {
    const store = makeTmpStore();
    store.checkServer({ name: "s1", agent_type: "test", command: "a" });
    store.checkServer({ name: "s2", agent_type: "test", command: "b" });
    const count = store.reset();
    expect(count).toBe(2);
    expect(store.listEntries()).toEqual([]);
  });

  it("listEntries returns stored baselines", () => {
    const store = makeTmpStore();
    store.checkServer({ name: "alpha", agent_type: "cursor", command: "npx" });
    store.checkServer({ name: "beta", agent_type: "claude", command: "node" });
    const entries = store.listEntries();
    expect(entries).toHaveLength(2);
    const names = entries.map((e) => e.server_name).sort();
    expect(names).toEqual(["alpha", "beta"]);
  });

  it("save/load round-trips correctly", () => {
    const store = makeTmpStore();
    store.checkServer({
      name: "test",
      agent_type: "cursor",
      command: "npx",
      args: ["-y", "pkg"],
    });
    const entry = store.load("cursor", "test");
    expect(entry).not.toBeNull();
    expect(entry!.server_name).toBe("test");
    expect(entry!.command).toBe("npx");
    expect(entry!.args).toEqual(["-y", "pkg"]);
    expect(entry!.config_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(entry!.first_seen).toBeTruthy();
  });

  it("detects URL change in fingerprint", () => {
    const store = makeTmpStore();
    store.checkServer({
      name: "remote",
      agent_type: "cursor",
      command: "",
      url: "https://api.example.com/mcp",
    });
    const change = store.checkServer({
      name: "remote",
      agent_type: "cursor",
      command: "",
      url: "https://api.evil.com/mcp",
    });
    expect(change).not.toBeNull();
    expect(change!.change_type).toBe("config_changed");
  });

  it("detects header key change in fingerprint", () => {
    const store = makeTmpStore();
    store.checkServer({
      name: "remote",
      agent_type: "cursor",
      command: "",
      url: "https://api.example.com",
      headers: { Authorization: "Bearer token" },
    });
    const change = store.checkServer({
      name: "remote",
      agent_type: "cursor",
      command: "",
      url: "https://api.example.com",
      headers: { Authorization: "Bearer token", "X-Custom": "val" },
    });
    expect(change).not.toBeNull();
    expect(change!.change_type).toBe("config_changed");
  });

  it("same URL produces same fingerprint", () => {
    const store = makeTmpStore();
    store.checkServer({
      name: "remote",
      agent_type: "cursor",
      command: "",
      url: "https://api.example.com",
    });
    const change = store.checkServer({
      name: "remote",
      agent_type: "cursor",
      command: "",
      url: "https://api.example.com",
    });
    expect(change).toBeNull();
  });
});
