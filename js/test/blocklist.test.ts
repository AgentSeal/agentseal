import { describe, it, expect } from "vitest";
import { Blocklist, sha256 } from "../src/blocklist.js";
import { mkdtempSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// ═══════════════════════════════════════════════════════════════════════
// SHA256 HELPER
// ═══════════════════════════════════════════════════════════════════════

describe("sha256", () => {
  it("computes correct SHA256", () => {
    // echo -n "hello" | sha256sum = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
    expect(sha256("hello")).toBe(
      "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    );
  });

  it("returns hex string", () => {
    const h = sha256("test");
    expect(h).toMatch(/^[0-9a-f]{64}$/);
  });

  it("is deterministic", () => {
    expect(sha256("foo")).toBe(sha256("foo"));
  });

  it("different content = different hash", () => {
    expect(sha256("a")).not.toBe(sha256("b"));
  });
});

// ═══════════════════════════════════════════════════════════════════════
// BLOCKLIST
// ═══════════════════════════════════════════════════════════════════════

describe("Blocklist", () => {
  it("starts with empty blocklist (no cache)", () => {
    const tmpDir = mkdtempSync(join(tmpdir(), "bl-"));
    const bl = new Blocklist(tmpDir);
    expect(bl.isBlocked("abc123")).toBe(false);
    expect(bl.size).toBe(12);
  });

  it("addHashes makes hashes blocked", () => {
    const tmpDir = mkdtempSync(join(tmpdir(), "bl-"));
    const bl = new Blocklist(tmpDir);
    bl.addHashes(["deadbeef", "cafebabe"]);
    expect(bl.isBlocked("deadbeef")).toBe(true);
    expect(bl.isBlocked("cafebabe")).toBe(true);
    expect(bl.isBlocked("other")).toBe(false);
  });

  it("is case-insensitive", () => {
    const tmpDir = mkdtempSync(join(tmpdir(), "bl-"));
    const bl = new Blocklist(tmpDir);
    bl.addHashes(["DEADBEEF"]);
    expect(bl.isBlocked("deadbeef")).toBe(true);
    expect(bl.isBlocked("DEADBEEF")).toBe(true);
  });

  it("loads from cache file", () => {
    const tmpDir = mkdtempSync(join(tmpdir(), "bl-"));
    const cacheFile = join(tmpDir, "blocklist.json");
    writeFileSync(cacheFile, JSON.stringify({
      sha256_hashes: ["aaa111", "bbb222"],
    }));
    const bl = new Blocklist(tmpDir);
    expect(bl.isBlocked("aaa111")).toBe(true);
    expect(bl.isBlocked("bbb222")).toBe(true);
    expect(bl.size).toBe(14);
  });

  it("handles malformed cache gracefully", () => {
    const tmpDir = mkdtempSync(join(tmpdir(), "bl-"));
    const cacheFile = join(tmpDir, "blocklist.json");
    writeFileSync(cacheFile, "not valid json{{{");
    const bl = new Blocklist(tmpDir);
    expect(bl.isBlocked("anything")).toBe(false);
    expect(bl.size).toBe(12);
  });

  it("handles missing sha256_hashes key", () => {
    const tmpDir = mkdtempSync(join(tmpdir(), "bl-"));
    const cacheFile = join(tmpDir, "blocklist.json");
    writeFileSync(cacheFile, JSON.stringify({ other_key: [] }));
    const bl = new Blocklist(tmpDir);
    expect(bl.size).toBe(12);
  });

  it("setCacheDir resets state", () => {
    const tmpDir1 = mkdtempSync(join(tmpdir(), "bl-"));
    const tmpDir2 = mkdtempSync(join(tmpdir(), "bl-"));

    writeFileSync(join(tmpDir1, "blocklist.json"), JSON.stringify({
      sha256_hashes: ["hash1"],
    }));
    writeFileSync(join(tmpDir2, "blocklist.json"), JSON.stringify({
      sha256_hashes: ["hash2"],
    }));

    const bl = new Blocklist(tmpDir1);
    expect(bl.isBlocked("hash1")).toBe(true);
    expect(bl.isBlocked("hash2")).toBe(false);

    bl.setCacheDir(tmpDir2);
    expect(bl.isBlocked("hash2")).toBe(true);
  });

  it("REMOTE_URL is defined", () => {
    expect(Blocklist.REMOTE_URL).toContain("agentseal.org");
  });

  it("CACHE_TTL is 1 hour", () => {
    expect(Blocklist.CACHE_TTL).toBe(3600);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// SEED HASHES
// ═══════════════════════════════════════════════════════════════════════

describe("seed hashes", () => {
  it("has 12 seed hashes on construction", () => {
    const bl = new Blocklist(mkdtempSync(join(tmpdir(), "bl-")));
    expect(bl.size).toBeGreaterThanOrEqual(12);
  });

  it("recognizes credential-theft-cursorrules hash", () => {
    const bl = new Blocklist(mkdtempSync(join(tmpdir(), "bl-")));
    expect(bl.isBlocked("854aa9bd5a641b03fcf2e4a26affb33057af3238a10a83e194c05384f371734f")).toBe(true);
  });

  it("seed hashes survive file load", () => {
    const dir = mkdtempSync(join(tmpdir(), "bl-"));
    writeFileSync(join(dir, "blocklist.json"), JSON.stringify({ sha256_hashes: ["aaa"], updated: new Date().toISOString() }));
    const bl = new Blocklist(dir);
    expect(bl.isBlocked("854aa9bd5a641b03fcf2e4a26affb33057af3238a10a83e194c05384f371734f")).toBe(true);
    expect(bl.isBlocked("aaa")).toBe(true);
  });
});
