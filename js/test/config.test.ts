import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { loadConfig, saveConfigKey, removeConfigKey, CONFIG_KEYS } from "../src/config.js";

describe("config", () => {
  let tempDir: string;
  beforeEach(() => { tempDir = mkdtempSync(join(tmpdir(), "agentseal-config-")); });
  afterEach(() => { rmSync(tempDir, { recursive: true, force: true }); });

  it("returns empty config when file does not exist", () => {
    expect(loadConfig(join(tempDir, "config.json"))).toEqual({});
  });

  it("saves and loads a key", () => {
    const path = join(tempDir, "config.json");
    saveConfigKey("model", "gpt-4o", path);
    expect(loadConfig(path).model).toBe("gpt-4o");
  });

  it("removes a key", () => {
    const path = join(tempDir, "config.json");
    saveConfigKey("model", "gpt-4o", path);
    removeConfigKey("model", path);
    expect(loadConfig(path).model).toBeUndefined();
  });

  it("CONFIG_KEYS contains expected keys", () => {
    expect(CONFIG_KEYS).toContain("model");
    expect(CONFIG_KEYS).toContain("api-key");
    expect(CONFIG_KEYS).toContain("ollama-url");
    expect(CONFIG_KEYS).toContain("dashboard-url");
  });
});
