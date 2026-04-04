import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { saveCredentials, loadCredentials, saveLicense, loadLicense } from "../src/login.js";

describe("login", () => {
  let tempDir: string;
  beforeEach(() => { tempDir = mkdtempSync(join(tmpdir(), "agentseal-login-")); });
  afterEach(() => { rmSync(tempDir, { recursive: true, force: true }); });

  it("saves and loads dashboard credentials", () => {
    const path = join(tempDir, "config.json");
    saveCredentials("https://agentseal.org/api/v1", "test-key-123", path);
    const creds = loadCredentials(path);
    expect(creds).not.toBeNull();
    expect(creds!.apiUrl).toBe("https://agentseal.org/api/v1");
    expect(creds!.apiKey).toBe("test-key-123");
  });

  it("returns null when no credentials saved", () => {
    expect(loadCredentials(join(tempDir, "nonexistent.json"))).toBeNull();
  });

  it("saves and loads license key", () => {
    const path = join(tempDir, "license.json");
    saveLicense("SEAL-PRO-XXXX-YYYY", path);
    expect(loadLicense(path)).toBe("SEAL-PRO-XXXX-YYYY");
  });
});
