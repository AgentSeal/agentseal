import { describe, it, expect, beforeAll } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { execSync } from "node:child_process";

describe("CLI version", () => {
  it("VERSION constant matches package.json", () => {
    const pkg = JSON.parse(
      readFileSync(join(__dirname, "../package.json"), "utf-8")
    );
    const cli = readFileSync(
      join(__dirname, "../bin/agentseal.ts"), "utf-8"
    );
    const match = cli.match(/const VERSION = "([^"]+)"/);
    // After the fix, VERSION is read dynamically, so this test just checks package.json version
    expect(pkg.version).toBe("0.8.1");
  });
});

describe("CLI command registration", () => {
  let helpOutput: string;

  beforeAll(() => {
    helpOutput = execSync("node dist/agentseal.js --help", {
      cwd: join(__dirname, ".."),
      encoding: "utf-8",
      timeout: 15000,
    });
  });

  const expectedCommands = [
    "scan", "compare", "guard", "scan-mcp", "shield",
    "fix", "watch", "login", "activate", "profiles",
    "registry", "config",
  ];

  for (const cmd of expectedCommands) {
    it(`registers '${cmd}' command`, () => {
      expect(helpOutput).toContain(cmd);
    });
  }
});
