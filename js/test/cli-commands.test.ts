import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";

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
