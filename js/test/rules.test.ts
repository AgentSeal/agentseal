import { describe, it, expect } from "vitest";
import { mkdtempSync, writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

import {
  fnmatchCase,
  RuleEngine,
  type Rule,
  type RuleTestResult,
} from "../src/rules.js";

// ═══════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════

function tmpDir(): string {
  return mkdtempSync(join(tmpdir(), "rules-test-"));
}

function writeYaml(dir: string, name: string, content: string): string {
  const p = join(dir, name);
  writeFileSync(p, content, "utf-8");
  return p;
}

const VALID_RULE_YAML = `
rules:
  - id: CUSTOM-001
    title: Block dangerous server
    description: Blocks servers running as root
    severity: critical
    verdict: danger
    remediation: Do not run as root
    match:
      type: mcp
      command: "*sudo*"
    tests:
      - name: matches sudo
        input:
          command: /usr/bin/sudo node server.js
        expect: match
      - name: no match on safe command
        input:
          command: node server.js
        expect: no_match
`;

// ═══════════════════════════════════════════════════════════════════════
// fnmatchCase
// ═══════════════════════════════════════════════════════════════════════

describe("fnmatchCase", () => {
  it("* matches everything", () => {
    expect(fnmatchCase("anything", "*")).toBe(true);
    expect(fnmatchCase("", "*")).toBe(true);
    expect(fnmatchCase("hello world", "*")).toBe(true);
  });

  it("? matches single character", () => {
    expect(fnmatchCase("a", "?")).toBe(true);
    expect(fnmatchCase("ab", "?")).toBe(false);
    expect(fnmatchCase("abc", "a?c")).toBe(true);
    expect(fnmatchCase("ac", "a?c")).toBe(false);
  });

  it("*slack* matches my-slack-mcp", () => {
    expect(fnmatchCase("my-slack-mcp", "*slack*")).toBe(true);
    expect(fnmatchCase("my-teams-mcp", "*slack*")).toBe(false);
  });

  it("[abc] character class matches", () => {
    expect(fnmatchCase("a", "[abc]")).toBe(true);
    expect(fnmatchCase("b", "[abc]")).toBe(true);
    expect(fnmatchCase("d", "[abc]")).toBe(false);
  });

  it("[!abc] negation class matches", () => {
    expect(fnmatchCase("d", "[!abc]")).toBe(true);
    expect(fnmatchCase("a", "[!abc]")).toBe(false);
  });

  it("regex special characters are escaped", () => {
    // "foo.bar" pattern should NOT match "fooXbar"
    expect(fnmatchCase("fooXbar", "foo.bar")).toBe(false);
    // "foo.bar" pattern SHOULD match "foo.bar"
    expect(fnmatchCase("foo.bar", "foo.bar")).toBe(true);
  });

  it("case-insensitive matching", () => {
    expect(fnmatchCase("HELLO", "hello")).toBe(true);
    expect(fnmatchCase("Hello", "hElLo")).toBe(true);
    expect(fnmatchCase("my-Slack-MCP", "*slack*")).toBe(true);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// RuleEngine.fromPaths
// ═══════════════════════════════════════════════════════════════════════

describe("RuleEngine.fromPaths", () => {
  it("loads valid YAML rules from file", () => {
    const dir = tmpDir();
    const f = writeYaml(dir, "rules.yaml", VALID_RULE_YAML);
    const engine = RuleEngine.fromPaths([f]);
    expect(engine).toBeInstanceOf(RuleEngine);
  });

  it("loads rules from directory (globbing)", () => {
    const dir = tmpDir();
    writeYaml(dir, "a.yaml", VALID_RULE_YAML);
    writeYaml(dir, "b.yml", `
rules:
  - id: CUSTOM-002
    title: Second rule
    description: Another rule
    severity: high
    verdict: warning
    remediation: Fix it
    match:
      type: mcp
      name: "*bad*"
`);
    const engine = RuleEngine.fromPaths([dir]);
    // Should load both files
    const results = engine.evaluateMcp(
      { name: "bad-server", command: "sudo node", source_file: "/a.json" } as any,
      {},
    );
    // Should match at least CUSTOM-002 (name) and CUSTOM-001 (command)
    expect(results.length).toBeGreaterThanOrEqual(2);
  });

  it("throws on missing required fields", () => {
    const dir = tmpDir();
    writeYaml(dir, "bad.yaml", `
rules:
  - id: NO-TITLE
    severity: high
    verdict: danger
    match:
      type: mcp
      command: "*"
`);
    expect(() => RuleEngine.fromPaths([join(dir, "bad.yaml")])).toThrow(/title/i);
  });

  it("throws on invalid severity", () => {
    const dir = tmpDir();
    writeYaml(dir, "bad.yaml", `
rules:
  - id: BAD-SEV
    title: Bad severity
    description: test
    severity: extreme
    verdict: danger
    remediation: fix
    match:
      type: mcp
      command: "*"
`);
    expect(() => RuleEngine.fromPaths([join(dir, "bad.yaml")])).toThrow(/severity/i);
  });

  it("throws on invalid verdict", () => {
    const dir = tmpDir();
    writeYaml(dir, "bad.yaml", `
rules:
  - id: BAD-VERD
    title: Bad verdict
    description: test
    severity: high
    verdict: fatal
    remediation: fix
    match:
      type: mcp
      command: "*"
`);
    expect(() => RuleEngine.fromPaths([join(dir, "bad.yaml")])).toThrow(/verdict/i);
  });

  it("throws on duplicate IDs across files", () => {
    const dir = tmpDir();
    writeYaml(dir, "a.yaml", VALID_RULE_YAML);
    writeYaml(dir, "b.yaml", VALID_RULE_YAML); // same CUSTOM-001
    expect(() => RuleEngine.fromPaths([dir])).toThrow(/duplicate.*CUSTOM-001/i);
  });

  it("skips files without 'rules' key", () => {
    const dir = tmpDir();
    writeYaml(dir, "not-rules.yaml", `
some_other_key:
  - foo: bar
`);
    const f = join(dir, "not-rules.yaml");
    const engine = RuleEngine.fromPaths([f]);
    // Should succeed but have 0 rules
    const results = engine.evaluateMcp({ name: "test", command: "test", source_file: "" } as any, {});
    expect(results).toEqual([]);
  });

  it("throws on invalid match.type", () => {
    const dir = tmpDir();
    writeYaml(dir, "bad.yaml", `
rules:
  - id: BAD-TYPE
    title: Bad type
    description: test
    severity: high
    verdict: danger
    remediation: fix
    match:
      type: unknown
      command: "*"
`);
    expect(() => RuleEngine.fromPaths([join(dir, "bad.yaml")])).toThrow(/type/i);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// evaluateMcp
// ═══════════════════════════════════════════════════════════════════════

describe("evaluateMcp", () => {
  function mcpEngine(matchBlock: Record<string, any>): RuleEngine {
    const rule: Rule = {
      id: "MCP-TEST",
      title: "Test MCP rule",
      description: "For testing",
      severity: "high",
      verdict: "danger",
      remediation: "Fix it",
      match: { type: "mcp", ...matchBlock },
      tests: [],
      source_file: "test.yaml",
    };
    return new RuleEngine([rule]);
  }

  it("AND across fields — both must match", () => {
    const engine = mcpEngine({ command: "*node*", name: "*slack*" });
    const findings = engine.evaluateMcp(
      { name: "slack-mcp", command: "node server.js", source_file: "" } as any,
      {},
    );
    expect(findings).toHaveLength(1);

    // Name doesn't match
    const findings2 = engine.evaluateMcp(
      { name: "teams-mcp", command: "node server.js", source_file: "" } as any,
      {},
    );
    expect(findings2).toHaveLength(0);
  });

  it("OR within field — any pattern matches", () => {
    const engine = mcpEngine({ command: ["*node*", "*python*"] });
    const f1 = engine.evaluateMcp(
      { name: "test", command: "node server.js", source_file: "" } as any,
      {},
    );
    expect(f1).toHaveLength(1);

    const f2 = engine.evaluateMcp(
      { name: "test", command: "python app.py", source_file: "" } as any,
      {},
    );
    expect(f2).toHaveLength(1);

    const f3 = engine.evaluateMcp(
      { name: "test", command: "ruby app.rb", source_file: "" } as any,
      {},
    );
    expect(f3).toHaveLength(0);
  });

  it("coerces string to [string]", () => {
    const engine = mcpEngine({ command: "*test*" });
    const findings = engine.evaluateMcp(
      { name: "x", command: "test-server", source_file: "" } as any,
      {},
    );
    expect(findings).toHaveLength(1);
  });

  it("null entity values treated as empty string", () => {
    const engine = mcpEngine({ name: "*" }); // matches anything including ""
    const findings = engine.evaluateMcp(
      { command: "test", source_file: "" } as any, // name missing → undefined
      {},
    );
    expect(findings).toHaveLength(1);
  });

  it("builds env_keys and env_values from rawConfig", () => {
    const rule: Rule = {
      id: "MCP-ENV",
      title: "Env test",
      description: "Check env",
      severity: "medium",
      verdict: "warning",
      remediation: "Remove secrets",
      match: { type: "mcp", env_keys: "*SECRET*" },
      tests: [],
      source_file: "test.yaml",
    };
    const engine = new RuleEngine([rule]);
    const findings = engine.evaluateMcp(
      { name: "test", command: "node", source_file: "" } as any,
      { env: { MY_SECRET_KEY: "val123", NORMAL_KEY: "val" } },
    );
    expect(findings).toHaveLength(1);
  });

  it("returns CustomFinding with correct fields", () => {
    const engine = mcpEngine({ command: "*node*" });
    const findings = engine.evaluateMcp(
      { name: "my-server", command: "node app.js", source_file: "/config.json" } as any,
      {},
    );
    expect(findings).toHaveLength(1);
    const f = findings[0]!;
    expect(f.code).toBe("MCP-TEST");
    expect(f.title).toBe("Test MCP rule");
    expect(f.severity).toBe("high");
    expect(f.verdict).toBe("danger");
    expect(f.remediation).toBe("Fix it");
    expect(f.rule_file).toBe("test.yaml");
    expect(f.entity_type).toBe("mcp");
    expect(f.entity_name).toBe("my-server");
  });
});

// ═══════════════════════════════════════════════════════════════════════
// evaluateSkill
// ═══════════════════════════════════════════════════════════════════════

describe("evaluateSkill", () => {
  it("content truncated to 10240 chars", () => {
    const rule: Rule = {
      id: "SKILL-TRUNC",
      title: "Long content",
      description: "test",
      severity: "low",
      verdict: "warning",
      remediation: "fix",
      match: { type: "skill", content: "*MARKER*" },
      tests: [],
      source_file: "test.yaml",
    };
    const engine = new RuleEngine([rule]);

    // Marker within first 10240 chars — should match
    const content1 = "A".repeat(5000) + "MARKER" + "B".repeat(5000);
    const f1 = engine.evaluateSkill({ name: "skill1", path: "/a.ts" } as any, content1);
    expect(f1).toHaveLength(1);

    // Marker beyond 10240 chars — should NOT match
    const content2 = "A".repeat(10241) + "MARKER";
    const f2 = engine.evaluateSkill({ name: "skill2", path: "/b.ts" } as any, content2);
    expect(f2).toHaveLength(0);
  });

  it("path matching works", () => {
    const rule: Rule = {
      id: "SKILL-PATH",
      title: "Path match",
      description: "test",
      severity: "medium",
      verdict: "warning",
      remediation: "fix",
      match: { type: "skill", path: "*.secret*" },
      tests: [],
      source_file: "test.yaml",
    };
    const engine = new RuleEngine([rule]);
    const f1 = engine.evaluateSkill({ name: "s", path: "/home/.secret-skill" } as any, "content");
    expect(f1).toHaveLength(1);

    const f2 = engine.evaluateSkill({ name: "s", path: "/home/normal-skill" } as any, "content");
    expect(f2).toHaveLength(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// evaluateAgent
// ═══════════════════════════════════════════════════════════════════════

describe("evaluateAgent", () => {
  it("agent_type matching", () => {
    const rule: Rule = {
      id: "AGENT-TYPE",
      title: "Agent type match",
      description: "test",
      severity: "high",
      verdict: "danger",
      remediation: "fix",
      match: { type: "agent", agent_type: "cursor" },
      tests: [],
      source_file: "test.yaml",
    };
    const engine = new RuleEngine([rule]);

    const f1 = engine.evaluateAgent({ agent_type: "cursor", name: "Cursor", config_path: "/c" } as any);
    expect(f1).toHaveLength(1);
    expect(f1[0]!.entity_type).toBe("agent");
    expect(f1[0]!.entity_name).toBe("Cursor");

    const f2 = engine.evaluateAgent({ agent_type: "vscode", name: "VS Code", config_path: "/v" } as any);
    expect(f2).toHaveLength(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// runTests
// ═══════════════════════════════════════════════════════════════════════

describe("runTests", () => {
  it("passing tests produce passed=true", () => {
    const dir = tmpDir();
    const f = writeYaml(dir, "rules.yaml", VALID_RULE_YAML);
    const engine = RuleEngine.fromPaths([f]);
    const results = engine.runTests();
    // The VALID_RULE_YAML has two tests
    expect(results).toHaveLength(2);
    // "matches sudo" should pass
    const sudo = results.find((r) => r.test_name === "matches sudo");
    expect(sudo).toBeDefined();
    expect(sudo!.passed).toBe(true);
    expect(sudo!.expected).toBe("match");
    expect(sudo!.actual).toBe("match");
  });

  it("failing tests produce passed=false", () => {
    const rule: Rule = {
      id: "FAIL-TEST",
      title: "Intentional fail",
      description: "test",
      severity: "low",
      verdict: "warning",
      remediation: "fix",
      match: { type: "mcp", command: "*node*" },
      tests: [
        {
          name: "should fail",
          input: { command: "node server.js" },
          expect: "no_match", // expects no_match but command matches
        },
      ],
      source_file: "test.yaml",
    };
    const engine = new RuleEngine([rule]);
    const results = engine.runTests();
    expect(results).toHaveLength(1);
    expect(results[0]!.passed).toBe(false);
    expect(results[0]!.expected).toBe("no_match");
    expect(results[0]!.actual).toBe("match");
  });
});
