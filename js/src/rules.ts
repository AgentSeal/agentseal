/**
 * YAML community rule engine with glob matching.
 *
 * Port of Python agentseal/rules.py — same structure, TypeScript classes.
 */

import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { parse } from "yaml";

import type {
  CustomFinding,
  MCPServerResult,
  SkillResult,
  AgentConfigResult,
} from "./guard-models.js";

// ═══════════════════════════════════════════════════════════════════════
// GLOB MATCHING
// ═══════════════════════════════════════════════════════════════════════

/**
 * Match a value against a glob pattern (case-insensitive).
 *
 * Supports `*` (any chars), `?` (single char), `[abc]` and `[!abc]` character classes.
 * All regex special characters are escaped except glob operators.
 */
export function fnmatchCase(value: string, pattern: string): boolean {
  let re = "";
  let i = 0;
  while (i < pattern.length) {
    const ch = pattern[i]!;
    if (ch === "*") {
      re += ".*";
    } else if (ch === "?") {
      re += ".";
    } else if (ch === "[") {
      let j = i + 1;
      if (j < pattern.length && pattern[j] === "!") {
        re += "[^";
        j++;
      } else {
        re += "[";
      }
      while (j < pattern.length && pattern[j] !== "]") {
        re += pattern[j];
        j++;
      }
      if (j < pattern.length) {
        re += "]";
        i = j; // advance past the closing ]
      } else {
        // Unmatched [ — treat as literal
        re += "\\[";
      }
    } else if (".$^+{}()|\\".includes(ch)) {
      re += "\\" + ch;
    } else {
      re += ch;
    }
    i++;
  }
  return new RegExp(`^${re}$`, "i").test(value);
}

// ═══════════════════════════════════════════════════════════════════════
// INTERFACES
// ═══════════════════════════════════════════════════════════════════════

export interface RuleTest {
  name: string;
  input: Record<string, string>;
  expect: string; // "match" | "no_match"
}

export interface Rule {
  id: string;
  title: string;
  description: string;
  severity: string;   // "critical" | "high" | "medium" | "low"
  verdict: string;    // "danger" | "warning"
  remediation: string;
  match: Record<string, string | string[]>;
  tests: RuleTest[];
  source_file: string;
}

export interface RuleTestResult {
  rule_id: string;
  test_name: string;
  passed: boolean;
  expected: string;
  actual: string;
}

// ═══════════════════════════════════════════════════════════════════════
// VALIDATION CONSTANTS
// ═══════════════════════════════════════════════════════════════════════

const VALID_SEVERITIES = new Set(["critical", "high", "medium", "low"]);
const VALID_VERDICTS = new Set(["danger", "warning"]);
const VALID_MATCH_TYPES = new Set(["mcp", "skill", "agent"]);
const REQUIRED_FIELDS = ["id", "title", "severity", "verdict", "match"] as const;

// ═══════════════════════════════════════════════════════════════════════
// RULE ENGINE
// ═══════════════════════════════════════════════════════════════════════

export class RuleEngine {
  private rules: Rule[];

  constructor(rules: Rule[]) {
    this.rules = rules;
  }

  /**
   * Load rules from file paths and/or directory paths.
   *
   * - Files are loaded directly.
   * - Directories are globbed for *.yaml and *.yml files.
   * - Files without a top-level "rules" key are silently skipped.
   * - Validates required fields, severity, verdict, match.type.
   * - Throws on duplicate IDs across files.
   */
  static fromPaths(paths: string[]): RuleEngine {
    const resolvedFiles: string[] = [];

    for (const p of paths) {
      const stat = statSync(p);
      if (stat.isDirectory()) {
        const entries = readdirSync(p);
        for (const entry of entries) {
          if (entry.endsWith(".yaml") || entry.endsWith(".yml")) {
            resolvedFiles.push(join(p, entry));
          }
        }
      } else {
        resolvedFiles.push(p);
      }
    }

    const allRules: Rule[] = [];
    const seenIds = new Map<string, string>(); // id → source_file

    for (const filePath of resolvedFiles) {
      const raw = readFileSync(filePath, "utf-8");
      const doc = parse(raw) as Record<string, any> | null;

      if (!doc || !("rules" in doc)) {
        continue; // skip files without "rules" key
      }

      const rulesList = doc.rules;
      if (!Array.isArray(rulesList)) {
        continue;
      }

      for (const r of rulesList) {
        // Check required fields
        for (const field of REQUIRED_FIELDS) {
          if (r[field] == null || r[field] === "") {
            throw new Error(
              `Rule in ${filePath} is missing required field: ${field}`,
            );
          }
        }

        // Validate severity
        const sev = String(r.severity).toLowerCase();
        if (!VALID_SEVERITIES.has(sev)) {
          throw new Error(
            `Rule "${r.id}" in ${filePath} has invalid severity: "${r.severity}" (must be one of: ${[...VALID_SEVERITIES].join(", ")})`,
          );
        }

        // Validate verdict
        const verd = String(r.verdict).toLowerCase();
        if (!VALID_VERDICTS.has(verd)) {
          throw new Error(
            `Rule "${r.id}" in ${filePath} has invalid verdict: "${r.verdict}" (must be one of: ${[...VALID_VERDICTS].join(", ")})`,
          );
        }

        // Validate match.type
        const matchType = r.match?.type;
        if (!matchType || !VALID_MATCH_TYPES.has(String(matchType).toLowerCase())) {
          throw new Error(
            `Rule "${r.id}" in ${filePath} has invalid match.type: "${matchType}" (must be one of: ${[...VALID_MATCH_TYPES].join(", ")})`,
          );
        }

        // Check for duplicate IDs
        const id = String(r.id);
        const existingFile = seenIds.get(id);
        if (existingFile) {
          throw new Error(
            `Duplicate rule ID "${id}" found in ${filePath} (already defined in ${existingFile})`,
          );
        }
        seenIds.set(id, filePath);

        // Build validated Rule
        const rule: Rule = {
          id,
          title: String(r.title),
          description: r.description ? String(r.description) : "",
          severity: sev,
          verdict: verd,
          remediation: r.remediation ? String(r.remediation) : "",
          match: r.match as Record<string, string | string[]>,
          tests: Array.isArray(r.tests)
            ? r.tests.map((t: any) => ({
                name: String(t.name ?? ""),
                input: (t.input ?? {}) as Record<string, string>,
                expect: String(t.expect ?? "no_match"),
              }))
            : [],
          source_file: filePath,
        };

        allRules.push(rule);
      }
    }

    return new RuleEngine(allRules);
  }

  // ─────────────────────────────────────────────────────────────────────
  // Internal matching
  // ─────────────────────────────────────────────────────────────────────

  /**
   * Check if a rule matches an entity's data.
   *
   * - AND logic across fields (all fields must match).
   * - OR logic within a field (any pattern in the array matches).
   * - The "type" field in match is skipped (used for routing only).
   */
  private _matchEntity(rule: Rule, entityData: Record<string, string>): boolean {
    for (const [field, patterns] of Object.entries(rule.match)) {
      if (field === "type") continue;

      const patternList = typeof patterns === "string" ? [patterns] : patterns;
      const entityValue = entityData[field] ?? "";

      let fieldMatched = false;
      for (const pattern of patternList) {
        if (fnmatchCase(entityValue, String(pattern))) {
          fieldMatched = true;
          break;
        }
      }
      if (!fieldMatched) return false;
    }
    return true;
  }

  // ─────────────────────────────────────────────────────────────────────
  // Evaluate methods
  // ─────────────────────────────────────────────────────────────────────

  /**
   * Evaluate MCP rules against a server result.
   */
  evaluateMcp(
    server: MCPServerResult | Record<string, any>,
    rawConfig: Record<string, any>,
  ): CustomFinding[] {
    const mcpRules = this.rules.filter(
      (r) => String(r.match.type).toLowerCase() === "mcp",
    );

    // Build entity data
    const args = rawConfig.args;
    const argsStr = Array.isArray(args) ? args.join(" ") : String(args ?? "");

    const env = rawConfig.env as Record<string, string> | undefined;
    const envKeys = env ? Object.keys(env).join(" ") : "";
    const envValues = env ? Object.values(env).join(" ") : "";

    const entityData: Record<string, string> = {
      name: String(server.name ?? ""),
      command: String(server.command ?? ""),
      args: argsStr,
      env_keys: envKeys,
      env_values: envValues,
      source_file: String(server.source_file ?? ""),
    };

    const findings: CustomFinding[] = [];
    for (const rule of mcpRules) {
      if (this._matchEntity(rule, entityData)) {
        findings.push({
          code: rule.id,
          title: rule.title,
          severity: rule.severity,
          verdict: rule.verdict,
          remediation: rule.remediation,
          rule_file: rule.source_file,
          entity_type: "mcp",
          entity_name: entityData.name,
        });
      }
    }
    return findings;
  }

  /**
   * Evaluate skill rules against a skill result.
   */
  evaluateSkill(
    skill: SkillResult | Record<string, any>,
    content: string,
  ): CustomFinding[] {
    const skillRules = this.rules.filter(
      (r) => String(r.match.type).toLowerCase() === "skill",
    );

    const entityData: Record<string, string> = {
      name: String(skill.name ?? ""),
      path: String(skill.path ?? ""),
      content: content.slice(0, 10240),
    };

    const findings: CustomFinding[] = [];
    for (const rule of skillRules) {
      if (this._matchEntity(rule, entityData)) {
        findings.push({
          code: rule.id,
          title: rule.title,
          severity: rule.severity,
          verdict: rule.verdict,
          remediation: rule.remediation,
          rule_file: rule.source_file,
          entity_type: "skill",
          entity_name: entityData.name,
        });
      }
    }
    return findings;
  }

  /**
   * Evaluate agent rules against an agent config result.
   */
  evaluateAgent(
    agent: AgentConfigResult | Record<string, any>,
  ): CustomFinding[] {
    const agentRules = this.rules.filter(
      (r) => String(r.match.type).toLowerCase() === "agent",
    );

    const entityData: Record<string, string> = {
      agent_type: String(agent.agent_type ?? ""),
      name: String(agent.name ?? ""),
      config_path: String(agent.config_path ?? ""),
    };

    const findings: CustomFinding[] = [];
    for (const rule of agentRules) {
      if (this._matchEntity(rule, entityData)) {
        findings.push({
          code: rule.id,
          title: rule.title,
          severity: rule.severity,
          verdict: rule.verdict,
          remediation: rule.remediation,
          rule_file: rule.source_file,
          entity_type: "agent",
          entity_name: entityData.name,
        });
      }
    }
    return findings;
  }

  // ─────────────────────────────────────────────────────────────────────
  // Self-test
  // ─────────────────────────────────────────────────────────────────────

  /**
   * Run embedded tests for all rules.
   */
  runTests(): RuleTestResult[] {
    const results: RuleTestResult[] = [];
    for (const rule of this.rules) {
      for (const test of rule.tests) {
        const matched = this._matchEntity(rule, test.input);
        const actual = matched ? "match" : "no_match";
        results.push({
          rule_id: rule.id,
          test_name: test.name,
          passed: actual === test.expect,
          expected: test.expect,
          actual,
        });
      }
    }
    return results;
  }
}
