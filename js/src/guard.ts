/**
 * Guard — one-command machine security scan.
 *
 * Chains machine discovery, skill scanning, blocklist, deobfuscation,
 * project config, custom rules, registry enrichment, history/delta,
 * and unlisted findings into a single zero-config experience.
 *
 * Port of Python agentseal/guard.py + agentseal/skill_scanner.py.
 */

import { createHash } from "node:crypto";
import { readFileSync, statSync } from "node:fs";
import { basename, extname } from "node:path";

import { BaselineStore } from "./baselines.js";
import { Blocklist } from "./blocklist.js";
import { deobfuscate } from "./deobfuscate.js";
import {
  GuardVerdict,
  guardReportFromDict,
  type CustomFinding,
  type GuardReport,
  type MCPServerResult,
  type SkillFinding,
  type SkillResult,
  type UnlistedFinding,
} from "./guard-models.js";
import { HistoryStore, computeDelta } from "./history.js";
import { scanDirectory, scanMachine, type DiscoveryResult } from "./machine-discovery.js";
import { MCPConfigChecker } from "./mcp-checker.js";
import {
  resolveProjectConfig,
  shouldIgnorePath,
  shouldIgnoreFinding,
  generateUnlistedFindings,
  type ProjectConfig,
} from "./project-config.js";
import { enrichMcpResults } from "./registry-client.js";
import { RuleEngine } from "./rules.js";
import { SkillScanner } from "./skill-scanner.js";
import { analyzeToxicFlows } from "./toxic-flows.js";

// ═══════════════════════════════════════════════════════════════════════
// PROGRESS CALLBACK
// ═══════════════════════════════════════════════════════════════════════

export type GuardProgressFn = (phase: string, detail: string) => void;

// ═══════════════════════════════════════════════════════════════════════
// GUARD OPTIONS
// ═══════════════════════════════════════════════════════════════════════

export interface GuardOptions {
  /** Enable semantic analysis (requires embedFn). Default: false */
  semantic?: boolean;
  /** Verbose output. Default: false */
  verbose?: boolean;
  /** Progress callback. */
  onProgress?: GuardProgressFn;
  /** Embedding function for semantic analysis. */
  embedFn?: (texts: string[]) => Promise<number[][]>;
  /** Scan a specific directory instead of the whole machine. */
  scanPath?: string;
  /** Pre-loaded project config. If not provided, resolved from scanPath. */
  config?: ProjectConfig;
  /** Skip registry enrichment. Default: false */
  noRegistry?: boolean;
  /** Skip history save and delta computation. Default: false */
  noDiff?: boolean;
  /** Paths to custom rule files/directories. */
  rulesPaths?: string[];
  /** Load a previously saved JSON report instead of scanning. */
  fromJson?: string;
  /** Fail threshold: "danger" (default), "warning", or "safe". */
  failOn?: string;
}

// ═══════════════════════════════════════════════════════════════════════
// SKILL FILE SCANNER
// ═══════════════════════════════════════════════════════════════════════

const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10 MB

/** Extract a human-readable name from a skill file path. */
function extractSkillName(filePath: string): string {
  const name = basename(filePath);
  if (name.toLowerCase() === "skill.md") {
    // Use parent directory name
    const parts = filePath.split("/");
    return parts[parts.length - 2] ?? name;
  }
  // Remove extension
  const ext = extname(name);
  return ext ? name.slice(0, -ext.length) : name;
}

/** Determine verdict from findings. Worst severity wins. */
function computeVerdict(findings: SkillFinding[]): GuardVerdict {
  if (findings.length === 0) return GuardVerdict.SAFE;
  if (findings.some((f) => f.severity === "critical")) return GuardVerdict.DANGER;
  if (findings.some((f) => f.severity === "high" || f.severity === "medium")) return GuardVerdict.WARNING;
  return GuardVerdict.SAFE;
}

/** Scan a single skill file through all detection layers. */
function scanSkillFile(
  filePath: string,
  scanner: SkillScanner,
  blocklist: Blocklist,
): SkillResult {
  const name = extractSkillName(filePath);

  // Read file
  let content: string;
  let sha256: string;
  try {
    const stat = statSync(filePath);
    if (stat.size > MAX_FILE_SIZE) {
      return {
        name,
        path: filePath,
        verdict: GuardVerdict.ERROR,
        findings: [{
          code: "SKILL-ERR",
          title: "File too large",
          description: `File is ${Math.floor(stat.size / 1024 / 1024)}MB, max is 10MB.`,
          severity: "low",
          evidence: "",
          remediation: "Skill files should be small text files.",
        }],
        blocklist_match: false,
        sha256: "",
      };
    }

    const raw = readFileSync(filePath);
    sha256 = createHash("sha256").update(raw).digest("hex");
    content = raw.toString("utf-8");
  } catch (err) {
    return {
      name,
      path: filePath,
      verdict: GuardVerdict.ERROR,
      findings: [{
        code: "SKILL-ERR",
        title: "Could not read file",
        description: String(err),
        severity: "low",
        evidence: "",
        remediation: "Check file permissions.",
      }],
      blocklist_match: false,
      sha256: "",
    };
  }

  if (!content.trim()) {
    return { name, path: filePath, verdict: GuardVerdict.SAFE, findings: [], blocklist_match: false, sha256 };
  }

  // Layer 1: Blocklist check
  if (blocklist.isBlocked(sha256)) {
    return {
      name,
      path: filePath,
      verdict: GuardVerdict.DANGER,
      findings: [{
        code: "SKILL-000",
        title: "Known malicious skill",
        description: "This skill matches a known malware hash in the AgentSeal threat database.",
        severity: "critical",
        evidence: `SHA256: ${sha256}`,
        remediation: "Remove this skill immediately and rotate all credentials.",
      }],
      blocklist_match: true,
      sha256,
    };
  }

  // Layer 2: Static pattern matching (on original + deobfuscated content)
  const findings = scanner.scanPatterns(content);
  const deobfuscated = deobfuscate(content);
  if (deobfuscated !== content) {
    const deobFindings = scanner.scanPatterns(deobfuscated);
    const existing = new Set(findings.map((f) => `${f.code}::${f.evidence}`));
    for (const f of deobFindings) {
      if (!existing.has(`${f.code}::${f.evidence}`)) {
        findings.push(f);
      }
    }
  }

  const verdict = computeVerdict(findings);

  return { name, path: filePath, verdict, findings, blocklist_match: false, sha256 };
}

// ═══════════════════════════════════════════════════════════════════════
// GUARD CLASS
// ═══════════════════════════════════════════════════════════════════════

export class Guard {
  private readonly options: GuardOptions;

  constructor(options: GuardOptions = {}) {
    this.options = options;
  }

  /** Execute full guard scan. Returns a GuardReport with all findings. */
  async run(): Promise<GuardReport> {
    // ── fromJson early return ──
    if (this.options.fromJson) {
      const data = JSON.parse(readFileSync(this.options.fromJson, "utf-8"));
      return guardReportFromDict(data);
    }

    const start = performance.now();
    const progress = this.options.onProgress ?? (() => {});

    // ── Phase 0: Resolve project config ──
    const config = this.options.config ?? resolveProjectConfig({ searchDir: this.options.scanPath });

    // ── Phase 0b: Resolve rules engine ──
    let ruleEngine: RuleEngine | null = null;
    const rulesPaths = this.options.rulesPaths ?? config?.rules_paths ?? [];
    if (rulesPaths.length > 0) {
      try {
        ruleEngine = RuleEngine.fromPaths(rulesPaths);
      } catch (err) {
        process.stderr.write(`[agentseal] warning: failed to load rules: ${err}\n`);
      }
    }

    // ── Phase 1: Discover ──
    let discovery: DiscoveryResult;
    if (this.options.scanPath) {
      progress("discover", `Scanning directory: ${this.options.scanPath}`);
      discovery = scanDirectory(this.options.scanPath);
    } else {
      progress("discover", "Scanning for AI agents, skills, and MCP servers...");
      discovery = scanMachine();
    }

    const installedCount = discovery.agents.filter(
      (a) => a.status === "found" || a.status === "installed_no_config",
    ).length;
    progress(
      "discover",
      `Found ${installedCount} agents, ${discovery.skillPaths.length} skills, ` +
        `${discovery.mcpServers.length} MCP servers`,
    );

    // ── Phase 1b: Filter skill paths by ignore_paths ──
    let skillPaths = discovery.skillPaths;
    if (config && config.ignore_paths.length > 0) {
      skillPaths = skillPaths.filter((p) => !shouldIgnorePath(config, p));
    }

    // ── Phase 2: Scan skills ──
    progress("skills", `Scanning ${skillPaths.length} skills for threats...`);
    const scanner = new SkillScanner();
    const blocklist = new Blocklist();
    const skillResults: SkillResult[] = [];
    for (let i = 0; i < skillPaths.length; i++) {
      const path = skillPaths[i]!;
      progress("skills", `[${i + 1}/${skillPaths.length}] ${basename(path)}`);
      skillResults.push(scanSkillFile(path, scanner, blocklist));
    }

    // ── Phase 2b: Evaluate custom rules on skills ──
    const customFindings: CustomFinding[] = [];
    if (ruleEngine) {
      for (const skill of skillResults) {
        let content = "";
        try {
          content = readFileSync(skill.path, "utf-8").slice(0, 10240);
        } catch { /* ignore read errors */ }
        const findings = ruleEngine.evaluateSkill(skill, content);
        customFindings.push(...findings);
      }
    }

    // ── Phase 3: Check MCP configs ──
    // Keep raw config dicts alongside results for rule evaluation and unlisted findings
    const rawMcpConfigs = discovery.mcpServers;
    progress("mcp", `Checking ${rawMcpConfigs.length} MCP server configurations...`);
    const mcpChecker = new MCPConfigChecker();
    const mcpResults: MCPServerResult[] = mcpChecker.checkAll(rawMcpConfigs);

    // ── Phase 3b: Evaluate custom rules on MCPs ──
    if (ruleEngine) {
      for (let i = 0; i < mcpResults.length; i++) {
        const result = mcpResults[i]!;
        const rawConfig = rawMcpConfigs[i] ?? {};
        const findings = ruleEngine.evaluateMcp(result, rawConfig);
        customFindings.push(...findings);
      }
    }

    // ── Phase 3c: Evaluate custom rules on agents ──
    if (ruleEngine) {
      for (const agent of discovery.agents) {
        const findings = ruleEngine.evaluateAgent(agent);
        customFindings.push(...findings);
      }
    }

    // ── Phase 4: Registry enrichment ──
    if (!this.options.noRegistry) {
      try {
        await enrichMcpResults(mcpResults);
      } catch {
        // Registry enrichment is best-effort
      }
    }

    // ── Phase 5: Unlisted findings ──
    const unlistedFindings: UnlistedFinding[] = config
      ? generateUnlistedFindings(config, discovery.agents, rawMcpConfigs)
      : [];

    // ── Phase 6: Toxic flow analysis ──
    const toxicFlows = rawMcpConfigs.length >= 2
      ? analyzeToxicFlows(rawMcpConfigs)
      : [];
    if (toxicFlows.length > 0) {
      progress("flows", `Found ${toxicFlows.length} toxic flow(s)`);
    }

    // ── Phase 7: Baseline check (rug pull detection) ──
    const baselineStore = new BaselineStore();
    const baselineChanges = rawMcpConfigs.length > 0
      ? baselineStore.checkAll(rawMcpConfigs).map((c) => ({
          server_name: c.server_name,
          agent_type: c.agent_type,
          change_type: c.change_type,
          detail: c.detail,
        }))
      : [];
    if (baselineChanges.length > 0) {
      progress("baselines", `${baselineChanges.length} baseline change(s) detected`);
    }

    // ── Phase 8: Apply ignore_findings filter ──
    if (config && config.ignore_findings.length > 0) {
      for (const skill of skillResults) {
        skill.findings = skill.findings.filter(
          (f) => !shouldIgnoreFinding(config, f.code, skill.path),
        );
        // Recompute verdict after filtering
        skill.verdict = computeVerdict(skill.findings);
      }
      for (const mcp of mcpResults) {
        mcp.findings = mcp.findings.filter(
          (f) => !shouldIgnoreFinding(config, f.code, mcp.source_file),
        );
        // Recompute verdict
        if (mcp.findings.length === 0) {
          mcp.verdict = GuardVerdict.SAFE;
        } else if (mcp.findings.some((f) => f.severity === "critical")) {
          mcp.verdict = GuardVerdict.DANGER;
        } else if (mcp.findings.some((f) => f.severity === "high" || f.severity === "medium")) {
          mcp.verdict = GuardVerdict.WARNING;
        } else {
          mcp.verdict = GuardVerdict.SAFE;
        }
      }
    }

    const duration = (performance.now() - start) / 1000;

    const report: GuardReport = {
      timestamp: new Date().toISOString(),
      duration_seconds: Math.round(duration * 100) / 100,
      agents_found: discovery.agents,
      skill_results: skillResults,
      mcp_results: mcpResults,
      mcp_runtime_results: [],
      toxic_flows: toxicFlows,
      baseline_changes: baselineChanges,
      llm_tokens_used: 0,
      unlisted_findings: unlistedFindings,
      custom_findings: customFindings,
      config_path: config?.config_path ?? "",
    };

    // ── Phase 9: History save + delta ──
    if (!this.options.noDiff) {
      try {
        const store = new HistoryStore();
        store.save(report, this.options.scanPath);
        const prev = store.loadPrevious(this.options.scanPath);
        if (prev) {
          const _delta = computeDelta(report, prev, this.options.scanPath);
          // Delta is computed but not stored on report yet (no field defined)
          // It could be accessed via history store by callers
        }
        store.close();
      } catch {
        // History is best-effort
      }
    }

    return report;
  }
}

// Re-export for convenience
export { scanSkillFile, extractSkillName, computeVerdict };
