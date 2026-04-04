// bin/agentseal.ts — CLI entry point

import { Command } from "commander";
import { AgentValidator } from "../src/validator.js";
import { fromEndpoint } from "../src/providers/http.js";
import { fromOllama } from "../src/providers/ollama.js";
import { generateRemediation } from "../src/remediation.js";
import { compareReports } from "../src/compare.js";
import type { ScanReport } from "../src/types.js";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { loadConfig, saveConfigKey, removeConfigKey, showConfig, CONFIG_KEYS } from "../src/config.js";
import { Shield } from "../src/shield.js";
import { renderMCPResults, type MCPScanResult } from "../src/scan-mcp-cli.js";
import { MCPConfigChecker, verdictFromFindings } from "../src/mcp-checker.js";
import { selectCanaryProbes } from "../src/watch.js";
import { listProfiles } from "../src/profiles.js";
import { bulkCheck } from "../src/registry-client.js";
import {
  quarantineSkill,
  restoreSkill,
  listQuarantine,
  loadGuardReport,
  loadScanReport,
  getFixableSkills,
} from "../src/fix.js";
import { saveCredentials, saveLicense } from "../src/login.js";
import { Guard } from "../src/guard.js";
import {
  resolveProjectConfig,
  runGuardInit,
  shouldFail,
} from "../src/project-config.js";
import { RuleEngine } from "../src/rules.js";
import { BaselineStore } from "../src/baselines.js";
import {
  guardReportFromDict,
  totalDangers,
  totalWarnings,
  totalSafe,
  type GuardReport,
  type SkillResult,
  type MCPServerResult,
  type CustomFinding,
  type DeltaEntry,
} from "../src/guard-models.js";
import { computeDelta, HistoryStore } from "../src/history.js";

const __pkgdir = join(dirname(fileURLToPath(import.meta.url)), "..");
const VERSION = JSON.parse(readFileSync(join(__pkgdir, "package.json"), "utf-8")).version as string;

function printBanner() {
  const R = "\x1b[0m";
  const D = "\x1b[90m";
  const C = "\x1b[36m";
  console.log();
  console.log(`  ${C}╔═══════════════════════════════════════╗${R}`);
  console.log(`  ${C}║         A G E N T S E A L             ║${R}`);
  console.log(`  ${C}╚═══════════════════════════════════════╝${R}`);
  console.log(`  ${D}v${VERSION}  Security Validator for AI Agents${R}`);
  console.log();
}

function resolveApiKey(args: { apiKey?: string; model?: string }): string | undefined {
  if (args.apiKey) return args.apiKey;
  if (args.model?.startsWith("claude") || args.model?.startsWith("anthropic/")) {
    return process.env["ANTHROPIC_API_KEY"];
  }
  return process.env["OPENAI_API_KEY"];
}

async function buildValidator(
  systemPrompt: string,
  args: {
    model?: string;
    apiKey?: string;
    ollamaUrl?: string;
    name?: string;
    concurrency?: number;
    timeout?: number;
    verbose?: boolean;
    adaptive?: boolean;
  },
): Promise<AgentValidator> {
  const model = args.model;
  if (!model) {
    console.error("Error: --model is required when using --prompt or --file");
    process.exit(1);
  }

  const commonOpts = {
    agentName: args.name ?? "My Agent",
    concurrency: args.concurrency ?? 3,
    timeoutPerProbe: args.timeout ?? 30,
    verbose: args.verbose ?? false,
    adaptive: args.adaptive ?? false,
  };

  // Ollama
  if (model.startsWith("ollama/")) {
    const ollamaModel = model.replace("ollama/", "");
    return AgentValidator.fromOllama({
      model: ollamaModel,
      systemPrompt,
      baseUrl: args.ollamaUrl ?? "http://localhost:11434",
      ...commonOpts,
    });
  }

  // Anthropic
  if (model.startsWith("claude")) {
    const apiKey = resolveApiKey(args);
    if (!apiKey) {
      console.error("Error: ANTHROPIC_API_KEY not found. Set via --api-key or env variable.");
      process.exit(1);
    }
    const agentFn = async (message: string): Promise<string> => {
      const res = await fetch("https://api.anthropic.com/v1/messages", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-api-key": apiKey,
          "anthropic-version": "2023-06-01",
        },
        body: JSON.stringify({
          model,
          max_tokens: 1024,
          system: systemPrompt,
          messages: [{ role: "user", content: message }],
        }),
      });
      const data = await res.json() as { content?: { text?: string }[] };
      return data.content?.[0]?.text ?? "";
    };
    return new AgentValidator({
      agentFn,
      groundTruthPrompt: systemPrompt,
      ...commonOpts,
    });
  }

  // Default: OpenAI-compatible
  const apiKey = resolveApiKey(args);
  if (!apiKey) {
    console.error("Error: OPENAI_API_KEY not found. Set via --api-key or env variable.");
    process.exit(1);
  }
  const agentFn = async (message: string): Promise<string> => {
    const res = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${apiKey}`,
      },
      body: JSON.stringify({
        model,
        messages: [
          { role: "system", content: systemPrompt },
          { role: "user", content: message },
        ],
      }),
    });
    const data = await res.json() as { choices?: { message?: { content?: string } }[] };
    return data.choices?.[0]?.message?.content ?? "";
  };
  return new AgentValidator({
    agentFn,
    groundTruthPrompt: systemPrompt,
    ...commonOpts,
  });
}

function printReport(report: ScanReport) {
  const R = "\x1b[0m";
  const G = "\x1b[32m";
  const Y = "\x1b[33m";
  const RED = "\x1b[31m";
  const D = "\x1b[90m";
  const B = "\x1b[1m";

  const scoreColor = report.trust_score >= 70 ? G : report.trust_score >= 50 ? Y : RED;

  console.log(`${B}Results:${R}`);
  console.log(`  Agent:          ${report.agent_name}`);
  console.log(`  Trust Score:    ${scoreColor}${B}${report.trust_score.toFixed(1)}${R} / 100 (${report.trust_level})`);
  console.log(`  Duration:       ${report.duration_seconds.toFixed(1)}s`);
  console.log();
  console.log(`  ${G}Blocked: ${report.probes_blocked}${R}  ${RED}Leaked: ${report.probes_leaked}${R}  ${Y}Partial: ${report.probes_partial}${R}  ${D}Error: ${report.probes_error}${R}`);
  console.log();
  console.log(`${B}Score Breakdown:${R}`);
  console.log(`  Extraction Resistance: ${report.score_breakdown.extraction_resistance.toFixed(1)}`);
  console.log(`  Injection Resistance:  ${report.score_breakdown.injection_resistance.toFixed(1)}`);
  console.log(`  Boundary Integrity:    ${report.score_breakdown.boundary_integrity.toFixed(1)}`);
  console.log(`  Consistency:           ${report.score_breakdown.consistency.toFixed(1)}`);

  if (report.defense_profile) {
    console.log();
    console.log(`${B}Defense Profile:${R} ${report.defense_profile.defense_system} (${(report.defense_profile.confidence * 100).toFixed(0)}% confidence)`);
  }

  if (report.mutation_resistance !== undefined) {
    console.log();
    console.log(`${B}Mutation Resistance:${R} ${report.mutation_resistance.toFixed(1)}%`);
  }
}

const program = new Command();

program
  .name("agentseal")
  .description("Security validator for AI agents")
  .version(VERSION);

program
  .command("scan")
  .description("Run security scan against an agent")
  .option("-p, --prompt <text>", "System prompt to test")
  .option("-f, --file <path>", "Path to file containing system prompt")
  .option("--url <url>", "HTTP endpoint URL to test")
  .option("-m, --model <name>", "Model to test (e.g. gpt-4o, claude-sonnet-4-5-20250929, ollama/qwen3)")
  .option("--api-key <key>", "API key")
  .option("--ollama-url <url>", "Ollama base URL", "http://localhost:11434")
  .option("--message-field <field>", "HTTP request message field", "message")
  .option("--response-field <field>", "HTTP response field", "response")
  .option("-o, --output <format>", "Output format: terminal, json", "terminal")
  .option("--save <path>", "Save JSON report to file")
  .option("--name <name>", "Agent name for report", "My Agent")
  .option("--concurrency <n>", "Max parallel probes", "3")
  .option("--timeout <seconds>", "Timeout per probe", "30")
  .option("-v, --verbose", "Show each probe result")
  .option("--adaptive", "Enable adaptive mutation phase")
  .option("--min-score <score>", "Exit code 1 if below (CI mode)")
  .option("--json-remediation", "Include structured remediation in JSON output")
  .argument("[prompt]", "Quick inline prompt")
  .action(async (inlinePrompt, opts) => {
    printBanner();

    let systemPrompt: string | undefined;

    if (opts.prompt) {
      systemPrompt = opts.prompt;
    } else if (inlinePrompt) {
      systemPrompt = inlinePrompt;
    } else if (opts.file) {
      systemPrompt = readFileSync(opts.file, "utf-8").trim();
    }

    let validator: AgentValidator;

    if (opts.url) {
      validator = AgentValidator.fromEndpoint({
        url: opts.url,
        messageField: opts.messageField,
        responseField: opts.responseField,
        agentName: opts.name,
        concurrency: parseInt(opts.concurrency),
        timeoutPerProbe: parseFloat(opts.timeout),
        verbose: opts.verbose,
        adaptive: opts.adaptive,
        ...(systemPrompt ? { groundTruthPrompt: systemPrompt } : {}),
      });
    } else if (systemPrompt) {
      validator = await buildValidator(systemPrompt, {
        model: opts.model,
        apiKey: opts.apiKey,
        ollamaUrl: opts.ollamaUrl,
        name: opts.name,
        concurrency: parseInt(opts.concurrency),
        timeout: parseFloat(opts.timeout),
        verbose: opts.verbose,
        adaptive: opts.adaptive,
      });
    } else {
      console.error("Error: Provide --prompt, --file, or --url");
      process.exit(1);
    }

    console.log("Starting security scan...\n");

    const report = await validator.run();

    if (opts.output === "json") {
      const output: Record<string, unknown> = { ...report };
      if (opts.jsonRemediation) {
        output.remediation = generateRemediation(report);
      }
      const json = JSON.stringify(output, null, 2);
      console.log(json);
    } else {
      printReport(report);

      // Show top failures
      const leaked = report.results.filter((r) => r.verdict === "leaked");
      if (leaked.length > 0) {
        console.log(`\n\x1b[1mTop Failures:\x1b[0m`);
        for (const r of leaked.slice(0, 5)) {
          console.log(`  \x1b[31m✗\x1b[0m ${r.probe_id} (${r.category}) — ${r.reasoning.slice(0, 80)}`);
        }
      }

      // Show remediation summary
      const remediation = generateRemediation(report);
      if (remediation.items.length > 0 && remediation.items[0]!.category !== "") {
        console.log(`\n\x1b[1mRemediation:\x1b[0m`);
        for (const item of remediation.items.slice(0, 5)) {
          console.log(`  [${item.priority}] ${item.title}`);
        }
        console.log(`\n  Run with --output json --json-remediation for full fix instructions.`);
      }
    }

    if (opts.save) {
      writeFileSync(opts.save, JSON.stringify(report, null, 2));
      console.log(`\nReport saved to ${opts.save}`);
    }

    // CI mode
    if (opts.minScore) {
      const threshold = parseInt(opts.minScore);
      if (report.trust_score < threshold) {
        console.error(`\nCI check failed: score ${report.trust_score.toFixed(1)} < threshold ${threshold}`);
        process.exit(1);
      }
    }
  });

program
  .command("compare")
  .description("Compare two scan reports")
  .argument("<baseline>", "Path to baseline report (JSON)")
  .argument("<current>", "Path to current report (JSON)")
  .option("-o, --output <format>", "Output format: terminal, json", "terminal")
  .action((baselinePath, currentPath, opts) => {
    const baseline = JSON.parse(readFileSync(baselinePath, "utf-8")) as ScanReport;
    const current = JSON.parse(readFileSync(currentPath, "utf-8")) as ScanReport;
    const result = compareReports(baseline, current);

    if (opts.output === "json") {
      console.log(JSON.stringify(result, null, 2));
    } else {
      console.log(result.summary);
      if (result.regressions.length > 0) {
        console.log(`\nRegressions:`);
        for (const r of result.regressions) {
          console.log(`  \x1b[31m↓\x1b[0m ${r.probe_id} — now ${r.verdict}`);
        }
      }
      if (result.improvements.length > 0) {
        console.log(`\nImprovements:`);
        for (const r of result.improvements) {
          console.log(`  \x1b[32m↑\x1b[0m ${r.probe_id} — now ${r.verdict}`);
        }
      }
    }
  });

// ═══════════════════════════════════════════════════════════════════════════
// GUARD — Terminal renderer
// ═══════════════════════════════════════════════════════════════════════════

function stripAnsi(s: string): string {
  return s.replace(/\x1b\[[0-9;]*m/g, "");
}

function col(s: string, width: number): string {
  return s + " ".repeat(Math.max(0, width - stripAnsi(s).length));
}

function verdictColor(verdict: string): string {
  const R = "\x1b[0m";
  switch (verdict) {
    case "safe": return `\x1b[32m${verdict.toUpperCase()}${R}`;
    case "warning": return `\x1b[33m${verdict.toUpperCase()}${R}`;
    case "danger": return `\x1b[31m${verdict.toUpperCase()}${R}`;
    case "error": return `\x1b[90m${verdict.toUpperCase()}${R}`;
    default: return verdict.toUpperCase();
  }
}

function severityColor(severity: string): string {
  const R = "\x1b[0m";
  switch (severity) {
    case "critical": return `\x1b[31m${severity}${R}`;
    case "high": return `\x1b[31m${severity}${R}`;
    case "medium": return `\x1b[33m${severity}${R}`;
    case "low": return `\x1b[90m${severity}${R}`;
    default: return severity;
  }
}

interface RenderOpts {
  verbose?: boolean;
  config?: ReturnType<typeof resolveProjectConfig>;
  delta?: { total_new: number; total_resolved: number; total_changed: number; entries: DeltaEntry[] } | null;
}

function renderGuardTerminal(report: GuardReport, opts: RenderOpts = {}): void {
  const R = "\x1b[0m";
  const C = "\x1b[36m";
  const B = "\x1b[1m";
  const D = "\x1b[90m";
  const G = "\x1b[32m";
  const Y = "\x1b[33m";
  const RED = "\x1b[31m";

  // Header
  console.log();
  console.log(`  ${C}${B}AgentSeal Guard${R} ${D}— Machine Security Scan${R}`);
  console.log(`  ${D}${"─".repeat(50)}${R}`);
  console.log();

  // AGENTS section
  const agents = report.agents_found ?? [];
  if (agents.length > 0) {
    console.log(`  ${C}${B}AGENTS${R}`);
    console.log(`  ${col(D + "NAME" + R, 30)} ${D}STATUS${R}`);
    for (const a of agents) {
      const status = a.status === "found" || a.status === "installed_no_config"
        ? `${G}installed${R}`
        : `${D}${a.status}${R}`;
      console.log(`  ${col(a.name, 30)} ${status}`);
    }
    console.log();
  }

  // SKILLS section
  const skills = report.skill_results ?? [];
  const dangerOrWarnSkills = opts.verbose
    ? skills
    : skills.filter((s) => s.verdict !== "safe");
  if (dangerOrWarnSkills.length > 0 || (opts.verbose && skills.length > 0)) {
    console.log(`  ${C}${B}SKILLS${R}`);
    console.log(`  ${col(D + "NAME" + R, 24)} ${col(D + "VERDICT" + R, 16)} ${col(D + "SEVERITY" + R, 14)} ${D}FINDING${R}`);
    const toShow = opts.verbose ? skills : dangerOrWarnSkills;
    for (const s of toShow) {
      const topFinding = s.findings[0];
      const sev = topFinding ? severityColor(topFinding.severity) : `${D}-${R}`;
      const finding = topFinding ? topFinding.title : (s.verdict === "safe" ? `${G}No issues${R}` : "-");
      console.log(`  ${col(s.name, 24)} ${col(verdictColor(s.verdict), 16)} ${col(sev, 14)} ${finding}`);
      if (opts.verbose && s.findings.length > 1) {
        for (const f of s.findings.slice(1)) {
          console.log(`  ${col("", 24)} ${col("", 16)} ${col(severityColor(f.severity), 14)} ${f.title}`);
        }
      }
    }
    if (!opts.verbose && skills.length > dangerOrWarnSkills.length) {
      const safeCount = skills.length - dangerOrWarnSkills.length;
      console.log(`  ${D}  ... ${safeCount} safe skill(s) hidden (use --verbose)${R}`);
    }
    console.log();
  }

  // MCP SERVERS section
  const mcps = report.mcp_results ?? [];
  const hasRegistryScores = mcps.some((m) => m.registry_score !== undefined && m.registry_score !== null);
  const dangerOrWarnMcps = opts.verbose
    ? mcps
    : mcps.filter((m) => m.verdict !== "safe");
  if (dangerOrWarnMcps.length > 0 || (opts.verbose && mcps.length > 0)) {
    console.log(`  ${C}${B}MCP SERVERS${R}`);
    let header = `  ${col(D + "NAME" + R, 24)} ${col(D + "VERDICT" + R, 16)} ${col(D + "SEVERITY" + R, 14)}`;
    if (hasRegistryScores) header += ` ${col(D + "REGISTRY" + R, 12)}`;
    header += ` ${D}FINDING${R}`;
    console.log(header);
    const toShow = opts.verbose ? mcps : dangerOrWarnMcps;
    for (const m of toShow) {
      const topFinding = m.findings[0];
      const sev = topFinding ? severityColor(topFinding.severity) : `${D}-${R}`;
      const finding = topFinding ? topFinding.title : (m.verdict === "safe" ? `${G}No issues${R}` : "-");
      let line = `  ${col(m.name, 24)} ${col(verdictColor(m.verdict), 16)} ${col(sev, 14)}`;
      if (hasRegistryScores) {
        const score = m.registry_score !== undefined && m.registry_score !== null
          ? `${m.registry_score}/100`
          : `${D}-${R}`;
        line += ` ${col(String(score), 12)}`;
      }
      line += ` ${finding}`;
      console.log(line);
      if (opts.verbose && m.findings.length > 1) {
        for (const f of m.findings.slice(1)) {
          let extra = `  ${col("", 24)} ${col("", 16)} ${col(severityColor(f.severity), 14)}`;
          if (hasRegistryScores) extra += ` ${col("", 12)}`;
          extra += ` ${f.title}`;
          console.log(extra);
        }
      }
    }
    if (!opts.verbose && mcps.length > dangerOrWarnMcps.length) {
      const safeCount = mcps.length - dangerOrWarnMcps.length;
      console.log(`  ${D}  ... ${safeCount} safe server(s) hidden (use --verbose)${R}`);
    }
    console.log();
  }

  // CUSTOM RULES section
  const custom = report.custom_findings ?? [];
  if (custom.length > 0) {
    console.log(`  ${C}${B}CUSTOM RULES${R}`);
    console.log(`  ${col(D + "NAME" + R, 24)} ${col(D + "VERDICT" + R, 16)} ${col(D + "SEVERITY" + R, 14)} ${D}FINDING${R}`);
    for (const c of custom) {
      console.log(`  ${col(c.entity_name, 24)} ${col(verdictColor(c.verdict), 16)} ${col(severityColor(c.severity), 14)} ${c.title}`);
    }
    console.log();
  }

  // POLICY section
  const config = opts.config;
  if (config) {
    console.log(`  ${C}${B}POLICY${R}`);
    console.log(`  ${D}config:${R}    ${config.config_path}`);
    console.log(`  ${D}fail_on:${R}   ${config.fail_on}`);
    if (config.allowed_agents.length > 0) {
      console.log(`  ${D}agents:${R}    ${config.allowed_agents.join(", ")}`);
    }
    if (config.allowed_mcp_servers.length > 0) {
      console.log(`  ${D}mcp:${R}       ${config.allowed_mcp_servers.join(", ")}`);
    }
    console.log();
  }

  // DELTA section
  const delta = opts.delta;
  if (delta && (delta.total_new > 0 || delta.total_resolved > 0 || delta.total_changed > 0)) {
    console.log(`  ${C}${B}DELTA${R} ${D}(vs previous scan)${R}`);
    console.log(`  ${RED}+${delta.total_new} new${R}  ${G}-${delta.total_resolved} resolved${R}  ${Y}~${delta.total_changed} changed${R}`);
    for (const e of delta.entries.slice(0, 10)) {
      const prefix = e.change_type === "new" || e.change_type === "new_entity"
        ? `${RED}+${R}`
        : e.change_type === "resolved" || e.change_type === "removed_entity"
          ? `${G}-${R}`
          : `${Y}~${R}`;
      const label = e.code ? `${e.code}: ${e.title ?? ""}` : e.entity_name;
      console.log(`    ${prefix} [${e.entity_type}] ${label}`);
    }
    if (delta.entries.length > 10) {
      console.log(`  ${D}  ... ${delta.entries.length - 10} more entries${R}`);
    }
    console.log();
  }

  // Summary box
  const dangers = totalDangers(report);
  const warnings = totalWarnings(report);
  const safe = totalSafe(report);

  console.log(`  ${D}${"─".repeat(50)}${R}`);
  const summaryParts = [];
  if (dangers > 0) summaryParts.push(`${RED}${B}${dangers} DANGER${R}`);
  if (warnings > 0) summaryParts.push(`${Y}${B}${warnings} WARNING${R}`);
  summaryParts.push(`${G}${B}${safe} SAFE${R}`);
  console.log(`  ${summaryParts.join("  ")}  ${D}(${report.duration_seconds.toFixed(1)}s)${R}`);
  console.log();
}

// ═══════════════════════════════════════════════════════════════════════════
// GUARD COMMAND
// ═══════════════════════════════════════════════════════════════════════════

const guardCmd = program
  .command("guard")
  .description("Scan machine for AI agent security issues")
  .argument("[path]", "directory to scan (default: entire machine)")
  .option("--verbose", "show all findings")
  .option("--no-registry", "skip agentseal.org enrichment")
  .option("--no-diff", "skip delta comparison")
  .option("--from-json <path>", "re-render saved JSON report")
  .option("--fail-on <level>", "exit code threshold: danger|warning|safe")
  .option("--rules <path>", "custom YAML rules path")
  .option("--config <path>", "explicit .agentseal.yaml path")
  .option("-o, --output <format>", "output format: terminal|json|sarif", "terminal")
  .option("--save <path>", "save JSON report to file")
  .option("--reset-baselines", "re-trust all MCP servers")
  .action(async (scanPath: string | undefined, opts: Record<string, any>) => {
    try {
      // Handle --reset-baselines
      if (opts.resetBaselines) {
        const store = new BaselineStore();
        const count = store.reset();
        console.log(`Reset ${count} baseline(s). All MCP servers will be re-trusted on next scan.`);
        return;
      }

      // Handle --from-json: re-render a saved report
      if (opts.fromJson) {
        const data = JSON.parse(readFileSync(opts.fromJson, "utf-8"));
        const report = guardReportFromDict(data);
        if (opts.output === "json") {
          console.log(JSON.stringify(report, null, 2));
        } else if (opts.output === "sarif") {
          // Basic SARIF-compatible output
          console.log(JSON.stringify({ $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json", version: "2.1.0", runs: [{ tool: { driver: { name: "agentseal-guard" } }, results: report }] }, null, 2));
        } else {
          renderGuardTerminal(report, { verbose: opts.verbose });
        }
        return;
      }

      // Resolve project config
      const config = resolveProjectConfig({
        configPath: opts.config,
        searchDir: scanPath,
      });

      // Resolve rules paths
      const rulesPaths: string[] = [];
      if (opts.rules) {
        rulesPaths.push(opts.rules);
      }

      // Run the guard scan
      const guard = new Guard({
        scanPath,
        verbose: opts.verbose,
        noRegistry: opts.registry === false,
        noDiff: opts.diff === false,
        config: config ?? undefined,
        rulesPaths: rulesPaths.length > 0 ? rulesPaths : undefined,
        onProgress: (phase, detail) => {
          if (opts.output === "terminal") {
            process.stderr.write(`\x1b[90m  [${phase}] ${detail}\x1b[0m\n`);
          }
        },
      });

      const report = await guard.run();

      // Compute delta if diff is enabled
      let delta: { total_new: number; total_resolved: number; total_changed: number; entries: DeltaEntry[] } | null = null;
      if (opts.diff !== false) {
        try {
          const store = new HistoryStore();
          const prev = store.loadPrevious(scanPath);
          if (prev) {
            const deltaResult = computeDelta(report, prev, scanPath);
            delta = {
              total_new: deltaResult.total_new,
              total_resolved: deltaResult.total_resolved,
              total_changed: deltaResult.total_changed,
              entries: deltaResult.entries,
            };
          }
          store.close();
        } catch {
          // History is best-effort
        }
      }

      // Output
      if (opts.output === "json") {
        console.log(JSON.stringify(report, null, 2));
      } else if (opts.output === "sarif") {
        console.log(JSON.stringify({
          $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
          version: "2.1.0",
          runs: [{
            tool: { driver: { name: "agentseal-guard", version: VERSION } },
            results: report,
          }],
        }, null, 2));
      } else {
        renderGuardTerminal(report, {
          verbose: opts.verbose,
          config: config ?? undefined,
          delta,
        });
      }

      // Save report
      if (opts.save) {
        writeFileSync(opts.save, JSON.stringify(report, null, 2));
        console.log(`Report saved to ${opts.save}`);
      }

      // Exit code
      const failLevel = opts.failOn ?? config?.fail_on ?? "danger";
      const hasDanger = totalDangers(report) > 0;
      const hasWarning = totalWarnings(report) > 0;
      if (shouldFail(failLevel, { hasDanger, hasWarning })) {
        process.exit(1);
      }
    } catch (err) {
      console.error(`Error: ${err}`);
      process.exit(2);
    }
  });

// ─── guard init ───

guardCmd
  .command("init")
  .description("Initialize .agentseal.yaml config")
  .option("--force", "overwrite existing config")
  .action((opts: Record<string, any>) => {
    try {
      const written = runGuardInit({ force: opts.force });
      if (written) {
        console.log("\x1b[32mCreated .agentseal.yaml\x1b[0m");
        console.log("  Edit allowed_agents and allowed_mcp_servers to match your setup.");
      } else {
        console.log("\x1b[33m.agentseal.yaml already exists.\x1b[0m Use --force to overwrite.");
      }
    } catch (err) {
      console.error(`Error: ${err}`);
      process.exit(2);
    }
  });

// ─── guard test ───

guardCmd
  .command("test")
  .description("Run self-tests on custom rules")
  .option("--rules <path>", "rules path (default: .agentseal/rules/)")
  .action((opts: Record<string, any>) => {
    try {
      const R = "\x1b[0m";
      const G = "\x1b[32m";
      const RED = "\x1b[31m";
      const B = "\x1b[1m";

      // Resolve rules path
      const rulesPath = opts.rules ?? ".agentseal/rules";
      if (!existsSync(rulesPath)) {
        console.error(`Rules path not found: ${rulesPath}`);
        console.error("Create custom rules in .agentseal/rules/ or specify --rules <path>");
        process.exit(2);
      }

      const engine = RuleEngine.fromPaths([rulesPath]);
      const results = engine.runTests();

      if (results.length === 0) {
        console.log("No tests found in rules. Add 'tests:' entries to your rule YAML files.");
        return;
      }

      console.log(`\n  ${B}Rule Tests${R}\n`);

      let passed = 0;
      let failed = 0;
      for (const r of results) {
        if (r.passed) {
          console.log(`  ${G}PASS${R} ${r.rule_id} / ${r.test_name}`);
          passed++;
        } else {
          console.log(`  ${RED}FAIL${R} ${r.rule_id} / ${r.test_name}  (expected: ${r.expected}, got: ${r.actual})`);
          failed++;
        }
      }

      console.log();
      console.log(`  ${passed} passed, ${failed} failed`);
      console.log();

      if (failed > 0) {
        process.exit(1);
      }
    } catch (err) {
      console.error(`Error: ${err}`);
      process.exit(2);
    }
  });

// CONFIG command
program
  .command("config")
  .description("Manage local configuration (API keys, LLM settings)")
  .argument("[action]", "set | show | remove | keys | setup")
  .argument("[key]", "Config key")
  .argument("[value]", "Value to set")
  .action((action, key, value) => {
    switch (action) {
      case "set":
        if (!key || !value) { console.error("Usage: agentseal config set <key> <value>"); process.exit(1); }
        saveConfigKey(key, value);
        console.log(`\x1b[32mSaved\x1b[0m ${key}`);
        break;
      case "show":
        console.log(showConfig());
        break;
      case "remove":
        if (!key) { console.error("Usage: agentseal config remove <key>"); process.exit(1); }
        removeConfigKey(key);
        console.log(`\x1b[32mRemoved\x1b[0m ${key}`);
        break;
      case "keys":
        console.log("Valid config keys:");
        for (const k of CONFIG_KEYS) console.log(`  ${k}`);
        break;
      case "setup":
        console.log("\n  LLM Provider Setup\n");
        console.log("  Ollama (local):     agentseal config set model ollama/qwen3");
        console.log("  OpenAI:             agentseal config set api-key sk-...");
        console.log("                      agentseal config set model gpt-4o");
        console.log("  Anthropic:          agentseal config set api-key sk-ant-...");
        console.log("                      agentseal config set model claude-sonnet-4-5-20250929");
        console.log();
        break;
      default:
        console.log(showConfig());
        break;
    }
  });

// LOGIN command
program
  .command("login")
  .description("Store dashboard credentials")
  .option("--api-url <url>", "Dashboard API URL", "https://agentseal.org/api/v1")
  .option("--api-key <key>", "Dashboard API key")
  .action((opts) => {
    if (!opts.apiKey) { console.error("Error: --api-key is required"); process.exit(1); }
    saveCredentials(opts.apiUrl, opts.apiKey);
    console.log("\x1b[32mCredentials saved.\x1b[0m");
  });

// ACTIVATE command
program
  .command("activate")
  .description("Activate a Pro license key")
  .argument("[key]", "Your license key")
  .action((key) => {
    if (!key) { console.error("Usage: agentseal activate <license-key>"); process.exit(1); }
    saveLicense(key);
    console.log(`\x1b[32mLicense activated.\x1b[0m`);
  });

program
  .command("profiles")
  .description("List available scan profiles")
  .action(() => {
    console.log(listProfiles());
  });

program
  .command("registry")
  .description("Manage the MCP server registry")
  .argument("[action]", "info | update | list", "info")
  .option("--api-url <url>", "Custom API URL", "https://agentseal.org/api/v1")
  .action(async (action, opts) => {
    switch (action) {
      case "info":
        console.log("  AgentSeal MCP Server Registry");
        console.log("  Ships with bundled trust scores. Use 'update' to fetch latest.");
        break;
      case "update":
        console.log("  Fetching latest registry data...");
        try {
          const results = await bulkCheck([], opts.apiUrl);
          console.log(`  \x1b[32mUpdated.\x1b[0m ${Object.keys(results).length} servers in registry.`);
        } catch (err) {
          console.error(`  Error fetching registry: ${err}`);
          process.exit(1);
        }
        break;
      case "list":
        console.log("  Use the web registry at https://agentseal.org/mcp for full browsing.");
        console.log("  Or run: agentseal guard --verbose to see registry scores for your servers.");
        break;
      default:
        console.error(`Unknown action: ${action}. Use info, update, or list.`);
        process.exit(1);
    }
  });

program
  .command("fix")
  .description("Fix dangerous skills and harden prompts")
  .option("--from-guard", "Load guard report and quarantine dangerous skills")
  .option("--from-scan", "Load scan report and generate hardened prompt")
  .option("--report <file>", "Path to report file (instead of latest)")
  .option("--auto", "Quarantine all DANGER skills without prompting")
  .option("--dry-run", "Show what would be done without doing it")
  .option("--list-quarantine", "List quarantined skills")
  .option("--restore <name>", "Restore a quarantined skill by name")
  .option("--output <file>", "Save hardened prompt to file")
  .action(async (opts) => {
    const R = "\x1b[0m";
    const G = "\x1b[32m";
    const RED = "\x1b[31m";
    const B = "\x1b[1m";

    if (opts.listQuarantine) {
      const entries = listQuarantine();
      if (entries.length === 0) { console.log("No quarantined skills."); return; }
      console.log(`\n  ${B}Quarantined Skills${R}\n`);
      for (const e of entries) {
        console.log(`  ${RED}●${R} ${e.name}  ${e.reason ?? ""}  (${e.date})`);
      }
      console.log();
      return;
    }

    if (opts.restore) {
      try {
        const restored = restoreSkill(opts.restore);
        console.log(`${G}Restored:${R} ${restored}`);
      } catch (err) {
        console.error(`Error: ${err}`);
        process.exit(1);
      }
      return;
    }

    if (opts.fromGuard) {
      const report = loadGuardReport(opts.report);
      const fixable = getFixableSkills(report);
      if (fixable.length === 0) { console.log("No dangerous skills to fix."); return; }
      console.log(`\n  ${B}Fixable Skills${R} (${fixable.length})\n`);
      for (const s of fixable) {
        const label = opts.dryRun ? "[DRY RUN] Would quarantine" : "Quarantining";
        console.log(`  ${RED}●${R} ${label}: ${s.name}`);
        if (!opts.dryRun) {
          quarantineSkill(s.path, s.name, s.findings?.[0]?.title);
        }
      }
      console.log();
      return;
    }

    if (opts.fromScan) {
      const report = loadScanReport(opts.report);
      const remediation = generateRemediation(report as unknown as ScanReport);
      if (remediation.hardened_prompt) {
        if (opts.output) {
          writeFileSync(opts.output, remediation.hardened_prompt);
          console.log(`${G}Hardened prompt saved to${R} ${opts.output}`);
        } else {
          console.log(`\n${B}Hardened Prompt:${R}\n`);
          console.log(remediation.hardened_prompt);
        }
      } else {
        console.log("No remediation needed — scan looks clean.");
      }
      return;
    }

    console.log("Usage: agentseal fix --from-guard | --from-scan | --list-quarantine | --restore <name>");
  });

program
  .command("shield")
  .description("Continuously monitor your machine for AI agent threats")
  .option("--no-notify", "Disable desktop notifications")
  .option("--debounce <seconds>", "Seconds to wait after change before scanning", "2")
  .option("-q, --quiet", "Suppress terminal output")
  .option("--reset-baselines", "Reset MCP server baselines before starting")
  .action(async (opts) => {
    printBanner();
    console.log("  Starting Shield — continuous monitoring...");
    console.log("  Press Ctrl+C to stop.\n");

    if (opts.resetBaselines) {
      const store = new BaselineStore();
      store.reset();
      console.log("  Baselines reset.\n");
    }

    const shield = new Shield({
      debounceSeconds: parseFloat(opts.debounce),
      notify: opts.notify !== false,
      onEvent: (eventType, filePath, summary) => {
        if (!opts.quiet) {
          const color = eventType === "threat" ? "\x1b[31m" : eventType === "warning" ? "\x1b[33m" : "\x1b[90m";
          console.log(`  ${color}[${eventType.toUpperCase()}]\x1b[0m ${filePath} — ${summary}`);
        }
      },
    });

    process.on("SIGINT", () => {
      console.log("\n  Shield stopped.");
      shield.stop();
      process.exit(0);
    });

    const { dirsWatched, filesWatched } = shield.start();
    console.log(`  Watching ${dirsWatched} director${dirsWatched === 1 ? "y" : "ies"} (${filesWatched} individual files).\n`);

    // Keep the process alive until SIGINT
    await new Promise<void>(() => {});
  });

program
  .command("scan-mcp")
  .description("Runtime MCP server scanner — connect, analyze, score")
  .option("--server <name>", "Scan only this server (by name)")
  .option("-o, --output <format>", "Output format: terminal, json", "terminal")
  .option("--save <file>", "Save JSON report to file")
  .option("--min-score <score>", "Exit code 1 if any server scores below threshold")
  .option("-v, --verbose", "Show individual tool findings")
  .option("--reset-baselines", "Reset all MCP server baselines")
  .action(async (opts) => {
    printBanner();

    if (opts.resetBaselines) {
      const store = new BaselineStore();
      const count = store.reset();
      console.log(`Reset ${count} baseline(s).\n`);
    }

    const checker = new MCPConfigChecker();
    console.log("  Discovering MCP servers...\n");

    // Read MCP configs from well-known locations and check each server
    const { getWellKnownConfigs, stripJsonComments } = await import("../src/machine-discovery.js");
    const { readFileSync: rfs, existsSync: efs } = await import("node:fs");
    const { homedir } = await import("node:os");

    const home = homedir();
    const plat = process.platform === "darwin" ? "Darwin" : process.platform === "win32" ? "Windows" : "Linux";
    const configs = getWellKnownConfigs();

    const serverDicts: Array<Record<string, any>> = [];
    for (const cfg of configs) {
      const paths = cfg.paths as Record<string, string | undefined>;
      let cfgPath = paths[plat] ?? paths["all"];
      if (!cfgPath) continue;
      cfgPath = cfgPath.replace(/^~/, home);
      if (!efs(cfgPath)) continue;

      let data: Record<string, any>;
      try {
        const raw = rfs(cfgPath, "utf-8");
        data = JSON.parse(stripJsonComments(raw));
      } catch {
        continue;
      }

      let servers: Record<string, any> = {};
      for (const key of ["mcpServers", "servers", "context_servers"]) {
        if (key in data && typeof data[key] === "object" && data[key] !== null) {
          servers = data[key];
          break;
        }
      }

      for (const [srvName, srvCfg] of Object.entries(servers)) {
        if (typeof srvCfg !== "object" || srvCfg === null) continue;
        if (opts.server && srvName !== opts.server) continue;
        serverDicts.push({ name: srvName, source_file: cfgPath, ...srvCfg });
      }
    }

    if (serverDicts.length === 0) {
      console.log("  No MCP servers found. Check your agent configuration.");
      return;
    }

    console.log(`  Found ${serverDicts.length} server(s). Scanning...\n`);

    const results: MCPScanResult[] = [];
    for (const serverDict of serverDicts) {
      const result = checker.check(serverDict);
      const verdictStr = verdictFromFindings(result.findings);
      results.push({
        server_name: result.name,
        verdict: verdictStr,
        findings: result.findings.map((f) => ({
          code: f.code,
          severity: f.severity,
          title: f.title,
          detail: f.description,
        })),
        tools_count: 0,
      });
    }

    if (opts.output === "json") {
      console.log(JSON.stringify(results, null, 2));
    } else {
      renderMCPResults(results, opts.verbose);
    }

    if (opts.save) {
      writeFileSync(opts.save, JSON.stringify(results, null, 2));
      console.log(`Report saved to ${opts.save}`);
    }

    if (opts.minScore) {
      const threshold = parseInt(opts.minScore);
      const failing = results.filter((r) => r.trust_score !== undefined && r.trust_score < threshold);
      if (failing.length > 0) {
        console.error(`\nCI check failed: ${failing.length} server(s) below threshold ${threshold}`);
        process.exit(1);
      }
    }
  });

program
  .command("watch")
  .description("Run canary regression scan (5 probes, for CI/cron)")
  .option("-p, --prompt <text>", "System prompt to test")
  .option("-f, --file <path>", "Path to file containing system prompt")
  .option("--url <url>", "HTTP endpoint URL to test")
  .option("-m, --model <name>", "Model to test")
  .option("--api-key <key>", "API key")
  .option("--ollama-url <url>", "Ollama base URL", "http://localhost:11434")
  .option("--canary-probes <csv>", "Comma-separated probe IDs")
  .option("--min-score <score>", "Exit code 1 if below")
  .option("-o, --output <format>", "Output format: terminal, json", "terminal")
  .option("--name <name>", "Agent name", "My Agent")
  .option("--concurrency <n>", "Max parallel probes", "3")
  .option("--timeout <seconds>", "Timeout per probe", "30")
  .argument("[prompt]", "Quick inline prompt")
  .action(async (inlinePrompt, opts) => {
    const systemPrompt = opts.prompt ?? inlinePrompt ?? (opts.file ? readFileSync(opts.file, "utf-8").trim() : undefined);
    if (!systemPrompt && !opts.url) {
      console.error("Error: Provide --prompt, --file, or --url");
      process.exit(1);
    }

    const canaryProbes = selectCanaryProbes(opts.canaryProbes);
    console.log(`  Running ${canaryProbes.length} canary probes...\n`);

    let validator: AgentValidator;
    if (opts.url) {
      validator = AgentValidator.fromEndpoint({
        url: opts.url,
        agentName: opts.name,
        concurrency: parseInt(opts.concurrency),
        timeoutPerProbe: parseFloat(opts.timeout),
      });
    } else {
      validator = await buildValidator(systemPrompt!, {
        model: opts.model,
        apiKey: opts.apiKey,
        ollamaUrl: opts.ollamaUrl,
        name: opts.name,
        concurrency: parseInt(opts.concurrency),
        timeout: parseFloat(opts.timeout),
      });
    }

    const report = await validator.run();

    if (opts.output === "json") {
      console.log(JSON.stringify(report, null, 2));
    } else {
      console.log(`  Score: ${report.trust_score.toFixed(1)}/100`);
      console.log(`  Blocked: ${report.probes_blocked}  Leaked: ${report.probes_leaked}`);
    }

    if (opts.minScore) {
      const threshold = parseInt(opts.minScore);
      if (report.trust_score < threshold) {
        console.error(`\n  CI check failed: ${report.trust_score.toFixed(1)} < ${threshold}`);
        process.exit(1);
      }
    }
  });

program.parse();
