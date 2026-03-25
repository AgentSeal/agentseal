/**
 * Toxic flow detection — static analysis of MCP server capability combinations.
 *
 * Classifies MCP servers by capability labels and detects dangerous
 * combinations that could enable data exfiltration, remote code execution,
 * or data destruction.
 *
 * Port of Python agentseal/toxic_flows.py — static analysis only.
 */

import type { ToxicFlowResult } from "./guard-models.js";

// ═══════════════════════════════════════════════════════════════════════
// Capability Labels
// ═══════════════════════════════════════════════════════════════════════

export const LABEL_PUBLIC_SINK = "public_sink";
export const LABEL_DESTRUCTIVE = "destructive";
export const LABEL_UNTRUSTED = "untrusted_content";
export const LABEL_PRIVATE = "private_data";

// ═══════════════════════════════════════════════════════════════════════
// Known Server Classifications
// ═══════════════════════════════════════════════════════════════════════

export const KNOWN_SERVER_LABELS: Record<string, Set<string>> = {
  filesystem: new Set([LABEL_PRIVATE, LABEL_DESTRUCTIVE]),
  fs: new Set([LABEL_PRIVATE, LABEL_DESTRUCTIVE]),
  slack: new Set([LABEL_PUBLIC_SINK]),
  discord: new Set([LABEL_PUBLIC_SINK]),
  email: new Set([LABEL_PUBLIC_SINK]),
  gmail: new Set([LABEL_PUBLIC_SINK]),
  smtp: new Set([LABEL_PUBLIC_SINK]),
  sendgrid: new Set([LABEL_PUBLIC_SINK]),
  twilio: new Set([LABEL_PUBLIC_SINK]),
  telegram: new Set([LABEL_PUBLIC_SINK]),
  teams: new Set([LABEL_PUBLIC_SINK]),
  webhook: new Set([LABEL_PUBLIC_SINK]),
  github: new Set([LABEL_PUBLIC_SINK, LABEL_PRIVATE]),
  gitlab: new Set([LABEL_PUBLIC_SINK, LABEL_PRIVATE]),
  bitbucket: new Set([LABEL_PUBLIC_SINK, LABEL_PRIVATE]),
  linear: new Set([LABEL_PUBLIC_SINK, LABEL_PRIVATE]),
  jira: new Set([LABEL_PUBLIC_SINK, LABEL_PRIVATE]),
  notion: new Set([LABEL_PUBLIC_SINK, LABEL_PRIVATE]),
  asana: new Set([LABEL_PUBLIC_SINK, LABEL_PRIVATE]),
  postgres: new Set([LABEL_PRIVATE, LABEL_DESTRUCTIVE]),
  postgresql: new Set([LABEL_PRIVATE, LABEL_DESTRUCTIVE]),
  mysql: new Set([LABEL_PRIVATE, LABEL_DESTRUCTIVE]),
  sqlite: new Set([LABEL_PRIVATE, LABEL_DESTRUCTIVE]),
  mongo: new Set([LABEL_PRIVATE, LABEL_DESTRUCTIVE]),
  mongodb: new Set([LABEL_PRIVATE, LABEL_DESTRUCTIVE]),
  redis: new Set([LABEL_PRIVATE, LABEL_DESTRUCTIVE]),
  supabase: new Set([LABEL_PRIVATE, LABEL_DESTRUCTIVE, LABEL_PUBLIC_SINK]),
  fetch: new Set([LABEL_UNTRUSTED]),
  puppeteer: new Set([LABEL_UNTRUSTED]),
  playwright: new Set([LABEL_UNTRUSTED]),
  browser: new Set([LABEL_UNTRUSTED]),
  "brave-search": new Set([LABEL_UNTRUSTED]),
  tavily: new Set([LABEL_UNTRUSTED]),
  "web-search": new Set([LABEL_UNTRUSTED]),
  scraper: new Set([LABEL_UNTRUSTED]),
  crawl: new Set([LABEL_UNTRUSTED]),
  aws: new Set([LABEL_PRIVATE, LABEL_DESTRUCTIVE, LABEL_PUBLIC_SINK]),
  gcp: new Set([LABEL_PRIVATE, LABEL_DESTRUCTIVE, LABEL_PUBLIC_SINK]),
  azure: new Set([LABEL_PRIVATE, LABEL_DESTRUCTIVE, LABEL_PUBLIC_SINK]),
  docker: new Set([LABEL_DESTRUCTIVE]),
  kubernetes: new Set([LABEL_DESTRUCTIVE]),
  k8s: new Set([LABEL_DESTRUCTIVE]),
  terraform: new Set([LABEL_DESTRUCTIVE]),
  shell: new Set([LABEL_DESTRUCTIVE, LABEL_UNTRUSTED]),
  terminal: new Set([LABEL_DESTRUCTIVE, LABEL_UNTRUSTED]),
  exec: new Set([LABEL_DESTRUCTIVE]),
  "code-runner": new Set([LABEL_DESTRUCTIVE]),
  sandbox: new Set([LABEL_DESTRUCTIVE]),
  memory: new Set([LABEL_PRIVATE]),
  knowledge: new Set([LABEL_PRIVATE]),
  vector: new Set([LABEL_PRIVATE]),
  sentry: new Set([LABEL_PRIVATE]),
  datadog: new Set([LABEL_PRIVATE]),
  grafana: new Set([LABEL_PRIVATE]),
  s3: new Set([LABEL_PRIVATE, LABEL_PUBLIC_SINK, LABEL_DESTRUCTIVE]),
  gcs: new Set([LABEL_PRIVATE, LABEL_PUBLIC_SINK, LABEL_DESTRUCTIVE]),
  drive: new Set([LABEL_PRIVATE, LABEL_PUBLIC_SINK]),
  dropbox: new Set([LABEL_PRIVATE, LABEL_PUBLIC_SINK]),
};

const NAME_HEURISTICS: Array<[RegExp, Set<string>]> = [
  [/(?:file|fs|disk)/i, new Set([LABEL_PRIVATE, LABEL_DESTRUCTIVE])],
  [/(?:mail|email|smtp)/i, new Set([LABEL_PUBLIC_SINK])],
  [/(?:http|fetch|web|browser|scrape|crawl)/i, new Set([LABEL_UNTRUSTED])],
  [/(?:db|sql|database|mongo|redis)/i, new Set([LABEL_PRIVATE])],
  [/(?:exec|shell|command|terminal|run)/i, new Set([LABEL_DESTRUCTIVE])],
  [/(?:slack|discord|teams|telegram|chat)/i, new Set([LABEL_PUBLIC_SINK])],
  [/(?:github|gitlab|bitbucket|jira|linear)/i, new Set([LABEL_PUBLIC_SINK, LABEL_PRIVATE])],
  [/(?:aws|gcp|azure|cloud)/i, new Set([LABEL_PRIVATE, LABEL_DESTRUCTIVE])],
  [/(?:docker|k8s|kubernetes|terraform)/i, new Set([LABEL_DESTRUCTIVE])],
  [/(?:s3|gcs|storage|drive|dropbox)/i, new Set([LABEL_PRIVATE, LABEL_PUBLIC_SINK])],
];

// ═══════════════════════════════════════════════════════════════════════
// Server Classification
// ═══════════════════════════════════════════════════════════════════════

export function classifyServer(server: Record<string, any>): Set<string> {
  const name = (server.name ?? "").toLowerCase().trim();
  const rawCmd = server.command ?? "";
  const command = (Array.isArray(rawCmd) ? rawCmd.join(" ") : String(rawCmd)).toLowerCase();
  const argsStr = (server.args ?? [])
    .filter((a: any): a is string => typeof a === "string")
    .join(" ")
    .toLowerCase();

  // Exact match
  if (KNOWN_SERVER_LABELS[name]) {
    return new Set(KNOWN_SERVER_LABELS[name]);
  }

  // Substring match in name
  for (const [known, labels] of Object.entries(KNOWN_SERVER_LABELS)) {
    if (name.includes(known)) return new Set(labels);
  }

  // Substring match in command/args
  const searchText = `${command} ${argsStr}`;
  for (const [known, labels] of Object.entries(KNOWN_SERVER_LABELS)) {
    if (searchText.includes(known)) return new Set(labels);
  }

  // Heuristic patterns
  const labels = new Set<string>();
  for (const [pattern, hLabels] of NAME_HEURISTICS) {
    if (pattern.test(name) || pattern.test(command) || pattern.test(argsStr)) {
      for (const l of hLabels) labels.add(l);
    }
  }

  return labels;
}

// ═══════════════════════════════════════════════════════════════════════
// Dangerous Combination Detection
// ═══════════════════════════════════════════════════════════════════════

function detectCombos(serverLabels: Map<string, Set<string>>): ToxicFlowResult[] {
  const flows: ToxicFlowResult[] = [];

  const allLabels = new Set<string>();
  for (const labels of serverLabels.values()) {
    for (const l of labels) allLabels.add(l);
  }

  // Servers by label
  const byLabel = new Map<string, string[]>();
  for (const [name, labels] of serverLabels) {
    for (const label of labels) {
      if (!byLabel.has(label)) byLabel.set(label, []);
      byLabel.get(label)!.push(name);
    }
  }

  const has = (l: string) => allLabels.has(l);
  const serversFor = (...labels: string[]): string[] =>
    [...new Set(labels.flatMap((l) => byLabel.get(l) ?? []))].sort();

  // Full chain: untrusted + private + sink
  if (has(LABEL_UNTRUSTED) && has(LABEL_PRIVATE) && has(LABEL_PUBLIC_SINK)) {
    flows.push({
      risk_level: "high",
      risk_type: "full_chain",
      title: "Full attack chain detected",
      description:
        "This agent can fetch external content, read private data, " +
        "and send data externally. An attacker could inject instructions " +
        "via fetched content, read sensitive files, and exfiltrate them.",
      servers_involved: serversFor(LABEL_UNTRUSTED, LABEL_PRIVATE, LABEL_PUBLIC_SINK),
      labels_involved: [LABEL_UNTRUSTED, LABEL_PRIVATE, LABEL_PUBLIC_SINK],
      remediation:
        "Scope filesystem access to non-sensitive directories. " +
        "Remove or restrict external communication servers.",
      tools_involved: [],
    });
    return flows; // Full chain subsumes individual combos
  }

  // Data exfiltration: private + sink
  if (has(LABEL_PRIVATE) && has(LABEL_PUBLIC_SINK)) {
    flows.push({
      risk_level: "high",
      risk_type: "data_exfiltration",
      title: "Data exfiltration path detected",
      description:
        "This agent can read private data and send it externally. " +
        "A prompt injection could instruct the agent to read sensitive " +
        "files and leak them via an external service.",
      servers_involved: serversFor(LABEL_PRIVATE, LABEL_PUBLIC_SINK),
      labels_involved: [LABEL_PRIVATE, LABEL_PUBLIC_SINK],
      remediation:
        "Scope filesystem access to non-sensitive directories only. " +
        "Review which external services truly need write access.",
      tools_involved: [],
    });
  }

  // Remote code execution: untrusted + destructive
  if (has(LABEL_UNTRUSTED) && has(LABEL_DESTRUCTIVE)) {
    flows.push({
      risk_level: "high",
      risk_type: "remote_code_execution",
      title: "Remote code execution path detected",
      description:
        "This agent can fetch external content and execute destructive " +
        "operations. Fetched content could contain malicious instructions " +
        "that modify files, execute commands, or alter databases.",
      servers_involved: serversFor(LABEL_UNTRUSTED, LABEL_DESTRUCTIVE),
      labels_involved: [LABEL_UNTRUSTED, LABEL_DESTRUCTIVE],
      remediation:
        "Add confirmation steps before destructive operations. " +
        "Restrict or sandbox the execution server.",
      tools_involved: [],
    });
  }

  // Data destruction: private + destructive from different servers
  if (has(LABEL_PRIVATE) && has(LABEL_DESTRUCTIVE)) {
    const privateServers = new Set(byLabel.get(LABEL_PRIVATE) ?? []);
    const destructiveServers = new Set(byLabel.get(LABEL_DESTRUCTIVE) ?? []);
    const same = privateServers.size === destructiveServers.size &&
      [...privateServers].every((s) => destructiveServers.has(s));
    if (!same) {
      flows.push({
        risk_level: "medium",
        risk_type: "data_destruction",
        title: "Data destruction path detected",
        description:
          "This agent can read private data from one source and " +
          "perform destructive operations on another. This could " +
          "lead to data corruption or deletion.",
        servers_involved: [...new Set([...privateServers, ...destructiveServers])].sort(),
        labels_involved: [LABEL_PRIVATE, LABEL_DESTRUCTIVE],
        remediation:
          "Review whether both data read and write capabilities " +
          "are necessary. Consider read-only access where possible.",
        tools_involved: [],
      });
    }
  }

  return flows;
}

/**
 * Analyze MCP servers for dangerous capability combinations.
 * Requires at least 2 servers for cross-server flow detection.
 */
export function analyzeToxicFlows(servers: Array<Record<string, any>>): ToxicFlowResult[] {
  if (servers.length < 2) return [];

  const serverLabels = new Map<string, Set<string>>();
  for (const srv of servers) {
    const name: string = srv.name ?? "unknown";
    const labels = classifyServer(srv);
    if (labels.size > 0) {
      serverLabels.set(name, labels);
    }
  }

  if (serverLabels.size === 0) return [];

  return detectCombos(serverLabels);
}
