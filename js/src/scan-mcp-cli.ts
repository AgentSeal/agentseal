export interface MCPScanResult {
  server_name: string;
  verdict: string;
  findings: Array<{ code: string; severity: string; title: string; detail?: string }>;
  trust_score?: number;
  tools_count: number;
}

export function renderMCPResults(results: MCPScanResult[], verbose: boolean): void {
  const R = "\x1b[0m";
  const B = "\x1b[1m";
  const C = "\x1b[36m";
  const G = "\x1b[32m";
  const Y = "\x1b[33m";
  const RED = "\x1b[31m";
  const D = "\x1b[90m";

  console.log(`\n  ${C}${B}MCP Server Scan Results${R}\n`);

  for (const r of results) {
    const color = r.verdict === "safe" ? G : r.verdict === "warning" ? Y : RED;
    const score = r.trust_score !== undefined ? ` (${r.trust_score}/100)` : "";
    console.log(`  ${color}${r.verdict.toUpperCase()}${R} ${r.server_name}${score} — ${r.tools_count} tools`);

    if (verbose || r.verdict !== "safe") {
      for (const f of r.findings) {
        const sevColor = f.severity === "critical" || f.severity === "high" ? RED : f.severity === "medium" ? Y : D;
        console.log(`    ${sevColor}${f.severity}${R} ${f.code}: ${f.title}`);
      }
    }
  }

  const dangers = results.filter((r) => r.verdict === "danger").length;
  const warnings = results.filter((r) => r.verdict === "warning").length;
  const safe = results.filter((r) => r.verdict === "safe").length;

  console.log(`\n  ${D}${"─".repeat(50)}${R}`);
  const parts: string[] = [];
  if (dangers > 0) parts.push(`${RED}${B}${dangers} DANGER${R}`);
  if (warnings > 0) parts.push(`${Y}${B}${warnings} WARNING${R}`);
  parts.push(`${G}${B}${safe} SAFE${R}`);
  console.log(`  ${parts.join("  ")}`);
  console.log();
}
